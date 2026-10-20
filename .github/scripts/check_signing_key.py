#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
"""校验 CI 里的更新签名私钥与 tauri.conf.json 的公钥是同一对。

★ 为什么必须有（2026-10-20）
────────────────────────────────────────────────────────────────
两者不匹配时，构建**仍然会成功**、发布也照常完成 ——
但所有客户端下载更新后验签失败，自动更新永久不可用，
而这个错误只在用户端出现（界面上只是一句「更新失败」）。

minisign 签名与公钥里都带同一个 8 字节 key id，比对它就能在
发版前发现这类错配，成本只有一次本地签名。

用法（在 release 构建 job 中，已 npm ci）：
    python .github/scripts/check_signing_key.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESKTOP = ROOT / "desktop"
CONF = DESKTOP / "src-tauri" / "tauri.conf.json"


def _key_id(blob: bytes) -> bytes:
    """minisign blob 的第 2–10 字节是 key id（前 2 字节是算法标识）。"""
    if len(blob) < 10:
        raise SystemExit("密钥格式异常：长度不足")
    return blob[2:10]


def _looks_like_text(blob: bytes) -> bool:
    """判断解码结果是不是「又一层文本」，而不是真正的签名二进制。"""
    if b"untrusted comment" in blob or b"trusted comment" in blob:
        return True
    # minisign 签名二进制里几乎不会有换行；有换行基本就是被 base64 套了一层的文本
    return b"\n" in blob or b"\r" in blob


def _extract_signature_blob(stdout: str, sig_path: Path) -> bytes:
    """从 `.sig` 文件或命令输出里取出签名二进制。

    ★ 2026-10-21：CI 实测发现不同版本的 CLI 输出形态不同 ——
      A. `<file>.sig` 里是完整 minisign 块（4 行，第 2 行才是签名）
      B. `<file>.sig` 里只有一行 base64
      C. stdout 里把**整个 .sig 文件内容再 base64 一次**打出来

      形态 C 是最坑的：它解码后是一段文本 `untrusted comment: ...`，
      长度也 > 74，于是「按长度筛选」会把它当成签名 ——
      取出的 key id 就成了 ASCII 的 `trusted `（7472757374656420），
      报出一个看起来像「公私钥不匹配」的假故障。
      （2026-10-21 发版第二次失败正是这个原因。）

      现在的策略：
        1. 收集所有可 base64 解码的候选；
        2. 排除「解码后仍是文本」的候选；
        3. 优先取长度恰好 74 的（2 算法 + 8 key id + 64 签名）。
    """
    lines: list[str] = []
    if sig_path.is_file():
        lines.extend(sig_path.read_text(encoding="utf-8-sig").splitlines())
    lines.extend((stdout or "").splitlines())

    candidates: list[bytes] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("untrusted comment") or s.startswith("trusted comment"):
            continue
        try:
            blob = base64.b64decode(s, validate=True)
        except (ValueError, TypeError):
            continue
        if len(blob) < 10 or _looks_like_text(blob):
            continue
        candidates.append(blob)

    exact = [b for b in candidates if len(b) == 74]
    if exact:
        return exact[0]
    coarse = [b for b in candidates if len(b) >= 74]
    if coarse:
        return coarse[0]
    raise SystemExit(
        "无法从签名输出解析出签名（CLI 输出格式可能变了）；"
        f"stdout 前 120 字：{(stdout or '')[:120]!r}"
    )


def main() -> int:
    key = os.environ.get("TAURI_SIGNING_PRIVATE_KEY", "").strip()
    password = os.environ.get("TAURI_SIGNING_PRIVATE_KEY_PASSWORD", "")
    if not key:
        raise SystemExit("TAURI_SIGNING_PRIVATE_KEY 为空 —— 无法签名更新包")

    conf = json.loads(CONF.read_text(encoding="utf-8"))
    pub_text = str(conf.get("plugins", {}).get("updater", {}).get("pubkey", "")).strip()
    if not pub_text:
        raise SystemExit("tauri.conf.json 未配置 plugins.updater.pubkey")

    env = {**os.environ, "TAURI_SIGNING_PRIVATE_KEY": key}

    with tempfile.TemporaryDirectory() as td:
        probe = Path(td) / "probe.txt"
        probe.write_text("xuandun updater key probe", encoding="utf-8")

        if os.name == "nt":
            cmd = f'npx --no-install tauri signer sign "{probe}"'
            if password:
                cmd += f' -p "{password}"'
            result = subprocess.run(
                cmd, cwd=str(DESKTOP), env=env, shell=True,
                capture_output=True, text=True,
            )
        else:
            argv = [
                "npx", "--no-install", "tauri", "signer", "sign", str(probe),
            ]
            if password:
                argv += ["-p", password]
            result = subprocess.run(
                argv, cwd=str(DESKTOP), env=env,
                capture_output=True, text=True,
            )

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()[-800:]
            raise SystemExit(
                "签名探测失败（私钥或密码不正确）：\n" + detail
            )

        sig_path = Path(str(probe) + ".sig")
        sig_blob = _extract_signature_blob(result.stdout, sig_path)

    pub_lines = base64.b64decode(pub_text).decode("utf-8").splitlines()
    if len(pub_lines) < 2:
        raise SystemExit("公钥格式异常")
    pub_blob = base64.b64decode(pub_lines[1])

    sig_id, pub_id = _key_id(sig_blob), _key_id(pub_blob)
    if sig_id != pub_id:
        raise SystemExit(
            f"签名私钥与配置公钥不是同一对"
            f"（key id {sig_id.hex()} != {pub_id.hex()}）—— "
            "更新包会被所有客户端拒绝，自动更新永久失效"
        )
    print(f"PASS：签名私钥与 tauri.conf.json 公钥匹配（key id {pub_id.hex()}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

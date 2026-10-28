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
import shutil
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


def _nested_lines(blob: bytes) -> list[str] | None:
    """如果解码结果还是一层 minisign 文本，返回它的行；否则返回 None。

    ★ 不能用「含换行就算文本」来判断：签名是 64 字节随机串，
      约四分之一的概率会碰巧出现 0x0A，用换行判断会把真签名误判成文本。
      （2026-10-21 本地复现时正是踩了这个坑，导致一个也解不出来。）
      只认 minisign 的固定首行标记。
    """
    if b"untrusted comment: " not in blob:
        return None
    try:
        return blob.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def _decode_candidates(lines: list[str], depth: int = 0) -> list[bytes]:
    """把文本行里所有可 base64 解出的二进制收集起来，遇到嵌套再解一层。

    ★ 2026-10-21 实测（本地复现 tauri-cli 2.11.5）：
      `tauri signer sign` 写出的 `<file>.sig` **只有一行**，
      内容是「整个 minisign 签名文件」的 base64。解一层得到：

          untrusted comment: signature from tauri secret key
          RUTrNQ8YHy9Zslyz...        ← 真正的签名（74 字节）
          trusted comment: timestamp:1792525926	file:probe.txt
          9bvFdoZBazpBpjQ9n9rG...     ← 对 trusted comment 的签名（64 字节）

      所以必须先解外层、再解第 2 行，才能拿到带 key id 的签名。
      旧实现只解一层，把外层那段文本当成了签名，
      key id 读成 ASCII 的 `trusted `（7472757374656420），
      报出一个「公私钥不匹配」的假故障。发版因此连着挂了两轮。
    """
    blobs: list[bytes] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("untrusted comment") or s.startswith("trusted comment"):
            continue
        try:
            blob = base64.b64decode(s, validate=True)
        except (ValueError, TypeError):
            continue
        if not blob:
            continue
        # 解出来是一层 minisign 文本 → 说明又被套了一层，递归进去找真签名
        inner = _nested_lines(blob) if depth < 2 else None
        if inner is not None:
            blobs.extend(_decode_candidates(inner, depth + 1))
            continue
        if len(blob) >= 10:
            blobs.append(blob)
    return blobs


def _extract_signature_blob(stdout: str, sig_path: Path) -> bytes:
    """从 `.sig` 文件或命令输出里取出签名二进制。

    CLI 版本不同，输出形态不同（见 `_decode_candidates` 的说明）。
    统一策略：把所有候选都解出来，优先取长度恰好 74 的
    （2 字节算法 + 8 字节 key id + 64 字节签名）。
    """
    lines: list[str] = []
    if sig_path.is_file():
        lines.extend(sig_path.read_text(encoding="utf-8-sig").splitlines())
    lines.extend((stdout or "").splitlines())

    blobs = _decode_candidates(lines)
    exact = [b for b in blobs if len(b) == 74]
    if exact:
        return exact[0]
    coarse = [b for b in blobs if len(b) >= 74]
    if coarse:
        return coarse[0]
    raise SystemExit(
        "无法从签名输出解析出签名（CLI 输出格式可能变了）；"
        f"stdout 前 200 字：{(stdout or '')[:200]!r}"
    )


def main() -> int:
    key = os.environ.get("TAURI_SIGNING_PRIVATE_KEY", "").strip()
    if not key:
        raise SystemExit("TAURI_SIGNING_PRIVATE_KEY 为空 —— 无法签名更新包")

    conf = json.loads(CONF.read_text(encoding="utf-8"))
    pub_text = str(conf.get("plugins", {}).get("updater", {}).get("pubkey", "")).strip()
    if not pub_text:
        raise SystemExit("tauri.conf.json 未配置 plugins.updater.pubkey")

    env = {**os.environ, "TAURI_SIGNING_PRIVATE_KEY": key}

    # ★ P1-23：不再经 shell 拼命令、也不再把口令写进 argv。
    #   · 旧实现在 Windows 上走 shell 拼 `-p "<口令>"`：
    #     口令进命令行 = 进程列表可见 + 会被引号注入改写；
    #   · 现在直接调 node 执行 @tauri-apps/cli 的入口脚本（argv 只含路径），
    #     口令由 CLI 原生支持的 TAURI_SIGNING_PRIVATE_KEY_PASSWORD
    #     环境变量传入（它本就在 os.environ 里，也随 env 传给子进程）。
    node = shutil.which("node")
    if not node:
        raise SystemExit("找不到 node —— 无法调用 tauri CLI 做签名探测")
    cli_js = DESKTOP / "node_modules" / "@tauri-apps" / "cli" / "tauri.js"
    if not cli_js.is_file():
        raise SystemExit(
            f"找不到 {cli_js} —— 请先在 desktop/ 下执行 npm ci"
        )

    with tempfile.TemporaryDirectory() as td:
        probe = Path(td) / "probe.txt"
        probe.write_text("xuandun updater key probe", encoding="utf-8")

        argv = [node, str(cli_js), "signer", "sign", str(probe)]
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

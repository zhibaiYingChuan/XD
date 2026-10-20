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
        if not sig_path.is_file():
            raise SystemExit("签名命令成功但没有产出 .sig 文件")
        sig_lines = sig_path.read_text(encoding="utf-8-sig").splitlines()
        if len(sig_lines) < 2:
            raise SystemExit("签名文件格式异常")
        sig_blob = base64.b64decode(sig_lines[1])

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

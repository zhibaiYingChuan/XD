#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
"""生成 Tauri 自动更新清单 latest.json。

输入：release 工作流里下载下来的 `artifacts/` 目录。
输出：`artifacts/latest.json`，由 action-gh-release 一并上传。

格式（Tauri v2 updater）：
    {
      "version": "0.1.18-alpha",
      "notes": "...",
      "pub_date": "2026-10-20T12:00:00Z",
      "platforms": {
        "windows-x86_64": {"signature": "...", "url": "..."},
        "darwin-aarch64": {"signature": "...", "url": "..."},
        "linux-x86_64":   {"signature": "...", "url": "..."}
      }
    }

★ 为什么必须让脚本失败而不是跳过缺失平台：
   跳过 = 「新版本发了，但那个平台所有旧版本都检查不到更新」，
   而且没有任何报错。Windows / macOS 必须有；Linux 的 AppImage
   是可选产物（linuxdeploy 失败会降级为 warning），缺失时跳过即可。
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "desktop" / "src-tauri" / "Cargo.toml"


def read_version() -> str:
    text = CARGO.read_text(encoding="utf-8")
    m = re.search(
        r"^\[package\][\s\S]*?^version\s*=\s*\"([^\"]+)\"", text, re.M
    )
    if not m:
        raise SystemExit(f"无法从 {CARGO} 读取版本号")
    return m.group(1)


def find_signature(path: Path) -> str | None:
    sig = Path(str(path) + ".sig")
    if not sig.is_file():
        return None
    value = sig.read_text(encoding="utf-8-sig").strip()
    return value or None


def main() -> int:
    art = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
    if not art.is_dir():
        raise SystemExit(f"artifacts 目录不存在: {art}")

    repo = os.environ.get("GITHUB_REPOSITORY", "zhibaiYingChuan/XD")
    tag = os.environ.get("GITHUB_REF_NAME", "")
    if not tag.startswith("v"):
        raise SystemExit(f"当前 ref 不是版本 tag: {tag!r}")

    base = f"https://github.com/{repo}/releases/download/{tag}"
    files = [p for p in art.rglob("*") if p.is_file()]

    platforms: dict[str, dict[str, str]] = {}

    def add(key: str, path: Path, required: bool) -> None:
        signature = find_signature(path)
        if signature is None:
            if required:
                raise SystemExit(
                    f"缺少签名文件 {path.name}.sig —— "
                    "更新包无法验签，检查 createUpdaterArtifacts 与密钥"
                )
            return
        platforms[key] = {
            "signature": signature,
            "url": f"{base}/{quote(path.name)}",
        }

    # Windows：NSIS 安装包（updater 直接执行它）
    exe = [
        p for p in files
        if p.name.endswith(".exe") and not p.name.endswith(".exe.sig")
    ]
    if not exe:
        raise SystemExit("未找到 Windows 安装包（.exe）")
    add("windows-x86_64", exe[0], required=True)

    # macOS：更新包是 .app.tar.gz，不是 .dmg
    mac = [p for p in files if p.name.endswith(".app.tar.gz")]
    if not mac:
        raise SystemExit("未找到 macOS 更新包（.app.tar.gz）")
    add("darwin-aarch64", mac[0], required=True)

    # Linux：AppImage 本身 + 同名 .sig（2026-10-21 实测：Tauri 对 Linux
    #   只产出 `.AppImage.sig`，**不会**产出 `.AppImage.tar.gz`。
    #   之前按 tar.gz 找，Linux 的自动更新永远登记不上。）
    linux = [p for p in files if p.name.endswith(".AppImage")]
    if linux:
        add("linux-x86_64", linux[0], required=False)
    else:
        print("::warning::没有 AppImage 更新包，Linux 自动更新本次不可用", file=sys.stderr)

    payload = {
        "version": read_version(),
        "notes": os.environ.get("RELEASE_NOTES", "见 GitHub Release 说明"),
        "pub_date": _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "platforms": platforms,
    }
    out = art / "latest.json"
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"latest.json 已生成：{', '.join(sorted(platforms))} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

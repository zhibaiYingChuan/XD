#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
"""版本号同步 / 校验。

★ 为什么必须有这个脚本（2026-10-20）
────────────────────────────────────────────────────────────────
版本号此前同时存在于 8 个地方：Cargo.toml、tauri.conf.json、
package.json、pyproject.toml、__init__.py、app.py、Layout.tsx、
tauriShim.ts。发版时靠人记得逐个改 —— 漏一处就会出现
「侧边栏显示 0.1.17、诊断报告写 0.1.18」这类自相矛盾，
而且没有任何检查会拦住它。

现在唯一真实来源是 ``desktop/src-tauri/Cargo.toml`` 的 ``[package].version``，
其余位置由本脚本派生。CI 用 ``--check`` 阻断不一致。

用法：
    python .github/scripts/sync_version.py            # 写入全部位置
    python .github/scripts/sync_version.py --check    # 只校验（不一致退出 1）
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "desktop" / "src-tauri" / "Cargo.toml"
CARGO_LOCK = ROOT / "desktop" / "src-tauri" / "Cargo.lock"

_VERSION_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\d*)?$", re.M
)


def read_ssot() -> str:
    """从 Cargo.toml 的 [package] 段读取版本号（唯一真实来源）。"""
    text = CARGO.read_text(encoding="utf-8")
    m = re.search(
        r"^\[package\][\s\S]*?^version\s*=\s*\"([^\"]+)\"", text, re.M
    )
    if not m:
        raise SystemExit(f"无法从 {CARGO} 读取 [package].version")
    version = m.group(1)
    if not _VERSION_RE.match(version):
        raise SystemExit(
            f"Cargo.toml 版本号格式不合法: {version!r}"
            "（应形如 0.1.18-alpha / 0.1.18）"
        )
    return version


def to_pep440(version: str) -> str:
    """把 0.1.18-alpha 转成 PEP 440 的 0.1.18a0。"""
    m = re.match(r"^(\d+\.\d+\.\d+)-(alpha|beta|rc)(\d*)$", version)
    if not m:
        return version
    tag = {"alpha": "a", "beta": "b", "rc": "rc"}[m.group(2)]
    return f"{m.group(1)}{tag}{m.group(3) or '0'}"


def _replace_json_version(text: str, version: str) -> str:
    """只替换**第一个**顶层 "version" 字段，保留原文件排版。"""
    return re.sub(
        r'("version"\s*:\s*")[^"]+(")',
        lambda m: f"{m.group(1)}{version}{m.group(2)}",
        text,
        count=1,
    )


def _replace_py_version(text: str, version: str) -> str:
    return re.sub(
        r'^__version__\s*=\s*"[^"]+"',
        f'__version__ = "{version}"',
        text,
        count=1,
        flags=re.M,
    )


def _replace_pyproject_version(text: str, version: str) -> str:
    return re.sub(
        r'^version\s*=\s*"[^"]+"',
        f'version = "{to_pep440(version)}"',
        text,
        count=1,
        flags=re.M,
    )


def _replace_lock_version(text: str, version: str) -> str:
    return re.sub(
        r'(\[\[package\]\]\nname = "xuandun-personal"\nversion = ")[^"]+(")',
        lambda m: f"{m.group(1)}{version}{m.group(2)}",
        text,
        count=1,
    )


def _replace_readme_version(text: str, version: str) -> str:
    return re.sub(
        r"(\*\*版本\*\*：v)[0-9A-Za-z.\-]+",
        lambda m: f"{m.group(1)}{version}",
        text,
        count=1,
    )


def build_targets(version: str):
    """返回 [(相对路径, 转换函数)]。转换函数只改版本，不动其他内容。"""
    return [
        ("desktop/src-tauri/tauri.conf.json", _replace_json_version),
        ("desktop/package.json", _replace_json_version),
        ("src/daoti_xuandun_personal/__init__.py", _replace_py_version),
        ("pyproject.toml", _replace_pyproject_version),
        ("desktop/src-tauri/Cargo.lock", _replace_lock_version),
        ("README.md", _replace_readme_version),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="同步/校验项目版本号")
    parser.add_argument(
        "--check", action="store_true", help="只校验，不写文件"
    )
    args = parser.parse_args()

    version = read_ssot()
    problems: list[str] = []
    changed: list[str] = []

    for rel, transform in build_targets(version):
        path = ROOT / rel
        if not path.exists():
            problems.append(f"{rel}: 文件不存在")
            continue
        old = path.read_text(encoding="utf-8")
        new = transform(old, version)
        if new == old:
            continue
        if args.check:
            problems.append(f"{rel}: 版本不是 {version}")
        else:
            # newline="" 保留原文件的换行风格，避免整文件 diff
            path.write_text(new, encoding="utf-8", newline="")
            changed.append(rel)

    if args.check:
        if problems:
            print("版本号不一致（唯一真实来源：Cargo.toml）:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            print(
                "\n修复：python .github/scripts/sync_version.py",
                file=sys.stderr,
            )
            return 1
        print(f"版本一致性检查通过：{version}")
        return 0

    if changed:
        print(f"已同步版本 {version} 到 {len(changed)} 个文件：")
        for c in changed:
            print(f"  - {c}")
    else:
        print(f"版本已一致：{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""版本号 SSOT（Single Source of Truth）同步与校验工具。

以 src-tauri/Cargo.toml 的 version 为唯一可信源，同步到：
  - package.json
  - tauri.conf.json
  - engine_flask.py (health 端点返回的 version)
  - pyproject.toml (Python SDK 版本号)
  - src/daoti_xuandun/__init__.py (__version__)
  - README.md (下载链接与 pip install 命令中的版本号)

使用方式：
  python sync_version.py          # 同步版本号
  python sync_version.py --check  # 仅校验，不修改（CI 门禁用，不一致时退出码 1）

说明：
  - 全部版本号统一以 Cargo.toml 为 SSOT，消除信任债
  - index.html 无版本号字段，跳过
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# 脚本所在目录（desktop/xuandun-desktop/）
SCRIPT_DIR = Path(__file__).resolve().parent
# Cargo.toml 作为 SSOT
CARGO_TOML = SCRIPT_DIR / "src-tauri" / "Cargo.toml"
PACKAGE_JSON = SCRIPT_DIR / "package.json"
TAURI_CONF_JSON = SCRIPT_DIR / "src-tauri" / "tauri.conf.json"
ENGINE_FLASK_PY = SCRIPT_DIR / "engine_flask.py"

# 项目根目录文件
PROJECT_ROOT = SCRIPT_DIR.parent.parent
PYPROJECT_TOML = PROJECT_ROOT / "pyproject.toml"
README_MD = PROJECT_ROOT / "README.md"
# Python SDK 包 __init__.py 中的 __version__
DAOTI_INIT_PY = PROJECT_ROOT / "src" / "daoti_xuandun" / "__init__.py"

# v1.3.3-beta 扩展：docker-compose.yml 镜像标签
DOCKER_COMPOSE = PROJECT_ROOT / "docker-compose.yml"

# v1.3.3-beta 扩展：admin-console 构建注入由 vite.config.ts 自动读取 pyproject.toml，无需手动同步


def read_cargo_version() -> str:
    """从 Cargo.toml 读取版本号（SSOT）。"""
    content = CARGO_TOML.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        raise RuntimeError(f"Cannot find version in {CARGO_TOML}")
    return match.group(1)


def sync_package_json(version: str, check_only: bool) -> bool:
    """同步 package.json 的 version 字段。返回是否有变更。"""
    data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    if data.get("version") == version:
        return False
    if check_only:
        return True
    data["version"] = version
    PACKAGE_JSON.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def sync_tauri_conf(version: str, check_only: bool) -> bool:
    """同步 tauri.conf.json 的 version 字段。返回是否有变更。"""
    data = json.loads(TAURI_CONF_JSON.read_text(encoding="utf-8"))
    if data.get("version") == version:
        return False
    if check_only:
        return True
    data["version"] = version
    TAURI_CONF_JSON.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def sync_engine_flask(version: str, check_only: bool) -> bool:
    """同步 engine_flask.py 中 _ENGINE_VERSION 常量。返回是否有变更。"""
    content = ENGINE_FLASK_PY.read_text(encoding="utf-8")
    # 匹配 _ENGINE_VERSION 常量赋值行（R4 修复后版本单一来源移至此常量）
    # 格式：_ENGINE_VERSION = "1.2.3"
    # 必须锚定 _ENGINE_VERSION = 前缀，避免误匹配文档注释中的版本号
    pattern = r'(_ENGINE_VERSION\s*=\s*")([^"]+)(")'
    match = re.search(pattern, content)
    if not match:
        print(f"WARNING: Cannot find _ENGINE_VERSION pattern in {ENGINE_FLASK_PY}", file=sys.stderr)
        return False
    current = match.group(2)
    if current == version:
        return False
    if check_only:
        return True
    new_content = content[:match.start()] + match.group(1) + version + match.group(3) + content[match.end():]
    ENGINE_FLASK_PY.write_text(new_content, encoding="utf-8")
    return True


def sync_pyproject(version: str, check_only: bool) -> bool:
    """同步 pyproject.toml 的 version 字段。返回是否有变更。"""
    if not PYPROJECT_TOML.exists():
        return False
    content = PYPROJECT_TOML.read_text(encoding="utf-8")
    # 匹配 [project] 段下的 version = "x.x.x"
    pattern = r'(^version\s*=\s*")([^"]+)(")'
    match = re.search(pattern, content, re.MULTILINE)
    if not match:
        return False
    current = match.group(2)
    if current == version:
        return False
    if check_only:
        return True
    new_content = content[:match.start()] + match.group(1) + version + match.group(3) + content[match.end():]
    PYPROJECT_TOML.write_text(new_content, encoding="utf-8")
    return True


def sync_readme(version: str, check_only: bool) -> bool:
    """同步 README.md 中的版本号引用。返回是否有变更。

    覆盖以下模式：
      - XuanDun_1.2.3_x64-setup.exe（下载链接）
      - pip install daoti-xuandun==1.2.3（pip 安装命令）
    """
    if not README_MD.exists():
        return False
    content = README_MD.read_text(encoding="utf-8")
    original = content
    # 匹配 XuanDun_<version>_ 文件名中的版本号
    content = re.sub(r'(XuanDun_)(\d+\.\d+\.\d+)([-\w]*)(_)', rf'\g<1>{version}\g<4>', content)
    # 匹配 daoti-xuandun==<version> pip 安装命令中的版本号
    # 修复：此前正则为 daoti-xuandun==(\d+\.\d+\.\d+)，不含预发布后缀(-beta)，
    # 导致替换时在 -beta 后重复追加后缀（1.3.3-beta-beta），每次 check 都误报不一致。
    # 现用 (\d+\.\d+\.\d+[-\w]*) 捕获完整版本（含 -beta/-rc 等），整体替换。
    content = re.sub(r'(daoti-xuandun==)(\d+\.\d+\.\d+[-\w]*)', rf'\g<1>{version}', content)
    if content == original:
        return False
    if check_only:
        return True
    README_MD.write_text(content, encoding="utf-8")
    return True


def sync_daoti_init(version: str, check_only: bool) -> bool:
    """同步 src/daoti_xuandun/__init__.py 中的 __version__。返回是否有变更。"""
    if not DAOTI_INIT_PY.exists():
        return False
    content = DAOTI_INIT_PY.read_text(encoding="utf-8")
    # 匹配 __version__ = "x.x.x"
    pattern = r'(__version__\s*=\s*")([^"]+)(")'
    match = re.search(pattern, content)
    if not match:
        return False
    current = match.group(2)
    if current == version:
        return False
    if check_only:
        return True
    new_content = content[:match.start()] + match.group(1) + version + match.group(3) + content[match.end():]
    DAOTI_INIT_PY.write_text(new_content, encoding="utf-8")
    return True


def sync_docker_compose(version: str, check_only: bool) -> bool:
    """同步 docker-compose.yml 中的镜像标签版本号。返回是否有变更。"""
    if not DOCKER_COMPOSE.exists():
        return False
    content = DOCKER_COMPOSE.read_text(encoding="utf-8")
    original = content
    # xuandun-gateway:1.3.2 / xuandun-console:1.3.2
    content = re.sub(r'(xuandun-gateway:)\d+\.\d+\.\d+(-\w+)?', rf'\g<1>{version}', content)
    content = re.sub(r'(xuandun-console:)\d+\.\d+\.\d+(-\w+)?', rf'\g<1>{version}', content)
    if content == original:
        return False
    if check_only:
        return True
    DOCKER_COMPOSE.write_text(content, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="版本号 SSOT 同步与校验")
    parser.add_argument("--check", action="store_true", help="仅校验，不修改（CI 门禁用）")
    args = parser.parse_args()

    cargo_version = read_cargo_version()
    print(f"SSOT version (Cargo.toml): {cargo_version}")

    changed = False
    changed |= sync_package_json(cargo_version, args.check)
    changed |= sync_tauri_conf(cargo_version, args.check)
    changed |= sync_engine_flask(cargo_version, args.check)
    changed |= sync_pyproject(cargo_version, args.check)
    changed |= sync_readme(cargo_version, args.check)
    changed |= sync_daoti_init(cargo_version, args.check)
    changed |= sync_docker_compose(cargo_version, args.check)

    if args.check:
        if changed:
            print(f"ERROR: Version mismatch detected! Run 'python sync_version.py' to sync.", file=sys.stderr)
            return 1
        print("OK: All version numbers are consistent across Cargo.toml, package.json, "
              "tauri.conf.json, engine_flask.py, pyproject.toml, README.md, daoti_xuandun/__init__.py.")
        return 0
    else:
        if changed:
            print(f"Synced version to {cargo_version} across all files.")
        else:
            print("All version numbers already consistent.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

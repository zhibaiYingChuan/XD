# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""运行期数据目录解析。

为什么需要这个模块
────────────────────────────────────────────────────────────────
配置、数据库、激活状态、吊销名单原本各自散落着拼
``%LOCALAPPDATA%/com.daoti.xuandun-personal``。稳定版和开发版
因此**共用同一份数据**：开发版跑一次 CDP 测试会改掉用户稳定版的
中转站配置、写入测试日志、污染真实统计。

引入单一入口后，只要设 ``XUANDUN_DATA_DIR`` 就能把整个进程
（引擎 + 桌面端）挪到独立目录，与稳定版彻底隔离。

★ 三处必须用同一套解析（否则隔离是假的）
  · config.py    —— config.json
  · storage/db.py —— xuandun_personal.db
  · license.py / proxy/app.py —— license.json、revoked_jtis.json
任何一处漏改，开发版就会写回稳定版目录，而界面毫无提示。
"""

from __future__ import annotations

import os
from pathlib import Path

#: 稳定版的目录名（也是安装版的默认目录名）。
APP_DIR_NAME = "com.daoti.xuandun-personal"

#: 数据目录覆盖环境变量。设了它，整套数据就与稳定版隔离。
DATA_DIR_ENV = "XUANDUN_DATA_DIR"


def data_dir() -> Path:
    """返回本进程应当读写的用户数据目录。

    优先级：

    1. ``XUANDUN_DATA_DIR``（开发/测试隔离用）
    2. ``%LOCALAPPDATA%/com.daoti.xuandun-personal``（稳定版默认，Windows）
    3. ``~/.config/com.daoti.xuandun-personal``（非 Windows 兜底）
    """
    override = os.getenv(DATA_DIR_ENV)
    if override:
        return Path(override)

    base = os.getenv("LOCALAPPDATA")
    if base:
        return Path(base) / APP_DIR_NAME
    return Path.home() / ".config" / APP_DIR_NAME


def data_file(name: str) -> Path:
    """返回数据目录下的某个文件路径（不创建目录）。"""
    return data_dir() / name
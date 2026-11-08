# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""测试基座：**强制隔离用户的真实数据目录**。

★★ 2026-10-29（第三轮审查 P0-8）为什么要这个文件
────────────────────────────────────────────────────────────────
本轮审查实测到两类「只在别人机器上才能复现」的问题，根因相同：

1. `test_privacy_hardening` 的 fixture 只设了 `XUANDUN_DATA_DIR` 再
   `importlib.reload(paths)`，但 `config.CONFIG_FILE` 是 **import 时固化**
   的路径 —— 用例实际读到的是开发机真实的 `config.json`（连带真实中转站），
   于是 `/v1/chat/completions` 真的向那家发了请求并拿到上游 401：
   同一个用例单独跑绿、整文件跑红。

2. 部分夹具会往 `%LOCALAPPDATA%/com.daoti.xuandun-personal/` 写签发记录
   与日志。测试污染真实用户数据，等于「跑一次测试改一次配置」。

因此这里做一个 autouse 的隔离基座：每个用例都有独立数据目录，
`config.CONFIG_FILE` 一并指向它。用例不需要知道这件事，
也不会因为忘记隔离而互相踩。

★ 注意：本文件只改**路径**，不改任何业务逻辑；
  需要验证「读真实目录」的用例请显式 monkeypatch 回去。
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture(autouse=True)
def _isolate_user_data(tmp_path, monkeypatch):
    """把数据目录与配置文件路径都钉到本用例的临时目录。"""
    data_dir = tmp_path / "userdata"
    data_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("XUANDUN_DATA_DIR", str(data_dir))

    cfg_mod = importlib.import_module("daoti_xuandun_personal.config")
    monkeypatch.setattr(
        cfg_mod, "CONFIG_FILE", data_dir / "config.json", raising=False
    )

    yield

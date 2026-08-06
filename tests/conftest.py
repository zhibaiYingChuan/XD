# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""pytest 全局配置。

测试环境默认在保护模式下运行，禁用观察模式，
确保拦截功能测试不受观察模式放行策略影响。
"""

import pytest

from daoti_xuandun.config import XuanDunConfig


@pytest.fixture(autouse=True)
def disable_observing_mode(monkeypatch):
    """自动禁用观察模式，确保测试在保护模式下运行。

    产品默认启用观察模式（旁听学习），但单元测试需要
    验证拦截功能，因此强制使用保护模式。
    """
    original_init = XuanDunConfig.__init__

    def patched_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.enable_observing_mode = False
        self.enable_builtin_attacks = False

    monkeypatch.setattr(XuanDunConfig, "__init__", patched_init)

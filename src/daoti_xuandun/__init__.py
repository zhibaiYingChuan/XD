# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""道体玄盾 —— 个人版内置护栏层（企业版 ``daoti_xuandun`` 的裁剪子集）。

为什么是裁剪子集
────────────────────────────────────────────────────────────────
企业版完整包含网关、计费、benchmark、integrations 等个人版完全
用不到的模块，且 ``__init__`` 会连带导入 reject_gate(196KB)、
xuandun(102KB) 等重型模块。个人版只需要**输出护栏**这一条链路，
故只保留其最小依赖闭包。详见仓库根目录 GUARDRAIL.md。

本文件刻意**不**照搬企业版的 ``__init__``：那份会 import
``benchmark`` / ``gateway`` / ``integrations`` 下的模块，
而它们不在本目录内，照搬会直接 ImportError。

对外接口与被调用方保持一致
────────────────────────────────────────────────────────────────
个人版 ``verifier._try_load_guardrail()`` 依赖：

    from daoti_xuandun.xuandun import XuanDun
    from daoti_xuandun.config import DefenseLevel, XuanDunConfig

所以这两个名字必须可从包根导入 —— 否则护栏永远加载失败，
而失败是静默的（界面照常显示「防护中」）。
"""

from __future__ import annotations

__version__ = "1.3.5-beta.personal-guardrail"

from daoti_xuandun.config import DefenseLevel, XuanDunConfig
from daoti_xuandun.xuandun import XuanDun

__all__ = [
    "DefenseLevel",
    "XuanDunConfig",
    "XuanDun",
]

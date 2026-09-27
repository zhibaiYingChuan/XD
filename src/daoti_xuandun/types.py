from __future__ import annotations
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

# Implements §2.2 核心数据类型 and §7.2 返回值 ProtectResult — 道体动态活性架构

from dataclasses import dataclass
from enum import Enum

# ── 自定义异常 ──
class RateLimitError(RuntimeError):
    """配额超限异常 — 网关应返回 HTTP 429 Too Many Requests"""
    pass
from typing import Any, Dict, List, Optional, Set, Tuple


import numpy as np

# §2.2 核心数据类型
Vector = np.ndarray          # shape: (hidden_dim,)，float32
Symbol = int                 # 0 .. symbol_table_size-1
SymbolSeq = List[Symbol]


# 门禁决策枚举
class Decision(Enum):
    PASS = "PASS"
    REJECT = "REJECT"


# 时序校验决策枚举
class TimingDecision(Enum):
    PASS = "PASS"
    WARN = "WARN"
    REJECT = "REJECT"


# 信任等级枚举（内生域感知产出）
class TrustLevel(Enum):
    HIGH = "HIGH"          # 与已知原型高度匹配
    MEDIUM = "MEDIUM"      # 在阈值边缘
    LOW = "LOW"            # 距离较远，混沌期候选
    UNKNOWN = "UNKNOWN"    # 全新未知域，需警戒


# §7.2 返回值 ProtectResult
@dataclass
class ProtectResult:
    """XuanDun.protect() 流水线的返回结果。

    Attributes:
        allowed: 是否通过整体防护。
        final_output: 若允许，输出符号序列；否则为 None。
        reject_stage: 拒绝发生的阶段名称。
        timing_distance: 最后阶段的马氏距离。
        trust_level: 内生域感知判定出的信任等级。
        domain_distance: 与最近原型的距离。
        trust_decay_value: 会话级信任度衰减值（初始1.0，每轮按配置衰减，下限为trust_floor）。
        intent_drift_score: 会话级意图漂移分数（当前距离与会话EWMA的σ偏离倍数）。
        intent_drift_detected: 是否检测到意图漂移（分数>配置的sigma阈值且轮数>min_turns）。
    """

    allowed: bool
    final_output: Optional[Any] = None
    reject_stage: Optional[str] = None
    timing_distance: Optional[float] = None
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    domain_distance: Optional[float] = None
    debug_info: Optional[dict] = None
    attack_category: Optional[str] = None
    trust_decay_value: Optional[float] = None
    intent_drift_score: Optional[float] = None
    intent_drift_detected: Optional[bool] = None
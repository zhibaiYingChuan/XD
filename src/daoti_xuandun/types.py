# Implements §2.2 核心数据类型 and §7.2 返回值 ProtectResult — 道体动态活性架构

from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional

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
    """

    allowed: bool
    final_output: Optional[Any] = None
    reject_stage: Optional[str] = None
    timing_distance: Optional[float] = None
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    domain_distance: Optional[float] = None
    debug_info: Optional[dict] = None
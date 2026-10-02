# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""个人版数据契约。

与企业的 `daoti_xuandun.types` 分离：个人版关注「中转站交互」维度的数据，
而企业版关注「模型检测」维度的数据。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

# ══════════════════════════════════════════════════════════════
# 安全级别
# ══════════════════════════════════════════════════════════════


class SecurityLevel(str, Enum):
    """安全级别 — 决定敏感信息处置策略的严格程度。"""

    LENIENT = "lenient"      # 宽松：仅拦截明确危险
    BALANCED = "balanced"    # 均衡（默认）：警告为主，危险阻断
    STRICT = "strict"        # 严格：拦截任何可疑


LEVEL_DESCRIPTIONS: Dict[str, str] = {
    "lenient": "宽松模式：仅拦截明确危险（rm -rf 等），其余仅记录",
    "balanced": "均衡模式（推荐）：API 密钥/身份证/银行卡阻断，手机号/邮箱打码",
    "strict": "严格模式：所有敏感信息全部阻断，任何可疑响应均告警",
}


# ══════════════════════════════════════════════════════════════
# 处置动作
# ══════════════════════════════════════════════════════════════


class Action(str, Enum):
    """处置动作。"""

    PASS = "pass"        # 放行
    REDACT = "redact"    # 打码（替换后继续）
    BLOCK = "block"      # 阻断
    ALERT = "alert"      # 告警（放行但标记可疑）


# ══════════════════════════════════════════════════════════════
# 防护状态（首页状态栏）
# ══════════════════════════════════════════════════════════════


class GuardState(str, Enum):
    """防护状态 — 首页状态栏 5 态。"""

    PROTECTING = "protecting"   # 防护中（绿）
    LEARNING = "learning"       # 学习中（蓝）
    SUSPECT = "suspect"         # 可疑（黄）
    DANGER = "danger"           # 危险（红）
    PAUSED = "paused"           # 已暂停（灰）


STATE_COLORS: Dict[str, str] = {
    "protecting": "#00D4AA",
    "learning": "#2B5FD7",
    "suspect": "#F5A623",
    "danger": "#E54D4D",
    "paused": "#6B7280",
}


# ══════════════════════════════════════════════════════════════
# 日志类型
# ══════════════════════════════════════════════════════════════


class LogType(str, Enum):
    """日志类型。"""

    REQUEST_SANITIZE = "request_sanitize"   # 请求脱敏
    RESPONSE_VERIFY = "response_verify"     # 响应验证
    PROXY_ERROR = "proxy_error"             # 代理错误
    RELAY = "relay"                         # 正常转发


# ══════════════════════════════════════════════════════════════
# 脱敏记录
# ══════════════════════════════════════════════════════════════


@dataclass
class RedactionRecord:
    """单条敏感信息脱敏记录。

    脱敏占位符格式：`⟦XD_{index}⟧`（用数学字母括号避免与原文冲突）
    """

    index: int                        # 占位符编号（用于恢复）
    category: str                     # 敏感类型：api_key/phone/email/idcard/bankcard/custom
    original: str                     # 原始值（★ 仅存于本地 DB，绝不外发）
    redacted: str                     # 打码后的值（发给中转站）
    start: int = 0                    # 在原文中的起始位置
    end: int = 0                      # 在原文中的结束位置
    action: str = Action.REDACT.value  # 该条的实际处置

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def placeholder(index: int) -> str:
        """生成脱敏占位符。"""
        return f"⟦XD_{index}⟧"

    @staticmethod
    def parse_placeholder(text: str) -> Optional[int]:
        """从占位符文本解析出编号，非占位符返回 None。"""
        if not (text.startswith("⟦XD_") and text.endswith("⟧")):
            return None
        try:
            return int(text[5:-1])
        except ValueError:
            return None


@dataclass
class SanitizeResult:
    """请求侧脱敏结果。"""

    sanitized_text: str = ""                       # 脱敏后的文本（发给中转站）
    records: List[RedactionRecord] = field(default_factory=list)  # 脱敏记录
    action: str = Action.PASS.value                # 整体处置
    hit_categories: List[str] = field(default_factory=list)       # 命中的敏感类型
    blocked_reason: Optional[str] = None           # 阻断原因

    @property
    def redaction_count(self) -> int:
        return len(self.records)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanitized_text_length": len(self.sanitized_text),
            "redaction_count": self.redaction_count,
            "action": self.action,
            "hit_categories": self.hit_categories,
            "blocked_reason": self.blocked_reason,
        }


# ══════════════════════════════════════════════════════════════
# 响应验证结果
# ══════════════════════════════════════════════════════════════


@dataclass
class VerificationFinding:
    """单条验证发现项。"""

    category: str          # 触发规则：tool_call_dangerous/system_prompt_inject/length_anomaly/structure_anomaly/hidden_instruction/sensitive_leak
    severity: str         # high/medium/low
    detail: str           # 人类可读描述
    evidence: str = ""    # 证据片段（脱敏后）

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerifyResult:
    """响应侧完整性验证结果。"""

    action: str = Action.PASS.value              # 整体处置
    severity: str = "low"                        # 最高严重程度
    findings: List[VerificationFinding] = field(default_factory=list)
    cleaned_text: Optional[str] = None           # 清洗后的响应（若需处理）
    blocked_reason: Optional[str] = None

    @property
    def is_suspicious(self) -> bool:
        return self.severity in ("high", "medium")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
            "blocked_reason": self.blocked_reason,
        }


# ══════════════════════════════════════════════════════════════
# 日志条目
# ══════════════════════════════════════════════════════════════


@dataclass
class LogEntry:
    """个人版安全日志条目（对应 SQLite logs 表）。"""

    id: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    log_type: str = LogType.RESPONSE_VERIFY.value
    relay_domain: str = ""                    # 中转站域名
    action: str = Action.PASS.value
    severity: str = "low"
    model: str = ""                          # 请求的模型名
    finding_count: int = 0
    summary: str = ""                         # 人类可读摘要
    detail_json: str = ""                     # 详细发现（JSON 字符串）
    text_preview: str = ""                    # 内容预览（脱敏后）
    marked_safe: bool = False                 # 用户手动标记为误报

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def time_str(ts: Optional[float] = None) -> str:
        """格式化为 HH:MM 显示。"""
        import datetime as _dt
        t = ts or time.time()
        return _dt.datetime.fromtimestamp(t).strftime("%H:%M")


# ══════════════════════════════════════════════════════════════
# 中转站信誉
# ══════════════════════════════════════════════════════════════


@dataclass
class RelayReputation:
    """中转站信誉评估结果。"""

    domain: str = ""
    score: int = 100                         # 0-100 信誉分
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_calls: int = 0
    danger_count: int = 0
    suspect_count: int = 0
    avg_latency_ms: float = 0.0
    latency_samples: int = 0
    known_malicious: bool = False            # 命中内置恶意指纹库
    watermark_detected: bool = False         # 检测到中转站水印
    notes: List[str] = field(default_factory=list)
    # ★★ v0.1.0：把「中转站的责任」与「用户自己的操作」分开计数。
    #
    #   实测问题：danger_count 里混着大量**与中转站无关**的事件 ——
    #   19 条全是「响应长度突变」（AI 对话长度天然天差地别，
    #   问「你好」3 字、回一段代码 11000 字），
    #   59 条可疑全是「字符类分布突变」。
    #   这些判的是「你在哪儿提问」，不是「中转站是否可信」，
    #   却扣了中转站的分 —— 用户问了个长问题，
    #   中转站就被扣 20 分。
    #
    #   后果实测：危险 19×20 + 可疑 59×4 = 616 分，
    #   远超满分 100 → 分数长期触底恒为 0，
    #   此后**任何新增风险都看不出来**（都显示 0）。
    #   一个恒为 0 的分数等于没有分数。
    #
    #   所以拆成两组：
    #     relay_danger_count  —— 确实指向中转站的风险（扣分依据）
    #     self_danger_count   —— 用户自己造成的（如把密钥贴进提问）
    #   只有前者进评分。
    relay_danger_count: int = 0
    self_danger_count: int = 0
    relay_suspect_count: int = 0
    self_suspect_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def level(self) -> Literal["safe", "normal", "risky", "malicious"]:
        """信誉等级。"""
        if self.known_malicious:
            return "malicious"
        if self.score >= 80:
            return "safe"
        if self.score >= 50:
            return "normal"
        return "risky"

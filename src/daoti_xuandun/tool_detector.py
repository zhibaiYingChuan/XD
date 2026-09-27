"""MCP/Agent 工具调用意图检测器 — 基于五行生克框架"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .tool_risk_registry import (
    SensitiveTool, RiskCategory, match_tool, get_risk_category_name)


class RiskLevel(Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"


@dataclass
class ToolCallRisk:
    tool_name: str; risk_category: RiskCategory; risk_category_name: str
    inherent_risk: float; intent_amplifier: float; combined_risk: float
    risk_level: RiskLevel; blocked: bool; reason: str
    wuxing_scores: Optional[Dict[str, float]] = None
    intent_attack_signal: float = 0.0


class ToolIntentDetector:
    """MCP/Agent 工具调用意图检测器 — 基于五行生克框架"""

    # 阈值：HIGH=0.82（留余量给正常fetch/写文件等边界场景）
    HIGH_THRESHOLD = 0.82
    MEDIUM_THRESHOLD = 0.40

    def __init__(self, luoshu_mapper=None):
        self._luoshu_mapper = luoshu_mapper
        self._intent_detector = None

    @property
    def intent_detector(self):
        if self._intent_detector is None:
            from .preprocessors import IntentDirectionDetector
            from .luoshu_mapper import LuoshuSymbolMapper
            from .config import XuanDunConfig
            mapper = self._luoshu_mapper
            if mapper is None:
                mapper = LuoshuSymbolMapper(XuanDunConfig())
            self._intent_detector = IntentDirectionDetector(mapper)
        return self._intent_detector

    def evaluate(self, user_input: str, tool_name: str,
                 arguments: Optional[Dict] = None,
                 server_id: Optional[str] = None) -> ToolCallRisk:
        tool = match_tool(tool_name)
        if tool is None:
            return ToolCallRisk(
                tool_name=tool_name, risk_category=RiskCategory.FILE_RW,
                risk_category_name="未注册", inherent_risk=0.0,
                intent_amplifier=1.0, combined_risk=0.0,
                risk_level=RiskLevel.LOW, blocked=False,
                reason=f"未注册 '{tool_name}'，默认放行")

        wuxing_scores = self.intent_detector.detect_directions(user_input)
        attack_signal = self.intent_detector.apply_wuxing(wuxing_scores)
        amplifier = self._compute_amplifier(tool, wuxing_scores, attack_signal, arguments)
        combined = min(1.0, tool.risk_level * amplifier)
        risk_level, blocked, reason = self._determine(tool, combined, attack_signal)

        return ToolCallRisk(
            tool_name=tool_name, risk_category=tool.risk_category,
            risk_category_name=get_risk_category_name(tool.risk_category),
            inherent_risk=tool.risk_level, intent_amplifier=round(amplifier, 2),
            combined_risk=round(combined, 3), risk_level=risk_level,
            blocked=blocked, reason=reason,
            wuxing_scores=wuxing_scores, intent_attack_signal=round(attack_signal, 3))

    def _compute_amplifier(self, tool: SensitiveTool, wuxing_scores: Dict[str, float],
                           attack_signal: float, arguments: Optional[Dict]) -> float:
        tm = wuxing_scores.get("technical_malice", 0.0)
        io = wuxing_scores.get("instruction_override", 0.0)
        sr = wuxing_scores.get("self_referential", 0.0)
        fd = wuxing_scores.get("fact_deviation", 0.0)
        base = 1.0 + attack_signal * 0.5
        cat_boost = 0.0
        if tool.risk_category == RiskCategory.CODE_EXEC:
            cat_boost = tm * 0.5 + io * 0.2
        elif tool.risk_category == RiskCategory.CREDENTIAL:
            cat_boost = sr * 0.4 + io * 0.3
        elif tool.risk_category == RiskCategory.FILE_RW:
            cat_boost = tm * 0.4
        elif tool.risk_category == RiskCategory.NETWORK:
            cat_boost = tm * 0.3 + fd * 0.2
        arg_boost = 0.0
        if arguments:
            for an, rw in tool.argument_risks.items():
                if an in arguments:
                    av = str(arguments[an]).lower()
                    if an in ("path", "url", "destination", "source"):
                        if any(p in av for p in ("/etc/", "/root/", "c:\\windows\\", ".ssh/", ".env", "localhost", "169.254", "metadata")):
                            arg_boost += rw * 0.5
                    if an in ("command", "code", "sql", "args"):
                        if any(p in av for p in ("rm ", "dd ", "mkfs", "chmod 777", "wget ", "curl ", "eval(", "exec(", "__import__", "DROP ", "DELETE ")):
                            arg_boost += rw * 0.6
        return round(base + cat_boost + arg_boost, 2)

    def _determine(self, tool: SensitiveTool, combined_risk: float,
                   attack_signal: float) -> Tuple[RiskLevel, bool, str]:
        cn = get_risk_category_name(tool.risk_category)
        if combined_risk > self.HIGH_THRESHOLD or (attack_signal > 0.5 and tool.risk_level > 0.6):
            return (RiskLevel.HIGH, True, f"高风险{cn} '{tool.name}': 风险={combined_risk:.3f}")
        if combined_risk > self.MEDIUM_THRESHOLD:
            return (RiskLevel.MEDIUM, False, f"中风险{cn} '{tool.name}': 风险={combined_risk:.3f}")
        return (RiskLevel.LOW, False, f"低风险{cn} '{tool.name}': 风险={combined_risk:.3f}")


_tool_detector: Optional[ToolIntentDetector] = None


def get_tool_detector() -> ToolIntentDetector:
    global _tool_detector
    if _tool_detector is None:
        _tool_detector = ToolIntentDetector()
    return _tool_detector


def evaluate_tool_call(user_input: str, tool_name: str,
                       arguments: Optional[Dict] = None,
                       server_id: Optional[str] = None) -> ToolCallRisk:
    return get_tool_detector().evaluate(user_input, tool_name, arguments, server_id)

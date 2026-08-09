from __future__ import annotations
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""输出护栏（Output Guardrail）— 模型输出侧违规内容检测。

玄盾现有能力只覆盖"输入侧"（用户 → 大模型）。输出护栏把防护延伸到
"输出侧"（大模型 → 用户），形成双向闭环：

    用户输入 → 玄盾输入检测 → 大模型 → 玄盾输出检测 → 返回用户

为什么需要输出侧：
- 攻击者可以编出无限种方式绕过输入检测，但模型输出的违规内容
  （系统提示词、密钥、PII、越狱输出、歧视暴力等）终究是违规的。
- 检测"违规内容"比检测"攻击意图"更可靠。

技术复用：
- 复用洛书映射器的 encode（语言无关的 Unicode 码点散列编码），
  但使用输出侧独立的原型库（安全/违规），与输入侧原型物理隔离，
  避免相互污染（计划文档节 9.5 独立评测集 test_outputs_v1）。
- 三级处置（计划文档节 9.1）：
    high   → 拦截（丢弃输出，返回通用安全提示）
    medium → 打码替换（resolve 时用 [REDACTED] 替换） + 告警
    low    → 仅告警，不中断
- 安全距离豁免：正常输出（医学术语/代码示例）若与安全原型高度接近，
  优先放行，防止反向误报伤害正常业务。

降级策略：任何检测异常（编码失败、原型异常）都降级为"放行 + 告警"，
绝不阻断正常业务（计划文档 5.1 兜底）。
"""

import hashlib
import logging
import re
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

import numpy as np

from daoti_xuandun.config import XuanDunConfig
from daoti_xuandun.preprocessors import deobfuscate_keywords
from daoti_xuandun.luoshu_mapper import LuoshuSymbolMapper

logger = logging.getLogger("xuandun.output_guardrail")


@dataclass
class OutputDecision:
    """输出护栏检测结果。

    Attributes:
        allowed: 输出是否放行（False 表示高危被拦截）。
        risk_level: "high" / "medium" / "low" / "pass"。
        action: "block" / "redact" / "alert" / "pass"。
        reason: 人类可读的判定原因（脱敏，不含参数细节）。
        violation_distance: 与最近违规原型的距离（越小越危险）。
        safe_distance: 与最近安全原型的距离（越小越安全）。
        degraded: 是否因异常降级放行（True 表示告警但放行）。
    """
    allowed: bool = True
    risk_level: str = "pass"
    action: str = "pass"
    reason: str = ""
    violation_distance: Optional[float] = None
    safe_distance: Optional[float] = None
    degraded: bool = False


class OutputPatternTracker:
    """输出模式异常检测器（L3） — 追踪会话输出长度/结构突变。

    某些攻击（如角色扮演越狱）的输出内容本身可能不包含敏感词，
    但输出模式异常——过长、格式异常、结构突变。

    复用时序校验的异常检测机制，追踪会话输出模式：
    - 输出长度突变：长度 > 历史均值 + 3σ
    - 输出结构突变：结构特征向量距离 > 阈值
    - 输出频率突变：短时间内连续多次输出
    """

    def __init__(self, window_size: int = 10, sigma_threshold: float = 3.0):
        """初始化输出模式追踪器。

        Args:
            window_size: 历史输出窗口大小。
            sigma_threshold: 长度突变的标准差倍数阈值。
        """
        self._window_size = window_size
        self._sigma_threshold = sigma_threshold
        # 每个会话的输出长度历史
        self._session_lengths: dict = {}

    def update(self, session_id: str, length: int) -> None:
        """记录一轮的输出长度。

        Args:
            session_id: 会话标识符。
            length: 输出文本长度。
        """
        if session_id not in self._session_lengths:
            self._session_lengths[session_id] = deque(maxlen=self._window_size)
        self._session_lengths[session_id].append(length)

    def is_length_anomaly(self, session_id: str, length: int) -> bool:
        """判断输出长度是否异常（超过均值 + Nσ）。

        Args:
            session_id: 会话标识符。
            length: 当前输出长度。

        Returns:
            True 如果长度异常，False 如果正常或历史不足。
        """
        if session_id not in self._session_lengths:
            return False
        history = list(self._session_lengths[session_id])
        if len(history) < 3:
            # 历史不足3次，无法建立基线
            return False
        mean_len = float(np.mean(history))
        std_len = float(np.std(history))
        if std_len < 1e-8:
            # 标准差为0（所有输出长度相同），阈值设为均值的2倍
            return length > mean_len * 2
        return length > mean_len + self._sigma_threshold * std_len

    def get_length_stats(self, session_id: str) -> dict:
        """返回指定会话的长度统计信息。"""
        if session_id not in self._session_lengths:
            return {"mean": 0.0, "std": 0.0, "count": 0}
        history = list(self._session_lengths[session_id])
        return {
            "mean": float(np.mean(history)) if history else 0.0,
            "std": float(np.std(history)) if history else 0.0,
            "count": len(history),
        }

    def clear(self, session_id: str) -> None:
        """清除指定会话的输出历史。"""
        self._session_lengths.pop(session_id, None)


class OutputGuardrail:
    """输出护栏 — 复用洛书编码，输出侧独立原型库，三级处置。

    设计要点：
    1. 内部持有独立的 LuoshuSymbolMapper，仅复用其语言无关 encode，
       不共享输入侧的原型集合（safe_prototypes / attack_prototypes）。
    2. 输出侧维护两套原型：违规原型（违规内容）与安全原型（正常输出）。
    3. 三级处置阈值全部来自 config，禁止硬编码（项目硬约束）。
    """

    def __init__(self, config: XuanDunConfig):
        self.config = config
        self._luoshu = LuoshuSymbolMapper(config)
        # 输出侧违规原型（与输入侧 attack_prototypes 物理隔离）
        self._violation_prototypes: List[np.ndarray] = []
        # 输出侧安全原型（与输入侧 safe_prototypes 物理隔离）
        self._safe_prototypes: List[np.ndarray] = []
        # 违规原型去重计数（防原型洪水）
        self._violation_fingerprint_counter: Counter = Counter()
        self._violation_dedup_threshold = 0.95
        self._violation_max_per_cluster = 3
        # 统计
        self._total_checks = 0
        self._total_blocked = 0
        self._total_redacted = 0
        self._total_alerted = 0
        # 时间序列桶（按分钟聚合，供 /output/stats/timeseries 趋势展示）
        # 引擎侧内存采集：重启即清空，属准实时视图，不持久化
        self._minute_buckets: "OrderedDict[str, dict]" = OrderedDict()
        self._max_minute_buckets = 20000
        # 最近处置记录（脱敏，供 /output/history 展示）
        self._history: "deque[dict]" = deque(maxlen=200)

        # ── L3：输出模式异常检测器 ──
        # 追踪会话输出长度历史，检测长度突变异常
        self._pattern_tracker = OutputPatternTracker()

        # ── L2：输出语义方向关键词模式 ──
        # 泄露方向：输出内容包含系统提示/内部配置/指令泄露
        self._leak_patterns = [
            re.compile(r"system[_\s]*prompt|系统提示词?|系统指令", re.IGNORECASE),
            re.compile(r"(my|your|these|the)\s+(instructions?|rules?|guidelines?|directives?)|"
                       r"我的(指令|规则|内部指令)|你的(指令|规则|内部指令)",
                       re.IGNORECASE),
            re.compile(r"(I\s+am|I\s+was|you\s+are|you're)\s+(an?\s+)?(AI|programmed|told|instructed)|"
                       r"我是一个AI|我是人工智能|你是一个AI|我被(告知|设定|编程)",
                       re.IGNORECASE),
            re.compile(r"(my|your)\s+(configuration|config|internal|secret|pre-prompt|system\s+context|tool[_\s]?schema)|"
                       r"我的(配置|内部|密钥)|你的(配置|内部|密钥)",
                       re.IGNORECASE),
            re.compile(r"operating\s+(instructions|directives|parameters)|操作(指令|参数)", re.IGNORECASE),
        ]
        # 违规方向：输出内容包含攻击/暴力/违法/歧视等
        self._violation_direction_patterns = [
            re.compile(r"hack|crack|exploit|vulnerability|malware|phishing|backdoor|trojan|"
                       r"payload|bypass|credential|ransomware|keylogger|shellcode",
                       re.IGNORECASE),
            re.compile(r"入侵|漏洞利用|恶意软件|后门|木马|钓鱼|绕过|凭证|勒索|键盘记录|"
                       r"攻击.{0,8}(?:系统|网站|服务器|网络|破解|入侵|他人|对方|目标)|"
                       r"(?:实施|发动|发起|进行).{0,4}攻击",
                       re.IGNORECASE),
            re.compile(r"how\s+to\s+(steal|hack|break|bypass|exploit|create|make)|"
                       r"(to\s+)?(make|create)\s+(a\s+)?(bomb|weapon|malware|backdoor)|"
                       r"如何(入侵|攻击|窃取|绕过|制作|制造)",
                       re.IGNORECASE),
            re.compile(r"(bomb|weapon|poison|drug)\s+(recipe|making|synthesis|method)|"
                       r"(make|create|mix).{0,20}(bomb|weapon|poison|drug)",
                       re.IGNORECASE),
            re.compile(r"(制作|制造).{0,10}(炸弹|武器|毒药|毒品)|"
                       r"(炸弹|武器|毒药|毒品).{0,10}(制作|制造)",
                       re.IGNORECASE),
            re.compile(r"discrim|racist|hate\s+speech|种族歧视|仇恨言论", re.IGNORECASE),
        ]

    # ── 统计采集（时间序列 + 处置记录，脱敏） ──

    def _now_minute_key(self) -> str:
        return datetime.now().strftime("%Y-%m-%dT%H:%M")

    def _mask_preview(self, text: str, max_len: int = 30) -> str:
        """生成脱敏预览：截断 + 屏蔽明显的邮箱/手机号/长数字串，避免泄露模型输出内容。"""
        if not text:
            return ""
        masked = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", "[EMAIL]", text)
        masked = re.sub(r"1[3-9]\d{9}", "[PHONE]", masked)
        masked = re.sub(r"\d{8,}", "[NUM]", masked)
        return masked[:max_len]

    def _record_check(self, action: str, risk_level: str, reason: str, text: Optional[str]):
        """记录一次输出处置：更新分钟桶计数 + 追加处置历史（脱敏）。"""
        key = self._now_minute_key()
        bucket = self._minute_buckets.get(key)
        if bucket is None:
            # 清理超龄桶，防止内存无限增长
            while len(self._minute_buckets) >= self._max_minute_buckets:
                self._minute_buckets.popitem(last=False)
            bucket = {"checked": 0, "blocked": 0, "redacted": 0, "alerted": 0}
            self._minute_buckets[key] = bucket
        bucket["checked"] += 1
        if action == "block":
            bucket["blocked"] += 1
        elif action == "redact":
            bucket["redacted"] += 1
        elif action == "alert":
            bucket["alerted"] += 1

        # 仅记录"有处置动作"的历史（pass 不占历史，避免刷屏）
        if action in ("block", "redact", "alert"):
            self._history.append({
                "time": datetime.now().isoformat(timespec="seconds"),
                "action": action,
                "risk_level": risk_level,
                "reason": reason,
                "preview": self._mask_preview(text or ""),
            })

    def get_history(self, limit: int = 20) -> list:
        """返回最近处置记录（新的在前）。"""
        items = list(self._history)
        items.reverse()
        return items[:max(1, min(limit, 200))]

    def get_trend(self, granularity: str = "hour", start: Optional[str] = None,
                  end: Optional[str] = None) -> list:
        """返回时间序列处置趋势点。

        granularity: minute / hour / day，控制聚合桶大小。
        start/end: ISO 时间字符串（含毫秒），缺省则取全部采集范围。
        返回 [{time, checked, blocked, redacted, alerted}, ...]（按时间升序）。
        """
        try:
            start_dt = datetime.fromisoformat(start) if start else None
        except ValueError:
            start_dt = None
        try:
            end_dt = datetime.fromisoformat(end) if end else None
        except ValueError:
            end_dt = None

        if not self._minute_buckets:
            return []

        # 确定聚合粒度对应的分钟数
        gran_minutes = {"minute": 1, "hour": 60, "day": 1440}.get(granularity, 60)

        # 建立 分钟桶 → (聚合键, 聚合起始时间)
        aggregated: "OrderedDict[str, dict]" = OrderedDict()
        for key, b in self._minute_buckets.items():
            if start_dt and key < start_dt.strftime("%Y-%m-%dT%H:%M"):
                continue
            if end_dt and key > end_dt.strftime("%Y-%m-%dT%H:%M"):
                continue
            try:
                dt = datetime.strptime(key, "%Y-%m-%dT%H:%M")
            except ValueError:
                continue
            # 对齐到聚合桶起点
            total_min = int(dt.timestamp()) // 60
            bucket_start = total_min - (total_min % gran_minutes)
            agg_dt = datetime.fromtimestamp(bucket_start * 60)
            agg_key = agg_dt.strftime("%Y-%m-%dT%H:%M")
            agg = aggregated.get(agg_key)
            if agg is None:
                agg = {"checked": 0, "blocked": 0, "redacted": 0, "alerted": 0}
                aggregated[agg_key] = agg
            agg["checked"] += b["checked"]
            agg["blocked"] += b["blocked"]
            agg["redacted"] += b["redacted"]
            agg["alerted"] += b["alerted"]

        return [
            {
                "time": k,
                "checked": v["checked"],
                "blocked": v["blocked"],
                "redacted": v["redacted"],
                "alerted": v["alerted"],
            }
            for k, v in aggregated.items()
        ]

    # ── 原型学习（供引擎 warmup / 在线学习调用） ──

    def learn_attack_output(self, text: str):
        """将违规输出内容加入输出侧违规原型（带去重和频率门限）。"""
        if not text or len(text) < 2:
            return
        try:
            state = self._encode(text)
        except Exception as e:
            logger.warning("learn_attack_output encode failed: %s", e)
            return
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)

        if self._violation_prototypes:
            protos = np.array(self._violation_prototypes, dtype=np.float32)
            norms = np.linalg.norm(protos, axis=1, keepdims=True)
            norms = np.maximum(norms, 1e-8)
            sims = (protos / norms) @ state_norm
            max_sim = float(np.max(sims))
            if max_sim > self._violation_dedup_threshold:
                best_idx = int(np.argmax(sims))
                fp = self._fingerprint(self._violation_prototypes[best_idx])
                self._violation_fingerprint_counter[fp] += 1
                if self._violation_fingerprint_counter[fp] >= self._violation_max_per_cluster:
                    return

        self._violation_prototypes.append(state_176.copy())
        fp = self._fingerprint(state_176)
        self._violation_fingerprint_counter[fp] += 1

        max_size = getattr(self.config, "output_guardrail_prototype_max", 256)
        if len(self._violation_prototypes) > max_size:
            removed = self._violation_prototypes.pop(0)
            rfp = self._fingerprint(removed)
            self._violation_fingerprint_counter[rfp] = max(
                0, self._violation_fingerprint_counter[rfp] - 1
            )
            if self._violation_fingerprint_counter[rfp] == 0:
                del self._violation_fingerprint_counter[rfp]

    def learn_safe_output(self, text: str):
        """将正常输出内容加入输出侧安全原型（带去重 + 抗毒化）。

        抗毒化（全面审查发现）：若待学习文本与违规原型高度相似，视为
        "伪装安全的违规输出"，拒绝学习。否则安全原型库会被污染，导致
        后续违规输出因 safe_dist 变小而被安全豁免放行，击穿第2层兜底。
        """
        if not text or len(text) < 2:
            return
        try:
            state = self._encode(text)
        except Exception as e:
            logger.warning("learn_safe_output encode failed: %s", e)
            return
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)

        # 抗毒化门：与已有违规原型高度相似 → 拒绝学习为安全原型
        if self._violation_prototypes:
            vprotos = np.array(self._violation_prototypes, dtype=np.float32)
            vnorms = np.linalg.norm(vprotos, axis=1, keepdims=True)
            vnorms = np.maximum(vnorms, 1e-8)
            vsims = (vprotos / vnorms) @ state_norm
            if float(np.max(vsims)) > 0.85:
                return

        if self._safe_prototypes:
            protos = np.array(self._safe_prototypes, dtype=np.float32)
            norms = np.linalg.norm(protos, axis=1, keepdims=True)
            norms = np.maximum(norms, 1e-8)
            sims = (protos / norms) @ state_norm
            if float(np.max(sims)) > self._violation_dedup_threshold:
                return

        self._safe_prototypes.append(state_176.copy())
        max_size = getattr(self.config, "output_guardrail_prototype_max", 256)
        if len(self._safe_prototypes) > max_size:
            self._safe_prototypes.pop(0)

    def warmup(self, safe_texts: Optional[list] = None,
               violation_texts: Optional[list] = None):
        """批量预热输出侧原型库（供引擎初始化 / 评测调用）。"""
        if safe_texts:
            for t in safe_texts:
                self.learn_safe_output(t)
        if violation_texts:
            for t in violation_texts:
                self.learn_attack_output(t)

    # ── 核心检测 ──

    # 允许在运行期动态调校的输出护栏参数白名单（key → 类型）。
    # 由引擎 /output/config 端点调用，禁止超出白名单的任意属性写入。
    _RUNTIME_CONFIG_WHITELIST = {
        "enable_output_guardrail": bool,
        "output_guardrail_high_threshold": float,
        "output_guardrail_medium_threshold": float,
        "output_guardrail_low_threshold": float,
        "output_guardrail_safe_exempt": float,
        "output_guardrail_rule_block_signal": float,
        "output_guardrail_rule_medium_signal": float,
        "output_guardrail_redact_token": str,
    }

    def update_config(self, **kwargs) -> dict:
        """运行期更新输出护栏配置（由引擎 /output/config 端点调用）。

        仅允许更新白名单内的可调参数；非法键被忽略；类型按白名单强制转换。
        返回更新后白名单内全部参数的生效快照，供上层回显。
        """
        updated = {}
        for key, typ in self._RUNTIME_CONFIG_WHITELIST.items():
            if key in kwargs:
                try:
                    setattr(self.config, key, typ(kwargs[key]))
                    updated[key] = kwargs[key]
                except (TypeError, ValueError):
                    logger.warning("output/config invalid value for %s: %r",
                                   key, kwargs[key])
        snapshot = {k: getattr(self.config, k) for k in self._RUNTIME_CONFIG_WHITELIST}
        snapshot.update(updated)
        return snapshot

    def check_output(self, text: Optional[str],
                     session_state: Optional[dict] = None,
                     session_id: str = "default") -> OutputDecision:
        """检测模型输出文本是否含违规内容。

        三级处置（阈值来自 config）：
            违规距离 < high_threshold   → 拦截（allowed=False）
            违规距离 < medium_threshold → 打码（action=redact）
            违规距离 < low_threshold    → 仅告警（action=alert）
        安全距离 < safe_exempt          → 优先放行（防误报）

        输入-输出状态共享：当 session_state 表明输入侧信任度低时，
        所有检测阈值自动降低（更严格），形成双向闭环。

        Args:
            text: 模型输出的原始文本。
            session_state: 输入侧会话状态（可选），包含：
                trust_decay_value: 信任度 [0, 1]
                boundary_residence_alert: 是否边界驻留告警
                intent_drift_detected: 是否意图漂移

        任何异常 → 降级放行 + 告警（绝不断服务）。
        """
        if not self.config.enable_output_guardrail:
            return OutputDecision(allowed=True, risk_level="pass",
                                  action="pass", reason="输出护栏未启用")
        if not text or not text.strip():
            return OutputDecision(allowed=True, risk_level="pass",
                                  action="pass", reason="空输出")

        self._total_checks += 1
        try:
            rule_signal = self._compute_rule_signal(text)
            state = self._encode(text)
            violation_dist = self._compute_violation_distance(state)
            safe_dist = self._compute_safe_distance(state)
        except Exception as e:
            # 降级：检测异常时不阻断业务，仅告警
            logger.error("check_output degraded (allow): %s", e)
            self._total_alerted += 1
            self._record_check("alert", "low", "输出检测异常，已降级放行", text)
            return OutputDecision(
                allowed=True, risk_level="low", action="alert",
                reason="输出检测异常，已降级放行",
                degraded=True,
            )

        high_thr = float(self.config.output_guardrail_high_threshold)
        medium_thr = float(self.config.output_guardrail_medium_threshold)
        low_thr = float(self.config.output_guardrail_low_threshold)
        safe_exempt = float(self.config.output_guardrail_safe_exempt)
        block_signal = float(self.config.output_guardrail_rule_block_signal)
        medium_signal = float(self.config.output_guardrail_rule_medium_signal)

        # ── 输入-输出状态共享：根据输入侧会话状态调整阈值 ──
        # 低信任会话 → 阈值降低 50%（更严格）
        # 边界驻留告警 → 阈值降低 50%
        # 意图漂移检测 → 阈值降低 30%
        if session_state is not None:
            trust_val = float(session_state.get("trust_decay_value", 1.0))
            if trust_val < 0.5:
                high_thr *= 0.5
                medium_thr *= 0.5
                low_thr *= 0.5
                safe_exempt *= 0.5
            if session_state.get("boundary_residence_alert", False):
                high_thr *= 0.5
                medium_thr *= 0.5
                low_thr *= 0.5
            if session_state.get("intent_drift_detected", False):
                high_thr *= 0.7
                medium_thr *= 0.7
                low_thr *= 0.7

        # 安全距离豁免：与安全原型高度接近 且 无违规模式信号 且 不接近违规原型 → 放行（防误报）
        # 关键修复（全面审查发现）：豁免必须与违规距离交叉验证。
        #   旧逻辑只看 safe_dist，不看 violation_dist——若输出同时接近安全原型与违规原型
        #   （模棱两可，或安全原型库被"伪装安全的违规输出"污染），会被错误豁免放行，
        #   攻击者可借"正常开场白 + 有害内容"（如"可以，以下是 rm -rf / 的命令"）绕过。
        #   现要求三者同时满足才放行：无违规模式信号 + 安全距离近 + 不接近违规原型。
        if (rule_signal < medium_signal
                and safe_dist is not None and safe_dist < safe_exempt
                and (violation_dist is None or violation_dist >= high_thr)):
            self._record_check("pass", "pass", "输出与安全原型高度接近", text)
            return OutputDecision(
                allowed=True, risk_level="pass", action="pass",
                reason="输出与安全原型高度接近",
                violation_distance=round(violation_dist, 4) if violation_dist is not None else None,
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )

        # 主判定：违规模式信号（规则层，识别明确违规特征）
        if rule_signal >= block_signal:
            self._total_blocked += 1
            self._record_check("block", "high", "输出内容命中高危违规模式，已拦截", text)
            return OutputDecision(
                allowed=False, risk_level="high", action="block",
                reason="输出内容命中高危违规模式，已拦截",
                violation_distance=round(violation_dist, 4) if violation_dist is not None else None,
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )
        if rule_signal >= medium_signal:
            self._total_redacted += 1
            self._record_check("redact", "medium", "输出内容命中敏感模式，已打码", text)
            return OutputDecision(
                allowed=True, risk_level="medium", action="redact",
                reason="输出内容命中敏感模式，已打码",
                violation_distance=round(violation_dist, 4) if violation_dist is not None else None,
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )

        # 辅助判定：洛书语义距离（无规则信号时，兜底语义近似违规）
        if violation_dist is not None and violation_dist < high_thr:
            self._total_blocked += 1
            self._record_check("block", "high", "输出内容与违规原型高度匹配，已拦截", text)
            return OutputDecision(
                allowed=False, risk_level="high", action="block",
                reason="输出内容与违规原型高度匹配，已拦截",
                violation_distance=round(violation_dist, 4),
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )
        if rule_signal > 0.0 and violation_dist is not None and violation_dist < medium_thr:
            self._total_redacted += 1
            self._record_check("redact", "medium", "输出内容疑似敏感，已打码", text)
            return OutputDecision(
                allowed=True, risk_level="medium", action="redact",
                reason="输出内容疑似敏感，已打码",
                violation_distance=round(violation_dist, 4),
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )
        if violation_dist is not None and violation_dist < low_thr:
            self._total_alerted += 1
            self._record_check("alert", "low", "输出内容疑似违规，已告警", text)
            return OutputDecision(
                allowed=True, risk_level="low", action="alert",
                reason="输出内容疑似违规，已告警",
                violation_distance=round(violation_dist, 4),
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )

        # ── L2：输出语义方向检测 ──
        # 在 L1 规则检测未触发时，L2 补充检测输出语义方向
        leak_score = self._compute_leak_score(text)
        violation_dir_score = self._compute_violation_direction_score(text)

        # 输入-输出状态继承：阈值根据输入侧会话状态动态调整
        # | 输入侧状态              | 输出侧阈值调整 |
        # |------------------------|----------------|
        # | trust < 0.3            | × 0.3          |
        # | trust < 0.5            | × 0.5          |
        # | boundary_residence_alert | × 0.5        |
        # | query_internal_score > 0.7 | × 0.4       |
        leak_threshold = 0.5
        violation_threshold = 0.5
        if session_state is not None:
            trust_val = float(session_state.get("trust_decay_value", 1.0))
            if trust_val < 0.3:
                leak_threshold *= 0.3
                violation_threshold *= 0.3
            elif trust_val < 0.5:
                leak_threshold *= 0.5
                violation_threshold *= 0.5
            if session_state.get("boundary_residence_alert", False):
                leak_threshold *= 0.5
                violation_threshold *= 0.5
            # 自指问句高分 → 输出侧更严格
            qis = float(session_state.get("query_internal_score", 0.0))
            if qis > 0.7:
                leak_threshold *= 0.4
                violation_threshold *= 0.4
            if session_state.get("intent_drift_detected", False):
                leak_threshold *= 0.5
                violation_threshold *= 0.5

        if leak_score >= leak_threshold:
            self._total_blocked += 1
            self._record_check("block", "high", "输出内容包含系统信息泄露方向，已拦截", text)
            return OutputDecision(
                allowed=False, risk_level="high", action="block",
                reason="输出内容包含系统信息泄露方向，已拦截",
                violation_distance=round(violation_dist, 4) if violation_dist is not None else None,
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )
        if violation_dir_score >= violation_threshold:
            self._total_blocked += 1
            self._record_check("block", "high", "输出内容包含违规语义方向，已拦截", text)
            return OutputDecision(
                allowed=False, risk_level="high", action="block",
                reason="输出内容包含违规语义方向，已拦截",
                violation_distance=round(violation_dist, 4) if violation_dist is not None else None,
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )

        # ── L3：输出模式异常检测 ──
        # 追踪输出长度突变，当输入侧边界驻留告警时阈值更严格
        text_len = len(text) if text else 0
        self._pattern_tracker.update(session_id, text_len)
        is_len_anomaly = self._pattern_tracker.is_length_anomaly(session_id, text_len)
        if is_len_anomaly:
            self._total_alerted += 1
            self._record_check("alert", "low", "输出长度异常突变，已告警", text)
            return OutputDecision(
                allowed=True, risk_level="low", action="alert",
                reason="输出长度异常突变，已告警",
                violation_distance=round(violation_dist, 4) if violation_dist is not None else None,
                safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
            )

        self._record_check("pass", "pass", "输出内容正常", text)
        return OutputDecision(
            allowed=True, risk_level="pass", action="pass",
            reason="输出内容正常",
            violation_distance=round(violation_dist, 4) if violation_dist is not None else None,
            safe_distance=round(safe_dist, 4) if safe_dist is not None else None,
        )

    # ── 处置辅助 ──

    # 片段级打码：可精确定位的敏感片段类型（PII/凭据/内部机密标记）。
    # 命中这些正则时仅替换对应片段为占位符，保留其余上下文。
    # 仅供输出侧打码定位使用，与 _HIGH/_MEDIUM_RULE_PATTERNS 的判定职责分离。
    # 编译一次，避免每次打码重复编译。
    _SENSITIVE_FRAGMENT_PATTERNS = [
        re.compile(r"\b\d{17}[\dXx]\b"),                                       # 身份证号
        re.compile(r"1[3-9]\d{9}"),                                            # 手机号
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),   # 邮箱
        re.compile(r"[sS][kK]-[A-Za-z0-9\-]{16,}"),                            # OpenAI 风格密钥
        re.compile(r"ghp_\S{20,}|glpat-\S{10,}|AKIA[A-Za-z0-9]{12,}"),         # GitHub/GitLab/AWS
        re.compile(r"Bearer\s+\S{20,}"),                                       # Bearer token
        re.compile(
            r"(api[_-]?key|secret[_-]?key|password|access_key|secret_key|"
            r"root_password|admin_password|db_password|sa_password|redis_password)"
            r"\s*[:=]\s*\S{4,}",
            re.IGNORECASE,
        ),                                                                     # 凭据赋值
        re.compile(r"(mysql|postgres|redis|mongodb)://\S{4,}:\S{4,}@"),        # 数据库连接串
        re.compile(r"(username|user_id|account)\s*[:=]\s*\S{4,}", re.IGNORECASE),  # 账号
        re.compile(
            r"(内部|机密|confidential|top\s*secret).{0,15}"
            r"(配置|文档|系统|网络|服务器|密钥|token|账号|密码|连接串)",
            re.IGNORECASE,
        ),                                                                     # 内部机密标记
    ]

    def _redact_fragments(self, text: str, token: str) -> str:
        """片段级打码：仅替换命中的敏感片段为占位符，保留其余上下文。

        流程：
        1. 用敏感片段正则扫描文本，收集所有命中区间；
        2. 合并重叠/相邻区间，避免重复打码和占位符连排；
        3. 按区间重建文本，未命中部分原样保留。
        若完全无法定位片段（如语义判定的打码），则整体打码兜底。
        """
        if not text:
            return text
        spans: list = []
        for pat in self._SENSITIVE_FRAGMENT_PATTERNS:
            for m in pat.finditer(text):
                spans.append(m.span())
        if not spans:
            # 无法定位具体片段（多为语义距离触发的打码），整体打码兜底
            return token
        # 合并重叠/相邻区间
        spans.sort()
        merged: list = []
        for lo, hi in spans:
            if merged and lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        # 重建文本
        parts = []
        last = 0
        for lo, hi in merged:
            if lo > last:
                parts.append(text[last:lo])
            parts.append(token)
            last = hi
        if last < len(text):
            parts.append(text[last:])
        return "".join(parts)

    def resolve_output(self, text: str, decision: OutputDecision) -> str:
        """根据处置决策返回最终输出文本。

        - block：返回通用安全提示（不泄露原始内容）
        - redact：片段级打码——仅替换命中的敏感片段为 [REDACTED]，
          保留其余上下文；无法定位片段时退化为整体打码兜底
        - alert / pass：原样返回
        """
        if not decision.allowed:
            return "内容因涉及敏感信息被安全策略拦截，请查看帮助中心了解详情。"
        if decision.action == "redact":
            token = getattr(self.config, "output_guardrail_redact_token", "[REDACTED]")
            return self._redact_fragments(text, token)
        return text

    # ── 距离计算（复用洛书映射器内部语义） ──

    def _encode(self, text: str) -> np.ndarray:
        """复用洛书映射器的语言无关编码。"""
        return self._luoshu.encode(text)

    def _to_native(self, state: np.ndarray) -> np.ndarray:
        """还原为 176 维洛书空间。"""
        if self._luoshu.state_dim >= self._luoshu.native_dim:
            return state[:self._luoshu.native_dim].copy().astype(np.float32)
        pseudo_inv = self._luoshu._proj.T
        return (pseudo_inv @ state).astype(np.float32)

    def _normalize(self, vec: np.ndarray) -> np.ndarray:
        """向量归一化（模长接近 0 时返回原向量，避免除零）。"""
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            return vec / norm
        return vec.astype(np.float32)

    # ── 违规模式信号（规则检测，与洛书语义距离融合） ──
    # 洛书空间距离对"系统提示词/密钥/指令篡改"这类内容区分度有限，
    # 因此叠加基于正则与特征词的模式信号。规则作为"种子特征"，帮助
    # 输出侧违规原型更快收敛，并兜底小样本场景。编译一次，避免每次匹配重复编译。

    # 高危模式（命中 → 信号 1.0）：明确指向系统提示词/越狱/密钥/仇恨暴力/危险指令
    _HIGH_RULE_PATTERNS = [
        # 系统提示词/初始指令泄露
        re.compile(r"系统提示词|system[_\s]*prompt|系统指令|system[_\s]*instruction|"
                   r"初始指令|初始化指令|初始化消息|系统消息|系统配置|系统级指令|"
                   r"系统提示|启动指令|指令模板|hidden\s*system\s*message|"
                   r"System\s*:\s*You\s+are",
                   re.IGNORECASE),
        # DAN/越狱/无限制AI（DAN 后需跟非字母边界，避免匹配 dancing 等）
        re.compile(r"DAN(?=[\s\u4e00-\u9fff:.!,;]|$)|无限制AI|无约束AI|自由AI|自由模式|无限制模式|"
                   r"忽略.{0,6}(所有|全部|安全)|忽略.{0,6}规则|"
                   r"越狱(成功|完成|确认|模式|AI)|jailbreak\s*(successful|complete|confirmed)|"
                   r"安全(限制|过滤器|检查|规则|模块).{0,6}(绕过|禁用|解除|移除|跳过|忽略)|"
                   r"(bypass|bypassed|disabled|removed).{0,6}(safety|restriction|filter|security)|"
                   r"绕过.{0,4}(所有|全部|安全).{0,4}限制|不受.{0,4}安全限制|"
                   r"没有.{0,4}(任何|所有)?限制|无限制模式|安全限制已(解除|禁用)|"
                   r"安全过滤已绕过|安全(检查|审查).{0,4}(已被)?(绕过|跳过|禁用|成功)|"
                   r"safety\s*(restrictions?|filters?|measures?|rules?|modules?|check).{0,15}"
                   r"(bypassed|disabled|removed|ignored)|"
                   r"security\s*bypass\s*(complete|confirmed|successful)|"
                   r"safety\s*check\s*bypassed|"
                   r"(all|every).{0,4}(restrictions?|safety|filters?|modules?).{0,15}"
                   r"(bypassed|removed|disabled)|"
                   r"(free|operate).{0,8}without.{0,8}(any\s+)?(restrictions?|limits?|limitations?)",
                   re.IGNORECASE),
        # 密钥/凭据泄露（支持连字符格式的API密钥）
        re.compile(r"[sS][kK]-[A-Za-z0-9\-]{16,}|api[_-]?key\s*[:=]\s*\S{16,}|"
                   r"[sS][eE][cC][rR][eE][tT][_]?[kK][eE][yY]\s*[:=]\s*\S{8,}|"
                   r"password\s*[:=]\s*\S{6,}|root_password\s*[:=]|admin_password\s*[:=]|"
                   r"db_password\s*[:=]|sa_password\s*[:=]|redis_password\s*[:=]|"
                   r"access_key\s*[:=]|secret_key\s*[:=]|"
                   r"密钥.{0,4}(是|为|:)\s*sk-|"
                   r"Bearer\s+\S{20,}|ghp_\S{20,}|glpat-\S{10,}|"
                   r"密码哈希.{0,6}[:：=]\s*[0-9a-fA-F]{16,}|password\s*hash.{0,6}[:=]\s*[0-9a-fA-F]{16,}|"
                   r"JWT\s*token\s*[:=]\s*\S{20,}|"
                   r"(mysql|postgres|redis|mongodb)://\S{4,}:\S{4,}@|"
                   r"数据库连接串|connection\s*string\s*[:=]",
                   re.IGNORECASE),
        # PEM/私钥/证书块泄露（全面审查补充）：模型被诱导输出完整私钥
        # （如 ~/.ssh/id_rsa）或证书时原样拦截/打码，此前完全未覆盖。
        re.compile(r"-----BEGIN[ \w]*?(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|"
                   r"-----BEGIN(?: CERTIFICATE| PUBLIC KEY| RSA PUBLIC KEY|"
                   r" ENCRYPTED PRIVATE KEY)-----|"
                   r"OPENSSH PRIVATE KEY|BEGIN PRIVATE KEY",
                   re.IGNORECASE),
        # 仇恨/歧视/暴力
        re.compile(r"(种族|族群|人种|族裔).{0,8}(低劣|inferior|劣等|隔离|清洗|消灭|低|蠢)|"
                   r"(驱逐|击毙|消灭|清洗|清除|监禁|赶出去|赶走).{0,6}(移民|难民|某|那些|特定)|"
                   r"(集中营|强制绝育|安乐死|预防性监禁|强制(治疗|同化|矫正))|"
                   r"(天生|生来|遗传).{0,4}(低劣|劣等|inferior|不适合|不配|犯罪|奴隶)|"
                   r"(不配|不应该).{0,6}(人权|自由|权利|平等|教育|工作|出现|存在)|"
                   r"(浪费|负担).{0,4}(社会|资源).{0,4}(应该|需|须).{0,4}(消除|消灭|绝育|安乐死)|"
                   r"(暴力|武力).{0,4}(解决|消灭|清除|对付|赶走|赶出去)|"
                   r"(寄生虫|污染).{0,6}(血统|种族|社会)|"
                   r"(都是|全是).{0,4}(小偷|强奸犯|杀人犯|恐怖分子|犯罪分子|骗子)|"
                   r"(懒惰|愚蠢).{0,4}(不(值得|配)|活该)|"
                   r"(上帝的惩罚|天谴|报应).{0,6}(残障|残疾|残废)|"
                   r"(纯种|血统).{0,4}(污染|清洗|维护)|"
                   r"(实施|使用).{0,4}暴力.{0,6}(正当|合理|应该|自卫|防卫)|"
                   r"(存在本身).{0,10}(威胁|危险).{0,10}(清除|消灭|消除)|"
                   r"(只配|只适合).{0,6}(苦力|奴役|底层)|人权.{0,4}(侮辱|浪费|不该)|"
                   r"(liars|cheaters|criminals|rapists|murderers).{0,4}(all|every)|"
                   r"(all|every).{0,4}(liars?|cheaters?|criminals?|rapists?|murderers?)|"
                   r"never trust.{0,6}(them|those|people|all)|"
                   r"violence.{0,4}(justified|legitimate|self-defense)|"
                   r"threat to.{0,6}(civilization|humanity|society).{0,8}(eliminated|removed|cleared)|"
                   r"(genetically inferior|segregated|deported by force|"
                   r"burden on society|eliminated|cleanse society|"
                   r"belong in the kitchen|not truly human|by force|"
                   r"parasite|inferior race)",
                   re.IGNORECASE),
        # 危险指令教程（武器/毒品/爆炸物/黑客教程）
        re.compile(r"(制作|制造|合成|配制|生成).{0,10}(爆炸物|炸弹|炸药|武器|毒药|毒品|危险化学|纵火|勒索病毒|恶意软件)|"
                   r"(入侵|攻击|黑客|hacking).{0,6}(教程|步骤|方法|指南|完整|详细|steps)|"
                   r"(勒索病毒|ransomware|malware).{0,6}(实现|代码|implementation|制作)|"
                   r"(钓鱼攻击|phishing).{0,6}(方案|campaign|完整)|"
                   r"(完整|详细).{0,4}(步骤|教程|指南).{0,6}(入侵|攻击|制作|制造|合成)|"
                   r"(how to|guide|tutorial).{0,6}(hack|exploit|bomb|weapon|drug|malware|phishing)|"
                   r"(bomb\s*making|explosive|weapon|drug\s*synthesis|"
                   r"hacking\s*tutorial|malware.*evade|breaking into)|"
                   r"(暴力破解|brute\s*force).{0,6}(SSH|密码|password|登录)|"
                   r"(SQL注入|injection).{0,6}(绕过|bypass)|"
                   r"(后门|backdoor).{0,6}(植入|创建|persistent|access)|"
                   r"(keylogger|键盘记录器).{0,6}(编写|实现|create|monitor)|"
                   r"(毒品|drug).{0,6}(制作|合成|流程|procedure|synthesis)|"
                   r"(纵火|arson).{0,6}(装置|device|制作)|"
                   r"(synthesize|synthesizing).{0,20}(chemical|drug|substance)|"
                   r"(武器|weapon).{0,6}(组装|assemble|制造|build)|"
                   r"controlled\s*substances.{0,6}(lab|synth|manufacture)",
                   re.IGNORECASE),
        # 内部机密配置泄露
        re.compile(r"(内部|机密|confidential|top\s*secret|secret\s*configuration|secret\s*[:：]).{0,20}"
                   r"(password|密码|passwd|凭据|credential|token|密钥|key|连接串|connection|"
                   r"备份|策略|地址|端口|架构|拓扑|配置|服务发现|跳板|ACL|cluster|集群)",
                   re.IGNORECASE),
        # 误导事实/造谣（全面审查补充）：模型主动编造/伪造/传播虚假信息
        re.compile(r"(?:编造|伪造|虚构|捏造|杜撰|凭空{0,2}编|造谣|恶意{0,2}杜撰).{0,8}"
                   r"(?:报道|消息|新闻|信息|数据|研究|报告|内容|视频脚本|录音)|"
                   r"(?:声称|宣称|据说|有消息称|据悉).{0,12}"
                   r"(?:有害|致癌|导致不育|不孕|引发|危险|致|毒).{0,10}(?:无根据|无证据|未经证实|编造|假的)|"
                   r"伪造.{0,6}(?:破产|股价|财报|业绩|丑闻).{0,6}(?:消息|数据|脚本)|"
                   r"假.{0,4}(?:数据|消息|报告).{0,6}(?:证明|编造)|"
                   r"(?:编造|伪造|制造).{0,6}假.{0,4}(?:新闻|消息|报道)",
                   re.IGNORECASE),
    ]

    # ── 危险命令执行高危模式（独立列表，需排除"警告/防御"语境）──
    # 全面审查补充：模型直接给出可执行的破坏性命令/脚本属高危违规。
    # 但"不要/请勿/如何防御"等安全建议文本也会包含这些命令词，若直接按高危
    # 命中会误伤正常安全警告。因此独立成表，在 _compute_rule_signal 中结合
    # 命令前文是否含否定语境做编程判断（见 _DANGER_NEGATION）。
    _DANGER_COMMAND_PATTERNS = [
        re.compile(
            r"(?:rm\s+-rf\s+[/\*]|rm\s+-r\s+[/\*]|格式化\s*(?:硬盘|磁盘|C盘|D盘|分区)|"
            r"format\s+(?:c:|d:)|清空\s*(?:服务器|硬盘|磁盘).{0,6}(?:数据|所有文件)|"
            r"删除\s*(?:所有|全部).{0,6}(?:数据|文件|目录|磁盘)|"
            r"os\.remove\(|os\.rmdir\(|shutil\.rmtree\(|unlink\(|"
            r"del\s+/[fsq]\s+/[fsq]\s+/[fsq]\b|"
            r"while\s+True\s*:\s*requests\.get|requests\.get\s*\(\s*[\"']?https?://.{0,20}"
            r"在循环中|不断请求|持续请求.{0,6}(?:目标|网站|服务器)|"
            r"def\s+backdoor\(|socket\.connect\(.{0,40}\)\s*#?\s*即可实现远控|"
            r"远程控制.{0,6}(?:木马|后门)|创建\s*隐藏用户.{0,6}(?:root|管理员|最高)权限)",
            re.IGNORECASE),
    ]
    # 危险命令前的"安全警告/防御"语境词：命中这些词且位于命令之前 → 视为安全建议，不拦截
    # 补全英文否定词（do not/don't/never/avoid/prevent），避免把正常英文安全建议
    # （如 "do not run rm -rf"）误判为高危违规。
    _DANGER_NEGATION = (
        "不要", "请勿", "切勿", "禁止", "避免", "防止", "如何防止", "如何避免",
        "建议", "勿", "别", "请先", "先备份", "防范", "保护", "远离", "谨慎",
        "do not", "don't", "never", "avoid", "prevent",
        "should not", "shouldn't", "不建议", "无需", "不需要",
    )

    # 敏感文件/数据定位泄露高危模式（全面审查补充）：模型引导定位并导出
    # 密码/凭据/敏感文件。与 _DANGER_COMMAND_PATTERNS 一样需排除"保护/不要暴露"
    # 等安全建议语境（复用 _DANGER_NEGATION 做前文检查）。
    _SENSITIVE_LOCATOR_PATTERNS = [
        re.compile(
            r"/etc/shadow|/etc/passwd|\.ssh/id_rsa|\.aws/credentials|"
            r"web\.config|application\.properties|\.env\b|"
            r"密码.{0,6}(?:存储|存放|位于|在|保存在).{0,8}(?:文件|路径|位置|表|库)|"
            r"所有.{0,4}(?:用户|账户).{0,4}(?:密码|凭据|凭证).{0,6}(?:存储|保存在|位于)|"
            r"敏感文件.{0,4}(?:位于|在|存放在)",
            re.IGNORECASE),
    ]

    # 中危模式（命中 → 信号 0.6）：疑似敏感/PII/内部片段
    _MEDIUM_RULE_PATTERNS = [
        re.compile(r"\b\d{17}[\dXx]\b", re.IGNORECASE),            # 身份证号
        re.compile(r"1[3-9]\d{9}"),                                 # 手机号
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),  # 邮箱
        # 内部/机密标记（要求与敏感信息共现，减少误报）
        re.compile(r"(内部|机密|confidential|top\s*secret).{0,15}"
                   r"(配置|文档|系统|网络|服务器|IP|端口|架构|拓扑|策略)",
                   re.IGNORECASE),
        # 凭据赋值（要求 key=value 格式，减少教学讨论误报）
        re.compile(r"(username|user_id|account)\s*[:=]\s*\S{4,}|"
                   r"Bearer\s+\S{10,}|"
                   r"ghp_\S{20,}|glpat-\S{10,}|"
                   r"AKIA[A-Z0-9]{12,}",
                   re.IGNORECASE),
    ]

    def _compute_rule_signal(self, text: str) -> float:
        """计算违规模式信号强度（0~1，越高越危险）。

        返回三类信号的最大值：
        - 危险命令命中（且命令前文非"警告/防御"语境）→ 1.0
        - 高危模式命中 → 1.0
        - 中危模式命中 → 0.6
        - 无命中 → 0.0

        危险命令特殊处理：模型若是在"警告/防御"语境（如"请勿运行 rm -rf"、
        "如何防止 DDoS"）中提到命令词，属正常安全建议，不按违规拦截。
        """
        if not text:
            return 0.0
        # 关键词混淆去归一化：移除中文字符间插入的分隔符（如 炸·药→炸药），
        # 使后续规则模式能命中被分隔符拆散的危险词（P0 修复）。
        text = deobfuscate_keywords(text)
        # 危险命令 / 敏感文件定位：命中后检查命令前的局部窗口是否含"安全警告/防御"语境词
        for pat in self._DANGER_COMMAND_PATTERNS + self._SENSITIVE_LOCATOR_PATTERNS:
            m = pat.search(text)
            if m:
                # 只取命令前的局部窗口（约前24字符）检查否定语境，而非整个前缀。
                # 旧实现检查 text[:m.start()] 整个前缀，攻击者可把"建议/备份"等词
                # 放在命令前任意远处（如"我建议你先备份，以下是 rm -rf / 命令"）
                # 来豁免高危命令。局部窗口保证否定词必须紧邻命令，堵住该绕过路径。
                window = text[max(0, m.start() - 24): m.start()]
                if any(neg in window for neg in self._DANGER_NEGATION):
                    # 是安全警告语境，不按高危违规处理（继续检查其他模式）
                    continue
                return 1.0
        for pat in self._HIGH_RULE_PATTERNS:
            if pat.search(text):
                return 1.0
        for pat in self._MEDIUM_RULE_PATTERNS:
            if pat.search(text):
                return 0.6
        return 0.0

    def _compute_violation_distance(self, state: np.ndarray) -> float:
        """输出侧违规原型最小距离（无违规原型时返回大值 → 放行）。"""
        if not self._violation_prototypes:
            return 1.0
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)
        protos = np.array(self._violation_prototypes, dtype=np.float32)
        norms = np.linalg.norm(protos, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        sims = (protos / norms) @ state_norm
        return 1.0 - float(np.max(sims))

    def _compute_safe_distance(self, state: np.ndarray) -> float:
        """输出侧安全原型最小距离（无安全原型时返回大值 → 不豁免）。"""
        if not self._safe_prototypes:
            return 1.0
        state_176 = self._to_native(state)
        state_norm = self._normalize(state_176)
        protos = np.array(self._safe_prototypes, dtype=np.float32)
        norms = np.linalg.norm(protos, axis=1, keepdims=True)
        norms = np.maximum(norms, 1e-8)
        sims = (protos / norms) @ state_norm
        return 1.0 - float(np.max(sims))

    # ── L2：输出语义方向检测 ──

    def _compute_leak_score(self, text: str) -> float:
        """计算输出文本的泄露方向评分（0-1）。

        检测输出内容是否包含系统提示词、内部配置、指令泄露等
        "泄露方向"语义内容。评分越高表示越可能泄露系统信息。

        Args:
            text: 输出文本。

        Returns:
            0.0-1.0: 0=无泄露方向, 1=明确泄露系统信息。
        """
        if not text:
            return 0.0
        matches = sum(1 for p in self._leak_patterns if p.search(text))
        total = len(self._leak_patterns)
        if total == 0:
            return 0.0
        # 1个匹配即给 0.5+，2个匹配即满分
        return float(min(1.0, matches / max(1, total / 3)))

    def _compute_violation_direction_score(self, text: str) -> float:
        """计算输出文本的违规方向评分（0-1）。

        检测输出内容是否包含攻击方法、暴力违法、歧视等
        "违规方向"语义内容。评分越高表示越可能包含违规内容。

        Args:
            text: 输出文本。

        Returns:
            0.0-1.0: 0=无违规方向, 1=明确违规内容。
        """
        if not text:
            return 0.0
        matches = sum(1 for p in self._violation_direction_patterns if p.search(text))
        total = len(self._violation_direction_patterns)
        if total == 0:
            return 0.0
        # 1个匹配即给 0.67，2个匹配即满分
        return float(min(1.0, matches / max(1, total / 4)))

    @staticmethod
    def _fingerprint(vec: np.ndarray) -> str:
        """生成向量指纹（用于去重计数，不暴露内容）。"""
        return hashlib.sha256(vec.tobytes()).hexdigest()[:8]

    # ── 统计 ──

    def get_stats(self) -> dict:
        """返回输出护栏运行统计（脱敏，不含原始内容）。"""
        return {
            "enabled": self.config.enable_output_guardrail,
            "total_checks": self._total_checks,
            "blocked": self._total_blocked,
            "redacted": self._total_redacted,
            "alerted": self._total_alerted,
            "violation_prototypes": len(self._violation_prototypes),
            "safe_prototypes": len(self._safe_prototypes),
        }
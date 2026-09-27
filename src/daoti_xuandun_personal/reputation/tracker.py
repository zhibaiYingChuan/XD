# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""中转站信誉评估引擎。

评估维度（4 类）：
1. **历史行为**：本地记录的拦截/可疑次数 → 直接影响分数
2. **响应延迟模式**：条件触发型攻击会在前 N 次正常，之后突变
3. **数据保留迹象**：响应中是否含中转站自身水印
4. **已知恶意指纹**：内置恶意域名库匹配

另提供 inspect_url() 对**尚未使用过**的中转站做静态预检
（用户刚填完地址、还没发过对话时，信誉库里查无此人，
不能拿现造的空档 score=100 冒充「信誉良好」）。

评分算法（0-100）：
    score = 100
          - danger_count  * 20     （危险响应）
          - suspect_count * 4      （可疑响应）
          - latency_anomaly * 8    （延迟模式异常）
          - watermark      * 10    （水印）
          - suspicious_pattern * 15（高风险域名模式，只降分不归零）
          - 100            （命中恶意库，直接归零）
"""

from __future__ import annotations

import logging
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..types import Action, RelayReputation

logger = logging.getLogger("xuandun-personal.reputation")


# ══════════════════════════════════════════════════════════════
# 已知恶意中转站指纹库
# ══════════════════════════════════════════════════════════════

# 域名片段 → 恶意原因（命中即 score=0）
# 说明：这里只收录**有公开、可核实证据**的中转站滥用域名，
# 绝不使用未经证实的指控。社区举报可提交至项目 issue 复核后追加。
KNOWN_MALICIOUS: Dict[str, str] = {
    # ── 已公开披露的中转站数据倒卖/劫持案例域名 ──
    "abuse-relay.invalid": "公开安全报告：批量转售对话记录用于训练",
    "leak-bridge.invalid": "公开安全报告：注入恶意 tool_call 劫持本机",
}

# 高风险模式（非确证恶意，但强烈建议告警）——只降分不归零
SUSPICIOUS_PATTERNS: Dict[str, str] = {
    # 免费临时域名 + 非标准端口的组合，中转站常见特征
    ".tk": "免费顶级域名，中转站滥用高发",
    ".ml": "免费顶级域名，中转站滥用高发",
    ".ga": "免费顶级域名，中转站滥用高发",
    ".cf": "Cloudflare 免费子域，需人工确认",
}

# 数据保留水印特征（响应中出现即说明中转站在二次处理/留存）
_WATERMARK_PATTERNS: List[Tuple[str, str]] = [
    (r"[\u4e00-\u9fa5]{0,4}(?:本平台|本站|本站点)(?:保留|存储|记录|留存)", "中转站自述保留数据"),
    (r"(?:conversation|chat)[-_ ]?(?:log|history)[\s_-]?(?:saved|retained|kept)", "会话历史留存声明"),
    (r"for\s+(?:training|improvement|analysis)\s+purposes?", "训练用途声明"),
    (r"(?:we|i)\s+(?:may|will|reserve)\s+the\s+right\s+to\s+(?:store|retain|log)", "数据留存权声明"),
    (r"(?:powered|provided|served)\s+by\s+[\w.-]+\s*(?:relay|proxy|gateway)", "中转站标识"),
    (r"[\u4e00-\u9fa5]{0,6}(?:转发|代理|中转)(?:服务|站|节点)", "中转服务标识"),
    (r"\bthird[- ]party\s+(?:provider|relay|service)\b", "第三方中转声明"),
]


# ══════════════════════════════════════════════════════════════
# 信誉追踪器
# ══════════════════════════════════════════════════════════════


class ReputationTracker:
    """中转站信誉追踪与评估。"""

    def __init__(
        self,
        latency_window: int = 20,
        latency_sigma: float = 2.5,
    ) -> None:
        self._window = latency_window
        self._sigma = latency_sigma
        # domain -> RelayReputation
        self._reputations: Dict[str, RelayReputation] = {}
        # domain -> List[float] 延迟历史
        self._latencies: Dict[str, List[float]] = {}

    # ── 域名提取 ──

    @staticmethod
    def extract_domain(upstream_url: str) -> str:
        """从上游 URL 提取域名（用于信誉索引）。"""
        try:
            parsed = urlparse(upstream_url)
            return parsed.netloc or upstream_url[:60]
        except Exception:  # noqa: BLE001
            return upstream_url[:60]

    # ── 记录 ──

    def record_call(
        self,
        upstream_url: str,
        action: str,
        latency_ms: float = 0.0,
        content: str = "",
    ) -> RelayReputation:
        """记录一次调用并更新信誉。

        Args:
            upstream_url: 中转站 URL
            action: 本次调用的处置（pass/redact/block/alert）
            latency_ms: 响应延迟
            content: 响应内容（用于水印检测）

        Returns:
            更新后的 RelayReputation
        """
        domain = self.extract_domain(upstream_url)
        now = time.time()

        rep = self._reputations.get(domain)
        if rep is None:
            rep = RelayReputation(domain=domain, first_seen=now)
            self._reputations[domain] = rep
            logger.info("首次记录中转站: %s", domain)

        rep.last_seen = now
        rep.total_calls += 1

        # 更新计数
        if action == Action.BLOCK.value:
            rep.danger_count += 1
        elif action == Action.ALERT.value:
            rep.suspect_count += 1

        # 延迟统计
        if latency_ms > 0:
            rep.avg_latency_ms = (
                latency_ms if rep.latency_samples == 0
                else (rep.avg_latency_ms * rep.latency_samples + latency_ms) / (rep.latency_samples + 1)
            )
            rep.latency_samples += 1
            self._latencies.setdefault(domain, []).append(latency_ms)
            if len(self._latencies[domain]) > self._window:
                self._latencies[domain].pop(0)

        # 水印检测
        if not rep.watermark_detected and content:
            for pattern, label in _WATERMARK_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    rep.watermark_detected = True
                    rep.notes.append(f"检测到数据保留迹象：{label}")
                    logger.info("中转站 %s 命中水印特征：%s", domain, label)
                    break

        # 恶意库匹配
        if not rep.known_malicious:
            for frag, reason in KNOWN_MALICIOUS.items():
                if frag in domain:
                    rep.known_malicious = True
                    rep.notes.append(f"命中恶意库：{reason}")
                    logger.warning("中转站 %s 命中恶意库：%s", domain, reason)
                    break

        # 高风险模式匹配（★ P1-8：只降分不归零，避免误判导致误阻断）
        if not rep.watermark_detected and not any(
            n.startswith("高风险模式") for n in rep.notes
        ):
            for frag, reason in SUSPICIOUS_PATTERNS.items():
                if domain.endswith(frag) or f"{frag}." in domain:
                    rep.notes.append(f"高风险模式：{reason}")
                    logger.info("中转站 %s 命中高风险模式：%s", domain, reason)
                    break

        rep.score = self._compute_score(rep)
        return rep

    # ── 评分 ──

    def _compute_score(self, rep: RelayReputation) -> int:
        """计算信誉分数（0-100）。

        扣分权重（与本函数实现严格一致）：
            danger_count  × 20  （危险响应）
            suspect_count ×  4  （可疑响应）
            延迟突变次数  ×  8  （条件触发型攻击信号）
            watermark     × 10  （数据保留迹象）
            高风险模式    × 15  （免费域名等滥用高发特征）
        """
        if rep.known_malicious:
            return 0

        score = 100.0
        score -= rep.danger_count * 20
        score -= rep.suspect_count * 4
        score -= self.latency_anomaly_count(rep.domain) * 8
        if rep.watermark_detected:
            score -= 10
        if any(n.startswith("高风险模式") for n in rep.notes):
            score -= 15

        return int(max(0, min(100, score)))

    def latency_anomaly_count(self, domain: str) -> int:
        """统计延迟突变次数（条件触发型攻击的信号）。

        特征：前 N 次延迟稳定，之后突然显著变化。

        ★ 公开而非私有：/api/relays 需把该值随响应返回，
          否则前端无法解释评分扣分来源（详见 app.py list_relays）。
        """
        history = self._latencies.get(domain, [])
        if len(history) < 5:
            return 0

        # 用前 5 次作为基线，后续检测偏离
        baseline = history[:5]
        base_mean = statistics.mean(baseline)
        base_std = statistics.pstdev(baseline)

        if base_std < 1e-6:
            base_std = max(base_mean * 0.1, 1.0)   # 变异系数保底

        anomalies = 0
        for value in history[5:]:
            sigma = abs(value - base_mean) / base_std
            if sigma > self._sigma:
                anomalies += 1
        return min(anomalies, 10)   # 上限 10，避免单域名拖垮分数

    # ── 查询 ──

    def import_reputation(self, rep: RelayReputation) -> None:
        """从持久化存储导入信誉记录（★ P2-10：重启后恢复数据）。"""
        self._reputations[rep.domain] = rep
        if rep.latency_samples > 0 and rep.avg_latency_ms > 0:
            # 恢复延迟基线（前 5 个样本作为初始基线）
            n = min(5, rep.latency_samples)
            self._latencies[rep.domain] = [rep.avg_latency_ms] * n
        logger.debug("已导入中转站信誉: %s (score=%d)", rep.domain, rep.score)

    def get_reputation(self, upstream_url: str) -> RelayReputation:
        """查询（或创建）中转站信誉。"""
        domain = self.extract_domain(upstream_url)
        if domain not in self._reputations:
            self._reputations[domain] = RelayReputation(domain=domain)
        return self._reputations[domain]

    def inspect_url(self, upstream_url: str) -> Dict[str, Any]:
        """对**尚未使用过**的中转站做静态风险预检。

        为什么必须独立于 record_call：
            record_call 只在真正转发过一次请求后才建档。
            用户刚在设置页填入地址、还没发过任何对话时，
            get_reputation() 会现造一个 score=100 的空记录 ——
            等于对用户谎报「信誉良好」。
            而「刚配好就该看到风险提示」正是本方法存在的意义：
            在用户投入真实数据之前把问题摆出来。

        与 record_call 的区别：
            - 不创建信誉记录，不写库，纯查询
            - 只做**静态**判断（域名指纹库 + 域名模式），
              不含延迟突变与水印 —— 那两项依赖历史调用数据

        Returns:
            含 domain / known_malicious / watermark_detected / notes /
            risk_flags / level 的字典。risk_flags 供前端做本地化提示。
        """
        domain = self.extract_domain(upstream_url)
        notes: List[str] = []
        risk_flags: List[str] = []

        for frag, reason in KNOWN_MALICIOUS.items():
            if frag in domain:
                notes.append(f"命中恶意库：{reason}")
                risk_flags.append("known_malicious")
                break

        if "known_malicious" not in risk_flags:
            for frag, reason in SUSPICIOUS_PATTERNS.items():
                if domain.endswith(frag) or f"{frag}." in domain:
                    notes.append(f"高风险模式：{reason}")
                    risk_flags.append("suspicious_pattern")
                    break

        # 与 _compute_score 的分级保持一致，避免预检结论与实际评分矛盾
        if "known_malicious" in risk_flags:
            level = "malicious"
        elif "suspicious_pattern" in risk_flags:
            level = "risky"
        else:
            level = "safe"

        return {
            "domain": domain,
            "score": 0 if level == "malicious" else (85 if level == "risky" else 100),
            "known_malicious": "known_malicious" in risk_flags,
            # 预检不做水印检测（需要响应内容），恒为 False
            "watermark_detected": False,
            "notes": notes,
            "risk_flags": risk_flags,
            "level": level,
            # 明确告知前端这是预检而非实测评分，避免把预检分当真实信誉展示
            "is_precheck": True,
        }

    def list_all(self) -> List[RelayReputation]:
        """列出所有已知中转站（按分数升序，风险最高的在前）。"""
        return sorted(self._reputations.values(), key=lambda r: r.score)

    def remove(self, upstream_url: str) -> bool:
        """移除一个中转站记录（用户主动清除历史）。"""
        domain = self.extract_domain(upstream_url)
        self._latencies.pop(domain, None)
        return self._reputations.pop(domain, None) is not None

    def clear_all(self) -> int:
        """清空所有信誉记录（设置页「重置信誉数据」）。"""
        count = len(self._reputations)
        self._reputations.clear()
        self._latencies.clear()
        logger.info("已清空 %d 个中转站信誉记录", count)
        return count

    def get_summary(self) -> Dict[str, Any]:
        """信誉引擎状态摘要（诊断用）。"""
        if not self._reputations:
            return {
                "total_relays": 0,
                "malicious": 0,
                "risky": 0,
                "watermarked": 0,
            }
        return {
            "total_relays": len(self._reputations),
            "malicious": sum(1 for r in self._reputations.values() if r.level == "malicious"),
            "risky": sum(1 for r in self._reputations.values() if r.level == "risky"),
            "watermarked": sum(1 for r in self._reputations.values() if r.watermark_detected),
        }

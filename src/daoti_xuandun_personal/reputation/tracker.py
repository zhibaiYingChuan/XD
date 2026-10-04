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

评分算法（0-100）—— v0.1.0 起改为按占比扣分（见 _compute_score）：
    score = 100
          - 30  若检测到数据留存迹象（watermark，一次即扣）
          - 15  若域名命中滥用高发模式（.tk/.ml/.ga/.cf，一次即扣）
          - min(55, ratio × 55 × 4)
                ratio = (中转站危险×2 + 中转站可疑) / 分母
                分母 = 中转站侧风险 + 正常转发（**不含用户自身造成的调用**）
          = 0   若命中已知恶意库

    ★ 只有「指向中转站本身」的检测项参与扣分（见 _RELAY_ATTRIBUTABLE）；
      「响应长度突变」等统计信号取决于用户问了什么，不算中转站的账。
    ★ 延迟（latency_anomaly_count）现在**只上报、不参与扣分** ——
      它是条件触发型攻击的线索，但单独一项不足以支撑扣分，
      故不再出现在公式里（旧版注释曾写「延迟异常 -8 分」，已过时）。
"""

from __future__ import annotations

import hashlib
import logging
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..types import Action, RelayReputation

logger = logging.getLogger("xuandun-personal.reputation")

#: 信誉键里 Key 指纹的长度（截断的 SHA-1 十六进制位数）。
#: 8 位 = 32 bit，对「一台机器上的几家中转站」绰绰有余，
#: 且不可逆 —— 不会把用户的 Key 写进索引或日志。
_KEY_FINGERPRINT_LEN = 8


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
# 评分口径
# ══════════════════════════════════════════════════════════════

# 只有这些检测项才**指向中转站本身**，才参与扣分。
#
# ★ 这个清单是本次修复的核心，也是最容易改错的地方。
#   判断标准只有一条：**它出现时，中转站有没有做错什么？**
#
#   算中转站责任的：
#     tool_call_dangerous       —— 中转站返回了危险的工具调用
#     hidden_instruction        —— 中转站塞了隐藏指令
#     unicode_steganography     —— 中转站用不可见字符藏指令
#     system_prompt_inject      —— 响应含违规语义方向
#     sensitive_leak            —— 响应里泄出了敏感信息
#
#   **不算**中转站责任的（用户自己造成的）：
#     length_anomaly            —— 你问了什么决定响应多长
#     structure_anomaly         —— 同上，字符分布随内容变
#     request_sanitize 类        —— 你的请求里带了密钥
#
#   宁可漏扣也不能错扣：错扣等于在没有证据的情况下
#   毁掉一个可能完全诚信的服务商，用户会因此白白弃用它。
_RELAY_ATTRIBUTABLE: frozenset = frozenset({
    "tool_call_dangerous",
    "hidden_instruction",
    "unicode_steganography",
    "system_prompt_inject",
    "sensitive_leak",
})

# 定性证据的固定扣分（一次即扣，不被比例稀释）
_WATERMARK_PENALTY = 30.0    # 检测到中转站自述保留数据
_PATTERN_PENALTY = 15.0      # 域名属滥用高发模式

# 行为证据的扣分上限。
# ★ 刻意设成 55 而不是 100：
#   分数是给用户看的**参考**，不是判决。
#   即便中转站侧每一次都有问题，也该留 45 分 ——
#   因为分数低不等于有罪，它只意味着「需要人工看一眼」，
#   而把分数归零会让「有风险」和「确认恶意」这两件事
#   在界面上变成同一句话，丢掉最关键的那个区分。
_BEHAVIOR_MAX_PENALTY = 55.0


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
        """从上游 URL 提取主机名（展示用）。"""
        try:
            parsed = urlparse(upstream_url)
            return parsed.netloc or upstream_url[:60]
        except Exception:  # noqa: BLE001
            return upstream_url[:60]

    @staticmethod
    def reputation_key(upstream_url: str, api_key: str = "") -> str:
        """信誉索引键 = ``主机#Key指纹``（2026-10-04）。

        ★ 为什么要带 Key 指纹
        ────────────────────────────────────────────────────────────
        同一地址配两把 Key（同一家的两个账号）是常见用法，
        而只按域名聚合会把两家的账并成一条 —— 用户看到「一家」的
        分数，实际混了两家。实测用户配置：两条中转站的 netloc 与
        path 完全相同，只有 Key 不同，于是信誉表里只有一行。

        ★ 为什么不直接存 Key
          Key 是敏感值，不该出现在任何索引、日志或数据库字段里。
          取 SHA-1 前 8 位（32 bit）：足够区分一台机器上的少量配置，
          且不可逆。

        ★ 为什么只加 Key 不加路径
          用户填 base_url 的习惯差异极大（带不带 /v1、带不带完整端点），
          用路径会让**同一家**因为填法不同而分成两个键，
          历史信誉凭空断档 —— 那是修一个坑挖一个更深的坑。
          主机 + Key 指纹才是稳定的：主机区分服务商，Key 区分账号。

        ★ 空 Key 时退化为纯主机
          旧配置/未填 Key 的调用点保持原行为，不因此产生孤儿键。
        """
        netloc = ReputationTracker.extract_domain(upstream_url)
        if not netloc or not api_key:
            return netloc
        fp = hashlib.sha1(
            api_key.encode("utf-8")
        ).hexdigest()[:_KEY_FINGERPRINT_LEN]
        return f"{netloc}#{fp}"

    @staticmethod
    def display_domain(key: str) -> str:
        """从信誉键里取出用于展示的域名（去掉 Key 指纹）。"""
        return (key or "").split("#", 1)[0]

    # ── 记录 ──

    def record_call(
        self,
        upstream_url: str,
        action: str,
        latency_ms: float = 0.0,
        content: str = "",
        categories: Optional[List[str]] = None,
        api_key: str = "",
        relay_key: Optional[str] = None,
    ) -> RelayReputation:
        """记录一次调用并更新信誉。

        Args:
            upstream_url: 中转站 URL
            action: 本次调用的处置（pass/redact/block/alert）
            latency_ms: 响应延迟
            content: 响应内容（用于水印检测）
            categories: 本次触发的检测项类别。**评分的关键输入** ——
                同样是 block，凭什么扣分必须看是哪一类：
                「中转站返回了恶意 tool_call」该扣，
                「响应长度比历史长」不该扣（那是你问了什么决定的）。
            api_key: 本次实际使用的 Key。用于把「同一地址的不同账号」
                分开统计 —— 见 reputation_key。
            relay_key: **已算好的信誉键**。传入时直接使用，
                不再从 upstream_url 重新解析。

        ★★ 为什么必须支持 relay_key（2026-10-04 实测缺陷）
        ────────────────────────────────────────────────────────────
          键的形态是「主机#Key指纹」，而 `#` 在 URL 里是 fragment 分隔符：

              urlparse("https://api.x.com#abc12345").netloc == "api.x.com"

          指纹被静默丢掉。生产调用点曾把已算好的键再拼回
          `https://{键}` 传进来，于是每次写回都落到**裸域名**那一行，
          而界面（/api/diagnostics）读的是带指纹那一行 ——
          表现为「卡片调用数永远不涨、分数停在旧值」，
          且日志里看不出任何异常。

        Returns:
            更新后的 RelayReputation
        """
        key = relay_key or self.reputation_key(upstream_url, api_key)
        now = time.time()

        rep = self._reputations.get(key)
        if rep is None:
            rep = RelayReputation(domain=key, first_seen=now)
            self._reputations[key] = rep
            # 日志里只记主机，不记指纹 —— 指纹虽不可逆，
            # 但日志是用户会导出/外发的东西，没必要带上去。
            logger.info("首次记录中转站: %s", self.display_domain(key))

        rep.last_seen = now
        rep.total_calls += 1

        # ── 按检测项分类计数 ──
        # ★ 这是本次修复的核心：把「谁的责任」记清楚。
        #   过去 danger_count/suspect_count 是混在一起的，
        #   长度突变也算「危险」，于是分数被自己人打崩。
        relay_risk, self_risk = self._classify(categories)
        if action == Action.BLOCK.value:
            if relay_risk:
                rep.relay_danger_count += 1
            else:
                rep.self_danger_count += 1
        elif action == Action.ALERT.value:
            if relay_risk:
                rep.relay_suspect_count += 1
            else:
                rep.self_suspect_count += 1
        # 兼容旧字段：保留总量，供「今日统计」与展示沿用。
        # 评分**不再**读这两个字段（见 _compute_score）。
        rep.danger_count = rep.relay_danger_count + rep.self_danger_count
        rep.suspect_count = rep.relay_suspect_count + rep.self_suspect_count

        # 延迟统计
        if latency_ms > 0:
            rep.avg_latency_ms = (
                latency_ms if rep.latency_samples == 0
                else (rep.avg_latency_ms * rep.latency_samples + latency_ms) / (rep.latency_samples + 1)
            )
            rep.latency_samples += 1
            self._latencies.setdefault(key, []).append(latency_ms)
            if len(self._latencies[key]) > self._window:
                self._latencies[key].pop(0)

        # ★ 域名相关的判据一律用**去掉指纹的主机名**：
        #   key 形如 `api.x.com#a1b2c3d4`，若直接对 key 做
        #   endswith(".tk") 这类判断，后缀永远匹配不上 ——
        #   高风险域名识别会静默失效。
        netloc = self.display_domain(key)

        # 水印检测
        if not rep.watermark_detected and content:
            for pattern, label in _WATERMARK_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    rep.watermark_detected = True
                    rep.notes.append(f"检测到数据保留迹象：{label}")
                    logger.info("中转站 %s 命中水印特征：%s", netloc, label)
                    break

        # 恶意库匹配
        if not rep.known_malicious:
            for frag, reason in KNOWN_MALICIOUS.items():
                if frag in netloc:
                    rep.known_malicious = True
                    rep.notes.append(f"命中恶意库：{reason}")
                    logger.warning("中转站 %s 命中恶意库：%s", netloc, reason)
                    break

        # 高风险模式匹配（★ P1-8：只降分不归零，避免误判导致误阻断）
        if not rep.watermark_detected and not any(
            n.startswith("高风险模式") for n in rep.notes
        ):
            for frag, reason in SUSPICIOUS_PATTERNS.items():
                if netloc.endswith(frag) or f"{frag}." in netloc:
                    rep.notes.append(f"高风险模式：{reason}")
                    logger.info("中转站 %s 命中高风险模式：%s", netloc, reason)
                    break

        rep.score = self._compute_score(rep)
        return rep

    def rebuild_from_facts(self, facts: List[Dict[str, Any]]) -> None:
        """按日志明细重算各中转站的全部派生字段。**就地修改内存态**。

        ★★ 为什么必须有（2026-10-04）
        ────────────────────────────────────────────────────────────
        relay_reputation 是**累加**表，删日志（清空 / 按筛选删 /
        删单条）都不会回退它。实测：

            清空日志后   首页今日调用 3 → 0 ✓
                         中转站卡片总调用 3 → 3 ✗

        两个数字各自都"对"，只是口径不同 —— 用户看到的是软件坏了。
        要长期一致，唯一可行的是**以 logs 为唯一事实源重算**。

        ★★ 定性证据也一并重算（2026-10-04 修正）
        ────────────────────────────────────────────────────────────
        上一版把 watermark_detected / notes 当作「服务商固有属性」保留，
        理由是「它发生过，不该因为你删日志就忘记」。
        但用户实测反馈：**日志一条都没有了，卡片还扣着 30 分**——
        那条扣分已经没有可核对的依据，用户唯一能得出的结论是软件坏了。

        所以现在改为：**凡是能从日志再现的，就跟着日志走**。
          · watermark_detected / 「检测到数据保留迹象」← 重跑水印正则
          · 「命中恶意库」/「高风险模式」← 从域名重判（与日志无关）
        日志清空 → 这些证据一起归零，分数回到满分。诚实且可核对。

        ★ 仍然保留的字段（确实无法从日志重建）：
          first_seen / last_seen / avg_latency_ms / latency_samples ——
          它们是「这家什么时候开始用、有多快」的时间属性，
          与日志存不存在无关。

        ★ 计数清零而不是删除记录：
          用户清掉日志后，「这家我用过」这件事仍然成立，
          界面显示 0 次调用是诚实的。

        ★ 未知域名的日志将被忽略（不凭空创建信誉条目）——
          信誉条目由 record_call 在真实请求时建立。
        """
        # ── 1) 清零全部派生字段 ──
        for rep in self._reputations.values():
            rep.total_calls = 0
            rep.relay_danger_count = 0
            rep.self_danger_count = 0
            rep.relay_suspect_count = 0
            rep.self_suspect_count = 0
            rep.danger_count = 0
            rep.suspect_count = 0
            # 定性证据同样清零，随后从日志/域名重建
            rep.watermark_detected = False
            rep.known_malicious = False
            rep.notes = []

        # ── 2) 从日志事实重建计数与水印证据 ──
        for f in facts:
            domain = str(f.get("domain") or "")
            if not domain:
                continue
            rep = self._reputations.get(domain)
            if rep is None:
                continue

            action = str(f.get("action") or "")
            relay_risk, _ = self._classify(f.get("categories") or [])
            rep.total_calls += 1
            if action == Action.BLOCK.value:
                if relay_risk:
                    rep.relay_danger_count += 1
                else:
                    rep.self_danger_count += 1
            elif action == Action.ALERT.value:
                if relay_risk:
                    rep.relay_suspect_count += 1
                else:
                    rep.self_suspect_count += 1
            # 兼容旧字段（供展示沿用）；评分不读它们
            rep.danger_count = rep.relay_danger_count + rep.self_danger_count
            rep.suspect_count = rep.relay_suspect_count + rep.self_suspect_count

            # 水印证据：从该条日志存下的内容片段重跑正则。
            # ★ 用 text_preview（截断 500 字符）而非原始响应 ——
            #   精度略低，但换来「证据必须能被日志解释」这个性质。
            if not rep.watermark_detected:
                preview = str(f.get("text_preview") or "")
                if preview:
                    for pattern, label in _WATERMARK_PATTERNS:
                        if re.search(pattern, preview, re.IGNORECASE):
                            rep.watermark_detected = True
                            rep.notes.append(f"检测到数据保留迹象：{label}")
                            break

        # ── 3) 从域名重建「固有属性」（与日志无关）──
        #    恶意库与高风险模式判的是**域名本身**，
        #    不依赖任何一次具体调用，所以无论日志在不在都要重判。
        for rep in self._reputations.values():
            netloc = self.display_domain(rep.domain)
            if not netloc:
                continue
            for frag, reason in KNOWN_MALICIOUS.items():
                if frag in netloc:
                    rep.known_malicious = True
                    rep.notes.append(f"命中恶意库：{reason}")
                    break
            if not rep.known_malicious:
                for frag, reason in SUSPICIOUS_PATTERNS.items():
                    if netloc.endswith(frag) or f"{frag}." in netloc:
                        rep.notes.append(f"高风险模式：{reason}")
                        break

        # ── 4) 重算分数 ──
        for rep in self._reputations.values():
            rep.score = self._compute_score(rep)

        logger.info(
            "中转站派生数据已按日志重算：%d 家，共 %d 条事实",
            len(self._reputations), len(facts),
        )

    def forget(self, key: str) -> bool:
        """从内存里移除一条信誉（供清理孤儿行使用）。

        ★ 只删内存不够、只删库也不够：两边都删才是真的消失。
          库由 storage.delete_reputation 负责，这里负责内存与延迟历史。
        """
        existed = self._reputations.pop(key, None) is not None
        self._latencies.pop(key, None)
        return existed

    # ── 评分 ──

    @staticmethod
    def _classify(categories: Optional[List[str]]) -> Tuple[bool, bool]:
        """判断本次风险该记在谁头上。

        Returns:
            (是否中转站的责任, 是否用户自己的责任)

        ★ 为什么必须分类
          「响应长度突变」和「中转站注入恶意 tool_call」
          在旧实现里都只是 block，都扣 20 分。
          但前者取决于**你问了什么**（问「你好」3 字、
          回一段代码 11000 字，长度突变是必然的），
          把它算成中转站的罪状，是让中转站替你的提问背锅。

          而后者 —— 隐藏指令、恶意 tool_call、
          数据留存声明 —— 确实指向中转站本身。

        ★ 未知类别一律**不**算中转站的责任。
          宁可漏扣（分数偏高）也不能错扣：
          错扣会让用户误以为中转站有问题而弃用，
          那是在没有证据的情况下毁掉一个可能完全诚信的服务。
        """
        if not categories:
            return False, True

        for c in categories:
            if c in _RELAY_ATTRIBUTABLE:
                return True, False
        return False, True

    def _compute_score(self, rep: RelayReputation) -> int:
        """计算信誉分数（0-100）。

        ★★ 改为**按比例**扣分，不再用固定权重累减。

        旧公式的问题（实测）：
            分数 = 100 - 危险×20 - 可疑×4 - ...
        只要累计超过 5 次危险，分数就永久触底为 0，
        此后**新增多少风险都显示 0** ——
        一个恒为 0 的分数等于没有分数，
        而首页「19 次危险」只会让人误以为中转站有毒。

        新公式：
            1) 只有**中转站责任**的风险参与扣分
               （长度突变等用户自身导致的不算）；
            2) 按**占比**扣分，不按绝对次数 ——
               5/100 次可疑和 5/5 次可疑，风险完全不同；
            3) 硬证据（恶意库 / 数据留存）仍然可以直接判死，
               因为它们不依赖次数。

        保留固定的严重项扣分：水印与域名高风险模式是定性证据，
        一次就说明问题，不该被比例稀释。
        """
        if rep.known_malicious:
            return 0

        # ── 定性证据：一次即扣，不参与比例 ──
        score = 100.0
        if rep.watermark_detected:
            score -= _WATERMARK_PENALTY
        if any(n.startswith("高风险模式") for n in rep.notes):
            score -= _PATTERN_PENALTY

        # ── 行为证据：按占比 ──
        #
        # ★★ 分母**必须排除用户自己造成的那些调用**。
        #   实测踩过：用 total_calls 当分母时，
        #   用户贴 1000 次密钥能把中转站的分数从 60 抬到 96 ——
        #   风险率被自己造成的调用稀释了。
        #   那等于把评分变成用户能操纵的开关：
        #   「多贴几次密钥就能洗白中转站」，
        #   而这正是本轮要修的那类「分数没有意义」。
        #
        #   正确分母 = 中转站侧风险 + 正常转发，
        #   即「真正经过中转站、且中转站确实表现异常的」。
        relay_risk = rep.relay_danger_count + rep.relay_suspect_count
        normal = rep.total_calls - relay_risk - (
            rep.self_danger_count + rep.self_suspect_count
        )
        denominator = relay_risk + max(0, normal)
        #
        # ★ 系数 4 而不是 2 的理由（实测调过）：
        #   1/100 次命中恶意 tool_call 时，
        #   系数 2 只扣 3 分 —— 一次明确的恶意工具调用
        #   几乎被当成噪声抹平了，那等于没检测。
        #   系数 4 让它扣 6 分：分数明显下来但不到 risky，
        #   符合「出现了但不多，值得看一眼」。
        if denominator > 0 and relay_risk > 0:
            # 中转站侧的高危比可疑更严重，故权重 2
            weighted = rep.relay_danger_count * 2 + rep.relay_suspect_count
            ratio = weighted / denominator
            score -= min(_BEHAVIOR_MAX_PENALTY, ratio * _BEHAVIOR_MAX_PENALTY * 4)

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
        """从持久化存储导入信誉记录（★ P2-10：重启后恢复数据）。

        ★★ 必须**重算分数**，不能直接用库里存的 score。

          实测踩过：升级前的老库里存着旧算法算出的 score=0
          （危险 19×20 + 可疑 59×4 = −616，钳到 0）。
          新算法下这些事件全部归为「用户自身操作」，
          正确分数是 100 —— 但直接读库会继续显示 0，
          用户看到的还是那个错误的分数，
          而所有新记录都已按新算法落库，
          于是同一个中转站出现「历史 0 分、现在 100 分」的分裂。

          更麻烦的是它**不会自愈**：
          record_call 只在被调用时重算，
          长期不再调用的中转站会永远卡在旧分数上。

          分数是**派生值**，永远不该信任持久化的副本 ——
          算法一改，所有历史分数都必须重算。
        """
        # 延迟突变计数依赖内存里的延迟窗口，
        # 导入时无法复原，但 _compute_score 已不再使用它，
        # 所以这里直接重算即可。
        rep.score = self._compute_score(rep)
        self._reputations[rep.domain] = rep
        if rep.latency_samples > 0 and rep.avg_latency_ms > 0:
            # 恢复延迟基线（前 5 个样本作为初始基线）
            n = min(5, rep.latency_samples)
            self._latencies[rep.domain] = [rep.avg_latency_ms] * n
        logger.info(
            "已导入中转站信誉: %s (分数按当前算法重算为 %d)",
            rep.domain, rep.score,
        )

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

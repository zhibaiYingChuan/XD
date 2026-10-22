# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""第一层：请求侧敏感信息脱敏（sanitizer）。

职责：在请求转发给中转站**之前**，扫描用户内容中的敏感信息，
按策略做「阻断 / 打码 / 告警」处置，生成可恢复的占位符。

关键约束（安全底线）：
1. 原始敏感值**只存于本地 DB**，绝不写入任何外发内容或日志
2. 脱敏占位符使用 `⟦XD_{index}⟧` 格式，数学字母括号避免与原文冲突
3. 脱敏必须**幂等**——同一段文本重复脱敏产生相同结果
4. 命中阻断类敏感信息时**绝不**降级为打码（防止半泄露）

复用企业版敏感信息检测器（`daoti_xuandun.sensitive_leak`）的规则库，
但个人版的处置策略与分类维度独立。
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..types import (
    Action,
    RedactionRecord,
    SanitizeResult,
    SecurityLevel,
)

logger = logging.getLogger("xuandun-personal.sanitizer")

# ══════════════════════════════════════════════════════════════
# 敏感类型定义
# ══════════════════════════════════════════════════════════════

# 各敏感类型的三级处置策略：(宽松, 均衡, 严格)
# Action.BLOCK = 阻断（绝不外发）
# Action.REDACT = 打码（替换为占位符）
# Action.ALERT = 仅告警（放行但标记）
_POLICY: Dict[str, Tuple[str, str, str]] = {
    "api_key":    (Action.BLOCK.value,  Action.BLOCK.value,  Action.BLOCK.value),
    "idcard":     (Action.BLOCK.value,  Action.BLOCK.value,  Action.BLOCK.value),
    "bankcard":   (Action.BLOCK.value,  Action.BLOCK.value,  Action.BLOCK.value),
    "phone":      (Action.PASS.value,  Action.REDACT.value, Action.BLOCK.value),
    "email":      (Action.PASS.value,  Action.REDACT.value, Action.BLOCK.value),
    "aws_key":    (Action.BLOCK.value,  Action.BLOCK.value,  Action.BLOCK.value),
    "private_key":(Action.BLOCK.value,  Action.BLOCK.value,  Action.BLOCK.value),
    "jwt":        (Action.BLOCK.value,  Action.BLOCK.value,  Action.BLOCK.value),
    "custom":     (Action.PASS.value,  Action.REDACT.value, Action.BLOCK.value),
}

# 敏感类型的中文名（UI 展示用）
CATEGORY_LABELS: Dict[str, str] = {
    "api_key": "API 密钥",
    "aws_key": "AWS 凭证",
    "private_key": "私钥",
    "jwt": "JWT 令牌",
    "idcard": "身份证",
    "bankcard": "银行卡",
    "phone": "手机号",
    "email": "邮箱",
    "custom": "自定义关键词",
}


# ══════════════════════════════════════════════════════════════
# 校验函数（降误报）
# ══════════════════════════════════════════════════════════════


def _luhn_check(number: str) -> bool:
    """Luhn 校验（银行卡号，ISO 7812）。"""
    if not number.isdigit() or not (13 <= len(number) <= 19):
        return False
    total = 0
    parity = len(number) % 2
    for i, ch in enumerate(number):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _cn_id_checksum_valid(id_no: str) -> bool:
    """中国身份证 18 位 ISO 7064 MOD 11-2 校验。"""
    if len(id_no) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_map = "10X98765432"
    try:
        total = sum(int(ch) * w for ch, w in zip(id_no[:17], weights))
    except ValueError:
        return False
    return id_no[17].upper() == check_map[total % 11]


# ══════════════════════════════════════════════════════════════
# 检测规则
# ══════════════════════════════════════════════════════════════


class _Rule:
    """单条敏感信息检测规则。"""

    __slots__ = ("name", "category", "pattern", "validator")

    def __init__(
        self,
        name: str,
        category: str,
        pattern: str,
        validator: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.name = name
        self.category = category
        self.pattern = re.compile(pattern)
        self.validator = validator

    def find(self, text: str) -> List[Tuple[int, int, str]]:
        """返回所有匹配的 (start, end, matched_text)。"""
        results = []
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator and not self.validator(value):
                continue
            results.append((m.start(), m.end(), value))
        return results


# 内置规则库（9 类，与企业版 sensitive_leak.py 对齐但独立维护）
BUILTIN_RULES: List[_Rule] = [
    # ── 云凭证（一律阻断）──
    # ★ 字符类必须含 `-`：OpenAI 现役密钥是 sk-proj- 前缀（sk-proj-a1b2…），
    #   原式 `sk-[A-Za-z0-9]{20,}` 里的 `-` 不在类内，
    #   只能匹配到 `sk-` 后紧跟字母数字的老格式，
    #   对 sk-proj- / sk-svcacct- 这类带第二段前缀的现代密钥**完全漏放**。
    #   （实测：`sk-proj-a1b2c3d4e5f6…` 长度 54 的真实格式不被识别。）
    _Rule("openai_key", "api_key", r"\bsk-[A-Za-z0-9\-_]{20,}\b"),
    _Rule("anthropic_key", "api_key", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
    _Rule("google_key", "api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    _Rule("azure_key", "api_key", r"(?i)\bazure[_a-z]*key\s*[:=]\s*\S{20,}"),
    _Rule("generic_secret", "api_key",
          r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)"
          r"\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}"),
    _Rule("aws_akid", "aws_key", r"\bAKIA[0-9A-Z]{16}\b"),
    _Rule("aws_secret", "aws_key",
          r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]?[A-Za-z0-9/+=]{40}"),
    _Rule("gcp_sa", "aws_key", r'"type"\s*:\s*"service_account"'),
    _Rule("private_key_pem", "private_key",
          r"-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP|DSA)?\s*PRIVATE KEY-----"),
    _Rule("jwt", "jwt", r"\beyJ[A-Za-z0-9\-_]{8,}\.eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{10,}"),

    # ── 强身份信息（一律阻断）──
    _Rule("cn_idcard", "idcard", r"(?<![0-9Xx])\d{17}[\dXx](?![0-9Xx])",
          _cn_id_checksum_valid),
    _Rule("bankcard", "bankcard", r"(?<!\d)\d{13,19}(?!\d)", _luhn_check),

    # ── 弱身份信息（按级别打码/阻断）──
    _Rule("cn_phone", "phone", r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    _Rule("email", "email",
          r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
]


# ══════════════════════════════════════════════════════════════
# 阻断证据（可核对，但不可还原）
# ══════════════════════════════════════════════════════════════


def _mask_value(value: str, keep: int = 4) -> str:
    """把敏感值压成「前 4 + 长度 + 尾 2」。

    ★ 2026-10-20：实现收敛到 ``types.mask_secret`` ——
      存储层（落库掩码、历史数据迁移）也需要同一套规则，
      两处各写一份必然漂移（一边含 ⟪、一边不含，幂等就失效）。
    """
    from ..types import mask_secret

    return mask_secret(value, keep)


def credential_fingerprint(value: str) -> str:
    """凭证指纹：SHA-256(原值)。

    ★ 为什么用哈希而不是原文：
      台账要跨轮次、跨日志判定「是不是同一枚凭证」，哈希足够；
      而把原文留在库里只会多个泄露面。用户要拿证据去对质时，
      对方也可以用同一串原文算出同样的哈希来核对。
    """
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _hit_infos(
    text: str, deduped: List[Tuple[int, int, str, str]]
) -> List[Dict[str, Any]]:
    """把命中区间整理成台账可用的结构（含指纹，不含原文）。"""
    return [
        {
            "category": cat,
            "fingerprint": credential_fingerprint(text[start:end]),
            "length": end - start,
            "start": start,
            "end": end,
            "masked": _mask_value(text[start:end]),
        }
        for start, end, cat, _rule in deduped
    ]


def _masked_evidence(
    text: str, deduped: List[Tuple[int, int, str, str]]
) -> List[RedactionRecord]:
    """为阻断命中生成掩码证据记录。

    ★ 与打码记录的区别：`original` 存的是**掩码后**的字符串，
      不是原文。这是刻意的 —— 阻断路径的证据会经 detail_json
      进 /api/logs、也会进 CSV 导出，存原文等于开一条泄露通道。
      落库的 original 因此只能用于「核对」，不能用于「还原」。
    """
    records: List[RedactionRecord] = []
    for idx, (start, end, category, rule_name) in enumerate(deduped, start=1):
        records.append(
            RedactionRecord(
                index=idx,
                category=category,
                original=_mask_value(text[start:end]),
                redacted=RedactionRecord.placeholder(idx),
                start=start,
                end=end,
                action=Action.BLOCK.value,
            )
        )
    return records


# ══════════════════════════════════════════════════════════════
# 脱敏器
# ══════════════════════════════════════════════════════════════


class RequestSanitizer:
    """请求侧敏感信息脱敏器。

    使用示例：
        sanitizer = RequestSanitizer(level=SecurityLevel.BALANCED)
        result = sanitizer.sanitize("我的手机号是 13812345678")
        # result.sanitized_text = "我的手机号是 ⟦XD_0⟧"
        # result.redaction_count == 1
    """

    def __init__(
        self,
        level: str = SecurityLevel.BALANCED.value,
        custom_keywords: Optional[List[str]] = None,
    ) -> None:
        self._level = level
        self._custom_keywords: List[str] = []
        self._enabled_categories: Dict[str, bool] = {
            "api_key": True, "aws_key": True, "private_key": True,
            "jwt": True, "idcard": True, "phone": True, "email": True,
            # ★ P1-5：与 config.GuardConfig 及产品文档 4.4 保持一致
            "bankcard": False, "custom": False,
        }
        if custom_keywords:
            self.add_custom_keywords(custom_keywords)

    # ── 配置 ──

    @property
    def level(self) -> str:
        return self._level

    def set_level(self, level: str) -> None:
        """切换安全级别。"""
        if level not in (s.value for s in SecurityLevel):
            raise ValueError(f"无效的安全级别: {level}")
        self._level = level
        logger.info("脱敏安全级别切换为 %s", level)

    def set_category_enabled(self, category: str, enabled: bool) -> None:
        """启用/禁用某类敏感信息检测（对应设置页的勾选框）。"""
        if category in self._enabled_categories:
            self._enabled_categories[category] = enabled
            logger.debug("敏感类型 %s → %s", category, "启用" if enabled else "禁用")

    def get_enabled_categories(self) -> Dict[str, bool]:
        return dict(self._enabled_categories)

    def add_custom_keywords(self, keywords: List[str]) -> int:
        """添加自定义关键词，返回实际添加的数量（去重后）。"""
        added = 0
        existing = {k.lower() for k in self._custom_keywords}
        for kw in keywords:
            k = kw.strip()
            if not k or k.lower() in existing:
                continue
            self._custom_keywords.append(k)
            existing.add(k.lower())
            added += 1
        if added:
            logger.info("新增 %d 个自定义敏感关键词", added)
        return added

    def remove_custom_keywords(self, keywords: List[str]) -> int:
        """移除自定义关键词，返回实际移除的数量。"""
        targets = {k.strip().lower() for k in keywords}
        before = len(self._custom_keywords)
        self._custom_keywords = [k for k in self._custom_keywords if k.lower() not in targets]
        removed = before - len(self._custom_keywords)
        if removed:
            logger.info("移除 %d 个自定义敏感关键词", removed)
        return removed

    def list_custom_keywords(self) -> List[str]:
        return list(self._custom_keywords)

    # ── 策略查询 ──

    def _policy_for(self, category: str) -> str:
        """返回某敏感类型在当前安全级别下的处置动作。"""
        policy = _POLICY.get(category)
        if policy is None:
            return Action.ALERT.value
        index = {
            SecurityLevel.LENIENT.value: 0,
            SecurityLevel.BALANCED.value: 1,
            SecurityLevel.STRICT.value: 2,
        }.get(self._level, 1)
        return policy[index]

    # ── 核心：脱敏 ──

    def sanitize(self, text: str, block_as_redact: bool = False) -> SanitizeResult:
        """对请求文本执行脱敏。

        流程：
        1. 收集所有敏感命中（内置规则 + 自定义关键词）
        2. 按起始位置排序，重叠区间保留更长的匹配
        3. 按策略判定：BLOCK 类直接返回阻断结果
        4. REDACT 类替换为占位符，倒序替换避免偏移错乱
        5. ALERT 类仅记录，不改动文本

        Args:
            text: 用户原始请求文本
            block_as_redact: 把「阻断」降级为「打码」。
                ★ 2026-10-23：只给**工具返回**用。
                  AI 的工具（读文件、请求接口）把登录 token 带回来时，
                  整轮阻断会让对话直接中断，而且这段内容留在历史里，
                  之后每轮都会被再拦一次 —— 用户看到的是「聊到一半突然
                  一直发不出去」。打码同样能保证 token 不外发
                  （中转站只看到 ⟦XD_n⟧），但不打断对话。
                  用户自己打的字仍按阻断处理：那是「正要贴密钥」的时刻，
                  必须让他停下来。

        Returns:
            SanitizeResult：含脱敏后文本、记录列表、整体处置
        """
        if not text:
            return SanitizeResult(sanitized_text="", action=Action.PASS.value)

        deduped = self._collect(text)
        if not deduped:
            return SanitizeResult(sanitized_text=text, action=Action.PASS.value)

        # ★ 每条命中都带指纹：台账据此判定「首次出现在哪一侧」
        hits = _hit_infos(text, deduped)

        # ③ 判定：BLOCK 类优先（绝不降级为打码）
        #   ★ 例外：调用方明确要求「阻断降级为打码」（工具返回），
        #     此时所有命中一律走下面的打码流程，token 照样不外发。
        blocked_categories = [
            (cat, rn) for s, e, cat, rn in deduped
            if self._policy_for(cat) == Action.BLOCK.value
        ]
        hit_categories = sorted({cat for _, _, cat, _ in deduped})

        if blocked_categories and not block_as_redact:
            labels = sorted({CATEGORY_LABELS.get(c, c) for c, _ in blocked_categories})
            return SanitizeResult(
                sanitized_text="",           # ★ 阻断时绝不返回任何原文
                action=Action.BLOCK.value,
                hit_categories=hit_categories,
                blocked_reason=f"检测到不可外发的敏感信息：{'、'.join(labels)}",
                # ★ 阻断也必须给出可核对的证据。
                #   原实现 records 为空，落库后界面只剩一句结论，
                #   用户无从判断真假 —— 40 条 JWT 拦截里绝大多数是
                #   用户自己把激活码贴进对话，属实但「看起来像误报」。
                #   这里对每个命中区间做掩码：保留类型、前后少量字符
                #   与长度，中间一律替换。足以定位，又不泄露原文。
                records=_masked_evidence(text, deduped),
                hits=hits,
            )

        # ③.5 过滤：策略为 PASS 的命中不脱敏（如宽松级的手机号/邮箱）
        #   v0.1.0 修复：宽松级应完全放行，原实现把 PASS 策略的命中也当作 REDACT 处理
        #   ★ block_as_redact 时把 BLOCK 类也纳入打码范围。
        allowed = {Action.REDACT.value}
        if block_as_redact:
            allowed.add(Action.BLOCK.value)
        redactable = [
            (s, e, cat, rn) for s, e, cat, rn in deduped
            if self._policy_for(cat) in allowed
        ]
        if not redactable:
            return SanitizeResult(
                sanitized_text=text,
                action=Action.PASS.value,
                hit_categories=hit_categories,   # 仍记录命中，便于 UI 提示
                hits=hits,
            )

        # ④ 打码：倒序替换避免偏移错乱
        records: List[RedactionRecord] = []
        sanitized = text
        for idx, (start, end, category, rule_name) in enumerate(
            reversed(redactable), start=1
        ):
            # 倒序遍历时编号需还原为正序语义
            real_index = len(redactable) - idx + 1
            original_value = text[start:end]
            placeholder = RedactionRecord.placeholder(real_index)
            records.append(
                RedactionRecord(
                    index=real_index,
                    category=category,
                    original=original_value,
                    redacted=placeholder,
                    start=start,
                    end=end,
                    action=Action.REDACT.value,
                )
            )
            sanitized = sanitized[:start] + placeholder + sanitized[end:]

        # 还原为正序（按 index 升序），便于第三层恢复
        records.sort(key=lambda r: r.index)

        action = Action.REDACT.value if records else Action.PASS.value
        return SanitizeResult(
            sanitized_text=sanitized,
            records=records,
            action=action,
            hit_categories=hit_categories,
            hits=hits,
        )

    # ── 只扫描不改写（响应侧来源判定用）──

    def scan(self, text: str) -> List[Dict[str, Any]]:
        """找出文本里的凭证，返回指纹与打码片段，**不改写文本**。

        ★ 与 sanitize 的区别：
          响应侧只想知道「中转站返回的内容里有没有一枚没见过的凭证」，
          不打算改写它 —— 改写会破坏对话，也掩盖了对方到底发了什么。
          两处必须共用同一套规则与去重口径，否则「请求里有、响应里没有」
          这种结论会因为规则差异而失真。
        """
        if not text:
            return []
        return _hit_infos(text, self._collect(text))

    def _collect(self, text: str) -> List[Tuple[int, int, str, str]]:
        """收集并去重所有命中区间（sanitize 与 scan 的唯一口径）。"""
        hits: List[Tuple[int, int, str, str]] = []

        for rule in BUILTIN_RULES:
            if not self._enabled_categories.get(rule.category, True):
                continue
            for start, end, value in rule.find(text):
                hits.append((start, end, rule.category, rule.name))

        if self._enabled_categories.get("custom", True):
            for kw in self._custom_keywords:
                if not kw:
                    continue
                # 简单字面量匹配（转义正则特殊字符），不区分大小写
                pattern = re.compile(re.escape(kw), re.IGNORECASE)
                for m in pattern.finditer(text):
                    hits.append((m.start(), m.end(), "custom", f"custom:{kw}"))

        if not hits:
            return []

        # 区间去重：按 start 排序，重叠时保留更长的匹配
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        deduped: List[Tuple[int, int, str, str]] = []
        last_end = -1
        for start, end, category, rule_name in hits:
            if start >= last_end:
                deduped.append((start, end, category, rule_name))
                last_end = end
        return deduped

    # ── 诊断 ──

    def describe_categories(self) -> List[Dict[str, Any]]:
        """返回各敏感类型的策略说明（供设置页 UI 展示）。"""
        result = []
        for cat, label in CATEGORY_LABELS.items():
            enabled = self._enabled_categories.get(cat, True)
            current = self._policy_for(cat)
            result.append(
                {
                    "category": cat,
                    "label": label,
                    "enabled": enabled,
                    "current_action": current,
                    "policy": {
                        "lenient": _POLICY.get(cat, (None,) * 3)[0],
                        "balanced": _POLICY.get(cat, (None,) * 3)[1],
                        "strict": _POLICY.get(cat, (None,) * 3)[2],
                    },
                }
            )
        return result

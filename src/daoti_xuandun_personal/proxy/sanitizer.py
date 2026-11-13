# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""第一层：请求侧敏感信息脱敏（sanitizer）。

职责：在请求转发给中转站**之前**，扫描用户内容中的敏感信息，
按策略做「阻断 / 打码 / 告警」处置，生成可恢复的占位符。

关键约束（安全底线）：
1. 原始敏感值**只存于本地 DB**，绝不写入任何外发内容或日志
2. 脱敏占位符使用 `⟦KH_{index}⟧` 格式，数学字母括号避免与原文冲突
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


def _card_network_ok(number: str) -> bool:
    """按卡组织规则校验「前缀 + 长度」是否匹配（ISO/IEC 7812）。

    ★★ 2026-11-04：为什么只做 Luhn 不够
    ────────────────────────────────────────────────────────────
    实测误报：用户消息里出现 3 个 15–16 位数字，全部通过 Luhn，
    被当成 3 张银行卡整条阻断。但其中：
      · 15 位、53 开头 —— MasterCard 必须是 16 位，不可能是卡
      · 16 位、16 开头 —— 16 不属于任何卡组织前缀
    也就是说，**Luhn 只校验「校验位对不对」，不校验「这是不是卡」**。
    任意 15–19 位数字约有 1/10 概率通过 Luhn，长文本里很容易撞上。

    这里补上卡组织的前缀与长度约束：只有同时满足，
    才可能是真卡。订单号、时间戳、日志 ID 基本都会被挡掉。
    """
    n = len(number)
    if not number.isdigit():
        return False
    p1 = number[0]
    p2 = number[:2]
    p3 = number[:3]
    p4 = number[:4]

    # Visa：13 / 16 / 19 位，4 开头
    if p1 == "4" and n in (13, 16, 19):
        return True
    # MasterCard：16 位，51–55 或 2221–2720
    if n == 16 and (
        p2 in {"51", "52", "53", "54", "55"}
        or (p4.isdigit() and 2221 <= int(p4) <= 2720)
    ):
        return True
    # American Express：15 位，34 / 37
    if n == 15 and p2 in {"34", "37"}:
        return True
    # Discover：16 位，6011 / 65 / 644–649
    if n == 16 and (
        p4 == "6011"
        or p2 == "65"
        or (p3.isdigit() and 644 <= int(p3) <= 649)
    ):
        return True
    # JCB：16 位，3528–3589
    if n == 16 and p4.isdigit() and 3528 <= int(p4) <= 3589:
        return True
    # UnionPay：16–19 位，62
    if 16 <= n <= 19 and p2 == "62":
        return True
    # Diners Club：14 位，300–305 / 36 / 38
    if n == 14 and (
        p2 in {"36", "38"}
        or (p3.isdigit() and 300 <= int(p3) <= 305)
    ):
        return True
    # Maestro：16–19 位，50 / 56–69
    if 16 <= n <= 19 and (
        p2 == "50" or (p2.isdigit() and 56 <= int(p2) <= 69)
    ):
        return True
    return False


def _luhn_check(number: str) -> bool:
    """银行卡号校验：卡组织前缀 + 长度 + Luhn（ISO 7812）。"""
    if not number.isdigit() or not (13 <= len(number) <= 19):
        return False
    # ★ 2026-11-04：先过卡组织规则，再过 Luhn。
    #   顺序不能反：Luhn 对任意数字都有 1/10 通过率，
    #   先做它等于让大量非卡数字进入下一步。
    if not _card_network_ok(number):
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


#: 卡号语境词。数字附近出现这些词，才认为用户是在说「卡号」。
#: ★ 2026-11-04：格式合法还不够 —— 长文本里的订单号、日志 ID
#:   也可能恰好符合卡组织格式。加一层语境判断，把「碰巧像卡」挡掉。
_CARD_CONTEXT = re.compile(
    r"(?:卡号|银行卡|信用卡|借记卡|储蓄卡|银联卡|"
    r"card\s*(?:no|number)?|credit\s*card|debit\s*card|"
    r"cvv|cvc|有效期|expiry|expiration)",
    re.IGNORECASE,
)


def _has_card_context(text: str, start: int, end: int, window: int = 40) -> bool:
    """数字附近是否有「卡号」语境，或它是否独占一行。

    ★ 为什么需要它（2026-11-04 实测误报）
    ────────────────────────────────────────────────────────────
    用户消息里 3 个 15–16 位数字被当成 3 张银行卡整条阻断，
    但用户确认没有输入任何卡号。格式校验只能挡掉「前缀/长度不对」的，
    挡不掉「格式完全合法但其实是订单号」的。

    判定口径：
      · 前后 40 字符内出现「卡号 / 银行卡 / card / CVV / 有效期」→ 是卡
      · 数字独占一行（前后只有空白或标点）→ 是卡
      · 其余情况 → 不当作卡，不阻断、不打码
    """
    left = text[max(0, start - window):start]
    right = text[end:end + window]
    if _CARD_CONTEXT.search(left) or _CARD_CONTEXT.search(right):
        return True

    # 独占一行：整行去掉首尾空白后，正好就是这个数字
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    return line == text[start:end]


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


#: 本产品自己的激活码前缀（见 license.py：XDACT- + RS256 JWT）
_ACTIVATION_PREFIX = "XDACT-"


def _is_own_activation_code(text: str, start: int) -> bool:
    """这个 JWT 命中是不是紧跟在 `XDACT-` 后面（即本产品自己的激活码）。"""
    head = text[max(0, start - len(_ACTIVATION_PREFIX)):start]
    return head.upper() == _ACTIVATION_PREFIX


class _Rule:
    """单条敏感信息检测规则。

    ★★ 2026-11-13：不再由本文件声明具体正则。
      全部判据来自 ``rules/credentials.py``（唯一真源），
      本类只负责把规范正则 + 校验器 + 排除器组合成可用的检测单元。

    ★★ 编译不加 IGNORECASE：判据自身需要忽略大小写时，
      在正则内部写 `(?i)`（azure_key / generic_secret / aws_secret_key /
      bearer_token 都是这么写的）。统一加标志会把请求侧拦截面整体放宽，
      实测把 `SK-hynix-semiconductor-annual-report-2026` 判成密钥整条阻断。
    """

    __slots__ = ("name", "category", "pattern", "validator", "allow_if")

    def __init__(
        self,
        name: str,
        category: str,
        pattern: str,
        validator: Optional[Callable[[str], bool]] = None,
        allow_if: Optional[Callable[[str, Any], bool]] = None,
    ) -> None:
        self.name = name
        self.category = category
        self.pattern = re.compile(pattern)
        self.validator = validator
        self.allow_if = allow_if

    def find(self, text: str) -> List[Tuple[int, int, str]]:
        """返回所有可信命中的 (start, end, matched_text)。"""
        results = []
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator and not self.validator(value):
                continue
            if self.allow_if and self.allow_if(text, m):
                continue
            results.append((m.start(), m.end(), value))
        return results


def _builtin_rules_from_registry() -> List[_Rule]:
    """由凭据规则表生成检测规则。

    ★ 为什么改成生成而不是手写列表：
      手写列表时，同一类凭据在 sanitizer / verifier / yaml / 企业版
      各写一份，改一处不生效（2026-11-13 私钥误报即此）。
      现在只在这里做一次映射，判据本身全部来自 credentials.SPECS。

    ★★ 为什么按 ``request_side`` 过滤：
      请求侧的处置是**阻断 / 打码**，直接影响用户能不能把消息发出去，
      误报代价最高。有一类判据的形态天生与无害物同形 ——
      例如 32/64 位裸 hex 既可能是 AES 密钥，也可能是 MD5/SHA 摘要，
      文本上没有可判别特征。这类判据在真源里声明 ``request_side=False``：
      响应侧与检测侧照常使用（那里只记录告警，误报代价低），
      请求侧不参与 —— 否则「帮我看看这段哈希」会被整条阻断。
      过滤条件来自声明，不在这里按 key 名打补丁。
    """
    from ..rules.credentials import SPECS

    return [
        _Rule(spec.key, spec.category, spec.pattern, spec.validator, spec.allow_if)
        for spec in SPECS
        if spec.request_side
    ]


# 内置规则库：由 rules/credentials.py 生成（勿在此手写正则）
BUILTIN_RULES: List[_Rule] = _builtin_rules_from_registry()


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
        # result.sanitized_text = "我的手机号是 ⟦KH_0⟧"
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

    def sanitize(
        self,
        text: str,
        block_as_redact: bool = False,
        vault: Any = None,
        session_id: str = "",
    ) -> SanitizeResult:
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
                  （中转站只看到 ⟦KH_n⟧），但不打断对话。
                  用户自己打的字仍按阻断处理：那是「正要贴密钥」的时刻，
                  必须让他停下来。
            vault: 可选 ``PlaceholderVault``。传入后占位符编号由保险箱
                按「会话 + 值」分配 —— 同一个值跨轮次、跨消息都是同一个
                编号。★ 这是还原能跨轮次工作的前提：按位置编号时，
                模型复述上一轮的 ⟦KH_3⟧ 会被本轮 3 号（另一个值）顶掉，
                静默替换成错误的秘密。
            session_id: 与 vault 配套的会话标识。

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
            original_value = text[start:end]
            if vault is not None and session_id:
                # ★ 稳定编号：同一个值在本会话内永远同一个号。
                #   分配失败（保险箱满）时退化为 0 号 —— 该号不会被解析，
                #   值仍然不外发（宁可还原不了，也不能漏出去）。
                real_index = vault.intern(session_id, original_value, category)
            else:
                # 倒序遍历时编号需还原为正序语义
                real_index = len(redactable) - idx + 1
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

        # 按编号升序（同号按出现位置），便于第三层恢复与证据展示
        records.sort(key=lambda r: (r.index, r.start))

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
                # ★★ 2026-10-27：放行勘合自己的激活码。
                #
                #   激活码本身就是 RS256 JWT（`XDACT-` + 三段式），
                #   JWT 规则必然命中，于是「用户把自家激活码贴进对话」
                #   会被自家产品当成「不可外发的令牌」直接拦下 ——
                #   实测已发生两次（日志 #4499 / #4500）。
                #   用户看到的只有「请求被拦截」，不会想到是自己贴的激活码。
                #
                #   放行不等于不设防：激活码一码一机、绑定硬件，
                #   泄露到中转站也换不了机器；而拦住它只会让用户没法求助。
                if rule.category == "jwt" and _is_own_activation_code(text, start):
                    continue
                # ★ 2026-11-04：银行卡必须同时满足「格式合法」和「有卡号语境」。
                #   格式合法但附近没有卡号语境的长数字（订单号、日志 ID、
                #   时间戳）不当作卡 —— 否则长文本里随便一个数字都能
                #   触发整条阻断，用户看到的就是「我没输卡号却被拦」。
                if rule.category == "bankcard" and not _has_card_context(
                    text, start, end
                ):
                    continue
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

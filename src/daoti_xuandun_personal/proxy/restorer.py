# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""第三层：脱敏内容恢复（restorer）。

职责：在响应返回给用户/AI 工具**之前**，把第一层打码的占位符
还原为用户原始值。

★ 2026-10-27 重做：映射改由 ``PlaceholderVault`` 托管
────────────────────────────────────────────────────────────
原实现把映射挂在本类上，键是「本轮请求内的顺序编号」，并在每轮
响应后整表清空。三个后果：

1. 同一值跨轮换号 → 模型无法复用引用；
2. 编号每轮从 1 重排 → 模型复述上一轮的 ``⟦XD_3⟧`` 时，
   本轮 3 号可能是另一个值，还原出**错误的秘密**；
3. 响应后清空 → 模型把占位符留到下一轮就再也还原不了。

现在编号按「会话 + 值」稳定分配，映射随会话存活。

安全约束（不变）
────────────────
1. 占位符必须是本会话由本代理生成的（防止中转站伪造占位符骗取原始值）
2. 恢复只在本机内存完成，绝不写回中转站
3. 中转站若篡改了占位符编号，解析失败 → 记为异常，原样保留占位符
"""

from __future__ import annotations

import json
import logging
import re
from typing import List, Optional, Tuple

from ..types import RedactionRecord, VerificationFinding
from .vault import PlaceholderVault

logger = logging.getLogger("xuandun-personal.restorer")

# 占位符匹配模式
_PLACEHOLDER_PATTERN = re.compile(r"⟦XD_(\d+)⟧")
# 中转站以 ensure_ascii=True 序列化时出现的形式
_ESCAPED_OPEN = "\\u27e6"
_ESCAPED_CLOSE = "\\u27e7"


class ContentRestorer:
    """脱敏内容恢复器。

    使用示例：
        restorer = ContentRestorer()
        session_id = restorer.begin_session("sess-abc")
        restorer.register(session_id, sanitize_result.records)
        # ... 转发到中转站 ...
        restored, anomalies = restorer.restore(session_id, upstream_response)
    """

    def __init__(
        self,
        max_sessions: int = 1000,
        ttl_seconds: float = 24 * 60 * 60,
    ) -> None:
        self._vault = PlaceholderVault(
            max_sessions=max_sessions, ttl_seconds=ttl_seconds
        )

    # ── 对外暴露保险箱（供脱敏侧分配稳定编号）──

    @property
    def vault(self) -> PlaceholderVault:
        return self._vault

    # ── 会话管理 ──

    def begin_session(self, session_id: Optional[str] = None) -> str:
        """开启（或续期）一个会话，返回实际 session_id。"""
        return self._vault.begin_session(session_id)

    def register(self, session_id: str, records: List[RedactionRecord]) -> None:
        """登记本次请求的脱敏记录（供后续恢复）。"""
        self._vault.begin_session(session_id)
        for rec in records:
            self._vault.bind(session_id, rec.index, rec.original, rec.category)
        logger.debug("会话 %s 登记 %d 条脱敏记录", session_id, len(records))

    def clear_after_response(self, session_id: str) -> None:
        """★ 保留 API，但语义已改变：**不再清空**。

        原实现在每轮响应后清空映射，目的是「防止原始敏感值长期驻留内存」。
        但代价是模型只要把占位符留到下一轮，就再也还原不了 ——
        而这恰恰是正常的对话形态（模型先说「稍后我会用你的邮箱」）。

        现在映射由 ``PlaceholderVault`` 按会话托管，随 24 小时 TTL 或
        LRU 淘汰自然释放，安全边界等价，功能不再被破坏。
        保留空实现是为了不打断既有调用点与测试。
        """
        return None

    def clear_session(self, session_id: str) -> None:
        """彻底移除一个会话。"""
        self._vault.drop_session(session_id)

    # ── 核心：恢复 ──

    def restore(
        self, session_id: str, text: str, json_escape: bool = False
    ) -> Tuple[str, List[VerificationFinding]]:
        """把响应中的占位符还原为原始值。

        Args:
            session_id: 会话标识
            text: 中转站返回的文本（若来源是 SSE 帧，则已做过转义归一）
            json_escape: 还原出来的值是否需要重新做 JSON 字符串转义。
                ★ 当上游以 ``\\u27e6XD_1\\u27e7`` 的转义形态发送占位符时，
                  本方法会先把转义还原成字面量再替换；此时被替换进去的
                  原始值如果含引号/反斜杠/换行，会直接撑破外层 JSON。
                  流式路径必须传 True。

        Returns:
            (restored_text, anomalies)
        """
        if not text or "⟦XD_" not in text:
            return text, []

        anomalies: List[VerificationFinding] = []
        unknown_ids: set = set()

        def _repl(m: re.Match) -> str:
            idx = int(m.group(1))
            original = self._vault.resolve(session_id, idx)
            if original is None:
                unknown_ids.add(idx)
                return m.group(0)      # 保持原样
            if json_escape:
                # 去掉外层引号，只保留转义体（含 \" \\ \n 等）
                return json.dumps(original, ensure_ascii=False)[1:-1]
            return original

        restored = _PLACEHOLDER_PATTERN.sub(_repl, text)

        if unknown_ids:
            if not self._vault.has_session(session_id) or self._vault.size(session_id) == 0:
                anomalies.append(
                    VerificationFinding(
                        category="placeholder_injection",
                        severity="high",
                        detail=(
                            "响应中出现未经本代理生成的脱敏占位符，"
                            "疑似中转站伪造以探测原始值"
                        ),
                        evidence=text[:80],
                    )
                )
            else:
                anomalies.append(
                    VerificationFinding(
                        category="placeholder_injection",
                        severity="medium",
                        detail=(
                            f"响应中出现本会话未登记的占位符编号 {sorted(unknown_ids)}，"
                            "中转站可能试图还原或伪造占位符"
                        ),
                        evidence="",
                    )
                )
            logger.warning(
                "会话 %s 出现未知占位符编号: %s", session_id, sorted(unknown_ids)
            )

        return restored, anomalies

    # ── 工具 ──

    def has_placeholders(self, text: str) -> bool:
        """判断文本中是否含占位符（快速预检，两种形态都认）。"""
        return bool(text) and ("⟦XD_" in text or _ESCAPED_OPEN in text)

    def count_placeholders(self, text: str) -> int:
        """统计占位符数量（字面量形态）。"""
        return len(_PLACEHOLDER_PATTERN.findall(text)) if text else 0

    def placeholder_ids(self, text: str) -> List[int]:
        """列出文本中出现的占位符编号（去重、升序）。"""
        if not text:
            return []
        return sorted({int(x) for x in _PLACEHOLDER_PATTERN.findall(text)})

    @staticmethod
    def normalize_escaped(text: str) -> str:
        """把 ``\\u27e6 … \\u27e7`` 归一成字面量 ``⟦ … ⟧``。"""
        if not text:
            return text
        return text.replace(_ESCAPED_OPEN, "⟦").replace(_ESCAPED_CLOSE, "⟧")

    @staticmethod
    def is_escaped_form(text: str) -> bool:
        """判断这段文本里的占位符是否以 ``\\u27e6`` 转义形态出现。"""
        return bool(text) and _ESCAPED_OPEN in text

    def stats(self) -> dict:
        """保险箱聚合统计（不含原文，可安全展示）。"""
        return self._vault.stats()

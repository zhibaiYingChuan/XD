# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""第三层：脱敏内容恢复（restorer）。

职责：在响应返回给用户/AI 工具**之前**，把第一层打码的占位符
还原为用户原始值。

安全约束：
1. 占位符必须是本会话由本代理生成的（防止中转站伪造占位符骗取原始值）
2. 恢复只在本机内存完成，绝不写回中转站
3. 中转站若篡改了占位符编号，返回对应的原始值会失败 → 记为异常
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from ..types import Action, RedactionRecord, VerificationFinding, VerifyResult

logger = logging.getLogger("xuandun-personal.restorer")

# 占位符匹配模式
_PLACEHOLDER_PATTERN = re.compile(r"⟦XD_(\d+)⟧")


class ContentRestorer:
    """脱敏内容恢复器。

    使用示例：
        restorer = ContentRestorer()
        session_id = restorer.begin_session()
        restorer.register(session_id, sanitize_result.records)
        # ... 转发到中转站 ...
        restored, anomalies = restorer.restore(session_id, upstream_response)
    """

    def __init__(self, max_sessions: int = 1000):
        self._max_sessions = max_sessions
        # session_id -> {index: RedactionRecord}
        self._sessions: Dict[str, Dict[int, RedactionRecord]] = {}
        self._order: List[str] = []   # LRU 顺序

    # ── 会话管理 ──

    def begin_session(self, session_id: Optional[str] = None) -> str:
        """开启一个新会话（返回实际 session_id）。"""
        sid = session_id or f"ps_{id(self)}_{len(self._order)}"
        if sid not in self._sessions:
            self._sessions[sid] = {}
            self._order.append(sid)
            # LRU 淘汰
            while len(self._order) > self._max_sessions:
                oldest = self._order.pop(0)
                self._sessions.pop(oldest, None)
                logger.debug("恢复器 LRU 淘汰会话 %s", oldest)
        return sid

    def register(self, session_id: str, records: List[RedactionRecord]) -> None:
        """登记本次请求的脱敏记录（供后续恢复）。"""
        if session_id not in self._sessions:
            self.begin_session(session_id)
        mapping = self._sessions[session_id]
        for rec in records:
            mapping[rec.index] = rec
        # 本次请求的记录已消费，清空旧记录（避免跨轮次占位符编号冲突）
        # 注意：保留本轮，下一轮 register 时覆盖
        logger.debug("会话 %s 登记 %d 条脱敏记录", session_id, len(records))

    def clear_after_response(self, session_id: str) -> None:
        """响应返回后清理本轮记录（防止原始敏感值长期驻留内存）。"""
        if session_id in self._sessions:
            self._sessions[session_id].clear()

    def clear_session(self, session_id: str) -> None:
        """彻底移除一个会话。"""
        self._sessions.pop(session_id, None)
        if session_id in self._order:
            self._order.remove(session_id)

    # ── 核心：恢复 ──

    def restore(self, session_id: str, text: str) -> Tuple[str, List[VerificationFinding]]:
        """把响应中的占位符还原为原始值。

        Args:
            session_id: 会话标识
            text: 中转站返回的文本

        Returns:
            (restored_text, anomalies)
            - restored_text：还原后的文本
            - anomalies：中转站篡改占位符的异常发现项
        """
        if not text or "⟦XD_" not in text:
            return text, []

        mapping = self._sessions.get(session_id, {})
        if not mapping:
            # 没有登记记录但出现占位符 → 中转站伪造
            anomalies = [
                VerificationFinding(
                    category="placeholder_injection",
                    severity="high",
                    detail="响应中出现未经本代理生成的脱敏占位符，疑似中转站伪造以探测原始值",
                    evidence=text[:80],
                )
            ]
            logger.warning("会话 %s 出现未登记的占位符（%d 处）",
                           session_id, len(_PLACEHOLDER_PATTERN.findall(text)))
            return text, anomalies

        anomalies: List[VerificationFinding] = []
        unknown_ids: set = set()

        def _repl(m: re.Match) -> str:
            idx = int(m.group(1))
            rec = mapping.get(idx)
            if rec is None:
                unknown_ids.add(idx)
                return m.group(0)      # 保持原样
            return rec.original

        restored = _PLACEHOLDER_PATTERN.sub(_repl, text)

        if unknown_ids:
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
            logger.warning("会话 %s 出现未知占位符编号: %s", session_id, sorted(unknown_ids))

        return restored, anomalies

    def has_placeholders(self, text: str) -> bool:
        """判断文本中是否含占位符（快速预检）。"""
        return bool(text) and "⟦XD_" in text

    def count_placeholders(self, text: str) -> int:
        """统计占位符数量。"""
        return len(_PLACEHOLDER_PATTERN.findall(text)) if text else 0

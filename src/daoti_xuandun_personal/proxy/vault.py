# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""占位符保险箱（vault）—— 脱敏与还原之间的唯一真相源。

为什么必须重做
──────────────
原来的恢复映射挂在 ``ContentRestorer`` 上，键是「本轮请求内的顺序编号」，
并且每轮响应结束就整表清空。这带来三个连锁故障，后果一次比一次严重：

1. **同一值换号**：同一个邮箱在第一次请求里是 ``⟦XD_1⟧``，
   第二次请求里因为位置变了变成 ``⟦XD_2⟧``。模型无法跨轮次复用引用。
2. **编号被复用**：编号每轮从 1 重新分配，于是模型只要复述上一轮的
   ``⟦XD_3⟧``，本轮就会用「3 号 = 另一个值」去替换 —— 还原出来的
   是**另一个秘密**。静默写错，比不还原危险得多。
3. **响应后即清空**：模型把占位符留到下一轮再使用时，映射已经没了，
   只能原样透传。

现在的口径
──────────
* 编号按「会话 + 值」分配：同一会话内，同一个值永远同一个编号；
* 编号单调递增、永不复用：宁可号段变长，也不能让旧编号指向新值；
* 映射随会话存活（默认 24 小时，最多 1000 个会话，LRU 淘汰）；
* 只在内存里，不落盘、不进日志。

安全边界
────────
* ``resolve`` 只认本会话分配过的编号 —— 中转站伪造的 ``⟦XD_999⟧``
  解析失败，不会被还原成任何真实值；
* ``bind`` 遇到「同一编号指向不同值」直接拒绝并告警，绝不覆盖 ——
  这是防止编号错位造成错误替换的最后一道闸。
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("xuandun-personal.vault")

# 单个会话内允许登记的占位符上限。
# 一个会话正常几十到几百个；设上限是防止异常客户端把内存撑爆。
_MAX_ENTRIES_PER_SESSION = 5000


class PlaceholderVault:
    """会话级的「值 ⇄ 占位符编号」双向映射。"""

    def __init__(
        self,
        max_sessions: int = 1000,
        ttl_seconds: float = 24 * 60 * 60,
    ) -> None:
        self._lock = threading.RLock()
        self._max_sessions = max(1, int(max_sessions))
        self._ttl = max(60.0, float(ttl_seconds))
        # session_id -> {"by_value": {value: index}, "by_index": {index: (value, category)},
        #                "next_id": int, "touched": float}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._order: List[str] = []          # 最近使用顺序（队尾最新）
        self._anonymous_seq = 0
        # 累计统计（供自检与界面展示，不含任何原文）
        self._stat_interned = 0
        self._stat_resolved = 0
        self._stat_unknown = 0

    # ── 会话生命周期 ──────────────────────────────────────────

    def begin_session(self, session_id: Optional[str] = None) -> str:
        """取得（或创建）一个会话并续期，返回实际使用的 session_id。"""
        with self._lock:
            sid = (session_id or "").strip()
            if not sid:
                self._anonymous_seq += 1
                sid = f"ps_anon_{self._anonymous_seq}"
            now = time.time()
            self._gc_locked(now)
            slot = self._sessions.get(sid)
            if slot is None:
                slot = {
                    "by_value": {},
                    "by_index": {},
                    "next_id": 1,
                    "touched": now,
                }
                self._sessions[sid] = slot
                self._order.append(sid)
                while len(self._order) > self._max_sessions:
                    oldest = self._order.pop(0)
                    self._sessions.pop(oldest, None)
                    logger.debug("占位符保险箱 LRU 淘汰会话 %s", oldest)
            else:
                slot["touched"] = now
                self._touch_locked(sid)
            return sid

    def drop_session(self, session_id: str) -> None:
        """彻底移除一个会话（登出 / 关闭连接时调用）。"""
        with self._lock:
            self._sessions.pop(session_id, None)
            if session_id in self._order:
                self._order.remove(session_id)

    # ── 核心：登记与解析 ──────────────────────────────────────

    def intern(self, session_id: str, value: str, category: str = "") -> int:
        """把原始值登记进保险箱，返回**稳定**的占位符编号。

        同一个值在同一会话内重复登记返回同一个编号 —— 这既是
        「模型能跨轮次复用引用」的前提，也让重复出现只占一个号。
        """
        with self._lock:
            slot = self._slot_locked(session_id)
            existing = slot["by_value"].get(value)
            if existing is not None:
                return int(existing)
            if len(slot["by_index"]) >= _MAX_ENTRIES_PER_SESSION:
                # 达到上限：不再分配新号，退回 0（调用方需按「无法脱敏」处理）
                logger.warning(
                    "会话 %s 占位符数量达到上限 %d，拒绝继续分配",
                    session_id, _MAX_ENTRIES_PER_SESSION,
                )
                return 0
            index = int(slot["next_id"])
            slot["next_id"] = index + 1
            slot["by_value"][value] = index
            slot["by_index"][index] = (value, category)
            self._stat_interned += 1
            return index

    def bind(
        self, session_id: str, index: int, value: str, category: str = ""
    ) -> bool:
        """登记一条已有编号（供 ``register`` 回填记录时使用）。

        ★ 同一编号已经指向**不同的值**时拒绝覆盖并告警。
          这通常意味着有人在外层重排了编号；覆盖会让后续还原
          静默替换成错误的值，比报错严重得多。
        """
        if index <= 0:
            return False
        with self._lock:
            slot = self._slot_locked(session_id)
            current = slot["by_index"].get(int(index))
            if current is not None:
                if current[0] != value:
                    logger.error(
                        "会话 %s 占位符编号 %d 已被占用且值不同，拒绝覆盖",
                        session_id, index,
                    )
                    return False
                return True
            slot["by_index"][int(index)] = (value, category)
            slot["by_value"].setdefault(value, int(index))
            slot["next_id"] = max(int(slot["next_id"]), int(index) + 1)
            return True

    def resolve(self, session_id: str, index: int) -> Optional[str]:
        """把占位符编号还原为原始值；未知编号返回 None。"""
        with self._lock:
            slot = self._sessions.get(session_id)
            if slot is None:
                self._stat_unknown += 1
                return None
            item = slot["by_index"].get(int(index))
            if item is None:
                self._stat_unknown += 1
                return None
            self._stat_resolved += 1
            return item[0]

    def knows(self, session_id: str, index: int) -> bool:
        with self._lock:
            slot = self._sessions.get(session_id)
            return bool(slot) and int(index) in slot["by_index"]

    def has_session(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._sessions

    def size(self, session_id: str) -> int:
        with self._lock:
            slot = self._sessions.get(session_id)
            return len(slot["by_index"]) if slot else 0

    def category_of(self, session_id: str, index: int) -> str:
        with self._lock:
            slot = self._sessions.get(session_id)
            if not slot:
                return ""
            item = slot["by_index"].get(int(index))
            return item[1] if item else ""

    # ── 观测 ──────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """返回聚合统计（绝不含原文，可安全展示/落日志）。"""
        with self._lock:
            return {
                "sessions": len(self._sessions),
                "entries": sum(len(s["by_index"]) for s in self._sessions.values()),
                "interned": self._stat_interned,
                "resolved": self._stat_resolved,
                "unknown": self._stat_unknown,
                "max_sessions": self._max_sessions,
                "ttl_seconds": int(self._ttl),
            }

    # ── 内部 ──────────────────────────────────────────────────

    def _slot_locked(self, session_id: str) -> Dict[str, Any]:
        slot = self._sessions.get(session_id)
        if slot is None:
            # 会话在解析前被 TTL 淘汰（长任务中途跨过 24 小时）：
            # 重建空槽，后续 resolve 会走「未知编号」异常路径，而不是崩。
            slot = {"by_value": {}, "by_index": {}, "next_id": 1, "touched": time.time()}
            self._sessions[session_id] = slot
            self._order.append(session_id)
        slot["touched"] = time.time()
        self._touch_locked(session_id)
        return slot

    def _touch_locked(self, session_id: str) -> None:
        try:
            self._order.remove(session_id)
        except ValueError:
            pass
        self._order.append(session_id)

    def _gc_locked(self, now: float) -> None:
        if len(self._sessions) < self._max_sessions:
            # 未到容量上限时也做一次轻量过期清理（最多扫 32 个，避免 O(n)）
            expired = [
                sid for sid in self._order[:32]
                if now - self._sessions.get(sid, {}).get("touched", now) > self._ttl
            ]
        else:
            expired = [
                sid for sid in self._order
                if now - self._sessions.get(sid, {}).get("touched", now) > self._ttl
            ]
        for sid in expired:
            self._sessions.pop(sid, None)
            try:
                self._order.remove(sid)
            except ValueError:
                pass

    def snapshot_ids(self, session_id: str) -> List[int]:
        """返回本会话已分配的编号（升序），供测试与自检使用。"""
        with self._lock:
            slot = self._sessions.get(session_id)
            return sorted(slot["by_index"].keys()) if slot else []

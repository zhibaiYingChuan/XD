"""玄盾网关 — 已吊销企业 API Key 黑名单（jti 集合，本地持久化）。

吊销是"软删除"：被吊销的 jti 会被网关在后续请求中拒绝，且不可恢复。
文件存于 gateway/.revoked_keys.json（不入库）。
"""
from __future__ import annotations

import json
import os
import threading
from typing import List, Set


class RevokedStore:
    """基于 JSON 文件的 jti 吊销黑名单（线程安全）。"""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.path.join(os.path.dirname(__file__), ".revoked_keys.json")
        self._lock = threading.Lock()
        self._jtis: Set[str] = set()
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._jtis = set(data.get("revoked", []))
        except (OSError, ValueError):
            self._jtis = set()

    def _persist(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"revoked": sorted(self._jtis)}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def contains(self, jti: str) -> bool:
        return jti in self._jtis

    def add(self, jti: str) -> bool:
        with self._lock:
            if jti in self._jtis:
                return False
            self._jtis.add(jti)
            self._persist()
            return True

    def remove(self, jti: str) -> bool:
        with self._lock:
            if jti not in self._jtis:
                return False
            self._jtis.discard(jti)
            self._persist()
            return True

    def list(self) -> List[str]:
        with self._lock:
            return sorted(self._jtis)

"""
审计日志持久化 — PostgreSQL 不可变审计链

用途:
  1. 持久化所有检测请求的审计记录
  2. SHA256 哈希链确保不可篡改性
  3. 支持按时间/会话/模型/结果查询
  4. 自动创建表和索引

架构:
  网关 → PostgreSQL (audit_logs 表)
         ├── 每行 SHA256 链接前一行
         └── 定期验证哈希链完整性
"""
import json
import time
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class AuditLogConfig:
    """审计日志配置"""

    def __init__(self,
                 dsn: str = "postgresql://localhost:5432/xuandun",
                 table_name: str = "audit_logs",
                 batch_size: int = 100,
                 flush_interval: float = 5.0,
                 enabled: bool = True):
        self.dsn = dsn
        self.table_name = table_name
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.enabled = enabled


class AuditLogStore:
    """PostgreSQL 审计日志存储 — 不可变哈希链

    设计:
      - 每条记录的 hash = SHA256(prev_hash + timestamp + session_id + event + result)
      - 第一条记录的 prev_hash = "genesis"
      - 定期验证: 重新计算哈希链，对比存储值
    """

    def __init__(self, config: Optional[AuditLogConfig] = None):
        self._config = config or AuditLogConfig()
        self._pool = None
        self._connected = False
        self._buffer: List[Dict] = []
        self._last_hash: str = "genesis"
        self._last_flush: float = 0.0

        if self._config.enabled:
            self._try_connect()

    def _try_connect(self):
        """尝试连接 PostgreSQL，失败时优雅降级"""
        try:
            import asyncpg
            # 注意：asyncpg 需要异步上下文，此处仅检测可用性
            # 实际使用在 FastAPI 的 lifespan 中异步初始化
            self._connected = True
        except ImportError:
            self._connected = False

    async def init_async(self):
        """异步初始化连接池和表结构"""
        if not self._config.enabled:
            return

        try:
            import asyncpg
            self._pool = await asyncpg.create_pool(
                self._config.dsn,
                min_size=1,
                max_size=5,
                command_timeout=10,
            )

            async with self._pool.acquire() as conn:
                # 创建审计日志表
                await conn.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self._config.table_name} (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        session_id VARCHAR(128),
                        event VARCHAR(64) NOT NULL,
                        text_preview VARCHAR(200),
                        allowed BOOLEAN,
                        reason VARCHAR(128),
                        stage VARCHAR(64),
                        latency_ms DOUBLE PRECISION,
                        client_ip VARCHAR(64),
                        model_id VARCHAR(128),
                        routed_to VARCHAR(128),
                        prev_hash VARCHAR(64) NOT NULL,
                        current_hash VARCHAR(64) NOT NULL
                    )
                """)

                # 创建索引
                await conn.execute(f"""
                    CREATE INDEX IF NOT EXISTS idx_{self._config.table_name}_timestamp
                    ON {self._config.table_name} (timestamp DESC)
                """)
                await conn.execute(f"""
                    CREATE INDEX IF NOT EXISTS idx_{self._config.table_name}_session
                    ON {self._config.table_name} (session_id)
                """)
                await conn.execute(f"""
                    CREATE INDEX IF NOT EXISTS idx_{self._config.table_name}_event
                    ON {self._config.table_name} (event)
                """)

                # 读取最后一条哈希链
                row = await conn.fetchrow(f"""
                    SELECT current_hash FROM {self._config.table_name}
                    ORDER BY id DESC LIMIT 1
                """)
                if row:
                    self._last_hash = row["current_hash"]

                self._connected = True

        except Exception as e:
            self._connected = False
            # 失败时缓冲区仍保留在内存中

    def _compute_hash(self, prev_hash: str, timestamp: str, session_id: str,
                      event: str, text_preview: str, result: str) -> str:
        """计算审计链哈希"""
        raw = f"{prev_hash}|{timestamp}|{session_id}|{event}|{text_preview[:50]}|{result}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def record(self, event: str, session_id: str = "anonymous",
               text_preview: str = "", allowed: Optional[bool] = None,
               reason: Optional[str] = None, stage: Optional[str] = None,
               latency_ms: float = 0.0, client_ip: str = "unknown",
               model_id: Optional[str] = None, routed_to: Optional[str] = None):
        """记录审计事件到缓冲区"""
        timestamp = datetime.now(timezone.utc).isoformat()
        result = "allow" if allowed else ("block" if allowed is False else "unknown")

        current_hash = self._compute_hash(
            self._last_hash, timestamp, session_id, event, text_preview, result)

        entry = {
            "timestamp": timestamp,
            "session_id": session_id,
            "event": event,
            "text_preview": text_preview[:200],
            "allowed": allowed,
            "reason": reason,
            "stage": stage,
            "latency_ms": latency_ms,
            "client_ip": client_ip,
            "model_id": model_id,
            "routed_to": routed_to,
            "prev_hash": self._last_hash,
            "current_hash": current_hash,
        }

        self._buffer.append(entry)
        self._last_hash = current_hash

        # 自动刷新：缓冲区满或时间间隔到
        now = time.time()
        if (len(self._buffer) >= self._config.batch_size or
                (self._buffer and now - self._last_flush >= self._config.flush_interval)):
            # 这里不能直接 await，调用方需主动调用 flush()
            pass

    async def flush(self):
        """将缓冲区批量写入 PostgreSQL"""
        if not self._buffer or not self._connected or not self._pool:
            return

        try:
            async with self._pool.acquire() as conn:
                columns = [
                    "timestamp", "session_id", "event", "text_preview",
                    "allowed", "reason", "stage", "latency_ms",
                    "client_ip", "model_id", "routed_to",
                    "prev_hash", "current_hash"
                ]
                placeholders = ", ".join(f"${i+1}" for i in range(len(columns)))
                col_names = ", ".join(columns)

                query = f"""
                    INSERT INTO {self._config.table_name} ({col_names})
                    VALUES ({placeholders})
                """

                for entry in self._buffer:
                    values = tuple(entry.get(c) for c in columns)
                    await conn.execute(query, *values)

            self._buffer.clear()
            self._last_flush = time.time()

        except Exception:
            # 写入失败时保留缓冲区，等待下次重试
            pass

    async def verify_chain(self, limit: int = 1000) -> Dict:
        """验证哈希链完整性"""
        if not self._connected or not self._pool:
            return {"valid": False, "reason": "not_connected", "records_checked": 0}

        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(f"""
                    SELECT id, prev_hash, current_hash, timestamp, event, text_preview,
                           CASE WHEN allowed THEN 'allow' WHEN allowed IS FALSE THEN 'block' ELSE 'unknown' END as result
                    FROM {self._config.table_name}
                    ORDER BY id ASC
                    LIMIT $1
                """, limit)

            if not rows:
                return {"valid": True, "records_checked": 0, "message": "empty_table"}

            expected_prev = "genesis"
            checked = 0
            for row in rows:
                row_hash = self._compute_hash(
                    expected_prev,
                    row["timestamp"].isoformat(),
                    row.get("session_id", ""),
                    row["event"],
                    row.get("text_preview", ""),
                    row.get("result", "unknown"),
                )
                if row_hash != row["current_hash"]:
                    return {
                        "valid": False,
                        "broken_at_id": row["id"],
                        "records_checked": checked,
                        "reason": "hash_mismatch",
                    }
                expected_prev = row["current_hash"]
                checked += 1

            return {"valid": True, "records_checked": checked}

        except Exception as e:
            return {"valid": False, "reason": str(e), "records_checked": 0}

    async def query(self, session_id: Optional[str] = None,
                    event: Optional[str] = None,
                    limit: int = 100, offset: int = 0) -> List[Dict]:
        """查询审计日志"""
        if not self._connected or not self._pool:
            return []

        try:
            conditions = []
            params = []
            idx = 1

            if session_id:
                conditions.append(f"session_id = ${idx}")
                params.append(session_id)
                idx += 1
            if event:
                conditions.append(f"event = ${idx}")
                params.append(event)
                idx += 1

            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"""
                SELECT id, timestamp, session_id, event, text_preview,
                       allowed, reason, stage, latency_ms, client_ip,
                       model_id, routed_to, current_hash
                FROM {self._config.table_name}
                {where}
                ORDER BY id DESC
                LIMIT ${idx} OFFSET ${idx+1}
            """
            params.extend([limit, offset])

            async with self._pool.acquire() as conn:
                rows = await conn.fetch(query, *params)

            return [dict(r) for r in rows]

        except Exception:
            return []

    def query_memory(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """查询内存缓冲区中的审计记录（未连接 PostgreSQL 时使用）

        返回最新在前的记录，与 PostgreSQL 的 ORDER BY id DESC 语义一致。
        """
        records = list(reversed(self._buffer))
        return records[offset:offset + limit]

    def get_status(self) -> Dict:
        """获取存储状态"""
        return {
            "backend": "postgresql",
            "connected": self._connected,
            "buffer_size": len(self._buffer),
            "last_hash": self._last_hash[:16] + "...",
            "table": self._config.table_name,
        }

    async def close(self):
        """关闭连接池"""
        await self.flush()
        if self._pool:
            await self._pool.close()
            self._connected = False

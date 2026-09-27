# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""个人版本地存储（SQLite）。

数据 100% 本地，无任何外发。
默认路径：`%LOCALAPPDATA%/com.daoti.xuandun-personal/xuandun_personal.db`
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..types import (
    Action,
    LogEntry,
    LogType,
    RedactionRecord,
    RelayReputation,
)

logger = logging.getLogger("xuandun-personal.storage")

_SCHEMA_FILE = Path(__file__).parent / "schema.sql"


def default_db_path() -> Path:
    """返回默认数据库路径。"""
    base = os.getenv("LOCALAPPDATA") or os.getenv("XDG_DATA_HOME")
    if base:
        directory = Path(base) / "com.daoti.xuandun-personal"
    else:
        directory = Path.home() / ".xuandun-personal"
    return directory / "xuandun_personal.db"


class PersonalStorage:
    """个人版 SQLite 存储。

    使用示例：
        storage = PersonalStorage()
        log_id = storage.insert_log(LogEntry(...))
        storage.insert_redactions(log_id, "sess1", records)
        entries = storage.query_logs(limit=100, log_type="response_verify")
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or default_db_path()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        logger.info("个人版存储就绪: %s", self._db_path)

    def _init_schema(self) -> None:
        """初始化表结构 + 向后兼容迁移。"""
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA_FILE.read_text(encoding="utf-8"))
            self._migrate_schema()

    def _migrate_schema(self) -> None:
        """向后兼容迁移：为已存在的表补齐新增列。

        用 PRAGMA table_info 检测，缺列才 ALTER —— 对新建表和旧库都安全，
        避免 schema.sql 里写死 ALTER TABLE 导致「新库重复加列」报错。
        """
        migrations = [
            ("logs", "marked_safe", "INTEGER NOT NULL DEFAULT 0"),
        ]
        for table, column, decl in migrations:
            cols = {
                str(r["name"])
                for r in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if not cols:
                continue  # 表不存在（建表语句会处理）
            if column not in cols:
                try:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
                    logger.info("已迁移 %s 表：新增列 %s", table, column)
                except sqlite3.OperationalError as e:
                    logger.warning("迁移 %s.%s 失败: %s", table, column, e)

    def close(self) -> None:
        """关闭数据库连接。"""
        self._conn.close()

    # ══════════════════════════════════════════════════════════
    # 日志
    # ══════════════════════════════════════════════════════════

    def insert_log(self, entry: LogEntry) -> int:
        """插入一条日志，返回日志 ID。"""
        with self._conn:
            cur = self._conn.execute(
                """INSERT INTO logs
                   (timestamp, log_type, relay_domain, action, severity,
                    model, finding_count, summary, detail_json, text_preview)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.timestamp,
                    entry.log_type,
                    entry.relay_domain,
                    entry.action,
                    entry.severity,
                    entry.model,
                    entry.finding_count,
                    entry.summary,
                    entry.detail_json,
                    entry.text_preview[:500],
                ),
            )
            log_id = int(cur.lastrowid or 0)
        entry.id = log_id
        return log_id

    def query_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        log_type: Optional[str] = None,
        action: Optional[str] = None,
        relay_domain: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        search: Optional[str] = None,
    ) -> List[LogEntry]:
        """查询日志（多条件过滤 + 客户端搜索）。"""
        clauses: List[str] = []
        params: List[Any] = []

        if log_type:
            clauses.append("log_type = ?")
            params.append(log_type)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if relay_domain:
            clauses.append("relay_domain = ?")
            params.append(relay_domain)
        if start_ts is not None:
            clauses.append("timestamp >= ?")
            params.append(start_ts)
        if end_ts is not None:
            clauses.append("timestamp <= ?")
            params.append(end_ts)
        if search:
            clauses.append("(summary LIKE ? OR text_preview LIKE ?)")
            pattern = f"%{search}%"
            params.extend([pattern, pattern])

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM logs {where} "
            f"ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_log(r) for r in rows]

    def count_logs(self, **filters: Any) -> int:
        """统计日志数量（支持与 query_logs 相同的过滤条件）。"""
        clauses: List[str] = []
        params: List[Any] = []
        for key, col in (("log_type", "log_type"), ("action", "action"),
                         ("relay_domain", "relay_domain")):
            if filters.get(key):
                clauses.append(f"{col} = ?")
                params.append(filters[key])
        if filters.get("start_ts") is not None:
            clauses.append("timestamp >= ?")
            params.append(filters["start_ts"])
        if filters.get("end_ts") is not None:
            clauses.append("timestamp <= ?")
            params.append(filters["end_ts"])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        row = self._conn.execute(
            f"SELECT COUNT(*) AS c FROM logs {where}", params
        ).fetchone()
        return int(row["c"]) if row else 0

    @staticmethod
    def _row_to_log(row: sqlite3.Row) -> LogEntry:
        return LogEntry(
            id=int(row["id"]),
            timestamp=float(row["timestamp"]),
            log_type=str(row["log_type"]),
            relay_domain=str(row["relay_domain"]),
            action=str(row["action"]),
            severity=str(row["severity"]),
            model=str(row["model"]),
            finding_count=int(row["finding_count"]),
            summary=str(row["summary"]),
            detail_json=str(row["detail_json"]),
            text_preview=str(row["text_preview"]),
            marked_safe=bool(row["marked_safe"]) if "marked_safe" in row.keys() else False,
        )

    def get_log(self, log_id: int) -> Optional[LogEntry]:
        """按 ID 精确查询单条日志（★ P2-14 修复）。

        原实现在 get_log_detail 里遍历最近 1000 条做线性匹配，
        既慢又有 1000 条截断缺陷，且残留一段无意义的死循环。
        """
        row = self._conn.execute(
            "SELECT * FROM logs WHERE id = ?", (log_id,)
        ).fetchone()
        return self._row_to_log(row) if row else None

    def mark_safe(self, log_id: int) -> bool:
        """标记日志为误报（★ P1-9：文档 4.1 要求的「标记为安全」按钮）。"""
        with self._conn:
            cur = self._conn.execute(
                "UPDATE logs SET marked_safe = 1 WHERE id = ?", (log_id,)
            )
        return bool(cur.rowcount)

    def unmark_safe(self, log_id: int) -> bool:
        """取消误报标记。"""
        with self._conn:
            cur = self._conn.execute(
                "UPDATE logs SET marked_safe = 0 WHERE id = ?", (log_id,)
            )
        return bool(cur.rowcount)

    def export_logs(
        self,
        limit: int = 10_000,
        log_type: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[LogEntry]:
        """导出日志（★ P1-9：文档 4.1 要求的「导出」按钮）。"""
        return self.query_logs(
            limit=limit, log_type=log_type, action=action
        )

    def get_all_for_export(self, limit: int = 10_000) -> List[LogEntry]:
        """导出全部日志（升序，便于阅读）。"""
        rows = self._conn.execute(
            "SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_log(r) for r in rows]

    def clear_logs(self, before_ts: Optional[float] = None) -> int:
        """清空日志（可指定仅清某时间之前）。"""
        with self._conn:
            if before_ts is None:
                cur = self._conn.execute("DELETE FROM logs")
            else:
                cur = self._conn.execute(
                    "DELETE FROM logs WHERE timestamp < ?", (before_ts,)
                )
        return int(cur.rowcount or 0)

    def delete_log(self, log_id: int) -> bool:
        """删除单条日志。"""
        with self._conn:
            cur = self._conn.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        return bool(cur.rowcount)

    # ══════════════════════════════════════════════════════════
    # 脱敏记录
    # ══════════════════════════════════════════════════════════

    def insert_redactions(
        self, log_id: int, session_id: str, records: List[RedactionRecord]
    ) -> int:
        """插入脱敏记录（保存原始敏感值，仅存本地）。"""
        if not records:
            return 0
        now = time.time()
        with self._conn:
            self._conn.executemany(
                """INSERT INTO redaction_records
                   (session_id, log_id, redaction_idx, category,
                    original, redacted, start_pos, end_pos, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                [
                    (session_id, log_id, r.index, r.category,
                     r.original, r.redacted, r.start, r.end, now)
                    for r in records
                ],
            )
        return len(records)

    def get_redactions(self, log_id: int) -> List[Dict[str, Any]]:
        """查询某条日志关联的脱敏记录。"""
        rows = self._conn.execute(
            "SELECT * FROM redaction_records WHERE log_id = ? ORDER BY redaction_idx",
            (log_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def clear_redactions_for_session(self, session_id: str) -> int:
        """清理某会话的脱敏记录（敏感值不留存）。"""
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM redaction_records WHERE session_id = ?", (session_id,)
            )
        return int(cur.rowcount or 0)

    # ══════════════════════════════════════════════════════════
    # 请求基线（★ v0.1.0 新增）
    #
    # 这是响应侧检测唯一可信的对照物来源。有了它，判据才能从
    # 「响应文本长得像不像攻击」变成「响应是否偏离了请求本身
    # 声明的工具 / 模型 / 提示词」。
    # ══════════════════════════════════════════════════════════

    def save_request_baseline(
        self,
        session_id: str,
        model: str,
        tools_hash: str,
        tool_names: List[str],
        system_hash: str,
        system_len: int,
        msg_count: int,
    ) -> None:
        """写入/更新某会话的请求基线。"""
        now = time.time()
        with self._conn:
            self._conn.execute(
                """INSERT INTO request_baseline
                   (session_id, model, tools_hash, tool_names,
                    system_hash, system_len, msg_count, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(session_id) DO UPDATE SET
                     model=excluded.model,
                     tools_hash=excluded.tools_hash,
                     tool_names=excluded.tool_names,
                     system_hash=excluded.system_hash,
                     system_len=excluded.system_len,
                     msg_count=excluded.msg_count,
                     updated_at=excluded.updated_at""",
                (
                    session_id, model, tools_hash,
                    json.dumps(tool_names, ensure_ascii=False),
                    system_hash, system_len, msg_count, now, now,
                ),
            )

    def get_request_baseline(self, session_id: str) -> Optional[Dict[str, Any]]:
        """读取某会话的请求基线；不存在返回 None。"""
        row = self._conn.execute(
            "SELECT * FROM request_baseline WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        try:
            data["tool_names"] = json.loads(data.get("tool_names") or "[]")
        except json.JSONDecodeError:
            data["tool_names"] = []
        return data

    def record_response_model(self, session_id: str, response_model: str) -> None:
        """记录中转站返回的模型名（供事后比对）。"""
        if not response_model:
            return
        with self._conn:
            self._conn.execute(
                """UPDATE request_baseline SET response_model = ?, updated_at = ?
                   WHERE session_id = ?""",
                (response_model, time.time(), session_id),
            )

    def clear_request_baseline(self, session_id: str) -> int:
        """清理某会话的基线。"""
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM request_baseline WHERE session_id = ?", (session_id,)
            )
        return int(cur.rowcount or 0)

    def purge_request_baseline(self, keep_days: int = 7) -> int:
        """清理过期基线（避免无限增长）。

        基线只在单个会话的生命周期内有意义：会话结束后，
        下一次请求会重新写入。保留数天只为支持「重启后仍能比对」。
        """
        cutoff = time.time() - keep_days * 86400
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM request_baseline WHERE updated_at < ?", (cutoff,)
            )
        return int(cur.rowcount or 0)

    # ══════════════════════════════════════════════════════════
    # 中转站信誉
    # ══════════════════════════════════════════════════════════

    def upsert_reputation(self, rep: RelayReputation) -> None:
        """写入/更新中转站信誉。"""
        with self._conn:
            self._conn.execute(
                """INSERT INTO relay_reputation
                   (domain, score, first_seen, last_seen, total_calls,
                    danger_count, suspect_count, avg_latency_ms, latency_samples,
                    known_malicious, watermark_detected, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET
                     score=excluded.score, last_seen=excluded.last_seen,
                     total_calls=excluded.total_calls,
                     danger_count=excluded.danger_count,
                     suspect_count=excluded.suspect_count,
                     avg_latency_ms=excluded.avg_latency_ms,
                     latency_samples=excluded.latency_samples,
                     known_malicious=excluded.known_malicious,
                     watermark_detected=excluded.watermark_detected,
                     notes=excluded.notes""",
                (
                    rep.domain, rep.score, rep.first_seen, rep.last_seen,
                    rep.total_calls, rep.danger_count, rep.suspect_count,
                    rep.avg_latency_ms, rep.latency_samples,
                    int(rep.known_malicious), int(rep.watermark_detected),
                    json.dumps(rep.notes, ensure_ascii=False),
                ),
            )

    def load_reputations(self) -> List[RelayReputation]:
        """加载所有中转站信誉。"""
        rows = self._conn.execute(
            "SELECT * FROM relay_reputation ORDER BY score ASC"
        ).fetchall()
        result = []
        for r in rows:
            try:
                notes = json.loads(r["notes"])
            except (json.JSONDecodeError, TypeError):
                notes = []
            result.append(
                RelayReputation(
                    domain=str(r["domain"]),
                    score=int(r["score"]),
                    first_seen=float(r["first_seen"]),
                    last_seen=float(r["last_seen"]),
                    total_calls=int(r["total_calls"]),
                    danger_count=int(r["danger_count"]),
                    suspect_count=int(r["suspect_count"]),
                    avg_latency_ms=float(r["avg_latency_ms"]),
                    latency_samples=int(r["latency_samples"]),
                    known_malicious=bool(r["known_malicious"]),
                    watermark_detected=bool(r["watermark_detected"]),
                    notes=notes,
                )
            )
        return result

    def clear_reputations(self) -> int:
        """清空信誉记录。"""
        with self._conn:
            cur = self._conn.execute("DELETE FROM relay_reputation")
        return int(cur.rowcount or 0)

    # ══════════════════════════════════════════════════════════
    # 配置
    # ══════════════════════════════════════════════════════════

    def set_config(self, key: str, value: str) -> None:
        """写入配置项。"""
        with self._conn:
            self._conn.execute(
                """INSERT INTO config (key, value, updated_at) VALUES (?,?,?)
                   ON CONFLICT(key) DO UPDATE SET
                     value=excluded.value, updated_at=excluded.updated_at""",
                (key, value, time.time()),
            )

    def get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """读取配置项。"""
        row = self._conn.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ).fetchone()
        return str(row["value"]) if row else default

    def get_all_config(self) -> Dict[str, str]:
        """读取全部配置。"""
        rows = self._conn.execute("SELECT key, value FROM config").fetchall()
        return {str(r["key"]): str(r["value"]) for r in rows}

    # ══════════════════════════════════════════════════════════
    # 每日统计（首页 KPI）
    # ══════════════════════════════════════════════════════════

    def update_daily_stats(
        self,
        total_calls: int = 0,
        danger: int = 0,
        suspect: int = 0,
        safe: int = 0,
        redactions: int = 0,
    ) -> None:
        """更新当日统计（累加）。"""
        import datetime as _dt
        date_str = _dt.date.today().isoformat()
        with self._conn:
            self._conn.execute(
                """INSERT INTO daily_stats
                   (date, total_calls, danger_count, suspect_count, safe_count, redaction_count)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(date) DO UPDATE SET
                     total_calls = total_calls + excluded.total_calls,
                     danger_count = danger_count + excluded.danger_count,
                     suspect_count = suspect_count + excluded.suspect_count,
                     safe_count = safe_count + excluded.safe_count,
                     redaction_count = redaction_count + excluded.redaction_count""",
                (date_str, total_calls, danger, suspect, safe, redactions),
            )

    def get_today_stats(self) -> Dict[str, int]:
        """查询今日统计（首页 KPI 卡片）。"""
        import datetime as _dt
        date_str = _dt.date.today().isoformat()
        row = self._conn.execute(
            "SELECT * FROM daily_stats WHERE date = ?", (date_str,)
        ).fetchone()
        if not row:
            return {
                "total_calls": 0, "danger_count": 0, "suspect_count": 0,
                "safe_count": 0, "redaction_count": 0,
            }
        return {
            "total_calls": int(row["total_calls"]),
            "danger_count": int(row["danger_count"]),
            "suspect_count": int(row["suspect_count"]),
            "safe_count": int(row["safe_count"]),
            "redaction_count": int(row["redaction_count"]),
        }

    def get_recent_stats(self, days: int = 7) -> List[Dict[str, Any]]:
        """查询最近 N 天统计（趋势图）。"""
        import datetime as _dt
        since = (_dt.date.today() - _dt.timedelta(days=days - 1)).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM daily_stats WHERE date >= ? ORDER BY date ASC", (since,)
        ).fetchall()
        return [
            {
                "date": str(r["date"]),
                "total_calls": int(r["total_calls"]),
                "danger_count": int(r["danger_count"]),
                "suspect_count": int(r["suspect_count"]),
                "safe_count": int(r["safe_count"]),
            }
            for r in rows
        ]

    def get_stats(self) -> Dict[str, Any]:
        """存储状态摘要。"""
        return {
            "db_path": str(self._db_path),
            "db_size_bytes": self._db_path.stat().st_size if self._db_path.exists() else 0,
            "total_logs": self.count_logs(),
            "total_relays": len(self.load_reputations()),
        }

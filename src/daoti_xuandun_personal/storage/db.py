# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""个人版本地存储（SQLite）。

数据 100% 本地，无任何外发。
默认路径：``paths.data_dir()/xuandun_personal.db``
（设了 ``XUANDUN_DATA_DIR`` 时改写到该目录，用于开发/测试隔离）
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import paths
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
    """返回默认数据库路径。

    ★ 走 paths.data_dir()：设了 XUANDUN_DATA_DIR 时，
      开发/测试的库与稳定版分开，测试日志不会污染用户真实统计。
    """
    return paths.data_file("xuandun_personal.db")

def _log_filters(
    log_type: Optional[str] = None,
    action: Optional[str] = None,
    relay_domain: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    search: Optional[str] = None,
    marked_safe: Optional[bool] = None,
    log_type_not: Optional[str] = None,
) -> tuple:
    """把过滤条件编译成 (WHERE 子句, 参数列表)。

    ★★ query_logs / count_logs / delete_logs 三处**必须**共用它
      （2026-10-03 修复）
      此前三处各写一套 WHERE：query_logs 支持 search 与时间范围，
      count_logs 只支持 log_type/action/时间 —— 于是搜索时
      列表被过滤而总数没被过滤，分页器显示「共 954 条 / 48 页」，
      点第 2 页却是空列表。用户看到的正是「筛不出来」，且无任何报错。

      这类 bug 的特征是「每个函数单测都绿、拼起来就错」，
      所以过滤条件只允许写一次。
    """
    clauses: List[str] = []
    params: List[Any] = []
    if log_type:
        clauses.append("log_type = ?")
        params.append(log_type)
    # ★ 2026-10-20：排除某一类日志。
    #   首页 KPI 刻意不计「转发中断」（proxy_error）—— 那是链路失败，
    #   不是内容风险。而状态栏的数字点进来若把这类也列出来，
    #   用户核对时就会看到「危险 26，列表 33 条」，再次认为数字造假。
    #   有了它，首页每个数字点进来的条数与数字本身一致。
    if log_type_not:
        clauses.append("log_type != ?")
        params.append(log_type_not)
    if action:
        # ★★ 2026-10-20：「已打码」不是一个 action 取值。
        #   打码发生在**请求侧**，而一条日志只记这次请求的最终结果
        #   （pass / alert / block）—— 库里从来没有 action='redact' 的行。
        #   旧实现按 action='redact' 过滤，于是用户点「已打码」
        #   永远看到 0 条，而状态栏明明写着「已打码 N 处」：
        #   一个什么都不返回的筛选器，比没有这个筛选器更糟。
        #   现在按「本行是否记录过打码」过滤，与状态栏计数同源。
        if action == Action.REDACT.value:
            clauses.append("redaction_count > 0")
        else:
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
    if marked_safe is not None:
        clauses.append("marked_safe = ?")
        params.append(1 if marked_safe else 0)
    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params


def kpi_contribution(
    log_type: str, action: str, marked_safe: bool = False
) -> tuple:
    """把「一行日志」折算成它对每日 KPI 的贡献：(total, danger, suspect, safe)。

    ★★ 为什么必须是一个**纯函数**（2026-10-19 修复）
    ────────────────────────────────────────────────────────────
    首页 KPI 有两个来源：**录入时累加**（app.py::_record_log 等）与
    **删除后重算**（_recompute_daily_stats）。两处若各写一套归类规则，
    就会出现「录入时不计的，重算时又计回来」——
    用户每删一次日志，首页的「危险 / 可疑 / 已检查」就可能凭空变化。

    实测分叉（本缺陷的原始形态）：
      · 录入时 proxy_error（超时 / 上游 4xx·5xx）**刻意不计**任何档，
        重算却按 action 全表统计 → action=block 的 proxy_error
        被计进「危险」，action=alert 的被计进「可疑」；
      · 用户标记为误报（marked_safe=1）的行录入时已回退，
        重算却只看 action、完全忽略 marked_safe → 误报被重新计回。

    录入 / 标记·取消标记 / 重算三处共用这一个函数，分叉从源头消失。
    返回四元组而非直接写库，是为了让它能被单独断言其一一对应关系。

    ★ 口径明细（务必与 _record_log 的实际写入逐条对齐）：
      · proxy_error：链路 / 鉴权级失败，不计入任何档
        （见 app.py 的 _proxy_error / _log_upstream_error）—— 连 total 也不计。
      · 其余类型（response_verify / request_sanitize / relay）每行计 1 次
        total，并按 action 归入 danger / suspect / safe 之一。
      · marked_safe=1：用户已确认是误报，不再计入风险档。
        与 _adjust_daily_stats_for_mark 的历史行为保持一致 ——
        只有 block / alert 被标记时才连 total 一起回退；
        pass 标记本就无意义（它不属于风险），维持原样。
    """
    if log_type == LogType.PROXY_ERROR.value:
        return (0, 0, 0, 0)
    danger = 1 if action == Action.BLOCK.value else 0
    suspect = 1 if action == Action.ALERT.value else 0
    safe = 1 if action == Action.PASS.value else 0
    total = 1
    if marked_safe:
        # 与 _adjust_daily_stats_for_mark 同一口径：
        # 只有 block / alert 被标记时才回退（pass 标记无意义，维持原样）。
        if action == Action.BLOCK.value:
            danger = 0
            total = 0
        elif action == Action.ALERT.value:
            suspect = 0
            total = 0
    return (total, danger, suspect, safe)


class _LockedConn:
    """把 sqlite3 连接包一层，用同一把可重入锁串行化所有访问。

    ★★ 为什么需要（M4，2026-10-04）
    ────────────────────────────────────────────────────────────
    `PersonalStorage` 用 `check_same_thread=False` 建连接 ——
    这**关掉了 SQLite 自带的线程守卫**，却没有提供任何替代保护。
    当前所有访问都发生在 uvicorn 的同一个事件循环线程上，所以暂时
    不会触发；但只要将来有任何一处代码走到线程池 / 后台线程
    （FastAPI 的同步路由、定时任务、批量导出……），就会变成
    「多线程共用一条连接」：轻则读到半提交状态，
    重则 `sqlite3.ProgrammingError` / 数据库损坏。

    这里用一把 RLock 把所有 `execute / executemany / executescript`
    以及 `with conn:` 事务块串行化：
      · 单个语句：加锁 → 执行 → 释放；
      · 事务块（`with self._conn:`）：进入时加锁并持有到退出，
        保证块内多条语句的原子性——这是 RLock 可重入的意义所在
        （内部 execute 会再次加锁，同线程直接通过）。
    这样即使将来引入多线程，也不会发生交错写入。
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock):
        self._conn = conn
        self._lock = lock

    def execute(self, *args, **kwargs):
        with self._lock:
            return self._conn.execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        with self._lock:
            return self._conn.executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        with self._lock:
            return self._conn.executescript(*args, **kwargs)

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self):
        # 事务块：持有锁直到 __exit__，保证块内原子性
        self._lock.acquire()
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            return self._conn.__exit__(exc_type, exc, tb)
        finally:
            self._lock.release()


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
        # ★ M4：所有连接访问共用这一把可重入锁（见 _LockedConn）
        self._lock = threading.RLock()
        self._conn = self._connect_with_recovery()
        logger.info("个人版存储就绪: %s", self._db_path)

    def _connect_with_recovery(self) -> "_LockedConn":
        """建立连接并完成建表；文件损坏时隔离旧文件后重建空库（★ M3）。

        ★★ 为什么必须能自愈（2026-10-04）
        ────────────────────────────────────────────────────────────
        原实现直接 `sqlite3.connect(...)` + `_init_schema()`：
        数据库文件一旦损坏（断电写坏、磁盘坏道、被别的程序改坏），
        第一次查询就抛 `sqlite3.DatabaseError`，而它在 lifespan 里
        无人接住 —— **整个引擎起不来**，桌面端表现为「服务启动失败」，
        用户完全无从得知真实原因是历史库损坏。

        现在：探测到损坏 → 把 `.db/.db-wal/.db-shm` 隔离成
        `.corrupt-<时间戳>` 备份 → 用空库重建 → 引擎照常启动。
        历史日志与信誉不可避免地丢失，但**原始文件保留**（可人工抢救），
        且应用不会因为一个坏文件整体报废。
        """
        for attempt in (1, 2):
            raw = sqlite3.connect(str(self._db_path), check_same_thread=False)
            raw.row_factory = sqlite3.Row
            self._conn = _LockedConn(raw, self._lock)
            try:
                self._init_schema()
                return self._conn
            except sqlite3.DatabaseError as e:
                # 首次访问（PRAGMA / 建表）就会暴露「文件不是数据库」
                # 或「database disk image is malformed」。
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001 — 关闭失败不影响后续重建
                    pass
                if attempt == 1:
                    self._quarantine_db(e)
                    continue
                raise
        raise RuntimeError("数据库重建失败")  # pragma: no cover — 循环内必返回或抛出

    def _quarantine_db(self, err: Exception) -> None:
        """把损坏的数据库文件（含 WAL/SHM 旁文件）改名隔离，供人工抢救。"""
        stamp = time.strftime("%Y%m%d-%H%M%S")
        moved: List[str] = []
        for suffix in ("", "-wal", "-shm"):
            src = Path(f"{self._db_path}{suffix}")
            if not src.exists():
                continue
            dst = src.with_name(f"{src.name}.corrupt-{stamp}")
            try:
                src.replace(dst)
                moved.append(dst.name)
            except OSError:
                pass
        logger.error(
            "数据库损坏（%s），已隔离为 %s 并重建空库。"
            "历史日志与中转站信誉不再可用；原文件已保留，可人工抢救。",
            err, ", ".join(moved) or "(无)",
        )

    def _init_schema(self) -> None:
        """初始化表结构 + 向后兼容迁移。

        ★★ PRAGMA secure_delete=ON（2026-10-03）
          SQLite 默认 secure_delete=OFF，删行只是把内容标记为「可复用」，
          **明文仍留在数据库文件的空闲页里**（WAL 旁文件同理）。
          实测：清空日志后用二进制搜索仍能在 xuandun_personal.db-wal 里
          搜到用户原始的 API Key。

          而清空日志的确认框与产品文档都写着「本地不留存任何原始敏感值」——
          这句话在关闭 secure_delete 时是假的：
          数据在逻辑表里没了，在磁盘上还在，而且能被任何拿到文件的人搜出来。

          代价是删除时多一次覆写（.db 文件通常只有几 MB），
          换来的是「删了就是真删了」。
        """
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA secure_delete=ON")
            self._conn.executescript(_SCHEMA_FILE.read_text(encoding="utf-8"))
            self._migrate_schema()

    def _migrate_schema(self) -> None:
        """向后兼容迁移：为已存在的表补齐新增列。

        用 PRAGMA table_info 检测，缺列才 ALTER —— 对新建表和旧库都安全，
        避免 schema.sql 里写死 ALTER TABLE 导致「新库重复加列」报错。
        """
        migrations = [
            ("logs", "marked_safe", "INTEGER NOT NULL DEFAULT 0"),
            # ★ v0.1.0：评分口径变更 —— 责任分列。
            #   老库里 danger_count/suspect_count 是混在一起的，
            #   无法区分是长度突变（用户提问导致）还是恶意 tool_call。
            #   迁移策略：老数据一律记为 relay_* = 0，
            #   即「旧记录不作为中转站的罪证」——
            #   宁可分数偏高，也不在没有依据的情况下指控中转站。
            ("relay_reputation", "relay_danger_count",
             "INTEGER NOT NULL DEFAULT 0"),
            ("relay_reputation", "self_danger_count",
             "INTEGER NOT NULL DEFAULT 0"),
            ("relay_reputation", "relay_suspect_count",
             "INTEGER NOT NULL DEFAULT 0"),
            ("relay_reputation", "self_suspect_count",
             "INTEGER NOT NULL DEFAULT 0"),
            # ★ 2026-10-20：把「本条打了几处码」落在日志行上。
            #   脱敏明细会在响应还原后被清除，只靠明细行数会让
            #   状态栏「已打码 N 处」与可下钻的记录对不上。
            ("logs", "redaction_count", "INTEGER NOT NULL DEFAULT 0"),
        ]
        added = set()
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
                    added.add((table, column))
                    logger.info("已迁移 %s 表：新增列 %s", table, column)
                except sqlite3.OperationalError as e:
                    logger.warning("迁移 %s.%s 失败: %s", table, column, e)

        # ★ 旧库回填：把「仍然留存」的脱敏明细折算到日志行。
        #   已被隐私清除的那部分无法还原（那正是清除的目的），
        #   只能记为 0 —— 宁可少报，也不凭空多报。
        if ("logs", "redaction_count") in added:
            self._conn.execute(
                "UPDATE logs SET redaction_count = ("
                "  SELECT COUNT(*) FROM redaction_records r "
                "  WHERE r.log_id = logs.id"
                ")"
            )
            # ★ 回填后必须**立刻重算一次**，让 daily_stats 与日志行对齐。
            #   否则升级后状态栏仍显示旧的累计值（实测 322），
            #   而日志里只能筛出 258 条 —— 用户会以为修完反而更错，
            #   而且要等到「删除任意一条日志」才会自愈。
            self._recompute_daily_stats()

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
                    model, finding_count, summary, detail_json, text_preview,
                    redaction_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
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
                    # ★ 2026-10-20：打码处数随日志行一起落库。
                    #   脱敏明细之后可能被隐私清除，这个数是唯一能
                    #   让「已打码 N 处」可下钻、可筛选的依据。
                    int(getattr(entry, "redaction_count", 0) or 0),
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
        marked_safe: Optional[bool] = None,
        log_type_not: Optional[str] = None,
    ) -> List[LogEntry]:
        """查询日志（多条件过滤 + 客户端搜索）。

        ★ 过滤条件走 ``_log_filters``，与 count_logs / delete_logs 同源 ——
          少一处就会让「列表」与「总数」口径分叉，
          表现为分页器显示的总页数点进去是空列表。
        """
        where, params = _log_filters(
            log_type=log_type, action=action, relay_domain=relay_domain,
            start_ts=start_ts, end_ts=end_ts, search=search,
            marked_safe=marked_safe, log_type_not=log_type_not,
        )
        sql = (
            f"SELECT * FROM logs {where} "
            f"ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_log(r) for r in rows]

    def count_logs(
        self,
        log_type: Optional[str] = None,
        action: Optional[str] = None,
        relay_domain: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        search: Optional[str] = None,
        marked_safe: Optional[bool] = None,
        log_type_not: Optional[str] = None,
    ) -> int:
        """统计日志数量。

        ★★ 过滤条件必须与 query_logs **完全一致**（2026-10-03 修复）
          原实现只支持 log_type/action/时间，漏了 search ——
          于是搜索时列表被过滤而总数没被过滤，分页器显示
          「共 954 条 / 48 页」，点第 2 页得到空列表，
          用户看到的正是「筛不出来」，且没有任何报错。
          这是典型的「两边各自都对、拼起来错」：
          列表走一套条件、计数走另一套条件。
        """
        where, params = _log_filters(
            log_type=log_type, action=action, relay_domain=relay_domain,
            start_ts=start_ts, end_ts=end_ts, search=search,
            marked_safe=marked_safe, log_type_not=log_type_not,
        )
        row = self._conn.execute(
            f"SELECT COUNT(*) AS c FROM logs {where}", params
        ).fetchone()
        return int(row["c"]) if row else 0

    def delete_logs(
        self,
        log_type: Optional[str] = None,
        action: Optional[str] = None,
        relay_domain: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        search: Optional[str] = None,
        marked_safe: Optional[bool] = None,
        log_type_not: Optional[str] = None,
    ) -> int:
        """按条件删除日志，返回删除条数。

        ★ 与查询同源过滤条件（``_log_filters``）——
          删除范围必须与用户看到的列表范围一致，
          否则「删掉我看到的这些」会变成「删掉别的」。

        ★ 连带删除脱敏记录：那些行经 detail_json 与 CSV 导出外发，
          留着它们等于日志删了但内容还在。
          log_id 上没有任何外键约束（schema.sql 里没写 REFERENCES），
          所以必须显式 DELETE —— 不能指望级联。
        """
        where, params = _log_filters(
            log_type=log_type, action=action, relay_domain=relay_domain,
            start_ts=start_ts, end_ts=end_ts, search=search,
            marked_safe=marked_safe, log_type_not=log_type_not,
        )
        with self._conn:
            # ★★ 2026-10-19：用**子查询**按同一过滤条件删除脱敏记录，
            #   不再把命中的 log_id 展开成 IN (?,?,...)。
            #   旧实现 `",".join("?" * len(victims))` 在日志量大时（>3 万条）
            #   会撞上 SQLite 变量上限抛 OperationalError，
            #   导致「按筛选清空」整单失败并返回 500。
            #
            #   顺序也必须是「先删脱敏记录、再删日志」：
            #   子查询引用 logs 表，若先删日志，子查询将命中空集，
            #   脱敏记录（含原始敏感值）永远删不掉。
            if where:
                self._conn.execute(
                    f"DELETE FROM redaction_records WHERE log_id IN "
                    f"(SELECT id FROM logs {where})",
                    params,
                )
                cur = self._conn.execute(f"DELETE FROM logs {where}", params)
            else:
                # 无过滤 = 全清：整表删除，天然无需参数列表
                self._conn.execute("DELETE FROM redaction_records")
                cur = self._conn.execute("DELETE FROM logs")
            deleted = int(cur.rowcount or 0)
            self._recompute_daily_stats()
        if deleted:
            self._scrub_wal()
        return deleted

    def log_breakdown(self) -> Dict[str, Any]:
        """日志概览统计（供日志管理界面展示）。

        回答用户真正会问的三件事：
          · 我这些日志都是些什么（按类型 / 按结果的分布）
          · 有多少是被我标记过误报的（这些不必再留着）
          · 最早记录是什么时候（决定要不要清理）
        """
        by_type = {
            str(r["log_type"]): int(r["c"])
            for r in self._conn.execute(
                "SELECT log_type, COUNT(*) AS c FROM logs "
                "GROUP BY log_type ORDER BY c DESC"
            ).fetchall()
        }
        by_action = {
            str(r["action"]): int(r["c"])
            for r in self._conn.execute(
                "SELECT action, COUNT(*) AS c FROM logs "
                "GROUP BY action ORDER BY c DESC"
            ).fetchall()
        }
        domains = [
            {"domain": str(r["relay_domain"] or ""), "count": int(r["c"])}
            for r in self._conn.execute(
                "SELECT relay_domain, COUNT(*) AS c FROM logs "
                "GROUP BY relay_domain ORDER BY c DESC LIMIT 5"
            ).fetchall()
        ]
        row = self._conn.execute(
            "SELECT COUNT(*) AS c, "
            "SUM(CASE WHEN marked_safe = 1 THEN 1 ELSE 0 END) AS marked, "
            "MIN(timestamp) AS oldest, MAX(timestamp) AS newest "
            "FROM logs"
        ).fetchone()
        return {
            "total": int(row["c"] or 0),
            "marked_safe": int(row["marked"] or 0),
            "oldest_ts": float(row["oldest"] or 0),
            "newest_ts": float(row["newest"] or 0),
            "by_type": by_type,
            "by_action": by_action,
            "top_domains": domains,
        }

    def iter_log_facts(self) -> List[Dict[str, Any]]:
        """列出每条响应侧日志的 (域名, 处置, 命中类别)，供信誉重算使用。

        ★ 为什么需要它（2026-10-04）
        ────────────────────────────────────────────────────────────
        relay_reputation 的计数是**累加**的：删日志（清空 / 按筛选删 /
        删单条）都不会回退它。于是出现「首页已归零，中转站卡片
        还写着 3 次调用」—— 两个数字各自都"对"，只是口径不同，
        用户只能认为软件坏了。

        要想让两者长期一致，唯一可行的是**以 logs 为唯一事实源重算**，
        而重算需要把每条日志还原成「记了谁一笔、算谁的账」。

        ★ 只取 response_verify 类型：
          只有这条路径会调 track.record_call（见 app.py 的
          _record_reputation 三个调用点）。若把 relay（直通）日志
          或 request_sanitize（请求侧阻断）也算进来，
          total_calls 会凭空变大 —— 重算反而制造新的不一致。

        ★ categories 从 detail_json 解析：那里存的是
          ``[f.to_dict() for f in findings]``。解析失败当空列表 ——
          「宁可少扣也不在无依据时指控中转站」与 tracker._classify
          的取向一致。

        ★ text_preview 一并返回（2026-10-04）：水印等**定性证据**也
          必须能从日志重算，否则清空日志后它仍会扣分 ——
          用户会看到「一条记录都没有，分数却还扣着」。
        """
        rows = self._conn.execute(
            "SELECT relay_domain, action, detail_json, text_preview FROM logs "
            "WHERE log_type = ?",
            (LogType.RESPONSE_VERIFY.value,),
        ).fetchall()
        facts: List[Dict[str, Any]] = []
        for r in rows:
            cats: List[str] = []
            try:
                raw = json.loads(r["detail_json"] or "[]")
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict) and item.get("category"):
                            cats.append(str(item["category"]))
            except (json.JSONDecodeError, TypeError):
                pass
            facts.append({
                "domain": str(r["relay_domain"] or ""),
                "action": str(r["action"] or ""),
                "categories": cats,
                "text_preview": str(r["text_preview"] or ""),
            })
        return facts

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
        """标记日志为误报（★ P1-9：文档 4.1 要求的「标记为安全」按钮）。

        ★★ 必须同时回退 daily_stats，否则界面在骗人。
          界面上点完这个按钮会提示「后续统计将不再计入风险」，
          而原实现只改 logs.marked_safe —— daily_stats 是累加缓存，
          永远不会因标记而回退。
          实测：标记前后 today 统计一模一样，
          于是用户以为「这条已经不算风险了」，
          首页的「危险 N」却纹丝不动，
          唯一的解释就是「玄盾在骗我」或「玄盾坏了」。
          一个防篡改产品的统计如果不能被用户纠正，
          那它给出的每个数字都值得怀疑。
        """
        entry = self.get_log(log_id)
        if entry is None:
            return False
        if entry.marked_safe:
            return True   # 已标记，不重复扣减
        with self._conn:
            cur = self._conn.execute(
                "UPDATE logs SET marked_safe = 1 WHERE id = ?", (log_id,)
            )
            if not cur.rowcount:
                return False
            self._adjust_daily_stats_for_mark(entry, delta=-1)
        return True

    def unmark_safe(self, log_id: int) -> bool:
        """取消误报标记（统计随之加回）。"""
        entry = self.get_log(log_id)
        if entry is None:
            return False
        if not entry.marked_safe:
            return True   # 本就未标记，不重复加回
        with self._conn:
            cur = self._conn.execute(
                "UPDATE logs SET marked_safe = 0 WHERE id = ?", (log_id,)
            )
            if not cur.rowcount:
                return False
            self._adjust_daily_stats_for_mark(entry, delta=1)
        return True

    def _adjust_daily_stats_for_mark(
        self, entry: LogEntry, delta: int
    ) -> None:
        """按 delta 回退/补回某条日志在 daily_stats 里占的份额。

        ★ 只按 action 归类，不碰 redaction_count：
          阻断路径本来就不计入打码数（那是诚实的 ——
          阻断根本没打码），若这里再动它就会凭空多出或少掉打码数。
          实测标注一条 block 日志会让「已打码 N 处」变成负数，
          那是把一个谎报换成另一个谎报。
        """
        if delta not in (-1, 1):
            raise ValueError("delta 只能是 -1 或 +1")
        # ★ 用与录入（_record_log）/ 重算（_recompute_daily_stats）**同一套口径**
        #   算出「未标记」与「已标记」两种贡献，两者之差就是这次
        #   标记 / 取消标记该回退 / 补回的份额。
        #   原实现只判 action 而写死列名，等于把归类规则又写了一遍 ——
        #   一旦录入侧口径变动，这里就会与重算一起漂移。
        #
        #   只有影响风险判定的两类才会产生非零差额：
        #   block（危险）与 alert（可疑）；pass（安全）标记本无意义，
        #   它的两种贡献完全相同、差额为零，天然不会改动任何计数 ——
        #   也就不会让「安全」数凭空变小（那同样是对用户的谎报）。
        unmarked = kpi_contribution(entry.log_type, entry.action, False)
        marked = kpi_contribution(entry.log_type, entry.action, True)
        if delta < 0:      # 标记：未标记 → 已标记
            d_total, d_danger, d_suspect, d_safe = (
                marked[i] - unmarked[i] for i in range(4)
            )
        else:              # 取消标记：已标记 → 未标记
            d_total, d_danger, d_suspect, d_safe = (
                unmarked[i] - marked[i] for i in range(4)
            )
        if not any((d_total, d_danger, d_suspect, d_safe)):
            return

        import datetime as _dt
        date_str = _dt.date.today().isoformat()
        row = self._conn.execute(
            "SELECT timestamp FROM logs WHERE id = ?", (entry.id,)
        ).fetchone()
        # 统计按「日志写入当天」归集，不按今天 ——
        # 否则用户隔天补标一条昨天的日志，会错扣今天的数。
        if row is not None:
            date_str = _dt.datetime.fromtimestamp(
                float(row["timestamp"])
            ).date().isoformat()

        with self._conn:
            self._conn.execute(
                """UPDATE daily_stats
                   SET total_calls = MAX(0, total_calls + ?),
                       danger_count = MAX(0, danger_count + ?),
                       suspect_count = MAX(0, suspect_count + ?),
                       safe_count = MAX(0, safe_count + ?)
                   WHERE date = ?""",
                (d_total, d_danger, d_suspect, d_safe, date_str),
            )

    def export_logs(
        self,
        limit: int = 10_000,
        log_type: Optional[str] = None,
        action: Optional[str] = None,
        search: Optional[str] = None,
        marked_safe: Optional[bool] = None,
        start_ts: Optional[float] = None,
        log_type_not: Optional[str] = None,
    ) -> List[LogEntry]:
        """导出日志（★ P1-9：文档 4.1 要求的「导出」按钮）。

        ★ 2026-10-19 修复：导出必须**尊重用户的筛选条件**。
          旧实现只在导出端点里按 limit 取全量，忽略 log_type/action/search，
          用户按筛选点「导出」拿到的是**全量数据** ——
          导出范围与界面所见不一致，属于「静默忽略用户输入」。
          这里把筛选条件下推到查询，复用 _log_filters，
          与 query_logs / count_logs / delete_logs 同源，杜绝口径漂移。

        ★ 排序用 **ASC（时间升序）**：
          导出成品（CSV/JSON）是给人按时间线顺序阅读的，升序更自然；
          而列表页是「最新在前」（DESC），两者取向不同，故此处独立指定。
        """
        where, params = _log_filters(
            log_type=log_type, action=action, search=search,
            marked_safe=marked_safe, start_ts=start_ts,
            log_type_not=log_type_not,
        )
        sql = f"SELECT * FROM logs {where} ORDER BY timestamp ASC LIMIT ?"
        rows = self._conn.execute(sql, list(params) + [limit]).fetchall()
        return [self._row_to_log(r) for r in rows]

    def get_all_for_export(self, limit: int = 10_000) -> List[LogEntry]:
        """导出全部日志（时间升序，便于按时间线阅读）。

        ★ 2026-10-19：委托给 export_logs，避免两套导出逻辑各自漂移。
          旧实现注释写「升序」、实际却 `ORDER BY timestamp DESC` ——
          注释与行为不符，导出结果与界面预期相反。
        """
        return self.export_logs(limit=limit)

    def clear_logs(self, before_ts: Optional[float] = None) -> int:
        """清空日志（可指定仅清某时间之前）。

        ★★ 2026-10-03 修复：必须连带清理两处，否则界面在骗人。
          ① daily_stats —— 首页那些数字来自这张累加缓存表，
             删日志不会碰它，于是「今日已检查 N 次」纹丝不动。
             实测：插入 1 条 + 统计，清空后 today 仍是非零。
             而清空按钮的确认框明确写着「此操作不可恢复」，
             用户清完回首页看到数字没变，只能认为玄盾坏了。
          ② redaction_records —— 这张表存着**原始敏感值**，
             而 schema 里 log_id 没有任何外键约束，
             所以删日志后原始 API Key / 手机号仍留在库里。
             界面承诺「本地不留存任何原始敏感值」，那句话当时是假的。
        """
        with self._conn:
            if before_ts is None:
                cur = self._conn.execute("DELETE FROM logs")
            else:
                cur = self._conn.execute(
                    "DELETE FROM logs WHERE timestamp < ?", (before_ts,)
                )
            deleted = int(cur.rowcount or 0)
            self._conn.execute("DELETE FROM redaction_records")
            self._recompute_daily_stats()
        self._scrub_wal()
        return deleted

    def _scrub_wal(self) -> None:
        """把 WAL 旁文件落回主库并清空，让敏感数据真的离开磁盘。

        ★★ 为什么 secure_delete 开着还不够（2026-10-03 实测）：
          WAL 是**追加写**的 —— 每次事务把新页追加到文件末尾，
          即使页内内容已被 secure_delete 覆写，**旧帧仍在文件里**。
          实测开启 secure_delete 后，二进制搜索仍能在
          ``xuandun_personal.db-wal`` 里搜到原始 API Key。

          所以删除敏感数据后必须：
            ① wal_checkpoint(TRUNCATE) —— 把 WAL 内容写回主库并**截断**文件；
            ② 再由主库页的 secure_delete 覆写原位置。
          顺序不能反：先截断再让主库覆写，才不会把明文又写回去。

          失败不抛异常 —— 这是清理动作，不该让「删除成功」的返回值变成报错。
        """
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            # 截断后 WAL 里仍有本页刚写的帧，再 checkpoint 一次覆盖掉
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception as e:  # noqa: BLE001
            logger.warning("WAL 清理失败（不影响本次删除结果）: %s", e)

    def delete_log(self, log_id: int) -> bool:
        """删除单条日志。"""
        with self._conn:
            cur = self._conn.execute("DELETE FROM logs WHERE id = ?", (log_id,))
            ok = bool(cur.rowcount)
            if ok:
                self._conn.execute(
                    "DELETE FROM redaction_records WHERE log_id = ?", (log_id,)
                )
                self._recompute_daily_stats()
        if ok:
            self._scrub_wal()
        return ok

    def _recompute_daily_stats(self) -> None:
        """按 logs 表里**实际剩下的**记录重算每日统计。

        ★ 为什么必须重算而不是简单置零：
          「清空全部」置零没问题，但 clear_logs(before_ts) 支持
          「只清某时间之前」—— 用户清掉昨天的日志，今天的统计不该跟着归零。
          置零会把「清理旧记录」变成「篡改今日数据」，
          那是把一个谎报换成另一个谎报。

        ★ 为什么以 logs 为准而不是在删除时做减法：
          daily_stats 是累加缓存，任何一次漏记/重复记都会让它永久漂移。
          从明细重算则天然自愈 —— 这是唯一能让两个口径长期不打架的做法。
          代价只是一次 COUNT，而它把「统计可能骗人」变成了「统计不可能骗人」。

        ★ redaction_count 不能从 logs 重算：
          打码数是「本条日志打了几处」，日志表里没存这个数，
          而 redaction_records 按 log_id 存着明细行数。
          所以它取自 redaction_records 的行数 ——
          删日志时上面已连带删掉对应行，两者天然同步。

        ★★ 2026-10-19 修复：重算必须与录入共用同一套归类口径。
          原实现按 `action` 全表聚合，于是：
            · log_type='proxy_error' 的行（录入时刻意不计 KPI）
              因 action 恰为 block / alert 而被重新计进「危险 / 可疑」；
            · 用户标记为误报（marked_safe=1）的行被完全忽略、
              重新计回风险档。
          后果：用户每删一次日志，首页的「危险 / 可疑 / 已检查」
          就可能凭空变化。现在逐行调用 kpi_contribution() ——
          与录入、标记是同一个函数，分叉从源头消失。
        """
        with self._conn:
            rows = self._conn.execute(
                "SELECT date(timestamp, 'unixepoch', 'localtime') AS d, "
                "log_type, action, marked_safe, redaction_count FROM logs"
            ).fetchall()
            # 逐行折算（口径见 kpi_contribution），按天归集。
            # 第 5 位是打码处数：★ 2026-10-20 改为取日志行上的计数，
            # 不再数 redaction_records —— 明细会在响应还原后被隐私清除，
            # 而计数不该跟着消失（否则「已打码 N 处」会随一次删除凭空变小）。
            per_day: Dict[str, List[int]] = {}
            for r in rows:
                d = r["d"]
                if not d:
                    continue
                acc = per_day.setdefault(str(d), [0, 0, 0, 0, 0])
                t, danger, suspect, safe = kpi_contribution(
                    str(r["log_type"]), str(r["action"]),
                    bool(r["marked_safe"]),
                )
                acc[0] += t
                acc[1] += danger
                acc[2] += suspect
                acc[3] += safe
                acc[4] += int(r["redaction_count"] or 0)

            dates = list(per_day.keys())
            if dates:
                # ★ 2026-10-19：改用子查询表达「不在这些日期里」，
                #   避免把日期展开成 NOT IN (?,?,...) ——
                #   一旦日志跨度极大（海量天）同样会撞变量上限。
                #   WHERE ... IS NOT NULL 不可省：SQL 的 NOT IN 列表里
                #   只要含 NULL 就整体判为未知，会导致一条也删不掉。
                self._conn.execute(
                    "DELETE FROM daily_stats WHERE date NOT IN "
                    "(SELECT DISTINCT date(timestamp, 'unixepoch', 'localtime') "
                    "FROM logs "
                    "WHERE date(timestamp, 'unixepoch', 'localtime') IS NOT NULL)"
                )
                for d in dates:
                    total, danger, suspect, safe, redactions = per_day[d]
                    self._conn.execute(
                        """INSERT INTO daily_stats
                           (date, total_calls, danger_count, suspect_count,
                            safe_count, redaction_count)
                           VALUES (?,?,?,?,?,?)
                           ON CONFLICT(date) DO UPDATE SET
                             total_calls = excluded.total_calls,
                             danger_count = excluded.danger_count,
                             suspect_count = excluded.suspect_count,
                             safe_count = excluded.safe_count,
                             redaction_count = excluded.redaction_count""",
                        (
                            d,
                            int(total),
                            int(danger),
                            int(suspect),
                            int(safe),
                            int(redactions),
                        ),
                    )
            else:
                self._conn.execute("DELETE FROM daily_stats")

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
                    known_malicious, watermark_detected, notes,
                    relay_danger_count, self_danger_count,
                    relay_suspect_count, self_suspect_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET
                     score=excluded.score, last_seen=excluded.last_seen,
                     total_calls=excluded.total_calls,
                     danger_count=excluded.danger_count,
                     suspect_count=excluded.suspect_count,
                     avg_latency_ms=excluded.avg_latency_ms,
                     latency_samples=excluded.latency_samples,
                     known_malicious=excluded.known_malicious,
                     watermark_detected=excluded.watermark_detected,
                     notes=excluded.notes,
                     relay_danger_count=excluded.relay_danger_count,
                     self_danger_count=excluded.self_danger_count,
                     relay_suspect_count=excluded.relay_suspect_count,
                     self_suspect_count=excluded.self_suspect_count""",
                (
                    rep.domain, rep.score, rep.first_seen, rep.last_seen,
                    rep.total_calls, rep.danger_count, rep.suspect_count,
                    rep.avg_latency_ms, rep.latency_samples,
                    int(rep.known_malicious), int(rep.watermark_detected),
                    json.dumps(rep.notes, ensure_ascii=False),
                    rep.relay_danger_count, rep.self_danger_count,
                    rep.relay_suspect_count, rep.self_suspect_count,
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

            def _i(key: str) -> int:
                # 老库可能缺列（迁移失败/被手工改过），缺失当 0。
                # 用 keys() 判断而不是直接下标 ——
                # 直接取会抛 IndexError，把一次读库失败变成崩溃。
                if key not in r.keys():
                    return 0
                try:
                    return int(r[key])
                except (TypeError, ValueError):
                    return 0

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
                    relay_danger_count=_i("relay_danger_count"),
                    self_danger_count=_i("self_danger_count"),
                    relay_suspect_count=_i("relay_suspect_count"),
                    self_suspect_count=_i("self_suspect_count"),
                )
            )
        return result

    def migrate_relay_key(self, old_key: str, new_key: str) -> Dict[str, int]:
        """把信誉键与日志域名从 old_key 迁到 new_key（2026-10-04，一次性）。

        ★ 为什么必须迁移
         信誉键从「纯主机」改为「主机#Key指纹」后，旧记录会与新记录
          并存 —— 界面上同一家出现两行（一行有历史数字、一行从 0 开始），
          用户会以为数据重复了或软件坏了。

        ★ 目标键已存在时**不覆盖**
          正常升级路径下 new_key 还不存在；万一存在（用户已跑过新版），
          说明新键的数据更新，应当保留。此时只迁日志域名，不动信誉行。

        ★ logs.relay_domain 也要一起迁
          否则按日志重算信誉时，旧日志匹配不到新键 —— 计数会被算成 0，
          用户看到「日志有 200 条、卡片显示 0 次调用」，比不迁移更糟。
        """
        if not old_key or not new_key or old_key == new_key:
            return {"reputation": 0, "logs": 0}
        with self._conn:
            exists = self._conn.execute(
                "SELECT COUNT(*) AS c FROM relay_reputation WHERE domain = ?",
                (new_key,),
            ).fetchone()
            reps = 0
            if not exists or not int(exists["c"]):
                cur = self._conn.execute(
                    "UPDATE relay_reputation SET domain = ? WHERE domain = ?",
                    (new_key, old_key),
                )
                reps = int(cur.rowcount or 0)
            cur2 = self._conn.execute(
                "UPDATE logs SET relay_domain = ? WHERE relay_domain = ?",
                (new_key, old_key),
            )
            return {"reputation": reps, "logs": int(cur2.rowcount or 0)}

    def delete_reputation(self, domain: str) -> bool:
        """删除一条中转站信誉记录（用于清理孤儿行）。

        ★ 什么时候会成孤儿（2026-10-04）：
          信誉键从「纯主机」升级为「主机#Key指纹」的迁移过程中，
          以及旧版本遗留的裸主机行 —— 它们既不在当前配置的键集合里，
          也没有任何日志引用。留着会让设置页/卡片出现「一行 0 次调用的
          陌生记录」，用户以为数据坏了。
        """
        if not domain:
            return False
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM relay_reputation WHERE domain = ?", (domain,)
            )
        return bool(cur.rowcount)

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

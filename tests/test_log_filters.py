# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""日志筛选与管理的契约测试。

★ 为什么要单独锁住（2026-10-03）
────────────────────────────────────────────────────────────────
用户报「稳定版日志 954 条，筛选不出来」。查下来是两级问题：

① **total 与 entries 口径分叉**（后端）
   /api/logs 的 entries 走 query_logs（支持 search），
   而 total 走 count_logs（当时漏了 search）——
   于是搜「你好」时列表只剩 3 条，分页器却显示「共 954 条 / 48 页」，
   点第 2 页得到空列表。这就是「筛不出来」，且**无任何报错**。

② **Rust 侧布尔参数丢失**（前端）
   marked_safe 是 JSON 布尔，而 Rust 拼 query 时只处理了
   as_u64（数字）与 as_str（字符串）—— 布尔走两条都取不到，
   参数根本没进 query string，筛选静默退化成「不筛选」。

这两类的共同特征：**没有报错，只有「筛不出来」**。
所以判据必须直接比对「列表条数」与「total」，而不是断言函数返回了非空。
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.storage import db as db_mod  # noqa: E402
from daoti_xuandun_personal.types import Action, LogEntry, LogType  # noqa: E402


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """建一个隔离的存储实例（不碰用户真实数据库）。"""
    monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
    import importlib

    from daoti_xuandun_personal import paths
    importlib.reload(paths)
    importlib.reload(db_mod)

    s = db_mod.PersonalStorage(db_path=tmp_path / "t.db")
    for i in range(30):
        s.insert_log(
            LogEntry(
                timestamp=1_700_000_000.0 + i,
                log_type=LogType.REQUEST_SANITIZE.value,
                relay_domain="a.example.invalid",
                action=Action.BLOCK.value,
                severity="high",
                model="m",
                finding_count=1,
                summary=f"命中密钥 {i}",
                detail_json="[]",
                text_preview=f"片段内容-{i}",
            )
        )
        s.insert_log(
            LogEntry(
                timestamp=1_700_000_000.0 + i,
                log_type=LogType.RESPONSE_VERIFY.value,
                relay_domain="b.example.invalid",
                action=Action.PASS.value,
                severity="low",
                model="m",
                finding_count=0,
                summary=f"正常转发 {i}",
                detail_json="[]",
                text_preview=f"回答内容-{i}",
            )
        )
    yield s

    monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
    importlib.reload(paths)
    importlib.reload(db_mod)


class TestListAndCountAgree:
    """① 列表与计数必须用同一套过滤条件。"""

    @pytest.mark.parametrize("kwargs", [
        {"search": "命中密钥"},
        {"search": "回答内容"},
        {"log_type": "request_sanitize"},
        {"action": "block"},
        {"log_type": "request_sanitize", "action": "block"},
        {"search": "密钥", "log_type": "request_sanitize"},
    ])
    def test_total_matches_list_length(self, store, kwargs):
        """★ 核心判据：不看函数返回什么，只看两者是否一致。

        「都返回了非空值」不是判据 —— 954 与 3 都非空，
        错恰恰在于它们不相等。
        """
        n_list = len(store.query_logs(limit=500, **kwargs))
        n_count = store.count_logs(**kwargs)
        assert n_list == n_count, (
            f"筛选 {kwargs}：列表 {n_list} 条，但 total 说 {n_count} 条 —— "
            f"分页器会按 total 算页数，点进去却是空列表"
        )

    def test_search_is_not_ignored(self, store):
        """★ 回归：search 必须真的生效（原缺陷就是漏了它）。"""
        n_all = store.count_logs()
        n_hit = store.count_logs(search="命中密钥")
        assert n_hit < n_all, (
            f"搜索后总数没变（{n_all}）—— search 又被忽略了"
        )
        assert n_hit == 30

    def test_pagination_within_filtered_set(self, store):
        """分页必须在筛选结果内翻，且不重不漏。"""
        seen = []
        for offset in range(0, 60, 20):
            seen.extend(
                e.id for e in store.query_logs(
                    search="命中密钥", limit=20, offset=offset)
            )
        assert len(seen) == len(set(seen)), "分页出现重复行"
        assert len(seen) == 30, f"分页漏行：翻完只有 {len(seen)} 条"

    def test_marked_safe_filter_agrees(self, store):
        """★ marked_safe 也要两边一致（前端新增的筛选维度）。"""
        store.mark_safe(store.query_logs(limit=1)[0].id)
        for want in (True, False):
            n_list = len(store.query_logs(marked_safe=want, limit=500))
            n_count = store.count_logs(marked_safe=want)
            assert n_list == n_count, (
                f"marked_safe={want}：列表 {n_list} 条 / total {n_count} 条"
            )


class TestFiltersSharedNotDuplicated:
    """② 三个方法必须共用 ``_log_filters``，不得各写一套。"""

    def test_all_three_use_the_same_builder(self):
        """★ 结构判据：过滤条件只允许写一次。

        这次的真缺陷正是「count_logs 少写了 search」——
        每个函数单测都绿，拼起来才错。
        所以必须从结构上锁住：三个方法都走同一个构造器。
        """
        src = (REPO / "src" / "daoti_xuandun_personal"
               / "storage" / "db.py").read_text(encoding="utf-8")

        import re
        for name in ("query_logs", "count_logs", "delete_logs"):
            m = re.search(
                rf"def {name}\(.*?\n(?=    def |\Z)", src, re.S)
            assert m, f"找不到 {name}"
            body = m.group(0)
            assert "_log_filters(" in body, (
                f"{name} 没有走 _log_filters —— "
                f"过滤条件各写一套必然漂移，"
                f"而漂移表现为「筛不出来」且无任何报错"
            )

    def test_builder_handles_every_filter(self):
        """构造器必须覆盖全部筛选维度（含布尔与搜索）。"""
        where, params = db_mod._log_filters(
            log_type="t", action="a", search="s", marked_safe=False,
            start_ts=1.0,
        )
        assert "log_type = ?" in where
        assert "action = ?" in where
        assert "summary LIKE ?" in where
        # ★ 布尔必须落进 WHERE：漏了它「排除误报」会退化成「不筛选」
        assert "marked_safe = ?" in where
        assert 0 in params, "marked_safe=False 被丢掉了 —— 该档位是「不看误报」"

    def test_empty_filters_mean_no_clause(self):
        where, params = db_mod._log_filters()
        assert where == ""
        assert params == []


class TestDeleteMatchesFilter:
    """③ 删除范围必须与用户看到的列表范围一致。"""

    def test_deletes_exactly_what_is_listed(self, store):
        listed = {e.id for e in store.query_logs(
            log_type="request_sanitize", action="block", limit=500)}
        assert listed, "前置条件：本用例需要确实能筛出东西"

        deleted = store.delete_logs(
            log_type="request_sanitize", action="block")
        assert deleted == len(listed), (
            f"删除了 {deleted} 条，但列表里有 {len(listed)} 条 —— "
            f"「删掉我看到的」变成了「删掉别的」"
        )
        assert store.count_logs(log_type="request_sanitize") == 0

    def test_delete_respects_search(self, store):
        store.delete_logs(search="命中密钥")
        assert store.count_logs(search="命中密钥") == 0
        # 另一类必须毫发无损
        assert store.count_logs(search="回答内容") == 30

    def test_delete_cascades_redactions(self, store):
        """★ 删除日志必须连带删掉脱敏记录。

        那些行会经 detail_json 与 CSV 导出外发 ——
        留着它们等于「日志删了但内容还在」，用户以为清干净了。
        """
        row = store.query_logs(log_type="request_sanitize", limit=1)[0]
        store.delete_logs(search="命中密钥")
        left = store._conn.execute(
            "SELECT COUNT(*) AS c FROM redaction_records WHERE log_id = ?",
            (row.id,),
        ).fetchone()
        assert int(left["c"]) == 0, (
            "日志删了但脱敏记录还在 —— 用户以为清干净了，"
            "内容其实仍可被导出"
        )


class TestLogBreakdown:
    """④ 概览统计要能回答用户真正会问的问题。"""

    def test_reports_distribution(self, store):
        b = store.log_breakdown()
        assert b["total"] == 60
        assert b["by_type"]["request_sanitize"] == 30
        assert b["by_action"]["block"] == 30
        assert b["oldest_ts"] > 0 and b["newest_ts"] >= b["oldest_ts"]
        assert len(b["top_domains"]) == 2

    def test_counts_marked_safe(self, store):
        store.mark_safe(store.query_logs(limit=1)[0].id)
        assert store.log_breakdown()["marked_safe"] == 1

    def test_empty_db_does_not_crash(self, tmp_path, monkeypatch):
        """空库必须返回结构完整的零值 —— 界面上有这些数字。"""
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        import importlib
        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        importlib.reload(db_mod)
        try:
            b = db_mod.PersonalStorage(db_path=tmp_path / "e.db").log_breakdown()
            assert b["total"] == 0
            assert b["marked_safe"] == 0
            assert b["by_type"] == {}
            assert b["top_domains"] == []
        finally:
            monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
            importlib.reload(paths)
            importlib.reload(db_mod)


class TestRustHandlesBooleanFilter:
    """⑤ Rust 侧必须处理布尔参数（前端新增了 marked_safe 筛选）。"""

    def test_rust_parses_marked_safe(self):
        """★ Rust 的 query 拼装只处理 as_u64 / as_str ——
        布尔走两条都取不到，不单独处理就会静默丢参。
        """
        src = (REPO / "desktop" / "src-tauri" / "src"
               / "lib.rs").read_text(encoding="utf-8")
        assert "marked_safe" in src, (
            "Rust 侧完全不认识 marked_safe —— "
            "「仅看误报/排除误报」在桌面端点了没反应"
        )
        assert "as_bool()" in src, (
            "marked_safe 没有用 as_bool 读取 —— "
            "它不在 as_u64 / as_str 的处理范围内，参数会被静默丢掉"
        )

    def test_rust_registers_new_commands(self):
        """新命令必须注册，否则前端调用直接报「命令不存在」。"""
        src = (REPO / "desktop" / "src-tauri" / "src"
               / "lib.rs").read_text(encoding="utf-8")
        handler = src.split("generate_handler![")[1].split("]")[0]
        for cmd in ("get_logs_stats", "count_filtered_logs",
                    "delete_filtered_logs"):
            assert cmd in handler, (
                f"{cmd} 已实现但未注册到 invoke_handler —— "
                f"前端调用会得到「命令不存在」"
            )

    def test_frontend_wires_marked_safe(self):
        """前端必须显式判 undefined —— ``if (v)`` 会漏掉 false。"""
        src = (REPO / "desktop" / "src" / "services"
               / "api.ts").read_text(encoding="utf-8")
        assert "marked_safe !== undefined" in src, (
            "前端用真值判断处理 marked_safe —— "
            "false（=排除误报）这一档会被漏掉，筛选静默失效"
        )


class TestBackendEndpointExists:
    """⑥ 新端点必须真的存在（否则界面按钮点了报 404）。"""

    def test_endpoints_registered(self):
        src = (REPO / "src" / "daoti_xuandun_personal"
               / "proxy" / "app.py").read_text(encoding="utf-8")
        for route in ('/api/logs/delete-filtered',
                      '/api/logs/delete-filtered/confirm',
                      '/api/logs/stats'):
            assert route in src, f"缺少端点 {route}"

    def test_dry_run_never_deletes(self):
        """★ dry run 必须只回报条数，绝不真删。

        删除不可恢复 —— 若「预演」这一步就真删了，
        用户连后悔的机会都没有。
        """
        src = (REPO / "src" / "daoti_xuandun_personal"
               / "proxy" / "app.py").read_text(encoding="utf-8")
        block = src.split('async def delete_filtered_logs(')[1].split("\n    @app")[0]
        assert "count_logs" in block, "预演没有走 count_logs"
        # 预演里绝不能出现 delete_logs / clear_logs
        assert "delete_logs" not in block, (
            "预演路径里调用了 delete_logs —— "
            "「看清范围再确认」就变成了「点一下直接删」"
        )
        assert '"deleted": 0' in block, "预演必须回报 deleted=0"
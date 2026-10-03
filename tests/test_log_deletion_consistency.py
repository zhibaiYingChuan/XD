# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""删除日志后「首页统计」与「原始敏感值」必须同步的契约测试。

★ 为什么要单独锁住（2026-10-03）
────────────────────────────────────────────────────────────────
用户装完 v0.1.3-alpha 后报：「安全日志我清空之后，首页还显示之前的记录数字。」
实测复现：

    清空前  today = {total 1, suspect 1, redaction 1}
    clear_logs 删了 1 条日志
    清空后  today = {total 1, suspect 1, redaction 1}   ← 纹丝不动

根因：首页数字来自 ``daily_stats``（逐条累加的缓存表），
而 ``clear_logs`` 只 ``DELETE FROM logs``，从不碰它。
两套数字各自都对，只是删完就不再一致了 ——
一个防篡改产品的统计如果不能被用户纠正，那它给出的每个数字都值得怀疑。

顺带查出第二个更严重的：``redaction_records`` 存着**原始敏感值**
（用户自己的 API Key / 手机号），而 ``schema.sql`` 里 ``log_id``
**没有任何外键约束**，所以删日志后原文仍留在库里。
界面确认框明明写着「脱敏记录会一并删除，本地不留存任何原始敏感值」，
那句话当时是假的。

这两个 bug 的共同特征：**不报错，只是数字/承诺与事实不符**。
所以判据必须直接比对「删完之后统计与明细是否一致」，
而不是断言函数返回了非空。
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.storage import db as db_mod  # noqa: E402
from daoti_xuandun_personal.types import (  # noqa: E402
    Action,
    LogEntry,
    LogType,
    RedactionRecord,
)


def _rec(category: str, original: str) -> RedactionRecord:
    return RedactionRecord(
        index=0, category=category, original=original,
        redacted="[REDACTED]", start=0, end=len(original),
    )


@pytest.fixture()
def store(tmp_path):
    """隔离存储实例（不碰用户真实数据库）。"""
    return db_mod.PersonalStorage(db_path=tmp_path / "del.db")


def _write(store, action, domain="a.example.invalid", redactions=(),
           ts=None, summary="测试记录"):
    """走**生产同款**写法：插日志 → 连带脱敏记录 → 累加每日统计。

    ★ 刻意复用 update_daily_stats，而不是只插日志 ——
      真实路径（proxy/app.py::_record_log）就是这么写的，
      只插日志会让「统计是缓存」这个前提在测试里不成立，
      于是测试通过而线上仍然错。
    """
    entry = LogEntry(
        timestamp=time.time() if ts is None else ts,
        log_type=LogType.RESPONSE_VERIFY.value,
        relay_domain=domain,
        action=action,
        severity="low",
        model="m",
        finding_count=1,
        summary=summary,
    )
    log_id = store.insert_log(entry)
    recs = list(redactions)
    if recs:
        store.insert_redactions(log_id, "sess", recs)
    store.update_daily_stats(
        total_calls=1,
        danger=1 if action == Action.BLOCK.value else 0,
        suspect=1 if action == Action.ALERT.value else 0,
        safe=1 if action == Action.PASS.value else 0,
        redactions=len(recs),
    )
    return log_id


class TestClearLogsResetsStats:
    """clear_logs 之后首页统计必须归零。"""

    def test_clear_all_zeroes_today_stats(self, store):
        _write(store, Action.ALERT.value, redactions=[_rec("api_key", "sk-SECRET-A")])
        _write(store, Action.BLOCK.value, redactions=[_rec("phone", "13800000000")])
        _write(store, Action.PASS.value)

        before = store.get_today_stats()
        assert before["total_calls"] == 3
        assert before["suspect_count"] == 1
        assert before["danger_count"] == 1

        store.clear_logs()

        after = store.get_today_stats()
        assert after["total_calls"] == 0, (
            f"清空全部日志后首页仍显示今日检查 {after['total_calls']} 次 —— "
            "daily_stats 是累加缓存，不重算就永远对不上"
        )
        assert after["danger_count"] == 0
        assert after["suspect_count"] == 0
        assert after["safe_count"] == 0
        assert after["redaction_count"] == 0

    def test_stats_equal_surviving_logs_after_partial_clear(self, store):
        """★ 通用判据：清完之后，统计必须等于「还剩的日志」。

        这条比「归零」更强 —— 它对任意删除子集都成立，
        意味着首页数字与日志页列表永远对得上。
        """
        now = time.time()
        _write(store, Action.BLOCK.value, ts=now - 86400 * 3)
        _write(store, Action.ALERT.value, ts=now - 86400 * 3)
        _write(store, Action.PASS.value, ts=now)

        store.clear_logs(now - 86400 * 2)

        today = store.get_today_stats()
        assert store.count_logs() == 1
        assert today["total_calls"] == store.count_logs(), (
            f"今日检查数 {today['total_calls']} 与实际剩余日志 "
            f"{store.count_logs()} 条不一致"
        )
        assert today["safe_count"] == 1
        assert today["danger_count"] == 0, (
            "清掉的是 3 天前的记录，今天的统计不该跟着变 —— "
            "置零会把「清理旧记录」变成「篡改今日数据」"
        )

    def test_recompute_is_idempotent(self, store):
        """重算两次与一次结果相同（幂等）。

        不幂等意味着每删一次日志统计就漂一次，
        删得越多数字越离谱。
        """
        _write(store, Action.ALERT.value, redactions=[_rec("api_key", "sk-S")])
        _write(store, Action.BLOCK.value)

        store._recompute_daily_stats()
        once = dict(store.get_today_stats())
        store._recompute_daily_stats()
        twice = dict(store.get_today_stats())

        assert once == twice, f"重算不幂等：{once} vs {twice}"
        assert once["total_calls"] == 2
        assert once["redaction_count"] == 1


class TestRedactionsAreCascaded:
    """★ 脱敏记录（原始敏感值）必须随日志一起消失。"""

    def test_clear_all_removes_original_secrets(self, store):
        log_id = _write(
            store, Action.ALERT.value,
            redactions=[_rec("api_key", "sk-REAL-SECRET-1"),
                        _rec("phone", "13800000000")],
        )
        assert store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records WHERE log_id = ?", (log_id,)
        ).fetchone()["c"] == 2

        store.clear_logs()

        left = store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records"
        ).fetchone()["c"]
        assert left == 0, (
            f"清空日志后仍残留 {left} 行原始敏感值 —— "
            "界面承诺「本地不留存任何原始敏感值」，"
            "而 schema 里 log_id 没有外键，删日志不会级联带走它们"
        )

    def test_delete_single_log_removes_its_redactions(self, store):
        keep = _write(store, Action.PASS.value)
        drop = _write(store, Action.ALERT.value,
                      redactions=[_rec("api_key", "sk-DROP-ME")])

        assert store.delete_log(drop) is True

        assert store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records WHERE log_id = ?", (drop,)
        ).fetchone()["c"] == 0, "删单条日志后它的原始敏感值还留着"
        assert store.get_log(keep) is not None, "删一条不该影响另一条"
        assert store.count_logs() == 1

    def test_delete_filtered_only_touches_matching_rows(self, store):
        """★ 按筛选删除：只连带删中标的脱敏记录，别家一个都不能少。"""
        a = _write(store, Action.ALERT.value, domain="a.example.invalid",
                   redactions=[_rec("api_key", "sk-A-DELETE")])
        b = _write(store, Action.BLOCK.value, domain="b.example.invalid",
                   redactions=[_rec("api_key", "sk-B-KEEP"),
                               _rec("phone", "13900000000")])

        deleted = store.delete_logs(relay_domain="a.example.invalid")
        assert deleted == 1

        assert store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records WHERE log_id = ?", (a,)
        ).fetchone()["c"] == 0, "中标的脱敏记录必须删掉"
        assert store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records WHERE log_id = ?", (b,)
        ).fetchone()["c"] == 2, (
            "没被筛中的日志，它的原始敏感值必须原样保留 —— "
            "删除范围与用户看到的列表范围不一致，比不删更危险"
        )
        assert store.get_log(b) is not None

    def test_delete_filtered_with_no_match_keeps_everything(self, store):
        log_id = _write(store, Action.ALERT.value, domain="a.example.invalid",
                        redactions=[_rec("api_key", "sk-KEEP")])
        assert store.delete_logs(relay_domain="nomatch.invalid") == 0
        assert store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records"
        ).fetchone()["c"] == 1, "没匹配到就不该动任何数据"


class TestNoForeignKeyToRelyOn:
    """守卫：不能有人日后"顺手"加个外键让这些显式 DELETE 变成冗余。"""

    def test_redaction_records_has_no_cascade(self, tmp_path):
        s = db_mod.PersonalStorage(db_path=tmp_path / "fk.db")
        fks = s._conn.execute(
            "PRAGMA foreign_key_list(redaction_records)"
        ).fetchall()
        assert not fks, (
            "redaction_records 上出现外键了，删除路径的显式 DELETE "
            "仍需保留（两处都要正确），但这条测试的注释需要更新"
        )

    def test_delete_api_is_reachable(self):
        """路由层的删除入口必须真的调到底层方法，而不是自己写 SQL。"""
        src = (REPO / "src" / "daoti_xuandun_personal" / "proxy"
               / "app.py").read_text(encoding="utf-8")
        assert "_storage.delete_logs(" in src, (
            "按筛选删除的端点没走 storage.delete_logs —— "
            "绕开它就会重演「列表与删除范围不一致」的历史缺陷"
        )
        assert "_storage.clear_logs(" in src
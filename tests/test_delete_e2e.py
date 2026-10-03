"""★ 端到端验证：删日志后首页统计必须同步（真实 HTTP 链路）。

与 test_log_deletion_consistency.py 的区别：
  那份直接调 PersonalStorage，属于「单元层」；
  这份起真实的 FastAPI 应用、经 TestClient 打真实的 HTTP 端点，
  覆盖「路由 → 存储 → 首页 /api/state」这条完整链路。

★ 为什么必须再补一层：
  历史失效形态恰恰是「底层方法是对的，但路由没走它」——
  比如按筛选删除的端点自己写了一段 SQL，绕开了 delete_logs()。
  那样的话，单元测试全绿而线上仍然错。
  所以判据要落在「HTTP 端点」上，而不是「Python 方法」上。
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

from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.storage import db as db_mod  # noqa: E402
from daoti_xuandun_personal.types import (  # noqa: E402
    Action,
    LogEntry,
    LogType,
    RedactionRecord,
)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """真实 app + 真实 SQLite + 真实 lifespan。

    ★★ 必须靠 ``XUANDUN_DATA_DIR`` 指向临时目录，**不能**手工注入
      ``app_mod._storage`` ——
      ``with TestClient(...)`` 会跑 lifespan，而 lifespan 里会自己
      ``_storage = PersonalStorage()`` 把我注入的那个覆盖掉。
      于是测试写的种子数据进了另一个库，端点读的是空库，
      症状是「assert 3 == 0 / 404 日志不存在」这种看起来像产品有 bug 的失败。

      这就是「拼装处才暴露」的典型：每个 helper 单独看都对，
      错在谁在最后又覆盖了一遍。

    ★ 必须在进入 lifespan **之后**才取 ``app_mod._storage`` 去写种子数据，
      因为那才是端点真正会读的那个实例。
    """
    monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
    import importlib

    from fastapi.testclient import TestClient

    from daoti_xuandun_personal import paths
    importlib.reload(paths)
    from daoti_xuandun_personal.proxy import app as app_mod

    try:
        with TestClient(app_mod.create_app()) as c:
            c.store = app_mod._storage
            assert c.store is not None, (
                "lifespan 跑完后 _storage 仍是 None —— "
                "引擎没起，后续断言会伪装成产品缺陷"
            )
            yield c
    finally:
        monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
        importlib.reload(paths)


def _seed(store, action, domain, redactions=()):
    entry = LogEntry(
        timestamp=time.time(),
        log_type=LogType.RESPONSE_VERIFY.value,
        relay_domain=domain,
        action=action,
        severity="low",
        model="m",
        finding_count=1,
        summary=f"{action}@{domain}",
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


def _rec(original: str) -> RedactionRecord:
    return RedactionRecord(index=0, category="api_key", original=original,
                           redacted="[API_KEY]", start=0, end=len(original))


class TestClearEndpointSyncsHome:
    """★ 用户报的那个现象：清空后首页数字还在。"""

    def test_home_state_zeroes_after_clear(self, client):
        store = client.store
        _seed(store, Action.ALERT.value, "a.example.invalid",
              [_rec("sk-SECRET-1"), _rec("sk-SECRET-2")])
        _seed(store, Action.BLOCK.value, "b.example.invalid", [_rec("sk-SECRET-3")])
        _seed(store, Action.PASS.value, "a.example.invalid")

        before = client.get("/api/state").json()["today"]
        assert before["total_calls"] == 3
        assert before["suspect_count"] == 1
        assert before["danger_count"] == 1
        assert before["redaction_count"] == 3

        r = client.post("/api/logs/clear", json={"before_days": 0})
        assert r.status_code == 200, r.text
        assert r.json()["deleted"] == 3

        after = client.get("/api/state").json()["today"]
        assert after["total_calls"] == 0, (
            f"清空日志后首页「今日已检查」仍显示 {after['total_calls']} 次 —— "
            "这就是用户报的现象，且不报任何错"
        )
        assert after["suspect_count"] == 0
        assert after["danger_count"] == 0
        assert after["redaction_count"] == 0

    def test_original_secrets_are_gone_from_disk(self, client, tmp_path):
        """★ 清空后原始敏感值不得留在库里。

        界面承诺「本地不留存任何原始敏感值」，
        而 schema 里 log_id 没有外键，删日志不会级联带走它们。
        """
        store = client.store
        _seed(store, Action.ALERT.value, "a.example.invalid",
              [_rec("sk-REAL-SECRET-VALUE")])

        client.post("/api/logs/clear", json={"before_days": 0})

        left = store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records"
        ).fetchone()["c"]
        assert left == 0, f"清空日志后仍残留 {left} 行原始敏感值"

        # ★ 直接扫库文件（含 WAL 旁文件）——
        #   删行 ≠ 内容消失：secure_delete 关闭时，
        #   被删的敏感值仍以明文躺在空闲页里。
        #   承诺「不留存」指的是磁盘上真的搜不到。
        for path in tmp_path.glob("xuandun_personal.db*"):
            if b"sk-REAL-SECRET-VALUE" in path.read_bytes():
                pytest.fail(
                    f"原始 API Key 仍能在 {path.name} 里搜到 —— "
                    "删行不等于内容从磁盘消失，需要 secure_delete"
                )


class TestSecureDeleteIsOn:
    """删除敏感数据时必须连磁盘上的明文一起清掉。"""

    def test_secure_delete_enabled(self, client):
        mode = client.store._conn.execute(
            "PRAGMA secure_delete"
        ).fetchone()[0]
        assert mode == 1, (
            "secure_delete 未开启 —— SQLite 删行只把内容标记为可复用，"
            "原始 API Key 仍以明文留在数据库文件的空闲页里，"
            "而界面承诺「本地不留存任何原始敏感值」"
        )


class TestDeleteFilteredEndpointSyncsHome:
    """按筛选删除同样要同步统计，且不能波及其他记录。"""

    def test_delete_filtered_confirm_syncs_home(self, client):
        store = client.store
        _seed(store, Action.ALERT.value, "a.example.invalid", [_rec("sk-A")])
        _seed(store, Action.BLOCK.value, "b.example.invalid", [_rec("sk-B")])

        dry = client.post(
            "/api/logs/delete-filtered",
            params={"action": "alert"},
        ).json()
        assert dry["dry_run"] is True and dry["deleted"] == 0, (
            "dry run 绝不能真删"
        )
        assert dry["matched"] == 1, (
            f"dry run 报匹配 {dry['matched']} 条，实际只有 1 条可疑 —— "
            "删除范围与用户看到的列表范围不一致"
        )
        assert client.get("/api/state").json()["today"]["total_calls"] == 2

        real = client.post(
            "/api/logs/delete-filtered/confirm",
            params={"action": "alert"},
        ).json()
        assert real["deleted"] == 1

        today = client.get("/api/state").json()["today"]
        assert today["total_calls"] == 1, (
            "按筛选删除后首页统计没跟着变 —— 界面仍谎报"
        )
        assert today["danger_count"] == 1, "B 的危险数不能被误清"
        assert store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records"
        ).fetchone()["c"] == 1, "只该删中标的脱敏记录"

    def test_delete_single_endpoint_syncs_home(self, client):
        store = client.store
        keep = _seed(store, Action.PASS.value, "a.example.invalid")
        drop = _seed(store, Action.ALERT.value, "b.example.invalid", [_rec("sk-D")])

        r = client.delete(f"/api/logs/{drop}")
        assert r.status_code == 200, r.text

        today = client.get("/api/state").json()["today"]
        assert today["total_calls"] == 1
        assert today["suspect_count"] == 0, "删掉唯一的可疑记录后可疑数还应留在界面上"
        assert store.get_log(keep) is not None
        assert store._conn.execute(
            "SELECT COUNT(*) c FROM redaction_records"
        ).fetchone()["c"] == 0

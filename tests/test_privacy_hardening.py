# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""隐私与本地安全加固的契约测试（2026-10-20）。

覆盖本轮修复的六类问题：
  ① 导出 CSV 的公式注入（=HYPERLINK / DDE）
  ② 脱敏原文以明文落库（现在只落掩码）
  ③ 旧库里已有的明文脱敏记录要就地掩码
  ④ 「清理 N 天前」不得连带删掉保留日志的脱敏明细
  ⑤ 日志搜索里的 LIKE 通配符必须按字面处理
  ⑥ 引擎 /api/* 的管理令牌门禁（注入时才生效）

★ 为什么单独成文件：
  这些不是「功能对不对」，而是「承诺与实现是否一致」——
  每一条都对应产品对用户说过的一句话，回归时应当能一眼看到。
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

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

TOKEN = "test-admin-token-0123456789"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """真实 app + 真实 SQLite + 真实 lifespan（与 test_delete_e2e 同构）。"""
    monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("XUANDUN_ADMIN_TOKEN", TOKEN)
    import importlib

    from fastapi.testclient import TestClient

    from daoti_xuandun_personal import paths
    importlib.reload(paths)
    from daoti_xuandun_personal.proxy import app as app_mod

    try:
        with TestClient(app_mod.create_app()) as c:
            c.store = app_mod._storage
            c.app_mod = app_mod
            assert c.store is not None, "lifespan 未初始化存储"
            yield c
    finally:
        monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
        monkeypatch.delenv("XUANDUN_ADMIN_TOKEN", raising=False)
        importlib.reload(paths)


def _log(store, summary="测试", ts=None, response_model=""):
    return store.insert_log(LogEntry(
        timestamp=ts if ts is not None else time.time(),
        log_type=LogType.RESPONSE_VERIFY.value,
        relay_domain="r.example.invalid",
        action=Action.PASS.value,
        severity="low",
        model="gpt-4o",
        response_model=response_model,
        finding_count=0,
        summary=summary,
        detail_json="[]",
        text_preview="",
    ))


# ══════════════════════════════════════════════════════════════
# ① CSV 公式注入
# ══════════════════════════════════════════════════════════════


class TestCsvFormulaInjection:
    """text_preview 来自**可能恶意的中转站**，导出后会被 Excel 打开。"""

    @pytest.mark.parametrize("payload", [
        '=HYPERLINK("http://evil.example","click")',
        "=cmd|'/c calc'!A0",
        "+1+1",
        "-2+3",
        "@SUM(A1:A9)",
        "\t=1+1",
    ])
    def test_dangerous_prefix_is_neutralized(self, payload):
        from daoti_xuandun_personal.proxy.app import _csv_escape

        out = _csv_escape(payload)
        assert out.lstrip('"').startswith("'"), (
            f"以 {payload[:2]!r} 开头的字段未被转义 —— "
            f"Excel 会把它当公式执行：{out!r}"
        )

    def test_normal_text_is_unchanged(self):
        from daoti_xuandun_personal.proxy.app import _csv_escape

        assert _csv_escape("正常的中文总结") == "正常的中文总结"

    def test_comma_and_quote_still_rfc4180(self):
        from daoti_xuandun_personal.proxy.app import _csv_escape

        assert _csv_escape('a,b') == '"a,b"'
        assert _csv_escape('a"b') == '"a""b"'


# ══════════════════════════════════════════════════════════════
# ②③ 脱敏原文：写入即掩码 + 历史数据补掩码
# ══════════════════════════════════════════════════════════════


class TestRedactionAtRest:
    SECRET = "sk-live-abcdefghijklmnopqrstuvwxyz"

    def test_insert_stores_mask_not_plaintext(self, client):
        lid = _log(client.store)
        client.store.insert_redactions(lid, "s1", [
            RedactionRecord(index=1, category="api_key",
                            original=self.SECRET, redacted="⟦XD_1⟧"),
        ])
        row = client.store.get_redactions(lid)[0]
        assert self.SECRET not in row["original"], (
            "明文 API Key 仍被写进数据库 —— 界面打码只是表象"
        )
        assert "⟪" in row["original"], "掩码格式不对，界面无法展示"

    def test_existing_plaintext_rows_are_masked_on_startup(self, client):
        lid = _log(client.store)
        with client.store._conn:
            client.store._conn.execute(
                "INSERT INTO redaction_records "
                "(session_id, log_id, redaction_idx, category, original,"
                " redacted, start_pos, end_pos, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                ("s1", lid, 1, "api_key", self.SECRET, "⟦XD_1⟧",
                 0, len(self.SECRET), time.time()),
            )
        client.store._mask_legacy_redactions()
        row = client.store.get_redactions(lid)[0]
        assert self.SECRET not in row["original"], (
            "旧库里的明文没有被迁移掩码"
        )

    def test_mask_is_idempotent(self):
        from daoti_xuandun_personal.types import mask_secret

        once = mask_secret(self.SECRET)
        twice = mask_secret(once)
        assert once == twice, "掩码不幂等 —— 展示层会把长度压缩两次"


# ══════════════════════════════════════════════════════════════
# ④ 按时间清理：不得误删保留日志的脱敏明细
# ══════════════════════════════════════════════════════════════


class TestClearOldLogsScope:
    def test_keeps_redactions_of_retained_logs(self, client):
        now = time.time()
        old = _log(client.store, "旧日志", ts=now - 10 * 86400)
        new = _log(client.store, "新日志", ts=now)
        for lid in (old, new):
            client.store.insert_redactions(lid, "s1", [
                RedactionRecord(index=1, category="phone",
                                original="13800138000", redacted="⟦XD_1⟧"),
            ])

        deleted = client.store.clear_logs(now - 5 * 86400)
        assert deleted == 1
        assert client.store.get_redactions(old) == []
        assert len(client.store.get_redactions(new)) == 1, (
            "清理旧日志时把保留日志的脱敏明细一起删了 —— "
            "日志还在，点开却什么都没有"
        )


# ══════════════════════════════════════════════════════════════
# ⑤ 搜索必须按字面处理 % 和 _
# ══════════════════════════════════════════════════════════════


class TestSearchWildcards:
    def test_percent_is_literal(self, client):
        _log(client.store, "完成度 100%")
        _log(client.store, "普通一条")
        assert client.store.count_logs(search="%") == 1, (
            "搜索「%」命中了全部记录 —— LIKE 通配符没转义"
        )

    def test_underscore_is_literal(self, client):
        _log(client.store, "变量 a_b")
        _log(client.store, "变量 axb")
        assert client.store.count_logs(search="_") == 1, (
            "搜索「_」匹配了任意单字符 —— LIKE 通配符没转义"
        )


# ══════════════════════════════════════════════════════════════
# ⑥ 返回模型落库（模型降级的核对依据）
# ══════════════════════════════════════════════════════════════


def test_response_model_roundtrip(client):
    lid = _log(client.store, response_model="gpt-4o-mini")
    row = client.store.get_log(lid)
    assert row.response_model == "gpt-4o-mini"
    # 列表行也必须带上，否则详情页拿不到
    assert client.store.query_logs(limit=5)[0].response_model == "gpt-4o-mini"


def test_redaction_count_survives_row_mapping(client):
    """★ 回归：_row_to_log 曾漏掉 redaction_count，列表里的「打码 N 处」永远是 0。"""
    lid = _log(client.store)
    with client.store._conn:
        client.store._conn.execute(
            "UPDATE logs SET redaction_count = 3 WHERE id = ?", (lid,)
        )
    assert client.store.query_logs(limit=1)[0].redaction_count == 3


# ══════════════════════════════════════════════════════════════
# ⑦ 管理接口令牌门禁
# ══════════════════════════════════════════════════════════════


class TestAdminTokenGuard:
    def test_api_requires_token(self, client):
        assert client.get("/api/state").status_code == 401
        assert client.get(
            "/api/state", headers={"X-Admin-Token": "wrong"}
        ).status_code == 401
        ok = client.get("/api/state", headers={"X-Admin-Token": TOKEN})
        assert ok.status_code == 200

    def test_health_and_business_endpoint_stay_open(self, client):
        # 健康检查不带令牌（Rust 侧用它判断引擎是否活着）
        assert client.get("/health").status_code == 200
        # 业务端点供 AI 工具调用，AI 工具不会带管理令牌
        assert client.post(
            "/v1/chat/completions", json={"model": "x", "messages": []}
        ).status_code != 401

    def test_token_is_fail_open_when_not_injected(self, tmp_path, monkeypatch):
        """手动启动引擎（开发/调试）时不注入令牌，必须保持可用。"""
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("XUANDUN_ADMIN_TOKEN", raising=False)
        import importlib

        from fastapi.testclient import TestClient

        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        from daoti_xuandun_personal.proxy import app as app_mod

        try:
            with TestClient(app_mod.create_app()) as c:
                assert c.get("/api/state").status_code == 200
        finally:
            monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
            importlib.reload(paths)


# ══════════════════════════════════════════════════════════════
# ⑧ 保留策略
# ══════════════════════════════════════════════════════════════


class TestRetention:
    def test_default_is_forever(self):
        from daoti_xuandun_personal.config import StorageConfig

        assert StorageConfig().log_retention_days == 0
        assert StorageConfig().validate() == []

    def test_invalid_days_rejected(self):
        from daoti_xuandun_personal.config import StorageConfig

        assert StorageConfig(log_retention_days=-1).validate()
        assert StorageConfig(log_retention_days=99999).validate()

    def test_purge_respects_setting(self, client, monkeypatch):
        old = _log(client.store, ts=time.time() - 10 * 86400)
        new = _log(client.store, ts=time.time())

        monkeypatch.setattr(
            client.app_mod, "_config",
            SimpleNamespace(storage=SimpleNamespace(log_retention_days=0)),
        )
        assert client.app_mod._purge_logs_by_retention() == 0
        assert client.store.count_logs() == 2

        monkeypatch.setattr(
            client.app_mod, "_config",
            SimpleNamespace(storage=SimpleNamespace(log_retention_days=7)),
        )
        assert client.app_mod._purge_logs_by_retention() == 1
        assert client.store.get_log(old) is None
        assert client.store.get_log(new) is not None


# ══════════════════════════════════════════════════════════════
# ⑨ 版本号一致性门禁必须真的能跑
# ══════════════════════════════════════════════════════════════


def test_version_consistency_gate_passes():
    script = REPO / ".github" / "scripts" / "sync_version.py"
    assert script.exists(), "版本同步脚本缺失"
    r = subprocess.run(
        [sys.executable, str(script), "--check"],
        capture_output=True, text=True, cwd=str(REPO),
    )
    assert r.returncode == 0, f"版本不一致：{r.stderr or r.stdout}"


def test_version_is_not_hardcoded_in_ui():
    """界面不得再内置发布版号（否则每发一版都要记得手改）。"""
    for rel in ("desktop/src/components/Layout.tsx",
                "desktop/src/lib/tauriShim.ts"):
        text = (REPO / rel).read_text(encoding="utf-8")
        assert "0.1.17" not in text and "0.1.18" not in text, (
            f"{rel} 仍硬编码了版本号"
        )

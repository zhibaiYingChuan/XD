# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""凭证来源台账 —— 「这枚 token 是谁放进来的」。

用户诉求
────────────────────────────────────────────────────────────
「我要拿证据去找中转站的麻烦。是他为什么需要这个令牌？
 是我任务的原因所需要的，还是中转站自己偷偷获取的？」

请求里的 token 只可能来自用户这边（手打 / 工具返回 / 历史）；
中转站能动手脚的只有它**返回**的内容。所以判据不是「响应里有没有凭证」，
而是「这枚凭证第一次出现在哪一侧」——台账按 SHA-256 指纹记录首次方向。

本文件锁四件事
────────────────────────────────────────────────────────────
1. 首次出现方向不被后来的出现改写（否则证据方向会反过来）
2. 响应里出现「请求从未发送过」的凭证 → 单独一条发现，措辞是「请核实」
3. 已经出现过的凭证（模型复述）不算新增，不能冤枉中转站
4. 证据包字段完整，且**不含凭证原文**
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.proxy.sanitizer import (  # noqa: E402
    RequestSanitizer,
    credential_fingerprint,
)
from daoti_xuandun_personal.storage.db import PersonalStorage  # noqa: E402
from daoti_xuandun_personal.types import LogEntry  # noqa: E402

TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3QifQ"
    ".c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU"
)


@pytest.fixture()
def storage():
    tmp = tempfile.TemporaryDirectory()
    s = PersonalStorage(Path(tmp.name) / "provenance.db")
    try:
        yield s
    finally:
        s.close()
        tmp.cleanup()


@pytest.fixture()
def app_mod(storage):
    from daoti_xuandun_personal.proxy import app as m

    old_storage, old_sanitizer = m._storage, m._sanitizer
    m._storage = storage
    m._sanitizer = RequestSanitizer(level="balanced")
    try:
        yield m
    finally:
        m._storage, m._sanitizer = old_storage, old_sanitizer


class TestFingerprint:
    def test_same_value_same_fingerprint(self):
        assert credential_fingerprint(TOKEN) == credential_fingerprint(TOKEN)

    def test_different_values_differ(self):
        assert credential_fingerprint(TOKEN) != credential_fingerprint(TOKEN + "x")

    def test_hits_carry_fingerprint_and_masked(self):
        r = RequestSanitizer(level="balanced").sanitize(f"token={TOKEN}")
        assert r.hits, "命中项没有带指纹 —— 台账无法跨轮次对上同一枚凭证"
        hit = r.hits[0]
        assert hit["fingerprint"] == credential_fingerprint(TOKEN)
        assert hit["length"] == len(TOKEN)
        assert TOKEN not in json.dumps(hit), "命中项里出现了凭证原文"
        assert "…" in hit["masked"] or "⟪" in hit["masked"]


class TestLedgerKeepsFirstDirection:
    def test_first_seen_direction_is_request(self, storage):
        fp = credential_fingerprint(TOKEN)
        storage.record_credential_events(
            [{"fingerprint": fp, "direction": "request",
              "role": "工具返回", "category": "jwt",
              "masked": "eyJ0……", "length": len(TOKEN)}],
            session_id="s1",
        )
        got = storage.get_credential(fp)
        assert got is not None
        assert got["direction"] == "request"
        assert got["role"] == "工具返回"

    def test_later_response_does_not_overwrite_first_seen(self, storage):
        """★★ 后来的出现不能改写首次方向 —— 否则证据会反过来。"""
        fp = credential_fingerprint(TOKEN)
        storage.record_credential_events(
            [{"fingerprint": fp, "direction": "request",
              "role": "用户提问", "category": "jwt", "length": len(TOKEN)}],
            session_id="s1",
        )
        storage.record_credential_events(
            [{"fingerprint": fp, "direction": "response",
              "role": "模型回复", "category": "jwt", "length": len(TOKEN)}],
            session_id="s1",
        )
        assert storage.get_credential(fp)["direction"] == "request"


class TestResponseSideDetection:
    def test_new_token_in_response_is_flagged(self, app_mod, storage):
        findings = app_mod._check_response_credentials(
            f"这是你需要的内容：{TOKEN}", session_id="s1")
        assert findings, "响应里出现了请求从未有过的凭证，却没有留下记录"
        f = findings[0]
        assert f.category == "credential_from_response"
        assert f.fingerprint == credential_fingerprint(TOKEN)
        assert "从未发送" in f.detail
        # 台账方向必须是 response —— 这是对质的依据
        rec = storage.get_credential(credential_fingerprint(TOKEN))
        assert rec["direction"] == "response"
        assert rec["role"] == "模型回复"

    def test_echo_of_request_token_is_not_flagged(self, app_mod, storage):
        """已经在你这边出现过的凭证，模型复述不算中转站新增。"""
        fp = credential_fingerprint(TOKEN)
        storage.record_credential_events(
            [{"fingerprint": fp, "direction": "request",
              "role": "用户提问", "category": "jwt", "length": len(TOKEN)}],
            session_id="s1",
        )
        findings = app_mod._check_response_credentials(
            f"你刚才发的是 {TOKEN}", session_id="s1")
        assert findings == [], "把用户自己发过的 token 当成了中转站新增 —— 会冤枉对方"

    def test_duplicate_occurrences_merge(self, app_mod):
        findings = app_mod._check_response_credentials(
            f"{TOKEN} …… {TOKEN}", session_id="s1")
        assert len(findings) == 1, "同一枚凭证在一段响应里出现了两次，被记成了两条"

    def test_no_credential_no_finding(self, app_mod):
        assert app_mod._check_response_credentials("今天天气不错", session_id="s1") == []

    def test_detection_is_observation_only(self):
        """响应侧新增凭证只提示，不阻断 —— 模型可能自己编示例 token。"""
        from daoti_xuandun_personal.proxy.verifier import OBSERVATION_ONLY_SIGNALS

        assert "credential_from_response" in OBSERVATION_ONLY_SIGNALS


class TestBlockEvidenceCarriesFingerprint:
    def test_block_detail_has_fingerprint(self, app_mod):
        r = RequestSanitizer(level="balanced").sanitize(TOKEN)
        detail = app_mod._block_evidence(
            r.hit_categories, r.records, "用户提问", r.hits)
        assert any(item.get("fingerprint") for item in detail), (
            "阻断依据里没有指纹 —— 证据包无法回查台账"
        )


class TestEvidenceBundle:
    def _make_log(self, storage, detail, action="block") -> int:
        entry = LogEntry(
            log_type="request_sanitize", relay_domain="api.example.invalid",
            action=action, severity="high", model="m",
            finding_count=1, summary="测试",
            detail_json=json.dumps(detail, ensure_ascii=False),
            text_preview="已打码",
        )
        return storage.insert_log(entry)

    def test_bundle_has_verdict_and_origin(self, app_mod, storage):
        fp = credential_fingerprint(TOKEN)
        storage.record_credential_events(
            [{"fingerprint": fp, "direction": "response",
              "role": "模型回复", "category": "jwt",
              "masked": "eyJ0…kI", "length": len(TOKEN)}],
            session_id="s1",
        )
        log_id = self._make_log(storage, [{
            "category": "jwt", "severity": "high",
            "detail": "第 1 处 · JWT 令牌", "evidence": "eyJ0…kI",
            "fingerprint": fp,
        }])

        app = app_mod.create_app()
        endpoint = next(
            r.endpoint for r in app.routes
            if getattr(r, "path", "") == "/api/logs/{log_id}/evidence"
        )
        import asyncio

        bundle = asyncio.run(endpoint(log_id))

        assert bundle["schema"] == "xuandun.evidence.v1"
        assert bundle["verdict"]["code"] == "response_side"
        assert bundle["hits"][0]["first_seen"]["direction"] == "response"
        assert bundle["hits"][0]["first_seen"]["role"] == "模型回复"
        assert bundle["hits"][0]["fingerprint"] == fp
        # 证据里绝不能出现凭证原文
        assert TOKEN not in json.dumps(bundle, ensure_ascii=False)

    def test_request_side_verdict(self, app_mod, storage):
        fp = credential_fingerprint(TOKEN)
        storage.record_credential_events(
            [{"fingerprint": fp, "direction": "request",
              "role": "工具返回", "category": "jwt",
              "masked": "eyJ0…kI", "length": len(TOKEN)}],
            session_id="s1",
        )
        log_id = self._make_log(storage, [{
            "category": "jwt", "severity": "high",
            "detail": "第 1 处 · JWT 令牌", "evidence": "eyJ0…kI",
            "fingerprint": fp,
        }])
        app = app_mod.create_app()
        endpoint = next(
            r.endpoint for r in app.routes
            if getattr(r, "path", "") == "/api/logs/{log_id}/evidence"
        )
        import asyncio

        bundle = asyncio.run(endpoint(log_id))
        assert bundle["verdict"]["code"] == "request_side"
        assert "工具返回" in json.dumps(bundle, ensure_ascii=False)

    def test_missing_log_is_404(self, app_mod):
        from fastapi import HTTPException

        app = app_mod.create_app()
        endpoint = next(
            r.endpoint for r in app.routes
            if getattr(r, "path", "") == "/api/logs/{log_id}/evidence"
        )
        import asyncio

        with pytest.raises(HTTPException) as e:
            asyncio.run(endpoint(999999))
        assert e.value.status_code == 404

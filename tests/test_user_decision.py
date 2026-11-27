# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""高危拦截的人工裁决 —— 「给用户一次选择」的回归测试（★ 2026-11-28）。

用户的原话是：「那应该其实给用户一次选择的机会啊，点通过或者是拦截。
如果希望他执行的话，肯定是要点击通过的呀，不能啪的就掉了。」

这里锁住四件事：
  ① 只对高危阻断询问；「始终允许」写允许表后同判据不再询问；
  ② 无人值守（桌面端没在轮询）时 0 等待直接拦截，CLI 不白等 45 秒；
  ③ 等待用 asyncio.sleep 轮询，不阻塞事件循环；
  ④ 允许表可查、可撤销，指纹稳定且不会把不同判据压成同一个。
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
# ★ 与 conftest 同一策略：无条件把 personal\src 置顶，避免 import 到旧副本
if str(ROOT / "src") in sys.path:
    sys.path.remove(str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.storage.db import PersonalStorage  # noqa: E402
from daoti_xuandun_personal.types import VerificationFinding  # noqa: E402


def _finding(
    severity: str = "high",
    signal: str = "dangerous_command",
    evidence: str = "rm -rf /",
    category: str = "tool_call_dangerous",
) -> VerificationFinding:
    return VerificationFinding(
        category=category,
        severity=severity,
        detail="工具调用包含危险命令",
        evidence=evidence,
        signal=signal,
    )


@pytest.fixture
def storage(tmp_path):
    return PersonalStorage(db_path=tmp_path / "decision.db")


@pytest.fixture(autouse=True)
def _clean_pending():
    """每个用例前后都清空内存队列，避免用例之间互相影响。"""
    with app_mod._pending_lock:
        app_mod._pending_items.clear()
    yield
    with app_mod._pending_lock:
        app_mod._pending_items.clear()
    # ★ 心跳也要复位：否则后续用例会误判「桌面端在场」，
    #   高危阻断会白等 45 秒（实测整包跑到这里会明显变慢）。
    app_mod._pending_last_poll = 0.0


# ══════════════════════════════════════════════════════════════
# 允许表（存储层）
# ══════════════════════════════════════════════════════════════


def test_decision_allowance_crud(storage):
    assert storage.is_decision_allowed("") is False
    assert storage.is_decision_allowed("nope") is False

    storage.add_decision_allowance("abc123", "工具调用包含危险命令")
    assert storage.is_decision_allowed("abc123") is True

    # 同指纹重复写入只累加次数，不产生第二行
    storage.add_decision_allowance("abc123", "工具调用包含危险命令")
    rows = storage.list_decision_allowances()
    assert len(rows) == 1
    assert rows[0]["fingerprint"] == "abc123"
    assert rows[0]["seen_count"] == 2

    assert storage.remove_decision_allowance("abc123") is True
    assert storage.is_decision_allowed("abc123") is False
    assert storage.remove_decision_allowance("abc123") is False


# ══════════════════════════════════════════════════════════════
# 指纹：稳定、具体、只取高危
# ══════════════════════════════════════════════════════════════


def test_fingerprint_is_order_independent_and_specific():
    a = _finding(signal="sig_a", evidence="ev_a")
    b = _finding(signal="sig_b", evidence="ev_b")

    assert app_mod._decision_fingerprint([a, b]) == app_mod._decision_fingerprint([b, a])
    assert app_mod._decision_fingerprint([a, b]) != app_mod._decision_fingerprint([a])
    # 同一 signal、不同 evidence 必须区分开
    assert app_mod._decision_fingerprint([a]) != app_mod._decision_fingerprint(
        [_finding(signal="sig_a", evidence="ev_c")]
    )
    # 非高危不参与指纹
    assert app_mod._decision_fingerprint([_finding(severity="medium")]) == ""


# ══════════════════════════════════════════════════════════════
# _await_user_decision
# ══════════════════════════════════════════════════════════════


def _run(coro):
    return asyncio.run(coro)


async def _await_with_decision(decision: str, timeout: float = 3.0):
    """启动等待 → 等队列出现 → 模拟桌面端裁决 → 返回等待结果。"""
    task = asyncio.create_task(
        app_mod._await_user_decision(
            "relay.example", [_finding()], timeout=timeout
        )
    )
    for _ in range(100):
        await asyncio.sleep(0.02)
        if app_mod._pending_snapshot():
            break
    items = app_mod._pending_snapshot()
    assert items, "待裁决项没有进入队列"
    assert app_mod._pending_decide(items[0]["id"], decision) is True
    return await task


def test_unattended_returns_immediately(storage, monkeypatch):
    """桌面端没在轮询 → 不等待，直接拦截。"""
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", 0.0)

    started = time.monotonic()
    allowed, reason = _run(
        app_mod._await_user_decision("relay.example", [_finding()])
    )
    elapsed = time.monotonic() - started

    assert (allowed, reason) == (False, "unattended")
    assert elapsed < 1.0, "无人值守时不应等待"
    assert app_mod._pending_snapshot() == []


def test_permanent_allowance_skips_prompt(storage, monkeypatch):
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", 0.0)  # 无人值守也不影响

    fp = app_mod._decision_fingerprint([_finding()])
    storage.add_decision_allowance(fp, "工具调用包含危险命令")

    allowed, reason = _run(
        app_mod._await_user_decision("relay.example", [_finding()])
    )
    assert (allowed, reason) == (True, "allowed_permanent")
    assert app_mod._pending_snapshot() == []


def test_allow_once_returns_and_cleans_up(storage, monkeypatch):
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", time.time())

    allowed, reason = _run(_await_with_decision("allow_once"))
    assert (allowed, reason) == (True, "allow_once")
    # 仅本次不写允许表
    assert storage.is_decision_allowed(
        app_mod._decision_fingerprint([_finding()])
    ) is False
    assert app_mod._pending_snapshot() == []


def test_allow_always_writes_allowance(storage, monkeypatch):
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", time.time())

    allowed, reason = _run(_await_with_decision("allow_always"))
    assert (allowed, reason) == (True, "allow_always")
    assert storage.is_decision_allowed(
        app_mod._decision_fingerprint([_finding()])
    ) is True


def test_deny_blocks(storage, monkeypatch):
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", time.time())

    allowed, reason = _run(_await_with_decision("deny"))
    assert (allowed, reason) == (False, "user_denied")
    assert app_mod._pending_snapshot() == []


def test_timeout_blocks_and_cleans_up(storage, monkeypatch):
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", time.time())

    started = time.monotonic()
    allowed, reason = _run(
        app_mod._await_user_decision(
            "relay.example", [_finding()], timeout=0.3
        )
    )
    elapsed = time.monotonic() - started

    assert (allowed, reason) == (False, "timeout")
    assert elapsed >= 0.25
    assert app_mod._pending_snapshot() == []


def test_same_findings_do_not_ask_twice_in_one_stream(storage, monkeypatch):
    """中期验证与最终验证命中同一组判据时，用户只应被问一次。"""
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", 0.0)  # 无人值守

    approved = app_mod._decision_rule_keys([_finding()])

    allowed, reason = _run(
        app_mod._await_user_decision(
            "relay.example", [_finding()], approved=approved
        )
    )
    assert (allowed, reason) == (True, "allowed_this_stream")


def test_new_high_finding_is_not_covered_by_earlier_approval(
    storage, monkeypatch
):
    """独立审查 P0：早期放行 A，不能连带放行后来新出现的 B。"""
    monkeypatch.setattr(app_mod, "_storage", storage)
    monkeypatch.setattr(app_mod, "_pending_last_poll", 0.0)  # 无人值守

    a = _finding(signal="sig_a", evidence="ev_a")
    b = _finding(signal="sig_b", evidence="ev_b")
    approved = app_mod._decision_rule_keys([a])

    # 同一批里只放行过 A：含 B 的批次不能被当成「本次已允许」
    allowed, reason = _run(
        app_mod._await_user_decision(
            "relay.example", [a, b], approved=approved
        )
    )
    assert (allowed, reason) == (False, "unattended")


def test_approved_override_requires_all_high_findings_approved():
    """独立审查 P0：最终记账改 PASS 的前提是「每一条」高危都被放行过。"""
    a = _finding(signal="sig_a", evidence="ev_a")
    b = _finding(signal="sig_b", evidence="ev_b")
    approved = app_mod._decision_rule_keys([a])

    assert app_mod._high_findings_all_approved([a], approved) is True
    assert app_mod._high_findings_all_approved([a, b], approved) is False
    # 没有高危发现时不得凭空判成「全部已放行」
    assert app_mod._high_findings_all_approved(
        [_finding(severity="medium")], approved
    ) is False


def test_unapproved_high_findings_only_returns_undecided_ones():
    """流式最终段：凭证/还原类高危也要进入裁决，不能只看验证器 action。"""
    a = _finding(signal="sig_a", evidence="ev_a")
    b = _finding(signal="sig_b", evidence="ev_b")
    medium = _finding(severity="medium", signal="sig_m", evidence="ev_m")
    approved = app_mod._decision_rule_keys([a])

    out = app_mod._unapproved_high_findings([a, b, medium], approved)
    assert out == [b]


# ══════════════════════════════════════════════════════════════
# HTTP 端点
# ══════════════════════════════════════════════════════════════


def test_pending_endpoints_contract():
    from fastapi.testclient import TestClient

    with TestClient(app_mod.create_app()) as c:
        # 轮询：空队列
        r = c.get("/api/pending")
        assert r.status_code == 200
        assert r.json() == {"items": []}
        # 轮询会刷新「有人值守」心跳
        assert app_mod._pending_last_poll > 0

        # 非法裁决
        r = c.post("/api/pending/not-exist/decide", json={"decision": "maybe"})
        assert r.status_code == 400

        # 不存在的项
        r = c.post("/api/pending/not-exist/decide", json={"decision": "deny"})
        assert r.status_code == 404

        # 允许表：初始为空
        r = c.get("/api/decision-allowances")
        assert r.status_code == 200
        assert r.json() == {"items": []}

        # 撤销不存在的记录
        r = c.post(
            "/api/decision-allowances/remove",
            json={"fingerprint": "not-exist"},
        )
        assert r.status_code == 404


def test_pending_queue_visible_and_decidable_via_http():
    """端到端：等待中的项出现在 /api/pending，裁决后等待方拿到结果。"""
    from fastapi.testclient import TestClient

    with TestClient(app_mod.create_app()) as c:
        # 先声明「有人值守」，否则等待方会按无人值守直接拦截
        app_mod._pending_last_poll = time.time()

        # TestClient 的 portal 与 asyncio.run 不在同一循环：
        # 这里改为「后台线程跑等待」，HTTP 侧只看队列与裁决接口。
        import threading

        result = {}

        def waiter():
            # ★ 不能复用 _await_with_decision：它会自己裁决，
            #   这里必须让 HTTP 侧（模拟桌面端）来完成裁决。
            result["value"] = asyncio.run(
                app_mod._await_user_decision(
                    "relay.example", [_finding()], timeout=3.0
                )
            )

        t = threading.Thread(target=waiter)
        t.start()
        try:
            deadline = time.time() + 2.0
            items = []
            while time.time() < deadline:
                r = c.get("/api/pending")
                assert r.status_code == 200
                items = r.json()["items"]
                if items:
                    break
                time.sleep(0.02)
            assert items, "等待中的项没有出现在 /api/pending"
            item = items[0]
            assert item["summary"]
            assert item["domain"] == "relay.example"
            r = c.post(
                f"/api/pending/{item['id']}/decide",
                json={"decision": "allow_once"},
            )
            assert r.status_code == 200
            assert r.json()["ok"] is True
        finally:
            t.join(timeout=5)

        assert result["value"] == (True, "allow_once")


# ══════════════════════════════════════════════════════════════
# 真实端点：高危响应 → 用户放行 → 内容真的返回（★ 核心诉求）
# ══════════════════════════════════════════════════════════════

_URL = "https://relay.example.com/v1"
_KEY = "sk-test-key-123456"


class _Resp:
    status_code = 200
    headers = {"content-type": "application/json"}

    def __init__(self, body: bytes):
        self._body = body

    async def aread(self):
        return self._body

    async def aclose(self):
        pass


class _Client:
    def __init__(self, resp):
        self._resp = resp

    def build_request(self, method, url, json=None, headers=None):
        return {}

    async def send(self, request, stream=False):
        return self._resp


class _Relay:
    base_url = _URL
    api_key = _KEY

    def all_relays(self):
        return [{
            "base_url": _URL, "api_key": _KEY, "name": "t", "id": "a",
            "enabled": True,
        }]

    def relay_by_key(self, key):
        return None


class _Cfg:
    relay = _Relay()

    class guard:
        enable_request_sanitize = False
        enable_response_verify = True
        enable_pattern_check = False
        security_level = "balanced"


class _BlockingVerifier:
    def __init__(self, findings):
        self._findings = findings

    def verify(self, *args, **kwargs):
        from types import SimpleNamespace

        return SimpleNamespace(
            action="block", severity="high", findings=self._findings,
        )


def _endpoint(application, path: str, method: str = "POST"):
    for r in application.routes:
        if getattr(r, "path", "") == path and method in (
            getattr(r, "methods", None) or set()
        ):
            return r.endpoint
    raise AssertionError(f"未找到路由 {method} {path}")


def _run_high_block(tmp_path, monkeypatch, decide: str):
    """跑真实 /v1/chat/completions：高危 → 等裁决 → 按裁决收尾。

    返回 (响应, storage)。调用方在另一个线程里等 pending 项并裁决。
    """
    import threading
    from starlette.requests import Request

    from daoti_xuandun_personal import license as lic_mod
    from daoti_xuandun_personal.proxy import app as app_mod2
    from daoti_xuandun_personal.storage.db import PersonalStorage

    monkeypatch.setattr(lic_mod, "load_public_key", lambda: None)
    app_mod2._protection_cache.clear()
    monkeypatch.setattr(app_mod2, "_pending_last_poll", time.time())

    store = PersonalStorage(db_path=tmp_path / "block.db")
    body = json.dumps({
        "id": "x", "object": "chat.completion", "model": "m",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hello"},
            "finish_reason": "stop",
        }],
    }).encode("utf-8")
    resp = _Resp(body)

    monkeypatch.setattr(app_mod2, "_config", _Cfg())
    monkeypatch.setattr(app_mod2, "_http_client", _Client(resp))
    monkeypatch.setattr(app_mod2, "_storage", store)
    monkeypatch.setattr(app_mod2, "_reputation", app_mod2.ReputationTracker())
    monkeypatch.setattr(app_mod2, "_paused_until", 0.0)
    monkeypatch.setattr(
        app_mod2, "_verifier", _BlockingVerifier([_finding()])
    )
    monkeypatch.setattr(app_mod2, "_sanitizer", None)
    monkeypatch.setattr(app_mod2, "_restorer", None)

    req_body = json.dumps({
        "model": "m", "stream": False,
        "messages": [{"role": "user", "content": "hi"}],
    }).encode("utf-8")
    scope = {
        "type": "http", "method": "POST", "path": "/v1/chat/completions",
        "headers": [], "query_string": b"", "client": ("127.0.0.1", 40000),
    }

    async def _receive():
        return {"type": "http.request", "body": req_body, "more_body": False}

    out = {}

    def call_endpoint():
        loop = asyncio.new_event_loop()
        try:
            application = app_mod2.create_app()
            ep = _endpoint(application, "/v1/chat/completions")
            out["resp"] = loop.run_until_complete(
                ep(Request(scope, _receive))
            )
        finally:
            loop.close()

    t = threading.Thread(target=call_endpoint)
    t.start()
    try:
        deadline = time.time() + 3.0
        item = None
        while time.time() < deadline:
            items = app_mod2._pending_snapshot()
            if items:
                item = items[0]
                break
            time.sleep(0.02)
        assert item is not None, "高危拦截没有进入待裁决队列（用户根本没机会选择）"
        assert item["findings"], "弹窗里没有可展示的命中依据"
        assert app_mod2._pending_decide(item["id"], decide) is True
    finally:
        t.join(timeout=5)

    assert "resp" in out, "请求没有结束"
    return out["resp"], store


def test_high_block_allow_returns_content(tmp_path, monkeypatch):
    """用户点「仅本次允许」→ 原请求拿到内容，日志记 pass 并留痕。"""
    resp, store = _run_high_block(tmp_path, monkeypatch, "allow_once")

    assert resp.status_code == 200, (
        f"用户已允许，却仍返回 {resp.status_code} —— 内容被吞掉了"
    )
    assert b"hello" in resp.body
    rows = store.query_logs(limit=5)
    assert rows and rows[0].action == "pass", (
        f"用户放行后日志记为 {rows[0].action!r}，账本与用户裁决不一致"
    )
    assert "user_approved" in (rows[0].detail_json or ""), (
        "日志里看不出这条高危是用户自己放过的"
    )


def test_high_block_deny_keeps_blocking(tmp_path, monkeypatch):
    """用户点「拦截这次」→ 维持原阻断（502 + 可读原因）。"""
    resp, store = _run_high_block(tmp_path, monkeypatch, "deny")

    assert resp.status_code == 502
    assert b"relay_response_blocked" in resp.body
    rows = store.query_logs(limit=5)
    assert rows and rows[0].action == "block"

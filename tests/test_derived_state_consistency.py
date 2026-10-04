# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""派生数据一致性 —— 契约测试。

★ 为什么单独一个文件（2026-10-04）
────────────────────────────────────────────────────────────────
用户反馈「这个问题一直在不断出现」：界面上的数字互相矛盾。
三轮修复后做了一次全角度审查，发现三个 Critical 有**同一个特征**：

    **函数本身是对的，错在调用点。**

  · `_resolve_action` 的 low 档逻辑正确，但非流式调用点传的是
    `VerifyResult` 对象（dataclass，无 __bool__，**恒为真值**）——
    于是「零发现」的干净响应也被记成「已告警」，
    每次非流式正常回答都进「今日提示」，KPI 的「安全」恒为 0。
    而流式调用点传的是 None，同一个函数两条路径语义相反。

  · `record_call` 支持 api_key 参数、能算出带指纹的键，
    但生产调用点把**已算好的键**再拼回 `https://{键}` 传进去 ——
    `#` 被 urlparse 当成 fragment 丢掉，指纹消失，
    计数写进裸域名那行，而界面读的是带指纹那行。

  · `update_config` 的掩码守卫会抛错，但它被写在 `setattr` **之后** ——
    抛 400 时磁盘没事、**内存已经污染**，之后切到那家中转站必然 401。

三处的旧测试都只调函数、不调调用点，所以全绿。
本文件刻意都走**真实入口**（HTTP 端点 / 真实配置对象）来判。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.reputation.tracker import (  # noqa: E402
    ReputationTracker,
)
from daoti_xuandun_personal.storage.db import PersonalStorage  # noqa: E402
from daoti_xuandun_personal.types import (  # noqa: E402
    Action,
    LogEntry,
    LogType,
    RelayReputation,
)

KEY_A = "sk-aaaa-1111"
KEY_B = "sk-bbbb-2222"
URL = "https://api.commandcode.ai/provider/v1/chat/completions"


class TestRelayKeySurvivesRoundTrip:
    """★★ 信誉键在写回时必须保住指纹（C2）。

    生产调用点曾把已算好的键再拼回 URL 传进来，而 `#` 是 fragment 分隔符：
        urlparse("https://api.x.com#abc12345").netloc == "api.x.com"
    """

    def test_record_call_with_relay_key_keeps_fingerprint(self):
        t = ReputationTracker()
        key = ReputationTracker.reputation_key(URL, KEY_A)
        assert "#" in key, "前提：键应带指纹"

        rep = t.record_call(URL, Action.PASS.value, 100.0, "",
                            relay_key=key)

        assert rep.domain == key, (
            f"写回后 domain 变成 {rep.domain!r}，指纹被 URL 解析吃掉了 —— "
            "计数会落到裸域名那行，而界面读的是带指纹那行"
        )
        assert rep.total_calls == 1

    def test_two_accounts_stay_separate_through_record(self):
        """同一地址两把 Key，各自记账（端到端）。"""
        t = ReputationTracker()
        ka = ReputationTracker.reputation_key(URL, KEY_A)
        kb = ReputationTracker.reputation_key(URL, KEY_B)

        t.record_call(URL, Action.PASS.value, 1.0, "", relay_key=ka)
        t.record_call(URL, Action.PASS.value, 1.0, "", relay_key=ka)
        t.record_call(URL, Action.BLOCK.value, 1.0, "",
                      categories=["tool_call_dangerous"], relay_key=kb)

        reps = {r.domain: r for r in t.list_all()}
        assert len(reps) == 2, f"应记成两家，实际 {sorted(reps)}"
        assert reps[ka].total_calls == 2 and reps[ka].relay_danger_count == 0
        assert reps[kb].total_calls == 1 and reps[kb].relay_danger_count == 1


class TestDerivedStateAlignsOnStartup:
    """★★ 启动时把派生数据对齐到 logs（旧脏数据自愈）。

    用户实测：日志一条都没有，中转站卡片还扣着 30 分 ——
    那次清空是旧版本做的，新版本不会自愈。
    """

    @pytest.fixture()
    def store(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        import importlib

        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        from daoti_xuandun_personal.storage import db as db_mod
        importlib.reload(db_mod)
        yield db_mod.PersonalStorage(db_path=tmp_path / "align.db")
        monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
        importlib.reload(paths)

    def _run_align(self, store, relays):
        class _Relay:
            base_url = relays[0]["base_url"]
            api_key = relays[0]["api_key"]

            def all_relays(self):
                return [dict(r) for r in relays]

        class _Cfg:
            relay = _Relay()

        old = (app_mod._storage, app_mod._config, app_mod._reputation)
        app_mod._storage = store
        app_mod._config = _Cfg()
        app_mod._reputation = ReputationTracker()
        for rep in store.load_reputations():
            app_mod._reputation.import_reputation(rep)
        try:
            app_mod._align_derived_state()
        finally:
            app_mod._storage, app_mod._config, app_mod._reputation = old

    def test_stale_evidence_clears_when_logs_are_empty(self, store):
        """★ 日志空 + 残留水印 → 启动对齐后分数回满分。"""
        key = ReputationTracker.reputation_key(URL, KEY_A)
        store.upsert_reputation(RelayReputation(
            domain=key, score=70, total_calls=16,
            watermark_detected=True,
            notes=["检测到数据保留迹象：中转服务标识"],
            first_seen=time.time(),
        ))
        assert store.load_reputations()[0].score == 70

        self._run_align(store, [{"base_url": URL, "api_key": KEY_A}])

        after = store.load_reputations()[0]
        assert after.watermark_detected is False, (
            "日志已空，水印扣分却还在 —— 用户看到「没有记录却扣着分」"
        )
        assert after.score == 100, f"分数仍是 {after.score}"
        assert after.total_calls == 0

    def test_orphan_row_is_removed(self, store):
        """★ 既不在配置、也无日志引用的残留行必须清掉。

        典型来源：信誉键从「纯主机」升级为「主机#指纹」时的遗留。
        留着会在设置页出现一行 0 次调用的陌生记录。
        """
        key = ReputationTracker.reputation_key(URL, KEY_A)
        store.upsert_reputation(RelayReputation(domain=key))
        store.upsert_reputation(RelayReputation(domain="api.commandcode.ai"))

        self._run_align(store, [{"base_url": URL, "api_key": KEY_A}])

        domains = [r.domain for r in store.load_reputations()]
        assert "api.commandcode.ai" not in domains, (
            f"无来源的残留行没被清掉：{domains}"
        )
        assert key in domains, "有来源的行不能误删"

    def test_configured_relay_is_never_deleted(self, store):
        """配置里存在的键，即使零调用也必须保留。

        ★ 否则「刚配好还没发过对话」会被当成孤儿删掉，
          用户看到配置莫名消失。
        """
        key = ReputationTracker.reputation_key(URL, KEY_A)
        store.upsert_reputation(RelayReputation(domain=key))

        self._run_align(store, [{"base_url": URL, "api_key": KEY_A}])

        assert [r.domain for r in store.load_reputations()] == [key]


class TestNonStreamCleanResponseIsPass:
    """★★ 非流式的干净响应必须记成 pass（C1）。

    ★ 为什么走真实端点：
      缺陷形态是「函数对、调用点错」—— 非流式传 VerifyResult 对象
      （恒真值），流式传 None，同一个函数两条路径语义相反。
      只测 `_resolve_action` 的话两边都是绿的。
    """

    def test_clean_response_records_pass_not_alert(self, tmp_path):
        import asyncio

        from starlette.requests import Request

        store = PersonalStorage(db_path=tmp_path / "ns.db")

        class _FakeResp:
            status_code = 200
            headers = {"content-type": "application/json"}

            def __init__(self):
                # ★ H1 改造后：上游响应以 stream=True 取得，处理器按字节读全量，
                #   不再调用 resp.json()。故假响应提供 aread()/aclose()。
                self._body = json.dumps({
                    "model": "m",
                    "choices": [{"message": {"content": "你好，有什么可以帮你？"}}],
                }).encode("utf-8")

            async def aread(self):
                return self._body

            async def aclose(self):
                return None

        class _FakeClient:
            def build_request(self, method, url, json=None, headers=None):
                return {"method": method, "url": url, "json": json, "headers": headers}

            async def send(self, request, stream=False):
                return _FakeResp()

        class _Relay:
            base_url = URL
            api_key = KEY_A

            def all_relays(self):
                return [{
                    "base_url": URL, "api_key": KEY_A, "name": "test",
                    "id": "a", "enabled": True,
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

        scope = {
            "type": "http", "method": "POST",
            "path": "/v1/chat/completions", "headers": [],
            "query_string": b"",
        }

        async def _receive():
            return {
                "type": "http.request",
                "body": b'{"model":"m","messages":[{"role":"user","content":"hi"}]}',
                "more_body": False,
            }

        old = (app_mod._config, app_mod._http_client, app_mod._storage,
               app_mod._reputation, app_mod._paused_until, app_mod._verifier)
        app_mod._config = _Cfg()
        app_mod._http_client = _FakeClient()
        app_mod._storage = store
        app_mod._reputation = ReputationTracker()
        app_mod._paused_until = 0.0          # 不暂停，走完整链路
        try:
            application = app_mod.create_app()
            endpoint = next(
                r.endpoint for r in application.routes
                if getattr(r, "path", "") == "/v1/chat/completions"
            )
            asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
                endpoint(Request(scope, _receive))
            )
        finally:
            (app_mod._config, app_mod._http_client, app_mod._storage,
             app_mod._reputation, app_mod._paused_until,
             app_mod._verifier) = old

        rows = store.query_logs(limit=5)
        assert rows, "干净响应没有写日志 —— 无法判断处置"
        entry = rows[0]
        assert entry.action == Action.PASS.value, (
            f"干净响应被记成 {entry.action!r} —— "
            "非流式路径把 VerifyResult 对象当成了「有发现」（恒真值），"
            "于是每次正常回答都进「今日提示」，KPI 的「安全」恒为 0"
        )
        assert store.get_today_stats()["safe_count"] == 1

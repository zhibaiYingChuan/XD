# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""上游协议适配 + 损坏自愈 —— 契约测试（H1–H5 / M1–M4）。

★ 为什么单独一个文件（2026-10-04）
────────────────────────────────────────────────────────────────
一次全角度审查发现：**六个高危问题的根因是同一个** ——
「上游响应（状态码 + 形态）」从未被当作一等输入去分类处理：

  · H1 转发用 `post()` 全量缓冲 → 「流式」其实等整段响应
  · H2 Anthropic SSE 无 `choices` → 第一个 continue 就跳过，
       流式内容完全绕过检测
  · H3 上游非 JSON → `upstream.json()` 抛异常 → 莫名其妙的 500
  · H4 上游 4xx/5xx → 被当成「检测通过」计入 KPI 与信誉
  · H5 缺省 session_id="default" → 多客户端共用会话，占位符串号

  · M1 桌面端 get_stats 硬编码 days=7
  · M2 配置损坏 → 静默回退默认，且不可逆
  · M3 数据库损坏 → 引擎整体起不来
  · M4 check_same_thread=False 却无锁

判据一律落在**真实调用点**：SSE 解析走真实函数、上游错误走真实端点、
配置/数据库损坏走真实 load()/构造。静态源码判据仅用于无法在 Python 内
执行的 Rust/TS 接线（M1）。
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.config import PersonalConfig  # noqa: E402
from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.reputation.tracker import ReputationTracker  # noqa: E402
from daoti_xuandun_personal.storage import db as db_mod  # noqa: E402
from daoti_xuandun_personal.types import Action  # noqa: E402

# ★ 注意：本套件里另有测试会 `importlib.reload(db_mod)` / `reload(config)`，
#   那会产生**全新的类对象**。因此凡涉及 isinstance / 构造，一律走
#   `db_mod.PersonalStorage` 这样的**模块属性实时查找**，
#   绝不在导入期把类对象固定下来 —— 否则会拿到 reload 前的旧类而误判。

APP_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py"
LIB_RS = ROOT / "desktop" / "src-tauri" / "src" / "lib.rs"
API_TS = ROOT / "desktop" / "src" / "services" / "api.ts"

URL = "https://relay.example.com/v1"
KEY = "sk-test-key-123456"


# ══════════════════════════════════════════════════════════════
# H2：SSE 双协议解析（Anthropic + OpenAI）
# ══════════════════════════════════════════════════════════════


class TestSseProtocols:
    """`_extract_sse_frames` 必须同时吃 OpenAI 与 Anthropic 两种流。"""

    def test_anthropic_text_deltas_are_collected(self):
        sse = (
            'event: message_start\n'
            'data: {"type":"message_start","message":{"model":"claude-3-5","id":"m1"}}\n\n'
            'event: content_block_start\n'
            'data: {"type":"content_block_start","index":0,'
            '"content_block":{"type":"text","text":""}}\n\n'
            'event: content_block_delta\n'
            'data: {"type":"content_block_delta","index":0,'
            '"delta":{"type":"text_delta","text":"你好"}}\n\n'
            'event: content_block_delta\n'
            'data: {"type":"content_block_delta","index":0,'
            '"delta":{"type":"text_delta","text":"世界"}}\n\n'
            'event: message_stop\ndata: {"type":"message_stop"}\n\n'
        )
        text, tools, model = app_mod._extract_sse_frames(sse)
        assert text == "你好世界", (
            f"Anthropic 流式文本未提取（得到 {text!r}）—— "
            "无 choices 事件被第一个 continue 跳过，流式内容完全绕过检测"
        )
        assert model == "claude-3-5", "未从 message_start 取到模型名"
        assert tools == []

    def test_anthropic_tool_use_is_merged(self):
        sse = (
            'data: {"type":"content_block_start","index":0,'
            '"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather"}}\n\n'
            'data: {"type":"content_block_delta","index":0,'
            '"delta":{"type":"input_json_delta","partial_json":"{\\"city\\":"}}\n\n'
            'data: {"type":"content_block_delta","index":0,'
            '"delta":{"type":"input_json_delta","partial_json":"\\"北京\\"}"}}\n\n'
            'data: {"type":"content_block_stop","index":0}\n\n'
        )
        _text, tools, _model = app_mod._extract_sse_frames(sse)
        assert tools, "Anthropic tool_use 未被归并 —— 工具类检测在流式下失效"
        assert tools[0]["function"]["name"] == "get_weather"
        assert tools[0]["function"]["arguments"] == {"city": "北京"}

    def test_openai_stream_still_works(self):
        """反向自证：修 Anthropic 不能把 OpenAI 分支改坏。"""
        sse = (
            'data: {"model":"gpt-4o","choices":[{"delta":{"content":"hi"}}]}\n\n'
            'data: {"model":"gpt-4o","choices":[{"delta":{"content":"!"}}]}\n\n'
            'data: [DONE]\n\n'
        )
        text, _tools, model = app_mod._extract_sse_frames(sse)
        assert text == "hi!"
        assert model == "gpt-4o"


# ══════════════════════════════════════════════════════════════
# H5：会话标识隔离
# ══════════════════════════════════════════════════════════════


def _request_with_headers(headers):
    from starlette.requests import Request

    scope = {
        "type": "http", "method": "POST",
        "path": "/v1/chat/completions",
        "headers": headers, "query_string": b"",
        "client": ("127.0.0.1", 54321),
    }

    async def _receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    return Request(scope, _receive)


class TestSessionIdentity:
    def test_explicit_header_wins(self):
        req = _request_with_headers([
            (b"x-session-id", b"my-session"),
            (b"authorization", b"Bearer A"),
        ])
        assert app_mod._derive_session_id(req) == "my-session"

    def test_different_keys_yield_different_sessions(self):
        a = _request_with_headers([(b"authorization", b"Bearer A")])
        b = _request_with_headers([(b"authorization", b"Bearer B")])
        sid_a = app_mod._derive_session_id(a)
        sid_b = app_mod._derive_session_id(b)
        assert sid_a != sid_b, (
            "两个不同 Key 的客户端拿到同一个会话标识 —— "
            "多客户端会共用基线与占位符映射，脱敏内容可能串号"
        )

    def test_same_client_is_stable(self):
        """反向自证：同一客户端的多次请求必须稳定（基线才能累积）。"""
        h = [(b"authorization", b"Bearer A"), (b"user-agent", b"cursor")]
        assert (
            app_mod._derive_session_id(_request_with_headers(h))
            == app_mod._derive_session_id(_request_with_headers(h))
        )

    def test_never_returns_empty(self):
        req = _request_with_headers([])
        assert app_mod._derive_session_id(req), "会话标识不能为空串"


# ══════════════════════════════════════════════════════════════
# H1 / H3 / H4：走真实 /v1/chat/completions 端点
# ══════════════════════════════════════════════════════════════


class _Resp:
    """假上游响应（支持 stream=True 语义的 aread/aclose）。"""

    def __init__(self, status_code=200, body=b"{}", content_type="application/json"):
        self.status_code = status_code
        self._body = body
        self.headers = {"content-type": content_type}
        self.closed = False

    async def aread(self):
        return self._body

    async def aclose(self):
        self.closed = True


class _Client:
    """假 httpx.AsyncClient：记录是否以 stream=True 发送。"""

    def __init__(self, resp):
        self._resp = resp
        self.saw_stream_true = False
        self.sent_request = None

    def build_request(self, method, url, json=None, headers=None):
        self.sent_request = {
            "method": method, "url": url, "json": json, "headers": headers,
        }
        return self.sent_request

    async def send(self, request, stream=False):
        self.saw_stream_true = stream
        return self._resp


class _Relay:
    base_url = URL
    api_key = KEY

    def all_relays(self):
        return [{
            "base_url": URL, "api_key": KEY, "name": "t", "id": "a",
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


def _run_endpoint(tmp_path, resp, *, paused=False, stream=False, headers=None):
    """把 /v1/chat/completions 端点跑起来，返回 (结果, storage, client)。"""
    import asyncio

    from starlette.requests import Request

    store = db_mod.PersonalStorage(db_path=tmp_path / "up.db")
    rep = ReputationTracker()
    client = _Client(resp)

    old = (app_mod._config, app_mod._http_client, app_mod._storage,
           app_mod._reputation, app_mod._paused_until, app_mod._verifier)
    old_verify = getattr(app_mod, "_verifier", None)
    app_mod._config = _Cfg()
    app_mod._http_client = client
    app_mod._storage = store
    app_mod._reputation = rep
    app_mod._paused_until = (10 ** 12) if paused else 0.0
    # verifier 保持 None：干净响应不应触发任何发现
    app_mod._verifier = None

    body = json.dumps({
        "model": "m", "stream": stream,
        "messages": [{"role": "user", "content": "hi"}],
    }).encode("utf-8")

    scope = {
        "type": "http", "method": "POST",
        "path": "/v1/chat/completions",
        "headers": headers or [], "query_string": b"",
        "client": ("127.0.0.1", 40000),
    }

    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    try:
        application = app_mod.create_app()
        endpoint = next(
            r.endpoint for r in application.routes
            if getattr(r, "path", "") == "/v1/chat/completions"
        )
        result = asyncio.new_event_loop().run_until_complete(
            endpoint(Request(scope, _receive))
        )
    finally:
        (app_mod._config, app_mod._http_client, app_mod._storage,
         app_mod._reputation, app_mod._paused_until,
         app_mod._verifier) = old
        app_mod._verifier = old_verify
    return result, store, rep, client


class TestUpstreamStatusClassification:
    """H4：上游 4xx/5xx 不能被当成「检测通过」。"""

    def test_upstream_500_is_not_counted_as_safe(self, tmp_path):
        resp = _Resp(
            status_code=500,
            body=b'{"error":{"message":"internal"}}',
        )
        result, store, rep, _client = _run_endpoint(tmp_path, resp)

        # 响应必须原样透传上游状态，AI 工具才能正确判断
        assert result.status_code == 500
        assert b"internal" in result.body

        today = store.get_today_stats()
        assert today["safe_count"] == 0, (
            "上游 500 被记成了「安全」—— 首页 KPI 被基础设施抖动刷高"
        )
        assert today["total_calls"] == 0

        rows = store.query_logs(limit=5)
        assert rows, "上游错误必须留一条日志供排查"
        assert rows[0].log_type == "proxy_error", (
            f"上游 500 被记成 {rows[0].log_type!r}，应记为 proxy_error"
        )

        # 一次 500 不代表中转站内容有问题，不该扣它的信誉
        assert all(r.total_calls == 0 for r in rep.list_all())

    def test_upstream_401_is_passed_through(self, tmp_path):
        resp = _Resp(status_code=401, body=b'{"error":"bad key"}')
        result, store, _rep, _client = _run_endpoint(tmp_path, resp)
        assert result.status_code == 401
        assert b"bad key" in result.body
        assert store.get_today_stats()["danger_count"] == 0


class TestNonJsonUpstream:
    """H3：上游返回非 JSON 时不能 500。"""

    def test_passthrough_non_json_does_not_500(self, tmp_path):
        resp = _Resp(
            status_code=200,
            body=b"<html>gateway</html>",
            content_type="text/html",
        )
        result, _store, _rep, _client = _run_endpoint(
            tmp_path, resp, paused=True,
        )
        assert result.status_code == 200, "上游非 JSON 被我们变成了 500"
        assert result.body == b"<html>gateway</html>"
        assert result.media_type == "text/html"


class TestRealStreaming:
    """H1：转发必须以 stream=True 发送（否则「流式」是假的）。"""

    def test_forward_uses_streaming_send(self, tmp_path):
        resp = _Resp(
            status_code=200,
            body=b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n',
        )
        _result, _store, _rep, client = _run_endpoint(
            tmp_path, resp, stream=True,
        )
        assert client.saw_stream_true is True, (
            "转发没有用 stream=True —— 上游响应被全量缓冲，"
            "首字延迟等于整段响应时长，与「流式」完全相反"
        )
        assert client.sent_request and client.sent_request["url"].startswith(
            "https://relay.example.com"
        )


# ══════════════════════════════════════════════════════════════
# M2：配置损坏必须备份
# ══════════════════════════════════════════════════════════════


class TestCorruptConfigBackup:
    def test_corrupt_config_is_backed_up(self, tmp_path, monkeypatch):
        from daoti_xuandun_personal import config as config_mod

        cfg_file = tmp_path / "config.json"
        cfg_file.write_text("{ this is not valid json", encoding="utf-8")
        monkeypatch.setattr(config_mod, "CONFIG_FILE", cfg_file)

        cfg = config_mod.PersonalConfig.load()
        assert isinstance(cfg, config_mod.PersonalConfig), "损坏时仍应返回可用配置"

        backups = list(tmp_path.glob("config.json.corrupt-*"))
        assert backups, (
            "损坏的配置没有被备份 —— 下次保存会用默认值覆盖，"
            "用户的地址与 Key 从此不可恢复"
        )
        assert backups[0].read_text(encoding="utf-8").startswith("{ this is not")


# ══════════════════════════════════════════════════════════════
# M3 / M4：存储自愈与并发安全
# ══════════════════════════════════════════════════════════════


class TestStorageRecoveryAndLock:
    def test_corrupt_db_is_quarantined_and_rebuilt(self, tmp_path):
        db_file = tmp_path / "bad.db"
        db_file.write_bytes(b"NOT A SQLITE FILE " * 64)

        store = db_mod.PersonalStorage(db_path=db_file)   # 不应抛异常
        assert store.get_today_stats()["total_calls"] == 0

        backups = list(tmp_path.glob("bad.db.corrupt-*"))
        assert backups, "损坏的数据库必须被隔离保留，不能直接删除"

    def test_connection_is_lock_wrapped(self, tmp_path):
        store = db_mod.PersonalStorage(db_path=tmp_path / "ok.db")
        assert isinstance(store._conn, db_mod._LockedConn), (
            "连接未被锁包装 —— check_same_thread=False 关掉了 SQLite 的"
            "线程守卫却没有替代保护"
        )

    def test_concurrent_writes_do_not_error(self, tmp_path):
        store = db_mod.PersonalStorage(db_path=tmp_path / "conc.db")
        errors = []

        def worker():
            try:
                for _ in range(25):
                    store.update_daily_stats(total_calls=1, safe=1)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"并发写入报错: {errors}"
        assert store.get_today_stats()["total_calls"] == 100


# ══════════════════════════════════════════════════════════════
# M1：桌面端 days 接线（Rust/TS 无法在 Python 内执行，做结构性判据）
# ══════════════════════════════════════════════════════════════


class TestStatsDaysWiredThrough:
    def test_rust_no_longer_hardcodes_days(self):
        src = LIB_RS.read_text(encoding="utf-8")
        assert '"/api/stats?days=7"' not in src, (
            "Rust get_stats 仍硬编码 days=7 —— 前端传的天数被静默丢弃"
        )
        assert 'p.0.get("days")' in src, "Rust 未从 payload 读取 days"

    def test_frontend_sends_days_in_payload(self):
        src = API_TS.read_text(encoding="utf-8")
        assert "/api/stats?days=${days}" in src
        assert "{ days }" in src, (
            "api.ts getStats 未把 days 放进 payload —— "
            "Tauri 模式走 invoke，Rust 收不到天数"
        )


# ══════════════════════════════════════════════════════════════
# M5：配置校验失败必须回滚运行态
# ══════════════════════════════════════════════════════════════


class TestConfigSaveRollback:
    def test_invalid_save_does_not_pollute_memory(self):
        """校验失败的保存，运行态必须一字未动（磁盘没变、内存也不能变）。"""
        import asyncio

        import pytest
        from fastapi import HTTPException
        from starlette.requests import Request

        cfg = PersonalConfig()
        original_port = cfg.server.port
        original_level = cfg.guard.security_level

        old = app_mod._config
        app_mod._config = cfg
        try:
            application = app_mod.create_app()
            endpoint = next(
                r.endpoint for r in application.routes
                if getattr(r, "path", "") == "/api/config"
                and "PUT" in (getattr(r, "methods", None) or set())
            )

            body = json.dumps({
                "guard": {"security_level": "strict"},
                "server": {"port": 80},          # 非法端口 → validate() 必然报错
            }).encode("utf-8")

            scope = {
                "type": "http", "method": "PUT", "path": "/api/config",
                "headers": [], "query_string": b"",
                "client": ("127.0.0.1", 40001),
            }

            async def _receive():
                return {"type": "http.request", "body": body, "more_body": False}

            with pytest.raises(HTTPException) as ei:
                asyncio.new_event_loop().run_until_complete(
                    endpoint(Request(scope, _receive))
                )
            assert ei.value.status_code == 400

            assert cfg.server.port == original_port, (
                "保存被拒后端口仍被改成了非法值 —— 运行态被污染"
            )
            assert cfg.guard.security_level == original_level, (
                "保存被拒后安全级别仍被改掉 —— 校验失败污染了内存"
            )
        finally:
            app_mod._config = old

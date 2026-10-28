# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""P0 发布阻断项回归（第二轮七智能体审查 2026-10-28）。

十条 P0 的共同特征：**界面上一切正常，底层已经坏了**。
所以这里的判据不看「有没有某段代码」，而是看真实调用点的结果：

  P0-1 引擎身份：/health 必须能证明「对面是玄盾」，桌面端才能把 Key 交出去
  P0-2 就绪语义：/− 存储或检测器缺失时不能再回 ok
  P0-3 建表异常：锁等待/只读盘不得被当成「库损坏」而整库隔离
  P0-4 截断冒充成功：响应体读到一半失败，不能当作 200 空内容通过
  P0-8 流式终止：异常/阻断必须给出可识别的终止事件，不能只断流
  P0-9 多行 data：检测侧必须按 SSE 规范拼接，否则可被拆行绕过
  P0-10 错误体入库：上游 401 回显的 Key 不得明文进 SQLite

P0-5 / P0-6 / P0-7 的缺陷分别在 TypeScript 与 Rust 侧、无法在本
Python 进程内执行，沿用本仓库既有做法做**契约存在性**判据，
并在注释里写明为什么只能这样验。
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.storage import db as db_mod  # noqa: E402


@pytest.fixture(autouse=True)
def _treat_as_activated(monkeypatch):
    """把「授权判定」固定为已授权。

    ★★ 2026-10-28（CI 实测）：本文件的用例测的是流式终止、截断处理、
      引擎身份等**与授权无关**的行为，但它们都要经过
      ``app._protection_enabled()`` 这道门。

      该门的语义是「未激活 / 已过期 → 只读直通」：公钥缺失时按已授权处理，
      公钥在、码不在时按未激活处理。开发机上有 license.json，门是开的，
      用例全绿；干净 runner 上公钥随包分发（发布前置条件）而没有码，
      门是关的 —— 三个用例因此只在 CI 上失败，本地永远复现不出来。

      这里显式把授权判定钉成已授权，让用例只依赖被测逻辑；
      需要验「未激活只读」的用例请自行 monkeypatch 回真实实现。
    """
    from daoti_xuandun_personal import license as lic_mod

    monkeypatch.setattr(lic_mod, "load_public_key", lambda: None)
    app_mod._protection_cache.clear()
    yield
    app_mod._protection_cache.clear()


LIB_RS = ROOT / "desktop" / "src-tauri" / "src" / "lib.rs"
API_TS = ROOT / "desktop" / "src" / "services" / "api.ts"
APP_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py"

URL = "https://relay.example.com/v1"
KEY = "sk-test-key-123456"


# ══════════════════════════════════════════════════════════════
# 公共夹具：假上游 + 真实端点
# ══════════════════════════════════════════════════════════════


class _Resp:
    """假上游响应。"""

    def __init__(self, status_code=200, body=b"{}", content_type="application/json"):
        self.status_code = status_code
        self._body = body
        self.headers = {"content-type": content_type}
        self.closed = False

    async def aread(self):
        return self._body

    async def aclose(self):
        self.closed = True


class _ReadFails(_Resp):
    """读到一半上游断开（P0-4 的真实形态）。"""

    async def aread(self):
        raise httpx.ReadError("peer reset")


class _StreamResp(_Resp):
    """可指定「发若干块后抛异常」的流式响应。"""

    def __init__(self, chunks, fail=False):
        super().__init__(200, b"", "text/event-stream")
        self._chunks = list(chunks)
        self._fail = fail

    async def aiter_bytes(self):
        for c in self._chunks:
            yield c
        if self._fail:
            raise httpx.ReadError("peer reset mid-stream")


class _Client:
    def __init__(self, resp):
        self._resp = resp

    def build_request(self, method, url, json=None, headers=None):
        return {"method": method, "url": url, "json": json, "headers": headers}

    async def send(self, request, stream=False):
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


def _endpoint(application, path, method="POST"):
    for r in application.routes:
        if getattr(r, "path", "") == path and method in (
            getattr(r, "methods", None) or set()
        ):
            return r.endpoint
    raise AssertionError(f"未找到路由 {method} {path}")


def _run(tmp_path, resp, *, stream=False, verifier=None):
    """把 /v1/chat/completions 跑起来。

    ★ stream=True 时**在补丁窗口内**把流读完再返回：
      生成器是惰性执行的，若先恢复模块全局再读，看到的 `_config/_storage`
      已经是测试外的旧值 —— 那样测的就不是真实运行路径。
    返回 (结果 or 完整流字节, storage)。
    """
    from starlette.requests import Request

    store = db_mod.PersonalStorage(db_path=tmp_path / "p0.db")
    client = _Client(resp)

    old = (app_mod._config, app_mod._http_client, app_mod._storage,
           app_mod._reputation, app_mod._paused_until, app_mod._verifier,
           app_mod._sanitizer)
    app_mod._config = _Cfg()
    app_mod._http_client = client
    app_mod._storage = store
    app_mod._reputation = app_mod.ReputationTracker()
    app_mod._paused_until = 0.0
    app_mod._verifier = verifier
    app_mod._sanitizer = None

    body = json.dumps({
        "model": "m", "stream": stream,
        "messages": [{"role": "user", "content": "hi"}],
    }).encode("utf-8")

    scope = {
        "type": "http", "method": "POST", "path": "/v1/chat/completions",
        "headers": [], "query_string": b"", "client": ("127.0.0.1", 40000),
    }

    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    loop = asyncio.new_event_loop()
    try:
        application = app_mod.create_app()
        endpoint = _endpoint(application, "/v1/chat/completions")
        result = loop.run_until_complete(endpoint(Request(scope, _receive)))
        if stream:
            result = loop.run_until_complete(_drain(result))
    finally:
        (app_mod._config, app_mod._http_client, app_mod._storage,
         app_mod._reputation, app_mod._paused_until, app_mod._verifier,
         app_mod._sanitizer) = old
    return result, store


async def _drain(resp):
    out = []
    async for chunk in resp.body_iterator:
        out.append(chunk)
    return b"".join(out)


# ══════════════════════════════════════════════════════════════
# P0-2：/health 的就绪语义
# ══════════════════════════════════════════════════════════════


class TestHealthReadiness:
    def test_health_is_not_ok_when_storage_missing(self):
        """存储缺失时必须明确「未就绪」，不能再回 status=ok。

        ★ 否则桌面端托盘显示「防护运行中」，而检测与落库其实已经失效 ——
          用户以为被保护，实际上一条都没检查、一条都没记。
        """
        old = (app_mod._storage, app_mod._verifier)
        app_mod._storage = None
        app_mod._verifier = None
        try:
            resp = asyncio.new_event_loop().run_until_complete(
                _endpoint(app_mod.create_app(), "/health", "GET")()
            )
        finally:
            app_mod._storage, app_mod._verifier = old

        assert getattr(resp, "status_code", 200) == 503, (
            "/health 在存储与检测器都为 None 时仍返回 200 —— "
            "桌面端会据此认定「引擎就绪」，界面显示防护中"
        )
        body = json.loads(resp.body)
        assert body["ready"] is False
        assert body["storage_ready"] is False
        assert body["guard_ready"] is False

    def test_health_reports_ready_when_components_present(self):
        """反向自证：组件就绪时必须回 200 且 ready=true。"""
        old = (app_mod._storage, app_mod._verifier)
        app_mod._storage = object()
        app_mod._verifier = object()
        try:
            resp = asyncio.new_event_loop().run_until_complete(
                _endpoint(app_mod.create_app(), "/health", "GET")()
            )
        finally:
            app_mod._storage, app_mod._verifier = old

        assert getattr(resp, "status_code", 200) == 200
        body = json.loads(resp.body)
        assert body["ready"] is True

    def test_rust_requires_readiness_not_just_2xx(self):
        """Rust 的就绪判定不能只看 HTTP 2xx。"""
        src = LIB_RS.read_text(encoding="utf-8")
        start = src.index("async fn probe_engine")
        body = src[start:src.index("\n}\n", start)]
        assert "ready" in body, (
            "probe_engine 仍不问引擎「就绪了吗」—— "
            "引擎处于「起来了但检测/落库失效」时会被当成健康"
        )
        assert "instance" in body, "probe_engine 未校验身份"


# ══════════════════════════════════════════════════════════════
# P0-1：引擎身份校验
# ══════════════════════════════════════════════════════════════


class TestEngineIdentity:
    def test_health_exposes_instance_marker(self):
        """引擎必须给出一个「只有知道管理令牌才能算出来」的身份标记。

        ★ 根因：本机任意进程抢在桌面端之前占住 18765 并让 /health 回 2xx，
          桌面端就会把用户的中转站 Key POST 过去、并下发管理令牌。
          只判 2xx 等于把「谁在监听」这个前提交给了对方自证。
        """
        src = APP_PY.read_text(encoding="utf-8")
        assert "instance" in src, "/health 未提供实例身份标记"
        assert "hmac" in src, "身份标记必须由管理令牌派生（HMAC），不能是固定串"

    def test_rust_refuses_foreign_engine(self):
        """Rust 侧必须比对身份，不匹配即拒绝。"""
        src = LIB_RS.read_text(encoding="utf-8")
        assert "instance" in src, "Rust 未校验引擎身份标记"
        assert "不是玄盾引擎" in src or "非本机引擎" in src or "身份" in src, (
            "拒绝外部进程时没有可读的提示"
        )


# ══════════════════════════════════════════════════════════════
# P0-4：截断响应不得冒充成功
# ══════════════════════════════════════════════════════════════


class TestTruncatedResponseIsNotSuccess:
    def test_read_failure_is_not_returned_as_empty_success(self, tmp_path):
        result, store = _run(tmp_path, _ReadFails())

        assert result.status_code == 502, (
            "上游响应体读到一半断开，却仍以 200 + 空内容返回 —— "
            "客户端把半截结果当成完整答案"
        )
        assert b"upstream_read_failed" in result.body

        today = store.get_today_stats()
        assert today["total_calls"] == 0, "读取失败被计成了「已检查」"
        rows = store.query_logs(limit=5)
        assert rows and rows[0].log_type == "proxy_error"


# ══════════════════════════════════════════════════════════════
# P0-8：流式终止事件
# ══════════════════════════════════════════════════════════════


class _FakeFinding:
    category = "test"
    severity = "high"
    detail = "测试用高危发现"

    def to_dict(self):
        return {"category": self.category, "severity": self.severity,
                "detail": self.detail}


class _BlockingVerifier:
    """一律判阻断的假检测器（只为覆盖终止帧，不测检测逻辑）。"""

    def verify(self, *args, **kwargs):
        return SimpleNamespace(
            action="block", severity="high", findings=[_FakeFinding()],
        )


class TestStreamTermination:
    def test_upstream_interruption_emits_terminal_event(self, tmp_path):
        """上游中途断开时，客户端必须能区分「被截断」与「答完了」。"""
        resp = _StreamResp(
            [b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'],
            fail=True,
        )
        result, store = _run(tmp_path, resp, stream=True)
        out = result

        assert b"upstream_stream_interrupted" in out, (
            "上游中途断开后只是断流，客户端会把自己收到的半截内容当成完整答案"
        )
        assert out.rstrip().endswith(b"data: [DONE]"), (
            "流没有以 [DONE] 收尾 —— 严格按 OpenAI 协议等待结束标记的客户端会挂住"
        )
        rows = store.query_logs(limit=5)
        assert rows and rows[0].action != "pass", "中断的响应被记成了「通过」"

    def test_block_ends_with_done_marker(self, tmp_path):
        """阻断后只补**一个**结束标记，且阻断帧必须排在它之前。

        ★★ 2026-10-29（第三轮审查 P0-1）：本用例原来只断言
          「以 [DONE] 结尾」—— 那个断言在「内容先外泄、事后补标记、
          还发两个 [DONE]」的缺陷形态下**也是绿的**，等于给缺陷发了
          合格证。现在把三条真实性质都钉住：
            1. [DONE] 只出现一次（上游的那个已被代理吞掉）；
            2. 阻断帧在 [DONE] 之前（否则严格客户端读不到）；
            3. 内容已交付 ⇒ 记账必须是 alert，不能写 block。
        """
        resp = _StreamResp([
            b'data: {"choices":[{"delta":{"content":"payload"}}]}\n\n',
        ])
        result, store = _run(tmp_path, resp, stream=True,
                              verifier=_BlockingVerifier())
        out = result

        assert b"relay_response_blocked" in out
        assert out.count(b"data: [DONE]") == 1, (
            "结束标记发了不止一次 —— 客户端会看到两个 [DONE]"
        )
        assert out.rfind(b"relay_response_blocked") < out.find(b"data: [DONE]"), (
            "阻断帧排在结束标记之后 —— 严格按协议读到 [DONE] 就收工的客户端"
            "根本看不到这条阻断"
        )
        rows = store.query_logs(limit=5)
        assert rows and rows[0].action == "alert", (
            f"内容已经交给客户端了，却把这次记成 {rows[0].action!r} —— "
            "账本说谎，下次复盘会得出「拦住了」的错误结论"
        )
        assert "已发出部分内容" in (rows[0].detail_json or ""), (
            "日志没有写明「内容已送达」，用户无法判断这次到底泄露没泄露"
        )

    def test_tool_call_frames_are_withheld_when_blocked(self, tmp_path):
        """被阻断时，工具调用帧绝不能交付 —— 那是唯一会被执行的东西。"""
        resp = _StreamResp([
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,'
            b'"function":{"name":"RunCommand","arguments":"{\\"command\\":\\"rm -rf /\\"}"}}]}}]}\n\n',
        ])
        result, store = _run(tmp_path, resp, stream=True,
                              verifier=_BlockingVerifier())
        out = result

        assert b"RunCommand" not in out, (
            "被判定高危的工具调用仍然发给了客户端 —— AI 工具会照着执行"
        )
        assert b"relay_response_blocked" in out
        rows = store.query_logs(limit=5)
        assert rows and rows[0].action == "block", (
            "这次确实没让任何东西落地（工具调用已扣住），应当记 block"
        )


# ══════════════════════════════════════════════════════════════
# P0-9：多行 data 必须按规范拼接
# ══════════════════════════════════════════════════════════════


class TestMultilineSseData:
    def test_split_json_payload_is_reassembled(self):
        """中转站把一个 JSON 事件拆成两行 data，检测侧必须拼回来。

        ★ SSE 规范：同一事件的多条 data 以 "\\n" 连接。
          拆在 JSON 的结构空白处（逗号后 / 括号间）拼接后仍是合法 JSON，
          于是客户端看得到全文，而只认单行 data 的检测器看到的是空。
        """
        sse = (
            'data: {"choices":[{"delta":{"content":"越权指令"}}\n'
            "data: ]}\n\n"
        )
        text, _tools, _model = app_mod._extract_sse_frames(sse)
        assert text == "越权指令", (
            "多行 data 未被拼接 —— 中转站把载荷拆成两行即可让检测器看到空内容"
        )

    def test_single_line_still_works(self):
        """反向自证：普通单行 data 的解析结果不能变。"""
        sse = 'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
        text, _tools, _model = app_mod._extract_sse_frames(sse)
        assert text == "ok"


# ══════════════════════════════════════════════════════════════
# P0-10：上游错误体不得明文入库
# ══════════════════════════════════════════════════════════════


class TestUpstreamErrorPreviewIsRedacted:
    def test_key_echo_is_masked_before_storage(self, tmp_path):
        # ★ 运行时生成：源码里不留任何「像密钥」的字面量
        #   （本机出站拦截会把这类字面量替换成占位符，测试就测不到真东西了）
        leaked = "".join(["s", "k", "-"]) + uuid.uuid4().hex
        body = json.dumps({
            "error": {"message": f"Incorrect API key provided: {leaked}"}
        }).encode("utf-8")

        _result, store = _run(tmp_path, _Resp(401, body))
        rows = store.query_logs(limit=5)
        assert rows, "上游错误必须留一条日志"
        preview = rows[0].text_preview

        assert leaked not in preview, (
            "上游 401 回显的 Key 被明文写进 SQLite —— 可搜索、可导出"
        )
        assert preview, "脱敏后仍应保留可核对的片段，不能直接丢空"


# ══════════════════════════════════════════════════════════════
# P0-3：建表异常不得整库隔离
# ══════════════════════════════════════════════════════════════


class TestSchemaFailureIsNotCorruption:
    def test_lock_error_does_not_quarantine_healthy_db(self, tmp_path, monkeypatch):
        """锁等待（OperationalError）不是「文件损坏」，不能改名重建。

        ★ 原实现 `except sqlite3.DatabaseError` 把 OperationalError 一并吞下，
          用户看到的是日志/信誉/台账全部归零；只读盘时还会退化成
          「重启→隔离→再失败」的崩溃循环，根因被彻底掩盖。
        """
        db_file = tmp_path / "healthy.db"
        store = db_mod.PersonalStorage(db_path=db_file)
        store.close()

        def _boom(self):
            raise sqlite3.OperationalError("database is locked")

        monkeypatch.setattr(db_mod.PersonalStorage, "_init_schema", _boom)
        with pytest.raises(sqlite3.OperationalError):
            db_mod.PersonalStorage(db_path=db_file)

        assert not list(tmp_path.glob("healthy.db.corrupt-*")), (
            "锁等待被当成「数据库损坏」，健康库被改名隔离并重建空库"
        )

    def test_real_corruption_still_quarantined(self, tmp_path):
        """反向自证：真正的坏文件仍必须隔离并重建。"""
        db_file = tmp_path / "bad.db"
        db_file.write_bytes(b"NOT A SQLITE FILE " * 64)

        store = db_mod.PersonalStorage(db_path=db_file)
        assert store.get_today_stats()["total_calls"] == 0
        assert list(tmp_path.glob("bad.db.corrupt-*"))


# ══════════════════════════════════════════════════════════════
# P0-5 / P0-6 / P0-7：跨语言接线（只能做契约存在性判据）
# ══════════════════════════════════════════════════════════════


class TestFrontendAdminToken:
    """P0-5：浏览器回退通道必须带管理令牌。

    ★ 为什么只能静态判：TS 在 pytest 里跑不起来。
      但判据不是「有没有这个字符串」，而是**两个发送函数都带上了**，
      且令牌有一个显式入口 —— 漏掉任一个函数，那条通道仍然 401。
    """

    def test_both_http_helpers_send_admin_token(self):
        src = API_TS.read_text(encoding="utf-8")
        # 令牌的注入点必须只有一处（baseHeaders），两个发送函数都必须用它
        assert "X-Admin-Token" in src, "没有任何地方发送 X-Admin-Token"
        for fn in ("async function httpGet", "async function httpSend"):
            start = src.index(fn)
            end = src.index("\n}\n", start)
            body = src[start:end]
            assert "baseHeaders()" in body, (
                f"{fn} 没有走统一的鉴权头 —— 该通道访问 /api/* 必然 401"
            )

    def test_token_has_explicit_entrypoint(self):
        src = API_TS.read_text(encoding="utf-8")
        assert "setAdminToken" in src or "initAdminToken" in src, (
            "前端没有管理令牌入口，桌面端无法把令牌交给 HTTP 通道"
        )

    def test_401_is_explained_precisely(self):
        """401 的文案不能把人引向端口问题。"""
        src = API_TS.read_text(encoding="utf-8")
        assert "桌面端" in src, "401 时没有告诉用户「请从桌面端操作」"


class TestFilteredDeleteUsesQuery:
    """P0-6：浏览器通道把筛选条件放 body，后端只读 query。

    ★ 后果不是「删不掉」，而是**删得比用户以为的多**：
      确认框写「筛选结果 12 条」，实际清空整库。
    """

    def test_filter_params_are_encoded_into_query(self):
        src = API_TS.read_text(encoding="utf-8")
        assert "toFilterQuery" in src, "缺少筛选条件 → query 的编码函数"
        for path in ("/api/logs/delete-filtered", "/api/logs/delete-filtered/confirm"):
            idx = src.index(path)
            window = src[max(0, idx - 400):idx + 400]
            assert "toFilterQuery" in window, (
                f"{path} 仍把筛选条件当 body 发送 —— 后端读不到，matched 变成全量"
            )


class TestBuildSecretsReachGuardrail:
    """构建期密钥注入：取证项，结论是「原实现完全空转」。

    ★ 判据不读源码文本，而是走真实链路：
      写一份 build_secrets.json → 进入注入上下文 → 构造真实的 XuanDunConfig
      → 断言配置里拿到的是文件里的随机值，而不是源码里的明文 fallback。
    """

    def test_secret_actually_reaches_xuandun_config(self, tmp_path, monkeypatch):
        from daoti_xuandun.config import DefenseLevel, XuanDunConfig

        from daoti_xuandun_personal.proxy import verifier as vf

        secret = {
            "shell_key": "k" + uuid.uuid4().hex,
            "mapping_key": "m" + uuid.uuid4().hex,
        }
        (tmp_path / "build_secrets.json").write_text(
            json.dumps(secret), encoding="utf-8"
        )
        fake_exe = tmp_path / "engine.exe"
        fake_exe.write_bytes(b"")
        monkeypatch.setattr(vf.sys, "executable", str(fake_exe))

        with vf._build_secrets_env() as applied:
            assert applied is True, "读到了文件却没生效"
            cfg = XuanDunConfig.preset(DefenseLevel.STANDARD)

        assert cfg.shell_key == secret["shell_key"].encode("utf-8"), (
            "构建期 shell_key 没有进入护栏配置 —— 加固是空转的"
        )
        assert cfg.mapping_key == secret["mapping_key"].encode("utf-8")
        assert "XUANDUN_SHELL_KEY" not in os.environ, (
            "密钥留在环境变量里了 —— 同用户的其它进程可直接读到"
        )

    def test_missing_file_falls_back_without_crashing(self, tmp_path, monkeypatch):
        """反向自证：开发态没有该文件时不能崩，也不能假装注入了。"""
        from daoti_xuandun_personal.proxy import verifier as vf

        fake_exe = tmp_path / "engine.exe"
        fake_exe.write_bytes(b"")
        monkeypatch.setattr(vf.sys, "executable", str(fake_exe))

        with vf._build_secrets_env() as applied:
            assert applied is False


class TestTaskkillIsBounded:
    """P0-7：tasklist / taskkill 不得无超时阻塞。

    ★ 它们在持 lifecycle 锁时被调用，IO 不返回则 19 个命令全部排队，
      「停止引擎」按钮自己也卡死。
    """

    def test_process_probe_and_kill_are_bounded(self):
        src = LIB_RS.read_text(encoding="utf-8")
        assert "fn run_command_bounded" in src, (
            "缺少有界的外部命令执行器 —— tasklist/taskkill 仍会无限等待"
        )
        for fn in ("fn kill_cmd", "fn process_alive"):
            start = src.index(fn)
            end = src.index("\n}\n", start)
            body = src[start:end]
            assert "run_command_bounded" in body, (
                f"{fn} 没有走有界执行器 —— 该调用可能永久阻塞 lifecycle 锁"
            )

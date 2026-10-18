# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""交付阻断缺陷的契约测试：首页 KPI 口径一致 + 流式占位符还原。

★ 为什么单独一个文件（2026-10-19）
────────────────────────────────────────────────────────────────
两个缺陷的共同特征是**用户直接可见、却不报错**：

  · P0-1 daily_stats 重算口径与录入口径分叉
      录入时 proxy_error / 上游错误「刻意不计 KPI」，
      重算却按 action 全表统计、且完全忽略 marked_safe。
      后果：用户每删一次日志，首页「危险 / 可疑 / 已检查」就凭空变化，
      被标记过的误报也被重新计回。

  · P0-2 流式响应里的脱敏占位符不还原
      chunk 在 yield 时以占位符原样发出，restore() 只改了服务端 full 变量，
      对已发给客户端的字节无效。Claude Code / Cursor 全走流式，
      用户会看到 ⟦XD_n⟧，工具调用参数也带着占位符被执行。

判据一律落在**真实调用点**：KPI 走真实的 storage 重算路径，
流式还原走真实的 /v1/chat/completions 端点。
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal import license as lic_mod  # noqa: E402
from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.proxy.restorer import ContentRestorer  # noqa: E402
from daoti_xuandun_personal.proxy.sanitizer import RequestSanitizer  # noqa: E402
from daoti_xuandun_personal.reputation.tracker import ReputationTracker  # noqa: E402
from daoti_xuandun_personal.storage import db as db_mod  # noqa: E402
from daoti_xuandun_personal.types import (  # noqa: E402
    Action,
    LogEntry,
    LogType,
    RedactionRecord,
)


# ══════════════════════════════════════════════════════════════
# P0-1：KPI 口径一致
# ══════════════════════════════════════════════════════════════


@pytest.fixture()
def store(tmp_path):
    """隔离存储实例（不碰用户真实数据库）。"""
    return db_mod.PersonalStorage(db_path=tmp_path / "kpi.db")


def _write(store, action, log_type=LogType.RESPONSE_VERIFY.value,
           ts=None, redactions=()):
    """按**生产同款**写法插一条日志：插日志 → 连带脱敏记录 → 累加统计。

    刻意复用 kpi_contribution 与 update_daily_stats（而非只插日志）——
    真实路径（proxy/app.py::_record_log）就是这么写的。
    """
    entry = LogEntry(
        timestamp=time.time() if ts is None else ts,
        log_type=log_type,
        relay_domain="a.example.invalid",
        action=action,
        severity="low",
        model="m",
        finding_count=1,
        summary="测试记录",
    )
    log_id = store.insert_log(entry)
    recs = list(redactions)
    if recs:
        store.insert_redactions(log_id, "sess", recs)
    total, danger, suspect, safe = db_mod.kpi_contribution(log_type, action)
    store.update_daily_stats(
        total_calls=total, danger=danger, suspect=suspect, safe=safe,
        redactions=len(recs),
    )
    return log_id


def _write_proxy_error(store, action=Action.BLOCK.value):
    """记一条链路级错误日志（★ 与 app._proxy_error 同口径：不碰 daily_stats）。"""
    entry = LogEntry(
        timestamp=time.time(),
        log_type=LogType.PROXY_ERROR.value,
        relay_domain="a.example.invalid",
        action=action,
        severity="low",
        model="m",
        summary="中转站响应超时",
    )
    return store.insert_log(entry)


def _expected_from_logs(store):
    """用**同一口径**（kpi_contribution）从剩余日志算出的 KPI。"""
    rows = store._conn.execute(
        "SELECT log_type, action, marked_safe FROM logs"
    ).fetchall()
    acc = [0, 0, 0, 0]
    for r in rows:
        c = db_mod.kpi_contribution(
            str(r["log_type"]), str(r["action"]), bool(r["marked_safe"])
        )
        for i in range(4):
            acc[i] += c[i]
    return tuple(acc)


def _kpi_tuple(store):
    t = store.get_today_stats()
    return (
        t["total_calls"], t["danger_count"],
        t["suspect_count"], t["safe_count"],
    )


class TestKpiContributionPureFunction:
    """纯函数的逐条映射（录入 / 标记 / 重算三处的共同依据）。"""

    def test_proxy_error_counts_nothing(self):
        for act in (Action.BLOCK.value, Action.ALERT.value, Action.PASS.value):
            assert db_mod.kpi_contribution(
                LogType.PROXY_ERROR.value, act
            ) == (0, 0, 0, 0), (
                "proxy_error 是链路/鉴权级失败，不该计入任何一档 KPI"
            )

    def test_normal_rows_map_by_action(self):
        assert db_mod.kpi_contribution(
            LogType.RESPONSE_VERIFY.value, Action.BLOCK.value
        ) == (1, 1, 0, 0)
        assert db_mod.kpi_contribution(
            LogType.RESPONSE_VERIFY.value, Action.ALERT.value
        ) == (1, 0, 1, 0)
        assert db_mod.kpi_contribution(
            LogType.RESPONSE_VERIFY.value, Action.PASS.value
        ) == (1, 0, 0, 1)

    def test_marked_safe_drops_risk_buckets(self):
        # 被标记为误报的 block / alert：风险档与 total 一并回退
        assert db_mod.kpi_contribution(
            LogType.RESPONSE_VERIFY.value, Action.BLOCK.value, True
        ) == (0, 0, 0, 0)
        assert db_mod.kpi_contribution(
            LogType.RESPONSE_VERIFY.value, Action.ALERT.value, True
        ) == (0, 0, 0, 0)
        # pass 标记无意义：维持原样（不能让「安全」凭空变小）
        assert db_mod.kpi_contribution(
            LogType.RESPONSE_VERIFY.value, Action.PASS.value, True
        ) == (1, 0, 0, 1)


class TestRecomputeMatchesRecording:
    """删除触发重算后，KPI 必须与「剩余日志按同一口径算出的值」一致。"""

    def test_delete_does_not_recount_proxy_error_or_marked_safe(self, store):
        _write(store, Action.BLOCK.value)                 # 危险
        _write(store, Action.ALERT.value)                 # 可疑
        keep_pass = _write(store, Action.PASS.value)      # 安全（待删）
        _write_proxy_error(store, Action.BLOCK.value)     # 链路错误，不计
        _write_proxy_error(store, Action.ALERT.value)     # 链路错误，不计
        marked = _write(store, Action.BLOCK.value)        # 先记为危险……
        assert store.mark_safe(marked) is True            # ……再标记误报 → 回退

        before = _kpi_tuple(store)
        # 录入口径基线：block 1 + alert 1 + pass 1 = 3 次；proxy_error 与误报均不计
        assert before == (3, 1, 1, 1), before

        # 删掉那条 pass 日志 → 触发 _recompute_daily_stats
        assert store.delete_log(keep_pass) is True
        after = _kpi_tuple(store)

        assert after == _expected_from_logs(store), (
            f"重算结果 {after} 与「剩余日志按同一口径算出的值」"
            f"{_expected_from_logs(store)} 不一致 —— 重算与录入口径分叉"
        )
        # 明确断言：重算不得把 proxy_error 与被标记的误报计回
        assert after == (2, 1, 1, 0), (
            f"重算把 proxy_error / marked_safe 计回了风险档：{after}"
        )

    def test_recompute_equals_recording_for_mixed_set(self, store):
        """通用不变式：任意一组日志，录入得到的 KPI == 重算得到的 KPI。"""
        _write(store, Action.BLOCK.value)
        _write(store, Action.ALERT.value)
        _write(store, Action.PASS.value)
        _write(store, Action.PASS.value)
        _write_proxy_error(store, Action.BLOCK.value)
        marked = _write(store, Action.ALERT.value)
        store.mark_safe(marked)

        recorded = _kpi_tuple(store)
        store._recompute_daily_stats()
        recomputed = _kpi_tuple(store)

        assert recorded == recomputed, (
            f"录入 KPI {recorded} 与重算 KPI {recomputed} 不一致 —— "
            "两套口径长期打架，用户每删一次日志数字就漂一次"
        )
        # 反向自证：重算没有把 proxy_error 计进去
        # （block 1 + alert 1 + pass 2 = 4；proxy_error 与被标记的 alert 均不计）
        assert recomputed == (4, 1, 1, 2), recomputed


# ══════════════════════════════════════════════════════════════
# P0-2：流式响应占位符还原
# ══════════════════════════════════════════════════════════════

URL = "https://relay.example.com/v1"
KEY = "sk-test-key-123456"


class _StreamResp:
    """假上游流式响应：按给定分片产出字节。"""

    def __init__(self, chunks, status_code=200,
                 content_type="text/event-stream"):
        self.status_code = status_code
        self._chunks = list(chunks)
        self.headers = {"content-type": content_type}
        self.closed = False

    async def aiter_bytes(self):
        for c in self._chunks:
            yield c

    async def aread(self):
        return b"".join(self._chunks)

    async def aclose(self):
        self.closed = True


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
        # ★ 必须开启请求侧脱敏：这样才能在转发前生成占位符并登记到恢复器，
        #   从而复现「响应里出现占位符」的真实场景。
        enable_request_sanitize = True
        enable_response_verify = True
        enable_pattern_check = False
        security_level = "balanced"


def _collect_stream(tmp_path, monkeypatch, chunks, user_text):
    """把 /v1/chat/completions 端点跑起来并消费流式响应，返回客户端收到的字节。"""
    from starlette.requests import Request

    # ★ 强制「防护已启用」：让引擎按已授权处理。
    #   否则未激活会走只读直通，完全绕过脱敏/恢复路径（本缺陷也就测不到）。
    monkeypatch.setattr(lic_mod, "load_public_key", lambda: None)
    app_mod._protection_cache.clear()

    store = db_mod.PersonalStorage(db_path=tmp_path / "stream.db")
    rep = ReputationTracker()
    resp = _StreamResp(chunks)

    old = (
        app_mod._config, app_mod._http_client, app_mod._storage,
        app_mod._reputation, app_mod._sanitizer, app_mod._restorer,
        app_mod._verifier, app_mod._paused_until,
    )
    app_mod._config = _Cfg()
    app_mod._http_client = _Client(resp)
    app_mod._storage = store
    app_mod._reputation = rep
    app_mod._sanitizer = RequestSanitizer(level="balanced")
    app_mod._restorer = ContentRestorer()
    app_mod._verifier = None
    app_mod._paused_until = 0.0

    body = json.dumps({
        "model": "m", "stream": True,
        "messages": [{"role": "user", "content": user_text}],
    }).encode("utf-8")

    scope = {
        "type": "http", "method": "POST",
        "path": "/v1/chat/completions",
        "headers": [(b"authorization", b"Bearer A")],
        "query_string": b"", "client": ("127.0.0.1", 40000),
    }

    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def _drive():
        application = app_mod.create_app()
        endpoint = next(
            r.endpoint for r in application.routes
            if getattr(r, "path", "") == "/v1/chat/completions"
        )
        result = await endpoint(Request(scope, _receive))
        assert hasattr(result, "body_iterator"), (
            f"流式请求未返回 StreamingResponse，而是 {type(result)!r}"
        )
        out = []
        async for part in result.body_iterator:
            out.append(part if isinstance(part, bytes) else part.encode("utf-8"))
        return b"".join(out)

    try:
        return asyncio.new_event_loop().run_until_complete(_drive())
    finally:
        (
            app_mod._config, app_mod._http_client, app_mod._storage,
            app_mod._reputation, app_mod._sanitizer, app_mod._restorer,
            app_mod._verifier, app_mod._paused_until,
        ) = old
        app_mod._protection_cache.clear()


PHONE = "13812345678"


class TestStreamRestoresPlaceholders:
    """客户端收到的字节里不得出现 ⟦XD_ 占位符。"""

    def test_placeholder_restored_in_complete_frame(self, tmp_path, monkeypatch):
        # 上游把占位符「原样回显」—— 真实模型经常这么做
        frame1 = (
            'data: {"choices":[{"delta":{"content":"你的手机号是 ⟦XD_1⟧"}}]}\n\n'
        )
        frame2 = "data: [DONE]\n\n"
        out = _collect_stream(
            tmp_path, monkeypatch,
            [frame1.encode("utf-8"), frame2.encode("utf-8")],
            user_text=f"我的手机号是 {PHONE}",
        )

        assert "⟦XD_".encode("utf-8") not in out, (
            "客户端收到了未还原的脱敏占位符 —— "
            "流式路径把占位符原样透传了"
        )
        assert PHONE.encode("utf-8") in out, (
            "占位符没有被还原为原始手机号"
        )

    def test_placeholder_split_across_chunks_is_restored(
        self, tmp_path, monkeypatch
    ):
        """占位符正好跨 chunk 边界被切断，也必须被拼回并还原。"""
        frame1 = (
            'data: {"choices":[{"delta":{"content":"你的手机号是 ⟦XD_1⟧"}}]}\n\n'
        )
        raw = frame1.encode("utf-8")
        # 在占位符「⟦XD」与「_1⟧」之间切开，制造跨 chunk 的截断
        cut = raw.index("⟦XD_1⟧".encode("utf-8")) + len("⟦XD".encode("utf-8"))
        chunks = [raw[:cut], raw[cut:], "data: [DONE]\n\n".encode("utf-8")]

        out = _collect_stream(
            tmp_path, monkeypatch, chunks,
            user_text=f"我的手机号是 {PHONE}",
        )

        assert "⟦XD_".encode("utf-8") not in out, (
            "跨 chunk 被切断的占位符没有被拼回还原 —— "
            "残留缓冲没有生效"
        )
        assert PHONE.encode("utf-8") in out

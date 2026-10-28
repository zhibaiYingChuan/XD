# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""第三轮审查 P1 批次的回归用例（2026-10-29）。

这一批的共同点与 P0 一样：**失败时不报错，只是看起来仍然成功**。
  · 配置顶层写成 `[]` → 引擎永久起不来，而磁盘上的文件完全可读；
  · 未激活直通被记成「已检查 / 安全」→ 同一屏两句相反的话；
  · 护栏整包缺失 → 界面照旧「防护中」，没有任何出口表达降级；
  · 鉴权中间件在 CORS 外层 → 401 没有 CORS 头，浏览器把它读成网络故障；
  · 空 Key 被掩码成 `***` → 「尚未配置」那段分支是死代码；
  · 别的端口历史上没绑上 → 「新增一家」被拒，报的却是无关端口；
  · 没填中转站地址 → 用户拿到 502「上游不可达」，而正确动作只是去填地址；
  · 检查更新直连 GitHub 失败 → 只抛 reqwest 原文，用户不知道能做什么；
  · CI 从不构建前端 → vite 跨三个主版本仍是三个 PR 全绿。

判据尽量落在**真实调用点**（端点函数、TestClient 走完整中间件栈），
确实只能在另一种语言 / 另一个平台执行的，用源码断言锁住那条契约。
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal import config as cfg_mod  # noqa: E402
from daoti_xuandun_personal.config import PersonalConfig, mask_relay_key  # noqa: E402
from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.storage import db as db_mod  # noqa: E402
from daoti_xuandun_personal.types import Action, LogEntry, LogType  # noqa: E402

LAYOUT_TSX = ROOT / "desktop" / "src" / "components" / "Layout.tsx"
SETTINGS_TSX = ROOT / "desktop" / "src" / "pages" / "Settings.tsx"
API_TS = ROOT / "desktop" / "src" / "services" / "api.ts"
UPDATER_TS = ROOT / "desktop" / "src" / "lib" / "updater.ts"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _endpoint(app, path: str, method: str):
    return next(
        r.endpoint for r in app.routes
        if getattr(r, "path", "") == path
        and method in (getattr(r, "methods", None) or set())
    )


def _force_license_state(monkeypatch, tmp_path, ok: bool) -> None:
    """把授权判定钉成确定结果（真跑 _compute_protection_enabled）。

    ★ 不 monkeypatch 引擎内部的闭包（那样测不到真实判定路径），
      而是替换它依赖的三个外部输入：授权文件位置、公钥、验签结果。
    """
    lic_path = tmp_path / "license.json"
    lic_path.write_text(json.dumps({"code": "XDACT-TEST-CODE"}), encoding="utf-8")
    monkeypatch.setattr(
        app_mod, "_license_file_path", lambda: str(lic_path), raising=False
    )
    # 引擎里是 `import jwt`：这里塞一个空模块，避免测试机缺依赖时
    # 走进「验签组件不可用 → 按已授权处理」的分支。
    monkeypatch.setitem(sys.modules, "jwt", types.ModuleType("jwt"))

    from daoti_xuandun_personal import license as lic

    monkeypatch.setattr(lic, "load_public_key", lambda: b"pub", raising=False)
    monkeypatch.setattr(
        lic, "verify",
        lambda *a, **k: types.SimpleNamespace(ok=ok, reason="测试态", message=""),
        raising=False,
    )
    app_mod._protection_cache.clear()


# ══════════════════════════════════════════════════════════════
# P1-1：配置顶层不是对象 → 备份 + 默认配置
# ══════════════════════════════════════════════════════════════


class TestTopLevelConfigIsNotAnObject:
    """`[]` / `null` / `"x"` 都能通过 json.loads，却在 raw.get 上炸。

    ★ 原行为：抛 AttributeError，没人捕获 → 引擎启动即崩，
      界面永远起不来；而磁盘上的文件其实完全可读，本来可以人工抢救。
      处理方式必须与「JSON 解析失败」一致：**先备份再降级**。
    """

    @pytest.mark.parametrize("text", ["[]", "null", '"x"', "123", "true"])
    def test_falls_back_to_default_and_keeps_a_backup(self, text):
        cfg_file = cfg_mod.CONFIG_FILE
        cfg_file.parent.mkdir(parents=True, exist_ok=True)
        cfg_file.write_text(text, encoding="utf-8")

        got = PersonalConfig.load()

        # ★ 不能用 isinstance：全量跑时别的用例会 importlib.reload(config)，
        #   类对象会换一个，isinstance 会假红。判的是「降级后是一份可用默认配置」。
        assert type(got).__name__ == "PersonalConfig", (
            "顶层类型异常时没有降级为默认配置"
        )
        # 必须真的是一份可用的默认配置，而不是「没抛错但字段是坏的」
        assert got.server.port > 0
        assert got.guard.security_level

        backups = sorted(
            p.name for p in cfg_file.parent.glob("config.json.corrupt-*")
        )
        assert backups, (
            "顶层类型异常时没有生成 .corrupt-* 备份 —— "
            "用户此后任何一次保存都会用默认值覆盖这份还看得懂的原始内容"
        )
        assert (cfg_file.parent / backups[-1]).read_text(
            encoding="utf-8"
        ) == text

    def test_normal_object_still_loads(self):
        """反向自证：正常的对象配置不受影响（否则降级会把用户设置全丢掉）。"""
        cfg_file = cfg_mod.CONFIG_FILE
        cfg_file.parent.mkdir(parents=True, exist_ok=True)
        cfg_file.write_text(
            json.dumps({"server": {"port": 18888}}, ensure_ascii=False),
            encoding="utf-8",
        )
        assert PersonalConfig.load().server.port == 18888


# ══════════════════════════════════════════════════════════════
# P1-2：只读态（未激活）的 KPI 口径
# ══════════════════════════════════════════════════════════════


class TestReadOnlyKpiIsHonest:
    """relay（未检测直通）只能算「已转发」，不能算「已检查且安全」。"""

    def test_relay_contributes_total_but_not_safe(self):
        assert db_mod.kpi_contribution(
            LogType.RELAY.value, Action.PASS.value
        ) == (1, 0, 0, 0), (
            "未检测直通被计进了「安全」—— 首页会同时显示"
            "「未激活不做防护」与「安全 N」两句相反的话"
        )

    def test_recompute_does_not_bring_safe_back(self, tmp_path):
        """★ 关键：删除日志会触发重算，口径必须在重算侧也一致。"""
        store = db_mod.PersonalStorage(db_path=tmp_path / "ro.db")
        store.insert_log(LogEntry(
            log_type=LogType.RELAY.value, relay_domain="r.example.invalid",
            action=Action.PASS.value, severity="low", model="m",
            summary="未激活，本次请求未经检测直接转发",
        ))
        t, d, sp, sf = db_mod.kpi_contribution(
            LogType.RELAY.value, Action.PASS.value)
        store.update_daily_stats(total_calls=t, danger=d, suspect=sp, safe=sf)
        today = store.get_today_stats()
        assert (today["total_calls"], today["safe_count"]) == (1, 0)

        store.clear_logs()          # 触发 _recompute_daily_stats
        assert store.get_today_stats()["safe_count"] == 0


class TestStateSeparatesForwardedFromChecked:
    """`/api/state` 必须能回答「这 N 次里有多少次其实没检测」。"""

    def _state(self, monkeypatch, tmp_path, read_only: bool):
        store = db_mod.PersonalStorage(db_path=tmp_path / "state.db")
        store.insert_log(LogEntry(
            log_type=LogType.RELAY.value, relay_domain="r.example.invalid",
            action=Action.PASS.value, severity="low", model="m",
            summary="未检测直通",
        ))
        t, d, sp, sf = db_mod.kpi_contribution(
            LogType.RELAY.value, Action.PASS.value)
        store.update_daily_stats(total_calls=t, danger=d, suspect=sp, safe=sf)

        old = (app_mod._config, app_mod._storage, app_mod._verifier,
               app_mod._paused_until)
        app_mod._config = PersonalConfig()
        app_mod._storage = store
        app_mod._verifier = None
        app_mod._paused_until = 0.0
        _force_license_state(monkeypatch, tmp_path, ok=not read_only)
        return store, old

    def test_read_only_state_says_forwarded_not_checked(self, monkeypatch, tmp_path):
        store, old = self._state(monkeypatch, tmp_path, read_only=True)
        try:
            data = _run(_endpoint(app_mod.create_app(), "/api/state", "GET")())
        finally:
            (app_mod._config, app_mod._storage, app_mod._verifier,
             app_mod._paused_until) = old
            store.close()

        assert data["read_only"] is True
        assert data["unchecked_forwarded"] == 1, (
            "状态接口无法区分「已转发但未经检测」—— "
            "前端只能把同一堆记录说成「已检查」"
        )
        assert data["today"]["safe_count"] == 0
        assert "已转发" in data["message"] and "未经检测" in data["message"], (
            f"只读态的 message 仍在说「已检查」：{data['message']!r}"
        )

    def test_layout_uses_forwarded_wording(self):
        src = _read(LAYOUT_TSX)
        assert "今日已转发" in src and "未经检测" in src, (
            "状态栏/托盘文案没有区分只读态的「已转发」，"
            "用户会读到「不做防护」+「已检查 N 次」两句矛盾的话"
        )


# ══════════════════════════════════════════════════════════════
# P1-3：降级必须可见
# ══════════════════════════════════════════════════════════════


class _StubVerifier:
    def __init__(self, degraded: bool, layers):
        self._degraded = degraded
        self._layers = layers

    def get_stats(self):
        return {
            "degraded": self._degraded,
            "guardrail_missing_layers": self._layers,
            "rules_source": "builtin_fallback" if self._degraded else "file",
        }


class TestDegradedStateIsExposed:
    def test_state_exposes_degrade_fields(self, monkeypatch, tmp_path):
        store = db_mod.PersonalStorage(db_path=tmp_path / "deg.db")
        old = (app_mod._config, app_mod._storage, app_mod._verifier,
               app_mod._paused_until)
        app_mod._config = PersonalConfig()
        app_mod._storage = store
        app_mod._verifier = _StubVerifier(
            True, ["system_prompt_inject", "sensitive_leak"])
        app_mod._paused_until = 0.0
        try:
            data = _run(_endpoint(app_mod.create_app(), "/api/state", "GET")())
        finally:
            (app_mod._config, app_mod._storage, app_mod._verifier,
             app_mod._paused_until) = old
            store.close()

        assert data["degraded"] is True, (
            "护栏缺失时 /api/state 仍是「一切正常」—— 检测能力缩水看不见"
        )
        assert data["guardrail_missing_layers"] == [
            "system_prompt_inject", "sensitive_leak"
        ]
        assert "license_check" in data and data["license_check"]["reason"] is not None
        assert data["rules_source"] == "builtin_fallback"

    def test_healthy_verifier_reports_no_degradation(self, monkeypatch, tmp_path):
        store = db_mod.PersonalStorage(db_path=tmp_path / "ok.db")
        old = (app_mod._config, app_mod._storage, app_mod._verifier,
               app_mod._paused_until)
        app_mod._config = PersonalConfig()
        app_mod._storage = store
        app_mod._verifier = _StubVerifier(False, [])
        app_mod._paused_until = 0.0
        try:
            data = _run(_endpoint(app_mod.create_app(), "/api/state", "GET")())
        finally:
            (app_mod._config, app_mod._storage, app_mod._verifier,
             app_mod._paused_until) = old
            store.close()
        assert data["degraded"] is False
        assert data["guardrail_missing_layers"] == []

    def test_status_bar_renders_a_persistent_banner(self):
        src = _read(LAYOUT_TSX)
        assert "state?.degraded" in src, (
            "状态栏没有渲染降级横幅 —— 每页都看不见「少了两层检测」"
        )
        assert "降级运行" in src
        assert "guardrail_missing_layers" in src


# ══════════════════════════════════════════════════════════════
# P1-4：CORS 与鉴权顺序
# ══════════════════════════════════════════════════════════════


class TestCorsIsOutermost:
    """401 与预检都必须带 CORS 头。

    ★ 原顺序：先加 CORS，再用 @app.middleware 加守卫 → 守卫在外层，
      401 短路不经过 CORS。浏览器于是把 401 读成 CORS 失败
      （fetch 先抛 TypeError），前端那两段 401 文案成了死代码，
      用户只看到「无法连接到玄盾本地服务」。
    """

    ORIGIN = "http://localhost:1420"

    def _client(self, monkeypatch):
        from fastapi.testclient import TestClient

        monkeypatch.setenv("XUANDUN_ADMIN_TOKEN", "unit-test-token")
        return TestClient(app_mod.create_app())

    def test_preflight_succeeds_with_cors_headers(self, monkeypatch):
        client = self._client(monkeypatch)
        r = client.options(
            "/api/config",
            headers={
                "Origin": self.ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-admin-token",
            },
        )
        assert 200 <= r.status_code < 300, (
            f"OPTIONS 预检被鉴权守卫拦下（{r.status_code}）—— "
            "浏览器连「能不能发这个请求」都问不出来"
        )
        assert r.headers.get("access-control-allow-origin") == self.ORIGIN

    def test_bare_options_also_answers_2xx_with_cors_header(self, monkeypatch):
        """不带 Access-Control-Request-* 的 OPTIONS 不算预检，但同样不能 401/405。"""
        client = self._client(monkeypatch)
        r = client.options("/api/config", headers={"Origin": self.ORIGIN})
        assert 200 <= r.status_code < 300, f"裸 OPTIONS 得到 {r.status_code}"
        assert r.headers.get("access-control-allow-origin") == self.ORIGIN

    def test_401_also_carries_cors_header(self, monkeypatch):
        client = self._client(monkeypatch)
        r = client.get("/api/config", headers={"Origin": self.ORIGIN})
        assert r.status_code == 401, "缺令牌的 /api/config 没有被拦住"
        assert r.headers.get("access-control-allow-origin") == self.ORIGIN, (
            "401 没有 CORS 头 —— 浏览器会把它读成网络故障，"
            "用户拿不到任何可诊断的信息"
        )

    def test_with_token_the_endpoint_is_reachable(self, monkeypatch, tmp_path):
        """反向自证：加对令牌能通过守卫（否则上面两条可能只是 401 之外的东西）。"""
        client = self._client(monkeypatch)
        old = app_mod._config
        app_mod._config = PersonalConfig()
        try:
            r = client.get(
                "/api/config",
                headers={"Origin": self.ORIGIN, "X-Admin-Token": "unit-test-token"},
            )
        finally:
            app_mod._config = old
        assert r.status_code == 200, r.text
        assert r.headers.get("access-control-allow-origin") == self.ORIGIN


# ══════════════════════════════════════════════════════════════
# P1-5：空 Key 的掩码语义
# ══════════════════════════════════════════════════════════════


class TestEmptyKeyMasking:
    def test_empty_key_masks_to_empty(self):
        assert mask_relay_key("") == "", (
            "空 Key 被掩码成 *** —— 界面把「没配」显示成「配过了」，"
            "之后每次 401 用户都不会想到 Key 一直是空的"
        )

    def test_empty_key_stays_empty_in_safe_dict(self):
        cfg = PersonalConfig()
        assert cfg.to_safe_dict()["relay"]["api_key"] == ""

    def test_non_empty_keys_still_masked(self):
        assert mask_relay_key("sk-a") == "***"
        long_key = "sk-" + "x" * 20 + "abcd"
        masked = mask_relay_key(long_key)
        assert "****" in masked and long_key not in masked

    def test_settings_shows_not_configured_when_key_empty(self):
        src = _read(SETTINGS_TSX)
        i = src.index("当前：")
        snippet = src[i:i + 200]
        assert "尚未配置" in snippet, (
            "空 Key 时界面没有「尚未配置」分支 —— 回显会显示成已配置的样子"
        )


# ══════════════════════════════════════════════════════════════
# P1-6：端口报错归属
# ══════════════════════════════════════════════════════════════


class TestPortErrorAttribution:
    """只有本次变更的那个端口失败才算本次操作失败。"""

    def test_other_ports_failures_do_not_block(self):
        errs = {18801: "端口 18801 已被占用"}
        assert app_mod._port_failure_for(errs, 18802, "测试") is None, (
            "别的端口历史失败被当成本次保存的失败 —— "
            "一个用户没动过的端口号封死了另一个域的正常路径"
        )

    def test_the_changed_port_failure_is_reported(self):
        errs = {18802: "端口 18802 已被占用", 18803: "别的错误"}
        got = app_mod._port_failure_for(errs, 18802, "测试")
        assert got == "端口 18802 已被占用"

    def test_no_port_requested_never_fails(self):
        assert app_mod._port_failure_for({18801: "x"}, 0, "测试") is None

    def test_handlers_no_longer_fail_on_any_error(self):
        src = _read(ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py")
        assert "next(iter(errs.values()))" not in src, (
            "仍有调用点「随便挑一条端口错误」就拒绝保存 —— "
            "报错会指向与本次操作无关的端口"
        )
        assert src.count("_port_failure_for(") >= 3, (
            "新增中转站 / 设置专属端口两处都必须走归属判定"
        )


# ══════════════════════════════════════════════════════════════
# P1-7：未配置 relay 的业务端点
# ══════════════════════════════════════════════════════════════


def _json_request(body: dict):
    from starlette.requests import Request

    raw = json.dumps(body).encode("utf-8")
    scope = {
        "type": "http", "method": "POST", "path": "/v1/chat/completions",
        "headers": [(b"content-type", b"application/json")],
        "query_string": b"", "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 18765),
    }
    sent = {"done": False}

    async def _receive():
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return Request(scope, _receive)


class TestRelayNotConfigured:
    """没填中转站地址时，用户该看到「去设置里填」而不是「上游不可达」。"""

    def test_returns_400_with_actionable_type(self, tmp_path):
        store = db_mod.PersonalStorage(db_path=tmp_path / "norelay.db")
        old = (app_mod._config, app_mod._storage, app_mod._http_client,
               app_mod._paused_until, app_mod._reputation)
        app_mod._config = PersonalConfig()      # base_url 为空
        app_mod._storage = store
        app_mod._http_client = None             # 一旦走到转发就会炸，正好当判据
        app_mod._paused_until = 0.0
        app_mod._reputation = None
        try:
            endpoint = _endpoint(
                app_mod.create_app(), "/v1/chat/completions", "POST")
            resp = _run(endpoint(_json_request(
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}
            )))
        finally:
            (app_mod._config, app_mod._storage, app_mod._http_client,
             app_mod._paused_until, app_mod._reputation) = old

        assert resp.status_code == 400, (
            f"未配置中转站时返回了 {resp.status_code} —— "
            "用户会照着「上游不可达」去查网络与中转站"
        )
        body = json.loads(bytes(resp.body))
        assert body["error"]["type"] == "relay_not_configured"
        assert "设置" in body["error"]["message"]

        rows = store.query_logs(limit=5)
        assert rows, (
            "未配置中转站时没有留下任何日志 —— 日志页里连「请求被拒过」"
            "都看不到，事后无法复盘"
        )
        assert "未配置" in rows[0].summary or "未配置" in rows[0].text_preview \
            or "尚未配置" in rows[0].summary
        store.close()


# ══════════════════════════════════════════════════════════════
# P1-9：检查更新 / IPC 的上界
# ══════════════════════════════════════════════════════════════


class TestUpdateCheckHasBoundedNetwork:
    def test_check_has_a_hard_timeout(self):
        src = _read(UPDATER_TS)
        assert "UPDATE_CHECK_TIMEOUT_MS" in src
        assert "withTimeout" in src, "检查更新没有硬超时，直连 GitHub 挂住时按钮永久转圈"
        assert "15_000" in src, "检查更新的超时上限应 ≤ 15s"

    def test_failure_message_is_actionable(self):
        src = _read(UPDATER_TS)
        assert "无法连接 GitHub" in src, (
            "仍把 reqwest 原文甩给用户 —— 既不是中文，也没有下一步"
        )
        assert "DOWNLOAD_PAGE_URL" in src
        assert "releases/latest" in src

    def test_settings_offers_open_download_page(self):
        src = _read(SETTINGS_TSX)
        assert "打开下载页" in src, "失败态没有「打开下载页」按钮"
        assert "openExternal" in src, "「打开下载页」没有用系统浏览器打开"

    def test_ipc_calls_are_bounded(self):
        src = _read(API_TS)
        assert "invokeBounded" in src, (
            "Tauri IPC 没有上界 —— Rust 侧卡住时界面永久停在 busy 态"
        )
        # 反向自证：不再有「裸 invoke」直接返回/等待（helper 内部那次除外）
        assert "return invoke<" not in src, "仍有未加上界的直接 invoke 调用"
        assert "await invoke<" not in src, "仍有未加上界的直接 invoke 调用"
        for cmd in ("get_engine_status", "restart_engine", "get_license_status",
                    "activate_license", "clear_license",
                    "build_rebind_request", "get_admin_token",
                    "get_active_port"):
            i = src.index(f"'{cmd}'")
            window = src[max(0, i - 260):i]
            assert "invokeBounded" in window, (
                f"{cmd} 的 IPC 调用没有走 invokeBounded —— 这条命令可以永久挂住"
            )


# ══════════════════════════════════════════════════════════════
# P1-10：CI 补前端与桌面构建
# ══════════════════════════════════════════════════════════════


class TestCiBuildsDesktop:
    def test_frontend_build_and_rust_check_are_in_ci(self):
        src = _read(CI_YML)
        assert "npm ci" in src, "CI 不装前端依赖 —— npm run build 从未被执行过"
        assert "npm run build" in src, (
            "CI 不构建前端：vite 跨三个主版本时 PR 仍然全绿"
        )
        assert "cargo check --locked" in src, (
            "CI 不做 Rust 类型检查：cargo 级错误只在发 tag 后才暴露"
        )
        assert "desktop/src-tauri" in src

    def test_build_order_respects_frontend_dist(self):
        """tauri 的 generate_context! 在编译期要求 frontendDist 存在。"""
        src = _read(CI_YML)
        assert src.index("npm run build") < src.index("cargo check --locked"), (
            "cargo check 排在前端构建之前 —— dist/ 不存在时 generate_context! 会失败"
        )

    def test_new_job_respects_egress_allowlist(self):
        src = _read(CI_YML)
        start = src.index("desktop:")
        body = src[start:]
        assert "egress-policy: block" in body, "新 job 没继承默认拒绝的出网策略"
        for host in ("registry.npmjs.org:443", "index.crates.io:443",
                     "static.rust-lang.org:443"):
            assert host in body, f"允许清单缺少 {host}，新 job 会被假阳性挂掉"

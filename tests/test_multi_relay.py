# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""多中转站：按 Key 识别转发、切换不丢配置、明文不下发。

用户诉求
────────────────────────────────────────────────────────────
「中转站的配置，如果用户同时使用两个中转站的 API 怎么办呢？」

单中转站时代，代理无条件用配置里的 Key 覆盖 Authorization。
用户同时用两家时，账单归属就说不清了 ——
你以为在用 A，实际扣的是 B 的钱，而界面上没有任何提示。

本文件锁的是多中转站下最容易出错、且出错后**静默**的那几件事
────────────────────────────────────────────────────────────
1. 按 Key 识别：带了哪家的 Key 就发给哪家，地址与 Key 必须是**同一家**的
2. 明文不下发：列表接口只能给掩码，给了明文等于把多家密钥同时交出去
3. 切换不丢配置：切走再切回，那一家的地址与 Key 必须一字不差
4. 归因不串台：本次转发给 B，风险就不能记到 A 头上
5. 保存不污染：前端回传的掩码串绝不能写回磁盘

判据的设计原则
────────────────────────────────────────────────────────────
★ 每条「不能错」的断言都配一条「必须对」的反向自证。
  只测「不报错」的测试，任何实现都能通过。
★ 静态源码判据只用于**结构性**事实（路由冲突、字段是否落库），
  行为判据一律走真实函数调用。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.config import (  # noqa: E402
    RelayConfig,
    is_masked_key,
    mask_relay_key,
    normalize_relay_base,
)

APP_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py"
LIB_RS = ROOT / "desktop" / "src-tauri" / "src" / "lib.rs"
API_TS = ROOT / "desktop" / "src" / "services" / "api.ts"
SETTINGS_TSX = ROOT / "desktop" / "src" / "pages" / "Settings.tsx"

KEY_A = "sk-relay-a-key-0123456789"
KEY_B = "sk-relay-b-key-9876543210"
KEY_C = "sk-relay-c-key-5555555555"
URL_A = "https://api.alpha.invalid/v1"
URL_B = "https://api.beta.invalid/v1"
URL_C = "https://api.gamma.invalid/v1"


def _two_relays() -> RelayConfig:
    """当前启用 A，列表里存着 B。"""
    return RelayConfig(
        name="A 家",
        base_url=URL_A,
        api_key=KEY_A,
        enabled=True,
        others=[
            {
                "id": RelayConfig.make_relay_id(URL_B, KEY_B),
                "name": "B 家",
                "base_url": URL_B,
                "api_key": KEY_B,
                "enabled": True,
            }
        ],
    )


def _camelize(name: str) -> str:
    """把 Rust 的 snake_case 参数名转成 Tauri 传给前端的 camelCase。

    ★ Tauri v2 默认对命令实参做 camelCase 转换，
      所以前端 invoke 的键名是 `base_url` → `baseUrl`。
      不做这个转换就比对，判据会在「两边字面一致」时通过，
      而运行时仍然反序列化失败 ——
      实测踩过：前端传 base_url、Rust 也写 base_url，
      字面上完全一致，实际却报「missing required key baseUrl」。
    """
    head, *rest = name.split("_")
    return head + "".join(w[:1].upper() + w[1:] for w in rest)


def _invoke_arg_keys(api_src: str, cmd: str) -> set:
    """抽出 `call('cmd', ...)` 里作为 tauriArgs 传入的对象的键。

    ★ 用花括号配对扫描而不是正则：
      实参里嵌套着对象字面量、泛型参数与注释，
      正则很容易跨过边界吃到下一个调用里去 ——
      实测踩过：给 removeRelay 匹配出了 ['base_url']，
      那是 addRelay 的字段，判据因此指向了错误的行。

    ★ 取的是命令名之后**最后一个**顶格 {...}：
      调用形如 call<T>(cmd, METHOD, path, body, timeoutMs, tauriArgs)，
      tauriArgs 总是最后一个实参；
      而 body 有时本身就是对象字面量（addRelay 传的是 relay），
      所以取「第一个」会拿到 body，判据就指向了错误的参数。
      实测踩过：因此把 add_relay 误判成「只传了 base_url」。

    ★★ 必须同时处理 `{ id }` 这种**省略值**的简写：
      只匹配 `(\\w+):` 的话，简写形式的键一个都取不到，
      于是 removeRelay 被判成「没传参数」，
      而它其实传得好好的。判据自身出错，
      比没有判据更糟：它会把正确的实现判成错的。
    """
    i = api_src.find(f"'{cmd}'")
    if i < 0:
        return set()
    # ★ 必须**向前**找 call 的左括号，不能从命令名向后找 ——
    #   命令名本身就在 call 的实参里，
    #   从它往后找括号会一路跑到下一个函数去（实测踩过）。
    k = api_src.rfind("call", 0, i)
    if k < 0:
        return set()
    start_paren = api_src.find("(", k)
    if start_paren < 0 or start_paren > i:
        return set()
    depth = 0
    end = None
    for j in range(start_paren, len(api_src)):
        if api_src[j] in "([":
            depth += 1
        elif api_src[j] in ")]":
            depth -= 1
            if depth == 0:
                end = j
                break
    if end is None:
        return set()
    args = api_src[start_paren + 1:end]

    # ★ 取实参里**最后一个**顶格 {...}：
    #   tauriArgs 总是最后一个实参；而 body 有时本身就是对象字面量
    #   （addRelay 传的是 relay），所以取「第一个」会拿到 body。
    #   实测踩过：因此把 add_relay 误判成「只传了 base_url」。
    spans = []
    depth = 0
    begin = None
    for j, ch in enumerate(args):
        if ch == "{":
            if depth == 0:
                begin = j
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and begin is not None:
                spans.append(args[begin + 1:j])
                begin = None
    if not spans:
        return set()

    # ★★ 必须同时处理 `{ id }` 这种**省略值**的简写：
    #   只匹配 `(\\w+):` 的话，简写形式的键一个都取不到，
    #   于是 removeRelay 被判成「没传参数」，
    #   而它其实传得好好的。判据自身出错，
    #   比没有判据更糟：它会把正确的实现判成错的。
    keys = set()
    for part in spans[-1].split(","):
        part = part.strip()
        if not part:
            continue
        keys.add(re.split(r"[:}]", part, 1)[0].strip())
    return keys


class _Cfg:
    """最小化的配置替身，允许注入指定的 relay。

    ★ save() 被打桩为**真的什么也不做**（只是记一笔）：
      add_relay / remove_relay 都会调 _config.save()，
      而它写的是**用户真实的 config.json**。
      测试若不拦住，用户的中转站地址与 Key 会被覆盖成
      `relay-second.example.invalid` —— 测试污染了产品数据。
    """

    def __init__(self, relay):
        self.relay = relay
        self.saved = 0
        # ★ 2026-10-22：端口接口要判断「是不是主端口」，
        #   替身也得有一个 server.port，否则测到的是 AttributeError。
        self.server = type("S", (), {"port": 18765})()

    def validate(self):
        return []

    def save(self):
        self.saved += 1

    def to_safe_dict(self):
        return {"relay": {"base_url": self.relay.base_url}}


class _Req:
    """最小化的 Request 替身（_resolve_upstream 只读 headers）。

    ★ 必须用 starlette 的 Headers 而不是普通 dict：
      HTTP header 名是大小写不敏感的，
      而 `dict.get("Authorization")` 找不到 `{"authorization": ...}`。
      用 dict 会让「小写 header 名」这条用例变成假阳性 ——
      它测的是容器的字典行为，不是实现的正确性。
    """

    def __init__(self, auth: str, lower: bool = False) -> None:
        from starlette.datastructures import Headers

        key = "authorization" if lower else "Authorization"
        self.headers = Headers({key: auth})


def _resolve(req):
    """在受控环境下调用 _resolve_upstream，跑完恢复全局配置。"""
    from daoti_xuandun_personal.proxy import app as app_mod

    old = app_mod._config
    app_mod._config = _Cfg(_two_relays())
    try:
        return app_mod._resolve_upstream(req)
    finally:
        app_mod._config = old


def _forward(base_url, api_key):
    """在受控配置下调用 resolve_forward_target。"""
    from daoti_xuandun_personal.proxy import app as app_mod

    target = None
    if base_url is not None:
        target = {"base_url": base_url, "api_key": api_key}

    old = app_mod._config
    app_mod._config = _Cfg(_two_relays())
    try:
        return app_mod.resolve_forward_target(target)
    finally:
        app_mod._config = old


def _record(domain: str):
    """在受控环境下调用 _record_reputation，返回信誉引擎。"""
    from daoti_xuandun_personal.proxy import app as app_mod
    from daoti_xuandun_personal.reputation import tracker as tr

    class _ActiveCfg:
        class relay:  # noqa: N801
            base_url = URL_A

    engine = tr.ReputationTracker()
    old_cfg, old_rep = app_mod._config, app_mod._reputation
    app_mod._config, app_mod._reputation = _ActiveCfg(), engine
    try:
        app_mod._record_reputation(
            domain, "block", 100.0, "x",
            categories=["tool_call_dangerous"])
    finally:
        app_mod._config, app_mod._reputation = old_cfg, old_rep
    return engine


# ══════════════════════════════════════════════════════════════
# 1. 按 Key 识别
# ══════════════════════════════════════════════════════════════


class TestKeyIdentifiesTheRelay:
    """带了哪家的 Key，就必须发给那家的地址。"""

    def test_matching_key_returns_that_relay(self):
        cfg = _two_relays()
        got = cfg.relay_by_key(KEY_B)
        assert got is not None, "B 家的 Key 没匹配上任何中转站"
        assert got["base_url"] == URL_B, (
            f"匹配到了错误的地址：{got['base_url']} —— "
            "会拿 B 的 Key 去请求 A 的地址，直接 401"
        )

    def test_active_key_also_matches(self):
        """当前启用项也必须在可识别范围内。

        ★ 否则「只用一家」的老用户每次都会被判成「未识别」，
          日志里的「转发给谁」永远显示「当前启用」——
          看似没错，但一旦用户改了地址就会露出破绽。
        """
        cfg = _two_relays()
        got = cfg.relay_by_key(KEY_A)
        assert got is not None, "当前启用的中转站无法按 Key 命中自己"

    def test_unknown_key_returns_none(self):
        """★ 未识别的 Key 必须返回 None，而不是瞎猜一家。

        返回某一家 = 让用户以为在用 A、实际发给了 A，
        而他填的是第三家的 Key —— 这正是本功能要消灭的账目混乱。
        """
        cfg = _two_relays()
        assert cfg.relay_by_key("sk-unknown-key") is None

    def test_empty_key_returns_none(self):
        cfg = _two_relays()
        assert cfg.relay_by_key("") is None
        assert cfg.relay_by_key("   ") is None

    def test_resolve_upstream_falls_back_to_active(self):
        """★ 未命中时回退到当前启用项，而不是报错。

        用户可能在别处换了 Key、还没同步到玄盾。
        此时拒绝服务会让整个 AI 工具不可用，
        静默延续现状只是「不更好」，不会更糟。
        """
        got = _resolve(_Req(f"Bearer sk-never-configured"))
        assert got is not None
        assert got["matched_by"] == "active", (
            "未命中的 Key 必须回退到当前启用项并标记为 active，"
            f"实际得到 {got['matched_by']}"
        )
        assert got["relay"]["base_url"] == URL_A

    def test_resolve_upstream_matches_by_key(self):
        got = _resolve(_Req(f"Bearer {KEY_B}"))
        assert got["matched_by"] == "key", "带 B 的 Key 却没走按 Key 识别"
        assert got["relay"]["base_url"] == URL_B
        assert got["relay"]["api_key"] == KEY_B

    def test_lowercase_bearer_is_accepted(self):
        """★ header 名与 scheme 都大小写不敏感。

        判定用 lower()、切片用原文的 7 个字符 ——
        "bearer " 与 "Bearer " 恰好等长才成立。
        实现若改成按判定结果切片，这里就是它的不变量守卫。
        """
        got = _resolve(_Req(f"bearer {KEY_B}", lower=True))
        assert got["matched_by"] == "key", "小写 bearer 没被识别"
        assert got["relay"]["api_key"] == KEY_B, (
            f"取出的 Key 带了多余前缀：{got['relay']['api_key']!r}"
        )

    def test_forward_target_carries_its_own_key(self):
        """★★ 转发必须用**目标那家**的 Key，不能用配置里的 Key 覆盖。

        历史实现是「先按 Key 识别出目标，转发时又用配置里的
        启用 Key 无条件覆盖 Authorization」——
        识别对了却在最后一步被推平，结果是拿 A 的 Key 请求 B 的地址。
        """
        got = _forward(URL_B, KEY_B)
        assert got["api_key"] == KEY_B, (
            f"转发用了 {got['api_key']!r} 而不是目标那家的 Key —— "
            "识别出 B 也会拿 A 的 Key 去请求 B 的地址"
        )
        assert got["base"] == normalize_relay_base(URL_B)

    def test_forward_of_first_relay_uses_that_relay_key(self):
        """自证：即使目标就是第一项，也仍该用第一项自己的 Key。"""
        got = _forward(URL_A, KEY_A)
        assert got["api_key"] == KEY_A

    def test_forward_falls_back_to_active_when_target_missing(self):
        got = _forward(None, None)
        assert got["api_key"] == KEY_A, "未指定目标时必须用当前启用项"
        assert got["base"] == normalize_relay_base(URL_A)

    def test_forward_falls_back_to_active_key_when_target_has_none(self):
        """目标缺 Key 时才回落 —— 回落方向必须是启用的那把。"""
        got = _forward("https://api.gamma.invalid/v1", "")
        assert got["api_key"] == KEY_A

    def test_route_really_sends_the_target_relays_key(self):
        """★★ 端到端：真跑一遍路由，抓**实际发出的** Authorization 头。

        为什么必须走到这一层：
          resolve_forward_target 返回对了，还不代表转发时用的是它 ——
          历史失效形态正是「解析对了，最后一步又用启用 Key 覆盖」。
          而 _forward_to_relay 是 create_app() 的闭包，
          直接调用拿不到，所以这里通过 FastAPI 的路由表取出端点，
          用假的 http_client 捕获真实发出的头。
        """
        import asyncio
        import tempfile
        import time

        from starlette.requests import Request

        from daoti_xuandun_personal.proxy import app as app_mod
        from daoti_xuandun_personal.storage.db import PersonalStorage

        sent = {}

        class _FakeResp:
            status_code = 200
            headers = {"content-type": "application/json"}

            async def aread(self):
                return b'{"ok": true}'

            async def aclose(self):
                return None

        class _FakeClient:
            # ★ H1 改造后：转发改用 build_request + send(stream=True)，
            #   假客户端据此捕获真实发出的 URL 与请求头。
            def build_request(self, method, url, json=None, headers=None):
                sent["url"] = url
                sent["headers"] = headers or {}
                return {"method": method, "url": url}

            async def send(self, request, stream=False):
                return _FakeResp()

        scope = {
            "type": "http", "method": "POST",
            "path": "/v1/chat/completions", "headers": [],
            "query_string": b"",
        }

        async def _receive():
            return {"type": "http.request",
                    "body": b'{"model":"m","messages":[]}',
                    "more_body": False}

        class _Cfg:
            relay = _two_relays()

            class guard:  # noqa: N801
                enable_request_sanitize = False
                security_level = "standard"

        # 暂停防护 → 走直通分支，才能聚焦「转发给谁」这一件事。
        # ★ 存储必须是**真的**：路由入口有 `_storage is None → 503` 的守卫，
        #   塞假对象会在到达转发之前就被拦下 ——
        #   那就变成「测的是 503 分支」，与本用例要验证的事无关。
        old = (app_mod._config, app_mod._http_client, app_mod._storage,
               app_mod._reputation, app_mod._paused_until)
        tmpdir = tempfile.TemporaryDirectory()
        storage = PersonalStorage(Path(tmpdir.name) / "e2e.db")
        app_mod._config = _Cfg()
        app_mod._http_client = _FakeClient()
        app_mod._storage = storage
        app_mod._reputation = None
        app_mod._paused_until = time.time() + 3600
        try:
            app = app_mod.create_app()
            endpoint = next(
                r.endpoint for r in app.routes
                if getattr(r, "path", "") == "/v1/chat/completions"
            )
            req = Request(scope, _receive)
            req.scope["headers"] = [
                (b"authorization", f"Bearer {KEY_B}".encode())
            ]
            asyncio.run(endpoint(req))
        finally:
            storage.close()
            tmpdir.cleanup()
            (app_mod._config, app_mod._http_client, app_mod._storage,
             app_mod._reputation, app_mod._paused_until) = old

        auth = sent.get("headers", {}).get("Authorization", "")
        assert auth == f"Bearer {KEY_B}", (
            f"实际发出的 Authorization 是 {auth!r} —— "
            "识别出 B 却没发 B 的 Key，账单会记到 A 头上"
        )
        assert sent.get("url", "").startswith(normalize_relay_base(URL_B)), (
            f"实际请求的地址是 {sent.get('url')!r}，不是 B 家的"
        )


# ══════════════════════════════════════════════════════════════
# 2. 明文不下发
# ══════════════════════════════════════════════════════════════


class TestSecretsNeverLeaveTheBackend:
    """列表接口只能给掩码。"""

    def test_configured_endpoint_masks_every_key(self):
        src = APP_PY.read_text(encoding="utf-8")
        m = re.search(
            r'@app\.get\("/api/relays/configured"\).*?(?=\n    @app\.)',
            src, re.S)
        assert m, "未找到 /api/relays/configured"
        block = m.group(0)
        assert "mask_relay_key" in block, (
            "列表接口未做掩码 —— 会把多家中转站的 Key 明文发给前端"
        )
        # 绝不能出现裸的 api_key 字段下发
        assert not re.search(r'"api_key"\s*:', block), (
            "响应体里出现了裸 api_key 字段"
        )

    def test_no_plaintext_key_in_response_shape(self):
        """★ 更强的一层：整段处理里都不能出现未掩码的 key 取值。"""
        src = APP_PY.read_text(encoding="utf-8")
        m = re.search(
            r'@app\.get\("/api/relays/configured"\).*?(?=\n    @app\.)',
            src, re.S)
        block = m.group(0)
        for line in block.splitlines():
            if re.search(r'mask_relay_key', line):
                continue
            assert not re.search(
                r'"api_key"\s*:\s*(r\.get|item\.get|\w+\.get)\('
                r'\s*"api_key"\s*\)\s*(?!\))', line), (
                f"疑似下发明文 Key：{line.strip()}"
            )

    def test_safe_dict_masks_others(self):
        """★ to_safe_dict 必须逐条掩码 others。

        实测踩过：只掩了顶层 relay.api_key，
        others 原样 asdict 出去 —— 于是一次保存就把
        前端拿到的是掩码、前端原样回传、后端写回磁盘，
        其余中转站的真实 Key 全被替换成 `sk-a…CD⟪…⟫`。
        """
        from daoti_xuandun_personal.config import PersonalConfig

        cfg = _two_relays()
        safe = PersonalConfig(relay=cfg).to_safe_dict()
        blob = repr(safe)
        assert KEY_A not in blob, "顶层 Key 明文出现在脱敏视图里"
        assert KEY_B not in blob, (
            "列表里某一家的 Key 明文出现在脱敏视图里 —— "
            "多中转站下等于一次性交出全部密钥"
        )
        assert is_masked_key(safe["relay"]["others"][0]["api_key"]), (
            "others 里的 Key 没被掩码"
        )
        # 自证：真实配置本身没被就地改坏
        assert cfg.others[0]["api_key"] == KEY_B, (
            "to_safe_dict 把掩码写回了内存配置 —— "
            "之后任何转发都会用掩码当 Key"
        )

    def test_mask_of_short_key_is_star(self):
        """短 Key 掩码成 ***，is_masked_key 必须能认出来。"""
        assert mask_relay_key("abc") == "***"
        assert is_masked_key("***")


# ══════════════════════════════════════════════════════════════
# 3. 保存不得污染
# ══════════════════════════════════════════════════════════════


class TestSavingDoesNotCorruptTheList:
    """掩码回显既不能写回磁盘，也不能把正常保存挡死。"""

    def test_masked_echo_is_restored_to_the_real_key(self):
        """服务端自己发出的掩码 = 用户没改过 → 换回真实 Key 并放行。

        ★★ 2026-10-29 实测 P0（用户截图）：旧实现「见掩码即整单拒绝」，
          于是只要配过一家中转站，配置页就再也保存不了任何设置 ——
          用户彻底被卡住。守卫要挡的是「把真 Key 写成掩码」，
          不是「回显了掩码」。
        """
        from daoti_xuandun_personal.proxy import app as app_mod

        current = [{
            "id": "b1", "name": "B 家", "base_url": URL_B, "api_key": KEY_B,
        }]
        merged, err = app_mod.reconcile_masked_others(
            [{
                "id": "b1", "name": "B 家", "base_url": URL_B,
                "api_key": mask_relay_key(KEY_B),
            }],
            current,
        )
        assert err is None, f"正常回显被拒了：{err}"
        assert merged[0]["api_key"] == KEY_B, (
            "掩码没被换回真实 Key —— 每保存一次配置就把别家的 Key 写坏，"
            "之后切到那家必然 401"
        )

    def test_mask_that_does_not_match_server_is_rejected(self):
        """对不上记录的掩码值仍然是错误：那才是「有人塞了假 Key」。"""
        from daoti_xuandun_personal.proxy import app as app_mod

        current = [{
            "id": "b1", "name": "B 家", "base_url": URL_B, "api_key": KEY_B,
        }]
        merged, err = app_mod.reconcile_masked_others(
            [{
                "id": "b1", "name": "B 家", "base_url": URL_B,
                "api_key": "sk-ZZZZ****9999",
            }],
            current,
        )
        assert err is not None, "伪造的掩码串被当成「未改动」放行了"
        assert "第 1 条" in err, "报错没指出是第几条，用户无从定位"

    def test_real_keys_pass_through(self):
        """反向自证：真实 Key 不能被改动。"""
        from daoti_xuandun_personal.proxy import app as app_mod

        merged, err = app_mod.reconcile_masked_others(
            [{"name": "B 家", "base_url": URL_B, "api_key": KEY_B}],
            [],
        )
        assert err is None
        assert merged[0]["api_key"] == KEY_B

    def test_non_dict_items_and_none_are_tolerated(self):
        from daoti_xuandun_personal.proxy import app as app_mod

        merged, err = app_mod.reconcile_masked_others(None, [])
        assert merged == [] and err is None
        merged, err = app_mod.reconcile_masked_others([], [])
        assert merged == [] and err is None
        merged, err = app_mod.reconcile_masked_others(["junk", 3], [])
        assert err is None and merged == ["junk", 3]

    def test_frontend_payload_does_not_carry_masked_others(self):
        """★ 前端的提交体必须逐字段显式列出，不能再整体展开。

        整体展开会把服务端返回的掩码列表一起带回去 ——
        那是这次「保存永远失败」的直接成因（见 Settings.tsx 注释）。
        """
        src = SETTINGS_TSX.read_text(encoding="utf-8")
        m = re.search(r"const relayPayload = \(\) => \{(.*?)\n  \};", src, re.S)
        assert m, "未找到 relayPayload"
        block = m.group(1)
        assert "...config.relay" not in block, (
            "relayPayload 又在整体展开 config.relay —— "
            "掩码的其余中转站会被一起回传，后端将整单拒绝"
        )
        assert re.search(r"api_key:\s*keyDraft", block), (
            "api_key 必须取 keyDraft（空串=保持原 Key），否则会提交掩码"
        )

    def test_switching_does_not_lose_configuration(self):
        """★★ 切走再切回，那一家的地址与 Key 必须一字不差。

        实测过的失效形态：把列表里的原始项当成当前项直接覆盖，
        用户切一下就发现原来那家的地址被改了 —— 再切回去已经不是它。
        """
        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        b_id = RelayConfig.make_relay_id(URL_B, KEY_B)

        app_mod.apply_relay_switch(cfg, b_id)
        assert cfg.base_url == URL_B, "切过去后地址没变"
        assert cfg.api_key == KEY_B

        # ★ 再切回来：A 必须完好无损
        a_id = RelayConfig.make_relay_id(URL_A, KEY_A)
        app_mod.apply_relay_switch(cfg, a_id)
        assert cfg.base_url == URL_A, "切回来后地址不对 —— 配置被改坏了"
        assert cfg.api_key == KEY_A, "切回来后 Key 不对"

    def test_switch_reports_when_nothing_changed(self):
        """★ 切到「当前启用项自己」必须是 no-op，且不重复入列。

        否则用户点一下当前那家，列表里就会多出一条重复项。
        """
        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        a_id = RelayConfig.make_relay_id(URL_A, KEY_A)
        res = app_mod.apply_relay_switch(cfg, a_id)
        assert res["changed"] is False, "切到自己却报告发生了变更"
        assert len(cfg.all_relays()) == 2, "切到自己后列表长度变了"

    def test_switch_unknown_id_raises(self):
        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        try:
            app_mod.apply_relay_switch(cfg, "no-such-id")
        except KeyError:
            return
        raise AssertionError(
            "切换到不存在的 id 必须报错 —— "
            "静默成功会让界面显示「已切换」而实际什么都没变"
        )

    def test_switch_keeps_all_relays(self):
        """切换是**重排**，不是增删：切换前后家数与内容必须完全一致。

        ★ 刻意**不**在测试里复现一遍算法：
          复现版只会验证「我抄的代码和我抄的代码一致」，
          哪怕生产代码整个写错也照样绿。
          这里直接调 apply_relay_switch —— 测的必须是真实现。
        """
        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        before = {r["base_url"]: r["api_key"] for r in cfg.all_relays()}
        assert len(before) == 2

        app_mod.apply_relay_switch(
            cfg, RelayConfig.make_relay_id(URL_B, KEY_B))

        after = cfg.all_relays()
        assert len(after) == 2, f"切换后家数变了：{len(after)}"
        got = {r["base_url"]: r["api_key"] for r in after}
        assert got == before, (
            f"切换前后配置集合不一致：\n  前 {before}\n  后 {got}"
        )


class TestAddingAndRemovingIsPossible:
    """★★ 必须有「新增」路径，否则多中转站只是看得见的界面。

    实测过的形态：列表只能靠切换产生，而切换不新增 ——
    用户改「当前中转站」的地址就等于把原来那家覆盖掉，
    于是界面上「已配置的中转站」永远只有一行，
    而功能看起来是存在的。
    """

    def _routes(self):
        from daoti_xuandun_personal.proxy import app as app_mod

        app = app_mod.create_app()
        return {
            (m, r.path): r.endpoint
            for r in app.routes
            for m in getattr(r, "methods", set()) or set()
            if r.path.startswith("/api/relays")
        }

    def test_add_and_remove_endpoints_exist(self):
        routes = self._routes()
        assert ("POST", "/api/relays/configured") in routes, (
            "没有新增中转站的接口 —— 列表永远长不出第二家"
        )
        assert ("POST", "/api/relays/configured/remove") in routes, (
            "没有移除中转站的接口 —— 用户加错了就撤不回来"
        )

    def test_add_does_not_change_the_active_one(self):
        """★ 新增只是「存着备着」，不能顺手把用户正在用的目标改掉。"""
        import asyncio

        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        holder = _Cfg(cfg)
        old = app_mod._config
        app_mod._config = holder
        try:
            endpoint = self._routes()[("POST", "/api/relays/configured")]
            res = asyncio.run(endpoint({
                "name": "C 家",
                "base_url": "https://api.gamma.invalid/v1",
                "api_key": "sk-gamma-key-abcdefghijkl",
            }))
        finally:
            app_mod._config = old

        assert res.get("ok") is True, f"新增失败：{res}"
        assert cfg.base_url == URL_A, "新增把当前使用中的那家改了"
        assert len(cfg.all_relays()) == 3, (
            f"新增后应有 3 家，实际 {len(cfg.all_relays())}"
        )
        assert holder.saved == 1, "新增后没有落盘"

    def test_add_rejects_masked_key(self):
        """★★ 新增路径同样不能把掩码串写成真实 Key。"""
        import asyncio

        from fastapi import HTTPException

        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        old = app_mod._config
        app_mod._config = _Cfg(cfg)
        try:
            endpoint = self._routes()[("POST", "/api/relays/configured")]
            try:
                asyncio.run(endpoint({
                    "name": "C 家", "base_url": URL_B,
                    "api_key": mask_relay_key(KEY_B),
                }))
            except HTTPException as e:
                assert e.status_code == 400
                return
        finally:
            app_mod._config = old
        raise AssertionError(
            "新增时掩码串被当成了真实 Key —— "
            "存进磁盘后切到那家必然 401，而界面看不出任何异常"
        )

    def test_add_rejects_the_current_one(self):
        """★ 重复添加当前那家必须报错，否则列表里会多出重复项。"""
        import asyncio

        from fastapi import HTTPException

        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        old = app_mod._config
        app_mod._config = _Cfg(cfg)
        try:
            endpoint = self._routes()[("POST", "/api/relays/configured")]
            try:
                asyncio.run(endpoint({
                    "name": "重复", "base_url": URL_A, "api_key": KEY_A,
                }))
            except HTTPException as e:
                assert e.status_code == 400
                return
        finally:
            app_mod._config = old
        raise AssertionError("把当前使用中的那家重复添加进了列表")

    def test_remove_refuses_the_active_one(self):
        """★★ 移除当前启用项会让 AI 工具立刻失去目标，必须拒绝。"""
        import asyncio

        from fastapi import HTTPException

        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        a_id = RelayConfig.make_relay_id(URL_A, KEY_A)
        old = app_mod._config
        app_mod._config = _Cfg(cfg)
        try:
            endpoint = self._routes()[
                ("POST", "/api/relays/configured/remove")]
            try:
                asyncio.run(endpoint({"id": a_id}))
            except HTTPException as e:
                assert e.status_code == 400, (
                    f"移除当前启用项应报 400，实际 {e.status_code}"
                )
                return
        finally:
            app_mod._config = old
        raise AssertionError(
            "允许移除当前使用中的中转站 —— "
            "移除后用户的 AI 工具会立刻没有目标可打"
        )

    def test_remove_drops_only_that_one(self):
        """★★ 必须用**三家**才测得出「只删了被指定的那一家」。

        变异验证实测：把实现改成「一锅端」（others = []），
        两条中转站时本用例照样绿 ——
        因为删掉 B 之后剩 A，删光之后也只剩 A，结果完全一样。
        三家时才能区分：期望剩两家，一锅端只剩一家。
        """
        import asyncio

        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        cfg.others.append({
            "id": RelayConfig.make_relay_id(URL_C, KEY_C),
            "name": "C 家", "base_url": URL_C,
            "api_key": KEY_C, "enabled": True,
        })
        assert len(cfg.all_relays()) == 3
        b_id = RelayConfig.make_relay_id(URL_B, KEY_B)

        old = app_mod._config
        app_mod._config = _Cfg(cfg)
        try:
            endpoint = self._routes()[
                ("POST", "/api/relays/configured/remove")]
            res = asyncio.run(endpoint({"id": b_id}))
        finally:
            app_mod._config = old

        assert res.get("ok") is True
        left = sorted(r["base_url"] for r in cfg.all_relays())
        assert left == sorted([URL_A, URL_C]), (
            f"移除 B 之后应剩 A 与 C，实际 {left} —— "
            "若只剩一家，说明实现是把列表清空了"
        )

    def test_frontend_has_an_add_entry(self):
        """★ 界面上必须有「添加另一家」入口，否则接口是死的。"""
        src = SETTINGS_TSX.read_text(encoding="utf-8")
        assert "添加另一家" in src, "设置页没有新增中转站的入口"
        assert "addRelay" in src
        assert "添加到列表" in src, "新增表单没有提交按钮"

    def test_frontend_add_does_not_touch_current_item(self):
        """★ 新增后刻意不调 load()：不能清掉用户填到一半的其他输入。"""
        src = SETTINGS_TSX.read_text(encoding="utf-8")
        m = re.search(
            r"const addRelay = useCallback\(async \(\) => \{(.*?)\n  \}, \[",
            src, re.S)
        assert m, "未找到 addRelay"
        block = m.group(1)
        assert "addRelay(" in block or "api.addRelay" in block, (
            "新增按钮没有调用后端"
        )
        assert "loadConfigured()" in block, "新增后没刷新列表"
        assert not re.search(r"\bawait load\(\)", block), (
            "新增后调用了 load() —— 会把用户正在填的当前中转站表单清空"
        )

    def test_form_open_state_is_not_the_request_state(self):
        """★★ 「表单已打开」与「请求在飞」必须是两个 state。

        CDP 实测抓到的真实缺陷：两者共用一个 state，
        于是用户刚点开「添加另一家」、什么都没干，
        按钮就已经显示「添加中…」——
        而实际上没有任何请求在发。那是在对用户说谎，
        而且会让自动化测试误判成「提交按钮不存在」。

        判据锁住「提交按钮的文案条件用的是请求态」，
        而不是笼统地断言存在两个 state ——
        那样写的话，把两个 state 换回一个也照样绿。
        """
        src = SETTINGS_TSX.read_text(encoding="utf-8")
        assert re.search(
            r"\{addingBusy \? '添加中…' : '添加到列表'\}", src), (
            "提交按钮的文案没有区分「请求在飞」—— "
            "打开表单就会显示「添加中…」，而并没有请求在发"
        )
        # ★ 断言「显示条件用的是 adding（是否已打开）而不是 addingBusy（请求在飞）」，
        #   而不是断言外层用的是什么标签 —— 包一层具名 div（.relay-add-form）
        #   只是为了让新增表单有明确边界，与语义无关。
        #   早先锁死 `<><div className="field-label">` 会让任何包裹层改动都假失败，
        #   那是在测写法而不是测语义。
        assert re.search(
            r"\{adding \? \(", src), (
            "找不到以 adding 为条件的表单分支"
        )
        assert not re.search(
            r"\{addingBusy \? \(", src), (
            "表单的显示条件用了请求态 addingBusy —— "
            "请求在飞时表单会整个消失，用户填到一半的内容凭空丢失"
        )
        assert "disabled={addingBusy}" in src, (
            "提交按钮没有在请求在飞时禁用 —— 可连点重复提交"
        )


# ══════════════════════════════════════════════════════════════
# 4. 归因不串台
# ══════════════════════════════════════════════════════════════


class TestReputationIsNotMisattributed:
    """本次转发给谁，风险就记到谁头上。"""

    def test_record_call_uses_domain_not_config(self):
        from daoti_xuandun_personal.reputation import tracker as tr

        t = tr.ReputationTracker()
        t.record_call(URL_B, "block", 100.0, "x",
                      categories=["tool_call_dangerous"])
        reps = t.list_all()
        assert len(reps) == 1
        assert reps[0].domain == "api.beta.invalid", (
            f"信誉记到了 {reps[0].domain} —— "
            "多中转站下会让无辜的一家替人背锅"
        )

    def test_record_reputation_respects_domain_argument(self):
        """★ _record_reputation 必须用传入的域名，而非配置里的启用项。

        原实现写死 `_config.relay.base_url`。
        单中转站下两者相同（所以从没暴露），
        多中转站下就是「B 的风险记到 A 头上」。
        """
        engine = _record("api.beta.invalid")
        domains = [r.domain for r in engine.list_all()]
        assert domains == ["api.beta.invalid"], (
            f"风险被记到了 {domains} —— "
            "本次明明转发给 B，启用项却是 A"
        )

    def test_empty_domain_falls_back_to_active(self):
        """老调用点仍传空域名时不能直接丢弃这次记录。"""
        engine = _record("")
        domains = [r.domain for r in engine.list_all()]
        assert domains == ["api.alpha.invalid"], (
            f"空域名时既没回退也没记录：{domains}"
        )


# ══════════════════════════════════════════════════════════════
# 5. 路由与老配置兼容
# ══════════════════════════════════════════════════════════════


class TestNoRouteShadowingAndBackCompat:
    def test_no_duplicate_routes(self):
        """★★ FastAPI 的同名路由不报错，先注册者胜，后来者是死代码。

        /api/relays 已被「信誉列表」占用。
        若新加的也写 /api/relays，它会变成一段
        永远不被调用、且没有任何异常提示的代码 ——
        代码读起来完全正常，只是「接口没生效」。
        """
        src = APP_PY.read_text(encoding="utf-8")
        seen: dict[tuple[str, str], int] = {}
        for m in re.finditer(
                r'@app\.(get|post|put|delete)\("([^"]+)"', src):
            key = (m.group(1).upper(), m.group(2))
            seen[key] = seen.get(key, 0) + 1
        dups = {k: v for k, v in seen.items() if v > 1}
        assert not dups, f"存在重复路由（后者为死代码）：{dups}"

    def test_configured_path_is_not_relays(self):
        src = APP_PY.read_text(encoding="utf-8")
        assert '@app.get("/api/relays")' in src, (
            "信誉列表路径消失，说明结构变了，请复核路由设计"
        )
        assert '@app.get("/api/relays/configured")' in src

    def test_old_config_loads_without_new_fields(self):
        """★ 老配置只有 4 个字段，加载后必须自动补齐，不能丢设置。

        实测踩过：PersonalConfig.load() 是**静态方法**、读全局路径，
        直接传路径会 TypeError —— 测试必须改模块级 CONFIG_FILE。
        """
        import json
        import tempfile

        from daoti_xuandun_personal import config as cfg_mod

        old = {
            "relay": {"name": "旧配置", "base_url": URL_A, "api_key": KEY_A,
                      "enabled": True},
            "guard": {"security_level": "standard"},
            "server": {"port": 18765},
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            p.write_text(json.dumps(old), encoding="utf-8")
            orig = cfg_mod.CONFIG_FILE
            cfg_mod.CONFIG_FILE = p
            try:
                cfg = cfg_mod.PersonalConfig.load()
            finally:
                cfg_mod.CONFIG_FILE = orig

            assert cfg.relay.base_url == URL_A, "老配置的基础设置丢了"
            assert cfg.relay.api_key == KEY_A
            assert cfg.relay.others == [], "老配置被塞进了不存在的列表项"
            assert cfg.relay.active_id == ""
            assert len(cfg.relay.all_relays()) == 1, (
                "老配置加载后应该只有一家可用"
            )

    def test_old_config_with_unknown_fields_still_loads(self):
        """★ 老库里可能有已废弃的字段，不能因此整份配置被丢弃。"""
        import json
        import tempfile

        from daoti_xuandun_personal import config as cfg_mod

        old = {
            "relay": {"name": "旧", "base_url": URL_A, "api_key": KEY_A,
                      "enabled": True, "removed_option": 1},
            "guard": {}, "server": {},
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            p.write_text(json.dumps(old), encoding="utf-8")
            orig = cfg_mod.CONFIG_FILE
            cfg_mod.CONFIG_FILE = p
            try:
                cfg = cfg_mod.PersonalConfig.load()
            finally:
                cfg_mod.CONFIG_FILE = orig
            assert cfg.relay.api_key == KEY_A, (
                "因一个废弃字段就整份丢弃配置 —— 用户设置全丢"
            )

    def test_active_id_defaults_to_derived(self):
        cfg = RelayConfig(name="A", base_url=URL_A, api_key=KEY_A)
        items = cfg.all_relays()
        assert items[0]["active"] is True
        assert items[0]["id"] == RelayConfig.make_relay_id(URL_A, KEY_A), (
            "未设 active_id 时应按自身地址/Key 推导 id"
        )

    def test_relay_id_is_stable_and_distinguishing(self):
        a1 = RelayConfig.make_relay_id(URL_A, KEY_A)
        a2 = RelayConfig.make_relay_id(URL_A, KEY_A)
        b = RelayConfig.make_relay_id(URL_B, KEY_B)
        assert a1 == a2, "id 不稳定 —— 每次刷新列表都像换了一家"
        assert a1 != b, "不同中转站的 id 撞了"

    def test_normalized_base_shared_by_all_relays(self):
        """★ 每一家都要走同一套规范化，否则用户填法千奇百怪。"""
        cfg = RelayConfig(name="x", base_url="", api_key="")
        assert cfg.normalized_base == "/v1"
        assert normalize_relay_base(
            "https://x.invalid/v1/chat/completions") == \
            "https://x.invalid/v1"
        assert normalize_relay_base("https://x.invalid/v1beta") == \
            "https://x.invalid/v1beta", "非 /v1 版本段被误改写"


# ══════════════════════════════════════════════════════════════
# 6. 端到端接线
# ══════════════════════════════════════════════════════════════


class TestFrontendAndDesktopAreWired:
    def test_api_ts_exposes_both_calls(self):
        src = API_TS.read_text(encoding="utf-8")
        assert "/api/relays/configured" in src, (
            "前端没调配置列表接口 —— 设置页永远显示「还没有配置中转站」"
        )
        assert "/api/relays/active" in src, (
            "前端没调切换接口 —— 「切到这家」按钮点了没反应"
        )

    def test_switch_is_callable_from_list_item(self):
        src = SETTINGS_TSX.read_text(encoding="utf-8")
        assert "switchTo(" in src, "列表项没有绑定切换动作"
        assert "切到这家" in src
        # ★ 非当前项才给按钮。
        #   判据只认 `!r.active` 与「切到这家」出现在**同一个条件块**里 ——
        #   否则「切换按钮」和「active 判断」分散在文件两处时，
        #   这条断言会变成恒真。
        m = re.search(
            r"\{!r\.active && \((.*?)\n\s*\)\}", src, re.S)
        assert m, "找不到「非当前项才显示操作按钮」的条件块"
        block = m.group(1)
        assert "切到这家" in block, (
            "切换按钮不在 !r.active 条件内 —— "
            "当前使用中的那家也给了按钮，用户会点出一个空操作"
        )
        assert "移除" in block, (
            "移除按钮不在 !r.active 条件内 —— "
            "用户会把正在用的那家删掉"
        )

    def test_switching_blocks_repeat_clicks(self):
        src = SETTINGS_TSX.read_text(encoding="utf-8")
        assert "switching" in src, "切换按钮无操作锁 —— 可连点重复提交"
        assert re.search(r"disabled=\{switching\}", src), (
            "切换按钮未在切换中禁用"
        )

    def test_list_loads_after_save(self):
        """★ 保存新配的一家后必须刷新列表，否则用户以为没保存成功。"""
        src = SETTINGS_TSX.read_text(encoding="utf-8")
        m = re.search(
            r"const saveRelay = async \(\) => \{(.*?)\n  \};", src, re.S)
        assert m, "未找到 saveRelay"
        assert "loadConfigured()" in m.group(1), (
            "保存中转站后没刷新已配置列表 —— "
            "用户保存完看不到刚加的那家"
        )

    def test_rust_bridges_both_commands(self):
        src = LIB_RS.read_text(encoding="utf-8")
        assert "get_configured_relays" in src, "Rust 侧缺 get_configured_relays"
        assert "switch_relay" in src, "Rust 侧缺 switch_relay"
        # 必须注册进 generate_handler，否则命令定义了却调不到
        handler = re.search(
            r"generate_handler!\[(.*?)\n\s*\]\)", src, re.S)
        assert handler, "未找到 generate_handler"
        body = handler.group(1)
        assert "get_configured_relays" in body, (
            "get_configured_relays 没有注册 —— 命令定义了却调不到"
        )
        assert "switch_relay" in body, (
            "switch_relay 没有注册 —— 命令定义了却调不到"
        )

    def test_tauri_arg_shapes_match_the_rust_signatures(self):
        """★★ 前端 invoke 的参数形状必须与 Rust 命令签名**逐个对齐**。

        CDP 实测抓到的真实缺陷：`addRelay` 把三个字段塞进 payload，
        而 Rust 的 `add_relay` 把它们声明成**顶层参数** ——
        Tauri 反序列化失败，界面上只显示「添加失败」，
        用户既看不到原因也看不到自己填的内容去了哪里。

        ★ 这类故障对 pytest 完全不可见：
          它不是逻辑错，而是「两处签名漂移」，
          只有真的点一次按钮才会暴露。

        判据做法：从两侧源码里抽出参数名并比对集合，
        而不是断言「代码里出现了某个字段名」。
        """
        api_src = API_TS.read_text(encoding="utf-8")
        rust_src = LIB_RS.read_text(encoding="utf-8")

        cases = {
            # ★ 2026-10-22：port 是后加的专属入口端口（0 表示不单独分配）
            "add_relay": ["name", "baseUrl", "apiKey", "port"],
            "remove_relay": ["id"],
            "switch_relay": ["id"],
            "set_relay_port": ["id", "port"],
        }
        for cmd, expected in cases.items():
            # Rust 侧：命令函数的参数（排除 app: AppHandle）
            m = re.search(
                r"async fn " + cmd + r"\(\s*"
                r"app: tauri::AppHandle,\s*(.*?)\n\) -> Result<",
                rust_src, re.S)
            assert m, f"未找到 Rust 命令 {cmd}"
            rust_params = set(re.findall(r"(\w+):\s", m.group(1)))

            # ★★ Rust 的 snake_case 参数名会被 Tauri 转成 camelCase 再传，
            #   所以两侧必须按**同一套命名规则**比对。
            #   实测踩过：前端传 base_url、Rust 声明 base_url，
            #   看起来「完全一致」，而 Tauri 找的是 baseUrl ——
            #   界面只显示「添加失败：invalid args」，
            #   没有控制台报错，也没有任何其他线索。
            camel = {_camelize(p) for p in rust_params}
            ts_args = _invoke_arg_keys(api_src, cmd)
            assert ts_args == camel, (
                f"前端对 {cmd} 的 invoke 传了 {sorted(ts_args)}，"
                f"而 Rust 的 {sorted(rust_params)} 经 Tauri 的 camelCase "
                f"转换后是 {sorted(camel)} —— 键名对不上就会反序列化失败，"
                "界面上只显示「添加失败」"
            )
            assert camel == set(expected), (
                f"{cmd} 的期望键名是 {sorted(expected)}，"
                f"实际推导出 {sorted(camel)}"
            )

    def test_logs_record_the_real_forward_target(self):
        """★ 日志必须写「本次转发给谁」，否则排查时无从下手。"""
        src = APP_PY.read_text(encoding="utf-8")
        assert "本次转发给" in src, (
            "直通日志未记录实际转发对象 —— "
            "多中转站下用户无法判断请求发去了哪里"
        )


# ══════════════════════════════════════════════════════════════
# 7. 专属入口端口（2026-10-22）
# ══════════════════════════════════════════════════════════════
#
# 用户诉求
# ────────────────────────────────────────────────────────────
# 「同一个中转站端口地址的话，在一些 AI 软件里面，比如说 IDE 里面
#   是无法输入的，那就需要多个端口。」
#
# 根因：AI 工具按「服务地址」区分供应商，同一地址只让填一条；
#       两家的模型 ID 又往往一样，于是第二家根本配不进去。
# 解法：每家中转站可以有一个专属端口，地址天然不同；
#       从哪个端口进来，就发给哪一家 —— 不看 Key。
#
# 本组判据只锁三件事
# ────────────────────────────────────────────────────────────
# 1. 端口能准确选中「那一家」，且优先级高于 Key
# 2. 端口冲突/主端口/停用项不会被静默接受
# 3. 没有真正监听时绝不假装成功


def _req_with_port(auth: str, port: int):
    """带本地端口的最小真实 Request（_resolve_upstream 读 scope + headers）。"""
    from starlette.requests import Request

    scope = {
        "type": "http", "method": "POST", "path": "/v1/chat/completions",
        "headers": [(b"authorization", auth.encode())],
        "query_string": b"",
        "server": ("127.0.0.1", port),
    }
    return Request(scope)


def _resolve_with(cfg, req):
    from daoti_xuandun_personal.proxy import app as app_mod

    old = app_mod._config
    app_mod._config = _Cfg(cfg)
    try:
        return app_mod._resolve_upstream(req)
    finally:
        app_mod._config = old


class TestDedicatedPortRouting:
    """从哪个门进来，就发给哪一家。"""

    def test_relay_by_port_finds_the_owner(self):
        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        got = cfg.relay_by_port(18801)
        assert got is not None, "按端口找不到那一家"
        assert got["base_url"] == URL_B

    def test_main_port_is_not_owned_by_any_relay(self):
        """★ 主端口不能命中任何一家，否则「按 Key 识别」这条老路会被短路。"""
        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        assert cfg.relay_by_port(18765) is None
        assert cfg.relay_by_port(0) is None

    def test_port_beats_key(self):
        """★★ 从 B 的端口进来、带着 A 的 Key —— 必须发给 B。

        这才是这个功能的全部意义：IDE 里填的 Key 常常是占位串，
        真正决定账单归属的是用户在玄盾里为端口指定的那一家。
        """
        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        got = _resolve_with(cfg, _req_with_port(f"Bearer {KEY_A}", 18801))
        assert got["matched_by"] == "port", (
            f"从专属端口进来却按 {got['matched_by']} 识别 —— "
            "用户配在 B 端口上的请求会被发去 A"
        )
        assert got["relay"]["base_url"] == URL_B
        assert got["relay"]["api_key"] == KEY_B, (
            "选择了 B 却没用 B 的 Key，转发会 401"
        )

    def test_main_port_still_matches_by_key(self):
        """反向自证：主端口的行为一字未改。"""
        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        got = _resolve_with(cfg, _req_with_port(f"Bearer {KEY_B}", 18765))
        assert got["matched_by"] == "key"
        assert got["relay"]["base_url"] == URL_B

    def test_unknown_port_falls_back_to_normal_rules(self):
        """既不是主端口、也没分配给任何一家的端口 → 不猜，按原规则走。"""
        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        got = _resolve_with(cfg, _req_with_port("Bearer sk-unknown", 18999))
        assert got["matched_by"] == "active"
        assert got["relay"]["base_url"] == URL_A

    def test_disabled_relay_port_is_ignored(self):
        """停用的那家不该继续占着一个门。"""
        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        cfg.others[0]["enabled"] = False
        assert cfg.relay_by_port(18801) is None
        assert 18801 not in cfg.assigned_ports()

    def test_switch_keeps_the_port_with_its_owner(self):
        """★★ 切换只换默认目标，端口必须跟着「那一家」走。

        实测最容易写坏的地方：切换时重建 dict，顺手漏掉 port ——
        用户切一下，AI 工具里填的那个端口就没了主人。
        """
        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        app_mod.apply_relay_switch(
            cfg, RelayConfig.make_relay_id(URL_B, KEY_B))
        assert cfg.base_url == URL_B
        assert cfg.port == 18801, "B 家切上来后端口丢了"
        assert cfg.relay_by_port(18801)["base_url"] == URL_B

        app_mod.apply_relay_switch(
            cfg, RelayConfig.make_relay_id(URL_A, KEY_A))
        assert cfg.port == 0, "A 家不该凭空获得 B 的端口"
        assert cfg.relay_by_port(18801)["base_url"] == URL_B, (
            "切回 A 之后，B 的端口没能继续指向 B"
        )


class TestPortValidation:
    def test_duplicate_ports_are_rejected(self):
        cfg = _two_relays()
        cfg.port = 18801
        cfg.others[0]["port"] = 18801
        errors = cfg.validate()
        assert any("都用了端口 18801" in e for e in errors), (
            f"两个家撞同一端口却没报错：{errors} —— "
            "后绑的那家会静默失败，界面却显示两家都配好了"
        )

    def test_port_out_of_range_is_rejected(self):
        cfg = _two_relays()
        cfg.others[0]["port"] = 70000
        assert any("1024" in e for e in cfg.validate())

    def test_port_cannot_equal_the_main_port(self):
        from daoti_xuandun_personal.config import PersonalConfig

        cfg = _two_relays()
        cfg.others[0]["port"] = 18765
        errors = PersonalConfig(relay=cfg).validate()
        assert any("主端口" in e for e in errors), (
            "专属端口可以等于主端口 —— 会让「从主端口进来发给谁」出现两套规则"
        )

    def test_zero_means_not_assigned(self):
        cfg = _two_relays()
        cfg.others[0]["port"] = 0
        assert cfg.validate() == []
        assert cfg.assigned_ports() == {}

    def test_parse_accepts_blank_and_rejects_junk(self):
        from daoti_xuandun_personal.config import parse_relay_port

        assert parse_relay_port("") == 0
        assert parse_relay_port(None) == 0
        assert parse_relay_port("18801") == 18801
        for bad in ("abc", "80", "70000", True):
            try:
                parse_relay_port(bad)
            except ValueError:
                continue
            raise AssertionError(f"非法端口 {bad!r} 被接受了")


class TestPortEndpointsDoNotLieAboutSuccess:
    """没有真正监听时，绝不能返回「已保存」。"""

    def _routes(self):
        from daoti_xuandun_personal.proxy import app as app_mod

        app = app_mod.create_app()
        return {
            (m, r.path): r.endpoint
            for r in app.routes
            for m in getattr(r, "methods", set()) or set()
            if r.path.startswith("/api/relays")
        }

    def test_port_endpoint_exists(self):
        assert ("POST", "/api/relays/configured/port") in self._routes(), (
            "没有改端口的接口 —— 用户只能加新家时顺手填，填错了改不了"
        )

    def test_assigning_port_without_listener_is_refused(self):
        """★ 引擎没起来/非 run() 启动时，端口不可能真的生效。

        此时若返回成功，用户会照着界面上的地址去配 AI 工具，
        然后连不上，且没有任何线索指向这次保存。
        """
        import asyncio

        from fastapi import HTTPException

        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        b_id = RelayConfig.make_relay_id(URL_B, KEY_B)
        old = app_mod._config
        app_mod._config = _Cfg(cfg)
        try:
            endpoint = self._routes()[
                ("POST", "/api/relays/configured/port")]
            try:
                asyncio.run(endpoint({"id": b_id, "port": 18801}))
            except HTTPException as e:
                assert e.status_code == 503, (
                    f"应报 503（端口还没就绪），实际 {e.status_code}"
                )
                assert cfg.others[0].get("port") in (None, 0), (
                    "报错后端口仍被写进了配置 —— 界面会显示一个不存在的入口"
                )
                return
        finally:
            app_mod._config = old
        raise AssertionError("没有监听器时端口分配被当成成功了")

    def test_duplicate_port_is_refused_at_the_endpoint(self):
        import asyncio

        from fastapi import HTTPException

        from daoti_xuandun_personal.proxy import app as app_mod

        cfg = _two_relays()
        cfg.others[0]["port"] = 18801
        a_id = RelayConfig.make_relay_id(URL_A, KEY_A)
        old = app_mod._config
        app_mod._config = _Cfg(cfg)
        try:
            endpoint = self._routes()[
                ("POST", "/api/relays/configured/port")]
            try:
                asyncio.run(endpoint({"id": a_id, "port": 18801}))
            except HTTPException as e:
                assert e.status_code == 400
                return
        finally:
            app_mod._config = old
        raise AssertionError("两家被允许使用同一个端口")

    def test_remove_unbinds_the_port(self):
        """移除那一家后，它的端口不应继续被监听。"""
        src = APP_PY.read_text(encoding="utf-8")
        m = re.search(
            r'@app\.post\("/api/relays/configured/remove"\).*?(?=\n    @app\.)',
            src, re.S)
        assert m, "未找到移除接口"
        assert "_sync_relay_ports" in m.group(0), (
            "移除中转站后没有回收它的专属端口 —— "
            "那个门还在，请求进来会悄悄退回当前启用项"
        )


class TestExtraPortsAreReallyServed:
    """真起一个额外端口，验证「/v1 放行、/api 不放行」。"""

    def test_extra_port_serves_v1_only(self):
        import asyncio
        import json
        import socket

        import httpx

        from daoti_xuandun_personal.proxy.listeners import RelayPortListeners

        async def echo_app(scope, receive, send):
            body = json.dumps({"port": scope["server"][1]}).encode()
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({"type": "http.response.body", "body": body})

        def free_port() -> int:
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", 0))
                return int(s.getsockname()[1])
            finally:
                s.close()

        async def scenario() -> None:
            port = free_port()
            mgr = RelayPortListeners(echo_app, "127.0.0.1", 18765)
            errs = await mgr.sync({port})
            assert not errs, f"额外端口起不来：{errs}"
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    ok = await client.get(f"http://127.0.0.1:{port}/v1/models")
                    assert ok.status_code == 200, (
                        f"/v1 被拦了：{ok.status_code} {ok.text}"
                    )
                    assert ok.json()["port"] == port, (
                        "服务报告的端口与监听端口不一致 —— 按端口识别会全错"
                    )
                    denied = await client.get(
                        f"http://127.0.0.1:{port}/api/config")
                    assert denied.status_code == 404, (
                        "额外端口把管理接口也暴露了（/api/config 可达）"
                    )
            finally:
                await mgr.close()

        asyncio.run(scenario())

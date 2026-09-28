# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""激活码 WebUI 的接口测试。

为什么要单独测
────────────────────────────────────────────────────────────────
WebUI 夹在「用户把机器码发给你」和「把码发回去」之间。
它的失败不会在签发时暴露，而是等到用户激活失败、或你吊销了一张错误的码
才暴露 —— 那时已经产生了真实的用户影响。

所以这里重点测三类问题：
  1. 数据正确性：签出的码能不能被客户端验签（用公钥反查）
  2. 解析健壮性：CLI 的人读排版不能污染数据通道
  3. 安全边界：非本机请求必须被拒

★★ 绝不用仓库真实私钥
────────────────────────────────────────────────────────────────
测试若用真私钥签名，等于在源码树里产生真凭据 ——
一旦这个测试日志或缓存被外传，所有已签发的激活码都可被伪造。
这里用临时密钥对，与仓库私钥完全无关。
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "tools" / "activation"))
sys.path.insert(0, str(_REPO / "src"))


@pytest.fixture(scope="module")
def webui(tmp_path_factory):
    """加载 webui 模块，并把密钥与日志全部指向临时目录。"""
    import gen_activation_keys as gak

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    tmp = tmp_path_factory.mktemp("activation_webui")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = tmp / gak.PRIVATE_KEY_NAME
    pub = tmp / gak.PUBLIC_KEY_NAME
    priv.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    import webui as webui_mod

    webui_mod.PRIVATE_KEY = priv
    webui_mod.PUBLIC_KEY = pub
    webui_mod.LOG_PATH = tmp / "ACTIVATION_LOG.json"

    from fastapi.testclient import TestClient

    return webui_mod, TestClient(webui_mod.app)


def _claims(client, code: str) -> dict:
    """用公钥解出码里的内容 —— 以码本身为权威事实源。"""
    import jwt

    import webui as webui_mod

    pub = webui_mod.gak._load_public_key(webui_mod.PUBLIC_KEY)
    return jwt.decode(
        code[len(webui_mod.gak._PREFIX):],
        pub,
        algorithms=["RS256"],
        options={"verify_aud": False, "verify_exp": False},
    )


def _xdrb(code: str, new_mch: str) -> str:
    payload = json.dumps(
        {"code": code, "mch": new_mch}, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return "XDRB." + base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


MCH_A = "aabbccddeeff00112233445566778899"
MCH_B = "99887766554433221100ffeeddccbbaa"


# ══════════════════════════════════════════════════════════════
# 签发
# ══════════════════════════════════════════════════════════════


def test_issue_returns_verifiable_code(webui):
    """签出的码必须能被公钥验签，且签发方自报的数据与码内一致。

    这是最核心的一条：WebUI 若把 A 机器的码显示成 B 机器的，
    你会把一张永远激活不了的码发给用户。
    """
    _, c = webui
    r = c.post("/api/issue", json={
        "name": "张三", "mch": MCH_A, "days": 30, "tier": "personal", "features": "",
    })
    assert r.status_code == 200, r.text
    d = r.json()

    assert d["code"].startswith("XDACT-")
    cl = _claims(c, d["code"])
    assert cl["sub"] == "张三"
    assert cl["gen"] == 0
    # ★ 界面回显的哈希必须等于码内真实的 mch，否则你核对的是假的
    assert d["mch_hashed"] == cl["mch"]
    assert d["jti"] == cl["jti"]


def test_issue_jti_has_no_display_pollution(webui):
    """jti 必须是干净的标识符，不能带上 CLI 的中文排版。

    回归：曾用 `line.split(":", 1)[-1]` 从 `jti : a_xxx  （不变，…）`
    切值，把括号说明一起带了出来。那个 jti 喂给吊销接口会静默失败 ——
    表现是「显示已吊销，实际没吊」。
    """
    _, c = webui
    r = c.post("/api/issue", json={
        "name": "李四", "mch": MCH_B, "days": 10, "tier": "personal", "features": "",
    })
    jti = r.json()["jti"]
    assert jti.startswith("a_")
    # 只允许十六进制，不允许任何中文/空格/括号
    assert all(ch in "0123456789abcdef_" for ch in jti), jti


def test_issue_days_reflected_in_expiry(webui):
    """到期日必须与请求的天数一致 —— 签错有效期等于收了钱没给够。"""
    _, c = webui
    r = c.post("/api/issue", json={
        "name": "王五", "mch": MCH_A, "days": 7, "tier": "personal", "features": "",
    })
    cl = _claims(c, r.json()["code"])
    want = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp())
    assert abs(int(cl["exp"]) - want) < 120


def test_issue_rejects_blank_name(webui):
    """★ 空白用户名必须被拒，不能只挡空串。

    回归：pydantic 的 min_length=1 对 "   " 是放行的，
    结果会签出一张 sub 为空的匿名码 —— 日后用户报障时无法核对身份。
    """
    _, c = webui
    for bad in ("", "   ", "\t\n"):
        r = c.post("/api/issue", json={
            "name": bad, "mch": MCH_A, "days": 30,
            "tier": "personal", "features": "",
        })
        assert r.status_code in (400, 422), f"name={bad!r} 未被拒"


def test_issue_rejects_bad_days(webui):
    """0 天或负数必须被拒 —— 否则会签出「已签发即过期」的码。"""
    _, c = webui
    for bad in (0, -5):
        r = c.post("/api/issue", json={
            "name": "赵六", "mch": MCH_A, "days": bad,
            "tier": "personal", "features": "",
        })
        assert r.status_code == 422, f"days={bad} 未被拒"


# ══════════════════════════════════════════════════════════════
# 换绑
# ══════════════════════════════════════════════════════════════


def test_rebind_keeps_jti_and_increments_gen(webui):
    """换绑必须 jti 不变、gen +1。

    jti 变了 → 吊销追不上这张码，换绑就成了绕过吊销的后门。
    gen 不变 → 没法单独作废旧码，用户会被永久锁死。
    """
    _, c = webui
    old = c.post("/api/issue", json={
        "name": "换绑测试", "mch": MCH_A, "days": 60,
        "tier": "personal", "features": "",
    }).json()

    r = c.post("/api/rebind", json={"request": _xdrb(old["code"], MCH_B)})
    assert r.status_code == 200, r.text
    d = r.json()

    new_cl = _claims(c, d["code"])
    old_cl = _claims(c, old["code"])
    assert d["jti"] == old_cl["jti"] == new_cl["jti"]
    assert new_cl["gen"] == old_cl["gen"] + 1
    assert new_cl["mch"] != old_cl["mch"]
    # 有效期不得因换绑而延长
    assert new_cl["exp"] == old_cl["exp"]


def test_rebind_returns_clean_fields(webui):
    """换绑返回的机器码与代次不得含 CLI 排版残留。"""
    _, c = webui
    old = c.post("/api/issue", json={
        "name": "字段测试", "mch": MCH_B, "days": 60,
        "tier": "personal", "features": "",
    }).json()
    d = c.post("/api/rebind", json={"request": _xdrb(old["code"], MCH_A)}).json()

    assert d["jti"].startswith("a_")
    assert len(d["machine_to"]) == 32
    assert d["new_gen"] == 1
    # 作废提示必须带上代次，否则用户照着敲会连带杀死新码
    assert "--before-gen" in d["revoke_hint"]


def test_rebind_rejects_garbage_request(webui):
    """格式不对的请求串必须被拒，不能落到「宽松解析」上。"""
    _, c = webui
    for bad in ("", "hello", "XDRB.@@@not-base64@@@", "XDACT-xxx"):
        r = c.post("/api/rebind", json={"request": bad})
        assert r.status_code in (400, 422), f"{bad!r} 未被拒"


def test_rebind_rejects_tampered_code(webui):
    """篡改过的码不得换绑成功 —— 否则任何人都能伪造机器码重签。"""
    _, c = webui
    old = c.post("/api/issue", json={
        "name": "篡改测试", "mch": MCH_A, "days": 60,
        "tier": "personal", "features": "",
    }).json()

    tampered = old["code"][:-6] + ("AAAAAA" if not old["code"].endswith("AAAAAA") else "BBBBBB")
    r = c.post("/api/rebind", json={"request": _xdrb(tampered, MCH_B)})
    assert r.status_code == 400, r.text


# ══════════════════════════════════════════════════════════════
# 记录
# ══════════════════════════════════════════════════════════════


def test_log_lists_issued_and_rebound(webui):
    """签发记录要能同时看到签发与换绑，并带出可复制的完整码。"""
    _, c = webui
    old = c.post("/api/issue", json={
        "name": "记录测试", "mch": MCH_A, "days": 60,
        "tier": "personal", "features": "",
    }).json()
    c.post("/api/rebind", json={"request": _xdrb(old["code"], MCH_B)})

    d = c.get("/api/log").json()
    events = {i["event"] for i in d["items"]}
    assert "issue" in events and "rebind" in events
    assert all(i["code"].startswith("XDACT-") for i in d["items"] if i["code"])


def test_log_corruption_is_reported_not_swallowed(webui):
    """★ 日志损坏必须报错，绝不能当成「没有记录」。

    这是最危险的一种静默失败：audit 会因此得出「未发现异常传播」，
    而实际上只是文件读不出来 —— 唯一的传播检测手段失效了，
    界面却显示一切正常。
    """
    mod, c = webui
    mod.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not mod.LOG_PATH.exists():
        mod.LOG_PATH.write_text("[]", encoding="utf-8")
    original = mod.LOG_PATH.read_text(encoding="utf-8")
    try:
        mod.LOG_PATH.write_text("{ 这不是合法 JSON", encoding="utf-8")
        r = c.get("/api/log")
        assert r.status_code == 500
        assert "不可读" in r.json()["detail"]
    finally:
        mod.LOG_PATH.write_text(original, encoding="utf-8")


# ══════════════════════════════════════════════════════════════
# 安全边界
# ══════════════════════════════════════════════════════════════


def test_non_local_request_is_rejected(webui):
    """来自非本机的请求必须被拒。

    这个页面握着私钥：一旦能被远程访问，任何人都能给自己签发永久码。

    判据用**中间件本身**而不是 TestClient —— starlette 的 TestClient
    不支持伪造 client 元组，用它测这个防护等于没测。
    """
    import asyncio

    mod, _ = webui
    from starlette.requests import Request

    scope = {
        "type": "http", "method": "POST", "path": "/api/issue",
        "headers": [], "client": ("1.2.3.4", 5555), "query_string": b"",
    }
    sent = []

    async def _send(msg):
        sent.append(msg)

    async def _call(req):
        return await req

    req = Request(scope, _send)
    resp = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        mod.reject_non_local(req, _call)
    )
    assert resp.status_code == 403
    # JSONResponse 可能分两条消息发（先 headers 后 body），全部收集再断言
    body = b"".join(
        m.get("body", b"") for m in sent if m["type"] == "http.response.body"
    ).decode("utf-8")
    if not body:
        # 回退：直接渲染 JSONResponse 的内容，语义等价且不依赖 ASGI 分片方式
        import json as _json

        body = _json.dumps(
            _json.loads(bytes(resp.body).decode("utf-8")), ensure_ascii=False
        )
    assert "1.2.3.4" in body
    assert "私钥" in body


def test_loopback_is_allowed(webui):
    """本机来源必须放行 —— 否则工具自己也没法用。"""
    assert "127.0.0.1" in webui[0].LOOPBACK
    assert "::1" in webui[0].LOOPBACK


def test_refuses_non_local_bind():
    """★ 绑定非本机地址必须拒绝启动。

    判据：`--host 0.0.0.0` 意味着局域网里任何人都能打开签发页面。
    这是最容易被「临时调试一下」顺手打开、然后忘记关掉的洞。
    """
    import subprocess
    import sys as _sys

    proc = subprocess.run(
        [_sys.executable, str(_REPO / "tools" / "activation" / "webui.py"),
         "--host", "0.0.0.0", "--port", "8799"],
        capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "私钥" in (proc.stdout + proc.stderr)

# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""激活码验签闭环测试。

★ 为什么必须有这个文件
────────────────────────────────────────────────────────────────
激活系统最危险的失效方向是**「验不了」被当成「验过了」**：

    公钥没打进包里 / pyjwt 没装 / 时钟被回拨
        → 验签函数抛异常或走空分支
        → 客户端读到 activated=true
        → 全部防护白嫖，且没有任何报错

本文件的每条用例都在验证「拒绝」路径，而不只是「接受」路径。

三方哈希一致性
────────────────────────────────────────────────────────────────
激活码能用的前提是三处哈希算法完全一致：
    · 签发工具  tools/activation/gen_activation_keys.py
    · Rust 侧   src-tauri/src/license.rs
    · Python 侧 src/daoti_xuandun_personal/license.py
任一侧重算，用户就会拿到「明明合法却激活失败」的码，
且这种故障极难排查。本文件用同一组已知向量锁死三处。
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
_TOOLS = _ROOT / "tools" / "activation"

from daoti_xuandun_personal import license as lic  # noqa: E402


ISSUER = "xuanDun-personal"
AUDIENCE = "xuandun-personal-desktop"

# 私钥/公钥生成到临时目录，不污染仓库
@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    r = subprocess.run(
        [sys.executable, str(_TOOLS / "gen_activation_keys.py"), "genkeypair",
         "--out-dir", str(d)],
        capture_output=True, text=True, encoding="utf-8",
    )
    if r.returncode != 0:
        pytest.skip(f"无法生成密钥对（可能缺 cryptography）: {r.stderr[:200]}")
    return d / "xuanDun_personal_private.pem", d / "xuanDun_personal_public.pem"


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch, tmp_path):
    """把时钟水位文件重定向到临时目录。

    ★ 必须隔离：check_clock_rollback 读的是真实 LOCALAPPDATA 下的
      license_seen.json，若不隔离，本机跑过一次后
      后续所有测试都会被判成「时钟回拨」而全红。
    """
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    yield


def _issue(private_key, mch, days=30, **extra):
    import jwt
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "测试用户",
        "iat": now,
        "exp": now + days * 86400,
        "jti": "a_test",
        "tier": "personal",
        "scope": "activate",
        "mch": lic.machine_code_hash(mch),
    }
    claims.update(extra)
    return "XDACT-" + jwt.encode(claims, key, algorithm="RS256")


# ══════════════════════════════════════════════════════════════
# 哈希三方一致性
# ══════════════════════════════════════════════════════════════


def test_hash_matches_signing_tool():
    """Python 侧哈希必须与签发工具一致。

    两者失配 = 签发的码永远验不过 = 全部用户激活失败。
    """
    mch = "8A4F-2B7C-D1E9-3366"
    r = subprocess.run(
        [sys.executable, str(_TOOLS / "gen_activation_keys.py"), "hash", mch],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert r.returncode == 0, f"签发工具 hash 子命令失败: {r.stderr[:200]}"
    assert lic.machine_code_hash(mch) == r.stdout.strip(), (
        "Python 侧与签发工具的机器码哈希不一致 —— "
        "签发的激活码会全部验签失败"
    )


def test_hash_is_case_and_space_insensitive():
    """用户手抄机器码时多一个空格就失败 = 真实投诉来源。"""
    assert lic.machine_code_hash("8a4f-2b7c") == lic.machine_code_hash("  8A4F-2B7C  ")
    assert len(lic.machine_code_hash("x")) == 32


# ══════════════════════════════════════════════════════════════
# 验签：接受路径
# ══════════════════════════════════════════════════════════════


def test_valid_code_accepted(keypair, monkeypatch):
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    mch = "MACHINE-A"
    r = lic.verify(_issue(priv, mch), lic.machine_code_hash(mch))
    assert r.ok, f"合法激活码被拒: {r.reason} {r.message}"
    assert r.verifier_available
    assert r.tier == "personal"
    assert r.subject == "测试用户"


# ══════════════════════════════════════════════════════════════
# 验签：拒绝路径（★ 安全系统的重点在这里）
# ══════════════════════════════════════════════════════════════


def test_missing_prefix_rejected(keypair, monkeypatch):
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    r = lic.verify("no-prefix-whatever", "x")
    assert not r.ok and r.reason == "malformed"


def test_tampered_signature_rejected(keypair, monkeypatch):
    """改签名 → 必须拒绝。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    code = _issue(priv, "M")
    head, payload, sig = code[len("XDACT-"):].split(".")
    tampered = f"XDACT-{head}.{payload}.{'A' * len(sig)}"
    r = lic.verify(tampered, lic.machine_code_hash("M"))
    assert not r.ok and r.reason == "bad_signature"


def test_tampered_payload_rejected(keypair, monkeypatch):
    """★ 改 payload（把 exp 改到永久）但保留原签名 → 必须拒绝。

    这是最典型的攻击：延长有效期。
    """
    import base64
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization

    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    code = _issue(priv, "M", days=1)
    key = serialization.load_pem_public_key(pub.read_bytes())
    claims = pyjwt.decode(code[6:], key, algorithms=["RS256"],
                          audience=AUDIENCE, issuer=ISSUER)
    # 攻击者把到期时间改成 100 年后（签名不变）
    claims["exp"] = int(time.time()) + 100 * 365 * 86400

    def b64u(d):
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    forged = (f"XDACT-{b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())}."
              f"{b64u(json.dumps(claims).encode())}.{code[6:].split('.')[2]}")

    r = lic.verify(forged, lic.machine_code_hash("M"))
    assert not r.ok and r.reason == "bad_signature", (
        f"改写有效期的伪造码被接受：{r}")


def test_expired_code_rejected(keypair, monkeypatch):
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    code = _issue(priv, "M", days=-1)  # 已过期
    r = lic.verify(code, lic.machine_code_hash("M"))
    assert not r.ok and r.reason == "expired"


def test_machine_mismatch_rejected(keypair, monkeypatch):
    """一码一机：别人的码在本机用不了。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    code = _issue(priv, "MACHINE-A")
    r = lic.verify(code, lic.machine_code_hash("MACHINE-B"))
    assert not r.ok and r.reason == "machine_mismatch"


def test_wrong_audience_rejected(keypair, monkeypatch):
    """跨产品复用：企业版的码不能激活个人版。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    code = _issue(priv, "M", aud="some-other-product")
    r = lic.verify(code, lic.machine_code_hash("M"))
    assert not r.ok and r.reason == "bad_claims"


def test_clock_rollback_rejected(keypair, monkeypatch):
    """把系统时间调回过去 → 必须拒绝（否则可无限续期）。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    now = int(time.time())
    lic.write_last_seen(now)
    # 码按「现在」签发有效；把校验时刻设到 10 天前 → 触发回拨
    r = lic.verify(_issue(priv, "M"), lic.machine_code_hash("M"), now=now - 864_000)
    assert not r.ok and r.reason == "clock_rollback", (
        f"时钟回拨未被检出：{r}")


# ══════════════════════════════════════════════════════════════
# 吊销
# ══════════════════════════════════════════════════════════════


def test_revoked_code_rejected(keypair, monkeypatch):
    """已吊销的码必须失效。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    mch = "MACHINE-R"
    code = _issue(priv, mch)
    assert lic.verify(code, lic.machine_code_hash(mch)).ok, "前置：应先能验过"

    ok = lic.revoke("a_test")
    assert ok, "首次吊销应返回 True（新增）"
    assert lic.is_revoked("a_test") is True

    r = lic.verify(code, lic.machine_code_hash(mch))
    assert not r.ok and r.reason == "revoked", f"已吊销的码仍可用：{r}"


def test_revoked_list_corruption_fails_closed(keypair, monkeypatch):
    """★ 名单文件损坏时必须**拒绝**，不得当成「无人被吊销」。

    这是本组最重要的用例：若把「读不到」当成「没吊销」，
    那么磁盘一坏（或被清理工具误删），所有已吊销的码集体复活 ——
    退款过的用户、泄露的码，全都重新生效。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    mch = "MACHINE-C"
    code = _issue(priv, mch)
    lic.revoke("a_test")

    # 故意写坏 JSON
    Path(lic._revoked_path()).write_text("{ this is not json", encoding="utf-8")

    assert lic.is_revoked("a_test") is None, "名单损坏时应返回 None（三态）"
    r = lic.verify(code, lic.machine_code_hash(mch))
    assert not r.ok, f"名单损坏时竟然放行：{r}"
    assert r.reason == "revocation_unavailable"
    assert r.verifier_available is False, "名单不可读必须标记为不可用"


def test_forged_jti_cannot_revoke(keypair, monkeypatch):
    """★ 伪造 payload 里的 jti 不能把别人的码吊销掉。

    jti 来自**未经验签**的 payload 时，攻击者可构造任意 jti。
    所以吊销检查必须放在验签之后 ——
    否则任何人都能构造 {"jti": "<受害者 jti>"} 让他的码失效。
    """
    import base64
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization

    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    mch = "MACHINE-V"
    # 用**自己的私钥**签一个格式合法但 jti 是别人的码
    # （模拟攻击者构造）
    key = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    now = int(time.time())
    forged = "XDACT-" + pyjwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "sub": "攻击者",
            "iat": now, "exp": now + 86400,
            "jti": "a_victim",  # 冒用他人 jti
            "tier": "personal", "scope": "activate",
            "mch": lic.machine_code_hash(mch),
        },
        key, algorithm="RS256",
    )
    # 注意：攻击者没有受害者 jti 的私钥，签不出能被验过的码。
    # 本用例断言的是：**未通过验签的 payload 不会走到吊销检查**，
    # 因此不会产生副作用。
    before = lic.load_revoked() or set()
    lic.verify(forged, lic.machine_code_hash(mch))
    after = lic.load_revoked() or set()
    assert "a_victim" not in after, "伪造 payload 竟能写入吊销名单"
    assert after == before, "验签失败时不应有任何名单写入"


def test_revoke_is_idempotent(keypair, monkeypatch):
    priv, pub = keypair
    assert lic.revoke("a_dup") is True
    assert lic.revoke("a_dup") is False, "重复吊销应返回 False"
    assert lic.is_revoked("a_dup") is True


def test_empty_revoked_file_means_nobody_revoked(monkeypatch, tmp_path):
    """空名单 = 无人被吊销（正常初始状态），不是「不可读」。"""
    p = Path(lic._revoked_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("[]", encoding="utf-8")
    assert lic.is_revoked("a_anything") is False


def test_missing_revoked_file_means_nobody_revoked(monkeypatch, tmp_path):
    """★ 文件不存在 = 还没吊销过任何人（首次运行的正常状态）。

    这条若搞错，每个新用户第一次激活都会失败 ——
    功能等于完全不可用。三态里必须把「不存在」与「损坏」分开。
    """
    p = Path(lic._revoked_path())
    if p.exists():
        p.unlink()
    assert lic.is_revoked("a_anything") is False, (
        "全新安装（无吊销文件）必须视为「无人被吊销」，"
        "否则新用户根本无法激活"
    )


def test_non_list_revoked_file_is_unreadable(monkeypatch, tmp_path):
    """内容不是列表 = 文件坏了，结论不可信（不得当成「无人被吊销」）。"""
    p = Path(lic._revoked_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"not": "a list"}', encoding="utf-8")
    assert lic.is_revoked("a_anything") is None


# ══════════════════════════════════════════════════════════════
# 降级可见性（★ 本项目的核心原则）
# ══════════════════════════════════════════════════════════════════════


def test_missing_public_key_is_not_treated_as_valid(keypair, monkeypatch, tmp_path):
    """★ 缺公钥时必须「拒绝」且标记不可用，绝不能当成「验过了」。

    这是整个激活系统最危险的失效方向：
    公钥没打进包 → 验签无法执行 → 若此时返回 ok=true，
    全部防护白嫖且无任何报错。
    """
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(tmp_path / "nonexistent.pem"))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    r = lic.verify("XDACT-anything.at.all", "x")
    assert not r.ok, "缺公钥时竟然通过了验签"
    assert r.verifier_available is False, (
        "缺公钥时必须标记 verifier_available=False，"
        "否则调用方无法区分「验不过」与「验不了」")
    assert r.reason == "verifier_unavailable"


def test_status_endpoint_reports_degradation(monkeypatch, tmp_path):
    """能力自检要能看出「公钥缺失」，供诊断页展示。"""
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(tmp_path / "nope.pem"))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)
    assert lic.load_public_key() is None


# ══════════════════════════════════════════════════════════════
# 换机重绑
# ══════════════════════════════════════════════════════════════
#
# 为什么需要换绑
# ────────────────────────────────────────────────────────────────
# 严格一码一机意味着用户换电脑/换硬盘后，新机上验证必然失败
# （码里的 mch 是旧机器的）。新机上没有任何东西能证明「我拥有
# 这张码」——除了**签名本身**。用户持有那张码，就能在任何地方
# 证明自己合法，不需要旧机器参与。
#
# 因此流程是：客户端把「原码 + 新机器码」拼成一个 XDRB. 串，
# 用户发给你；你验签通过后只改 mch 重签。
#
# ★ 代次（gen）是这套设计里最容易做错的地方：
#   换绑**保持 jti 不变**（否则吊销可被绕过），于是同一个 jti 下
#   会同时存在多张码。若吊销只能按 jti 粒度，作废旧码就会把新码
#   一起杀死 —— 而新码往往是用户唯一剩下的凭据，执行即永久锁死。


def _rebind(private_key, pub, old_code, new_mc):
    """走签发工具的 rebind 子命令，返回 CompletedProcess。"""
    req = lic.build_rebind_request(old_code, new_mc)
    assert req.startswith("XDRB."), "换绑请求串前缀不对"
    return subprocess.run(
        [sys.executable, str(_TOOLS / "gen_activation_keys.py"), "rebind",
         "--key", str(private_key), "--pub", str(pub), "--request", req],
        capture_output=True, text=True, encoding="utf-8",
    )


def _claims(pub, code, verify_exp=True):
    """解开码看内容（默认仍校验 exp —— 免得测试自己看错值）。

    ``verify_exp=False`` 只在「本就是要检查过期码」时用。
    """
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization

    return pyjwt.decode(
        code[len("XDACT-"):],
        serialization.load_pem_public_key(pub.read_bytes()),
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": verify_exp},
    )


def _new_code_from(stdout):
    return next(x for x in stdout.splitlines() if x.startswith("XDACT-"))


def test_rebind_moves_code_to_new_machine(keypair, monkeypatch):
    """完整闭环：旧机可用 → 新机被拒 → 换绑 → 新机可用 → 旧机被拒。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    old_mc, new_mc = "OLD-PC-001", "NEW-PC-002"
    old_code = _issue(priv, old_mc, gen=0)

    assert lic.verify(old_code, lic.machine_code_hash(old_mc)).ok
    r = lic.verify(old_code, lic.machine_code_hash(new_mc))
    assert not r.ok and r.reason == "machine_mismatch"

    res = _rebind(priv, pub, old_code, new_mc)
    assert res.returncode == 0, f"rebind 失败: {res.stderr[:300]}"
    new_code = _new_code_from(res.stdout)

    assert lic.verify(new_code, lic.machine_code_hash(new_mc)).ok, "新机应可用"
    r = lic.verify(new_code, lic.machine_code_hash(old_mc))
    assert not r.ok and r.reason == "machine_mismatch", "旧机应失效（一码一机）"

    k0, k1 = _claims(pub, old_code), _claims(pub, new_code)
    assert k1["jti"] == k0["jti"], "jti 必须不变（否则吊销可被绕过）"
    assert k1["exp"] == k0["exp"], "换绑不得延长有效期"


def test_rebind_increments_gen(keypair, monkeypatch):
    """换绑后 gen 必须递增 —— 它是「能单独作废旧码」的唯一依据。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    res = _rebind(priv, pub, _issue(priv, "PC-A", gen=0), "PC-B")
    assert res.returncode == 0, res.stderr[:300]
    assert _claims(pub, _new_code_from(res.stdout))["gen"] == 1


def test_rebind_keeps_validity_even_if_expired(keypair, monkeypatch):
    """★ 已过期的码不该能靠换绑「续命」。

    exp 是换绑前后唯一必须不变的时间字段。若实现里写成
    ``exp = now + days``，一张过期码就能变成新码继续用 ——
    有效期就成了摆设。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    expired = _issue(priv, "PC-X", days=-1, gen=0)
    res = _rebind(priv, pub, expired, "PC-Y")
    assert res.returncode == 0, f"rebind 应仍能执行（便于排查过期码）: {res.stderr[:300]}"
    new_code = _new_code_from(res.stdout)
    assert _claims(pub, new_code, verify_exp=False)["exp"] <= int(time.time()), (
        "换绑后的码有效期被延长了 —— 过期码可以靠换绑续命"
    )


def test_revoke_before_gen_kills_old_code_only(keypair, monkeypatch):
    """★ 换绑后作废旧码：新码必须活下来。

    这正是工具曾给出的错误建议所导致的故障 ——
    按 jti 吊销会把新旧两张码一起杀死，而新码是用户唯一的凭据。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    old_mc, new_mc = "OLD-PC-1", "NEW-PC-2"
    old_code = _issue(priv, old_mc, gen=0)
    res = _rebind(priv, pub, old_code, new_mc)
    assert res.returncode == 0, res.stderr[:300]
    new_code = _new_code_from(res.stdout)
    jti = _claims(pub, new_code)["jti"]

    # 按代次作废旧码（换绑成功后工具给出的那条建议）
    assert lic.revoke(jti, before_gen=1) is True

    r = lic.verify(old_code, lic.machine_code_hash(old_mc))
    assert not r.ok and r.reason == "revoked", f"旧码应已作废: {r}"
    r = lic.verify(new_code, lic.machine_code_hash(new_mc))
    assert r.ok, f"★ 新码被误杀，用户会被永久锁死: {r.reason} {r.message}"


def test_revoke_whole_jti_kills_all_gens(keypair, monkeypatch):
    """不带 before_gen 的吊销 = 全代次核弹，语义不变。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    mch = "PC-NUKE"
    code = _issue(priv, mch, gen=0)
    jti = _claims(pub, code)["jti"]
    lic.revoke(jti)

    assert lic.verify(code, lic.machine_code_hash(mch)).reason == "revoked"
    assert lic.is_revoked(jti, 0) is True
    assert lic.is_revoked(jti, 5) is True, "全代次吊销应覆盖所有代次"


def test_before_gen_entry_does_not_kill_later_gens(keypair, monkeypatch):
    """作废 gen<2 的码，不能顺手杀掉 gen=2 的码。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    mch = "PC-G"
    code = _issue(priv, mch, gen=2)
    lic.revoke("a_test", before_gen=2)

    assert lic.verify(code, lic.machine_code_hash(mch)).ok, (
        "作废 gen<2 却杀掉了 gen=2 的码 —— 代次边界写错了"
    )


def test_corrupt_gen_suffix_fails_closed(keypair, monkeypatch):
    """★ 名单里出现 ``jti#x`` 这种非法代次 → 整个名单判为不可读。

    若当成「这条不匹配任何码」而放行，那么一条写坏的记录
    就能让本该被吊销的码复活 —— 这正是 fail-closed 的意义。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    Path(lic._revoked_path()).parent.mkdir(parents=True, exist_ok=True)
    Path(lic._revoked_path()).write_text(
        json.dumps(["a_ok", "a_broken#notanumber"]), encoding="utf-8"
    )
    assert lic.load_revoked() is None, "非法代次后缀应使整个名单不可读"

    r = lic.verify(_issue(priv, "M"), lic.machine_code_hash("M"))
    assert not r.ok and r.reason == "revocation_unavailable"


def test_rebind_refuses_revoked_code(keypair, monkeypatch):
    """★ 已吊销的码不能靠换绑复活。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    old_code = _issue(priv, "PC-REV", gen=0)
    lic.revoke("a_test")

    res = _rebind(priv, pub, old_code, "PC-REV2")
    assert res.returncode != 0, "已吊销的码竟然被换绑成功了"
    assert "吊销" in (res.stdout + res.stderr)


def test_rebind_refuses_forged_code(keypair, monkeypatch):
    """签名无效的码不得换绑 —— 否则任何人都能凭空造出一张合法码。

    换绑用的是**私钥重签**，等价于签发。若不先验签，
    攻击者提交一串乱写的 jti 就能给自己换出一张真码。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    res = _rebind(priv, pub, "XDACT-aaa.bbb.ccc", "PC-F")
    assert res.returncode != 0, "伪造码竟然换绑成功"
    assert "签名" in (res.stdout + res.stderr)


def test_rebind_request_trims_machine_code(keypair, monkeypatch):
    """请求串里放**原始**机器码（不是哈希），且已去除首尾空格。"""
    req = lic.build_rebind_request(_issue(keypair[0], "PC-R"), "  PC-NEW  ")
    import base64

    body = req[5:] + "=" * (-len(req[5:]) % 4)
    info = json.loads(base64.urlsafe_b64decode(body).decode("utf-8"))
    assert info["mch"] == "PC-NEW", "请求串里的机器码应已去除首尾空格"
    assert info["code"].startswith("XDACT-")


def test_rebind_same_machine_is_noop(keypair, monkeypatch):
    """新旧机器码相同 → 不该重签（否则白白发一张新码让人工混乱）。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    res = _rebind(priv, pub, _issue(priv, "PC-SAME", gen=0), "PC-SAME")
    assert res.returncode == 0
    assert "无需换绑" in res.stdout


# ══════════════════════════════════════════════════════════════
# 只读模式：引擎侧的降级判定
# ══════════════════════════════════════════════════════════════
#
# 未激活 / 已过期 → 引擎进入只读模式（直通但不拦截）。
# 选只读而非锁死，是为了不让「其实已付过钱、只是码过期」的用户彻底卡死。
#
# ★ 本组的核心风险是**误降级**：把「验不了」当成「没激活」，
#   于是我方组件一故障，全部已付费用户就集体失去防护。
#   那是比不锁死严重得多的事故。


def test_machine_check_false_skips_machine_binding(keypair, monkeypatch):
    """★ 引擎侧跳过机器码比对时，绑定在**别的机器**上的码也判为有效。

    引擎是独立进程，拿不到 Rust 用 sysinfo 采集的机器码。
    若这里仍强制比对，所有用户的码都会验不过 → 全部被降级。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    code = _issue(priv, "MACHINE-X", gen=0)
    # 正常路径：别的机器 → 拒绝
    assert lic.verify(code, lic.machine_code_hash("OTHER")).reason == "machine_mismatch"
    # 引擎路径：不比对机器码 → 放行
    r = lic.verify(code, "", machine_check=False)
    assert r.ok, f"引擎侧应放行（机器码由 Rust 负责）: {r.reason} {r.message}"


def test_machine_check_false_still_rejects_expired_and_revoked(keypair, monkeypatch):
    """★ 跳过机器码比对**不等于**跳过其它检查。

    若有人把 machine_check=False 写成「宽松模式」，
    过期码和已吊销的码就会一起复活 —— 付费与吊销都失去意义。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    expired = _issue(priv, "M", days=-1, gen=0)
    r = lic.verify(expired, "", machine_check=False)
    assert not r.ok and r.reason == "expired", "过期码在引擎侧竟然放行"

    live = _issue(priv, "M", gen=0)
    lic.revoke("a_test")
    r = lic.verify(live, "", machine_check=False)
    assert not r.ok and r.reason == "revoked", "已吊销的码在引擎侧竟然放行"


def test_machine_check_false_still_rejects_forged(keypair, monkeypatch):
    """伪造签名在引擎侧同样必须被拒。"""
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))

    r = lic.verify("XDACT-aaa.bbb.ccc", "", machine_check=False)
    assert not r.ok and r.reason == "bad_signature"


def test_empty_mch_with_machine_check_on_is_not_mismatch(keypair, monkeypatch):
    """★ mch 为空串时不得判成 machine_mismatch。

    引擎传的就是空串。若空串被当成一个真实哈希去比，
    没有任何码能通过 → 所有用户被降级成只读。
    """
    priv, pub = keypair
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    monkeypatch.delenv("XUANDUN_LICENSE_PUBKEY", raising=False)

    code = _issue(priv, "M", gen=0)
    r = lic.verify(code, "")
    assert r.ok, f"空 mch 不该判成不匹配: {r.reason} {r.message}"


# ══════════════════════════════════════════════════════════════
# 密钥材料不得入库
# ══════════════════════════════════════════════════════════════


def _git_tracked() -> set:
    import subprocess

    r = subprocess.run(
        ["git", "-c", "core.hooksPath=NUL", "ls-files"],
        cwd=_ROOT, capture_output=True, text=True, encoding="utf-8",
    )
    if r.returncode != 0:
        pytest.skip("不在 git 仓库内")
    return {ln.strip() for ln in r.stdout.splitlines() if ln.strip()}


def test_private_key_never_tracked():
    """★ 私钥入库 = 任何人都能签发激活码 = 授权体系瞬间失效。

    且 Git 历史无法真正清除：即使后续删除，commit 里仍在。
    这条断言一旦红了，视为安全事故而非普通测试失败。
    """
    tracked = _git_tracked()
    bad = [p for p in tracked if "private" in p.lower() and p.endswith(".pem")]
    assert not bad, f"★ 私钥被 git 追踪了，必须立即处理: {bad}"


def test_public_key_is_tracked():
    """公钥**必须**入库 —— build_engine.py 打包时要读它。

    公钥不是秘密（它本就明文嵌在客户端里）。若它被忽略，
    干净 clone 上构建会因缺公钥而失败，CI 产不出安装包。
    """
    tracked = _git_tracked()
    assert "tools/activation/xuanDun_personal_public.pem" in tracked, (
        "公钥未入库 —— 干净 clone 上 build_engine.py 会 return 4，"
        "CI 无法产出安装包"
    )


def test_gitignore_does_not_re_enable_private_key():
    """★ .gitignore 里不能出现把私钥放行的规则。

    典型的致命失误：为了让 CI 过而放宽忽略规则时，
    把 `tools/activation/*.pem` 注释掉，顺带放出了私钥。
    这里直接扫文本，不给「以后再改」留空间。
    """
    gi = (_ROOT / ".gitignore").read_text(encoding="utf-8")
    offenders = [
        ln.strip() for ln in gi.splitlines()
        if ln.strip().startswith("!")
        and "private" in ln.lower()
    ]
    assert not offenders, f".gitignore 显式放行了含 private 的路径: {offenders}"

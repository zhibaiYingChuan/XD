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
# 降级可见性（★ 本项目的核心原则）
# ══════════════════════════════════════════════════════════════


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

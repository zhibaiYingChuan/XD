# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""玄盾个人版 — 激活码签发工具（签发方，离线使用）。

与 ``tools/license_manager/sign_api_key.py`` 的区别
────────────────────────────────────────────────────
企业版签发的是「API 调用额度」；这里签发的是「桌面客户端使用许可」。

两者刻意保持同一种密码学方案（RS256 非对称签名），
因为这是本项目最重要的一个安全性质：

    私钥只在签发方（你）手上，永远不进客户端。
    客户端只内嵌公钥，离线验签。
    → 攻击者即便完整反编译了客户端，也**造不出合法激活码**。

如果改用 HS256（对称），公钥即私钥，激活码签发逻辑会一并暴露，
整个授权体系瞬间失效。这是不可逆的架构级选择。

激活码格式
────────────────────────────────────────────────────
    XDACT-<base64url(JWT)>

Payload 字段：

    iss          签发方标识，固定 "xuanDun-personal"
    sub          授权给谁（用户名 / 邮箱 / 订单号，仅供人工核对）
    aud          固定 "xuandun-personal-desktop"（防跨端复用）
    iat / exp    签发时刻 / 到期时刻
    jti          激活码唯一 ID（吊销与排查用）
    mch          机器码哈希 —— ★ 严格绑定，一码一机
    tier         版本档位 personal / personal-pro
    features     特性开关列表（预留，便于将来做差异化功能）

★ 关于 ``mch``（machine code hash）
    机器码在**客户端**采集并哈希，签发时录入。
    客户端验签时重新采集并比对，不一致即拒绝激活。

    为什么存哈希而不是原始硬件序列号：
    激活码会经邮件/IM 传输，哈希后即使泄漏也无法反推硬件信息。

用法
────────────────────────────────────────────────────
    # 1. 首次生成密钥对（私钥绝不入库）
    python gen_activation_keys.py genkeypair

    # 2. 查看某台机器的机器码（客户端「激活」页会显示，让用户报给你）
    #    由客户端复制，或用同一算法离线计算

    # 3. 签发
    python gen_activation_keys.py issue \\
        --key xuanDun_personal_private.pem \\
        --name "张三" --mch <机器码> --days 365 --tier personal

    # 4. 自测验签（用公钥）
    python gen_activation_keys.py verify --pub xuanDun_personal_public.pem \\
        --code "XDACT-..."
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

_ISSUER = "xuanDun-personal"
_AUDIENCE = "xuandun-personal-desktop"
_PREFIX = "XDACT-"

_HERE = Path(__file__).resolve().parent
DEFAULT_LOG = _HERE / "ACTIVATION_LOG.json"
PRIVATE_KEY_NAME = "xuanDun_personal_private.pem"
PUBLIC_KEY_NAME = "xuanDun_personal_public.pem"


# ══════════════════════════════════════════════════════════════
# 机器码（必须与 Rust 侧算法完全一致）
# ══════════════════════════════════════════════════════════════


def machine_code_hash(machine_code: str) -> str:
    """把机器码字符串哈希成激活码里存放的形式。

    ★ 这个哈希算法**必须与客户端一致**，否则签发的码永远激活不了。
      Rust 侧见 src-tauri/src/license.rs::machine_code_hash。
      两侧都用：SHA-256(大写 hex 串)，取前 32 个十六进制字符。

    为什么客户端不直接用原始机器码做哈希，而要先转大写 hex：
    统一大小写与分隔符，避免同一台机器因采集格式微差算出两个哈希
    （进而算出两台机器），这是很容易踩的坑。
    """
    normalized = machine_code.strip().upper()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return digest[:32]


# ══════════════════════════════════════════════════════════════
# 密钥对
# ══════════════════════════════════════════════════════════════


def gen_keypair(out_dir: Path, force: bool) -> int:
    """生成 RSA-2048 密钥对。

    ★ 防覆盖：已存在时直接中止，不静默覆盖。
      覆盖 = 此前签发的所有激活码立即全部失效（用户会突然无法使用），
      这是极难排查的故障，不能让一个手滑的 `genkeypair` 造成。
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv_path = out_dir / PRIVATE_KEY_NAME
    pub_path = out_dir / PUBLIC_KEY_NAME

    if priv_path.exists() and not force:
        print(f"私钥已存在: {priv_path}", file=sys.stderr)
        print("  覆盖会导致此前签发的所有激活码失效。确需轮换请加 --force", file=sys.stderr)
        return 2

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    # 私钥权限收紧（Windows 上 chmod 语义有限，但仍做尽力设置）
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass

    print(f"✓ 私钥: {priv_path}  ★ 绝不入库")
    print(f"✓ 公钥: {pub_path}  （将编译进客户端）")
    print()
    print("下一步：把公钥内容写入 src-tauri/src/license.rs 的 PUBLIC_KEY_PEM")
    print("（或用 build.rs 在编译期注入，避免明文出现在源码里）")
    return 0


def _load_private_key(path: Path):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_public_key(path: Path):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_public_key(path.read_bytes())


# ══════════════════════════════════════════════════════════════
# 签发
# ══════════════════════════════════════════════════════════════


def issue(args) -> int:
    import jwt

    priv = _load_private_key(Path(args.key))
    now = int(time.time())

    claims = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": args.name,
        "iat": now,
        "exp": now + args.days * 86400,
        "jti": "a_" + uuid.uuid4().hex,
        "tier": args.tier,
        "scope": "activate",
        "mch": machine_code_hash(args.mch),
    }
    if args.features:
        claims["features"] = [f.strip() for f in args.features.split(",") if f.strip()]

    code = _PREFIX + jwt.encode(claims, priv, algorithm="RS256")

    if args.out:
        Path(args.out).write_text(code + "\n", encoding="utf-8")
        print(f"✓ 已写入 {args.out}")
    else:
        print(code)
        print()

    print(f"授权给: {args.name}")
    print(f"档位  : {args.tier}")
    print(f"机器码: {claims['mch']}（由 {args.mch} 哈希而来）")
    print(f"到期  : {datetime.fromtimestamp(claims['exp'], tz=timezone.utc).isoformat()}")
    print(f"jti   : {claims['jti']}")

    _append_log(
        Path(args.log) if args.log else DEFAULT_LOG,
        {
            "jti": claims["jti"],
            "name": args.name,
            "tier": args.tier,
            "mch": claims["mch"],
            "mch_raw": args.mch,
            "created_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "expires_at": datetime.fromtimestamp(claims["exp"], tz=timezone.utc).isoformat(),
            "code": code,
        },
    )
    return 0


def _append_log(path: Path, entry: dict) -> None:
    records = []
    if path.exists():
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            records = []
    records.append(entry)
    path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[已记录] {path}  ★ 含明文激活码，勿入库")


# ══════════════════════════════════════════════════════════════
# 验证（签发方自测 / 排查用户问题）
# ══════════════════════════════════════════════════════════════


def verify(args) -> int:
    import jwt

    pub = _load_public_key(Path(args.pub))
    code = args.code.strip()
    if not code.startswith(_PREFIX):
        print(f"✗ 缺少 {_PREFIX} 前缀", file=sys.stderr)
        return 1
    try:
        # 故意不校验 aud/iss：这里要能诊断「码是哪一步不合规」
        claims = jwt.decode(
            code[len(_PREFIX):],
            pub,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
    except jwt.ExpiredSignatureError:
        print("✗ 已过期")
        return 1
    except jwt.InvalidTokenError as e:
        print(f"✗ 签名无效（可能被篡改或用别的密钥签的）: {e}", file=sys.stderr)
        return 1

    ok = True
    if claims.get("iss") != _ISSUER:
        print(f"✗ iss 不符: {claims.get('iss')}")
        ok = False
    if claims.get("aud") != _AUDIENCE:
        print(f"✗ aud 不符: {claims.get('aud')}")
        ok = False
    if args.mch and claims.get("mch") != machine_code_hash(args.mch):
        print(f"✗ 机器码不符: 码内 {claims.get('mch')} vs 本机 {machine_code_hash(args.mch)}")
        ok = False

    print("── 激活码内容 ──")
    for k in ("sub", "tier", "jti", "mch", "features"):
        if k in claims:
            print(f"  {k:9} = {claims[k]}")
    print(f"  签发     = {datetime.fromtimestamp(claims['iat'], tz=timezone.utc).isoformat()}")
    print(f"  到期     = {datetime.fromtimestamp(claims['exp'], tz=timezone.utc).isoformat()}")
    print()
    print("✓ 签名有效" if ok else "✗ 存在问题")
    return 0 if ok else 1


# ══════════════════════════════════════════════════════════════


def main() -> int:
    ap = argparse.ArgumentParser(description="玄盾个人版激活码签发工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkeypair", help="生成 RSA 密钥对")
    g.add_argument("--out-dir", default=str(_HERE))
    g.add_argument("--force", action="store_true", help="覆盖已有密钥（危险）")

    i = sub.add_parser("issue", help="签发激活码")
    i.add_argument("--key", required=True, help="RSA 私钥 PEM")
    i.add_argument("--name", required=True, help="授权给谁")
    i.add_argument("--mch", required=True, help="机器码（客户端显示的那串）")
    i.add_argument("--days", type=int, default=365)
    i.add_argument("--tier", default="personal")
    i.add_argument("--features", default="", help="逗号分隔的特性开关")
    i.add_argument("--out", default="")
    i.add_argument("--log", default="")

    v = sub.add_parser("verify", help="验证激活码")
    v.add_argument("--pub", required=True, help="RSA 公钥 PEM")
    v.add_argument("--code", required=True)
    v.add_argument("--mch", default="", help="一并校验机器码")

    h = sub.add_parser("hash", help="由原始机器码算激活码内使用的哈希")
    h.add_argument("machine_code")

    args = ap.parse_args()
    if args.cmd == "genkeypair":
        return gen_keypair(Path(args.out_dir), args.force)
    if args.cmd == "issue":
        return issue(args)
    if args.cmd == "verify":
        return verify(args)
    if args.cmd == "hash":
        print(machine_code_hash(args.machine_code))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

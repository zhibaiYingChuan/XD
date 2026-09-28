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
        "gen": 0,
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
            "gen": claims.get("gen", 0),
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
# 吊销
# ══════════════════════════════════════════════════════════════


def rebind(args) -> int:
    """换机重签：同一张码换一个机器码，保持 jti/有效期/档位不变。

    为什么需要
    ────────────────────────────────────────────────────────────
    严格一码一机意味着用户换电脑/换硬盘后，
    新机器上验证必然失败（码里的 mch 是旧机器的）。
    纯客户端无法自助完成 —— 新机器上没有任何能证明「我拥有这张码」
    的东西，除了**签名本身**。

    ★ 关键认识：一张通过验签的码，其签名就是所有权证明。
      用户持有它，就能在任何地方证明自己合法，
      不需要旧机器参与。所以换绑只需「旧码 + 新机器码」两个字符串。

    保持 jti 不变的意义：
      · 吊销名单按 jti 索引，换绑后仍能被正确吊销
      · 出问题时能追溯到同一张订单
      · 避免「换绑成为绕过吊销的后门」——
        若换绑换新 jti，被吊销的码换个机器就复活了

    用法
    ────────────────────────────────────────────────────────────
        # 客户端会给出换绑请求串，直接粘贴即可
        python gen_activation_keys.py rebind --pub <公钥> --request "<请求串>"
    """
    import jwt

    pub = _load_public_key(Path(args.pub))

    # 解析客户端给出的请求串：XDRB.<base64url(json)>
    raw = args.request.strip()
    if not raw.startswith("XDRB."):
        print(
            "✗ 请求串格式不对（应以 XDRB. 开头）\n"
            "  从客户端「激活」页复制完整的换绑请求串",
            file=sys.stderr,
        )
        return 1
    import base64

    body = raw[5:]
    body += "=" * (-len(body) % 4)
    try:
        info = json.loads(base64.urlsafe_b64decode(body).decode("utf-8"))
    except Exception as e:
        print(f"✗ 无法解析请求串: {e}", file=sys.stderr)
        return 1

    old_code = str(info.get("code", ""))
    new_mch_raw = str(info.get("mch", ""))
    if not old_code.startswith(_PREFIX):
        print("✗ 请求串中缺少有效的原激活码", file=sys.stderr)
        return 1
    if not new_mch_raw:
        print("✗ 请求串中缺少新机器码", file=sys.stderr)
        return 1

    # ★ 必须验签通过才允许换绑：
    #   否则任何人都能拿一个乱写的 jti 来换绑
    try:
        claims = jwt.decode(
            old_code[len(_PREFIX):], pub, algorithms=["RS256"],
            options={"verify_aud": False, "verify_exp": False},
        )
    except jwt.InvalidTokenError as e:
        print(f"✗ 原激活码签名无效，拒绝换绑: {e}", file=sys.stderr)
        return 1

    if claims.get("iss") != _ISSUER:
        print(f"✗ iss 不符: {claims.get('iss')}", file=sys.stderr)
        return 1

    new_mch = machine_code_hash(new_mch_raw)
    old_mch = str(claims.get("mch", ""))
    if new_mch == old_mch:
        print("· 新旧机器码相同，无需换绑")
        return 0

    # 检查是否已被吊销 —— 换绑不能成为绕过吊销的后门
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
    try:
        from daoti_xuandun_personal import license as lic

        # ★ 按**原码的代次**查：若这张码已被作废（gen 0 写了 jti#1），
        #   就不该再拿它换绑出新码 —— 那等于复活一张已死的码。
        old_gen = int(claims.get("gen", 0) or 0)
        if lic.is_revoked(str(claims.get("jti", "")), old_gen) is True:
            print(f"✗ 该激活码已被吊销，拒绝换绑", file=sys.stderr)
            print("  （换绑不改 jti，所以吊销状态依然有效）", file=sys.stderr)
            return 1
    except ImportError:
        print("[WARN] 无法导入 license 模块，跳过吊销检查")

    # 重新签发：只改 mch，jti/exp/sub/tier 全部保持
    new_claims = dict(claims)
    new_claims["mch"] = new_mch
    # ★ gen 递增：这是「能单独作废旧码」的唯一依据。
    #   jti 不变 + gen 递增 → 吊销可以精确到代次。
    new_claims["gen"] = int(claims.get("gen", 0) or 0) + 1
    # iat 刷新为当前时刻（便于排查换绑发生时间），exp 不变
    new_claims["iat"] = int(time.time())

    private_key = _load_private_key(Path(args.key))
    new_code = _PREFIX + jwt.encode(new_claims, private_key, algorithm="RS256")

    new_gen = int(new_claims["gen"])

    print(new_code)
    print()
    print(f"授权给  : {claims.get('sub')}")
    print(f"档位    : {claims.get('tier')}")
    print(f"jti     : {claims.get('jti')}  （不变，吊销仍有效）")
    print(f"代次    : {claims.get('gen', 0)} → {new_gen}")
    print(f"机器码  : {old_mch} → {new_mch}")
    print(
        f"到期    : {datetime.fromtimestamp(claims['exp'], tz=timezone.utc).isoformat()}"
        f"  （不变）"
    )
    print()
    print("★ 下一步：让用户把新码重新粘贴进客户端。若旧码可能外泄，")
    print("  单独作废旧码（只杀 gen < 新代次，新码不受影响）：")
    print(f"  python gen_activation_keys.py revoke {claims.get('jti')} --before-gen {new_gen}")

    # ★ 换绑必须记日志 —— 它是「码在传播」的唯一直接信号。
    #   不记的话，下面的 audit 子命令看不见任何换绑痕迹，
    #   而换绑次数正是判断「一张码被几个人用」的核心依据。
    _append_log(
        Path(args.log) if getattr(args, "log", "") else DEFAULT_LOG,
        {
            "jti": claims.get("jti"),
            "gen": new_gen,
            "name": claims.get("sub"),
            "tier": claims.get("tier"),
            "mch": new_mch,
            "mch_raw": new_mch_raw,
            "event": "rebind",
            "from_mch": old_mch,
            "from_gen": int(claims.get("gen", 0) or 0),
            "created_at": datetime.fromtimestamp(
                int(new_claims["iat"]), tz=timezone.utc
            ).isoformat(),
            "expires_at": datetime.fromtimestamp(
                claims["exp"], tz=timezone.utc
            ).isoformat(),
            "code": new_code,
        },
    )
    return 0


def audit(args) -> int:
    """签发日志异常检测 —— 「码是否在被传播」的唯一可见手段。

    ★★ 为什么这是整个体系里最有用的一环
    ────────────────────────────────────────────────────────────
    客户端校验防不住破解（校验发生在用户机器上，用户拥有那台机器）。
    所以真正的防线不在客户端，而在这里 —— **签发方掌握全部真相**：

        一张码被换绑到第 3 台机器 = 极可能已被传播
        同一个码短时间多次换绑     = 有人在批量薅
        已吊销的码之后又出现换绑   = 有人拿废码试

    这三类信号客户端一个都给不出，只有签发日志能看见。

    ★ 判据用「阈值」而不是「有一处异常就报」：
      正常用户一年可能换一次机（换硬盘、系统重装）。
      阈值定太低会把正常用户报成异常，报了也没人看 ——
      **一个永远在报警的告警等于没有告警**。
    """
    path = Path(args.log) if args.log else DEFAULT_LOG
    if not path.exists():
        print(f"（尚无签发日志：{path}）")
        print("  签发第一张码后即可用本命令审计传播情况。")
        return 0

    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"✗ 签发日志不可读（{e}）: {path}", file=sys.stderr)
        print("  日志损坏会让传播检测失效 —— 别当成「没有异常」。", file=sys.stderr)
        return 1

    if not isinstance(records, list):
        print(f"✗ 签发日志格式异常（不是列表）: {path}", file=sys.stderr)
        return 1

    # 按 jti 聚合：换绑次数、涉及机器数、是否已被吊销
    by_jti: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        jti = str(rec.get("jti", "")).strip()
        if not jti:
            continue
        info = by_jti.setdefault(
            jti,
            {
                "name": rec.get("name", "?"),
                "issued": 0,
                "rebinds": 0,
                "machines": set(),
                "first": rec.get("created_at", ""),
                "last": rec.get("created_at", ""),
                "events": [],
            },
        )
        event = rec.get("event", "issue")
        if event == "rebind":
            info["rebinds"] += 1
        else:
            info["issued"] += 1
        mch = str(rec.get("mch", "")).strip()
        if mch:
            info["machines"].add(mch)
        ts = str(rec.get("created_at", ""))
        if ts:
            if not info["first"] or ts < info["first"]:
                info["first"] = ts
            if ts > info["last"]:
                info["last"] = ts
        info["events"].append((ts, event, mch))

    try:
        from daoti_xuandun_personal import license as lic

        revoked = lic.load_revoked() or set()
    except Exception:
        revoked = set()

    total_codes = len(by_jti)
    total_rebinds = sum(v["rebinds"] for v in by_jti.values())

    print("=" * 68)
    print("  签发日志审计 —— 传播情况")
    print("=" * 68)
    print(f"  日志: {path}")
    print(f"  激活码: {total_codes} 张    换绑: {total_rebinds} 次")
    print()

    alerts = []
    for jti, info in by_jti.items():
        reasons = []
        if len(info["machines"]) > args.max_machines:
            reasons.append(
                f"绑定了 {len(info['machines'])} 台机器"
                f"（阈值 {args.max_machines}）—— 极可能已传播"
            )
        if info["rebinds"] > args.max_rebinds:
            reasons.append(
                f"换绑 {info['rebinds']} 次（阈值 {args.max_rebinds}）"
                f"—— 疑似批量使用"
            )
        is_revoked = any(
            e == jti or e.startswith(f"{jti}#") for e in revoked
        )
        if is_revoked and any(e == "rebind" for _, e, _ in info["events"]):
            # 吊销在客户端名单里，签发方这边只记换绑 → 无法直接比时间。
            # 这里提示人工核对，而不是下断言。
            reasons.append("该码已被吊销，但日志里仍有换绑记录 —— 请人工核对时序")

        if reasons:
            alerts.append((jti, info, reasons))

    if not alerts:
        print("  ✓ 未发现异常传播迹象")
        print()
        print("  阈值：单码最多 %d 台机器 / %d 次换绑"
              % (args.max_machines, args.max_rebinds))
        print("  （正常用户一年可能换一次机，阈值定太低会把正常用户报成异常）")
    else:
        print(f"  ⚠ 发现 {len(alerts)} 张码有异常：")
        print()
        for jti, info, reasons in alerts:
            print(f"  jti {jti}  ({info['name']})")
            for r in reasons:
                print(f"      · {r}")
            print(f"      时间跨度: {info['first'][:19]} → {info['last'][:19]}")
            print(f"      机器数 {len(info['machines'])}，换绑 {info['rebinds']} 次")
            print()
        print("  处理建议：")
        print("    1) 先核对是否正常换机（用户是否真的报过换机）")
        print("    2) 确认传播后按 jti 吊销：")
        print(f"       python gen_activation_keys.py revoke {alerts[0][0]}")
        print("    3) 同一 jti 已换到多台机器时，可用 --before-gen 只作废早期代次，")
        print("       保留最新一台（避免把唯一有效的码一起吊销掉）")

    print("=" * 68)
    # 有异常时返回非 0，便于挂到定时任务里
    return 1 if alerts else 0


def revoke(args) -> int:
    """把已签发的激活码加入吊销名单。

    ★ 为什么要做：激活码一旦发出，收据里就躺着明文码。
      用户退款、手误签发、或码被公开泄露时，必须有手段让它失效。
      没有吊销 = 一旦泄漏就永远可用。

    ★ ``--before-gen`` 为什么必要（换绑场景下的陷阱）：
      换绑保持 jti 不变，只有 gen 递增。此时同一 jti 下同时存在
      多张码（分别绑不同机器）。若按 jti 吊销，新旧两张码会**一起**
      被杀死 —— 而新码往往是用户唯一剩下的凭据，执行即永久锁死。
      指定 ``--before-gen N`` 表示「只作废 gen < N 的码」。

    名单落在**用户机器**上（%LOCALAPPDATA%\\com.daoti.xuandun-personal\\
    revoked_jtis.json）—— 这是本实现的已知限制，见下方说明。
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
    try:
        from daoti_xuandun_personal import license as lic
    except ImportError as e:
        print(f"✗ 无法导入个人版 license 模块: {e}", file=sys.stderr)
        return 2

    if args.before_gen is not None and args.before_gen < 0:
        print("✗ --before-gen 不能为负", file=sys.stderr)
        return 1

    added = lic.revoke(args.jti, before_gen=args.before_gen)
    if added:
        scope = f"gen < {args.before_gen} 的码" if args.before_gen is not None else "全部代次"
        print(f"✓ 已吊销 {args.jti}  （范围：{scope}）")
    else:
        print(f"· {args.jti} 已在吊销名单中（无需重复）")
    print(f"  名单文件: {lic._revoked_path()}")

    if not args.deploy:
        print()
        print("⚠ 重要：本次吊销只写到了**当前这台机器**的名单。")
        print("  要让该码在用户机器上真正失效，还需要：")
        print("    1) 把 revoked_jtis.json 随下一次版本更新分发，或")
        print("    2) 客户端在验签时联网拉取吊销列表（尚未实现）")
        print("  加 --deploy 可把名单同步到分发目录（若已配置）")
    return 0


def list_revoked(args) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
    from daoti_xuandun_personal import license as lic

    revoked = lic.load_revoked()
    if revoked is None:
        print("✗ 吊销名单不可读（文件损坏？）—— 已吊销的码可能全部复活")
        print(f"  路径: {lic._revoked_path()}")
        return 1
    if not revoked:
        print("（暂无吊销记录）")
        return 0
    print(f"已吊销 {len(revoked)} 个：")
    for j in sorted(revoked):
        print(f"  {j}")
    return 0


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
    for k in ("sub", "tier", "jti", "gen", "mch", "features"):
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

    rb = sub.add_parser("rebind", help="换机重签（同一张码换一个机器码）")
    rb.add_argument("--key", required=True, help="RSA 私钥 PEM（用于重签）")
    rb.add_argument("--pub", required=True, help="RSA 公钥 PEM（用于校验原码）")
    rb.add_argument("--request", required=True,
                    help="客户端给出的换绑请求串（XDRB.…）")
    rb.add_argument("--log", default="",
                    help="签发日志路径（换绑必须留痕，否则 audit 看不见传播）")

    rv = sub.add_parser("revoke", help="吊销一个已签发的激活码")
    rv.add_argument("jti", help="激活码的 jti（在签发日志/用户报障信息里）")
    rv.add_argument("--before-gen", type=int, default=None,
                    help="只作废该 jti 中 gen 小于此值的码（换绑后作废旧码用）")
    rv.add_argument("--deploy", action="store_true",
                    help="同步名单到分发目录（需自行配置目标）")

    ls = sub.add_parser("revoked", help="列出已吊销的 jti")

    ad = sub.add_parser("audit", help="审计签发日志，检测激活码传播迹象")
    ad.add_argument("--log", default="", help="签发日志路径（默认 ACTIVATION_LOG.json）")
    ad.add_argument("--max-machines", type=int, default=2,
                    help="单张码允许绑定的机器数上限（超过即视为可能传播）")
    ad.add_argument("--max-rebinds", type=int, default=2,
                    help="单张码允许的换绑次数上限（超过即视为批量使用）")

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
    if args.cmd == "rebind":
        return rebind(args)
    if args.cmd == "revoke":
        return revoke(args)
    if args.cmd == "revoked":
        return list_revoked(args)
    if args.cmd == "audit":
        return audit(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())

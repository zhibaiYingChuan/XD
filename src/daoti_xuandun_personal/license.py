# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""个人版激活码校验（引擎侧）。

为什么验签在 Python 侧而不是 Rust 侧
────────────────────────────────────────────────────────────────
两个原因，都是工程现实而非偏好：

1. **依赖可及性**：Rust 侧要验签需引入 ``rsa``/``pkcs8``，
   而本机网络被策略阻断（证书吊销检查失败）拉不到这些 crate。
   Python 侧 ``cryptography`` 本就已就位，零新增依赖。
2. **更难绕过**：本模块会被 Nuitka 编译进引擎二进制，
   反编译者拿不到明文 Python 源码；改 Rust 侧的校验点则只需改几行 Rust。

安全模型
────────────────────────────────────────────────────────────────
能防住：

* 伪造激活码 —— 私钥只在签发方，从未进入任何客户端产物
* 改写有效期/档位/特征 —— 都在签名覆盖范围内，改动即验签失败
* 复制到另一台机器 —— ``mch``（机器码哈希）不匹配
* ``alg: none`` 绕过 —— 显式限定 ``algorithms=["RS256"]``

防不住（抬高门槛而非绝对防线）：给校验函数打补丁后重打包、
运行时 hook。这些靠「校验点分散」缓解：Rust 侧在关键命令入口
独立复核，引擎侧自己也校验，两处都通过才算激活。

机器码哈希
────────────────────────────────────────────────────────────────
本模块的 ``machine_code_hash``、签发工具
``tools/activation/gen_activation_keys.py``、Rust 侧
``license.rs::machine_code_hash`` 三者算法必须完全一致：
``sha256(机器码 trim + 转大写)`` 的十六进制前 32 字符。

任一侧重算都会导致「用户拿到的码永远激活不了」，
且这类故障极难排查 —— 所以三处都写死了「前 32 位」这个长度。
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_ISSUER = "xuanDun-personal"
_AUDIENCE = "xuandun-personal-desktop"
_PREFIX = "XDACT-"

# 时钟回拨容忍窗口（秒）。NTP 校时 / 网络抖动会带来少量漂移，
# 超过 5 分钟才判定为人为回拨。
_CLOCK_DRIFT_TOLERANCE = 300

# 持久化「上次校验通过时刻」的文件名
_STATE_FILE = "license_seen.json"


def machine_code_hash(machine_code: str) -> str:
    """机器码 → 激活码内使用的哈希。

    ★ 与 Rust 侧 ``license.rs::machine_code_hash`` 必须逐字节一致。
      统一做大写 + trim 是为了避免「同一台机器因格式微差算出两个哈希」
      —— 那会让用户明明没换硬件却提示「码与本机不匹配」。
    """
    normalized = (machine_code or "").strip().upper()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def now_unix() -> int:
    return int(time.time())


@dataclass
class VerifyResult:
    """验签结论。

    ``verifier_available=False`` 表示**引擎没能执行校验**
    （例如公钥缺失 / 依赖不可用）。此时 ``ok`` 不可信，
    调用方必须拒绝激活 —— 绝不能把「验不了」当成「验过了」。
    """

    ok: bool
    reason: Optional[str] = None
    message: Optional[str] = None
    subject: Optional[str] = None
    tier: Optional[str] = None
    jti: Optional[str] = None
    exp: Optional[int] = None
    features: List[str] = field(default_factory=list)
    verifier_available: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "message": self.message,
            "subject": self.subject,
            "tier": self.tier,
            "jti": self.jti,
            "exp": self.exp,
            "features": self.features,
            "verifierAvailable": self.verifier_available,
        }


# ══════════════════════════════════════════════════════════════
# 公钥
# ══════════════════════════════════════════════════════════════


def load_public_key() -> Optional[str]:
    """读取 RSA 公钥（PEM 文本）。

    查找顺序（先具体后兜底）：

    1. ``XUANDUN_LICENSE_PUBKEY`` 环境变量全文 —— CI 可用 secret 覆盖
    2. ``XUANDUN_LICENSE_PUBKEY_FILE`` 指向的文件
    3. **引擎可执行文件同级**的 ``license_pub.pem``
       —— 这是发布形态下的实际落点（由 build_engine.py 拷入）
    4. 用户配置目录下的 ``license_pub.pem``

    ★ 绝不设默认值。企业版 ``config.py`` 里有
      ``shell_key = b"daoti_xuandun_16"`` 这类硬编码 fallback，
      那是另一套密钥体系；激活码公钥一旦有 fallback，
      就等于「无公钥也能验签」，授权体系直接失效。
      找不到就返回 None，由调用方如实报告「验签组件不可用」。
    """
    pem = os.getenv("XUANDUN_LICENSE_PUBKEY", "").strip()
    if pem and "BEGIN PUBLIC KEY" in pem:
        return pem

    candidates = []
    env_path = os.getenv("XUANDUN_LICENSE_PUBKEY_FILE", "").strip()
    if env_path:
        candidates.append(env_path)

    # ③ 引擎可执行文件同级 —— 发布形态下的主路径
    try:
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.append(os.path.join(exe_dir, "license_pub.pem"))
    except Exception:
        pass

    # Nuitka standalone 下 __file__ 指向解包目录，一并找
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(here, "license_pub.pem"))
    except Exception:
        pass

    # ④ 用户配置目录（开发态手工放置）
    candidates.append(
        os.path.join(
            os.getenv("LOCALAPPDATA") or os.path.expanduser("~/.config"),
            "com.daoti.xuandun-personal",
            "license_pub.pem",
        )
    )

    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            if "BEGIN PUBLIC KEY" in content:
                return content
        except OSError:
            continue
    return None


# ══════════════════════════════════════════════════════════════
# 时钟水位
# ══════════════════════════════════════════════════════════════


def _seen_path() -> str:
    return os.path.join(
        os.getenv("LOCALAPPDATA") or os.path.expanduser("~/.config"),
        "com.daoti.xuandun-personal",
        _STATE_FILE,
    )


def read_last_seen() -> Optional[int]:
    try:
        with open(_seen_path(), "r", encoding="utf-8") as f:
            import json

            return int(json.load(f).get("lastSeen", 0)) or None
    except (OSError, ValueError, TypeError):
        return None


def write_last_seen(ts: int) -> None:
    try:
        import json

        p = _seen_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"lastSeen": int(ts)}, f)
    except OSError:
        pass


def check_clock_rollback(now: int, last_seen: Optional[int]) -> Optional[str]:
    """检测时钟回拨。返回错误提示，正常时返回 None。"""
    if last_seen and now < last_seen - _CLOCK_DRIFT_TOLERANCE:
        return "检测到系统时间被回拨，请校准系统时间后重试"
    return None


# ══════════════════════════════════════════════════════════════
# 验签
# ══════════════════════════════════════════════════════════════


def verify(code: str, mch: str, now: Optional[int] = None) -> VerifyResult:
    """校验激活码。

    Args:
        code: 用户输入的激活码原文
        mch: 本机机器码哈希（由调用方用本模块的
             ``machine_code_hash`` 算出）
        now: 当前 Unix 秒。显式传入便于测试确定性。

    ★ ``verifier_available=False`` 的每一条路径都必须让 ``ok=False``。
      「验不了」绝不能被当成「验过了」—— 那是授权系统最危险的失效方向。
    """
    now = int(now if now is not None else now_unix())

    # ① 时钟回拨要在**验签之前**查：若时钟被回拨到有效期之前，
    #    先验签会看到「未过期」而误判为有效。
    rollback = check_clock_rollback(now, read_last_seen())
    if rollback:
        return VerifyResult(False, "clock_rollback", rollback)

    raw = (code or "").strip()
    if not raw.startswith(_PREFIX):
        return VerifyResult(
            False, "malformed", "激活码格式不正确，请检查是否复制完整"
        )

    pub = load_public_key()
    if not pub:
        return VerifyResult(
            False,
            "verifier_unavailable",
            "激活校验组件不可用，请联系售后",
            verifier_available=False,
        )

    try:
        import jwt
    except ImportError:
        return VerifyResult(
            False,
            "verifier_unavailable",
            "激活校验组件不可用，请联系售后",
            verifier_available=False,
        )

    token = raw[len(_PREFIX):]
    try:
        # ★ 三个要点，缺一即被绕过：
        #   algorithms=["RS256"]  限定算法（否则 alg=none / HS256 自签可过）
        #   require 必需字段存在
        #   显式校验 iss / aud     防跨产品复用同一份码
        claims = jwt.decode(
            token,
            pub,
            algorithms=["RS256"],
            audience=_AUDIENCE,
            issuer=_ISSUER,
            options={"require": ["iss", "aud", "exp", "mch"]},
        )
    except jwt.ExpiredSignatureError:
        return VerifyResult(False, "expired", "激活码已过期，请联系售后来延长")
    except jwt.InvalidAudienceError:
        return VerifyResult(False, "bad_claims", "激活码不适用于本产品")
    except jwt.InvalidIssuerError:
        return VerifyResult(False, "bad_claims", "激活码不适用于本产品")
    except jwt.MissingRequiredClaimError:
        return VerifyResult(False, "malformed", "激活码不完整，请重新获取")
    except jwt.InvalidTokenError:
        # 签名不符 / 格式损坏 / alg 不匹配都落这里。
        # ★ 措辞刻意含糊：不说「签名无效」，减少反编译者
        #   从错误文案推断出「这里是验签点」。
        return VerifyResult(False, "bad_signature", "激活码无效，请确认是玄盾官方发出的码")

    got_mch = str(claims.get("mch", ""))
    if got_mch != mch:
        return VerifyResult(
            False,
            "machine_mismatch",
            "激活码与本机不匹配（一码一机）。若更换了硬件，请联系售后",
        )

    return VerifyResult(
        True,
        subject=str(claims.get("sub", "")),
        tier=str(claims.get("tier", "personal")),
        jti=str(claims.get("jti", "")),
        exp=int(claims.get("exp", 0)),
        features=list(claims.get("features", []) or []),
    )


# ══════════════════════════════════════════════════════════════
# 测试
# ══════════════════════════════════════════════════════════════


if __name__ == "__main__":  # 手工自测：python -m ...license <机器码> <激活码>
    import sys

    if len(sys.argv) < 3:
        print("用法: python -m daoti_xuandun_personal.license <机器码> <激活码>")
        raise SystemExit(2)
    mc, code = sys.argv[1], sys.argv[2]
    r = verify(code, machine_code_hash(mc))
    print(f"ok={r.ok} reason={r.reason} message={r.message}")
    if r.ok:
        print(f"  subject={r.subject} tier={r.tier} exp={r.exp}")
    raise SystemExit(0 if r.ok else 1)

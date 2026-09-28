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

★★ 但要注意**哈希算几次**：本哈希只对「原始硬件串」算一次。
   界面给用户看的、以及激活码里存的，都是**算完这一次的结果**。
   签发工具 ``issue --mch`` 收到的是界面显示值，必须原样存入、
   **不能再哈希**；只有 ``rebind`` 才会对本模块 ``machine_code()``
   返回的原始串做这一次哈希。详见该工具里的 ``client_machine_code``。
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


# ══════════════════════════════════════════════════════════════
# 机器码采集（本模块是**唯一实现**）
# ══════════════════════════════════════════════════════════════
#
# ★★★ 为什么必须收在这里，而不是各侧各写一份
#
#   历史上机器码有三处实现：Rust 的 license.rs、签发工具自己复制的
#   machine_code_hash、以及本模块的哈希函数。三份各自演化，
#   结果是 2026-09-28 线上版用户「码明明是按 UI 上的机器码签的，
#   却提示与本机不匹配」——签发时与验证时算出的值不同。
#
#   更糟的是旧实现**本身就不稳定**（已被移除，见下）：
#   它取「第一块非移动磁盘的卷标 + 容量」。卷标会变（改名、
#   重装、换盘符），枚举顺序也不保证，插拔移动硬盘就能改变
#   「第一块」是谁。同一台机器在不同时刻可以算出不同机器码。
#
# ★ 采集方式：调用系统自带的 WMI/CIM 查询，零新增依赖
#   · Windows: PowerShell 的 Get-CimInstance（不依赖已弃用的 wmic）
#   · macOS:   ioreg -rd1 -c IOPlatformExpertDevice
#   · 其余平台：降级到「无稳定硬件 ID」，见下方 fallback。
#
#   刻意不引入 `windows` crate 拿序列号：本机网络被策略阻断
#   （证书吊销检查失败，CRYPT_E_NO_REVOCATION_CHECK），拉不到新依赖，
#   而「本机跑不通的代码」比「多一个依赖」危险得多。

_WMI_QUERY = (
    "Get-CimInstance Win32_DiskDrive | "
    "Where-Object { $_.InterfaceType -ne 'USB' -and $_.SerialNumber } | "
    "ForEach-Object { $_.SerialNumber }; "
    "Get-CimInstance Win32_BaseBoard | "
    "ForEach-Object { $_.SerialNumber }; "
    "Get-CimInstance Win32_Processor | "
    "ForEach-Object { $_.ProcessorId }"
)

# WMI 里这些是「占位序列号」，厂商没填。混进机器码会让
# 一批同型号机器算出同一个值，一码一机直接失效。
#
# ★ 存的是**去掉所有空白后**的大写形式，与 _is_real_serial
#   的比较口径一致 —— 否则 "Default string" 与
#   "DefaultString" 会是两个条目，其中一个漏网。
_PLACEHOLDER_KEYS = {
    "".join(s.upper().split())
    for s in (
        "",
        "TOBEFILLEDBYOEMS",
        "TOBEFILLEDBYMANUFACTURER",
        "TOBEFILLEDBYSYSTEM",
        "DEFAULT STRING",
        "DEFAULTSTRING",
        "NONE",
        "UNKNOWN",
        "NULL",
        "NOTAPPLICABLE",
        "NOT APPLICABLE",
        "NOTAVAILABLE",
        "NOTSPECIFIED",
        "SYSTEMSERIALNUMBER",
        "SYSTEM SERIAL NUMBER",
        "BASEBOARD SERIAL NUMBER",
        "CHASSIS SERIAL NUMBER",
    )
}


def _is_real_serial(value: str) -> bool:
    """判断一个序列号是否值得采信。"""
    v = (value or "").strip()
    # ★ 比较前先去掉所有空白：WMI 会返回 "Default string"、
    #   "Not Specified"、"baseboard serial number" 这类变体，
    #   按原样比对会漏掉一半，占位值就会混进机器码。
    key = "".join(v.upper().split())
    if key in _PLACEHOLDER_KEYS:
        return False
    # 纯数字且全同（如 0000000000）同样是占位
    return not (v.isdigit() and len(set(v)) == 1)


def _run_windows_serials() -> list:
    """Windows：走 PowerShell 取磁盘/主板/CPU 序列号。"""
    import subprocess

    try:
        out = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-Command", _WMI_QUERY,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    text = (out.stdout or b"").decode("utf-8", errors="replace")
    serials = []
    for ln in text.splitlines():
        # ★ 逐段清洗：WMI 的磁盘序列号常带尾随空格与点号
        #   （如 "TA2032704020153     _00000001."）。这些噪声在不同
        #   WMI 版本上不一致，留着会让机器码随系统更新而变 ——
        #   那正是要消灭的那类不稳定性。
        v = ln.strip().rstrip(".").strip()
        if _is_real_serial(v):
            serials.append(v)
    return serials


def _run_macos_serials() -> list:
    """macOS：IOPlatformUUID 是 Apple 定义的唯一硬件标识。"""
    import subprocess

    try:
        out = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    text = (out.stdout or b"").decode("utf-8", errors="replace")
    found = []
    for line in text.splitlines():
        if '"IOPlatformUUID"' in line and "=" in line:
            val = line.split("=", 1)[1].strip().strip('"')
            if _is_real_serial(val):
                found.append(val)
    return found


def machine_code() -> str:
    """采集本机机器码（原始串，不哈希）。

    ★ 这是**唯一**实现。签发工具、引擎验签都从这里取，
      Rust 侧不再自行采集（它拿不到稳定的等价手段，
      而两侧各自实现必然漂移 —— 那正是 2026-09-28 线上激活
      失败的根因）。

    ★ 强度说明（如实告知，不夸大）：
      Windows 取磁盘+主板+CPU 序列号，macOS 取 IOPlatformUUID，
      都是厂商烧录的硬件 ID，同一台机器重启、插拔硬盘、
      改盘符、改卷标都不会变。
      仍挡不住的是「伪造」—— 有能力改客户端二进制的人可以
      写死任意机器码。客户端校验本质上是可绕过的，
      真正的价值在于「私钥不出签发方」与「换绑留痕」。

    ⚠ 采集失败时返回带 ``hw-unavailable:`` 前缀的降级串。
      绝不返回空串 —— 空串会让所有用户算出同一个哈希，
      等于取消一码一机。用前缀标记是为了让签发方一眼看出
      这台机器拿不到稳定 ID，从而在签发前就与用户沟通。
    """
    import platform as _platform
    import sys as _sys

    system = _platform.system()
    if system == "Windows":
        serials = _run_windows_serials()
    elif system == "Darwin":
        serials = _run_macos_serials()
    else:
        serials = []

    if not serials:
        return "hw-unavailable:" + (system or _sys.platform or "unknown")

    # 排序去重：同一台机器多次采集必须得到完全相同的串，
    # 否则 WMI 返回顺序一变哈希就变了 —— 正是旧实现的翻车方式。
    uniq = sorted(set(serials))
    return "|".join(uniq)


def now_unix() -> int:
    return int(time.time())


# ══════════════════════════════════════════════════════════════
# 吊销名单
# ══════════════════════════════════════════════════════════════
#
# ★ 为什么必须做（这不是可选项）
#   激活码一旦发出，收据里就躺着明文码。用户退款、你手误签发、
#   或码被公开泄露（贴到论坛/社交媒体）时，必须有手段让它失效。
#   没有吊销 = 一旦泄漏就永远可用，只能等过期。
#
# ★ 形态选择：JSON 文件而非 SQLite
#   名单规模是「已售出数量」量级，几十到几千条 JSON 足够，
#   且可以直接用文本编辑器/Git 审阅改动 —— 吊销是低频高危操作，
#   必须能被人眼核对。写入用原子替换（临时文件 + os.replace），
#   避免半截文件导致名单失效。
_REVOKED_FILE = "revoked_jtis.json"


def _revoked_path() -> str:
    return os.path.join(
        os.getenv("LOCALAPPDATA") or os.path.expanduser("~/.config"),
        "com.daoti.xuandun-personal",
        _REVOKED_FILE,
    )


def load_revoked() -> Optional[set]:
    """读吊销名单。

    返回三态，**这个区分是本模块的关键**：

    * ``set()``      —— 名单可读，**无人被吊销**（含「文件不存在」）
    * ``set{...}``   —— 名单可读，含若干已吊销 jti
    * ``None``       —— **名单不可读**，结论不可信

    ★ 为什么「文件不存在」要算「无人被吊销」而不是「不可读」：
      全新安装的用户机器上根本没有这个文件。若把它当「不可读」
      并据此拒绝，那么每个新用户在第一次激活时都会看到
      「无法校验激活码状态」—— 功能完全不可用。

    ★ 为什么「文件损坏」才算不可读：
      名单损坏时若当成「无人被吊销」，所有已吊销的码会集体复活
      （退款过的、泄露过的全都重新生效）。那比拒绝更糟。
    """
    path = _revoked_path()
    if not os.path.exists(path):
        # 首次运行：还没有吊销过任何人
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            import json

            data = json.load(f)
    except (OSError, ValueError):
        return None

    if not isinstance(data, list):
        # 内容不是列表 = 文件被改坏或格式不对，结论不可信
        return None

    entries = {str(x).strip() for x in data if str(x).strip()}
    for e in entries:
        if "#" in e and not _valid_before_gen(e):
            # ★ 条目带代次后缀但代次不是非负整数 = 名单被改坏。
            #   判为「不可读」而非「这条不匹配」——后者是 fail-open，
            #   一条写坏的记录就能让本该被吊销的码复活。
            return None
    return entries


def _valid_before_gen(entry: str) -> bool:
    """``jti#N`` 中的 N 是否为合法代次。"""
    try:
        return int(entry.rsplit("#", 1)[1]) >= 0
    except (ValueError, IndexError):
        return False


def _entry_revokes(entry: str, jti: str, gen: int) -> bool:
    """名单里的一条记录是否命中（jti, gen）。

    两种记录形态：

    * ``a_xxx``      —— 全代次核弹：该 jti 的任何代次都已被吊销
    * ``a_xxx#2``    —— 作废代次：该 jti 中 gen < 2 的码已吊销，
                        gen ≥ 2（更晚换绑出来的）仍然有效

    ★ 代次机制解决的是「换绑后如何单独作废旧码」：
      换绑保持 jti 不变（否则吊销可被绕过），于是同一个 jti
      先后可能存在多张码，分别绑定不同机器。若只有 jti 粒度，
      唯一能做的吊销会把新旧两张码一起杀死 ——
      而新码往往是用户唯一剩下的凭据，执行即永久锁死。
    """
    if "#" in entry:
        e_jti, _, e_gen = entry.rpartition("#")
        try:
            return e_jti == jti and gen < int(e_gen)
        except ValueError:
            return False  # 正常路径不会到这里（load_revoked 已拦）
    return entry == jti


def is_revoked(jti: str, gen: int = 0) -> Optional[bool]:
    """该 jti（指定代次）是否已被吊销。

    返回值三态：

    * ``True``  —— 已吊销
    * ``False`` —— 未吊销
    * ``None``  —— **名单不可读，结论不可信**

    ★ 那个 ``None`` 是关键。调用方拿到 None 时必须按「拒绝」处理：
      把「查不到吊销记录」当成「没被吊销」，等于让名单文件
      一损坏，所有已吊销的码集体复活。
    """
    if not jti:
        return False
    revoked = load_revoked()
    if revoked is None:
        return None
    return any(_entry_revokes(e, jti, gen) for e in revoked)


def revoke(jti: str, before_gen: Optional[int] = None) -> bool:
    """把一个 jti 加入吊销名单（供管理端调用）。

    Args:
        jti: 激活码唯一 ID
        before_gen: 只作废该 jti 中 gen 小于此值的码（换绑后作废旧码用）。
                    ``None`` 表示作废全部代次。
    """
    entry = jti if before_gen is None else f"{jti}#{int(before_gen)}"
    revoked = load_revoked()
    if revoked is None:
        revoked = set()
    if entry in revoked:
        return False
    revoked.add(entry)

    path = _revoked_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    import json
    import tempfile

    # 原子写：先写临时文件再 os.replace，
    # 避免进程中断留下半截 JSON（那会让名单整体失效）
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sorted(revoked), f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


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
    4. **包内** ``license_pub.pem``（随源码分发，公开材料）
    5. 用户配置目录下的 ``license_pub.pem``

    ★ 绝不设默认值。企业版 ``config.py`` 里有
      硬编码 fallback 密钥，那是另一套密钥体系；
      激活码公钥一旦有 fallback，就等于「无公钥也能验签」，
      授权体系直接失效。找不到就返回 None，由调用方如实报告
      「验签组件不可用」。
    """
    pem = os.getenv("XUANDUN_LICENSE_PUBKEY", "").strip()
    if pem and "BEGIN PUBLIC KEY" in pem:
        return pem

    # ★ 显式指定的路径**先单独判定**，不与兜底候选混在一起。
    #   混了的话，路径配错时会悄悄用兜底里的另一把公钥验签 ——
    #   表现为「所有码都无效」，而配置里那个路径看起来一切正常，
    #   极难定位。「显式配置」与「兜底发现」是两种语义，不能混。
    env_path = os.getenv("XUANDUN_LICENSE_PUBKEY_FILE", "").strip()
    if env_path:
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                content = f.read()
            if "BEGIN PUBLIC KEY" in content:
                return content
        except OSError as e:
            raise FileNotFoundError(
                f"XUANDUN_LICENSE_PUBKEY_FILE 指向的公钥不可用: {env_path}（{e}）"
            ) from e
        raise ValueError(f"公钥文件内容不是有效的 PEM: {env_path}")

    candidates = []

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

    # 兜底候选全部落空 = 组件确实不可用。
    # ★ 返回 None 而不抛错：这是「没装公钥」的正常状态
    #   （开发态、CI），调用方据此报 verifier_unavailable。
    #   与上面「显式配错」区分开 —— 那个是配置错误，必须抛。
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


def verify(
    code: str,
    mch: str,
    now: Optional[int] = None,
    machine_check: bool = True,
) -> VerifyResult:
    """校验激活码。

    Args:
        code: 用户输入的激活码原文
        mch: 本机机器码哈希（由调用方用本模块的
             ``machine_code_hash`` 算出）
        now: 当前 Unix 秒。显式传入便于测试确定性。
        machine_check: 是否比对机器码。

    ★ ``machine_check=False`` 只给**测试**用 —— 用来构造
      「不校验机器码」的调用场景以覆盖其它分支。
      生产路径一律传 True：机器码由本模块采集，
      调用方无从也不该插手（那正是 2026-09-28 线上激活失败的成因
      —— Rust 侧自采的机器码既不稳定，又与签发方算法漂移）。

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

    # ★ load_public_key 在「显式配置的路径不存在」时会抛异常
    #   （那是配置错误，不该被静默兜底掩盖）。
    #   但异常绝不能穿透到调用方 —— verify 的契约是「永远返回结论」，
    #   否则 Rust 侧会拿到 Err 而当成引擎故障，界面显示不出真因。
    try:
        pub = load_public_key()
    except Exception as e:
        return VerifyResult(
            False,
            "verifier_unavailable",
            f"激活校验组件不可用（{e}），请联系售后",
            verifier_available=False,
        )
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
    # ★ 只要**任一侧**没有机器码，就不比对。
    #   引擎侧传空串（独立进程拿不到 Rust 采集的机器码）。
    #   若把空串当成一个真实哈希去比，没有任何码能通过 ——
    #   结果是所有用户都被降级成只读，防护整体失效。
    #   机器码绑定由 Rust 在激活入口强制执行，两处都过才算激活。
    if machine_check and mch and got_mch != mch:
        return VerifyResult(
            False,
            "machine_mismatch",
            "激活码与本机不匹配（一码一机）。若更换了硬件，请联系售后",
        )

    # ④ 吊销检查
    #
    # ★ 必须放在**验签之后**：jti 来自未经验证的 payload 时，
    #   任何人都能构造 {"jti": "<别人的 jti>"} 把别人的码吊销掉。
    #   只有签名通过的 jti 才是可信的。
    jti = str(claims.get("jti", ""))
    # gen 是换绑代次：同一 jti 换绑后 jti 不变，只有 gen 递增。
    # 缺失时按 0 处理（首版签发的码都没有这个字段）。
    try:
        gen = int(claims.get("gen", 0) or 0)
        if gen < 0:
            raise ValueError
    except (TypeError, ValueError):
        return VerifyResult(
            False, "malformed", "激活码数据异常，请重新获取"
        )
    revoked = is_revoked(jti, gen)
    if revoked is None:
        # 名单不可读 → 按「拒绝」处理。
        # 把「查不到吊销记录」当成「没被吊销」，
        # 等于名单文件一损坏，所有已吊销的码集体复活。
        return VerifyResult(
            False,
            "revocation_unavailable",
            "无法校验激活码状态，请稍后重试或联系售后",
            verifier_available=False,
        )
    if revoked:
        return VerifyResult(
            False,
            "revoked",
            "该激活码已失效（可能已退款或被撤销），请重新获取",
            jti=jti,
        )

    return VerifyResult(
        True,
        subject=str(claims.get("sub", "")),
        tier=str(claims.get("tier", "personal")),
        jti=jti,
        exp=int(claims.get("exp", 0)),
        features=list(claims.get("features", []) or []),
    )


# ══════════════════════════════════════════════════════════════
# 换机重绑请求
# ══════════════════════════════════════════════════════════════


def build_rebind_request(code: str, machine_code_raw: str) -> str:
    """生成换绑请求串（客户端 → 签发方）。

    ★ 为什么是「客户端生成、签发方重签」而不是纯自助：
      严格一码一机下，新机器上验证必然失败（码里的 mch 是旧机器的）。
      新机器上没有任何东西能证明「我拥有这张码」——除了**签名本身**。
      所以流程是：用户把「原码 + 新机器码」一起发给你，
      你验签通过后只改 mch 重签。

    格式：``XDRB.<base64url(json)>``
    base64url 而非 base64：避免复制过程中 ``+`` / ``/`` / ``=``
    被聊天软件转义或截断。实测这是长串传输最常见的失败原因。

    刻意**不加密** —— 内容是「一个已签名的码 + 原始机器码串」，
    本身不含隐私；而加密会引入一个「客户端解密密钥」，
    那才是真正的泄露点。

    ★★ ``machine_code_raw`` 收的是**原始硬件串**（未哈希），
      由调用方传 ``machine_code()`` 的返回值；签发方 ``rebind``
      拿到后自行哈希。**不要**传界面显示的哈希进来 ——
      那样签发方再哈希一次，就会得到 hash(显示值)，
      与验签时的比对口径（显示值）不一致，换绑后的码同样激活不了。
      这与 ``issue --mch`` 的口径**相反**（那里收的正是显示值），
      两处刻意取不同的参数名就是为了避免用混。
    """
    import base64
    import json as _json

    payload = _json.dumps(
        {"code": (code or "").strip(), "mch": (machine_code_raw or "").strip()},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "XDRB." + base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


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

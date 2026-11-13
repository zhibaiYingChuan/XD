# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

# scan-secrets: allow-pem-placeholder
#   本文件里的 PEM 头全部是**判据的正负样例**（例如「头 + 48 字符体」长什么样），
#   用于证明正则能命中真实形态、且不误伤「只提到标记」的提问。
#   这些样例不含任何一把真实可用的私钥：体是最多两行的截断串，
#   长度远低于一把 RSA-2048 密钥（约 1600 字符），无法解析为密钥。
#   扫描器对此有专门判据：头之后连续 base64 ≥200 字符才算密钥体，
#   因此本文件即使没有这句声明，也不会被当成真钥匙 —— 这句声明只是为了
#   让「为什么这里会有 PEM 头」在代码里显式可查，而不是让人猜。

"""凭据判据的唯一真源（Single Source of Truth）。

★★ 为什么要有这个文件
────────────────────────────────────────────────────────────
2026-11-13 的误报排查暴露了一个结构性问题：
同一类凭据（私钥 / API Key / AWS / JWT / 身份证 / 银行卡…）
在仓库里被写了 **4–5 份正则**，分别散落在：

  1. proxy/sanitizer.py            —— 请求侧生产链路
  2. proxy/verifier.py             —— 响应侧生产链路
  3. rules/detection_rules.yaml    —— 声明副本
  4. daoti_xuandun/sensitive_leak.py   —— 企业版检测器
  5. daoti_xuandun/_check_output.py    —— 企业版输出护栏

后果有两个，都是实测踩到的：

  · **改一处不生效**。修了请求侧的私钥判据，响应侧与输出护栏仍是旧的，
    用户换个入口又被误拦。
  · **规则无限膨胀**。每次误报就「再加一条更严的正则」，两份副本各加各的，
    最后谁也不知道哪条在生效。私钥那个「只认头标记」的旧判据就是这么留下来的。

所以这里做两件事：

  A. **每类凭据只声明一次**「它长什么样」——用 `CredentialSpec`，
     包含：规范正则、必需的校验器、可选的误报排除规则、正负样例。
  B. **四处消费方一律引用本表**，不允许各自再内联正则。
     `tests/test_credential_registry.py` 会扫描全部消费方源码，
     发现任何一处内联了凭据正则就判失败。

★★ 为什么不是「纯配置驱动」
────────────────────────────────────────────────────────────
判据有两种形态，性质完全不同：

  · **结构型**（私钥、JWT、AWS AKID、OpenAI key）：有确定字面形态，
    适合写成正则 + 结构约束（如私钥必须「头 + 体」）。
  · **校验型**（身份证、银行卡）：正则只能圈定候选，
    必须靠 MOD 11-2 / Luhn 校验位才能把误报压下去。

把两类都塞进 YAML 会丢掉校验器，所以本表用 Python 声明，
`detection_rules.yaml` 只作为**导出视图**（供审计与热更新比对），
不再由它承载唯一逻辑。

★★ 增删规则的纪律
────────────────────────────────────────────────────────────
· 加一类凭据 → 只改本文件 + 补一组正负样例。
· 压误报 → 优先改 `allow_if`（排除条件），不要收紧主正则。
  收紧主正则是最容易制造漏报的做法（私钥那次就是证明）。
· 任何改动都必须能让 `tests/test_credential_registry.py` 的
  「正例必中 / 负例必不中」断言全绿。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern, Sequence, Tuple


# ══════════════════════════════════════════════════════════════
# 校验器：把「形状对」升级为「确实是」
# ══════════════════════════════════════════════════════════════

def luhn_valid(number: str) -> bool:
    """Luhn 校验（银行卡 / IMEI）。仅对纯数字有效。"""
    if not number.isdigit():
        return False
    digits = [int(d) for d in number]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def cn_id_checksum_valid(id_no: str) -> bool:
    """中国大陆 18 位身份证校验位（ISO 7064:1983 MOD 11-2）。"""
    if len(id_no) != 18:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_map = "10X98765432"
    try:
        total = sum(int(ch) * w for ch, w in zip(id_no[:17], weights))
    except ValueError:
        return False
    return id_no[17].upper() == check_map[total % 11]


# ══════════════════════════════════════════════════════════════
# 判据声明
# ══════════════════════════════════════════════════════════════

#: 请求侧处置类别 → 检测器（sensitive_leak）历史落库分类名。
#:
#: ★★ 为什么是「类别约定」而不是「逐条声明」：
#:   检测器的落库分类是以**类别**为粒度定义的（key_aws / key_jwt /
#:   pii_idcard…），不是逐条定义。旧实现在 `_init_builtin_rules` 里
#:   手写了一整张 `{category: detector_name}` 表；收敛到本表后那张表
#:   被删了，但映射关系本身没有替代品，于是 20 条判据全部用请求侧的
#:   类别名落库 —— key_hex_aes / key_bearer / key_gcp 被静默改名成
#:   key_api / key_aws，历史日志的分类统计会突变。
#:
#:   映射属于「两个消费方之间的约定」，所以留在真源里；
#:   个别判据若需偏离约定，用 `detector_category=` 单条覆盖。
DETECTOR_CATEGORY: dict[str, str] = {
    "private_key": "key_private",
    "api_key": "key_api",
    "aws_key": "key_aws",
    "jwt": "key_jwt",
    "idcard": "pii_idcard",
    "bankcard": "pii_bankcard",
    "phone": "pii_phone",
    "email": "pii_email",
    "passport": "pii_passport",
    "plate": "pii_plate",
    "certificate": "key_certificate",
}


@dataclass(frozen=True)
class CredentialSpec:
    """一类凭据的完整判据声明。

    字段说明：
      key        稳定标识（跨模块引用、落库、前端图标映射都用它）
      category   处置类别（sanitizer 的策略表按这个查 BLOCK/REDACT）
      pattern    规范正则（**唯一一份**）
      validator  可选校验器，收到 match.group(0) 返回是否可信
      allow_if   可选排除器，收到 (全文, match) 返回 True 表示这是误报
      severity   风险等级：high 阻断 / medium 打码 / low 告警
      positive   必须命中的样例（测试用）
      negative   必须不命中的样例（测试用）
      note       为什么长这样（尤其是踩过的坑）
      request_side
                 请求侧是否参与**阻断/打码**判定，**默认 False（需显式开启）**。
                 ★ 为什么默认关闭，而不是默认开启：
                   请求侧一命中就要么阻断要么打码，用户消息直接发不出去 ——
                   这是全链路代价最高的处置。新增一条判据时，
                   「它该不该阻断用户发消息」必须是**显式决定**，
                   不能因为「忘了写声明」就自动获得阻断权。
                   实测教训：默认开启时，把规则表接进请求侧会让
                   原本只在响应侧用的判据（Bearer / GitHub / 车牌…）
                   静默获得阻断权，`Bearer token-based-authentication-is-enabled`
                   这种普通英文短语因此整条被拦。
                 ★ 另有一类判据的形态天生与无害物同形（32/64 位裸 hex
                   既可能是 AES 密钥，也可能是 MD5/SHA 摘要），
                   文本上不可判别，这类同样不开请求侧。
      detector_category  检测器（sensitive_leak）落库用的分类名。
                 默认按 DETECTOR_CATEGORY 的类别约定推导（见下方映射），
                 不再由检测器自己维护一张表 —— 那张表曾把
                 key_hex_aes / key_bearer / key_gcp 静默改名。
      detector_severity  检测器用的严重级，默认等于 severity。
                 ★ 为什么允许与请求侧不同：
                   两侧的「严重」含义不一样。请求侧 high = 禁止外发；
                   检测器 high = 拦截，medium = 打码。同一类凭据在两边
                   本来就可以有不同处置 —— 例如银行卡在请求侧必须阻断
                   （要外发就不能发），在检测器里打码即可。
    """

    key: str
    category: str
    pattern: str
    severity: str
    positive: Tuple[str, ...]
    negative: Tuple[str, ...]
    validator: Optional[Callable[[str], bool]] = None
    allow_if: Optional[Callable[[str, "re.Match[str]"], bool]] = None
    note: str = ""
    request_side: bool = False
    detector_category: Optional[str] = None
    detector_severity: Optional[str] = None

    @property
    def leak_category(self) -> str:
        """检测器落库分类（未单独声明时按类别约定推导）。"""
        return self.detector_category or DETECTOR_CATEGORY.get(
            self.category, self.category
        )

    @property
    def leak_severity(self) -> str:
        """检测器使用的严重级（未单独声明时沿用 severity）。"""
        return self.detector_severity or self.severity

    def compile(self) -> Pattern[str]:
        """编译本判据。

        ★★ 2026-11-13（回归修复）：**不加** re.IGNORECASE。
          上一版在这里统一加了 IGNORECASE，把请求侧拦截面整体放宽 ——
          而请求侧命中即阻断，实测误报：
            「SK-hynix-semiconductor-annual-report-2026 是什么公司」
            「Bearer token-based-authentication-is-enabled 对不对」
            「akiaIOSFODNN7EXAMPLE 这个是不是密钥」
          三条改动前都放行，改动后全被阻断。
          真正的敏感格式本身大小写固定（AKIA 大写、sk- 小写、eyJ、ghp_），
          放宽大小写不会有任何增益，只会把普通英文词判成凭据。
          需要不区分大小写的判据（azure_key / generic_secret /
          aws_secret_key / bearer_token）在正则里自己写 `(?i)`，
          这是判据自身的一部分，不再由编译期统一兜底。
        """
        return re.compile(self.pattern)

    def find(self, text: str) -> List[Tuple[int, int, str]]:
        """返回全部可信命中的 (start, end, matched)。"""
        out: List[Tuple[int, int, str]] = []
        pat = _compiled(self.key, self)
        for m in pat.finditer(text):
            value = m.group(0)
            if self.validator and not self.validator(value):
                continue
            if self.allow_if and self.allow_if(text, m):
                continue
            out.append((m.start(), m.end(), value))
        return out


_COMPILED: dict[str, Pattern[str]] = {}


def _compiled(key: str, spec: "CredentialSpec") -> Pattern[str]:
    pat = _COMPILED.get(key)
    if pat is None:
        pat = spec.compile()
        _COMPILED[key] = pat
    return pat


# ── 误报排除器 ─────────────────────────────────────────────
#
# ★★ 2026-11-13：这里**不再有任何 allow_if 排除器**。
#   原因见 `combined_pattern()` 的说明：合成正则时不携带 allow_if，
#   于是「请求侧放行、其它三处照拦」的口径分裂屡次发生
#   （自家激活码被输出护栏阻断即此）。
#
#   现在所有排除条件都写成 pattern 内部的断言，随正则一起流动 ——
#   五处消费方拿到的就是完整判据，不存在「漏带一段语义」的可能。
#   对「上下文相关、无法写成固定宽度断言」的排除需求
#   （例如裸 hex 与摘要同形），改用 `request_side=False` 声明，
#   语义同样写在声明里，不留在代码路径上。


def _looks_like_prose(text: str, m: "re.Match[str]") -> bool:
    """密钥体是否其实是英文散文（而非 Base64 密钥）。

    ★ 保留为**独立可测的判定函数**，但不再挂在任何 SPECS 的 allow_if 上。
      私钥判据已改为「只看结构」（单段 ≥48 或多行折行），
      散文天然不满足结构，不需要额外的语义排除 ——
      而语义排除一旦放进 allow_if，就会被 combined_pattern 丢掉。

    ★ 前三版都踩了坑，记录在此以免后人重犯：
      ① 「元音比例 > 0.35」—— Base64 里 A/E/I 频繁，真实 RSA 体能到 0.31，
         差距太小，判据不稳。
      ② 「体内含空格」—— 被 Markdown 缩进、头体同行误触发（都是合法形态）。
      ③ 「出现 ≥3 个连续小写」—— URL-safe Base64 的随机串偶尔会凑够 3 次，
         实测把真实 OpenSSH 密钥判成散文 → 漏报。
      ④ 「出现中文即判散文」—— 「头 + 一行中文注释 + 真密钥体」是
         真实形态（用户自己加的注释），整条排除会造成漏报。

    现在只用于诊断与测试，不参与生产判定。
    """
    body = m.group(0)
    parts = body.split("-----", 2)
    payload = parts[2] if len(parts) > 2 else body

    tokens = [t for t in re.split(r"\s+", payload) if t]
    if not tokens:
        return False
    longest = max(tokens, key=len)
    if len(longest) < 24:
        return False

    lower = sum(c.islower() for c in longest)
    return lower / len(longest) > 0.55


# ══════════════════════════════════════════════════════════════
# 规则表（唯一真源）
# ══════════════════════════════════════════════════════════════

SPECS: Tuple[CredentialSpec, ...] = (
    # ── 私钥 ────────────────────────────────────────────────
    CredentialSpec(
        key="private_key_pem",
        category="private_key",
        pattern=(
            r"-----BEGIN[ \t]+(?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)[ \t]+)?"
            r"PRIVATE[ \t]+KEY-----"
            r"[\s\S]{0,128}?"
            # ★★ 「像密钥材料的一行」= 同时含大写、小写、数字，且够长。
            #
            #   为什么必须加这个结构约束（2026-11-13 二次回归，实测）：
            #   只写「每行 ≥16 字符、至少两行」时，这些**正常内容**
            #   会被请求侧整条阻断（用户消息发不出去）：
            #     · -----BEGIN PRIVATE KEY-----
            #       NOTE_REPLACE_WITH_YOUR_OWN_KEY / DO_NOT_PASTE_REAL_KEY_HERE
            #       （占位符模板，最常见的「私钥该怎么填」提问）
            #     · your_private_key_goes_here_please_replace / …
            #       （配置示例）
            #   不能靠「出现 KEY/REPLACE/YOUR」这类语境词排除 ——
            #   那是把词表一条条硬编码，换个写法就再次误报。
            #
            #   ★ 结构事实：真实 PEM 体是**加密随机数据经 Base64 编码**，
            #     长度够时必然同时出现大写、小写与数字（大数定律：
            #     64 字符里缺任一类的概率 < 1e-8）。
            #     而占位符 / 路径 / 散文 / CSV 是人写的文本：
            #     要么全大写、要么有空格、要么没有数字。
            #
            #   ★★ 前视断言必须**有界**（{0,128} 而不是无限）：
            #     写成 `(?=[^ \t\r\n]*[A-Z])` 时，遇到 20 万字符的单行
            #     输入要在每个起始位置向后扫描到行尾 —— 实测 1.1 秒，
            #     也就是「用一次长 base64 就能卡住主链路」。
            #     加上界后同一输入降到 1 毫秒，判据结果完全不变。
            r"(?:"
            r"(?=[^ \t\r\n]{0,128}[A-Z])"
            r"(?=[^ \t\r\n]{0,128}[a-z])"
            r"(?=[^ \t\r\n]{0,128}[0-9])"
            r"[A-Za-z0-9+/=_\-]{48,}"
            r"|(?:"
            r"(?=[^ \t\r\n]{0,128}[A-Z])"
            r"(?=[^ \t\r\n]{0,128}[a-z])"
            r"(?=[^ \t\r\n]{0,128}[0-9])"
            r"[A-Za-z0-9+/=_\-]{16,}[ \t]*\r?\n[ \t]*"
            r"){2,}"
            r"(?=[^ \t\r\n]{0,128}[A-Z])"
            r"(?=[^ \t\r\n]{0,128}[a-z])"
            r"(?=[^ \t\r\n]{0,128}[0-9])"
            r"[A-Za-z0-9+/=_\-]{16,}"
            r")"
        ),
        severity="high",
        request_side=True,
        positive=(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
            "-----END RSA PRIVATE KEY-----",
            # URL-safe Base64（含 - 和 _）
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz-_\n",
            # Markdown 代码块缩进
            "    -----BEGIN RSA PRIVATE KEY-----\n    "
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n",
            # 加密 PEM
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,3F2A9B1C\n\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n",
            # 头体同行
            "-----BEGIN PRIVATE KEY----- "
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
            # JSON 转义（工具参数）
            '{"content": "-----BEGIN RSA PRIVATE KEY-----\\n'
            'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"}',
            # ★ 40 列折行（窄窗口 / 终端复制）
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cK\n"
            "jMzEfYyjiWA4R4M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
            "-----END RSA PRIVATE KEY-----",
            # ★ 32 列折行（更窄）
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc\n"
            "wggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyji\n"
            "WA4R4M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8j\n"
            "-----END RSA PRIVATE KEY-----",
            # ★ 头之后先有一行中文注释，再是真密钥体
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "# 这是服务器上生成的密钥，不要外传\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n",
        ),
        negative=(
            "-----BEGIN PRIVATE KEY-----",                       # 只有标记
            "-----BEGIN PRIVATE KEY----- 这种格式是什么文件？",      # 提问
            "-----BEGIN PRIVATE KEY-----\n这是私钥的第一行说明。",   # 中文说明
            "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n",    # 体太短
            "-----BEGIN CERTIFICATE-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n",
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n",
            # 32 字符英文散文：单段不足 48，且没有「两行以上」的折行结构
            "-----BEGIN PRIVATE KEY-----\nThisIsTheStandardPKCS8HeaderAbcde",
            # ★★ 以下三条是「解释 PEM 格式」的最常见提问形态，
            #   第一版多行分支把它们全判成泄露并阻断（实测），必须放行：
            #   占位符全大写常量的多行模板
            "-----BEGIN PRIVATE KEY-----\n"
            "NOTE_REPLACE_WITH_YOUR_OWN_KEY\n"
            "DO_NOT_PASTE_REAL_KEY_HERE\n"
            "SEE_DOCS_FOR_GENERATION_STEPS",
            #   配置示例（小写+下划线，没有数字）
            "-----BEGIN PRIVATE KEY-----\n"
            "your_private_key_goes_here_please_replace\n"
            "another_placeholder_line_for_example\n"
            "final_placeholder_line_replace_me_now",
            #   多行文件路径
            "-----BEGIN PRIVATE KEY-----\n"
            "/usr/local/etc/nginx/certs/server\n"
            "/etc/ssl/private/example.key\n"
            "/home/deploy/.ssh/id_rsa_backup",
        ),
        note=(
            "只认头部标记会把「提到这行字」判成要外发私钥（2026-11-13 实测 "
            "id=26166）。必须「头 + 体」；中间 [\\s\\S]{0,128}? 有界跳过，"
            "覆盖缩进 / 加密头 / 同行 / JSON 转义四种真实形态。\n"
            "★★ 2026-11-13 二次回归（独立审查指出，已实测确认）：\n"
            "  ① 只写单段 `{48,}` 会把「多行折行」的真实密钥全放过去 ——"
            "40 列折行、32 列折行、头后夹一行中文注释这三种都能被 "
            "`cryptography` 正常解析成私钥，却通不过「单段 ≥48」。\n"
            "  ② 补上「多行折行」后，又把这些**正常内容**判成泄露：\n"
            "     占位符模板（NOTE_REPLACE_WITH_YOUR_OWN_KEY…）、"
            "     配置示例（your_private_key_goes_here…）、多行路径。\n"
            "     原因是「每行 ≥16」对任何人写的文本都成立。\n"
            "  → 现在要求每行同时含**大写 + 小写 + 数字**：\n"
            "    真实 PEM 体是随机数据的 Base64，64 字符里缺任一类的概率 < 1e-8；\n"
            "    而占位符/路径/散文/CSV 要么全大写、要么有空格、要么没数字。\n"
            "    这是结构判据，不是语境词表，不会随说法变化而失效。"
        ),
    ),

    # ── OpenAI / Anthropic 风格 ─────────────────────────────
    CredentialSpec(
        key="openai_key",
        category="api_key",
        pattern=r"(?<![A-Za-z0-9_\-])sk-(?:ant-)?[A-Za-z0-9\-_]{20,}",
        severity="high",
        request_side=True,
        positive=(
            "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
            "sk-1234567890abcdefghijklmnop",
        ),
        negative=(
            "risk-assessment-framework-2026-final",   # 复合词里的 sk-
            "task-orchestration-pipeline-v2",
            "disk-usage-monitor-service",
            "sk-short",
        ),
        note=(
            "左边界必须排除字母数字和连字符：`risk-assessment-` 里的 `sk-` "
            "曾被判成密钥整条阻断（id=2059）。旧版 _check_output 用的是 "
            "`[sS][kK]-...{16,}` 无边界、宽度 16，漂移后误报复活。"
        ),
    ),

    # ── AWS ────────────────────────────────────────────────
    CredentialSpec(
        key="aws_access_key_id",
        category="aws_key",
        pattern=r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])",
        severity="high",
        request_side=True,
        positive=(
            "AKIAIOSFODNN7EXAMPLE",
            "aws_key = 'AKIAZZ12ABCDEFGHIJKL'",
        ),
        negative=(
            "AKIAabcdefghijkl",        # 长度不足、含小写
            "XAKIAIOSFODNN7EXAMPLE",   # 左侧紧贴字母
        ),
        note=(
            "AKID 恒为 AKIA + 16 位大写字母数字。旧版 _check_output 写成 "
            "`AKIA[A-Za-z0-9]{12,}`（12 位、忽略大小写），"
            "会把 `AKIAabcdefghijkl` 判成密钥。"
        ),
    ),

    CredentialSpec(
        key="aws_secret_key",
        category="aws_key",
        pattern=(
            r"(?i)\baws[^\n]{0,20}?(?:secret|private)[^\n]{0,20}?"
            r"['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        severity="high",
        request_side=True,
        positive=(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        negative=(
            "aws secret 这个字段叫什么",
        ),
        note="40 字符 base64 片段，必须紧跟 secret/private 提示词。",
    ),

    # ── GCP 服务账号 ────────────────────────────────────────
    CredentialSpec(
        key="gcp_service_account",
        category="aws_key",
        pattern=r'"type"\s*:\s*"service_account"',
        severity="high",
        request_side=True,
        detector_category="key_gcp",
        positive=('{"type": "service_account", "project_id": "x"}',),
        negative=('{"type": "user"}',),
        note=(
            "GCP 服务账号 JSON 的标志性字段。\n"
            "★ detector_category 单独声明为 key_gcp：企业版历史落库口径是 "
            "key_gcp，而请求侧归在 aws_key（同为「云凭证」一类处置）。"
            "两边都要保留原值，否则历史日志的分类统计会突变。"
        ),
    ),

    # ── Google API Key ─────────────────────────────────────
    CredentialSpec(
        key="google_api_key",
        category="api_key",
        pattern=r"(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9_\-])",
        severity="high",
        request_side=True,
        positive=("AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI",),
        negative=("AIzaShort", "XAIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"),
        note="AIza + 35 位。",
    ),

    # ── Azure ──────────────────────────────────────────────
    CredentialSpec(
        key="azure_key",
        category="api_key",
        pattern=r"(?i)\bazure[_a-z]*key\s*[:=]\s*\S{20,}",
        severity="high",
        request_side=True,
        positive=("azure_api_key = 0123456789abcdef0123456789abcdef",),
        negative=("azure key 是什么意思",),
        note="键名 + 分隔符 + 20 位以上值，避免只提到词。",
    ),

    # ── 通用密钥键值对 ──────────────────────────────────────
    CredentialSpec(
        key="generic_secret",
        category="api_key",
        pattern=(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)"
            r"\s*[:=]\s*['\"]?"
            # ★ 2026-11-13（回归修复）：首字符**不能**是 `/`。
            #   字符类补上 `+/=` 之后，下面这些正常配置被请求侧整条阻断：
            #     api_key = /usr/local/share/nginx
            #     api_key = /etc/ssl/private/server.key
            #   `键名 = /路径` 是最普通的配置写法（值是文件位置，不是密钥）。
            #   真实密钥首字符不会是 `/`（Base64 首字符是字母或数字，
            #   即便含 `/` 也只是中间分隔）。用首字符约束表达，
            #   而不是靠「PATH / FILE / DIR」这些语境词。
            r"(?!/)[A-Za-z0-9\-_/+=]{16,}"
        ),
        severity="high",
        request_side=True,
        positive=(
            "api_key = abcd1234efgh5678ijkl",
            # ★ 2026-11-13（回归修复）：值里含 `/` 的 base64 风格密钥。
            #   旧输出护栏写的是 `api[_-]?key\s*[:=]\s*\S{16,}`（任意非空白），
            #   收敛到本表时字符类收了 `-/_`，把 `/` `+` `=` 漏在外面 →
            #   AWS secret 这类含 `/` 的值不再命中，是实打实的漏报。
            "api_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        negative=(
            "api key 应该怎么申请",
            "api_key 这个字段是必填的吗",
            # ★ 值是文件路径（普通配置），不是密钥 —— 必须放行
            "api_key = /usr/local/share/nginx",
            "api_key = /etc/ssl/private/server.key",
        ),
        note=(
            "必须有分隔符与实值，光提到键名不算。"
            "★ 值字符类必须含 `+/=`：base64 风格的密钥（AWS secret、"
            "部分云厂商 token）里这三类字符很常见，收窄会造成漏报。"
            "★ 但首字符不能是 `/`：`键名 = /路径` 是最普通的配置写法，"
            "补上 `/` 之后这两条正常内容曾被整条阻断（实测）。"
        ),
    ),

    # ── GitHub / GitLab ────────────────────────────────────
    CredentialSpec(
        key="github_token",
        category="api_key",
        pattern=r"\bgh[pousr]_[A-Za-z0-9]{36,}",
        severity="high",
        positive=("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",),
        negative=("ghp_ 是什么前缀",),
        note="GitHub PAT 现行前缀：ghp_/gho_/ghu_/ghs_/ghr_。",
    ),

    CredentialSpec(
        key="gitlab_token",
        category="api_key",
        pattern=r"\bglpat-[A-Za-z0-9\-_]{20,}",
        severity="high",
        positive=("glpat-xxxxxxxxxxxxxxxxxxxx",),
        negative=("glpat- 是什么意思",),
        note="GitLab Personal Access Token。",
    ),

    # ── JWT ────────────────────────────────────────────────
    CredentialSpec(
        key="jwt",
        category="jwt",
        pattern=(
            # ★★ 2026-11-13（回归修复）：把「排除自家激活码」内联成正则断言。
            #
            #   上一版靠 `allow_if=_is_own_activation_code`，但
            #   `combined_pattern()` 只拼 pattern、不携带 allow_if ——
            #   于是 verifier 的 _SENSITIVE_LEAK_RE 与输出护栏的
            #   _HIGH_RULE_PATTERNS 都**看不到**这个排除条件，实测
            #   「用户贴自家激活码求助」被输出护栏判 high/block（旧版放行）。
            #
            #   排除条件属于判据本身，写进 pattern 才能保证「五处一致」。
            #   XDACT- 是固定 6 字符前缀，固定宽度后视断言合法。
            r"(?<!(?i:XDACT-))"
            r"\beyJ[A-Za-z0-9\-_]{8,}\.eyJ[A-Za-z0-9\-_]{8,}"
            r"\.[A-Za-z0-9\-_]{10,}"
        ),
        severity="high",
        request_side=True,
        positive=(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            # 左侧不是 XDACT- 前缀时照常命中
            '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.'
            'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}',
        ),
        negative=(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.short",   # 签名段太短
            "eyJ 是什么编码",                                  # 只提前缀
            # ★ 本产品自己的激活码（XDACT- + RS256 JWT）：不算用户密钥泄露
            "XDACT-eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "xdact-eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ),
        note=(
            "三段式：头.载荷.签名，第三段必须 ≥10 位。"
            "旧版 verifier/YAML 只匹配前两段（`eyJ...\\.eyJ`），"
            "会把「eyJ 开头的东西」都算成 JWT；企业版又要求签名 ≥43 位。"
            "三处宽度不一致，统一到这里。\n"
            "★★ 自家激活码排除为什么写在正则里而不是 allow_if：\n"
            "  `combined_pattern()` 只拼 pattern，allow_if 会被静默丢弃，"
            "  导致「请求侧放行、响应侧/输出护栏照拦」的口径分裂。"
            "  排除条件必须随 pattern 一起流动。"
        ),
    ),

    # ── Bearer ─────────────────────────────────────────────
    CredentialSpec(
        key="bearer_token",
        category="api_key",
        pattern=(
            # ★★ 2026-11-13（二次回归修复）：必须带 Authorization 上下文。
            #
            #   旧写法只有 `(?i)\bbearer\s+(\S{20,})`，于是下面这些
            #   **普通英文短语**只要够 20 字符就被判成令牌：
            #     Bearer token-based-authentication-is-enabled 对不对
            #     Bearer authentication-with-oauth2-scopes-description
            #   `token-based-authentication-…` 恰好全是 `[A-Za-z\-]`，
            #   长度也够 —— 光靠「值的字符集 + 长度」区分不了
            #   「令牌」与「英文技术短语」，这是形态本身的 ambiguous。
            #
            #   它们已构成真实误报（输出护栏曾判 high/block 丢弃整条回复）。
            #   加「必须含大写或数字」也救不了：`oauth2` 就有数字。
            #
            #   ★ 结构事实：Bearer 是 HTTP 认证**方案名**，它出现的
            #     真实语境只有 `Authorization: Bearer <token>`。
            #     孤立的 `Bearer xxx` 在自然语言里几乎总是「在讨论 Bearer」。
            #     所以要求 `authorization` 前缀，这是协议约定，不是词表。
            r"(?i:authorization)['\"]?\s*[:=]\s*['\"]?(?i:bearer)\s+"
            r"[A-Za-z0-9\-._~+/]{20,}=*"
        ),
        severity="medium",
        detector_category="key_bearer",
        positive=(
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
            'headers = {"Authorization": "Bearer abcdefghijklmnop12345678"}',
            "authorization: bearer 9f8e7d6c5b4a3210fedcba9876543210",
            "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'",
        ),
        negative=(
            "bearer token 怎么传",
            # ★ 真实误报样本：普通英文技术短语，不是令牌
            "Bearer token-based-authentication-is-enabled 对不对",
            "Bearer authentication-with-oauth2-scopes-description",
            "The bearer-token-based-flow-is-recommended",
            "Authorization: Bearer 这个头怎么写",
        ),
        note=(
            "Authorization + Bearer + 20 位以上实值。\n"
            "★ 为什么必须要求 Authorization 前缀 —— 见 pattern 上方的说明：\n"
            "  孤立的 `Bearer <长英文短语>` 与真实令牌在字符集/长度上同形，\n"
            "  只有协议语境能区分。这不是语境词表，是 HTTP 认证方案的固定用法。\n"
            "★ detector_category=\"key_bearer\"：企业版历史落库口径。"
        ),
    ),

    # ── 身份证 ─────────────────────────────────────────────
    CredentialSpec(
        key="cn_id_card",
        category="idcard",
        pattern=r"(?<![0-9A-Za-z])[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
                r"(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9A-Za-z])",
        severity="high",
        request_side=True,
        validator=cn_id_checksum_valid,
        positive=(
            "110101199003078670",
            "身份证 310101198506121004 请核对",
        ),
        negative=(
            "110101199003078671",       # 校验位错
            "订单号 123456789012345678", # 18 位但非身份证结构
        ),
        note=(
            "正则先圈定「省市区 + 生日 + 顺序码 + 校验位」结构，"
            "再用 MOD 11-2 校验。旧版 _check_output 用裸 `\\b\\d{17}[\\dXx]\\b` "
            "无校验，把 18 位订单号判成身份证。"
        ),
    ),

    # ── 银行卡 ─────────────────────────────────────────────
    CredentialSpec(
        key="bank_card",
        category="bankcard",
        pattern=r"(?<![0-9A-Za-z])\d{15,19}(?![0-9A-Za-z])",
        severity="high",
        request_side=True,
        validator=luhn_valid,
        detector_severity="medium",
        positive=(
            "4111111111111111",
            "5500000000000004",
        ),
        negative=(
            "4111111111111112",          # Luhn 不过
            "123456789012345",           # Luhn 不过
        ),
        note=(
            "15–19 位 + Luhn。旧版企业版用 13–19 无上限，"
            "且 _check_output 完全没有银行卡规则（13 位卡号直接放行）。\n"
            "★ detector_severity=\"medium\"：企业版历史上对银行卡是**打码**，"
            "不是拦截。上一版把它统一成 high 会让企业版从「打码」变「拦截」，"
            "属于静默改变产品行为。两侧严重级含义不同，已在字段注释里说明。\n"
            "★ 带空格分隔的卡号（5500 0000 0000 0004）不在本判据范围内："
            "送检前需要先归一化空白，这一点由各消费方负责，本表只认连续数字。"
        ),
    ),

    # ── 手机号 ─────────────────────────────────────────────
    CredentialSpec(
        key="cn_phone",
        category="phone",
        pattern=r"(?<!\d)1[3-9]\d{9}(?!\d)",
        severity="medium",
        request_side=True,
        positive=("13812345678", "手机 15900001111 请回电"),
        negative=("12345678901", "12812345678"),
        note="中国大陆 11 位手机号。",
    ),

    # ── 邮箱 ───────────────────────────────────────────────
    CredentialSpec(
        key="email",
        category="email",
        # ★★ 2026-11-13（性能修复）：旧写法
        #     \b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b
        #   在长非空白串上会平方级回溯 —— 实测 "sk-" × 2万（6 万字符）
        #   耗时 17 秒，"-----BEGIN" × 1万 耗时 13.7 秒。
        #   根因：`+` 无长度上限 + `\b` 末尾断言，匹配失败后要逐字符回退
        #   重试。真实请求里只要模型输出一段长 base64，主链路就会卡住。
        #
        #   修复：给三段都加上**现实长度上限**（本地部分 ≤64、域名 ≤255、
        #   TLD ≤24，均符合 RFC 5321），并用显式前后边界替代 `\b`。
        #   半径缩短后不再需要长距离回退，实测降到 3 毫秒。
        pattern=(
            r"(?<![A-Za-z0-9._%+\-])"
            r"[A-Za-z0-9._%+\-]{1,64}"
            r"@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}"
            # ★ 2026-11-13（回归修复）：尾部边界**不能**排除 `.`。
            #   上一版写成 (?![A-Za-z0-9.\-])，于是句末形态
            #   「请把材料发到 user@example.com.」整条不命中 →
            #   请求侧 pass（邮箱明文外发），而响应侧 _PII_LEAK_RE
            #   用 \b 仍能命中 → 两侧口径分裂。
            #   句号属于句子的结束符，不是邮箱的一部分；
            #   域名本身不允许以 `.` 结尾，所以这里只需排除
            #   字母数字与连字符就够（`-` 排除是为了不切在域名中间）。
            #   注意不能放宽成完全不排除 —— 那会让 user@example.com.cn
            #   只匹配到 .com 部分。
            r"(?![A-Za-z0-9\-])"
        ),
        severity="low",
        request_side=True,
        positive=(
            "user@example.com",
            "first.last+tag@sub.example.co.uk",
            # ★ 句末形态：句号是句子结束符，不是邮箱的一部分
            "请把材料发到 user@example.com.",
            "请把材料发到 user@example.com。",
        ),
        negative=(
            "这不是邮箱",
            "@example.com",
            "user@",
            "a" * 100 + "@example.com",
        ),
        note=(
            "标准邮箱形态；单独 @ 不算。三段都设了 RFC 上限，"
            "这是消除平方级回溯的关键，不要为了「支持超长邮箱」把上限去掉。"
        ),
    ),

    # ── 裸 hex（AES 原始密钥）──────────────────────────────
    CredentialSpec(
        key="hex_aes_key",
        category="api_key",
        pattern=r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64})(?![0-9a-fA-F])",
        severity="medium",
        detector_category="key_hex_aes",
        positive=(
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        negative=(
            "0123456789abcde",   # 15 位，不够
            "g123456789abcdef0123456789abcdef",  # 含非 hex 字符
        ),
        note=(
            "AES-128 / AES-256 的原始 hex 密钥。前后必须是非 hex 边界，"
            "避免误伤 UUID 或更长 hex 串的一段。\n"
            "★★ 为什么不开请求侧（2026-11-13 实测 3 条误报）：\n"
            "  32 位 / 64 位裸 hex 与 MD5 / SHA-256 摘要**完全同形**，"
            "  文本上没有任何可判别特征。实测被阻断的三句是：\n"
            "    「这个提交的哈希是 3f2a9c…8b，帮我看看有没有冲突。」\n"
            "    「哈希值 5d4140…c592 对应什么原文？」\n"
            "    「这个 32 位十六进制字符串是 MD5 吗：d41d8c…7e？」\n"
            "  三者都是用户拿哈希来提问，属最常见的正常用法。\n"
            "  不能靠「附近有『哈希/MD5』就放行」来救 —— 那是把语境词表"
            "  一条条硬编码，换个说法（校验和、摘要、commit id、指纹）"
            "  就再次误报，永无尽头。\n"
            "  所以这里只声明一个事实：这条判据的形态是 ambiguous 的。\n"
            "  `request_side` 默认就是 False，本条因此无需显式声明；\n"
            "  检测侧（sensitive_leak，只记录与告警，误报代价低）仍然启用，"
            "  真正的 AES 密钥出现在被检文本里照样能被抓住。"
        ),
    ),

    # ── 证书 / 公钥块（输出侧泄露）────────────────────────
    CredentialSpec(
        key="pem_certificate",
        category="certificate",
        pattern=(
            r"-----BEGIN(?: [A-Z]+)?(?: CERTIFICATE| PUBLIC KEY| RSA PUBLIC KEY)-----"
            r"[\s\S]{0,128}?[A-Za-z0-9+/=_\-]{48,}"
        ),
        severity="medium",
        positive=(
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n"
            "-----END CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7VJTUt9Us8cKjMzEfYyj\n",
        ),
        negative=(
            "-----BEGIN CERTIFICATE----- 怎么解析？",   # 只提到标记
            "-----BEGIN PUBLIC KEY-----",               # 只有头部
        ),
        note=(
            "证书与公钥单独成类：它们不是「用户凭据」，而是模型输出里可能夹带的块。"
            "输出护栏要把它们当泄露处理，请求侧不必阻断 —— 分类不同，处置策略才不同。"
            "旧实现对这两个是裸头部匹配，模型问「CERTIFICATE 怎么解析」就被判泄露整条回复。"
        ),
    ),

    # ── 护照 ───────────────────────────────────────────────
    CredentialSpec(
        key="cn_passport",
        category="passport",
        pattern=r"(?<![A-Za-z0-9])(?:[EG]\d{8}|D\d{7})(?![A-Za-z0-9])",
        severity="medium",
        positive=("E12345678", "护照号 D1234567"),
        negative=("E1234", "X12345678"),
        note="中国护照：E/G + 8 位，或 D + 7 位。",
    ),

    # ── 车牌 ───────────────────────────────────────────────
    CredentialSpec(
        key="cn_plate",
        category="plate",
        pattern=(
            r"(?<![A-Za-z0-9])"
            r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领]"
            r"[A-Z][A-HJ-NP-Z0-9]{5,6}[A-HJ-NP-Z0-9挂学警港澳]?"
            r"(?![A-Za-z0-9])"
        ),
        severity="low",
        positive=("京A12345", "沪B88888"),
        negative=("这不是车牌", "A12345"),
        note="省简称 + 字母 + 5~6 位；排除 I/O 避免与数字混淆。",
    ),
)

#: key → spec，供消费方按需取用
BY_KEY = {s.key: s for s in SPECS}


def specs_for(category: str) -> List[CredentialSpec]:
    """取某一处置类别下的全部判据。"""
    return [s for s in SPECS if s.category == category]


def find_all(text: str) -> List[Tuple[int, int, str, "CredentialSpec"]]:
    """按位置排序返回全部凭据命中。重叠区间保留更长的那个。"""
    hits: List[Tuple[int, int, str, CredentialSpec]] = []
    for spec in SPECS:
        for start, end, value in spec.find(text):
            hits.append((start, end, value, spec))
    if not hits:
        return []
    hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
    out: List[Tuple[int, int, str, CredentialSpec]] = []
    for hit in hits:
        if out and hit[0] < out[-1][1]:
            continue  # 被更靠前、更长的命中覆盖
        out.append(hit)
    return out


def combined_pattern(keys: Sequence[str]) -> str:
    """把若干判据合成一条 alternation（供 verifier 这类一次性 search 的场景用）。

    ★ 必须处理内联的全局标志 `(?i)`：同一段正则塞进 alternation 后，
      Python 要求 `(?i)` 只能出现在整个表达式最开头，否则抛
      `global flags not at the start of the expression`。
      这里把 `(?i)rest` 改写成作用域形式 `(?i:rest)`，
      调用方不再需要（也不应该）在 `re.compile` 上加 IGNORECASE ——
      那会把所有判据一起放宽，实测把 `SK-hynix…` 判成密钥。

    ★★ 为什么对带 `validator` / `allow_if` 的判据直接报错
    ────────────────────────────────────────────────────────────
    合成的正则只有「形状」，**无法携带校验位与排除条件**：

      · 身份证的 MOD 11-2、银行卡的 Luhn 都在 validator 里 ——
        丢掉它，18 位订单号会被判成身份证。
      · 排除器同理：JWT 排除自家激活码的条件若留在 allow_if，
        合成后就消失，于是「请求侧放行、响应侧与输出护栏照拦」。
        实测自家激活码被输出护栏判 high/block。

    这两类判据必须逐条 `spec.find()`（校验器与排除器都在那里生效），
    不能走合成路径。让它在拼接时**当场报错**，比事后发现
    「某处悄悄少了一层语义」代价小得多。
    """
    invalid = [
        k for k in keys
        if BY_KEY[k].validator is not None or BY_KEY[k].allow_if is not None
    ]
    if invalid:
        raise ValueError(
            "以下判据带校验器或排除器，不能合成为单条正则"
            "（合成会丢掉校验位与排除条件）："
            f"{invalid}。请改用逐条 spec.find()。"
        )
    parts = [f"(?:{_scope_inline_flags(BY_KEY[k].pattern)})" for k in keys]
    return "|".join(parts)


def _scope_inline_flags(pattern: str) -> str:
    """把 `(?i)rest` 改写成 `(?i:rest)`，使标志只作用于本分支。

    只处理出现在分支开头的全局标志 —— 本项目全部判据都是这个写法。
    """
    m = re.match(r"^\(\?([aiLmsux]+)\)(.*)$", pattern, re.S)
    return f"(?{m.group(1)}:{m.group(2)})" if m else pattern


#: YAML 导出时包含的判据键（与 detection_rules.yaml 的 sensitive_leak 段一致）
YAML_EXPORT_KEYS: Tuple[str, ...] = (
    "private_key_pem",
    "openai_key",
    "aws_access_key_id",
    "jwt",
)


def export_yaml_block() -> str:
    """生成 detection_rules.yaml 的 sensitive_leak 段（供同步与断言用）。"""
    label_map = {
        "private_key_pem": "PEM 私钥",
        "openai_key": "OpenAI / Anthropic 风格密钥",
        "aws_access_key_id": "AWS Access Key",
        "jwt": "JWT 令牌",
    }
    lines = []
    for key in YAML_EXPORT_KEYS:
        spec = BY_KEY[key]
        lines.append(f"  - pattern: '{spec.pattern}'")
        lines.append(f"    label: {label_map[key]}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    import sys

    if "--export-yaml" in sys.argv:
        print(export_yaml_block())
    else:
        for s in SPECS:
            print(f"{s.key:<20} {s.category:<12} {s.severity}")

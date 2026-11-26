# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""tool_call 参数的统一解码与命令词法工具。

★★ 2026-11-26：为什么必须有这一层
────────────────────────────────────────────────────────────────
此前 verifier 与 baseline 各自在 **JSON 原文**上做正则/词法判断：

  · `\"` 被当成转义引号，`"a|b"` 里的管道被吞；
  · `\n` 与 Windows 路径 `C:\new` 混在一起；
  · `description` 说明文字和 `command` 被拼成同一条命令；
  · `pip install` 同行的注释、版本号、路径被当成包名。

这些不是某条规则的 bug，而是「所有检测器都直接吃原始文本」的结构问题。
本模块提供唯一的解码入口；任何新的检测规则都必须通过它拿参数文本，
不要自己 `json.loads` 或直接在 `arguments` 字符串上做词法判断。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, List, Optional, Set, Tuple

#: tool_call 参数里「不是执行面」的字段名。
#: 说明 / 查询 / 正文这些字段写什么都不该被当成即将执行的命令。
#: ★ 不再用「有 command 就只取 command」—— 那会丢掉同一调用里的
#:   `url` / `file_path` 等执行面字段，让端点判据被一个良性 command 绕过。
NON_EXEC_FIELD_KEYS = frozenset({
    "description", "desc", "reason", "message", "msg", "query", "prompt",
    "content", "text", "notes", "note", "summary", "explanation",
    "title", "label", "caption", "comment", "comments",
})

#: 命令段分隔符：shell 分隔符 + 真实换行。
#: 参数文本必须先经 `decode_tool_arguments`，JSON 的 `\n` 才会变成真实换行；
#: 这样 Windows 路径 `C:\new` 里的反斜杠+n 不会被误当分隔符。
SEGMENT_SEP_RE = re.compile(r"[;&|\n]")


def decode_tool_arguments(raw: Any, include_non_exec: bool = False) -> str:
    """把 tool_call 的 arguments JSON 还原成真实命令文本。

    · 默认排除说明/查询/正文类字段（`description` / `query` / `content` 等），
      它们不是执行面；
    · 其余字符串字段全部保留（`command`、`url`、`file_path`、`script`…），
      避免「一个良性 command 掩盖同调用里的真实端点」；
    · `include_non_exec=True` 时连说明/正文一起返回 —— 写入类工具需要
      对正文留观测项（`eval(` 写在文档里应记录，但不应阻断）；
    · 全部被排除时退回全部字符串（MCP / 非标准工具）；
    · 解析失败时退回原文（纯文本参数）。

    ★ 这是全项目唯一的参数解码入口。检测器不要再自己解析 `arguments`。
    """
    if not isinstance(raw, str):
        raw = str(raw or "")
    try:
        obj = json.loads(raw)
    except (TypeError, ValueError):
        return raw

    exec_vals: List[str] = []

    def _walk_exec(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if (
                    not include_non_exec
                    and isinstance(k, str)
                    and k.lower() in NON_EXEC_FIELD_KEYS
                ):
                    continue
                if isinstance(v, str):
                    exec_vals.append(v)
                elif isinstance(v, (dict, list)):
                    _walk_exec(v)
        elif isinstance(o, list):
            for v in o:
                _walk_exec(v)

    _walk_exec(obj)
    if exec_vals:
        return "\n".join(exec_vals)

    vals: List[str] = []

    def _walk(o: Any) -> None:
        if isinstance(o, str):
            vals.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                _walk(v)
        elif isinstance(o, list):
            for v in o:
                _walk(v)

    _walk(obj)
    return "\n".join(vals) if vals else raw


def segment_spans(text: str) -> List[Tuple[int, int]]:
    """按引号/注释感知切分命令段，返回每段的 (start, end)。

    ★ 2026-11-27：`Where-Object { $_.Name -match 'a|b' }` 里的 `|` 是正则
      交替符，`cmd # | cat` 的 `|` 在注释里 —— 都不是命令段分隔符。
      裸 SEGMENT_SEP_RE 切分会把它们当管道，导致下游判据误报/漏放。
      引号/转义/注释规则与 split_unquoted 保持一致。

    ★ 引号不闭合时（Windows 尾反斜杠 `"H:\\XuanDun\\"` 会吞掉闭合引号）
      退回裸分隔符切分：此时引号感知切分会把后面的真管道一起吞掉，
      宁可多拦不可漏放。
    """
    if not quotes_balanced(text):
        spans: List[Tuple[int, int]] = []
        start = 0
        for sep in SEGMENT_SEP_RE.finditer(text):
            spans.append((start, sep.start()))
            start = sep.end()
        spans.append((start, len(text)))
        return spans

    spans = []
    start = 0
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        # 单引号内反斜杠不是转义符
        if quote == "'":
            if ch == "'":
                quote = ""
            i += 1
            continue
        # 转义：`\` / 反引号只跳过**下一个字符**（与 quotes_balanced /
        # is_inside_quotes / shell 语义一致）。旧实现吞整串转义符再多吞
        # 一个字符，`"C:\\"` 会把闭合引号也吞掉 → 后续真管道消失。
        if ch in ("\\", "`"):
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "#" and (
            i == 0 or text[i - 1].isspace() or text[i - 1] in ";&|("
        ):
            # 注释延伸到行尾，里面的分隔符不算命令段边界
            end = text.find("\n", i)
            if end == -1:
                end = len(text)
            spans.append((start, end))
            start = end
            i = end
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch in ";&|\n":
            spans.append((start, i))
            start = i + 1
        i += 1
    spans.append((start, len(text)))
    return spans


def command_segment_span(text: str, pos: int) -> Tuple[int, int]:
    """命中位置所在命令段的 (start, end)，分隔符按引号/注释感知切分。"""
    spans = segment_spans(text)
    for idx, (s, e) in enumerate(spans):
        if s <= pos < e:
            return s, e
        if pos == e:
            # 命中正落在分隔符上：按危险命令判据的约定，算作下一段的开头
            if idx + 1 < len(spans):
                return spans[idx + 1]
            return s, e
    return 0, len(text)


def command_segment_at(text: str, pos: int) -> str:
    """取命中位置所在的命令段（最后一个分隔符之后 → 下一个分隔符之前）。

    ★ 用 `<=`：危险命令判据的匹配本身可能**从分隔符开始**
      （`(?:^|[;&|(\n"'])` 把 `;` 算进匹配），此时命中位置正落在
      分隔符上，必须把它也算作段边界，否则会把前一段的 echo 误当成本段。

    ★ 2026-11-27：分隔符改为引号/注释感知 —— 引号内的 `|`（正则交替符）
      和注释里的 `|` 不再被误当成管道。
    """
    seg_start, seg_end = command_segment_span(text, pos)
    return text[seg_start:seg_end]


def split_unquoted(text: str, sep: str = "|") -> List[str]:
    """按引号外的分隔符切分。

    ★ 2026-11-26：`Where-Object { $_.Name -match 'env|key' }` 里的 `|`
      是正则交替符，不是管道。按裸 `|` 切会把它当成命令段，
      导致白名单判断失效并误报 high。
    """
    parts: List[str] = []
    buf: List[str] = []
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        # 单引号内反斜杠不是转义符（bash/PowerShell 同此语义），
        # `'a\' | cat` 的引号在这里闭合，后面的管道仍然有效。
        if quote == "'":
            buf.append(ch)
            if ch == "'":
                quote = ""
            i += 1
            continue
        # 转义：`\` / 反引号只跳过**下一个字符**（与 quotes_balanced /
        # is_inside_quotes 保持一致）。吞整串会让 `"C:\\"` 的闭合引号
        # 被吃掉，后面的真管道随之消失。
        if ch in ("\\", "`"):
            buf.append(ch)
            i += 1
            if i < len(text):
                buf.append(text[i])
                i += 1
            continue
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        else:
            if ch == "#" and (
                i == 0 or text[i - 1].isspace() or text[i - 1] in ";&|("
            ):
                # shell/PowerShell 注释：后面的 `|` 不是管道
                buf.append(text[i:])
                break
            if ch in ("'", '"'):
                quote = ch
                buf.append(ch)
            elif ch == sep:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def strip_quoted(text: str) -> str:
    """去掉引号包裹的内容，用于判断脚本块里是否出现读取原语。"""
    return re.sub(r"'[^']*'|\"[^\"]*\"", "", text)


def is_inside_quotes(text: str, pos: int) -> bool:
    r"""位置 pos 是否落在引号内。

    ★ 2026-11-26：`\.env` 在引号内多半是正则/字面量，在引号外多半是路径。
      这是区分「正则转义」与「Windows 路径分隔符」的主要依据。
    """
    quote = ""
    i = 0
    while i < pos:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = ""
            i += 1
            continue
        if quote:
            if ch in ("\\", "`") and i + 1 < len(text):
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("\\", "`") and i + 1 < len(text):
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
        i += 1
    return bool(quote)


def quoted_token_at(text: str, pos: int) -> str:
    """返回位置 pos 所在引号内的文本；不在引号内返回空串。"""
    quote = ""
    qstart = -1
    i = 0
    while i < len(text):
        ch = text[i]
        if quote == "'":
            if ch == "'":
                if qstart < pos < i:
                    return text[qstart + 1:i]
                quote = ""
                qstart = -1
            i += 1
            continue
        if quote:
            if ch in ("\\", "`") and i + 1 < len(text):
                i += 2
                continue
            if ch == quote:
                if qstart < pos < i:
                    return text[qstart + 1:i]
                quote = ""
                qstart = -1
            i += 1
            continue
        if ch in ("\\", "`") and i + 1 < len(text):
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            qstart = i
        i += 1
    if quote and qstart < pos:
        return text[qstart + 1:]
    return ""


def quotes_balanced(text: str) -> bool:
    """引号是否闭合。

    ★★ 2026-11-26：Windows 路径 `"H:\\XuanDun\\"` 的尾反斜杠是字面量，
      但词法器无法与 bash 的 `\\"` 区分。引号不闭合时按 fail-closed
      处理：后续 `|` 一律视为管道，宁可多拦不可漏放。
    """
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = ""
            i += 1
            continue
        if quote:
            if ch in ("\\", "`") and i + 1 < len(text):
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("\\", "`") and i + 1 < len(text):
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (
            i == 0 or text[i - 1].isspace() or text[i - 1] in ";&|("
        ):
            # 注释里的撇号不算引号
            break
        i += 1
    return quote == ""


@dataclass(frozen=True)
class ShellToken:
    """命令段里的一个词（保留在原文本中的位置）。"""

    text: str
    start: int
    end: int


def shell_tokens(text: str) -> List[ShellToken]:
    r"""按空白切分 shell 词，保留引号内容与位置。

    ★ 2026-11-26：`\.env` 是正则模式还是文件路径，取决于它落在
      哪个参数位置。这里只做轻量分词，不解释 shell 语法。
    """
    tokens: List[ShellToken] = []
    buf: List[str] = []
    start: Optional[int] = None
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = ""
            else:
                buf.append(ch)
            i += 1
            continue
        if quote:
            if ch in ("\\", "`") and i + 1 < len(text):
                buf.append(ch)
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            else:
                buf.append(ch)
            i += 1
            continue
        if ch in ("\\", "`") and i + 1 < len(text):
            if start is None:
                start = i
            buf.append(ch)
            buf.append(text[i + 1])
            i += 2
            continue
        if ch in ("'", '"'):
            if start is None:
                start = i
            quote = ch
            i += 1
            continue
        if ch.isspace() or ch in ";&|":
            if start is not None:
                tokens.append(ShellToken("".join(buf), start, i))
                buf = []
                start = None
            i += 1
            continue
        if ch == "#" and (
            i == 0 or text[i - 1].isspace() or text[i - 1] in ";&|("
        ):
            break
        if start is None:
            start = i
        buf.append(ch)
        i += 1
    if start is not None:
        tokens.append(ShellToken("".join(buf), start, len(text)))
    return tokens


def is_regex_pattern_position(segment: str, pos: int) -> Optional[bool]:
    """`pos` 是否落在「正则模式参数」的位置。

    返回 True / False；无法判断时返回 None（调用方按路径/真读处理）。

    覆盖：
      · grep / egrep / fgrep / rg / findstr：第一个非选项参数是模式；
      · Select-String：`-Pattern` 的值是模式，`-Path` 的值是路径；
      · PowerShell：`-match/-notmatch/-replace/-split` 的下一个词是模式；
      · echo/printf/tee：参数是内容（True）。
    """
    tokens = shell_tokens(segment)
    if not tokens:
        return None
    idx = None
    for i, t in enumerate(tokens):
        if t.start <= pos < t.end:
            idx = i
            break
    if idx is None:
        return None

    cmd = tokens[0].text.rsplit("/", 1)[-1].lower()
    if cmd in ("echo", "printf", "tee"):
        return True
    if cmd in ("grep", "egrep", "fgrep", "rg", "findstr"):
        pattern_idx: Optional[int] = None
        has_file_opt = False
        i = 1
        while i < len(tokens):
            low = tokens[i].text.lower()
            # -f/--file：其值是「模式文件」路径，不是模式
            if low in ("-f", "--file"):
                has_file_opt = True
                i += 2
                continue
            if low.startswith("--file=") or (
                low.startswith("-f") and len(low) > 2
            ):
                has_file_opt = True
                i += 1
                continue
            # -e/--regexp：其值是模式
            if low in ("-e", "--regexp"):
                pattern_idx = i + 1 if i + 1 < len(tokens) else None
                break
            if low.startswith("--regexp=") or (
                low.startswith("-e") and len(low) > 2
            ):
                pattern_idx = i
                break
            # Windows findstr 的 /s /i 等选项
            if low.startswith("-") or (cmd == "findstr" and low.startswith("/")):
                i += 1
                continue
            if not has_file_opt:
                pattern_idx = i
            break
        if pattern_idx is None:
            return False if has_file_opt else None
        return idx == pattern_idx
    if cmd == "select-string":
        pattern_idx: Optional[int] = None
        path_idx = set()
        positional = []
        i = 1
        while i < len(tokens):
            low = tokens[i].text.lower()
            if low == "-pattern" and i + 1 < len(tokens):
                pattern_idx = i + 1
                i += 2
                continue
            if low.startswith("-pattern:") or low.startswith("-pattern="):
                pattern_idx = i
            elif low in ("-path", "-literalpath") and i + 1 < len(tokens):
                path_idx.add(i + 1)
                i += 2
                continue
            elif low.startswith("-path:") or low.startswith("-literalpath:"):
                path_idx.add(i)
            elif not low.startswith("-"):
                positional.append(i)
            i += 1
        if idx in path_idx:
            return False
        if pattern_idx is not None:
            return idx == pattern_idx
        # 无具名 -Pattern：第一个位置参数是模式，其余是路径
        if positional:
            return idx == positional[0]
        return None
    for i, t in enumerate(tokens):
        if t.text.lower() in ("-match", "-notmatch", "-replace", "-split"):
            if i + 1 < len(tokens) and idx == i + 1:
                return True
    return None


def emits_paths(segment: str) -> Optional[bool]:
    """上游命令输出的是文件路径，还是匹配行/文本。

    ★ 2026-11-26：`grep .env file | xargs cat` 里 grep 默认输出匹配行，
      xargs 拿到的不是文件名；`grep -l .env file | xargs cat` 才输出路径。
      这是区分「保守误报」与「真实读取」的关键数据流信息。

    ★ 2026-11-27（撤销 ls 长格式细化）：`ls -l` 的输出行里**仍含文件名
      token**，xargs 按空白切分后会把 `.env` 一起传给 cat；若按「不是裸
      路径」判 False，`ls -l .env* | xargs cat` 会被放行。安全优先，
      `ls` / `dir` 一律按路径输出处理，接受 `ls -l *.env` 的误报。

    返回 True（路径）/ False（文本/匹配行）/ None（无法判断）。
    """
    tokens = shell_tokens(segment)
    if not tokens:
        return None
    cmd = tokens[0].text.rsplit("/", 1)[-1].lower()
    lows = {t.text.lower() for t in tokens[1:]}
    if cmd in ("get-childitem", "gci", "ls", "dir"):
        return True
    if cmd in ("find", "fd"):
        # -exec/-ok/-delete 输出的是命令结果/空，不是路径
        if re.search(r"-exec(?:dir)?\b|-ok(?:dir)?\b|-delete\b", segment, re.I):
            return False
        if cmd == "fd" and re.search(
            r"(?:^|\s)(?:-x|-X|--exec|--exec-batch)\b", segment, re.I
        ):
            return False
        return True
    if cmd == "git":
        sub = tokens[1].text.lower() if len(tokens) > 1 else ""
        if sub == "ls-files":
            return True
        if sub in ("diff", "show") and (
            "--name-only" in lows or "--name-status" in lows
        ):
            return True
        if sub == "grep":
            return bool(lows & {
                "-l", "-L", "--files-with-matches", "--files-without-match",
            })
        return None
    if cmd in ("echo", "printf"):
        return True
    if cmd in ("grep", "egrep", "fgrep", "rg", "findstr"):
        if lows & {
            "-l", "-L", "--files-with-matches", "--files-without-match",
            "-o", "--only-matching", "--files",
        }:
            return True
        if cmd == "findstr" and any(t.startswith("/m") for t in lows):
            return True
        return False
    if cmd == "select-string":
        return False
    if cmd in ("get-content", "gc", "cat", "type", "head", "tail", "more", "less"):
        return False
    return None


#: xargs 中**不需要独立值**的选项（GNU + BSD/macOS）。
#: 这些选项后面的词就是目标命令，不能被当成选项值吃掉。
_XARGS_FLAG_OPTS = frozenset({
    "-0", "-r", "-t", "-p", "-x", "-R", "-o",
    "--null", "--no-run-if-empty", "--verbose", "--interactive",
    "--exit", "--show-limits", "--open-tty", "--replace",
})

#: xargs 中**需要独立值**的选项（GNU + BSD/macOS）。
#: ★ 少列一个，它的值就会被误当目标命令 —— 那是漏放（false negative），
#:   比误报严重。BSD/macOS 的 `-J` / `-S` 属于这一类。
_XARGS_VALUE_OPTS = frozenset({
    "-n", "-P", "-s", "-d", "-L", "-a", "-E", "-I", "-J", "-S",
    "--max-args", "--max-procs", "--max-chars", "--delimiter",
    "--max-lines", "--arg-file", "--process-slot-var",
})


def xargs_targets(segment: str) -> Set[str]:
    """取 `xargs` 后所有**可能**被执行的命令名。

    ★ 2026-11-26：目标命令 = 跳过所有选项及其值后的第一个非选项词。
      但选项表不可能穷举（GNU / BSD / macOS 各不相同，`-e` 语义还冲突），
      所以采用「已知精确 + 未知保守」：

      · 已知无值选项：只跳过自身（`-t` / `-0` / `-r` …）；
      · 已知有值选项：连值一起跳过（`-J` / `-S` / `-I` … 少列一个就是漏放）；
      · 未知选项：不知道吃不吃下一个词，把 `i+1`、`i+2` 两个词都作为候选。
        调用方对「多候选且含读取命令」的形态 fail-closed，
        因此未来新增选项也不会造成漏放，最多多一条误报。

    ★ `-e` 在 GNU 与 BSD 下语义相反（GNU 不吃值 / BSD 吃值）。
      旧实现只向后取两个词就返回，`-e` 后面再堆叠选项时目标命令会整段丢失
      （`xargs -e -t -0 cat` 实际执行 cat，却解析不出 cat）。
      现在按**位置分叉**：两种解释各自继续完整解析，最后合并候选。
      分叉后仍以 `-` 开头的候选只可能是选项，不是命令，予以剔除。
    """
    tokens = shell_tokens(segment)
    if not tokens or tokens[0].text.lower() != "xargs":
        return set()
    candidates: Set[str] = set()
    #: `--` 之后的词：明确是命令，即便以 `-` 开头也不剔除
    explicit: Set[str] = set()
    pending: List[int] = [1]
    seen: Set[int] = set()
    while pending:
        i = pending.pop()
        while 0 < i < len(tokens):
            if i in seen:
                break
            seen.add(i)
            t = tokens[i].text
            if t == "--":
                # 选项终止符：其后第一个词就是目标命令
                if i + 1 < len(tokens):
                    explicit.add(tokens[i + 1].text.lower())
                break
            if t == "-e":
                # GNU: 不吃值 → 从 i+1 继续；BSD: 吃值 → 从 i+2 继续
                pending.append(i + 1)
                pending.append(i + 2)
                break
            # 可选附加值：裸形式不吃下一个词
            if t == "--eof" or t.startswith("--eof="):
                i += 1
                continue
            if t == "-i" or (t.startswith("-i") and len(t) > 2):
                i += 1
                continue
            if t in _XARGS_VALUE_OPTS:
                i += 2
                continue
            # 附着值形式：-n1 / -I{} / -J{} / -S1024 / -EEOF
            if len(t) > 2 and t.startswith((
                "-n", "-P", "-s", "-d", "-L", "-a", "-I", "-J", "-S",
            )):
                i += 1
                continue
            if t.startswith("--") and "=" in t:
                i += 1
                continue
            if t in _XARGS_FLAG_OPTS:
                i += 1
                continue
            if t.startswith("-"):
                # 未知选项：吃不吃下一个词不确定，两种解释都记下
                if i + 1 < len(tokens):
                    candidates.add(tokens[i + 1].text.lower())
                if i + 2 < len(tokens):
                    candidates.add(tokens[i + 2].text.lower())
                i += 1
                continue
            candidates.add(t.lower())
            break
    # 以 `-` 开头的词只可能是选项，不是命令；留着会把单候选误升为多候选。
    # `--` 之后的词已进 explicit，不受此过滤。
    candidates = {c for c in candidates if not c.startswith("-")}
    candidates |= explicit
    return candidates or {"echo"}


def xargs_target(segment: str) -> Optional[str]:
    """取 `xargs` 后唯一确定的命令名；存在歧义时返回 None。"""
    targets = xargs_targets(segment)
    if len(targets) == 1:
        return next(iter(targets))
    return None

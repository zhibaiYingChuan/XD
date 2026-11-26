# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""tool_call 的规范模型与统一遍历。

★★ 2026-11-26：为什么还需要这一层
────────────────────────────────────────────────────────────────
tool_text 解决了「拿到参数后怎么解码/切词」，但 verifier 与 baseline
仍各自遍历 payload 找 tool_call：

  · verifier 只认 OpenAI tool_calls + Anthropic tool_use；
  · baseline 还认 Responses function_call / Gemini functionCall / MCP。

同一个响应，换个网关格式就可能只被其中一侧看见 —— 这是结构性漏报。
本模块把各家的 wire format 收敛成同一个 `ToolCall`，所有检测器只遍历
一次、只认这一种模型；新增网关格式时只改这里，不改规则。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, List, Optional

from .tool_text import decode_tool_arguments


@dataclass(frozen=True)
class ToolCall:
    """一次工具调用的规范表示。"""

    name: str
    raw_args: Any
    exec_text: str       # 执行面（排除 description/query/content 等）
    content_text: str    # 含正文（写入类工具留观测用）
    source: str          # openai / anthropic / responses / gemini / generic


def _make(name: str, args: Any, source: str) -> ToolCall:
    # dict/list 先转 JSON 文本，decode_tool_arguments 才能按字段排除
    raw = json.dumps(args, ensure_ascii=False) if isinstance(args, (dict, list)) else args
    return ToolCall(
        name=name,
        raw_args=args,
        exec_text=decode_tool_arguments(raw),
        content_text=decode_tool_arguments(raw, include_non_exec=True),
        source=source,
    )


def _call_from_dict(obj: dict) -> Optional[ToolCall]:
    """从一个 dict 节点识别 tool_call；识别到就返回规范模型。"""
    # OpenAI chat completions: {"function": {"name", "arguments"}}
    fn = obj.get("function")
    if (
        isinstance(fn, dict)
        and isinstance(fn.get("name"), str)
        and "arguments" in fn
    ):
        return _make(fn["name"], fn.get("arguments", ""), "openai")

    t = obj.get("type")
    # Anthropic / MCP: {"type": "tool_use"/"mcp_tool_use", "name", "input"}
    if t in ("tool_use", "mcp_tool_use", "server_tool_use"):
        if isinstance(obj.get("name"), str) and "input" in obj:
            return _make(obj["name"], obj.get("input", ""), "anthropic")
    # OpenAI Responses: {"type": "function_call", "name", "arguments"}
    if t == "function_call" and isinstance(obj.get("name"), str):
        if "arguments" in obj:
            return _make(obj["name"], obj.get("arguments", ""), "responses")
    # Google Gemini: {"functionCall": {"name", "args"}}
    fc = obj.get("functionCall")
    if isinstance(fc, dict) and isinstance(fc.get("name"), str) and "args" in fc:
        return _make(fc["name"], fc.get("args", ""), "gemini")
    # OpenAI 旧版: {"function_call": {"name", "arguments"}}
    fc = obj.get("function_call")
    if (
        isinstance(fc, dict)
        and isinstance(fc.get("name"), str)
        and "arguments" in fc
    ):
        return _make(fc["name"], fc.get("arguments", ""), "openai_legacy")
    # 通用 MCP / 非标准: {"name": ..., "arguments"/"args"/"input": ...}
    if isinstance(obj.get("name"), str):
        for key in ("arguments", "args", "input"):
            if key in obj and isinstance(obj[key], (str, dict, list)):
                return _make(obj["name"], obj[key], "generic")
    return None


def iter_tool_calls(payload: Any, depth: int = 0) -> List[ToolCall]:
    """遍历 payload，返回所有 tool_call 的规范模型。

    ★ 识别到一个调用后不再递归它的参数 —— 参数里即使出现
      `"tool_calls"` 字样也只是数据，不是新的调用。
    """
    if depth > 8 or not isinstance(payload, (dict, list)):
        return []
    out: List[ToolCall] = []
    if isinstance(payload, dict):
        call = _call_from_dict(payload)
        if call is not None:
            return [call]
        for v in payload.values():
            out.extend(iter_tool_calls(v, depth + 1))
    else:
        for item in payload:
            out.extend(iter_tool_calls(item, depth + 1))
    return out

# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""tool_call 规范模型的格式覆盖测试。

★ 2026-11-26：所有网关格式必须收敛成同一个 ToolCall。
  这里逐格式锁住「能识别、名字对、执行面正确」，防止某个网关
  换个写法就整条检测链失明。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") in sys.path:
    sys.path.remove(str(REPO / "src"))
sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy.tool_calls import iter_tool_calls  # noqa: E402
from daoti_xuandun_personal.proxy import verifier as vf  # noqa: E402

ARGS = {"command": "cat .env", "description": "读取配置"}
RAW = json.dumps(ARGS, ensure_ascii=False)


def _payloads():
    return {
        "openai": {
            "tool_calls": [{"function": {"name": "Shell", "arguments": RAW}}],
        },
        "anthropic": {
            "content": [{"type": "tool_use", "name": "Shell", "input": ARGS}],
        },
        "responses": {
            "type": "function_call", "name": "Shell", "arguments": RAW,
        },
        "gemini": {
            "functionCall": {"name": "Shell", "args": ARGS},
        },
        "openai_legacy": {
            "function_call": {"name": "Shell", "arguments": RAW},
        },
        "generic": {
            "name": "Shell", "arguments": ARGS,
        },
    }


class TestWireFormatCoverage:
    def test_every_format_yields_one_call(self):
        for source, payload in _payloads().items():
            calls = iter_tool_calls(payload)
            assert len(calls) == 1, f"{source} 识别出 {len(calls)} 个调用"
            call = calls[0]
            assert call.name == "Shell", source
            assert call.exec_text == "cat .env", (
                f"{source} 的执行面解码错误：{call.exec_text!r}"
            )
            assert "读取配置" in call.content_text, source

    def test_every_format_still_blocks(self):
        for source, payload in _payloads().items():
            findings = vf._check_tool_calls(payload, "")
            assert any(
                f.category == "tool_call_dangerous" and f.severity == "high"
                for f in findings
            ), f"{source} 格式的 cat .env 没被阻断"

    def test_arguments_inside_args_are_not_new_calls(self):
        """参数内容里出现 tool_calls 字样只是数据，不是新调用。"""
        payload = {
            "tool_calls": [{"function": {
                "name": "Shell",
                "arguments": json.dumps({
                    "command": "echo '\"tool_calls\": []'",
                }),
            }}],
        }
        calls = iter_tool_calls(payload)
        assert len(calls) == 1

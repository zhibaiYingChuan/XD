# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""结构性守卫：tool_call 参数只能走 tool_text 统一解码。

★ 2026-11-26：这是「结构必须不存在」类判据（见 docs/DEVELOPMENT.md 的测试口径）。
  不锁具体文案，只锁一条红线：检测模块不得自己 `json.loads(arguments)`
  或重复实现解码器 —— 否则下一次新增规则又会绕开共享层，误报复发。
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROXY = (
    Path(__file__).resolve().parent.parent
    / "src" / "daoti_xuandun_personal" / "proxy"
)


@pytest.mark.parametrize("name", ["verifier.py", "baseline.py"])
def test_detection_modules_use_shared_decoder(name):
    src = (PROXY / name).read_text(encoding="utf-8")
    # ★ 2026-11-27：检测模块的统一入口是 iter_tool_calls ——
    #   它在 _make 里调用 tool_text.decode_tool_arguments。
    #   旧断言只匹配「源码里出现 decode_tool_arguments 字样」，
    #   注释里提到就能骗过；这里锁真正的调用形态。
    assert "iter_tool_calls(" in src, (
        f"{name} 没有调用 tool_calls.iter_tool_calls —— "
        "网关格式覆盖会与另一侧漂移，参数也不会经共享解码层"
    )
    for line in src.splitlines():
        if "json.loads(" in line:
            pytest.fail(
                f"{name} 直接解析 JSON：{line.strip()} —— "
                "tool_call 参数必须走 tool_text.decode_tool_arguments / iter_tool_calls"
            )


def test_tool_calls_uses_shared_decoder():
    """解码保证锁在 tool_calls 层：iter_tool_calls 必须经共享解码器。"""
    src = (PROXY / "tool_calls.py").read_text(encoding="utf-8")
    assert "decode_tool_arguments(" in src, (
        "tool_calls.iter_tool_calls 没有调用 tool_text.decode_tool_arguments —— "
        "所有检测模块都会拿到原始 JSON 文本"
    )


def test_only_tool_text_defines_decoder():
    for path in PROXY.glob("*.py"):
        if path.name == "tool_text.py":
            continue
        src = path.read_text(encoding="utf-8")
        assert "def decode_tool_arguments" not in src, (
            f"{path.name} 重复实现了参数解码器 —— 共享层必须唯一"
        )

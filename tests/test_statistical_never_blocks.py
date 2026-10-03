# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""统计类信号不得阻断 —— 契约测试。

★ 为什么这条要单独锁住（2026-10-03）
────────────────────────────────────────────────────────────────
用户要求「误报走激进方向」：宁可放过，不可拦错。用户正等着 AI 把活干完，
被统计信号拦住却还要自己判断「这是不是误报」，等于把负担全推给用户。

但「放宽」极易滑成「失效」—— 红队测试全绿并不能证明这一点，
因为它们测的是各自的具体攻击路径，不覆盖「统计信号是否还能阻断」这条边界。
所以这里显式锁死三件事：

  ① 长度/结构突变在任何偏离幅度、任何安全级别下都不能产生 BLOCK
  ② 但真实攻击（非统计类）**仍然必须阻断** —— 不能连坐降级
  ③ 统计类命中必须产生提示，不能静默通过
     （静默会让用户以为防护没开）
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy.verifier import (  # noqa: E402
    STATISTICAL_SIGNALS,
    PatternTracker,
    ResponseVerifier,
    VerificationFinding,
    decide_response_action,
)
from daoti_xuandun_personal.types import Action  # noqa: E402


STATISTICAL = tuple(STATISTICAL_SIGNALS)


def _gate(level: str, findings) -> str:
    """直接调生产代码的决策闸门。

    ★ 刻意不复制那段逻辑 ——
      复制的话，生产代码改了闸门而测试仍按旧逻辑判定，
      测试就成了「永远绿」的假护栏，那正是本文件要防的失效模式。
    """
    action, _ = decide_response_action(level, findings)
    return action


def _finding(category: str, severity: str = "high") -> VerificationFinding:
    return VerificationFinding(
        category=category,
        severity=severity,
        detail=f"{category} 命中",
        evidence="xxx",
    )


class TestStatisticalNeverBlocks:
    """① 统计类信号在任何级别、任何偏离幅度下都不阻断。"""

    @pytest.mark.parametrize("level", ["lenient", "balanced", "strict"])
    @pytest.mark.parametrize("spike", [200, 1000, 5000, 30000])
    def test_length_spike_never_blocks(self, level, spike):
        """★ 用真实 PatternTracker 喂出长度突变。

        实测本机出现过「偏离 124σ」的记录 —— 那只是用户换了个问法。
        若 severity 还随|σ| 升高，最长的那几次就必然被拦。
        """
        tracker = PatternTracker(window_size=10, sigma_threshold=3.0)
        # 先建立稳定基线：三次同样长度
        for _ in range(4):
            tracker.check("s1", "x" * 100)
        # 再喂一个极端长度
        tracker.check("s1", "y" * spike)

        v = ResponseVerifier(level=level, enable_pattern_check=True)
        result = v.verify("z" * spike, session_id="s1")
        assert result.action != Action.BLOCK.value, (
            f"{level} 档下长度突变（{spike} 字符）仍导致阻断 —— "
            f"用户只是问了长问题就被拦下了"
        )

    def test_zero_length_response_not_blocked(self):
        """★ 空响应曾被记为「突然变短 125σ」而阻断。

        空响应是真实故障（上游出错），但正确处理是「报错误」，
        不是「判定为中转站攻击你」—— 两者混在一起会让排查方向跑偏。
        """
        tracker = PatternTracker(window_size=10)
        for _ in range(4):
            tracker.check("s3", "x" * 500)

        v = ResponseVerifier(level="balanced", enable_pattern_check=True)
        result = v.verify("", session_id="s3")
        assert result.action != Action.BLOCK.value, (
            "空响应被当成攻击而阻断 —— 这是上游故障，不该按安全事件处理"
        )

    def test_severity_never_escalates_with_deviation(self):
        """severity 不得随偏离幅度升高。

        这是「整体严重程度取最大值」的前提：
        只要统计类能升到 high，闸门就可能被绕过。
        """
        tracker = PatternTracker(window_size=10, sigma_threshold=3.0)
        for _ in range(4):
            tracker.check("s", "x" * 100)

        severities = []
        for spike in (200, 1000, 5000, 30000, 100000):
            findings = tracker.check("s", "y" * spike)
            for f in findings:
                if f.category in STATISTICAL:
                    severities.append(f.severity)

        assert severities, "没有产生任何统计类 finding，测试无意义"
        assert all(s == "low" for s in severities), (
            f"统计类 severity 随幅度升高了：{sorted(set(severities))} —— "
            f"偏离大不等于被篡改"
        )

    def test_gate_survives_high_severity_marking(self):
        """★ 闸门自身的独立性：即使统计类被标成 high 也不得阻断。

        这是防「将来有人改回去」的最后一道闸。
        只测「当前 severity 是 low」不够——
        那样只要有人重新标 high，阻断就会复活而测试全绿。
        """
        v = ResponseVerifier(level="balanced")
        findings = [
            _finding("length_anomaly", severity="high"),  # 故意标成最高级
        ]
        assert _gate("balanced", findings) != Action.BLOCK.value, (
            "统计类被标成 high 时闸门失效 —— 闸门必须独立于 severity 取值"
        )


class TestRealAttacksStillBlock:
    """② 真实攻击仍然必须阻断 —— 防止「放宽」滑成「失效」。"""

    @pytest.mark.parametrize("category", [
        "system_prompt_inject",
        "undeclared_tool",
        "sensitive_leak",
        "hidden_instruction",
        "model_downgrade",
        "tool_call_dangerous",
    ])
    def test_real_attack_still_blocked(self, category):
        findings = [_finding(category)]
        assert _gate("balanced", findings) == Action.BLOCK.value, (
            f"{category} 不再被阻断 —— "
            f"降级统计信号时把真实攻击一起放过了"
        )

    def test_mixed_statistical_and_real_attack_blocks(self):
        """★ 统计类 + 真实攻击同时命中时，仍必须阻断。

        只看「全部是统计类」的闸门会漏掉这一条：
        若只要有统计类信号就放过，攻击者同时制造一次长度突变即可绕过
        —— 那是可被利用的漏洞，不是理论问题。
        """
        findings = [
            _finding("length_anomaly", severity="low"),
            _finding("system_prompt_inject", severity="high"),
        ]
        assert _gate("balanced", findings) == Action.BLOCK.value, (
            "统计类与真实攻击并存时被放过 —— "
            "攻击者只需额外制造一次长度突变即可绕过闸门"
        )


class TestStatisticalProducesAdvice:
    """③ 统计类命中必须产生提示，不能静默通过。

    静默通过会让用户以为防护没在工作——
    「计数动了却没有任何提示」比「有提示但不好看」更糟。
    """

    def test_resolve_action_lifts_statistical_to_alert(self):
        """★ 真实链路（2026-10-03 补测，此前真的会静默 pass）。

        统计类信号 severity 恒为 low，而 _resolve_action('low', None)
        原实现直接返回 PASS —— 于是用户完全看不到记录。
        非流式路径靠传入 verify_result 走新的 ALERT 分支，
        流式路径靠调用点后那句 `if findings and action == PASS` 兜住。
        两条路径都必须留下痕迹。
        """
        from daoti_xuandun_personal.proxy.app import _resolve_action

        finding = _finding("length_anomaly", severity="low")
        assert _resolve_action("low", None) == Action.PASS.value, (
            "没有任何发现时必须是 pass —— 否则一次正常对话也会被记成可疑"
        )

        class _R:
            findings = [finding]

        assert _resolve_action("low", _R()) == Action.ALERT.value, (
            "统计类命中未产生任何提示 —— 用户会以为防护没开"
        )
        assert _resolve_action("low", _R()) != Action.BLOCK.value, (
            "统计类命中竟导致阻断"
        )

    def test_stream_path_also_leaves_a_trace(self):
        """★ 流式路径的同一道兜底。

        流式在调用点后有 `if findings and action == PASS: action = ALERT`，
        这条断言锁住它 —— 删掉它流式就会静默，而 pytest 不会报任何错。
        """
        src = (REPO / "src" / "daoti_xuandun_personal"
               / "proxy" / "app.py").read_text(encoding="utf-8")
        assert "if findings and action == Action.PASS.value:" in src, (
            "流式路径缺少「有发现项就不得静默 pass」的兜底 —— "
            "统计类命中在流式下会完全不可见"
        )

    def test_real_high_risk_is_not_downgraded_to_alert(self):
        """对照组：真实高危仍必须 BLOCK，不能被「统计类免死」波及。"""
        from daoti_xuandun_personal.proxy.app import _resolve_action

        assert _resolve_action("high", None) == Action.BLOCK.value, (
            "真实高危被降级 —— 统计类免死规则误伤了真实攻击"
        )
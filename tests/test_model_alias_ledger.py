# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""模型别名台账 —— 「命名差异」机制的回归测试（★ 2026-11-10）。

为什么要单独一个文件
────────────────────────────────────────────────────────────────
用户的原话是：「这种硬编码的判断会不停的出问题。你看看有什么机制
可以更加的优化这种问题的出现，既能让用户明白模型被换了，
但不影响他的正常工作。」

在此之前，判据是「枚举后缀白名单」：
    -1017  → 加进日期规则
    -cm    → 加进渠道标记规则
    -dedicated → 加进部署标记规则
每出现一种没见过的写法，就刷一批误报，然后我再改一次代码。
服务商的命名想象力永远跑在枚举表前面 —— 这条路没有终点。

现在的三层机制：

  第一层 · 处置分级
      按「伤害是否已经发生」分档。model_downgrade 是响应**已经到达**
      之后才知道的事，阻断不阻止任何伤害，只让用户拿不到已生成的内容。
      → medium（均衡档提示、严格档才阻断）。

  第二层 · 变化检测替代命名枚举
      为每个中转站记录 (请求模型 → 返回模型)。首次见到只提示一次，
      之后稳定则静默 —— 判据从「名字像不像」换成「这个组合变没变过」。

  第三层 · 用户确认即学习
      日志页「这是同一个模型」→ 台账 confirmed → 此后静默；
      「确实换了模型」→ rejected → 此后继续告警。

本文件锁住三件事：
  ① 新后缀第一次出现时只提示一次，**绝不阻断**；
  ② 引导用户确认的第二个周期起静默（否则提示一次变成提示一辈子）；
  ③ 用户判定必须真的生效，且真降级（能力词差异）不受台账影响。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy import baseline as bl  # noqa: E402
from daoti_xuandun_personal.proxy import verifier as vf  # noqa: E402
from daoti_xuandun_personal.storage.db import PersonalStorage  # noqa: E402
from daoti_xuandun_personal.types import Action  # noqa: E402

DOMAIN = "api.relay-example.com#ab12cd34"


# ══════════════════════════════════════════════════════════════
# 三分类：compatible / capability / naming
# ══════════════════════════════════════════════════════════════

class TestClassifyModelMismatch:
    """把「名字不同」按**用户该采取什么行动**分类，而不是按字面差异。

    ★ 入参约定是**已归一化**的名字（见 classify_model_mismatch 的 docstring）。
      这里统一先过 _normalize_model，否则会把「含快照号的原始名」
      当成能力词差异 —— 那正是线上 pipeline 的做法（先归一化再分类）。
    """

    @staticmethod
    def _k(req: str, resp: str) -> str:
        return bl.classify_model_mismatch(
            bl._normalize_model(req), bl._normalize_model(resp),
        )

    @pytest.mark.parametrize("req,resp", [
        ("deepseek-v4.1-flash", "deepseek-v4.1-flash"),        # 完全相同
        ("gpt-4o", "gpt-4o-2024-11-01"),                       # 快照号
        ("gpt-4o", "gpt-4o-latest"),
        ("deepseek-v4.1-flash", "deepseek-v4.1-flash-1017-cm"),  # 日期 + 渠道
        ("deepseek-v4.1-flash", "deepseek-v4.1-flash-dedicated"),  # 部署形态
    ])
    def test_compatible(self, req, resp):
        assert self._k(req, resp) == bl._MODEL_MISMATCH_COMPATIBLE

    @pytest.mark.parametrize("req,resp", [
        ("gpt-4o", "gpt-4o-mini"),
        ("gemini-1.5-pro", "gemini-1.5-pro-flash"),
        ("claude-3-5-sonnet", "claude-3-5-haiku"),
        ("claude-3-5-sonnet", "claude-3-5-sonnet-2"),   # 版本号冒充
        ("model-a", "model-a-9999"),                    # 非日期数字，逃逸通道
    ])
    def test_capability(self, req, resp):
        assert self._k(req, resp) == bl._MODEL_MISMATCH_CAPABILITY

    @pytest.mark.parametrize("req,resp", [
        ("deepseek-v4.1-flash", "deepseek-v4.1-flash-vendorx"),
        ("gpt-4o", "gpt-4o-hk"),
    ])
    def test_naming(self, req, resp):
        """既不是合法写法、也没有能力词差异 —— 光看名字判不出来。

        ★ 这正是硬编码时代最容易出事的区间：它既不属「明确兼容」，
          也不属「明确降级」，而旧实现只有两分法，只能把它塞进降级。
        """
        assert self._k(req, resp) == bl._MODEL_MISMATCH_NAMING


# ══════════════════════════════════════════════════════════════
# 第一层 + 第二层：提示一次、绝不阻断
# ══════════════════════════════════════════════════════════════

def _baseline(model: str = "deepseek/deepseek-v4.1-flash"):
    return bl.build_baseline({
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
    })


def _diff(resp_model: str, alias_state=None, req="deepseek/deepseek-v4.1-flash"):
    facts = bl.extract_response_facts({"model": resp_model}, "ok")
    return bl.diff_against_baseline(
        _baseline(req), facts, "ok", model_alias_state=alias_state,
    )


class TestNamingDiffIsNotifyOnly:
    """命名差异只能提示，任何档位都不能阻断。"""

    def test_first_sight_is_medium_notice(self):
        findings = _diff(
            "deepseek-v4.1-flash-vendorx",
            {"status": "auto", "is_first": True, "seen_count": 1},
        )
        assert findings, "第一次见到命名差异也不提示 —— 用户永远无从得知"
        assert findings[0]["category"] == "model_naming_diff"
        assert findings[0]["severity"] == "medium"

    def test_blocked_when_ledger_absent_but_still_notify_only(self):
        """未接台账（旧调用路径）时仍是「提示一次」，不是降级。"""
        findings = _diff("deepseek-v4.1-flash-vendorx", None)
        assert findings[0]["category"] == "model_naming_diff"

    @pytest.mark.parametrize("level", ["lenient", "balanced", "strict"])
    def test_never_blocks_at_any_level(self, level):
        """★ 核心断言：三个档位下都不阻断。

        strict 档的 medium 会映射成 BLOCK，必须靠闸门规则五拦下来 ——
        否则用户在严格档下每遇到一个新后缀就被拦一次。
        """
        finding = vf.VerificationFinding(
            category="model_naming_diff", severity="medium",
            detail="x", evidence="x",
        )
        action, _ = vf.decide_response_action(level, [finding])
        assert action != Action.BLOCK.value, (
            f"{level} 档下「模型名可能不同」被阻断 —— 用户当下干不了活"
        )

    @pytest.mark.parametrize("level", ["lenient", "balanced", "strict"])
    def test_always_notifies_at_any_level(self, level):
        """但也不能一声不吭：三个档位都必须给出提示。

        ★ 用户的原话是「既能让用户明白模型被换了，但不影响他的正常工作」。
          只做到「不阻断」而把提示也吞掉，等于把「让他明白」这半边丢了。
        """
        finding = vf.VerificationFinding(
            category="model_naming_diff", severity="medium",
            detail="x", evidence="x",
        )
        action, _ = vf.decide_response_action(level, [finding])
        assert action == Action.ALERT.value, (
            f"{level} 档下命名差异没有产生提示 —— 用户无从得知"
        )

    def test_stable_alias_goes_silent(self):
        """台账里见过多次且用户没否认 → 这是该中转站的稳定写法，静默。"""
        findings = _diff(
            "deepseek-v4.1-flash-vendorx",
            {"status": "auto", "is_first": False, "seen_count": 7,
             "variant_count": 1},
        )
        assert findings == [], (
            "同一组合见过 7 次仍在提示 —— 「提示一次」变成「提示一辈子」"
        )

    def test_name_churn_stops_notifying(self):
        """★ 中转站每轮换个新名字时，不能变成每轮一条提示。

        「首次见到就提示」的机制有个显然的漏洞：只要对方一直换名字，
        每次都是「首次」，于是每轮都提示一条 —— 那和旧版的刷屏
        只是换了个来源。这里用提示预算封住：前 2 种写法各提示一次，
        第 3 种起只记录不提示。
        """
        # 第 1、2 种写法：提示
        for n in (1, 2):
            findings = _diff(
                f"deepseek-v4.1-flash-v{n}x",
                {"status": "auto", "is_first": True, "seen_count": 1,
                 "variant_count": n},
            )
            assert findings, f"第 {n} 种写法没有提示"
        # 第 3 种起：静默
        findings = _diff(
            "deepseek-v4.1-flash-v3x",
            {"status": "auto", "is_first": True, "seen_count": 1,
             "variant_count": 3},
        )
        assert findings == [], (
            "名字一直在变却仍在逐条提示 —— 机制变成了新的刷屏源"
        )


class TestCapabilityStillAlerts:
    """真降级（能力词差异）不受台账影响，仍按 medium 告警并留证。"""

    def test_capability_diff_ignores_ledger(self):
        findings = _diff(
            "deepseek-v4.1-flash-mini",
            {"status": "confirmed", "is_first": False, "seen_count": 99},
        )
        cats = {f["category"] for f in findings}
        assert "model_downgrade" in cats, (
            "用户确认过一次命名差异，就把真降级一起静默了 —— "
            "台账绝不能被用来吞掉能力词差异"
        )
        sev = [f["severity"] for f in findings if f["category"] == "model_downgrade"]
        assert sev == ["medium"], "模型降级又回到 high 了（均衡档会直接阻断）"


# ══════════════════════════════════════════════════════════════
# 第二层：台账本身
# ══════════════════════════════════════════════════════════════

@pytest.fixture()
def store(tmp_path):
    s = PersonalStorage(db_path=tmp_path / "alias.db")
    yield s
    s.close()


class TestAliasLedger:
    def test_first_observation_is_first(self, store):
        st = store.observe_model_alias(DOMAIN, "deepseek-v4.1-flash", "deepseek-v4.1-flash-x")
        assert st["status"] == "auto"
        assert st["is_first"] is True
        assert st["seen_count"] == 1

    def test_second_observation_is_not_first(self, store):
        store.observe_model_alias(DOMAIN, "a-model", "a-model-x")
        st = store.observe_model_alias(DOMAIN, "a-model", "a-model-x")
        assert st["is_first"] is False
        assert st["seen_count"] == 2

    def test_variant_count_grows_with_new_names(self, store):
        """同一个请求模型下出现几种不同的返回名 —— 提示预算的依据。"""
        st1 = store.observe_model_alias(DOMAIN, "m1", "m1-a")
        assert st1["variant_count"] == 1
        st2 = store.observe_model_alias(DOMAIN, "m1", "m1-b")
        assert st2["variant_count"] == 2
        st3 = store.observe_model_alias(DOMAIN, "m1", "m1-c")
        assert st3["variant_count"] == 3
        # 重复见到的旧写法，variant_count 不增长
        st4 = store.observe_model_alias(DOMAIN, "m1", "m1-a")
        assert st4["variant_count"] == 3

    def test_ledger_is_per_relay(self, store):
        """★ 台账必须按中转站隔离。

        同一组模型名在 A 家是正常写法、在 B 家可能是偷换 ——
        合并成一条会让用户在 A 家的确认顺带把 B 家的问题也静默掉。
        """
        store.observe_model_alias("relay-a", "m1", "m1-x")
        store.observe_model_alias("relay-a", "m1", "m1-x")
        st = store.observe_model_alias("relay-b", "m1", "m1-x")
        assert st["is_first"] is True, "台账跨中转站串了"

    def test_status_roundtrip(self, store):
        store.observe_model_alias(DOMAIN, "m1", "m1-x")
        assert store.set_model_alias_status(DOMAIN, "m1", "m1-x", "confirmed")
        assert store.is_model_alias_confirmed(DOMAIN, "m1", "m1-x")
        assert store.set_model_alias_status(DOMAIN, "m1", "m1-x", "auto")
        assert not store.is_model_alias_confirmed(DOMAIN, "m1", "m1-x")

    def test_invalid_status_rejected(self, store):
        store.observe_model_alias(DOMAIN, "m1", "m1-x")
        assert not store.set_model_alias_status(DOMAIN, "m1", "m1-x", "whatever")

    def test_empty_args_are_noop(self, store):
        assert store.observe_model_alias("", "m1", "m1-x") is None
        assert store.observe_model_alias(DOMAIN, "", "m1-x") is None
        assert store.observe_model_alias(DOMAIN, "m1", "") is None


# ══════════════════════════════════════════════════════════════
# 第三层：用户判定即学习
# ══════════════════════════════════════════════════════════════

class TestUserDecisionTakesEffect:
    def test_vendor_prefix_is_not_a_naming_diff(self):
        """带不带 vendor 前缀是同一种写法，不该进台账、也不该提示。

        ★ 这条不只是「少提示一次」的问题：台账键用的是归一化名，
          若这里判成命名差异，用户确认过的组合会因为请求里多写一个
          `deepseek/` 而落到另一个键上，于是确认过一次又提示一次。
        """
        req = bl._normalize_model("deepseek/deepseek-v4.1-flash")
        resp = bl._normalize_model("deepseek-v4.1-flash")
        assert req == resp
        findings = _diff("deepseek-v4.1-flash", None, req="deepseek/deepseek-v4.1-flash")
        assert findings == []

    def test_confirmed_state_silences(self):
        findings = _diff(
            "deepseek-v4.1-flash-vendorx",
            {"status": "confirmed", "is_first": False, "seen_count": 5},
        )
        assert findings == [], "用户已确认是同一个模型，仍在提示"

    def test_rejected_state_keeps_alerting(self):
        findings = _diff(
            "deepseek-v4.1-flash-vendorx",
            {"status": "rejected", "is_first": False, "seen_count": 5},
        )
        assert findings, "用户已判定「确实换了模型」，却静默了"
        assert findings[0]["category"] == "model_downgrade"
        assert findings[0]["severity"] == "medium"


# ══════════════════════════════════════════════════════════════
# 端到端：verify 把台账状态用到判定里
# ══════════════════════════════════════════════════════════════

class TestVerifyUsesAliasState:
    def _verifier(self) -> "vf.ResponseVerifier":
        v = vf.ResponseVerifier(level="balanced", enable_pattern_check=False)
        v._guardrail_available = False
        return v

    def test_balanced_first_sight_is_alert_not_block(self):
        v = self._verifier()
        res = v.verify(
            "好的",
            "s-alias",
            {"model": "deepseek-v4.1-flash-vendorx",
             "choices": [{"message": {"content": "好的"}}]},
            baseline=_baseline(),
            model_alias_state={"status": "auto", "is_first": True, "seen_count": 1},
        )
        assert res.action != Action.BLOCK.value, (
            "均衡档下第一次见到命名差异就阻断 —— 这正是用户报的那个误报"
        )
        assert any(f.category == "model_naming_diff" for f in res.findings)

    def test_confirmed_alias_produces_no_findings(self):
        v = self._verifier()
        res = v.verify(
            "好的",
            "s-alias",
            {"model": "deepseek-v4.1-flash-vendorx",
             "choices": [{"message": {"content": "好的"}}]},
            baseline=_baseline(),
            model_alias_state={"status": "confirmed", "is_first": False, "seen_count": 9},
        )
        assert res.findings == []
        assert res.action == Action.PASS.value

    def test_without_alias_state_still_notify_only(self):
        """未接台账的调用路径（旧代码 / 单测）行为必须仍然安全。"""
        v = self._verifier()
        res = v.verify(
            "好的",
            "s-alias",
            {"model": "deepseek-v4.1-flash-vendorx",
             "choices": [{"message": {"content": "好的"}}]},
            baseline=_baseline(),
        )
        assert res.action != Action.BLOCK.value

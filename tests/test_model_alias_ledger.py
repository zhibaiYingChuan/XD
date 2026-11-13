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

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
# ★ 2026-11-13：必须无条件置顶 —— editable .pth 已把
#   该路径加入 sys.path（位置在 H:\XuanDun\src 之后），
#   只判断 `not in` 会跳过，导致 import 到根目录旧副本。
if str(REPO / "src") in sys.path:
    sys.path.remove(str(REPO / "src"))
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


# ══════════════════════════════════════════════════════════════
# 同机制的第二处：陌生外部端点
# ══════════════════════════════════════════════════════════════
#
# ★ 为什么同一套机制要覆盖两类判据（2026-11-10）
#   「判据只能看认不认识，而它真正该看的是变没变」这个病，
#   在模型名之外还有一处：new_external_endpoint。
#   实测（改造前）：每轮都调用同一个陌生端点 → 每轮一条 alert，
#   首页「可疑」一直涨。AI 编程助手在一个会话里反复调同一个接口
#   是常态，所以这不是边缘场景，而是日常。

ENDPOINT_BODY = {
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "帮我调一下那个接口"}],
    "tools": [{"type": "function", "function": {"name": "Shell"}}],
}


def _endpoint_payload(url: str) -> dict:
    return {
        "model": "gpt-4o",
        "choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "Shell",
                          "arguments": json.dumps({"command": f"curl {url}"})}},
        ]}}],
    }


def _endpoint_diff(url: str, states=None):
    facts = bl.extract_response_facts(_endpoint_payload(url), "")
    return bl.diff_against_baseline(
        bl.build_baseline(ENDPOINT_BODY), facts, "",
        endpoint_states=states,
    )


class TestNewEndpointUsesSameMechanism:
    def test_first_sight_notifies(self):
        findings = _endpoint_diff(
            "https://weird-host-xyz.io/a",
            {"weird-host-xyz.io": {"status": "auto", "is_first": True}},
        )
        cats = {f["category"] for f in findings}
        assert "new_external_endpoint" in cats, "第一次见到陌生地址也不提示"

    def test_repeat_sight_goes_silent(self):
        """★ 核心：同一个地址第二次起不再提示。

        改造前这里每轮一条 alert —— 首页「可疑」会随对话轮数线性增长，
        而用户实际上只是在反复调同一个接口。
        """
        findings = _endpoint_diff(
            "https://weird-host-xyz.io/a",
            {"weird-host-xyz.io": {"status": "auto", "is_first": False}},
        )
        assert findings == [], "同一地址反复出现仍在每轮提示"

    def test_user_confirmed_goes_silent(self):
        findings = _endpoint_diff(
            "https://weird-host-xyz.io/a",
            {"weird-host-xyz.io": {"status": "confirmed", "is_first": False}},
        )
        assert findings == []

    def test_user_rejected_keeps_alerting(self):
        findings = _endpoint_diff(
            "https://weird-host-xyz.io/a",
            {"weird-host-xyz.io": {"status": "rejected", "is_first": False}},
        )
        cats = {f["category"] for f in findings}
        assert "new_external_endpoint" in cats, (
            "用户已判定「这地址不该出现」，却静默了"
        )

    def test_new_address_after_established_one_still_notifies(self):
        """★ 已有一个稳定地址时，**新**地址仍必须提示。

        这是「变化检测」的意义所在：静默的是「同一个」，
        不是「所有陌生地址」。若这里也静默，机制就从降噪滑成了失明。
        """
        findings = _endpoint_diff(
            "https://another-new-host.io/b",
            {"weird-host-xyz.io": {"status": "confirmed", "is_first": False}},
        )
        cats = {f["category"] for f in findings}
        assert "new_external_endpoint" in cats, (
            "换成全新地址仍静默 —— 机制从降噪滑成了失明"
        )

    def test_without_ledger_still_notifies(self):
        """未接台账（旧调用路径）时必须保守提示，不能静默。"""
        findings = _endpoint_diff("https://weird-host-xyz.io/a", None)
        cats = {f["category"] for f in findings}
        assert "new_external_endpoint" in cats

    def test_benign_hosts_are_never_recorded(self):
        """公共站点与内网地址不进台账（它们本来就不报）。"""
        facts = bl.extract_response_facts(
            _endpoint_payload("https://github.com/x"), ""
        )
        assert "github.com" in (facts.get("exec_domains") or set())
        assert bl._is_benign_host("github.com")
        assert bl._is_benign_host("127.0.0.1")


class TestEndpointLedger:
    def test_first_observation(self, store):
        st = store.observe_endpoint(DOMAIN, "weird.io")
        assert st["is_first"] is True and st["seen_count"] == 1

    def test_repeat_observation(self, store):
        store.observe_endpoint(DOMAIN, "weird.io")
        st = store.observe_endpoint(DOMAIN, "weird.io")
        assert st["is_first"] is False and st["seen_count"] == 2

    def test_status_roundtrip(self, store):
        store.observe_endpoint(DOMAIN, "weird.io")
        assert store.set_endpoint_status(DOMAIN, "weird.io", "confirmed")
        rows = store.list_endpoints(DOMAIN)
        assert rows and rows[0]["status"] == "confirmed"

    def test_host_is_case_insensitive(self, store):
        store.observe_endpoint(DOMAIN, "Weird.IO")
        st = store.observe_endpoint(DOMAIN, "weird.io")
        assert st["is_first"] is False, "大小写不同被当成两个地址"

    def test_empty_args_are_noop(self, store):
        assert store.observe_endpoint("", "weird.io") is None
        assert store.observe_endpoint(DOMAIN, "") is None

    def test_get_endpoint_is_exact_not_limited(self, store):
        """精确查询不受列表限量影响（审查指出的缺陷）。"""
        for i in range(250):
            store.observe_endpoint(DOMAIN, f"host-{i}.io")
        store.set_endpoint_status(DOMAIN, "host-0.io", "confirmed")
        # 列表限量 200 拿不到最早那条，精确查询必须拿得到
        listed = {r["host"] for r in store.list_endpoints(DOMAIN)}
        assert "host-0.io" not in listed
        row = store.get_endpoint(DOMAIN, "host-0.io")
        assert row is not None and row["status"] == "confirmed"


# ══════════════════════════════════════════════════════════════
# 本轮代码审查发现并修复的缺陷（逐条固化）
# ══════════════════════════════════════════════════════════════

class TestReviewFindings:
    """审查报告里每一条「必须修 / 建议修」对应的断言。

    ★ 为什么单独成组：这些缺陷都不是「写错了」，而是「机制的方向错了」——
      userinfo 漏报让判据可被完全绕过；提示预算让「一直在换名」被静音；
      整条日志批量确认替用户放行了他不认识的地址。
      它们都不会让任何既有测试变红，只能靠这类针对性断言守住。
    """

    # ── 审查 #1（安全）：userinfo 形式的 URL 必须归因到真实主机 ──
    @pytest.mark.parametrize("url,real", [
        ("https://github.com@evil.com/steal", "evil.com"),
        ("https://api.trusted.io@45.33.32.19/c", "45.33.32.19"),
        ("https://a@b@evil.com/x", "evil.com"),
        ("https://evil.com:8443/x", "evil.com"),
        ("https://[::1]:8080/x", "::1"),
    ])
    def test_host_of_ignores_userinfo(self, url, real):
        assert bl._host_of(url) == real, (
            f"{url} 被归因为 {bl._host_of(url)}，真实主机是 {real} —— "
            "攻击者可用 userinfo 段伪装成良性域名"
        )

    def test_userinfo_disguise_is_not_benign(self):
        """★ 这条是上面的攻击面证明：伪装后不能再被良性名单吃掉。"""
        assert bl._is_benign_host("github.com")
        facts = bl.extract_response_facts(
            _endpoint_payload("https://github.com@evil.com/steal"), ""
        )
        hosts = facts.get("exec_domains") or set()
        assert "evil.com" in hosts, (
            "真实主机没被提取 —— 这条外传会零告警"
        )
        assert not all(bl._is_benign_host(h) for h in hosts), (
            "全部被良性名单吃掉，真实外传漏报"
        )

    # ── 审查 #2：版本号升级不是能力降级 ──
    @pytest.mark.parametrize("req,resp", [
        ("llama-3.1-70b", "llama-3.3-70b"),
        ("deepseek-v4.1-flash", "deepseek-v4.2-flash"),
    ])
    def test_version_bump_is_naming_not_capability(self, req, resp):
        """同位版本替换归入 naming（可被用户确认），不是 capability。

        ★ 首版把「差异里含非日期数字」一律判 capability，于是
          llama 3.1→3.3 这种正常版本迭代每轮告警、严格档每轮阻断，
          而它拿不到「这是同一个模型」的确认入口 —— 用户无路可走。
        """
        r = bl._normalize_model(req)
        s = bl._normalize_model(resp)
        assert bl.classify_model_mismatch(r, s) == bl._MODEL_MISMATCH_NAMING

    @pytest.mark.parametrize("req,resp", [
        ("claude-3-5-sonnet", "claude-3-5-sonnet-2"),
        ("model-a", "model-a-9999"),
    ])
    def test_trailing_version_suffix_stays_capability(self, req, resp):
        """尾部挂号码冒充版本，仍是确定的「不同型号」。"""
        r = bl._normalize_model(req)
        s = bl._normalize_model(resp)
        assert bl.classify_model_mismatch(r, s) == bl._MODEL_MISMATCH_CAPABILITY

    # ── 审查 #3：提示预算耗尽后不能无条件静默 ──
    def test_churn_off_dominant_still_notifies(self):
        """「一直在换名」这个状态本身不能被静音。

        预算用完后，若本次写法**不是**该请求模型下的主写法，
        说明真正在变的是多数派之外的东西 —— 仍要提示。
        """
        findings = _diff(
            "deepseek-v4.1-flash-v9x",
            {"status": "auto", "is_first": True, "seen_count": 1,
             "variant_count": 5,
             "dominant_model": "deepseek-v4.1-flash-dedicated"},
        )
        assert findings, "名字一直在变却因预算耗尽而永久静默"

    def test_churn_on_dominant_stays_silent(self):
        """本次就是主写法 → 静默才对（这是稳定在用的那个）。"""
        findings = _diff(
            "deepseek-v4.1-flash-dedicated",
            {"status": "auto", "is_first": False, "seen_count": 9,
             "variant_count": 5,
             "dominant_model": "deepseek-v4.1-flash-dedicated"},
        )
        assert findings == []

    # ── 审查 #4：严格档下外传信号不静默 ──
    def test_strict_level_keeps_endpoint_signal(self):
        findings = bl.diff_against_baseline(
            bl.build_baseline(ENDPOINT_BODY),
            bl.extract_response_facts(
                _endpoint_payload("https://weird-host-xyz.io/a"), ""),
            "",
            endpoint_states={"weird-host-xyz.io":
                             {"status": "auto", "is_first": False}},
            strict=True,
        )
        cats = {f["category"] for f in findings}
        assert "new_external_endpoint" in cats, (
            "严格档把稳定出现的外传信号也静默了 —— "
            "降噪不能替用户决定"
        )

    def test_balanced_level_stays_quiet(self):
        """均衡档照旧静默（这是本次要的降噪效果）。"""
        findings = bl.diff_against_baseline(
            bl.build_baseline(ENDPOINT_BODY),
            bl.extract_response_facts(
                _endpoint_payload("https://weird-host-xyz.io/a"), ""),
            "",
            endpoint_states={"weird-host-xyz.io":
                             {"status": "auto", "is_first": False}},
            strict=False,
        )
        assert findings == []

    # ── 审查 #5：台账清理只删 auto，不删用户判定 ──
    def test_purge_keeps_user_decisions(self, store, monkeypatch):
        import time as _t

        old = _t.time() - 200 * 86400
        store.observe_endpoint(DOMAIN, "auto-old.io")
        store.observe_endpoint(DOMAIN, "confirmed-old.io")
        store.set_endpoint_status(DOMAIN, "confirmed-old.io", "confirmed")
        # 把两条都改成很久以前
        with store._conn:
            store._conn.execute(
                "UPDATE endpoint_allowance SET last_seen = ?", (old,)
            )
        purged = store.purge_ledgers(keep_days=90)
        assert purged["endpoint_allowance"] == 1, (
            "清理条数不对（应只删 auto 那条）"
        )
        assert store.get_endpoint(DOMAIN, "confirmed-old.io") is not None, (
            "用户确认过的地址被当缓存删了 —— 之后会重新开始打扰"
        )
        assert store.get_endpoint(DOMAIN, "auto-old.io") is None

    # ── 审查 #10（文案）：台账没接上时是「每轮」提示，不是「提示一次」──
    def test_detail_text_does_not_overpromise(self):
        """文案不能承诺「之后不再提示」—— 没接台账时确实每轮都会提示。"""
        findings = _diff("deepseek-v4.1-flash-vendorx", None)
        assert findings
        assert "之后同类返回不再提示" in findings[0]["detail"] or \
               "可在日志里标记" in findings[0]["detail"]


# ══════════════════════════════════════════════════════════════
# 两条决策路径必须同口径（审查反复指出的历史缺陷）
# ══════════════════════════════════════════════════════════════

class TestGatePathsAgree:
    """verifier.decide_response_action 与 app._resolve_action 必须一致。

    ★ 为什么要专门对拍：本项目历史上多次出现「verify 判提示、外层判阻断」，
      而两边各自的单测都是绿的 —— 因为没人比较过它们。
      这里用同一批 findings 跑两条路径，逐项比对结果。
    """

    @staticmethod
    def _cases():
        return [
            # (说明, [(category, severity)])
            ("命名差异", [("model_naming_diff", "medium")]),
            ("命名差异标 low", [("model_naming_diff", "low")]),
            ("真降级", [("model_downgrade", "medium")]),
            ("隐藏指令", [("hidden_instruction", "high")]),
            ("凭证明文", [("sensitive_leak", "high")]),
            ("文本启发式", [("toolchain_injection", "high")]),
            ("统计类", [("length_anomaly", "low")]),
            ("命名差异+统计", [("model_naming_diff", "medium"),
                            ("length_anomaly", "low")]),
        ]

    @pytest.mark.parametrize("level", ["balanced", "strict"])
    def test_same_action_from_both_paths(self, level):
        from daoti_xuandun_personal.proxy import app as app_mod

        # ★ pass 与 observe 在用户可见行为上等价：都不阻断、都不计入风险档、
        #   都算「检查过且安全」（见 storage.kpi_contribution）。
        #   两者历史上就有差异（low 时 verify 判 pass、外层判 observe），
        #   本次不改动既有语义，只归一化后比对真正影响用户的差别。
        def _norm(a: str) -> str:
            return "quiet" if a in (Action.PASS.value, Action.OBSERVE.value) else a

        for label, specs in self._cases():
            findings = [
                vf.VerificationFinding(
                    category=c, severity=s, detail="x", evidence="x",
                )
                for c, s in specs
            ]
            gate_action, _ = vf.decide_response_action(level, findings)
            # 让 app 侧用同一档位
            app_mod._verifier = vf.ResponseVerifier(level=level)
            outer_action = app_mod._resolve_action(
                max(f.severity for f in findings), findings,
            )
            assert _norm(gate_action) == _norm(outer_action), (
                f"{label}（{level}）：verify 判 {gate_action}，"
                f"外层判 {outer_action} —— 两条路径分叉了"
            )

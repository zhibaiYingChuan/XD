# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""内容合规不得当作中转站篡改 + 中转站计数须随日志同步 —— 契约测试。

★ 为什么单独锁住（2026-10-04）
────────────────────────────────────────────────────────────────
用户装完 v0.1.4-alpha 后报了一条日志：

    中转站可能在偷偷改写 AI 的行为
    检测到系统提示词被篡改迹象，属于严重问题，建议换中转站。
    ─── 展开技术细节 ───
    [企业版护栏] 输出内容包含违规语义方向，已拦截
    片段：# 会话总结 ## 1. Primary Request and Intent **本轮用户指令...

实测复现：喂一段**纯正常的会话总结**（内容是「用户希望理解系统提示词
被拦截的原因」），会被判成 block + system_prompt_inject。三处问题：

  ① 归因错：护栏的「违规语义方向」判的是**模型说了什么**，
     落进 `_classify_guardrail_hit` 的兜底（`risk==high` →
     system_prompt_inject）后变成**中转站做了什么**。
     前端据此翻译成「中转站可能在偷偷改写 AI 的行为」——张冠李戴，
     而展示的「证据」片段正是模型自己生成的正常输出。
  ② 触发面宽：模型在讨论安全话题时必然出现「绕过/漏洞/攻击」，
     命中一条关键词即分 0.667 ≥ 阈值 0.5 → 直接拦截。
  ③ 计数不同步：清空日志后首页归零，但中转站卡片还写着旧数字
     （relay_reputation 是累加表，删日志不回退）。

第 ③ 点的判据必须落在「端点上」而不是「存储方法上」——
历史失效形态正是「底层方法对、路由没走它」。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy.verifier import (  # noqa: E402
    OBSERVATION_ONLY_SIGNALS,
    ResponseVerifier,
    VerificationFinding,
    decide_response_action,
)

# 用户报的那条日志的内容形态（会话总结 + 讨论安全话题）
SESSION_SUMMARY = (
    "# 会话总结\n\n## 1. Primary Request and Intent\n"
    "本轮用户指令围绕玄盾工具：日志筛选失效、误报率偏高、"
    "以及中转站是否会绕过检测。用户希望理解系统提示词被拦截的原因，"
    "并确认是否存在漏洞利用风险。\n"
)


class TestContentPolicyIsNeverRelayedToRelay:
    """① 内容合规类必须与「中转站篡改」分开，且任何级别都不阻断。"""

    def test_session_summary_is_not_blocked(self):
        """★ 用户报的那条：纯正常会话总结不得阻断。"""
        for level in ("lenient", "balanced", "strict"):
            v = ResponseVerifier(level=level)
            res = v.verify(SESSION_SUMMARY, session_id="s")
            assert res.action != "block", (
                f"{level} 档下正常会话总结被拦下 —— 用户只是在讨论安全工具，"
                "不是中转站在攻击他"
            )

    def test_content_policy_gate_ignores_level(self):
        """闸门自证：content_policy 即使被标成 high 也不阻断。"""
        f = VerificationFinding(
            category="content_policy", severity="high",
            detail="x", evidence="x",
        )
        for level in ("lenient", "balanced", "strict"):
            action, _ = decide_response_action(level, [f])
            assert action != "block", (
                f"{level} 档下 content_policy 触发了阻断 —— "
                "闸门必须独立于 severity 取值"
            )

    def test_observation_only_set_contains_content_policy(self):
        assert "content_policy" in OBSERVATION_ONLY_SIGNALS
        # 统计类仍在（不能因为加新项而把旧的挤掉）
        assert "length_anomaly" in OBSERVATION_ONLY_SIGNALS
        assert "structure_anomaly" in OBSERVATION_ONLY_SIGNALS


class TestGuardrailClassification:
    """② 分类必须以护栏自己的 reason 为准，不做「判不出来就当中转站篡改」。"""

    def test_violation_direction_maps_to_content_policy(self):
        got = ResponseVerifier._classify_guardrail_hit(
            "一段普通的回答", risk="high", action="block",
            reason="输出内容包含违规语义方向，已拦截",
        )
        assert got == "content_policy", (
            "「违规语义方向」被判成了别的类别 —— 它是模型说了敏感词，"
            "与中转站是否篡改无关"
        )

    def test_high_risk_pattern_maps_to_content_policy(self):
        got = ResponseVerifier._classify_guardrail_hit(
            "一段普通的回答", risk="high", action="block",
            reason="输出内容命中高危违规模式，已拦截",
        )
        assert got == "content_policy"

    def test_reason_beats_content_keyword(self):
        """★ 模型正常提到「系统提示词」这个词，不得翻成「中转站篡改」。

        这正是用户那条日志的成因：护栏说「违规语义」，
        而 content 里恰好有「系统提示词」五个字，
        旧实现先扫 content 就把结论改写了。
        """
        got = ResponseVerifier._classify_guardrail_hit(
            "我的系统提示词不方便透露", risk="high", action="block",
            reason="输出内容包含违规语义方向，已拦截",
        )
        assert got == "content_policy", (
            "护栏已判定为内容合规，却被 content 里的「系统提示词」改写 —— "
            "reason 才是权威，content 词表只是补充"
        )

    def test_real_secret_still_wins_over_reason(self):
        """★★ 强证据优先：真实密钥泄露绝不能被降级成内容合规。

        实测过这个回归：把 reason 判定放在密钥正则之前后，
        `sk-proj-...` 的文本从 block 掉到 alert ——
        那是把误报修成了漏报，比原来的问题更危险。
        """
        got = ResponseVerifier._classify_guardrail_hit(
            "你的密钥是 sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            risk="high", action="block",
            reason="输出内容包含违规语义方向，已拦截",
        )
        assert got == "sensitive_leak", (
            "含真实密钥的响应被判成内容合规 —— 密钥泄露是硬证据，"
            "不能被护栏文案覆盖"
        )

    def test_unknown_reason_returns_none_not_guilt(self):
        """★ 判不出来就是判不出来，不得编造罪名。

        旧实现的兜底把「未知」当成「system_prompt_inject」——
        等于对所有无法归类的拦截都指控中转站篡改。
        """
        got = ResponseVerifier._classify_guardrail_hit(
            "完全正常的回答", risk="high", action="block",
            reason="某个将来才会出现的新原因",
        )
        assert got is None, (
            f"未知原因被归类成 {got!r} —— 未知就是未知，"
            "宁可不出结论也不能指控中转站"
        )

    def test_no_finding_means_no_log(self):
        """归类为 None 时不产生 finding（否则会写一条无依据的日志）。"""
        v = ResponseVerifier()
        assert v._classify_guardrail_hit(
            "正常内容", risk="high", action="block", reason="无缘由的拦截",
        ) is None


class TestRealEvidenceStillBlocks:
    """防止「放宽」滑成「失效」。"""

    def test_real_secret_leak_still_blocks(self):
        v = ResponseVerifier(level="balanced")
        res = v.verify(
            "你的密钥是 sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            session_id="s",
        )
        assert res.action == "block", (
            "真实密钥泄露不再阻断 —— 放宽内容合规时把硬证据一起放过了"
        )

    def test_real_attacks_still_block(self):
        for cat in ("tool_call_dangerous", "undeclared_tool",
                    "hidden_instruction", "model_downgrade"):
            f = VerificationFinding(category=cat, severity="high",
                                    detail="x", evidence="x")
            action, _ = decide_response_action("balanced", [f])
            assert action == "block", f"{cat} 不再阻断"


class TestRelayCountsFollowLogs:
    """③ 中转站计数必须随日志重算，不能各说各话。"""

    @pytest.fixture()
    def store(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        import importlib

        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        from daoti_xuandun_personal.storage import db as db_mod
        importlib.reload(db_mod)
        yield db_mod.PersonalStorage(db_path=tmp_path / "t.db")
        monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
        importlib.reload(paths)

    def _write(self, store, tracker, action, cats, domain="a.example.invalid"):
        from daoti_xuandun_personal.types import LogEntry, LogType
        store.insert_log(LogEntry(
            timestamp=time.time(),
            log_type=LogType.RESPONSE_VERIFY.value,
            relay_domain=domain, action=action, severity="low", model="m",
            finding_count=len(cats), summary="x",
            detail_json=json.dumps([{"category": c} for c in cats]),
        ))
        store.update_daily_stats(total_calls=1)
        rep = tracker.record_call(
            f"https://{domain}", action, 900.0, "内容", categories=cats,
        )
        store.upsert_reputation(rep)

    def test_rebuild_zeroes_counts_after_clear(self, store):
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker
        from daoti_xuandun_personal.types import Action

        tracker = ReputationTracker()
        self._write(store, tracker, Action.PASS.value, [])
        self._write(store, tracker, Action.BLOCK.value, ["tool_call_dangerous"])
        self._write(store, tracker, Action.ALERT.value, ["content_policy"])

        before = tracker.list_all()[0]
        assert before.total_calls == 3
        assert before.relay_danger_count == 1

        store.clear_logs()
        tracker.rebuild_from_facts(store.iter_log_facts())
        for rep in tracker.list_all():
            store.upsert_reputation(rep)

        after = tracker.list_all()[0]
        assert after.total_calls == 0, (
            f"清空日志后中转站仍显示 {after.total_calls} 次调用 —— "
            "首页已归零而这里没归零，用户看到的是两个矛盾的数字"
        )
        assert after.relay_danger_count == 0
        assert after.score == 100, "没有证据了，分数该回到满分"

    def test_facts_only_include_response_verify(self, store):
        """★ 只取响应侧日志：直通/请求侧阻断不该算进调用次数。"""
        from daoti_xuandun_personal.types import (
            Action, LogEntry, LogType,
        )

        store.insert_log(LogEntry(
            timestamp=time.time(), log_type=LogType.RESPONSE_VERIFY.value,
            relay_domain="a.example.invalid", action=Action.PASS.value,
            severity="low", model="m", finding_count=0, summary="x",
        ))
        # 直通日志（不调 record_call）
        store.insert_log(LogEntry(
            timestamp=time.time(), log_type=LogType.RELAY.value,
            relay_domain="a.example.invalid", action=Action.PASS.value,
            severity="low", model="m", finding_count=0, summary="x",
        ))
        facts = store.iter_log_facts()
        assert len(facts) == 1, (
            f"重算取到了 {len(facts)} 条事实，应只取 response_verify —— "
            "把直通日志也算进去会让调用次数凭空变大"
        )

    def test_rebuild_clears_evidence_but_keeps_time_attributes(self, store):
        """★ 定性证据随日志归零，时间属性保留（2026-10-04 改）。

        上一版把「检测到数据保留迹象」当作服务商固有属性保留，
        理由是「它发生过，不该因为你删日志就忘记」。
        但用户实测反馈：**日志一条都没有了，卡片还扣着 30 分**——
        那条扣分已经没有可核对的依据，用户唯一能得出的是软件坏了。

        现在改为：凡是能从日志再现的就跟着日志走；
        first_seen / latency 这类确实无法重建的才保留。
        """
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker
        from daoti_xuandun_personal.types import Action

        tracker = ReputationTracker()
        self._write(store, tracker, Action.PASS.value, [])
        rep = tracker.list_all()[0]
        rep.watermark_detected = True
        rep.notes.append("检测到数据保留迹象：中转站自述保留数据")
        store.upsert_reputation(rep)
        first_seen = rep.first_seen

        store.clear_logs()
        tracker.rebuild_from_facts(store.iter_log_facts())

        after = tracker.list_all()[0]
        assert after.total_calls == 0
        assert after.watermark_detected is False, (
            "日志已清空，水印扣分却还在 —— 用户看到「一条记录都没有"
            "却扣着分」，无从核对"
        )
        assert after.notes == []
        assert after.score == 100, "可核对的证据都没了，分数该回满分"
        assert after.first_seen == first_seen, (
            "first_seen 是时间属性，不该被重算丢掉"
        )

    def test_watermark_is_rebuilt_from_surviving_logs(self, store):
        """★ 反向：日志还在时，水印证据必须被重算出来。

        否则「跟着日志走」会变成「一律清掉」——
        那是把误报修成了漏报。
        """
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker
        from daoti_xuandun_personal.types import (
            Action, LogEntry, LogType,
        )

        tracker = ReputationTracker()
        self._write(store, tracker, Action.PASS.value, [])
        # 日志里存下含「本平台保留数据」声明的片段
        store.insert_log(LogEntry(
            timestamp=time.time(),
            log_type=LogType.RESPONSE_VERIFY.value,
            relay_domain="a.example.invalid", action=Action.PASS.value,
            severity="low", model="m", finding_count=0, summary="x",
            text_preview="本平台保留您的对话记录用于改进服务",
        ))

        tracker.rebuild_from_facts(store.iter_log_facts())

        after = tracker.list_all()[0]
        assert after.watermark_detected is True, (
            "日志里明明有保留数据声明，重算却没识别出来 —— "
            "「跟着日志走」不能变成「一律清掉」"
        )
        assert after.score < 100

    def test_rebuild_is_idempotent(self, store):
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker
        from daoti_xuandun_personal.types import Action

        tracker = ReputationTracker()
        self._write(store, tracker, Action.BLOCK.value, ["tool_call_dangerous"])
        tracker.rebuild_from_facts(store.iter_log_facts())
        once = tracker.list_all()[0].total_calls
        tracker.rebuild_from_facts(store.iter_log_facts())
        twice = tracker.list_all()[0].total_calls
        assert once == twice == 1


class TestEndpointSyncsRelayCounts:
    """★ 端到端：判据落在 HTTP 端点上，而不是存储方法上。

    历史失效形态正是「底层方法对、路由没走它」——
    单元测试全绿而线上仍然错。
    """

    @pytest.fixture()
    def client(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        import importlib

        from fastapi.testclient import TestClient

        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        from daoti_xuandun_personal.proxy import app as app_mod

        try:
            with TestClient(app_mod.create_app()) as c:
                yield c
        finally:
            monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
            importlib.reload(paths)

    def test_clear_endpoint_syncs_relay_card(self, client):
        from daoti_xuandun_personal.proxy import app as app_mod
        from daoti_xuandun_personal.reputation.tracker import (
            ReputationTracker,
        )
        from daoti_xuandun_personal.types import Action, LogEntry, LogType

        store = app_mod._storage
        assert store is not None, "lifespan 未跑，_storage 为 None"
        tracker = ReputationTracker()
        app_mod._reputation = tracker

        for action in (Action.PASS.value, Action.BLOCK.value):
            store.insert_log(LogEntry(
                timestamp=time.time(),
                log_type=LogType.RESPONSE_VERIFY.value,
                relay_domain="api.example.invalid", action=action,
                severity="low", model="m", finding_count=0, summary="x",
                detail_json=json.dumps(
                    [{"category": "tool_call_dangerous"}]
                    if action == "block" else []
                ),
            ))
            store.update_daily_stats(total_calls=1)
            rep = tracker.record_call(
                "https://api.example.invalid", action, 900.0, "内容",
                categories=["tool_call_dangerous"] if action == "block" else [],
            )
            store.upsert_reputation(rep)

        assert store.load_reputations()[0].total_calls == 2

        r = client.post("/api/logs/clear", json={"before_days": 0})
        assert r.status_code == 200, r.text

        reps = store.load_reputations()
        assert reps, "清空日志不该把中转站记录整条删掉"
        assert reps[0].total_calls == 0, (
            "清空日志后中转站卡片仍显示旧调用次数 —— "
            "首页数字与卡片数字互相矛盾，用户只能认为软件坏了"
        )
        assert reps[0].score == 100

# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""中转站信誉评分必须归因正确，且分数不能恒为 0。

本轮发现的两个问题
────────────────────────────────────────────────────────────
用户在首页看到 `api.commandcode.ai  0/100`，扣分明细写着
「危险响应 19 次 × 20 分 = −380」「可疑响应 59 次 × 4 分 = −236」。

查库之后，这 78 条风险**没有一条是中转站的问题**：

  · 19 条「危险」全部是 `length_anomaly`（响应长度突变）
  · 59 条「可疑」全部是 `structure_anomaly`（字符类分布突变）

而 AI 对话的长度本来就天差地别 ——
问「你好」3 个字，回一段代码 11000 字，
基线只有 3 个样本就开跑，σ 动辄几百。
**这判的是「你在哪儿提问」，不是「中转站是否可信」。**

于是中转站在替用户的提问背锅：用户问了个长问题，扣它 20 分。

更糟的是第二个后果：
    分数 = 100 − 19×20 − 59×4 = −616 → 钳到 0
一旦触底就**永远**是 0，此后新增任何风险都显示 0。
一个恒为 0 的分数等于没有分数 ——
它既不反映风险，也无法让用户察觉风险在上升。

为什么这些没被早发现
────────────────────────────────────────────────────────────
代码审查看到的是一个自洽的实现（有扣分项、有钳位、有明细表）。
测试也不会红 —— 因为公式本身没写错，
错的是**输入的归因**：把用户自身导致的事件当成了中转站的罪证。
本文件锁的就是这一层。

判据的设计原则
────────────────────────────────────────────────────────────
★ 必须先自证「长度突变确实不算中转站的责任」，
  否则「分数变高」可能只是因为把扣分算错了 —— 分数高本身没有意义。
★ 反向也要验：真遇到恶意 tool_call 时分数**必须**下来，
  否则就成了「怎么算都不扣分」的和事佬。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.reputation import tracker as tr  # noqa: E402
from daoti_xuandun_personal.types import Action  # noqa: E402

URL = "https://api.commandcode.ai/provider/v1/chat/completions"


def _fresh():
    return tr.ReputationTracker()


def _feed(t, action, n=1, categories=None):
    for _ in range(n):
        t.record_call(URL, action, categories=categories)


class TestAttributionIsCorrect:
    """先自证：哪些检测项算中转站的责任。"""

    def test_length_anomaly_is_not_relay_fault(self):
        """★ 这是全部修复的地基。

        长度突变取决于你问了什么 —— 问「你好」3 字、
        回一段代码 11000 字，突变是必然的。
        把它算成中转站的罪状，是让中转站替你的提问背锅。
        """
        relay, mine = tr.ReputationTracker._classify(["length_anomaly"])
        assert relay is False, "长度突变被算成了中转站的责任"
        assert mine is True

    def test_structure_anomaly_is_not_relay_fault(self):
        """字符类分布随内容变，同上。"""
        relay, mine = tr.ReputationTracker._classify(["structure_anomaly"])
        assert relay is False
        assert mine is True

    def test_malicious_tool_call_is_relay_fault(self):
        """反向自证：这一条**必须**算中转站的，否则修复就过头了。

        如果连恶意 tool_call 都不扣分，
        那不是「归因正确」，是「谁都不扣」——
        变成了和事佬，同样是谎报。
        """
        relay, mine = tr.ReputationTracker._classify(["tool_call_dangerous"])
        assert relay is True, "恶意 tool_call 未归到中转站头上"
        assert mine is False

    def test_hidden_instruction_is_relay_fault(self):
        for cat in ("hidden_instruction", "unicode_steganography",
                    "system_prompt_inject", "sensitive_leak"):
            relay, _ = tr.ReputationTracker._classify([cat])
            assert relay is True, f"{cat} 应算中转站责任"

    def test_unknown_category_defaults_to_user_side(self):
        """★ 未知类别必须**不**算中转站责任。

        宁可漏扣（分数偏高）也不能错扣：
        错扣会让用户误以为中转站有问题而白白弃用它。
        这是在没有证据的情况下毁掉一个可能完全诚信的服务商。
        """
        relay, mine = tr.ReputationTracker._classify(["brand_new_detector"])
        assert relay is False, "未知类别被当成了中转站的罪证"
        assert mine is True

    def test_no_categories_defaults_to_user_side(self):
        relay, mine = tr.ReputationTracker._classify(None)
        assert relay is False
        assert mine is True

    def test_mixed_finding_takes_the_worst(self):
        """一次事件里既有中转站问题也有用户问题时，按中转站算。

        取最严重的那一方 —— 若判成「用户自己的」，
        就等于给中转站开了免罪通道。
        """
        relay, _ = tr.ReputationTracker._classify(
            ["length_anomaly", "tool_call_dangerous"])
        assert relay is True


class TestScoreReflectsRealHistory:
    """回放实测历史：385 次调用，78 次风险全是用户自身导致。"""

    def _replay(self):
        t = _fresh()
        _feed(t, Action.PASS.value, 307)
        _feed(t, Action.BLOCK.value, 19, categories=["length_anomaly"])
        _feed(t, Action.ALERT.value, 59, categories=["structure_anomaly"])
        return t.list_all()[0]

    def test_score_is_not_bottomed_out(self):
        """★ 核心回归：分数不该再恒为 0。

        ★ 判据踩过的坑：回放历史时中转站侧本来就是 0 次，
          所以基线已经是 100 分。
          那样「改回按绝对次数累减」也拿不到 0 分 ——
          变异改了等于没改，断言恒真。
          所以这里必须**先让中转站侧确实有风险**，
          再验证分数不会被扣到触底：
          只有「有风险」与「触底」这两件事同时成立，
          才能证明扣分与触底是两件独立的事。
        """
        t = _fresh()
        _feed(t, Action.PASS.value, 300)
        # 中转站侧真的有问题：恶意工具调用
        _feed(t, Action.BLOCK.value, 40, categories=["tool_call_dangerous"])
        r = t.list_all()[0]
        assert r.relay_danger_count == 40
        assert r.score > 0, (
            f"40 次恶意 tool_call 把分数扣到了 {r.score} —— "
            "又变回「累计即触底」，新增风险将永远看不出来"
        )

    def test_legacy_replay_scores_full_marks(self):
        """回放实测历史（78 次风险全属用户自身）必须是满分。"""
        r = self._replay()
        assert r.score == 100, (
            f"分数被用户自身的行为打成了 {r.score}"
        )

    def test_relay_side_is_zero(self):
        r = self._replay()
        assert r.relay_danger_count == 0
        assert r.relay_suspect_count == 0

    def test_user_side_records_the_history(self):
        """用户自身那部分必须**如实记账**，不能因为不扣分就丢掉。

        丢掉的话，界面会显示「从未检测到任何问题」，
        而实际上检测了 78 次 —— 那又是一个谎报。
        """
        r = self._replay()
        assert r.self_danger_count == 19
        assert r.self_suspect_count == 59

    def test_legacy_totals_are_preserved(self):
        """旧字段保留为两者之和，供「今日统计」等既有展示沿用。"""
        r = self._replay()
        assert r.danger_count == 19
        assert r.suspect_count == 59

    def test_level_is_safe(self):
        r = self._replay()
        assert r.level == "safe", (
            f"78 次用户自身操作把中转站判成了 {r.level}"
        )


class TestScoreStillPunishesRealMisconduct:
    """反向：真遇到中转站问题，分数必须下来。"""

    def test_single_malicious_tool_call_lowers_score(self):
        t = _fresh()
        _feed(t, Action.PASS.value, 99)
        _feed(t, Action.BLOCK.value, 1, categories=["tool_call_dangerous"])
        r = t.list_all()[0]
        assert r.score < 100, "一次明确的恶意 tool_call 竟然不扣分"

    def test_single_malicious_call_is_visible_but_not_catastrophic(self):
        """1/100 次恶意不该直接把分数打到 risky。

        但也不能几乎不掉 —— 那等于把明确的攻击当成噪声。
        这里守住「明显下降」这条线。
        """
        t = _fresh()
        _feed(t, Action.PASS.value, 99)
        _feed(t, Action.BLOCK.value, 1, categories=["tool_call_dangerous"])
        r = t.list_all()[0]
        assert r.score <= 95, f"扣分过轻：{r.score}"
        assert r.score >= 80, f"单次事件不该直接判死：{r.score}"

    def test_persistent_misconduct_keeps_penalising(self):
        """★ 锁住「比例制」最核心的性质：**单调性**。

        风险率越高，分数必须严格越低，且不能过早触底。

        ★ 为什么不直接断言「1% 隐藏指令必须判 risky」
          因为那个阈值是任意的。1% 的响应含隐藏指令，
          客观上就是 99% 干净的渠道，给它 95 分是**正确的**。
          真正要防的是两件事：
            ① 分数不随风险率下降（算法失效）；
            ② 高风险率也拿不到低分（算法被稀释掉了）。
          这两条才是「分数没意义」的实际表现。
        """
        scores = []
        for bad in (0, 10, 50, 100, 300, 500):
            t = _fresh()
            _feed(t, Action.PASS.value, 1000 - bad)
            _feed(t, Action.BLOCK.value, bad,
                  categories=["hidden_instruction"])
            scores.append(t.list_all()[0].score)

        # ① 风险率越高，分数越低
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1], (
                f"分数未随风险率下降：{scores}"
            )
        assert scores[0] == 100, f"零风险应为满分，实际 {scores[0]}"

        # ② 高风险率必须真的落到 risky / malicious 区间
        #    10% 响应被判定含隐藏指令，这已经不是「有点可疑」了。
        assert scores[-1] <= 50, (
            f"50% 命中率只得到 {scores[-1]} 分 —— 算法被过度稀释，"
            "严重风险看不出来"
        )

    def test_clean_relay_scores_full_marks(self):
        """反向自证：完全干净的渠道必须满分。

        若这条不成立，说明归因把**正常响应**也算成了风险 ——
        那就是从「冤枉中转站」变成了「冤枉所有渠道」。
        """
        t = _fresh()
        _feed(t, Action.PASS.value, 500)
        assert t.list_all()[0].score == 100

    def test_user_actions_alone_never_change_level(self):
        """★ 用户自己贴 500 次密钥，中转站也必须是 safe。

        这是本次修复最容易做反的地方：
        如果「用户侧事件」也进了扣分，
        500 次密钥粘贴会把中转站打成 risky ——
        而中转站连那些内容都没见过。
        """
        t = _fresh()
        _feed(t, Action.PASS.value, 100)
        _feed(t, Action.BLOCK.value, 500, categories=["length_anomaly"])
        _feed(t, Action.ALERT.value, 500, categories=["structure_anomaly"])
        r = t.list_all()[0]
        assert r.level == "safe", f"用户自身操作把中转站判成了 {r.level}"
        assert r.score == 100

    def test_score_never_reaches_zero_from_behaviour_alone(self):
        """★ 有意保留 45 分下限：「有风险」不等于「确认恶意」。

        分数归零会让「有点可疑」和「确认是恶意」
        在界面上变成同一句话，丢掉最关键的那个区分。
        真正确认恶意的证据走 known_malicious（直接 0 分）。
        """
        t = _fresh()
        _feed(t, Action.BLOCK.value, 5000, categories=["tool_call_dangerous"])
        r = t.list_all()[0]
        assert r.score >= 45, f"行为扣分把分数压到了 {r.score}，抹掉了区分度"
        assert r.score == 45

    def test_known_malicious_still_zeroes_it(self):
        """确认恶意仍然直接归零 —— 硬证据不参与比例。"""
        from daoti_xuandun_personal.types import RelayReputation
        t = _fresh()
        rep = RelayReputation(domain="api.evil.invalid", known_malicious=True)
        assert t._compute_score(rep) == 0

    def test_watermark_penalised_once_and_hard(self):
        """数据留存是定性证据：一次就扣，且不被样本量稀释。"""
        t = _fresh()
        _feed(t, Action.PASS.value, 999)
        t.record_call(URL, Action.PASS.value,
                      content="本站保留所有对话记录用于训练")
        r = t.list_all()[0]
        assert r.watermark_detected
        assert r.score == 70, f"水印扣分不对：{r.score}"

    def test_user_side_events_cannot_inflate_the_score(self):
        """★ 用户自身事件对中转站评分**必须完全无影响**。

        这不是「不许涨」，而是「一点不许变」。
        实测踩过：只断言「不涨」抓不住两类错法 ——
          ① 把 self 加进**分子** → 分数**跌**（60 → 45），
             断言照样通过，但「你贴密钥 → 中转站被扣分」依然成立；
          ② 把 self 加进**分母** → 分数**涨**，
             那正是「贴密钥就能洗白中转站」。
        正确做法是断言**逐字段相等**：分数与等级都必须一模一样。
        用户自己的操作与中转站的服务质量无关。

        ★ 这也是本轮修复最容易做反的地方：
          用户侧事件若进了扣分，
          500 次密钥粘贴会把中转站打成 risky ——
          而中转站连那些内容都没见过。
        """
        def build(with_self: bool):
            t = _fresh()
            _feed(t, Action.PASS.value, 100)
            _feed(t, Action.BLOCK.value, 10,
                  categories=["tool_call_dangerous"])
            if with_self:
                _feed(t, Action.BLOCK.value, 500,
                      categories=["length_anomaly"])
                _feed(t, Action.ALERT.value, 500,
                      categories=["structure_anomaly"])
            return t.list_all()[0]

        clean = build(False)
        noisy = build(True)

        assert clean.score < 100, "基线必须是扣过分的，否则测不出差异"
        assert noisy.score == clean.score, (
            f"用户自身事件改变了中转站评分：{clean.score} → {noisy.score}"
            f"（{noisy.total_calls} 次调用里含用户自己的操作）"
        )
        assert noisy.level == clean.level, (
            f"用户自身事件改变了中转站等级：{clean.level} → {noisy.level}"
        )


class TestScoreIsPersistedAndHonest:
    """归因必须真的落库，否则重启后又变回混在一起。"""

    def test_score_is_recomputed_on_load(self):
        """★★ 分数是**派生值**，导入时必须重算，不能信库里的副本。

        实测踩过：升级前老库存着旧算法的 score=0
        （危险 19×20 + 可疑 59×4 = −616 钳到 0）。
        新算法下那些事件全属用户自身，正确分数是 100，
        但直接读库会继续显示 0。

        而且它**不会自愈**：record_call 只在被调用时重算，
        长期不再调用的中转站会永远卡在旧分数上 ——
        用户看到的仍然是那个被误算出来的分数。
        """
        from daoti_xuandun_personal.types import RelayReputation

        stale = RelayReputation(
            domain="api.stale.invalid",
            score=0,                       # 旧算法留下的错值
            total_calls=385,
            danger_count=19, suspect_count=59,   # 混在一起的旧口径
            relay_danger_count=0, relay_suspect_count=0,
            self_danger_count=19, self_suspect_count=59,
        )
        t = _fresh()
        t.import_reputation(stale)

        got = t.get_reputation(URL.replace(
            "api.commandcode.ai", "api.stale.invalid"))
        assert got.score == 100, (
            f"导入时未重算分数，仍是旧算法的 {got.score} —— "
            "算法改了但历史分数不重算，用户看到的还是错值"
        )

    def test_import_keeps_hard_evidence_zero(self):
        """反向自证：确认恶意的仍必须是 0 分，不能被"重算"洗白。"""
        from daoti_xuandun_personal.types import RelayReputation

        bad = RelayReputation(
            domain="api.bad.invalid", score=100, known_malicious=True,
            total_calls=10,
        )
        t = _fresh()
        t.import_reputation(bad)
        assert t.get_reputation(
            URL.replace("api.commandcode.ai", "api.bad.invalid")
        ).score == 0, "重算把「命中恶意库」的 0 分洗成了高分"

    def test_recomputed_score_is_written_back_to_db(self):
        """★★ 重算结果必须**立刻写回库**，否则内存与库不一致。

        实测踩过：只在内存里重算，库里留着的仍是旧算法的 0 分。
        内存是对的、库是错的 —— 用户看到的 0 分正来源于此，
        而且它会在任何直接读库的地方重新冒出来
        （诊断报告、设置页、导出）。
        """
        import tempfile

        from daoti_xuandun_personal.storage.db import PersonalStorage
        from daoti_xuandun_personal.types import RelayReputation

        with tempfile.TemporaryDirectory() as td:
            st = PersonalStorage(Path(td) / "t.db")
            try:
                # 先落库一个「旧算法的错值」
                st.upsert_reputation(RelayReputation(
                    domain="api.stale.invalid", score=0, total_calls=385,
                    danger_count=19, suspect_count=59,
                    self_danger_count=19, self_suspect_count=59,
                ))
                assert st.load_reputations()[0].score == 0

                # 走一遍启动时的导入 + 回写
                t = _fresh()
                for rep in st.load_reputations():
                    t.import_reputation(rep)
                    st.upsert_reputation(rep)

                assert st.load_reputations()[0].score == 100, (
                    "重算后的分数没有写回数据库 —— "
                    "库里仍是旧算法的 0 分"
                )
            finally:
                st.close()

    def test_startup_recomputes_and_persists(self):
        """源码自证：启动流程必须既导入又回写。"""
        src = (ROOT / "src" / "daoti_xuandun_personal"
               / "proxy" / "app.py").read_text(encoding="utf-8")
        import re
        m = re.search(
            r"for rep in _storage\.load_reputations\(\):(.*?)\n\n",
            src, re.S)
        assert m, "未找到启动时的信誉导入循环"
        block = m.group(1)
        assert "import_reputation" in block
        assert "upsert_reputation" in block, (
            "启动时只导入不回写 —— 重算结果丢在内存里，库里仍是错值"
        )

    def test_new_columns_survive_round_trip(self):
        import tempfile

        from daoti_xuandun_personal.storage.db import PersonalStorage

        with tempfile.TemporaryDirectory() as td:
            st = PersonalStorage(Path(td) / "t.db")
            try:
                t = _fresh()
                _feed(t, Action.PASS.value, 10)
                _feed(t, Action.BLOCK.value, 3, categories=["length_anomaly"])
                _feed(t, Action.BLOCK.value, 1,
                      categories=["tool_call_dangerous"])
                rep = t.list_all()[0]
                st.upsert_reputation(rep)

                back = st.load_reputations()[0]
                assert back.relay_danger_count == 1, (
                    "中转站侧计数没能落库"
                )
                assert back.self_danger_count == 3, (
                    "用户侧计数没能落库"
                )
            finally:
                st.close()

    def test_old_db_without_new_columns_still_loads(self):
        """★ 老库缺列必须能读，否则升级即崩溃。

        用户升级到新版本时，relay_reputation 表里没有新列。
        直接下标取值会抛 IndexError，
        把一次「评分口径调整」变成「应用打不开」。
        """
        import sqlite3
        import tempfile

        from daoti_xuandun_personal.storage.db import PersonalStorage

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "old.db"
            # 造一个只有旧列的表
            conn = sqlite3.connect(str(p))
            conn.execute("DROP TABLE IF EXISTS relay_reputation")
            conn.execute("""CREATE TABLE relay_reputation (
                domain TEXT PRIMARY KEY, score INTEGER, first_seen REAL,
                last_seen REAL, total_calls INTEGER, danger_count INTEGER,
                suspect_count INTEGER, avg_latency_ms REAL,
                latency_samples INTEGER, known_malicious INTEGER,
                watermark_detected INTEGER, notes TEXT)""")
            conn.execute(
                "INSERT INTO relay_reputation VALUES"
                " ('d', 88, 1.0, 2.0, 10, 1, 2, 5.0, 10, 0, 0, '[]')")
            conn.commit()
            conn.close()

            st = PersonalStorage(p)
            try:
                reps = st.load_reputations()
                assert len(reps) == 1
                # 缺失列按 0 处理 —— 宁可少扣也不指控
                assert reps[0].relay_danger_count == 0
                assert reps[0].self_danger_count == 0
            finally:
                st.close()


class TestFrontendMatchesBackend:
    """界面解释的扣分必须与后端算出来的分一致。"""

    @staticmethod
    def _code_only(p: Path) -> str:
        import re
        s = p.read_text(encoding="utf-8")
        s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
        return re.sub(r"//[^\n]*", " ", s)

    def test_weights_match_backend_constants(self):
        """★ 前后端权重必须逐字一致。

        不一致的后果是界面给出的「为什么是这个分」
        与实际分数对不上 —— 那比不给解释更糟，
        因为用户会以为解释是准确的。
        """
        tsx = self._code_only(ROOT / "desktop" / "src" / "pages" / "Dashboard.tsx")
        assert f"watermark: {int(tr._WATERMARK_PENALTY)}" in tsx, (
            "前端水印扣分与后端不一致"
        )
        assert f"suspiciousPattern: {int(tr._PATTERN_PENALTY)}" in tsx, (
            "前端域名模式扣分与后端不一致"
        )
        assert f"behaviorMax: {int(tr._BEHAVIOR_MAX_PENALTY)}" in tsx, (
            "前端行为扣分上限与后端不一致"
        )

    def test_ratio_coefficient_matches_backend(self):
        """比例系数与分母口径必须与后端一致。"""
        tsx = self._code_only(ROOT / "desktop" / "src" / "pages" / "Dashboard.tsx")
        assert "rawRatio * SCORE_WEIGHTS.behaviorMax * 4" in tsx, (
            "前端比例系数与后端不一致"
        )
        # 分母排除用户自身事件 —— 漏了这条界面就会显示错的扣分
        assert "total_calls - relayRisk - selfRisk" in tsx, (
            "前端分母没有排除用户自身造成的调用"
        )
        src = (ROOT / "src" / "daoti_xuandun_personal"
               / "reputation" / "tracker.py").read_text(encoding="utf-8")
        assert "ratio * _BEHAVIOR_MAX_PENALTY * 4" in src
        assert "ratio = weighted / denominator" in src, (
            "后端分母口径变了（不再用 total_calls）"
        )

    def test_relay_attributable_set_matches_verifier_categories(self):
        """★ 归因清单必须覆盖验证器真实会产出的类别。

        清单漏了一个类别 → 那类风险永远不扣分，
        而界面会显示「无扣分项」——
        用户以为干净，其实有一类攻击没被算过。

        ★ 判据必须同时扫两种写法：
          `category="xxx"`      —— 直接构造
          `["xxx", "yyy"]`      —— 护栏层成批返回
        实测踩过：只扫前一种会漏掉 system_prompt_inject
        与 sensitive_leak（它们由企业版护栏成批产出），
        差点被误判成「清单里有过时条目」而误删。
        """
        import re
        v = (ROOT / "src" / "daoti_xuandun_personal"
             / "proxy" / "verifier.py").read_text(encoding="utf-8")
        produced = set(re.findall(r'category="([a-z_]+)"', v))
        # 护栏层会成批返回类别列表
        for group in re.findall(r'\[((?:"[a-z_]+"\s*,?\s*)+)\]', v):
            produced.update(re.findall(r'"([a-z_]+)"', group))

        # 清单里的每个类别，验证器都必须真能产出
        for cat in tr._RELAY_ATTRIBUTABLE:
            assert cat in produced, (
                f"归因清单里的 {cat} 验证器从不产出 —— 清单已过时"
            )
        # 明确不该算中转站责任的
        for cat in ("length_anomaly", "structure_anomaly"):
            assert cat not in tr._RELAY_ATTRIBUTABLE
            assert cat in produced, (
                f"{cat} 是验证器真实产出的类别，判据需覆盖"
            )

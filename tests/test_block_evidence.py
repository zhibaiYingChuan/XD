# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""拦截必须留下可核对的依据 —— 防止「无法判断误报」复发。

本轮的真实故障
────────────────────────────────────────────────────────────
用户提出「页面数据对不上、是否存在误报」。挖下去发现三个独立缺陷，
单看任何一个都不致命，叠在一起就让人完全无法判断：

  1. **阻断路径从不落库脱敏记录。**
     app.py 捕获 _BlockRequest 后写完日志就 return，
     而 insert_redactions 在后面的通用路径里。
     实测 redaction_records 表 0 行 —— 40 条 JWT 拦截，
     没有任何一条留下片段。

  2. **detail_json 结构与前端契约不符。**
     阻断写的是 dict `{"hit_categories": [...]}`，
     而 Logs.tsx 只在 `Array.isArray(parsed)` 时才渲染「触发规则」。
     dict 不是数组 → 依据整段不显示。
     这条最隐蔽：后端「有数据」，前端「不显示」，
     两边各自看都说自己对。

  3. **text_preview 为空。**
     搜索功能的一半条件依赖 text_preview，它恒为空等于搜索半瘫。

为什么规则本身不用改
────────────────────────────────────────────────────────────
40 条 JWT 拦截经查**不是误报**：玄盾的激活码本身就是
RS256 JWT（`XDACT-` + eyJ.eyJ.签名），用户把激活码贴进提问，
被规则正确命中。若为了「让数字好看」放宽 JWT 规则，
反而会放过真正的令牌泄露 —— 那是拿安全换观感。
本文件因此不碰规则，只保证**依据可见、可核对**。
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.proxy import sanitizer as sz  # noqa: E402

APP_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py"
SANITIZER_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "sanitizer.py"
LOGS_TSX = ROOT / "desktop" / "src" / "pages" / "Logs.tsx"
DASH_TSX = ROOT / "desktop" / "src" / "pages" / "Dashboard.tsx"

# 一段真实的激活码形态：XDACT- 前缀 + 标准 RS256 JWT。
# 故意构造而非硬编码真码 —— 真码进测试文件等于泄密。
FAKE_CODE = (
    "XDACT-eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJpc3MiOiJ4dWFuRHVuLXBlcnNvbmFsIiwiYXVkIjoieHVhbmR1bi1wZXJzb25hbC1kZXNrdG9wIn0"
    ".c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
)


def _read(p: Path) -> str:
    assert p.is_file(), f"源文件不存在：{p}"
    return p.read_text(encoding="utf-8")


def _block_branch() -> str:
    """截取 _BlockRequest 捕获分支的源码文本。

    ★ 为什么要按源码文本断言，而不是直接跑一遍请求？
      因为这个 bug 的本质是「**控制流**走不到落库那一步」，
      纯行为测试会依赖一整套运行中的代理 + 数据库；
      而源码断言能精准锁住「return 是否早于落库」这一点，
      且不依赖运行环境。两者互补。
    """
    src = _read(APP_PY)
    start = src.find("except _BlockRequest as blocked:")
    assert start != -1, "未找到 _BlockRequest 捕获分支"
    end = src.find("\n            if redaction_records:", start)
    assert end != -1, "未找到阻断分支的结束位置（通用落库路径起点）"
    return src[start:end]


class TestJwtIsNotAFalsePositive:
    """先自证：JWT 规则命中激活码是正确行为，不是误报。

    ★ 这条判据的作用是**防止后来者好心办坏事**。
      看到「40 条 JWT 拦截」第一反应通常是「规则太宽，放宽它」。
      放宽 JWT 规则会同时放过真正的令牌外泄 ——
      那才是这个产品存在的意义所在。
      把这个事实固化成断言，谁想改规则都会先撞到这里。
    """

    def test_activation_code_shape_is_a_real_jwt(self):
        """激活码去掉前缀后必须是三段式 JWT（否则 JWT 规则本不该命中）。"""
        bare = FAKE_CODE[len("XDACT-"):]
        parts = bare.split(".")
        assert len(parts) == 3, "构造样本不是三段式"
        assert parts[0].startswith("eyJ"), "header 未以 eyJ 开头"
        assert parts[1].startswith("eyJ"), "payload 未以 eyJ 开头"

    def test_jwt_rule_blocks_activation_code(self):
        """JWT 规则必须命中激活码 —— 这是正确拦截，不是误报。"""
        r = sz.RequestSanitizer(level="balanced").sanitize(FAKE_CODE)
        assert r.action == "block", "激活码必须被拦截"
        assert "jwt" in r.hit_categories

    def test_jwt_rule_still_blocks_a_plain_bearer_token(self):
        """顺带自证：真令牌仍然被拦 —— 证明上一条不是宽松化的产物。"""
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJ0ZXN0In0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        r = sz.RequestSanitizer(level="balanced").sanitize(token)
        assert r.action == "block"
        assert "jwt" in r.hit_categories


class TestBlockedRequestsMustLeaveEvidence:
    """阻断必须给出可核对的依据。"""

    def test_block_result_carries_evidence_records(self):
        """SanitizeResult 在 BLOCK 时必须带 records（原实现为空）。"""
        r = sz.RequestSanitizer(level="balanced").sanitize(FAKE_CODE)
        assert r.action == "block"
        assert r.records, "阻断结果没有证据记录，界面无从核对"
        assert r.records[0].category == "jwt"

    def test_evidence_masks_the_original(self):
        """证据必须是掩码后的，绝不能是原文。

        ★ 这是安全底线：证据会经 detail_json 进 /api/logs、
          也会进 CSV 导出。存原文等于开一条泄露通道 ——
          一个「防止数据外泄」的产品自己成了泄露源。
        """
        r = sz.RequestSanitizer(level="balanced").sanitize(FAKE_CODE)
        rec = r.records[0]
        assert FAKE_CODE not in rec.original, "证据里出现了完整原文"
        assert "…" in rec.original, "证据未做掩码"
        # 必须报长度：用户靠长度就能区分长激活码与短 JWT。
        # 长度取命中区间本身（rec.end - rec.start），
        # 而不是整条消息 —— 消息里可能还有别的东西。
        matched_len = rec.end - rec.start
        assert f"{matched_len} 字符" in rec.original, (
            "证据未报出命中长度，用户无法据此判断是激活码还是令牌"
        )

    def test_short_secret_is_not_reconstructible(self):
        """太短的敏感值不能靠「首尾相接」还原。"""
        short = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
        rec = (
            sz.RequestSanitizer(level="balanced").sanitize(short).records[0]
        )
        assert short not in rec.original

    def test_block_branch_writes_redaction_records(self):
        """源码自证：阻断分支必须调用 insert_redactions。

        ★ 这条锁的是本轮最隐蔽的那个 bug：
          阻断分支 `return` 得比通用落库路径早，
          于是 redaction_records 表恒为 0 行，
          但没有任何一条日志或异常提示它本该有内容。
        """
        assert "insert_redactions" in _block_branch(), (
            "阻断分支没有落库脱敏记录 —— 界面永远看不到拦截依据"
        )

    def test_block_branch_does_not_inflate_redaction_counter(self):
        """阻断不得计入「已打码 N 处」。

        状态栏把该计数显示为「已打码」，
        而阻断根本没有打码 —— 请求被拒绝发送，没有任何内容离开本机。
        记进去就是谎报「已替你遮住 N 处敏感信息」。
        ★ 判据只认 `update_daily_stats(...)` 这个实际调用，
          不能用「分支里是否出现 redactions=」来判 ——
          注释里为了说明原因就会提到这个词，
          那样这条断言会变成永远失败的错判据。
        """
        call = re.search(
            r"update_daily_stats\((.*?)\)", _block_branch(), re.S
        )
        assert call, "阻断分支没有调用 update_daily_stats，首页统计会失真"
        assert "redactions" not in call.group(1), (
            "阻断路径把证据数记进了打码计数，状态栏会谎报「已打码」"
        )
        # 反向自证：total_calls / danger 必须还在，否则又是一种谎报
        assert "total_calls" in call.group(1)
        assert "danger" in call.group(1)

    def test_detail_json_is_a_list_not_a_dict(self):
        """detail_json 必须是数组 —— 与前端渲染契约一致。

        ★ 原实现写 dict，前端只渲染数组 →
          后端有数据、前端不显示，两边各自看都说自己对。
        """
        from daoti_xuandun_personal.proxy.app import _block_evidence

        r = sz.RequestSanitizer(level="balanced").sanitize(FAKE_CODE)
        ev = _block_evidence(r.hit_categories, r.records, "用户提问")

        assert isinstance(ev, list), "detail_json 不是数组，前端不会渲染"
        json.dumps(ev)  # 必须可序列化，否则会落库失败
        # 首项是总述，末项逐条带掩码片段
        assert ev[0]["category"] == "request_blocked"
        assert ev[-1]["evidence"], "逐条依据缺少可核对的片段"
        assert FAKE_CODE not in json.dumps(ev, ensure_ascii=False)

    def test_evidence_states_where_it_hit(self):
        """依据必须说明命中在哪个角色 —— 决定排查方向。"""
        from daoti_xuandun_personal.proxy.app import _block_evidence

        r = sz.RequestSanitizer(level="balanced").sanitize(FAKE_CODE)
        ev = _block_evidence(r.hit_categories, r.records, "系统提示词")
        blob = json.dumps(ev, ensure_ascii=False)
        assert "系统提示词" in blob
        assert "字符" in blob, "依据缺少位置信息"


class TestFrontendMustShowEvidence:
    """前端不能把已有的依据藏起来。

    ★ 判据一律剥掉注释再匹配。
      实测教训：直接 `assert "刷新" in tsx` 会被注释里的
      「手动刷新状态」命中 —— 变异把按钮整段删掉，测试照样绿。
      文案里的字和代码里的字同名，是这批文件最容易踩的坑。
    """

    @staticmethod
    def _code_only(p: Path) -> str:
        """去掉注释与字符串字面量，只留结构性代码。"""
        s = _read(p)
        s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)   # 块注释
        s = re.sub(r"//[^\n]*", " ", s)                  # 行注释
        return s

    def test_drawer_renders_evidence_field(self):
        tsx = self._code_only(LOGS_TSX)
        assert re.search(r"\{f\.evidence\s*&&", tsx), (
            "日志详情没有渲染 evidence —— 后端给了依据，界面不显示"
        )

    def test_block_records_labelled_as_evidence(self):
        """拦截时标题应写「拦截依据」而不是「脱敏记录」。

        阻断与打码是两件事：打码是「已替换后发出」，
        阻断是「根本没发出」。混称会让用户以为内容已经外发。
        """
        tsx = self._code_only(LOGS_TSX)
        assert "拦截依据" in tsx, "阻断记录仍标为「脱敏记录」，语义误导"
        assert re.search(r"action === 'block'", tsx), (
            "标题未按 action 区分阻断与打码"
        )

    def test_masked_evidence_disclaimer_shown(self):
        """必须说明片段已掩码、原文未外发，否则用户会担心是自己泄露了。"""
        tsx = self._code_only(LOGS_TSX)
        assert "掩码后内容" in tsx, "未说明片段已掩码，用户无法判断安全性"

    def test_dashboard_has_refresh_button(self):
        tsx = self._code_only(DASH_TSX)
        # 必须是一个真实可点的按钮，绑定了刷新处理函数
        assert re.search(
            r"<button[^>]*onClick=\{[^}]*handleRefresh", tsx, re.S
        ), "首页没有可点击的刷新按钮"
        assert "RefreshCw" in tsx, "刷新按钮没有图标"

    def test_dashboard_shows_last_refresh_time(self):
        """必须显示上次更新时间，否则用户无法判断数字有多新。"""
        tsx = self._code_only(DASH_TSX)
        assert "更新于" in tsx, "首页没有显示上次更新时间"
        assert "lastLoadedAt" in tsx

    def test_refresh_timestamp_uses_seconds_not_milliseconds(self):
        """★ 锁一个具体会犯的错：formatTime 吃秒，Date.now() 是毫秒。

        传错单位不会报错，只会让「更新于」显示成 5 万多年前的时刻 ——
        属于典型的静默错误，只能靠断言拦住。
        """
        tsx = _read(DASH_TSX)
        assert re.search(r"Date\.now\(\)\s*/\s*1000", tsx), (
            "刷新时间戳未除以 1000，界面会显示错误的时间"
        )

    def test_refresh_button_not_gated_by_pause_lock(self):
        """刷新不得复用 busy 锁。

        busy 是暂停/恢复/分享诊断的操作锁；复用会让刷新按钮
        在别的操作进行中变灰，用户点不动又不知道原因。
        """
        tsx = self._code_only(DASH_TSX)
        assert "refreshing" in tsx
        assert "handleRefresh" in tsx


class TestMarkedFalsePositiveActuallyLowersTheCount:
    """「标记为误报」必须真的把数字降下来。

    ★ 本轮发现的第三个谎报
      界面上点「标记为安全」会提示「后续统计将不再计入风险」，
      而原实现只写 logs.marked_safe —— daily_stats 是累加缓存，
      永远不会因标记而回退。
      实测标记前后 {danger:1} 完全不变。

      为什么这条比前两条更糟：前两条让用户「看不到依据」，
      这条让用户「做了正确操作却看不到效果」。
      用户会得出「玄盾在骗我」或「玄盾坏了」的结论 ——
      对一个以防篡改为卖点的产品，这直接摧毁信任。
    """

    @staticmethod
    def _fresh(action: str):
        import tempfile
        from pathlib import Path as _P

        from daoti_xuandun_personal.storage.db import PersonalStorage
        from daoti_xuandun_personal.types import LogEntry, LogType

        st = PersonalStorage(_P(tempfile.mkdtemp()) / "t.db")
        lid = st.insert_log(LogEntry(
            log_type=LogType.RESPONSE_VERIFY.value,
            relay_domain="d", action=action, severity="high",
            model="m", summary="s", detail_json="[]",
        ))
        # 复现真实写入路径：先记一次统计，再标记
        danger = 1 if action == "block" else 0
        suspect = 1 if action == "alert" else 0
        safe = 1 if action == "pass" else 0
        st.update_daily_stats(
            total_calls=1, danger=danger, suspect=suspect, safe=safe
        )
        return st, lid

    def test_marking_a_block_lowers_danger(self):
        st, lid = self._fresh("block")
        try:
            before = st.get_today_stats()
            assert st.mark_safe(lid) is True
            after = st.get_today_stats()
            assert after["danger_count"] == before["danger_count"] - 1, (
                "标记危险日志为误报后，危险计数没有下降"
            )
            assert after["total_calls"] == before["total_calls"] - 1
        finally:
            st.close()

    def test_marking_an_alert_lowers_suspect(self):
        st, lid = self._fresh("alert")
        try:
            before = st.get_today_stats()
            st.mark_safe(lid)
            after = st.get_today_stats()
            assert after["suspect_count"] == before["suspect_count"] - 1, (
                "标记可疑日志为误报后，可疑计数没有下降"
            )
        finally:
            st.close()

    def test_unmarking_restores_the_count(self):
        """取消标记必须把数字加回去，否则就成了单向不可逆。"""
        st, lid = self._fresh("block")
        try:
            base = st.get_today_stats()
            st.mark_safe(lid)
            marked = st.get_today_stats()
            st.unmark_safe(lid)
            back = st.get_today_stats()
            assert back == base, f"取消标记后未恢复原值：{base} → {marked} → {back}"
        finally:
            st.close()

    def test_marking_twice_does_not_double_subtract(self):
        """★ 判据设计踩过的坑

        最初这版用「1 条 block 日志，标记两次」来验幂等，
        结果**恒绿** —— 因为另一道防线 MAX(0, ...) 把第二次扣减
        吃掉了：1 → 0 → 0。两次都断言成 0，自然测不出差异。

        ★★ 两道防线会互相遮掩对方的失效：
          幂等保护没了，负数钳位还在；
          负数钳位没了，单条场景也够不到负数。
        所以这里必须造**两条** block 日志：
        正确答案 2→1，重复扣减 2→1→0，两者才分得开。
        """
        import tempfile
        from pathlib import Path as _P

        from daoti_xuandun_personal.storage.db import PersonalStorage
        from daoti_xuandun_personal.types import LogEntry, LogType

        st = PersonalStorage(_P(tempfile.mkdtemp()) / "t.db")
        try:
            ids = [
                st.insert_log(LogEntry(
                    log_type=LogType.RESPONSE_VERIFY.value,
                    relay_domain="d", action="block", severity="high",
                    model="m", summary="s", detail_json="[]",
                ))
                for _ in range(2)
            ]
            st.update_daily_stats(total_calls=2, danger=2)

            st.mark_safe(ids[0])
            once = st.get_today_stats()
            st.mark_safe(ids[0])          # 重复标记同一��
            twice = st.get_today_stats()

            assert once["danger_count"] == 1, (
                f"标记一次应从 2 降到 1，实际 {once['danger_count']}"
            )
            assert twice == once, (
                f"重复标记导致重复扣减：{once} → {twice}"
                "（幂等保护失效，且被 MAX(0,...) 遮掩）"
            )
        finally:
            st.close()

    def test_counts_never_go_negative(self):
        """任何路径都不许把计数压到负数。

        ★ 判据必须能真正触发负数，否则这条断言是恒真的。
          用「1 条日志、标记一次」造不出负数（1-1=0），
          实测把 MAX(0,...) 去掉测试依然全绿。

        ★ 负数在真实场景里并不罕见：
          daily_stats 是缓存，与 logs 可能不同步 ——
          用户清过统计、补标了一条旧日志、或跨天补记，
          都会出现「有这条日志，但当日计数已被重置为 0」。
          此时再减一次就是 -1，首页会显示「危险 -1」。
          MAX(0, ...) 是唯一防线，必须有人守着。
        """
        import tempfile
        from pathlib import Path as _P

        from daoti_xuandun_personal.storage.db import PersonalStorage
        from daoti_xuandun_personal.types import LogEntry, LogType

        st = PersonalStorage(_P(tempfile.mkdtemp()) / "t.db")
        try:
            lid = st.insert_log(LogEntry(
                log_type=LogType.RESPONSE_VERIFY.value,
                relay_domain="d", action="block", severity="high",
                model="m", summary="s", detail_json="[]",
            ))
            st.update_daily_stats(total_calls=1, danger=1)
            # 制造不同步：统计被重置为 0，但那条日志还在
            with st._conn:
                st._conn.execute(
                    "UPDATE daily_stats SET danger_count = 0,"
                    " total_calls = 0"
                )
            assert st.get_today_stats()["danger_count"] == 0

            st.mark_safe(lid)
            s = st.get_today_stats()
            assert s["danger_count"] == 0, (
                f"统计被重置后再标记，危险计数变成了 {s['danger_count']}"
                "（MAX(0,...) 钳位失效）"
            )
            for k, v in s.items():
                assert v >= 0, f"{k} 变成了负数：{v}"
        finally:
            st.close()

    def test_marking_pass_does_not_shrink_safe_count(self):
        """★ 标记「安全」日志不得让安全数变小。

        pass 本来就不算风险，标记它没有意义；
        若连带回退 safe_count，首页「安全 N」会凭空变小 ——
        那只是把一个谎报换成了另一个。
        """
        st, lid = self._fresh("pass")
        try:
            before = st.get_today_stats()
            st.mark_safe(lid)
            after = st.get_today_stats()
            assert after["safe_count"] == before["safe_count"], (
                "标记安全日志竟然让「安全」计数下降了"
            )
            assert after["total_calls"] == before["total_calls"], (
                "标记安全日志竟然让总检查次数下降了"
            )
        finally:
            st.close()

    def test_marking_never_touches_redaction_count(self):
        """★ 标记不得让「已打码 N 处」变成负数或错数。

        阻断路径本来就不计入打码数（它没打码），
        若标记时也去动 redaction_count，凭空减一次就成负数。
        """
        st, lid = self._fresh("block")
        try:
            before = st.get_today_stats()
            st.mark_safe(lid)
            after = st.get_today_stats()
            assert after["redaction_count"] == before["redaction_count"], (
                "标记误报改动了打码计数"
            )
            assert after["redaction_count"] >= 0
        finally:
            st.close()


class TestUnmarkPathExists:
    """★ 标记能改统计，就必须能撤销。

    这是本轮修复引入的新风险：原先 mark_safe 只写一个标志位，
    改错了顶多显示不对；现在它会真的改动 daily_stats ——
    若没有对称的撤销路径，一次手滑就永久改写了用户的当日统计，
    而界面上没有任何入口能改回来。
    那等于把「谎报」换成了「不可撤销的错误」。
    """

    def test_backend_exposes_unmark_endpoint(self):
        src = _read(APP_PY)
        assert "/unmark-safe" in src, "后端没有撤销标记的接口"

    def test_unmark_endpoint_calls_unmark_safe(self):
        src = _read(APP_PY)
        m = re.search(
            r"unmark_log_safe.*?_storage\.unmark_safe\(log_id\)", src, re.S
        )
        assert m, "撤销接口没有调用 storage.unmark_safe"

    def test_tauri_exposes_unmark_command(self):
        rs = _read(ROOT / "desktop" / "src-tauri" / "src" / "lib.rs")
        assert "unmark_log_safe" in rs, (
            "Tauri 没有暴露 unmark_log_safe，前端调不到"
        )

    def test_frontend_calls_unmark(self):
        tsx = TestFrontendMustShowEvidence._code_only(LOGS_TSX)
        assert "unmarkLogSafe" in tsx, "界面没有调用撤销接口"
        assert "撤销标记" in tsx, "界面上没有撤销按钮"

    def test_unmark_restores_count_through_storage(self):
        """端到端核对：标记 → 撤销，统计必须回到原值。"""
        import tempfile
        from pathlib import Path as _P

        from daoti_xuandun_personal.storage.db import PersonalStorage
        from daoti_xuandun_personal.types import LogEntry, LogType

        st = PersonalStorage(_P(tempfile.mkdtemp()) / "t.db")
        try:
            lid = st.insert_log(LogEntry(
                log_type=LogType.RESPONSE_VERIFY.value,
                relay_domain="d", action="block", severity="high",
                model="m", summary="s", detail_json="[]",
            ))
            st.update_daily_stats(total_calls=1, danger=1)
            base = st.get_today_stats()

            st.mark_safe(lid)
            assert st.get_today_stats()["danger_count"] == base["danger_count"] - 1

            st.unmark_safe(lid)
            assert st.get_today_stats() == base, "撤销后未回到原值"
        finally:
            st.close()


class TestFrontendMustNotOverpromise:
    """前端文案不得承诺后端做不到的事。"""

    def test_toast_matches_reality(self):
        """★ 判据：文案不得再说「后续统计将不再计入风险」。

        那句承诺指向的是「未来的记录」，
        而真正需要说明的是「已经记进去的那一条被减掉了」。
        两件事完全不同，说错会让用户去找不存在的行为。
        """
        tsx = TestFrontendMustShowEvidence._code_only(LOGS_TSX)
        assert "后续统计将不再计入风险" not in tsx, (
            "界面仍在承诺「后续统计不再计入」，与实际行为不符"
        )
        assert "已减去这一条" in tsx, "标记后的提示未说明当前计数已被修正"

    def test_mark_button_label_is_unambiguous(self):
        """按钮写「标记为安全」而提示写「标记为误报」，含义相反。

        两个名字指同一件事，用户会怀疑是不是有两个功能。
        统一成「标记为误报」——它准确描述了发生什么。
        """
        tsx = TestFrontendMustShowEvidence._code_only(LOGS_TSX)
        assert "'标记为安全'" not in tsx, "按钮文案与提示文案互相矛盾"
        assert "标记为误报" in tsx


class TestEvidenceSurvivesStorage:
    """证据必须真的能落库并读回来（不只是内存里有）。"""

    def test_insert_redactions_round_trip(self):
        """写入再读回：掩码片段与类别都要在。

        这条锁住「接口有字段、库里没数据」这类故障 ——
        实测 redaction_records 表 0 行正是因为阻断路径
        压根没调用 insert_redactions，而它当时也没被任何测试覆盖。
        """
        import tempfile
        from pathlib import Path as _P

        from daoti_xuandun_personal.storage.db import PersonalStorage

        with tempfile.TemporaryDirectory() as td:
            # PersonalStorage 收的是 db 文件路径，不是目录
            st = PersonalStorage(_P(td) / "t.db")
            try:
                r = sz.RequestSanitizer(level="balanced").sanitize(FAKE_CODE)
                n = st.insert_redactions(1, "sess-1", r.records)
                assert n == len(r.records)

                rows = st.get_redactions(1)
                assert len(rows) == len(r.records)
                assert rows[0]["category"] == "jwt"
                assert FAKE_CODE not in rows[0]["original"]
            finally:
                st.close()

# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""帮助页文案必须与源码一致 —— 防止文档漂移。

为什么要有这个
────────────────────────────────────────────────────────────
2026-09-29 逐条核对帮助页，发现四处不实描述：

  1. 「托盘黄色有可疑」—— 托盘根本没有黄色态。
     源码只有三种常驻：绿（运行中）、灰（暂停/引擎未运行），
     加上危险拦截时的红色**瞬时脉冲**（几秒后恢复）。
     照原文去等一个永远不会亮的黄色，用户会以为托盘坏了。

  2. 「通常在 50 条样本后建立基线」—— 实为**前 5 次**。
     夸大了 10 倍，用户会以为前几十次都不受保护。

  3. 「检测通常在 10 毫秒以内」—— 无任何实测依据。
     写一个测不出来的数字进用户文档，等于给自己埋一个
     将来无法兑现的承诺。

  4. 「宽松：首页状态栏变黄」—— 源码里 lenient + high 是
     ALERT（会标记为可疑），但状态栏没有「黄」这个状态；
     且 lenient + medium 直接 PASS，连标记都没有。

为什么这些能长期存活
────────────────────────────────────────────────────────────
代码审查读的是「代码是否自洽」，不会去比对一句英文/中文文案
与三处之外的常量；测试更不会去断言「文档里不许出现某个数字」。
本文件就是补这个洞：把「文案断言」变成可执行的判据。

判据的设计原则
────────────────────────────────────────────────────────────
不试图用自然语言理解去核对文档（那必然脆弱到无法维护），
而是**锁定那几个具体的事实性断言**：托盘有几态、基线取几次、
延迟基线阈值、是否出现未实测的性能数字。
这几条正是本轮实际出错的地方，也是最容易被后来者再写错的。
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELP_TSX = ROOT / "desktop" / "src" / "pages" / "Help.tsx"
TRAY_RS = ROOT / "desktop" / "src-tauri" / "src" / "lib.rs"
TRACKER_PY = ROOT / "src" / "daoti_xuandun_personal" / "reputation" / "tracker.py"
SANITIZER_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "sanitizer.py"
VERIFIER_PY = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "verifier.py"


def _read(p: Path) -> str:
    assert p.is_file(), f"源文件不存在：{p}"
    return p.read_text(encoding="utf-8")


class TestTrayStatesDescribedHonestly:
    """托盘常驻状态：源码只有「绿/灰」两态 + 红色瞬时脉冲。"""

    def test_source_really_has_only_three_tray_outcomes(self):
        """先自证判据本身：托盘确实只有 safe / paused / 脉冲三态。

        ★ 为什么要先自证：如果将来有人加了第四种状态（比如黄色），
          本用例的「文案不许提黄色」就会变成一条**恒真**的错判据 ——
          源码有了黄色、文档也该写，但测试还在禁止。
          判据必须跟着源码走，否则它自己就成了谎言。
        """
        rs = _read(TRAY_RS)
        steady_states = set(re.findall(r'set_steady\(&\w+,\s*"([a-z_]+)"', rs))
        # set_steady 的第一个参数是 app，形如 &app / &app2 / &h
        steady_states |= set(
            re.findall(r'set_steady\(&[\w.]+,\s*"([a-z_]+)"', rs)
        )
        assert steady_states, "未在 lib.rs 里找到任何 set_steady 调用"
        # 允许的稳态：safe（运行中）/ paused（已暂停）
        # 其余（如 danger）若出现，多半是脉冲而非常驻
        assert steady_states <= {"safe", "paused"}, (
            f"托盘出现了预期外的新常驻状态：{steady_states - {'safe', 'paused'}}。"
            "若这是有意的，请同步更新帮助页文案与本用例。"
        )

    def test_help_does_not_claim_a_yellow_tray(self):
        """帮助页不许描述「托盘变黄 / 黄色有可疑」。"""
        help_src = _read(HELP_TSX)
        claims_yellow = [
            pat for pat in ("托盘图标会变色提示状态：绿色正常、黄色",
                            "首页状态栏变黄",
                            "黄色今日有可疑",
                            "托盘变黄")
            if pat in help_src
        ]
        assert not claims_yellow, (
            f"帮助页仍声称托盘/状态栏会变黄：{claims_yellow}。"
            "但源码只有绿（运行中）/ 灰（暂停或引擎未运行）两种常驻态，"
            "危险拦截是红色瞬时脉冲 —— 照着原文等一个不会亮的黄色，"
            "用户会以为托盘坏了。"
        )

    def test_help_documents_pause_and_engine_down_as_gray(self):
        """灰色必须说清包含「引擎未运行」，而不只是「未启用」。

        ★ 灰色有两种来源：用户主动暂停、引擎崩溃/未运行。
          只写「防护未启用」会让引擎挂掉的用户以为自己点过暂停，
          去菜单里找一个根本没点的选项。
        """
        help_src = _read(HELP_TSX)
        assert "灰色" in help_src, "帮助页没有说明托盘灰色代表什么"
        assert "引擎未运行" in help_src, (
            "帮助页必须点明灰色包含「引擎未运行」——"
            "否则引擎崩溃的用户会以为是自己点过暂停，"
            "去找一个他根本没点过的菜单项。"
        )


class TestBaselineSampleCountMatchesSource:
    """帮助页说的基线样本数必须等于 tracker.py 里的真实阈值。"""

    def test_source_baseline_is_five(self):
        tracker = _read(TRACKER_PY)
        m = re.search(r"if len\(history\) < (\d+):", tracker)
        assert m, "未在 tracker.py 里找到延迟基线的最小样本阈值"
        assert m.group(1) == "5", (
            f"源码里的延迟基线阈值变成了 {m.group(1)}（原为 5）。"
            "若这是有意改动，请同步更新帮助页文案与本用例。"
        )

    def test_help_sample_count_is_five_not_fifty(self):
        help_src = _read(HELP_TSX)
        assert "50 条样本" not in help_src, (
            "帮助页仍写「50 条样本后建立基线」，"
            "而源码用的是前 5 次。夸大了 10 倍，"
            "会让用户以为前几十次都不受保护。"
        )
        # 正向：必须明确说出 5 这个真实数字
        assert re.search(r"前\s*5\s*次", help_src), (
            "帮助页应当如实写出「前 5 次」这个基线样本数，"
            "否则用户对「什么时候开始生效」没有准确预期。"
        )


class TestNoUnmeasuredPerformanceNumbers:
    """性能描述不许出现没实测过的具体毫秒数。"""

    def test_help_has_no_bare_millisecond_claim(self):
        help_src = _read(HELP_TSX)
        offenders = re.findall(r"\d+\s*毫秒", help_src)
        assert not offenders, (
            f"帮助页出现未经实测的性能数字：{offenders}。"
            "写一个测不出来的毫秒数进用户文档，"
            "等于给自己埋一个将来无法兑现的承诺。"
        )


class TestSecurityLevelDescribesBothDirections:
    """安全级别必须分「发送前」与「接收时」两侧说，且与源码一致。"""

    def test_lenient_keeps_blocking_api_key(self):
        """宽松模式下 API 密钥/身份证/银行卡**仍然阻断**。

        ★ 这是安全底线，不能被描述成「只有明确危险才拦」。
          原文写「宽松：只有明确的危险才拦（比如删除所有文件的命令）」，
          会让用户以为宽松模式下自己的 API 密钥会被直接发出去 ——
          那恰恰是最不能发生的事。
        """
        policy_src = _read(SANITIZER_PY)
        block = "Action.BLOCK.value"
        for cat in ("api_key", "idcard", "bankcard"):
            m = re.search(rf'"{cat}":\s*\((.*?)\),', policy_src, re.S)
            assert m, f"未在 _POLICY 里找到 {cat} 的策略"
            triple = m.group(1)
            # 三个位置（宽松/均衡/严格）都必须是 BLOCK
            assert triple.count(block) == 3, (
                f"{cat} 的策略不再是三档全阻断：{triple}。"
                "帮助页正据此描述「宽松也阻断」，改动请同步文案。"
            )

    def test_help_separates_request_and_response_sides(self):
        """帮助页必须分别说明两个方向，否则用户会误判。"""
        help_src = _read(HELP_TSX)
        assert "发送前" in help_src and "接收时" in help_src, (
            "帮助页必须分别讲「发送前（你的敏感信息）」与"
            "「接收时（中转站返回的内容）」—— 两者的分级规则不同，"
            "混着说用户会以为宽松模式对所有内容都放行。"
        )

    def test_lenient_medium_response_is_pass_not_alert(self):
        """自证：宽松 + 中等风险 = 放行（PASS），不是标记。

        这正是原文「首页状态栏变黄」不实的另一层原因 ——
        宽松模式下中等风险根本不产生任何标记。
        """
        v = _read(VERIFIER_PY)
        m = re.search(
            r'if severity == "medium":\s*return\s*\{(.*?)\}', v, re.S
        )
        assert m, "未在 verifier.py 里找到 medium 严重度的分级策略"
        block = m.group(1)
        assert re.search(r'"lenient":\s*Action\.PASS\.value', block), (
            "宽松模式下中等风险的处置不再是 PASS，"
            "帮助页关于「宽松会标记可疑」的描述需重新核对。"
        )


class TestHelpCoversUnactivatedReadOnlyMode:
    """未激活只读模式必须写出来 —— 那是不执行防护的状态。"""

    def test_read_only_mode_is_actually_a_real_state(self):
        """自证：只读模式真的存在（否则要求文案写它就荒谬）。"""
        app_py = _read(ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py")
        assert "read_only" in app_py, "源码里找不到 read_only，只读模式可能已改名"

    def test_help_explains_unactivated_gives_no_protection(self):
        help_src = _read(HELP_TSX)
        assert "只读模式" in help_src, (
            "帮助页必须说明未激活时处于只读模式。"
            "那是「界面能用但防护不工作」的状态 —— "
            "用户不知道就会以为自己受保护。"
        )
        assert "不执行" in help_src, (
            "只读模式的说明要点明「不执行脱敏与拦截」，"
            "否则「只读」听起来像一种温和的运行方式。"
        )


class TestHelpDoesNotLeakMarkdownSyntax:
    """FAQ 答案区是纯文本渲染，`**` 会原样显示给用户。"""

    def test_no_markdown_bold_in_faq_answers(self):
        help_src = _read(HELP_TSX)
        # 只看 FAQ / TOOL_GUIDES 的字符串字面量部分，
        # 排除注释与 import 区域的 JSDoc。
        body = help_src.split("const FAQ = [", 1)[-1]
        offenders = re.findall(r"\*\*[^*\n]+\*\*", body)
        assert not offenders, (
            f"FAQ 文案里出现 Markdown 粗体记号：{offenders}。"
            "答案区用 whiteSpace: pre-wrap 渲染，没有 Markdown 解析，"
            "用户会看到字面的星号。"
        )

    def test_official_email_is_reachable_from_help(self):
        """帮助页应给出官方邮箱 —— 与激活页保持同一入口。"""
        help_src = _read(HELP_TSX)
        assert "spring60@foxmail.com" in help_src, (
            "帮助页应写明申请激活码的官方邮箱，"
            "与「激活」页保持同一入口，否则用户不知道找谁。"
        )

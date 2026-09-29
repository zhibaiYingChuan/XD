# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""中转站地址规范化的回归测试。

为什么必须测这里
────────────────────────────────────────────────────────────────
``normalized_base`` 的产物会直接拼成 ``{base}/chat/completions``。
算错不会有任何报错，只会得到一个 404 —— 而用户看到的现象是
「中转站不可用」，于是去查中转站、查 Key、查网络，
唯独不会想到是地址被拼坏了。这条静默失效必须在测试里钉住。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from daoti_xuandun_personal.config import (  # noqa: E402
    RelayConfig,
    is_masked_key,
)

ROOT = Path(__file__).resolve().parent.parent


def _base(url: str) -> str:
    return RelayConfig(base_url=url).normalized_base


class TestRelayBaseNormalization:
    def test_bare_domain_gets_v1(self) -> None:
        assert _base("https://api.example.com") == "https://api.example.com/v1"

    def test_trailing_slash_is_removed(self) -> None:
        assert _base("https://api.example.com/") == "https://api.example.com/v1"

    def test_existing_v1_is_kept(self) -> None:
        assert _base("https://api.example.com/v1") == "https://api.example.com/v1"
        assert _base("https://api.example.com/v1/") == "https://api.example.com/v1"

    def test_version_like_segment_is_not_duplicated(self) -> None:
        """``/v1beta``、``/api/v4`` 本身已是版本段，不得再补一层。

        ★ 旧判据是 ``endswith("/v1")``，会把它们拼成 /v1beta/v1。
        """
        assert _base("https://api.example.com/v1beta") == "https://api.example.com/v1beta"
        assert _base("https://api.example.com/api/v4") == "https://api.example.com/api/v4"

    def test_full_endpoint_is_stripped(self) -> None:
        """连完整端点一起粘进来时必须剥掉，而不是再拼一层。

        ★ 中转站后台一般同时展示「接入地址」与「完整端点」，
          用户按配置 API 的直觉复制的就是后者 —— 这不是填错，
          是产品必须接住的输入。
        """
        assert _base("https://api.example.com/v1/chat/completions") == (
            "https://api.example.com/v1"
        )
        assert _base("https://api.example.com/v1/chat/completions/") == (
            "https://api.example.com/v1"
        )

    def test_real_world_provider_path_is_preserved(self) -> None:
        """实测案例：中转站的接入地址本身带额外路径段。

        ★ 2026-09-29 本机配置填的就是这一条。旧逻辑把它拼成
          ``.../chat/completions/v1/chat/completions``，实测 404
          「is not a registered route」，而用户只会以为中转站挂了。
        """
        assert _base(
            "https://api.commandcode.ai/provider/v1/chat/completions"
        ) == "https://api.commandcode.ai/provider/v1"

    def test_query_string_and_fragment_are_dropped(self) -> None:
        """从文档复制常带查询串/锚点，留着会污染请求路径。"""
        assert _base("https://api.example.com/v1/chat/completions?x=1&y=2") == (
            "https://api.example.com/v1"
        )
        assert _base("https://api.example.com/v1#frag") == "https://api.example.com/v1"

    def test_anthropic_style_tail_is_stripped(self) -> None:
        """Anthropic 形态的端点也要能收下。"""
        assert _base("https://api.example.com/v1/messages") == "https://api.example.com/v1"

    def test_surrounding_whitespace_is_ignored(self) -> None:
        """粘贴常带首尾空格 —— 带进 URL 会让请求直接失败。"""
        assert _base("  https://api.example.com/v1  ") == "https://api.example.com/v1"

    def test_scheme_is_preserved(self) -> None:
        """协议头不得被改写 —— 把 https 降级成 http 会让 Key 明文传输。"""
        assert _base("https://api.example.com").startswith("https://")


class TestMaskedKeyIsNotAKey:
    """掩码值绝不能被当成真实 API Key 落盘。

    ★ 防的是**静默**失效：服务端读取配置时返回的是掩码
      （``mask_key()`` 的产物），前端若原样回传，掩码就被写成真实 Key。
      之后所有请求 401，而配置页上一切正常 ——
      用户只会以为中转站封了他的账号。
    """

    def test_real_keys_are_accepted(self) -> None:
        for good in (
            "user_54j4xYi6onFDvzwVKaT6UuPFFEJTro1ZSBjHqLhQpGN8ed7F",
            "sk-proj-abc123",
            "key-with-dashes",
            "no0O1lI-like-chars",
        ):
            assert not is_masked_key(good), f"真实 Key 被误判为掩码：{good!r}"

    def test_mask_key_output_is_rejected(self) -> None:
        """判据要用 mask_key() 的**实际产物**，不能手写一个期望值。

        ★ 手写的 ``xxxx****yyyy`` 会与实现一起漂移：
          实现改了掩码格式，测试仍然通过，而线上已经在写坏 Key。
        """
        for raw in (
            "user_54j4xYi6onFDvzwVKaT6UuPFFEJTro1ZSBjHqLhQpGN8ed7F",
            "sk-proj-abcdefghijklmnop",
        ):
            masked = RelayConfig(base_url="", api_key=raw).mask_key()
            assert masked != raw, "mask_key() 没有做任何脱敏，测试前提不成立"
            assert is_masked_key(masked), f"mask_key() 的产物未被识别为掩码：{masked!r}"

    def test_short_key_mask_is_rejected(self) -> None:
        """短 Key 的掩码形态是纯星号，同样不得被写回。"""
        assert is_masked_key("***")
        assert is_masked_key(RelayConfig(base_url="", api_key="sk-1").mask_key())

    def test_empty_means_unchanged_and_must_pass(self) -> None:
        """空串不是掩码 —— 它的语义是「保持原 Key 不变」，必须放行。

        ★ 若把空串也判为掩码，用户就再也改不了地址以外的任何配置。
        """
        assert not is_masked_key("")
        assert not is_masked_key(None)

    def test_update_config_rejects_masked_key_loudly(self) -> None:
        """掩码回传必须**报错**，不能只记日志就跳过。

        ★ 静默跳过的后果：用户收到「中转站配置已保存并立即生效」，
          而真实 Key 根本没换 —— 下一次请求 401，
          且用户无从把这次 401 与这次保存联系起来。
          守卫本身绝不能制造它要消灭的那种失效。

        ★ 判据直接读源码：断言「raise HTTPException」真的在守卫分支里，
          而不是「logger.warning 之后 continue」。
        """
        app_py = (ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py").read_text(
            encoding="utf-8"
        )
        body = app_py.split("async def update_config", 1)[1]
        body = body.split('if "guard" in payload', 1)[0]
        guard = body.split("is_masked_key(v)", 1)[1]
        # 守卫分支必须在 raise 之前不再有 continue —— continue 会让
        # 掩码被静默吞掉，用户却拿到成功提示。
        head = guard.split("setattr", 1)[0]
        assert "raise HTTPException" in head, (
            "掩码 Key 的守卫分支没有抛错 —— 它会静默跳过，"
            "用户收到「已保存」但 Key 未生效，之后所有请求 401 且无从追查"
        )
        assert "continue" not in head, (
            "掩码 Key 的守卫分支里仍有 continue —— 那等于静默吞掉，"
            "正是本守卫要消灭的失效模式"
        )

    def test_stale_test_result_is_discarded(self) -> None:
        """测试进行中改地址/Key/保存，在飞的结论必须被作废。

        ★ 探针最长 45s。若没有序号守卫：
          测试 a.com（30s）→ 用户改成 b.com → 面板清空 →
          20s 后旧请求返回 → 面板显示「a.com 连接正常」。
          用户据此认为 b.com 可用，而 b.com 从未被探测过。
        """
        tsx = (ROOT / "desktop" / "src" / "pages" / "Settings.tsx").read_text(
            encoding="utf-8"
        )
        assert "testSeqRef" in tsx, (
            "设置页没有测试请求序号 —— 旧结论会覆盖用户改后的新输入"
        )
        # 序号必须在**写入结论前**比对，否则守卫形同虚设
        assert "seq !== testSeqRef.current" in tsx, (
            "异步返回没有比对序号 —— 在飞请求的结论仍会渲染出来"
        )
        # 点击测试时递增序号（用的是前置 ++ 形式）
        fn = tsx.split("const handleTestRelay", 1)[1].split("const handleCopyUrl", 1)[0]
        assert "++testSeqRef.current" in fn, "点击测试时没有递增序号"
        for path in ("base_url: e.target.value", "setKeyDraft(e.target.value)"):
            idx = tsx.find(path)
            assert idx != -1, f"未找到输入处理：{path}"
            window = tsx[idx : idx + 400]
            assert "testSeqRef.current += 1" in window, (
                f"改 {path.split(':')[0]} 时没有作废在飞的测试 —— "
                "旧结论会在新输入上重新出现"
            )


class TestRelayTestContract:
    """引擎探针会给出的每种结论，前端联合类型里都必须有。

    ★ 这是本仓库反复踩的一类坑：引擎新增一种结论（如 ``address``），
      前端的联合类型没跟上。TS 不会报错（只是字符串比较），
      运行时会落进 else 分支，用户拿到的是**错误**的提示 ——
      而「测试连接」的全部价值就在于给出准确的结论。
    """

    def test_engine_kinds_match_frontend_union(self) -> None:
        app_py = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "app.py"
        body = app_py.read_text(encoding="utf-8").split("async def test_relay", 1)[1]
        body = body.split('@app.get("/api/config")', 1)[0]
        emitted = set(re.findall(r'_result\(\s*(?:True|False),\s*"([a-z]+)"', body))
        assert emitted, "没能从 test_relay 里解析出任何 kind —— 契约测试本身已失效"

        api_ts = ROOT / "desktop" / "src" / "services" / "api.ts"
        block = api_ts.read_text(encoding="utf-8").split("export interface RelayTestResult", 1)[1]
        block = block.split("}", 1)[0]
        declared = set(re.findall(r"'([a-z]+)'", block.split("kind:", 1)[1].split(";", 1)[0]))
        assert declared, "没能从 RelayTestResult 里解析出 kind 联合类型"

        assert not (emitted - declared), (
            f"引擎会返回这些 kind，但前端 RelayTestResult 里没有："
            f"{sorted(emitted - declared)} —— 用户会拿到错误的提示文案"
        )
        assert not (declared - emitted), (
            f"前端声明了这些 kind，但引擎永远不会返回：{sorted(declared - emitted)}"
        )


class TestFrontendNeverEchoesMaskedKey:
    """设置页不得把服务端返回的掩码回传给后端。

    ★ 旧实现在这里出过问题：``config.relay.api_key`` 装的是掩码，
      用户点一次「保存中转站配置」就会把 ``xxxx****yyyy`` 写进
      config.json —— 真实 Key 被替换，之后所有请求 401，
      而页面上看不出任何异常。
    """

    def test_settings_does_not_submit_the_whole_relay_object(self) -> None:
        tsx = (ROOT / "desktop" / "src" / "pages" / "Settings.tsx").read_text(encoding="utf-8")
        assert "relay: config.relay" not in tsx, (
            "设置页直接提交了整个 relay 对象 —— 其中的 api_key 是掩码，"
            "提交它等于用掩码覆盖真实 Key"
        )
        assert "api_key: config.relay.api_key" not in tsx, (
            "设置页把掩码当成 api_key 提交了"
        )
        assert "keyDraft" in tsx, (
            "设置页必须用独立的草稿状态承载用户输入，而不是把掩码放进可提交状态"
        )
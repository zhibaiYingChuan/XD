# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""占位符双向通道的契约测试（2026-10-27）。

这一组锁的是「脱敏之后还能不能干活」：

  1. 同一个值，在同一会话内**编号稳定** —— 跨轮次、跨消息都是同一个号。
     按位置编号时，模型复述上一轮的 ⟦XD_3⟧ 会被本轮 3 号（另一个值）顶掉，
     还原出来的是**另一个秘密**，静默写错。
  2. 不同会话的编号空间互相独立 —— 两个 AI 工具同时开，不能串号。
  3. 非流式响应的还原结果必须**无条件写回**，且要覆盖 tool_calls.arguments。
     旧实现把写回放在 `if restore_anomalies:` 里，正常还原被直接丢弃；
     而 `_set_content` 只认 message.content，纯工具调用响应完全无效。
  4. 请求历史里的工具调用参数必须脱敏 —— 否则「AI 把密钥写进工具参数」
     这段历史每轮都会原样发给中转站。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from daoti_xuandun_personal.proxy import app as app_mod  # noqa: E402
from daoti_xuandun_personal.proxy.restorer import ContentRestorer  # noqa: E402
from daoti_xuandun_personal.proxy.sanitizer import RequestSanitizer  # noqa: E402
from daoti_xuandun_personal.proxy.vault import PlaceholderVault  # noqa: E402

EMAIL = "alice@example.com"
EMAIL2 = "bob@example.com"
PHONE = "13800138000"


# ══════════════════════════════════════════════════════════════
# 保险箱
# ══════════════════════════════════════════════════════════════


class TestPlaceholderVault:
    def test_same_value_gets_same_id(self):
        v = PlaceholderVault()
        sid = v.begin_session("s1")
        a = v.intern(sid, EMAIL, "email")
        b = v.intern(sid, EMAIL, "email")
        assert a == b, "同一个值两次登记拿到了不同编号 —— 模型无法复用引用"

    def test_different_values_get_different_ids(self):
        v = PlaceholderVault()
        sid = v.begin_session("s1")
        assert v.intern(sid, EMAIL, "email") != v.intern(sid, EMAIL2, "email")

    def test_ids_are_never_reused(self):
        v = PlaceholderVault()
        sid = v.begin_session("s1")
        first = v.intern(sid, EMAIL, "email")
        assert v.resolve(sid, first) == EMAIL
        # 绑定一个已占用但值不同的编号必须被拒绝
        assert v.bind(sid, first, EMAIL2, "email") is False
        assert v.resolve(sid, first) == EMAIL, "编号被错值覆盖了 —— 会静默还原成错误秘密"

    def test_sessions_are_isolated(self):
        v = PlaceholderVault()
        sid1 = v.begin_session("s1")
        sid2 = v.begin_session("s2")
        idx = v.intern(sid1, EMAIL, "email")
        assert v.resolve(sid2, idx) is None, "占位符跨会话串号了"

    def test_unknown_id_resolves_to_none(self):
        v = PlaceholderVault()
        sid = v.begin_session("s1")
        assert v.resolve(sid, 999999) is None

    def test_stats_contain_no_plaintext(self):
        v = PlaceholderVault()
        sid = v.begin_session("s1")
        v.intern(sid, EMAIL, "email")
        dump = json.dumps(v.stats(), ensure_ascii=False)
        assert EMAIL not in dump


# ══════════════════════════════════════════════════════════════
# 脱敏侧：编号稳定
# ══════════════════════════════════════════════════════════════


class TestSanitizerStableIds:
    def test_duplicate_value_uses_one_id(self):
        r = ContentRestorer()
        sid = r.begin_session("s1")
        sz = RequestSanitizer(level="balanced")
        res = sz.sanitize(f"{EMAIL} 和 {EMAIL}", vault=r.vault, session_id=sid)
        assert res.records, "邮箱没有被脱敏"
        assert len({rec.index for rec in res.records}) == 1, (
            "同一个邮箱出现了两个编号 —— 模型会把它们当成两个不同的东西"
        )
        assert res.sanitized_text.count(f"⟦XD_{res.records[0].index}⟧") == 2

    def test_id_survives_across_requests(self):
        r = ContentRestorer()
        sid = r.begin_session("s1")
        sz = RequestSanitizer(level="balanced")
        first = sz.sanitize(EMAIL, vault=r.vault, session_id=sid)
        second = sz.sanitize(f"再确认一次：{EMAIL2} / {EMAIL}", vault=r.vault, session_id=sid)
        idx_email = first.records[0].index
        assert f"⟦XD_{idx_email}⟧" in second.sanitized_text, (
            "同一个邮箱在下一轮换了编号 —— 模型复述旧编号会被顶替成别的值"
        )


# ══════════════════════════════════════════════════════════════
# 还原侧：跨轮次存活 + 全结构写回
# ══════════════════════════════════════════════════════════════


class TestRestorer:
    def test_mapping_survives_next_turn(self):
        r = ContentRestorer()
        sid = r.begin_session("s1")
        idx = r.vault.intern(sid, EMAIL, "email")
        r.clear_after_response(sid)     # 现在是 no-op，仅为兼容旧调用点
        out, anomalies = r.restore(sid, f"你的邮箱是 ⟦XD_{idx}⟧")
        assert EMAIL in out
        assert not anomalies

    def test_forged_placeholder_is_not_restored(self):
        """本会话从未脱敏时：换不出任何值，只记录，不指控「伪造」。"""
        r = ContentRestorer()
        sid = r.begin_session("s1")
        out, anomalies = r.restore(sid, "⟦XD_42⟧")
        assert out == "⟦XD_42⟧", "未知编号被还原了 —— 中转站可以借此探测真实值"
        assert anomalies and anomalies[0].severity == "low", (
            "本会话没有可置换的原始值，按 high 阻断会把「讨论占位符格式」判成攻击"
        )

    def test_forged_id_in_redacted_session_is_high(self):
        """本会话确实脱敏过，却出现未登记编号 —— 这才是伪造探测。"""
        r = ContentRestorer()
        sid = r.begin_session("s2")
        r.vault.intern(sid, EMAIL, "email")
        out, anomalies = r.restore(sid, "⟦XD_9999⟧")
        assert out == "⟦XD_9999⟧", "未登记编号不得被还原"
        assert anomalies and anomalies[0].severity == "high"

    def test_restore_payload_rewrites_content(self):
        r = ContentRestorer()
        sid = r.begin_session("s1")
        idx = r.vault.intern(sid, EMAIL, "email")
        payload = {
            "choices": [{"message": {"role": "assistant",
                                     "content": f"已记录：⟦XD_{idx}⟧"}}]
        }
        restored, stats = app_mod._restore_payload(payload, r, sid)
        assert restored["choices"][0]["message"]["content"] == f"已记录：{EMAIL}"
        assert stats["count"] == 1 and stats["ids"] == [idx]

    def test_restore_payload_rewrites_tool_calls(self):
        """纯工具调用响应（content 为 null）也必须被还原。"""
        r = ContentRestorer()
        sid = r.begin_session("s1")
        idx = r.vault.intern(sid, EMAIL, "email")
        ph = f"⟦XD_{idx}⟧"
        arguments = json.dumps({"path": "/tmp/a.conf", "content": f"mail={ph}"})
        payload = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1", "type": "function",
                        "function": {"name": "write_file", "arguments": arguments},
                    }],
                }
            }]
        }
        restored, stats = app_mod._restore_payload(payload, r, sid)
        args = restored["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        assert ph not in args, "工具调用参数里的占位符没有被还原 —— 会被原样执行"
        assert f"mail={EMAIL}" in args
        assert json.loads(args)["content"] == f"mail={EMAIL}", "还原后 JSON 结构被破坏了"
        assert stats["count"] == 1

    def test_restore_payload_handles_anthropic_tool_use(self):
        r = ContentRestorer()
        sid = r.begin_session("s1")
        idx = r.vault.intern(sid, PHONE, "phone")
        payload = {
            "content": [
                {"type": "text", "text": f"手机号 ⟦XD_{idx}⟧"},
                {"type": "tool_use", "id": "t1", "name": "save",
                 "input": {"phone": f"⟦XD_{idx}⟧"}},
            ]
        }
        restored, _ = app_mod._restore_payload(payload, r, sid)
        assert restored["content"][0]["text"] == f"手机号 {PHONE}"
        assert restored["content"][1]["input"]["phone"] == PHONE

    def test_escaped_sse_frame_stays_valid_json(self):
        """`\\u27e6` 形态还原后必须重新转义，否则含引号的值会撑破 JSON。"""
        r = ContentRestorer()
        sid = r.begin_session("s1")
        tricky = 'p"a\\ss'
        idx = r.vault.intern(sid, tricky, "custom")
        frame = 'data: {"choices":[{"delta":{"content":"\\u27e6XD_%d\\u27e7"}}]}\n\n' % idx

        escaped = r.is_escaped_form(frame)
        assert escaped, "转义形态没有被识别"
        normalized = r.normalize_escaped(frame)
        restored, _ = r.restore(sid, normalized, json_escape=escaped)

        body = restored[len("data: "):].strip()
        parsed = json.loads(body)   # 结构必须仍然合法
        assert parsed["choices"][0]["delta"]["content"] == tricky


# ══════════════════════════════════════════════════════════════
# 请求侧：工具调用参数也要脱敏
# ══════════════════════════════════════════════════════════════


class TestRequestToolCallsAreSanitized:
    def test_openai_tool_call_arguments(self):
        r = ContentRestorer()
        sid = r.begin_session("s1")
        sz = RequestSanitizer(level="balanced")
        body = {
            "messages": [
                {"role": "user", "content": "帮我改一下配置"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1", "type": "function",
                        "function": {
                            "name": "write_file",
                            "arguments": json.dumps({"content": f"mail={EMAIL}"}),
                        },
                    }],
                },
            ]
        }
        records = app_mod._sanitize_messages_inplace(
            body, sz, None, vault=r.vault, session_id=sid
        )
        args = body["messages"][1]["tool_calls"][0]["function"]["arguments"]
        assert EMAIL not in args, "工具调用参数里的邮箱被原样发给了中转站"
        assert "⟦XD_" in args
        assert records, "脱敏记录为空，日志里看不到这次打码"

    def test_anthropic_tool_use_input(self):
        r = ContentRestorer()
        sid = r.begin_session("s1")
        sz = RequestSanitizer(level="balanced")
        body = {
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "改配置"}]},
                {
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use", "id": "t1", "name": "write_file",
                        "input": {"content": f"mail={EMAIL}"},
                    }],
                },
            ]
        }
        app_mod._sanitize_messages_inplace(
            body, sz, None, vault=r.vault, session_id=sid
        )
        value = body["messages"][1]["content"][0]["input"]["content"]
        assert EMAIL not in value
        assert "⟦XD_" in value

    def test_user_message_still_blocks(self):
        """用户本轮亲手贴密钥，仍然必须被拦住（不能被「只打码」吞掉）。"""
        import pytest

        r = ContentRestorer()
        sid = r.begin_session("s1")
        sz = RequestSanitizer(level="balanced")
        body = {"messages": [
            {"role": "user", "content": "这是我的 key：sk-proj-abcdefghijklmnopqrstuvwxyz0123"},
        ]}
        with pytest.raises(app_mod._BlockRequest):
            app_mod._sanitize_messages_inplace(
                body, sz, None, vault=r.vault, session_id=sid
            )

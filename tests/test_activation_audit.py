# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""签发日志传播检测（audit 子命令）测试。

★ 为什么这个文件值得存在
────────────────────────────────────────────────────────────────
客户端校验防不住破解 —— 校验发生在用户机器上，用户拥有那台机器。
所以「码有没有被传播」这件事，**只有签发方能看见**。

换绑是传播的唯一直接信号，而不记录它就等于把眼睛闭上：
`rebind` 原先不写签发日志，于是 audit 什么都发现不了。

本文件验证的核心判据是**不误报**：
正常用户一年可能换一次机（换硬盘、系统重装）。
阈值定太低会把正常用户报成异常 —— 而一个永远在报警的告警
等于没有告警，最终没人看。
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
_TOOL = _ROOT / "tools" / "activation" / "gen_activation_keys.py"


@pytest.fixture
def signer(tmp_path, monkeypatch):
    """临时密钥对 + 隔离的签发日志。

    ★ 刻意**不用仓库里的真实私钥**：测试在源码树里用真凭据签名
      意味着一旦测试输出泄漏，凭据也跟着走。临时密钥无此风险。
    """
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    (tmp_path / "appdata").mkdir(parents=True, exist_ok=True)

    r = subprocess.run(
        [sys.executable, str(_TOOL), "genkeypair", "--out-dir", str(tmp_path)],
        capture_output=True, text=True, encoding="utf-8",
    )
    if r.returncode != 0:
        pytest.skip(f"无法生成密钥对（可能缺 cryptography）: {r.stderr[:200]}")

    key = tmp_path / "xuanDun_personal_private.pem"
    pub = tmp_path / "xuanDun_personal_public.pem"
    monkeypatch.setenv("XUANDUN_LICENSE_PUBKEY_FILE", str(pub))
    return {
        "key": key,
        "pub": pub,
        "log": tmp_path / "ACTIVATION_LOG.json",
    }


def _issue(s, name, mch):
    r = subprocess.run(
        [sys.executable, str(_TOOL), "issue", "--key", str(s["key"]),
         "--name", name, "--mch", mch, "--days", "90", "--log", str(s["log"])],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert r.returncode == 0, r.stderr[:300]
    return json.loads(s["log"].read_text(encoding="utf-8"))[-1]["code"]


def _rebind(s, code, new_mc):
    from daoti_xuandun_personal import license as lic

    req = lic.build_rebind_request(code, new_mc)
    r = subprocess.run(
        [sys.executable, str(_TOOL), "rebind", "--key", str(s["key"]),
         "--pub", str(s["pub"]), "--request", req, "--log", str(s["log"])],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert r.returncode == 0, r.stderr[:400]
    return json.loads(s["log"].read_text(encoding="utf-8"))[-1]["code"]


def _audit(s, *extra):
    r = subprocess.run(
        [sys.executable, str(_TOOL), "audit", "--log", str(s["log"]), *extra],
        capture_output=True, text=True, encoding="utf-8",
    )
    return r.returncode, r.stdout, r.stderr


# ══════════════════════════════════════════════════════════════
# 换绑必须留痕
# ══════════════════════════════════════════════════════════════


def test_rebind_is_recorded_in_log(signer):
    """★ 换绑必须写进签发日志。

    不记的话，audit 看不见任何传播痕迹 ——
    而换绑次数正是判断「一张码被几个人用」的唯一依据。
    """
    code = _issue(signer, "张三", "PC-A")
    assert not _rebind(signer, code, "PC-B") is None

    records = json.loads(signer["log"].read_text(encoding="utf-8"))
    assert len(records) == 2, f"应有签发 + 换绑两条记录，实际 {len(records)}"
    rebind_rec = records[-1]
    assert rebind_rec.get("event") == "rebind", "换绑记录必须带 event 标记"
    assert rebind_rec.get("from_mch"), "换绑记录必须记下原机器码"
    assert rebind_rec.get("gen") == 1, "换绑后 gen 应为 1"


def test_issue_record_has_no_event_marker(signer):
    """签发记录不带 event（默认按 issue 处理），避免与换绑混淆。"""
    _issue(signer, "李四", "PC-X")
    rec = json.loads(signer["log"].read_text(encoding="utf-8"))[-1]
    assert rec.get("event", "issue") == "issue"
    assert rec.get("gen") == 0


# ══════════════════════════════════════════════════════════════
# 传播检测
# ══════════════════════════════════════════════════════════════


def test_normal_rebind_does_not_alert(signer):
    """★ 正常用户换一次机**不应**告警。

    这是本文件最重要的判据：阈值定太低会把正常用户报成异常，
    而一个永远在报警的告警等于没有告警。
    """
    code = _issue(signer, "张三", "PC-A")
    _rebind(signer, code, "PC-B")

    rc, out, _ = _audit(signer)
    assert rc == 0, f"正常换机不该告警：\n{out}"
    assert "未发现异常" in out


def test_third_machine_triggers_alert(signer):
    """★ 同一码换到第 3 台机器 → 告警。

    这是「码在传播」最直接的信号，客户端一个都给不出。
    """
    code = _issue(signer, "张三", "PC-A")
    _rebind(signer, code, "PC-B")
    _rebind(signer, code, "PC-C")

    rc, out, _ = _audit(signer)
    assert rc == 1, f"传播到 3 台机器应告警：\n{out}"
    assert "极可能已传播" in out
    # 告警必须给出可执行的处置建议，而不只是「有问题」
    assert "revoke" in out, "告警必须给出吊销命令，否则签发方不知道下一步做什么"


def test_threshold_is_adjustable(signer):
    """阈值可调 —— 不同发行规模下「几次换绑算异常」不一样。"""
    code = _issue(signer, "张三", "PC-A")
    _rebind(signer, code, "PC-B")
    _rebind(signer, code, "PC-C")

    rc, _, _ = _audit(signer, "--max-machines", "5")
    assert rc == 0, "放宽阈值后不该告警"


def test_rebind_count_threshold(signer):
    """换绑次数超阈值也要告警（同一台机器反复换绑也是异常信号）。"""
    code = _issue(signer, "张三", "PC-A")
    for i in range(3):
        code = _rebind(signer, code, f"PC-{i}")

    rc, out, _ = _audit(signer, "--max-machines", "99", "--max-rebinds", "2")
    assert rc == 1, f"换绑 3 次应告警：\n{out}"
    assert "批量使用" in out


# ══════════════════════════════════════════════════════════════
# 退化路径：绝不能把「查不了」当成「没问题」
# ══════════════════════════════════════════════════════════════


def test_missing_log_is_not_an_error(signer):
    """尚无签发日志是正常状态（还没卖出去），不该报错。"""
    rc, out, _ = _audit(signer)
    assert rc == 0
    assert "尚无签发日志" in out


def test_corrupted_log_fails_closed(signer, tmp_path):
    """★ 日志损坏必须返回非 0，并明确提示别当成「无异常」。

    若损坏时返回 0 且打印「未发现异常」，那是最危险的组合：
    传播检测看起来在工作，实际已经瞎了。
    """
    signer["log"].write_text("{ not json", encoding="utf-8")
    rc, out, err = _audit(signer)
    assert rc == 1, "日志损坏必须返回非 0"
    assert "未发现异常" not in out, "损坏时不得输出「未发现异常」"
    assert "别当成" in err, "必须明确提示别把损坏当成无异常"


def test_non_list_log_fails_closed(signer):
    """内容不是列表 = 文件被改坏，同样不得当成「无异常」。"""
    signer["log"].write_text('{"not": "a list"}', encoding="utf-8")
    rc, out, _ = _audit(signer)
    assert rc == 1
    assert "未发现异常" not in out


def test_records_without_jti_are_skipped(signer):
    """缺 jti 的记录应跳过而非崩溃 —— 日志可能被人手编辑过。"""
    signer["log"].write_text(
        json.dumps([{"name": "无 jti"}, {"jti": "", "name": "空 jti"}]),
        encoding="utf-8",
    )
    rc, out, _ = _audit(signer)
    assert rc == 0, f"缺 jti 的记录应被跳过，不该崩溃：\n{out}"


def test_audit_does_not_touch_real_user_state(signer, monkeypatch, tmp_path):
    """★ audit 只读签发日志，不得改动吊销名单。

    它是**检测**工具，不是处置工具 ——
    看到异常就自动吊销会误伤正常用户（阈值本来就有误报可能）。
    """
    from daoti_xuandun_personal import license as lic

    code = _issue(signer, "张三", "PC-A")
    _rebind(signer, code, "PC-B")
    _rebind(signer, code, "PC-C")

    before = lic.load_revoked()
    _audit(signer)
    after = lic.load_revoked()
    assert before == after, "audit 不得修改吊销名单"

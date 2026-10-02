# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""守卫类测试的变异验证。

为什么需要这个脚本
────────────────────────────────────────────────────────────────
本轮加的守卫（掩码 Key 报错、测试序号作废）都是「读源码 + 断言」形式。
这类测试最大的风险不是写错，而是**恒真** —— 断言看起来在检查，
实际无论代码怎么坏都能通过。那样它比没有测试更糟：给人虚假的安全感。

判据只有一条：**把守卫改坏，测试必须红**。
所以这里真的去改坏它，跑测试，确认变红，再还原。

用法：
    python tests/mutation_check.py
退出码 0 = 全部变异都被捕获（守卫有效）。
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (名称, 相对路径, 把守卫改坏的替换规则, 期望失败的测试名片段)
MUTATIONS = [
    (
        "去掉测试序号比对（陈旧结论会覆盖新输入）",
        "desktop/src/pages/Settings.tsx",
        [
            (
                r"if \(!mountedRef\.current \|\| seq !== testSeqRef\.current\) return;",
                "if (!mountedRef.current) return;",
            )
        ],
        "test_stale_test_result_is_discarded",
    ),
    (
        "改地址时不再作废在飞请求",
        "desktop/src/pages/Settings.tsx",
        [
            # 只删地址 onChange 里的那一处。地址处理形如
            #   setConfig({ ...config, relay: { ...config.relay,
            #     base_url: e.target.value } });
            # 后面跟着若干注释行，再是 testSeqRef.current += 1。
            # 全文有多处 testSeqRef.current += 1，不能一刀切删掉。
            (
                r"(base_url: e\.target\.value \} \}\);\s*\n(?:\s*//[^\n]*\n)*\s*)"
                r"testSeqRef\.current \+= 1;",
                r"\1",
            )
        ],
        "test_stale_test_result_is_discarded",
    ),
    (
        "掩码 Key 守卫改回静默 continue",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"raise HTTPException\(\s*status_code=400,\s*detail=\(\s*\"这个 API Key.*?\),\s*\)",
                "continue",
            )
        ],
        "test_update_config_rejects_masked_key_loudly",
    ),
    # ── 拦截依据（2026-10-02）──
    #   阻断路径从不落库 + detail_json 写成 dict，
    #   导致 40 条真实拦截在界面上看起来像 40 次误报。
    (
        "阻断分支不再落库脱敏记录",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"if blocked\.records:\s*\n\s*_storage\.insert_redactions\(\s*\n"
                r"\s*log_id, session_id, blocked\.records\s*\n\s*\)",
                "pass  # 变异：故意不落库",
            )
        ],
        "test_block_branch_writes_redaction_records",
    ),
    (
        "阻断依据改回空记录",
        "src/daoti_xuandun_personal/proxy/sanitizer.py",
        [(r"records=_masked_evidence\(text, deduped\),", "records=[],  # 变异")],
        "test_block_result_carries_evidence_records",
    ),
    (
        "证据不掩码、直接存原文",
        "src/daoti_xuandun_personal/proxy/sanitizer.py",
        [
            (
                r"original=_mask_value\(text\[start:end\]\),",
                "original=text[start:end],  # 变异",
            )
        ],
        "test_evidence_masks_the_original",
    ),
    (
        "detail_json 改回 dict（前端只渲染数组）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"    out: List\[Dict\[str, Any\]\] = \[\s*\n"
                r'        \{\s*\n\s*"category": "request_blocked",',
                '    out: Dict[str, Any] = {}  # 变异\n    _unused = [\n        {\n'
                '            "category": "request_blocked",',
            ),
            (r"^    return out$", "    return out  # 变异"),
        ],
        "test_detail_json_is_a_list_not_a_dict",
    ),
    (
        "阻断又记进「已打码」计数",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"_storage\.update_daily_stats\(total_calls=1, danger=1\)",
                "_storage.update_daily_stats(total_calls=1, danger=1,"
                " redactions=len(blocked.records))  # 变异",
            )
        ],
        "test_block_branch_does_not_inflate_redaction_counter",
    ),
    (
        "前端不再渲染 evidence 字段",
        "desktop/src/pages/Logs.tsx",
        [(r"\{f\.evidence && \(", "{false && (  # 变异")],
        "test_drawer_renders_evidence_field",
    ),
    (
        "首页刷新按钮不再触发动作",
        "desktop/src/pages/Dashboard.tsx",
        [
            (
                r"onClick=\{\(\) => void handleRefresh\(\)\}\s*\n"
                r"\s*disabled=\{refreshing\}\s*\n\s*aria-label=\"刷新数据\"",
                'onClick={() => undefined}  # 变异\n            disabled={true}\n'
                '            aria-label="刷新数据"',
            )
        ],
        "test_dashboard_has_refresh_button",
    ),
    (
        "刷新时间戳忘了 /1000（秒/毫秒错配）",
        "desktop/src/pages/Dashboard.tsx",
        [
            (
                r"setLastLoadedAt\(Date\.now\(\) / 1000\);",
                "setLastLoadedAt(Date.now());  # 变异",
            )
        ],
        "test_refresh_timestamp_uses_seconds_not_milliseconds",
    ),
    # ── 标记误报必须真的降数（2026-10-02）──
    (
        "标记误报不再回退 daily_stats",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"            self\._adjust_daily_stats_for_mark\(entry, delta=-1\)",
                "            pass  # 变异：不再回退统计",
            )
        ],
        "test_marking_a_block_lowers_danger",
    ),
    (
        "标记误报连带回退「安全」计数",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r'        if entry\.action == Action\.BLOCK\.value:\n'
                r'            col = "danger_count"\n'
                r"        elif entry\.action == Action\.ALERT\.value:\n"
                r'            col = "suspect_count"\n'
                r"        else:\n            return",
                '        col = {"block": "danger_count", "alert": "suspect_count",'
                '\n               "pass": "safe_count"}[entry.action]'
                "  # 变异",
            )
        ],
        "test_marking_pass_does_not_shrink_safe_count",
    ),
    (
        "标记误报时重复扣减（去掉幂等保护）",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"        if entry\.marked_safe:\n"
                r"            return True   # 已标记，不重复扣减",
                "        # 变异：幂等保护被去掉",
            )
        ],
        "test_marking_twice_does_not_double_subtract",
    ),
    (
        "取消标记不再把数字加回",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"            self\._adjust_daily_stats_for_mark\(entry, delta=1\)",
                "            pass  # 变异：不加回",
            )
        ],
        "test_unmarking_restores_the_count",
    ),
    (
        "计数不再防负数",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"SET \{col\} = MAX\(0, \{col\} \+ \?\),\n"
                r"\s*total_calls = MAX\(0, total_calls \+ \?\)",
                "SET {col} = {col} + ?,\n"
                "                    total_calls = total_calls + ?",
            )
        ],
        "test_counts_never_go_negative",
    ),
    (
        "前端又承诺「后续统计不再计入」",
        "desktop/src/pages/Logs.tsx",
        [
            (
                r"toast\.success\('已标记为误报，今日「危险/可疑」计数已减去这一条'\);",
                "toast.success('已标记为误报，后续统计将不再计入风险');"
                "  // 变异",
            )
        ],
        "test_toast_matches_reality",
    ),
    # ── 评分归因（2026-10-02）──
    #   用户看到 0/100，扣分明细 −380。查库发现那 19 次「危险」
    #   全部是「响应长度突变」——用户问了个长问题，
    #   中转站被扣了 380 分。评分算法必须按责任归因。
    (
        "长度突变又算回中转站的责任",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"_RELAY_ATTRIBUTABLE: frozenset = frozenset\(\{\n"
                r'    "tool_call_dangerous",',
                '_RELAY_ATTRIBUTABLE: frozenset = frozenset({\n'
                '    "length_anomaly",  # 变异\n'
                '    "tool_call_dangerous",',
            )
        ],
        "test_length_anomaly_is_not_relay_fault",
    ),
    (
        "评分改回按绝对次数累减（会触底）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"            weighted = rep\.relay_danger_count \* 2"
                r" \+ rep\.relay_suspect_count\n"
                r"            ratio = weighted / denominator\n"
                r"            score -= min\(_BEHAVIOR_MAX_PENALTY,"
                r" ratio \* _BEHAVIOR_MAX_PENALTY \* 4\)",
                "            score -= rep.relay_danger_count * 20"
                "  # 变异\n"
                "            score -= rep.relay_suspect_count * 4",
            )
        ],
        "test_score_is_not_bottomed_out",
    ),
    (
        "分母不排除用户自身事件（可被洗白）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        relay_risk = rep\.relay_danger_count"
                r" \+ rep\.relay_suspect_count\n"
                r"        normal = rep\.total_calls - relay_risk - \(\n"
                r"            rep\.self_danger_count \+ rep\.self_suspect_count\n"
                r"        \)\n"
                r"        denominator = relay_risk \+ max\(0, normal\)",
                "        denominator = rep.total_calls  # 变异",
            )
        ],
        "test_user_side_events_cannot_inflate_the_score",
    ),
    (
        "分母改用 total_calls（用户侧可洗白分数）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"            ratio = weighted / denominator",
                "            ratio = weighted / rep.total_calls  # 变异",
            )
        ],
        "test_user_side_events_cannot_inflate_the_score",
    ),
    (
        "评分不再有下限（可被稀释到 0）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"_BEHAVIOR_MAX_PENALTY = 55\.0",
                "_BEHAVIOR_MAX_PENALTY = 500.0  # 变异",
            )
        ],
        "test_score_never_reaches_zero_from_behaviour_alone",
    ),
    (
        "用户侧事件被算进扣分（可刷分）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"            weighted = rep\.relay_danger_count \* 2"
                r" \+ rep\.relay_suspect_count",
                "            weighted = (rep.relay_danger_count"
                " + rep.self_danger_count) * 2"
                " + rep.relay_suspect_count + rep.self_suspect_count"
                "  # 变异",
            )
        ],
        "test_user_side_events_cannot_inflate_the_score",
    ),
    (
        "水印扣分被稀释进比例",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        if rep\.watermark_detected:\n"
                r"            score -= _WATERMARK_PENALTY",
                "        if rep.watermark_detected:\n"
                "            score -= _WATERMARK_PENALTY / 10  # 变异",
            )
        ],
        "test_watermark_penalised_once_and_hard",
    ),
    (
        "恶意库不再直接归零",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        if rep\.known_malicious:\n            return 0",
                "        # 变异：不再直接归零",
            )
        ],
        "test_known_malicious_still_zeroes_it",
    ),
    (
        "前端扣分权重与后端脱钩",
        "desktop/src/pages/Dashboard.tsx",
        [
            (
                r"  watermark: 30,",
                "  watermark: 10,  # 变异",
            )
        ],
        "test_weights_match_backend_constants",
    ),
    (
        "新字段不落库（重启后归因丢失）",
        "src/daoti_xuandun_personal/storage/db.py",
        [
            (
                r"                    rep\.relay_danger_count, rep\.self_danger_count,\n"
                r"                    rep\.relay_suspect_count, rep\.self_suspect_count,",
                "                    0, 0, 0, 0,  # 变异",
            )
        ],
        "test_new_columns_survive_round_trip",
    ),
    (
        "导入时不重算分数（沿用旧算法的错值）",
        "src/daoti_xuandun_personal/reputation/tracker.py",
        [
            (
                r"        rep\.score = self\._compute_score\(rep\)\n"
                r"        self\._reputations\[rep\.domain\] = rep",
                "        # 变异：不重算\n"
                "        self._reputations[rep.domain] = rep",
            )
        ],
        "test_score_is_recomputed_on_load",
    ),
    (
        "重算结果不写回库（内存对库里错）",
        "src/daoti_xuandun_personal/proxy/app.py",
        [
            (
                r"        _reputation\.import_reputation\(rep\)\n"
                r"        try:\n"
                r"            _storage\.upsert_reputation\(rep\)\n"
                r"        except Exception as e:  # noqa: BLE001\n"
                r"            # 重算后的分数写回失败不应阻断启动：\n"
                r"            # 内存里的值已经是正确的，接口照常可用。\n"
                r"            logger\.warning\(\"信誉分数回写失败（内存值仍正确）: %s\", e\)",
                "        _reputation.import_reputation(rep)  # 变异：不回写",
            )
        ],
        "test_startup_recomputes_and_persists",
    ),
]


def run_tests(pattern: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "tests/test_relay_config.py", "tests/test_block_evidence.py",
            "tests/test_reputation_score.py",
            "-q", "-k", pattern, "--tb=line", "-rf",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    # ★★ 这里必须只保留 pytest 的**摘要行**，丢弃其余全部输出。
    #
    #   踩过的坑：判据要读 Logs.tsx / Dashboard.tsx 源码，
    #   pytest 会把断言失败时的源码片段整段打进输出，
    #   「FAILED ...::test_xxx」摘要行被顶到上万字符之外。
    #   于是只截尾部 → 漏掉摘要行 → 明明红了却判成
    #   「红的是别的用例」。
    #
    #   --tb=line 也**不足以**解决：断言消息本身
    #   就包含整份源码（不是 traceback 才带），
    #   所以正确做法是主动过滤，只留含 FAILED/PASSED 的行。
    #   这比调大截取长度可靠 —— 后者只是把阈值往后挪，
    #   源码再长一点又会漏。
    lines = [
        ln for ln in (proc.stdout or "").splitlines()
        if "FAILED" in ln or "passed" in ln or "failed" in ln
        or "error" in ln.lower()
    ]
    return proc.returncode, "\n".join(lines)


def _named_test_failed(out: str, expect: str) -> bool:
    """确认**指定的那条**判据报红，而不是随便哪条红了。

    ★ 为什么必须这么严
      只看「整体红没红」是不够的：变异可能意外弄坏了别的用例，
      于是 exit code 非零，但我们要验的那条判据其实没被测到。
      那等于用一条假判据冒充真判据 ——
      比没有变异验证更糟，因为它给了虚假的安全感。
    """
    return expect in out


def main() -> int:
    print("=" * 72)
    print("  守卫测试的变异验证 —— 把守卫改坏，测试必须红")
    print("=" * 72)

    # 先确认基线是绿的
    rc, out = run_tests("")
    if rc != 0:
        print("[FATAL] 基线就已经不是绿的，无法评估变异：")
        print(out[-1500:])
        return 2
    print("  基线: 绿")

    all_caught = True
    for name, rel, rules, expect in MUTATIONS:
        target = ROOT / rel
        backup = Path(tempfile.mkdtemp()) / Path(rel).name
        shutil.copy2(target, backup)
        text = original = target.read_text(encoding="utf-8")

        hit = False
        for pat, rep in rules:
            text, n = re.subn(pat, rep, text, flags=re.S)
            hit = hit or n > 0
        if not hit:
            print(f"\n  [SKIP] {name}")
            print("        变异规则没匹配到源码 —— 规则本身可能已过时，")
            print("        这本身就是需要人看的问题。")
            shutil.copy2(backup, target)
            all_caught = False
            continue

        target.write_text(text, encoding="utf-8")
        try:
            rc, out = run_tests(expect)
        finally:
            shutil.copy2(backup, target)

        # ── 判据：既要看整体红，也要确认是**指定那条**红 ──
        long_out = out
        caught = rc != 0 and _named_test_failed(long_out, expect)
        print(f"\n  [{'PASS' if caught else 'FAIL'}] {name}")
        if caught:
            first = [
                ln for ln in long_out.splitlines()
                if expect in ln and ("AssertionError" in ln or "assert" in ln)
            ]
            if not first:
                first = [
                    ln for ln in long_out.splitlines()
                    if "AssertionError" in ln or "assert" in ln
                ]
            if first:
                print(f"        {first[0].strip()[:110]}")
        elif rc != 0:
            print(f"        测试变红了，但红的是别的用例 —— 期望 {expect}，")
            print("        说明这条判据没被测到，却拿了别人的红当证据。")
            all_caught = False
        else:
            print("        测试仍然绿 —— 守卫没有真正被测到，这条断言是恒真的")
            all_caught = False

    # 还原确认
    for _, rel, _, _ in MUTATIONS:
        pass  # 每次变异都已即时还原

    print()
    print("=" * 72)
    if all_caught:
        print("  结论: 全部变异都被捕获 —— 守卫确实在被测")
        return 0
    print("  结论: 存在未被捕获的变异 —— 有断言是恒真的，必须修")
    return 1


if __name__ == "__main__":
    sys.exit(main())

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
]


def run_tests(pattern: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "tests/test_relay_config.py", "tests/test_block_evidence.py",
            "-q", "-k", pattern,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, (proc.stdout or "")[-4000:]


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

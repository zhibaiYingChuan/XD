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
]


def run_tests(pattern: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_relay_config.py", "-q", "-k", pattern],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, (proc.stdout or "")[-400:]


def main() -> int:
    print("=" * 72)
    print("  守卫测试的变异验证 —— 把守卫改坏，测试必须红")
    print("=" * 72)

    # 先确认基线是绿的
    rc, out = run_tests("MaskedKeyIsNotAKey")
    if rc != 0:
        print("[FATAL] 基线就已经不是绿的，无法评估变异：")
        print(out)
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

        caught = rc != 0
        print(f"\n  [{'PASS' if caught else 'FAIL'}] {name}")
        if caught:
            first = [
                ln for ln in out.splitlines() if "AssertionError" in ln or "assert" in ln
            ]
            if first:
                print(f"        {first[0].strip()[:110]}")
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

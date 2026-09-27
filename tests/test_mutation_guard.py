# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""测试自身的可靠性验证（变异测试 / mutation testing）。

为什么需要这个文件
────────────────────────────────────────────────────────────────
本轮真实发生过一次「假通过」：把 typosquat 的判据彻底关掉后，
32 个 pytest 用例全绿。原因是断言只检查
`bool(findings)` —— 只要有任何判据命中就算通过，
而 A2 样本同时被 data_exfiltration 等其他判据覆盖，
于是 typosquat 检测失效这件事被完全掩盖。

这类问题不会自己暴露：代码没坏、测试没红、CI 通过，
只有防护能力悄悄消失了。

本文件用「故意破坏 → 确认测试失败」的方式验证测试有效。
运行：pytest tests/test_mutation_guard.py
"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC_FILE = ROOT / "src" / "daoti_xuandun_personal" / "proxy" / "baseline.py"


# (变异描述, 原始代码片段, 变异后代码片段, 应当失败的测试)
MUTATIONS = [
    (
        "关闭 typosquat 编辑距离判据",
        "if _damerau_levenshtein(sig, real_bare, cap=1) == 1:",
        "if False:",
        "tests/test_false_positive.py::test_typosquat_still_detected",
    ),
    (
        "关闭工具名归一化（退回逐字节比较）",
        "if not _tool_name_matches_any(n, declared)",
        "if n not in declared",
        "tests/test_false_positive.py::test_tool_name_gateway_variants_allowed",
    ),
    (
        "关闭约束违背检测",
        "violations = _check_constraint_violations(baseline, content)",
        "violations = []",
        "tests/test_redteam_attack.py::test_prompt_integrity_blocked",
    ),
    (
        "关闭工具链注入检测",
        "findings.extend(_check_toolchain_injection(baseline, content))",
        "pass",
        "tests/test_redteam_attack.py::test_toolchain_injection_detected",
    ),
    (
        "关闭未声明工具检测（undeclared_tool 恒为空）",
        "undeclared = [\n            n for n in returned\n"
        "            if not _tool_name_matches_any(n, declared)\n        ]",
        "undeclared = []",
        "tests/test_redteam_attack.py::test_tool_call_hijack_blocked",
    ),
    (
        # ★ 这个变异点最初写成「把 req_model 换成裸 strip()」，
        #   结果测试仍通过 —— 因为 resp_model 那一行仍走归一化，
        #   gpt-4o-2024-11-01 被归一化成 gpt-4o，恰好等于请求侧。
        #   教训：变异必须破坏**机制本身**，不能只改一个调用点，
        #   否则被其他路径的同一机制兜住，测不出退化。
        "关闭模型名归一化机制",
        "    # 剥掉 vendor 前缀（可能多层，如 accounts/fireworks/models/xxx）\n"
        "    changed = True",
        "    return s\n"
        "    # 剥掉 vendor 前缀（可能多层，如 accounts/fireworks/models/xxx）\n"
        "    changed = True",
        "tests/test_false_positive.py::test_no_false_positive_on_model_variants",
    ),
]


def _run_pytest(target: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", target,
         "-q", "--no-header", "-x", "-p", "no:cacheprovider"],
        cwd=str(ROOT), capture_output=True, text=True,
    )


@pytest.mark.parametrize(
    "desc,original,mutated,target",
    MUTATIONS,
    ids=[m[0] for m in MUTATIONS],
)
def test_mutation_is_detected(desc, original, mutated, target):
    """故意破坏判据后，对应测试必须失败。

    若本测试失败（变异后测试仍通过），说明断言太宽松，
    防护能力会悄悄退化而无人察觉。
    """
    original_src = SRC_FILE.read_text(encoding="utf-8")
    if original not in original_src:
        pytest.skip(f"变异点未找到（baseline.py 已改动）：{original[:50]}")

    try:
        SRC_FILE.write_text(
            original_src.replace(original, mutated, 1), encoding="utf-8"
        )
        r = _run_pytest(target)
        assert r.returncode != 0, (
            f"★假通过：{desc} —— 破坏判据后 {target} 仍然通过，"
            f"说明该测试没有真正锁住这项能力"
        )
    finally:
        SRC_FILE.write_text(original_src, encoding="utf-8")


def test_suite_is_green_after_restore():
    """所有变异测试跑完后，源码必须已完全还原且测试全绿。

    两个必须注意的点：
      ① 跑 pytest 时**排除本文件** —— 否则变异测试会递归调用自己，
         形成「变异测试跑变异测试」的无限嵌套（实测会失败）。
      ② 检查源码无残留变异 —— 防止某个变异点还原失败却无人察觉。
    """
    src = SRC_FILE.read_text(encoding="utf-8")
    assert "if False:" not in src, "baseline.py 仍残留变异代码"

    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests",
         "-q", "--no-header", "-p", "no:cacheprovider",
         "--ignore=tests/test_mutation_guard.py"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    assert r.returncode == 0, (
        f"还原后测试未全绿：\n{r.stdout[-1500:]}"
    )

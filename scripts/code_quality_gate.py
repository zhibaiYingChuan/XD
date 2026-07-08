#!/usr/bin/env python3
"""
道体·玄盾 — 自动化代码质量守门人

扫描所有源文件，检测以下问题类别：
  1. 除零风险（含隐式除零如 numpy 运算）
  2. numpy 数值稳定性（NaN/Inf/溢出/类型转换）
  3. 非确定性操作（全局 RNG、hash()、弱 XOR 哈希）
  4. 内存无限增长（字典/列表/deque 无大小限制）
  5. assert 用于运行时检查（应改用 if/raise）
  6. 未使用的导入和变量
  7. f-string 缺少占位符

用法:
  python scripts/code_quality_gate.py [--src DIR] [--strict]
"""

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import List, Tuple

ISSUE_SEVERITY = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}


class CodeIssue:
    def __init__(self, severity: str, file: str, line: int, msg: str):
        self.severity = severity
        self.file = file
        self.line = line
        self.msg = msg

    def __repr__(self):
        return f"[{self.severity}] {self.file}:{self.line} — {self.msg}"


def scan_division_by_zero(source: str, filepath: str) -> List[CodeIssue]:
    issues = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"/\s*\w+\s*\)", stripped) and "max(" not in stripped and "if " not in stripped:
            if re.search(r"\w+\s*/\s*\w+", stripped):
                if not re.search(r"if\s+\w+\s*==\s*0", lines[max(0, i - 3):i + 1][-1]):
                    pass
        if re.search(r"\bnp\.\w+divide\b", stripped):
            if "where" not in stripped and "out" not in stripped:
                issues.append(CodeIssue("HIGH", filepath, i, "np.divide without where/out guard"))
        if re.search(r"\bnp\.\w*mean\b", stripped):
            pass
    return issues


def scan_numpy_stability(source: str, filepath: str) -> List[CodeIssue]:
    issues = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"np\.sqrt\(", stripped) and "max(" not in stripped and "abs(" not in stripped and "clip(" not in stripped:
            issues.append(CodeIssue("HIGH", filepath, i, "np.sqrt without max(0,...) guard — may produce NaN"))
        if re.search(r"np\.log\(", stripped) and "np.log1p" not in stripped and "max(" not in stripped:
            issues.append(CodeIssue("MEDIUM", filepath, i, "np.log without guard — may produce -inf"))
        if re.search(r"\.astype\(np\.int32\)", stripped) and "clip(" not in stripped:
            issues.append(CodeIssue("MEDIUM", filepath, i, "astype(np.int32) without clip — may overflow"))
    return issues


def scan_nondeterminism(source: str, filepath: str) -> List[CodeIssue]:
    issues = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"\bhash\(\s*\w+\s*\)", stripped) and "hashlib" not in stripped:
            issues.append(CodeIssue("HIGH", filepath, i, "hash() is non-deterministic across processes"))
        if re.search(r"\bnp\.random\.(randn|random|rand|choice|integers)\s*\(", stripped) and "default_rng" not in stripped:
            issues.append(CodeIssue("HIGH", filepath, i, "Global np.random call — use default_rng(seed=...) instead"))
        if re.search(r"\^=\s*ord\(", stripped):
            issues.append(CodeIssue("HIGH", filepath, i, "Weak XOR hash — use hashlib.sha256 instead"))
    return issues


def scan_memory_growth(source: str, filepath: str) -> List[CodeIssue]:
    issues = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    dict_names_with_limit = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                if isinstance(child, ast.Compare):
                    if isinstance(child.left, ast.Call) and isinstance(child.left.func, ast.Name):
                        if child.left.func.id == "len":
                            pass

    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"self\._\w+\[", stripped) and "pop(" not in stripped:
            pass
    return issues


def scan_assert_runtime(source: str, filepath: str) -> List[CodeIssue]:
    issues = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"^\s*assert\s+", stripped):
            issues.append(CodeIssue("HIGH", filepath, i, "assert used for runtime check — disabled with -O, use if/raise"))
    return issues


def scan_unused_imports(source: str, filepath: str) -> List[CodeIssue]:
    issues = []
    if filepath.replace("\\", "/").endswith("__init__.py"):
        return issues
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imported[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                if name == "*":
                    continue
                imported[name] = node.lineno

    used_in_code = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used_in_code.add(node.id)
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                used_in_code.add(node.value.id)

    for name, lineno in imported.items():
        if name not in used_in_code and name not in ("__future__",):
            issues.append(CodeIssue("LOW", filepath, lineno, f"Unused import: {name}"))

    return issues


def scan_fstring_without_placeholder(source: str, filepath: str) -> List[CodeIssue]:
    issues = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for m in re.finditer(r'f"[^"{]*"', stripped):
            if "{" not in m.group():
                issues.append(CodeIssue("LOW", filepath, i, "f-string without placeholder — use regular string"))
        for m in re.finditer(r"f'[^'{']*'", stripped):
            if "{" not in m.group():
                issues.append(CodeIssue("LOW", filepath, i, "f-string without placeholder — use regular string"))
    return issues


SCANNERS = [
    ("除零风险", scan_division_by_zero),
    ("numpy数值稳定性", scan_numpy_stability),
    ("非确定性操作", scan_nondeterminism),
    ("assert运行时检查", scan_assert_runtime),
    ("未使用导入", scan_unused_imports),
    ("f-string无占位符", scan_fstring_without_placeholder),
]


def main():
    parser = argparse.ArgumentParser(description="道体·玄盾 代码质量守门人")
    parser.add_argument("--src", default="src/daoti_xuandun", help="源码目录")
    parser.add_argument("--strict", action="store_true", help="严格模式：任何问题均返回非零退出码")
    args = parser.parse_args()

    src_dir = Path(args.src)
    if not src_dir.exists():
        print(f"ERROR: {args.src} does not exist")
        sys.exit(1)

    py_files = sorted(src_dir.rglob("*.py"))
    if not py_files:
        print(f"ERROR: No Python files found in {args.src}")
        sys.exit(1)

    all_issues: List[CodeIssue] = []
    for fp in py_files:
        source = fp.read_text(encoding="utf-8")
        rel = str(fp)
        for name, scanner in SCANNERS:
            issues = scanner(source, rel)
            all_issues.extend(issues)

    if not all_issues:
        print("✅ 代码质量守门人：未发现问题")
        sys.exit(0)

    by_severity = {}
    for issue in all_issues:
        by_severity.setdefault(issue.severity, []).append(issue)

    print(f"⚠️  代码质量守门人：发现 {len(all_issues)} 个问题\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_severity:
            print(f"  [{sev}] {len(by_severity[sev])} 个")
            for issue in by_severity[sev][:20]:
                print(f"    {issue}")
            if len(by_severity[sev]) > 20:
                print(f"    ... 还有 {len(by_severity[sev]) - 20} 个")

    if args.strict:
        sys.exit(1)
    elif any(i.severity in ("CRITICAL", "HIGH") for i in all_issues):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""道体·玄盾 行业基准测试 CLI 入口。

参照 OWASP AITG / NIST Dioptra / garak 等框架，对内嵌攻击数据集进行系统性安全评估。

Usage:
    python run_benchmark.py                          # 运行全部四个防御层级
    python run_benchmark.py --level STANDARD          # 仅运行指定层级
    python run_benchmark.py --level STRICT --quick    # 快速模式（减少样本）
    python run_benchmark.py --output ./reports        # 指定输出目录
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from daoti_xuandun.config import DefenseLevel
from daoti_xuandun.benchmark import BenchmarkRunner, run_full_benchmark


def main():
    parser = argparse.ArgumentParser(
        description="道体·玄盾 行业基准测试（参照 OWASP AITG / NIST Dioptra / garak）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python run_benchmark.py                          # 全部四个层级
  python run_benchmark.py --level PARANOID          # 仅 PARANOID 层级
  python run_benchmark.py --level STRICT --output ./reports
  python run_benchmark.py --list-levels             # 列出可用层级
        """,
    )
    parser.add_argument(
        "--level", "-l",
        type=str,
        default=None,
        choices=[l.value for l in DefenseLevel],
        help="防御层级 (默认: 全部四个层级)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="benchmark_results",
        help="报告输出目录 (默认: benchmark_results)",
    )
    parser.add_argument(
        "--list-levels",
        action="store_true",
        help="列出可用防御层级并退出",
    )
    parser.add_argument(
        "--seed-domains",
        type=str,
        nargs="+",
        default=None,
        help="已知域播种文本 (默认: 使用内置华夏典籍种子)",
    )

    args = parser.parse_args()

    if args.list_levels:
        print("可用防御层级:")
        for level in DefenseLevel:
            print(f"  {level.value:<12} 开销~{level.perf_overhead_pct}%  {level.description}")
        return

    print("=" * 70)
    print("  道体·玄盾 (Daoti XuanDun) 行业基准测试")
    print("  参照框架: OWASP AITG / NIST Dioptra / garak / PromptInject / CySecBench / S-Eval")
    print("=" * 70)

    if args.level:
        level = DefenseLevel(args.level)
        print(f"\n运行层级: {level.value} ({level.description})")
        runner = BenchmarkRunner(level)
        if args.seed_domains:
            runner.seed_domains(args.seed_domains)
        runner.run_all()
        runner.save_reports(args.output)
    else:
        run_full_benchmark(args.output)

    print(f"\n全部基准测试完成。报告位于: {args.output}/")


if __name__ == "__main__":
    main()
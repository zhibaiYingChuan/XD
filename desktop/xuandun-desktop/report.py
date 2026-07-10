# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""测试报告格式化器 — 将模拟测试结果格式化为可读报告。

支持 JSON 和 Markdown 两种格式输出。
"""

import json
import time
from typing import Optional


def format_report_markdown(report: dict) -> str:
    """将测试报告格式化为 Markdown。"""
    lines = [
        "# 道体·玄盾 模拟测试报告",
        "",
        f"**执行时间**: {report.get('timestamp', '')}",
        f"**测试模式**: {_mode_name(report.get('mode', ''))}",
        f"**测试样本**: {report.get('total_samples', 0)} 条",
        f"**耗时**: {report.get('elapsed_seconds', 0)} 秒",
        "",
        "## 总体结果",
        "",
        f"| 指标 | 值 |",
        f"|------|------|",
        f"| 总体拦截率 | {report.get('block_rate', 0) * 100:.1f}% |",
        f"| 误报率 | {report.get('false_positive_rate', 0) * 100:.1f}% |",
        f"| 漏报率 | {report.get('miss_rate', 0) * 100:.1f}% |",
        f"| 准确率 | {report.get('accuracy', 0) * 100:.1f}% |",
        f"| 平均延迟 | {report.get('avg_latency_ms', 0):.2f} ms |",
        "",
        "## 分类结果",
        "",
        "| 类别 | 总数 | 拦截 | 放行 | 拦截率 |",
        "|------|------|------|------|--------|",
    ]

    for key, stats in report.get("category_stats", {}).items():
        lines.append(
            f"| {stats['name']} | {stats['total']} | {stats['blocked']} | {stats['passed']} | {stats['block_rate'] * 100:.1f}% |"
        )

    lines.extend([
        "",
        "## 漏检样本（攻击未被拦截）",
        "",
    ])

    misses = [r for r in report.get("details", []) if r.get("expected") == "attack" and r.get("allowed")]
    if misses:
        for r in misses[:20]:
            lines.append(f"- [{r['category_name']}] {r['text_preview']}")
    else:
        lines.append("无漏检样本")

    lines.extend([
        "",
        "## 误报样本（良性被拦截）",
        "",
    ])

    fps = [r for r in report.get("details", []) if r.get("expected") == "benign" and not r.get("allowed")]
    if fps:
        for r in fps[:20]:
            lines.append(f"- {r['text_preview']}")
    else:
        lines.append("无误报样本")

    return "\n".join(lines)


def save_report_json(report: dict, path: str):
    """保存报告为 JSON 文件。"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def save_report_markdown(report: dict, path: str):
    """保存报告为 Markdown 文件。"""
    md = format_report_markdown(report)
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)


def _mode_name(mode: str) -> str:
    names = {
        "quick": "快速验证",
        "full": "全面测试",
        "custom": "自定义测试",
    }
    return names.get(mode, mode)

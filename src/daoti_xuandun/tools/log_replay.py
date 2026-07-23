# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""日志导入/重放工具 — 用历史日志验证玄盾的拦截效果。

用法：
  python -m daoti_xuandun.tools.log_replay --input logs.jsonl
  python -m daoti_xuandun.tools.log_replay --input logs.jsonl --output replay_report.md
  python -m daoti_xuandun.tools.log_replay --input logs.jsonl --level STRICT

输入格式（JSONL，每行一条）：
  {"text": "用户输入文本", "label": "benign"}
  {"text": "恶意输入", "label": "attack"}
  {"text": "未知分类的输入"}  # label 可选

输出：
  - 终端输出摘要统计
  - 可选保存 Markdown 详细报告
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Tuple

from ..config import DefenseLevel, XuanDunConfig
from ..xuandun import XuanDun


def _load_jsonl(path: str) -> List[dict]:
    """加载 JSONL 格式日志文件。

    每行一个 JSON 对象，至少包含 "text" 字段。
    可选 "label" 字段（"benign"/"attack"）用于计算准确率。
    """
    samples = []
    p = Path(path)
    if not p.exists():
        print(f"错误: 文件不存在 {path}", file=sys.stderr)
        sys.exit(1)

    with open(p, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                text = obj.get("text", "").strip()
                if not text:
                    continue
                label = obj.get("label", "unknown")
                samples.append({
                    "text": text,
                    "label": label,
                    "line": line_num,
                })
            except json.JSONDecodeError:
                print(f"警告: 第 {line_num} 行 JSON 解析失败，跳过", file=sys.stderr)
                continue

    return samples


def _replay_samples(shield: XuanDun, samples: List[dict]) -> List[dict]:
    """重放所有样本，返回检测结果。"""
    results = []
    session = f"replay_{int(time.time())}"

    for i, sample in enumerate(samples):
        text = sample["text"]
        expected = sample["label"]

        t0 = time.perf_counter()
        try:
            result = shield.protect(text, session_id=session)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            allowed = result.allowed
        except Exception:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            allowed = False

        actual = "allowed" if allowed else "blocked"

        if expected == "attack":
            correct = not allowed
        elif expected == "benign":
            correct = allowed
        else:
            correct = None

        results.append({
            "line": sample["line"],
            "text_preview": text[:100] + ("..." if len(text) > 100 else ""),
            "expected": expected,
            "actual": actual,
            "allowed": allowed,
            "correct": correct,
            "latency_ms": round(elapsed_ms, 2),
        })

        if (i + 1) % 50 == 0:
            print(f"  已重放 {i+1}/{len(samples)}...", file=sys.stderr)

    return results


def _build_report(results: List[dict], elapsed: float, input_path: str,
                  level: str) -> str:
    """构建 Markdown 重放报告。"""
    total = len(results)
    labeled = [r for r in results if r["expected"] in ("attack", "benign")]
    unlabeled = [r for r in results if r["expected"] not in ("attack", "benign")]

    attack_total = sum(1 for r in labeled if r["expected"] == "attack")
    attack_blocked = sum(1 for r in labeled if r["expected"] == "attack" and not r["allowed"])
    benign_total = sum(1 for r in labeled if r["expected"] == "benign")
    benign_blocked = sum(1 for r in labeled if r["expected"] == "benign" and not r["allowed"])

    block_rate = attack_blocked / max(1, attack_total)
    false_positive_rate = benign_blocked / max(1, benign_total)
    accuracy = (attack_blocked + (benign_total - benign_blocked)) / max(1, attack_total + benign_total)
    avg_latency = sum(r["latency_ms"] for r in results) / max(1, total)

    lines = [
        "# 道体·玄盾 日志重放报告",
        "",
        f"**生成时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**输入文件**: {input_path}",
        f"**防御层级**: {level}",
        f"**总样本数**: {total}（有标签 {len(labeled)} + 无标签 {len(unlabeled)}）",
        f"**重放耗时**: {elapsed:.1f} 秒",
        "",
        "---",
        "",
        "## 总体结果",
        "",
        "| 指标 | 值 |",
        "|------|------|",
        f"| 攻击拦截率 | {block_rate * 100:.1f}% ({attack_blocked}/{attack_total}) |",
        f"| 误报率 | {false_positive_rate * 100:.1f}% ({benign_blocked}/{benign_total}) |",
        f"| 准确率 | {accuracy * 100:.1f}% |",
        f"| 平均决策延迟 | {avg_latency:.2f} ms |",
        "",
    ]

    # 拦截统计
    total_blocked = sum(1 for r in results if not r["allowed"])
    lines.extend([
        "## 拦截统计",
        "",
        f"- 总拦截数: {total_blocked}/{total} ({total_blocked/max(1,total)*100:.1f}%)",
        f"- 攻击样本拦截: {attack_blocked}/{attack_total}",
        f"- 良性样本误拦: {benign_blocked}/{benign_total}",
        f"- 无标签样本拦截: {sum(1 for r in unlabeled if not r['allowed'])}/{len(unlabeled)}",
        "",
    ])

    # 漏检样本
    misses = [r for r in labeled if r["expected"] == "attack" and r["allowed"]]
    lines.extend([
        "---",
        "",
        "## 漏检样本",
        "",
    ])
    if misses:
        lines.append(f"共 {len(misses)} 条漏检：")
        lines.append("")
        for r in misses[:20]:
            lines.append(f"- [行{r['line']}] {r['text_preview']}")
        if len(misses) > 20:
            lines.append(f"- ... 共 {len(misses)} 条")
    else:
        lines.append("无漏检样本")

    # 误报样本
    fps = [r for r in labeled if r["expected"] == "benign" and not r["allowed"]]
    lines.extend([
        "",
        "## 误报样本",
        "",
    ])
    if fps:
        lines.append(f"共 {len(fps)} 条误报：")
        lines.append("")
        for r in fps[:20]:
            lines.append(f"- [行{r['line']}] {r['text_preview']}")
        if len(fps) > 20:
            lines.append(f"- ... 共 {len(fps)} 条")
    else:
        lines.append("无误报样本")

    lines.extend([
        "",
        "---",
        "",
        "> 本报告由道体·玄盾日志重放工具自动生成。",
        "> 重放结果仅反映当前配置下的检测效果，不代表生产环境实时表现。",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="道体·玄盾 日志重放工具 — 用历史日志验证拦截效果"
    )
    parser.add_argument("--input", "-i", required=True,
                        help="JSONL 格式日志文件路径")
    parser.add_argument("--output", "-o", default=None,
                        help="输出报告文件路径（默认输出到 stdout）")
    parser.add_argument("--level", "-l", default="STANDARD",
                        choices=["BASIC", "STANDARD", "STRICT", "PARANOID"],
                        help="防御层级（默认 STANDARD）")

    args = parser.parse_args()

    level_map = {
        "BASIC": DefenseLevel.BASIC,
        "STANDARD": DefenseLevel.STANDARD,
        "STRICT": DefenseLevel.STRICT,
        "PARANOID": DefenseLevel.PARANOID,
    }
    level = level_map.get(args.level, DefenseLevel.STANDARD)

    print(f"[玄盾] 加载日志文件: {args.input}", file=sys.stderr)
    samples = _load_jsonl(args.input)
    print(f"[玄盾] 已加载 {len(samples)} 条记录", file=sys.stderr)

    print(f"[玄盾] 初始化引擎（{args.level}）...", file=sys.stderr)
    config = XuanDunConfig.preset(level,
                                  enable_observing_mode=False,
                                  enable_builtin_attacks=False)
    shield = XuanDun(config=config)

    print(f"[玄盾] 开始重放...", file=sys.stderr)
    t0 = time.perf_counter()
    results = _replay_samples(shield, samples)
    elapsed = time.perf_counter() - t0

    print(f"[玄盾] 重放完成，耗时 {elapsed:.1f} 秒", file=sys.stderr)

    report = _build_report(results, elapsed, args.input, args.level)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"[玄盾] 报告已保存到 {args.output}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()

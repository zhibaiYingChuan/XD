#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""发布前的误报率门槛。

为什么需要它
────────────
「每个版本都有新误报」的根因不是修得慢，而是**没有度量**：
每次只修眼前那几条，没人回答「这一版整体误报率是多少」。
没有数字，就没有「不能发」的判断依据。

本脚本读本地日志库，算出「已标记误报 / 全部告警+拦截」的比例，
超过阈值就以非零码退出 —— 让发版流程在本地就停下来。

口径
────
  · 分母：action ∈ {alert, block} 的全部日志（全部时间）
  · 分子：其中 marked_safe = 1 的条数（用户已确认是误报）
  · 观察（observe）不计入分母 —— 它本来就不打扰用户

用法
────
    python .github/scripts/check_fp_rate.py
    python .github/scripts/check_fp_rate.py --db <路径> --max-rate 0.15
    python .github/scripts/check_fp_rate.py --days 7   # 只看最近 7 天

退出码
──────
    0  通过（或样本量不足，无法判断）
    1  超过阈值
    2  数据库不存在 / 无法读取
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

#: 样本量下限。少于这个数时比例没有统计意义 ——
#: 3 条里 1 条误报就是 33%，但那不说明任何问题。
MIN_SAMPLES = 20

#: 默认阈值。超过 15% 说明文本判据又在制造噪声。
DEFAULT_MAX_RATE = 0.15


def default_db_path() -> Path:
    """与引擎一致的默认库路径（尊重 XUANDUN_DATA_DIR）。"""
    override = os.environ.get("XUANDUN_DATA_DIR")
    if override:
        return Path(override) / "xuandun_personal.db"
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return Path(base) / "com.daoti.xuandun-personal" / "xuandun_personal.db"


def measure(
    db_path: Path, days: int | None, since: float | None = None
) -> tuple[int, int]:
    """返回 (告警+拦截总数, 其中已标记误报数)。"""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        where = "action IN ('alert', 'block')"
        params: list = []
        if since is not None:
            where += " AND timestamp >= ?"
            params.append(since)
        elif days and days > 0:
            cutoff = time.time() - days * 86400
            where += " AND timestamp >= ?"
            params.append(cutoff)
        row = conn.execute(
            f"SELECT COUNT(*) AS total, "
            f"SUM(CASE WHEN marked_safe = 1 THEN 1 ELSE 0 END) AS marked "
            f"FROM logs WHERE {where}",
            params,
        ).fetchone()
        return int(row[0] or 0), int(row[1] or 0)
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="发布前误报率门槛")
    parser.add_argument("--db", type=Path, default=None, help="日志库路径")
    parser.add_argument(
        "--max-rate", type=float, default=DEFAULT_MAX_RATE,
        help=f"允许的最大误报率（默认 {DEFAULT_MAX_RATE:.0%}）",
    )
    parser.add_argument(
        "--days", type=int, default=7,
        help="只统计最近 N 天（默认 7；传 0 表示全部时间）",
    )
    parser.add_argument(
        "--since", type=float, default=None,
        help=(
            "只统计该 Unix 时间戳之后的日志（优先于 --days）。"
            "用于「只看本次修复上线后的误报率」——"
            "历史积压的误报不该拖住新版本发版。"
        ),
    )
    args = parser.parse_args()

    db_path = args.db or default_db_path()
    if not db_path.exists():
        print(f"[跳过] 日志库不存在：{db_path}")
        print("       没有本地样本，无法判断误报率。")
        return 0

    try:
        total, marked = measure(db_path, args.days, args.since)
    except sqlite3.Error as e:
        print(f"[失败] 读取日志库出错：{e}")
        return 2

    if total < MIN_SAMPLES:
        print(
            f"[跳过] 样本量不足：{total} 条告警/拦截"
            f"（至少需要 {MIN_SAMPLES} 条才有统计意义）"
        )
        return 0

    rate = marked / total
    if args.since is not None:
        scope = time.strftime("%Y-%m-%d %H:%M", time.localtime(args.since)) + " 之后"
    elif args.days:
        scope = f"最近 {args.days} 天"
    else:
        scope = "全部时间"
    print(f"误报率（{scope}）：{marked}/{total} = {rate:.1%}")
    print(f"阈值：{args.max_rate:.0%}")

    if rate > args.max_rate:
        print(
            "\n[不通过] 误报率超过阈值。\n"
            "  先复核最近的告警，把同类误报固化成回归测试，再发版。\n"
            "  参考：tests/test_false_positive_regressions.py\n"
            "  若这是历史积压（旧版本留下的误报），用 --since 只看本次修复上线后的数据。"
        )
        return 1

    print("\n[通过] 误报率在阈值内。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

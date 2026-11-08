#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""构建产物护栏断言 —— CI 用。

防的是什么
────────────────────────────────────────────────────────────────
「线上构建出来的包没有护栏，却当成防火墙发布出去」。

护栏（提示词注入 + 敏感泄露两类检测）在源码里已入库，但它的 import
是**延迟 import** —— Nuitka 的静态分析看不到它，必须显式
`--include-package=daoti_xuandun`。

而判定「护栏在不在场」的路径曾指向仓库外的企业版目录：
  · 本地开发：那个目录恰好存在 → 碰巧编进去了
  · 干净 clone（= GitHub runner）：不存在 → 静默跳过
于是产出一个缺两层检测的包，界面照常显示「防护中」。
用户以为自己受保护，实际上没有。

★ 为什么这个文件是独立文件而不是 YAML 内联脚本
────────────────────────────────────────────────────────────────
2026-09-28 连续三次因内联 Python 失败，每次都要等十分钟的 CI 才暴露：
  1. f-string 里嵌套同类引号 → SyntaxError
  2. set -u 下 FOUND=$(find ...) → unbound variable
  3. Windows 上 test -f 相对路径 → 路径解析失败

内联脚本藏在 YAML 缩进里，本机无从验证。独立文件可以
`python verify_guardrail_bundle.py` 先跑通再推。

判据
────────────────────────────────────────────────────────────────
在**二进制**里搜**只有护栏层才会产生**的符号。

不找 .py 文件 —— Nuitka standalone 把模块编译进二进制，源码不落盘。
不只看目录存在 —— 空壳目录也满足，而它毫无防护能力。

★★ 2026-10-29（第三轮审查 P0-2）：此前的判据是
   `system_prompt_inject` / `sensitive_leak`，并注释写「这些标识只由
   护栏代码产生」—— **那句注释是错的**。这两个字符串恰恰由个人版
   自己在「护栏不可用」分支里产出（verifier.get_stats 的
   guardrail_missing_layers、各类 finding 的 category 名）。
   后果：护栏整包没编进去，这两个串反而必然出现在二进制里，
   门禁恒真 —— 一个月、三轮审查全绿，而包可能根本没有防护能力。

   现在的判据换成护栏模块自己的类名（个人版一行都不出现）：
     OutputGuardrail   ← _check_output.py
     SensitiveLeakDetector ← sensitive_leak.py
     PromptLeakChecker ← _check_prompt_leak.py
   并且**三个都要在**，少一个就说明只编进了一部分。
"""

from __future__ import annotations

import sys
from pathlib import Path

# 候选产物目录。resources/engine 是 build_engine.py 拷入的最终产物，
# 也是 Tauri 真正打进安装包的东西；dist 是兜底。
ROOTS = [
    Path("src-tauri/resources/engine"),
    Path("engine_main.dist"),
]

# ★ 只由护栏层产生的符号（个人版源码里不出现这些标识）。
#   护栏缺失时必然搜不到 —— 这是「防护能力在不在」的判据。
SIGS = [
    b"OutputGuardrail",
    b"SensitiveLeakDetector",
    b"PromptLeakChecker",
]

BIN_SUFFIXES = (".exe", ".bin")


def _list_dir(d: Path) -> None:
    """把目录内容打进日志 —— 断言失败时能直接看出问题在哪。"""
    print(f"  {d} 存在={d.is_dir()}")
    if not d.is_dir():
        return
    for p in sorted(d.iterdir())[:20]:
        if p.is_dir():
            kind = "dir"
        else:
            kind = f"{p.stat().st_size}B"
        print(f"    {p.name} ({kind})")


def main() -> int:
    # ★ 2026-10-29：支持 `--root <dir>`，让测试能用**合成产物**验证
    #   「护栏缺失时必须失败」。没有负样本的门禁不算门禁。
    roots = ROOTS
    if "--root" in sys.argv:
        idx = sys.argv.index("--root")
        try:
            roots = [Path(sys.argv[idx + 1])]
        except IndexError:
            print("::error::--root 后面要跟一个目录")
            return 2

    # ★ 只验公钥：build_engine.py 拷公钥，但「脚本说拷了」不等于
    #   「真的拷了」。缺公钥的包能启动、能自检通过，
    #   唯独每个用户都激活不了 —— 发布后才发现等于白发一个版本。
    if "--pubkey-only" in sys.argv:
        hits = [
            p
            for r in roots
            if r.is_dir()
            for p in r.rglob("license_pub.pem")
        ]
        if not hits:
            print("::error::引擎产物里没有 license_pub.pem —— 所有用户都将无法激活")
            for r in roots:
                _list_dir(r)
            return 1
        print(f"PASS：公钥已落入引擎产物（{hits[0]}）")
        return 0

    bins = [
        p
        for r in roots
        if r.is_dir()
        for p in r.iterdir()
        if p.is_file() and p.suffix in BIN_SUFFIXES
    ]

    if not bins:
        # ★ macOS / Linux 的 sidecar 按 Tauri externalBin 约定**没有扩展名**
        #   （如 `xuandun-engine-aarch64-apple-darwin`）。只认 .exe/.bin 会让
        #   这两个平台在「找不到可执行文件」处直接失败 —— 那是判据写错，
        #   不是产物有问题。这里退化为「根目录里最大的那个文件」。
        candidates = [
            p
            for r in roots
            if r.is_dir()
            for p in r.iterdir()
            if p.is_file() and p.stat().st_size > 1_000_000
        ]
        bins = sorted(
            candidates, key=lambda p: p.stat().st_size, reverse=True
        )[:1]

    if not bins:
        print("::error::在引擎产物目录里找不到可执行文件")
        for r in roots:
            _list_dir(r)
        return 1

    failed = False
    for b in bins:
        data = b.read_bytes()
        size_mb = len(data) / 1024 / 1024
        missing = [s.decode() for s in SIGS if s not in data]
        print(f"检查产物: {b}  ({size_mb:.1f} MB)")

        if missing:
            # ★ 说清后果：这类包能启动、能自检通过、界面照常显示
            #   「防护中」，只有用户被攻击时才发现没有防护。
            print(f"::error::{b.name} 里缺少护栏判据标识：{' '.join(missing)}")
            print("::error::护栏未编入这个包 —— 提示词注入与敏感泄露两类检测")
            print("::error::完全失效，而界面照常显示「防护中」，用户不会察觉。")
            print("::error::发布一个没有防护能力的防火墙，比构建失败坏得多。")
            failed = True
        else:
            print(f"PASS：{b.name} 内含护栏判据，防护能力在位")

    # ★ 全部产物都要过。不因为「另一个过了」就放过这个。
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""桌面端不应弹出 cmd 黑窗 —— 产物级断言。

为什么需要这个测试
────────────────────────────────────────────────────────────────
2026-09-28 用户装好包，双击启动时弹出一个 cmd 黑窗，
里面还不断刷引擎日志。原因是主程序没声明 windows 子系统：
MSVC 链接的 exe 默认是 console 子系统，Windows 就会为它
分配一个控制台。

★ 为什么不能靠肉眼判断：
  `src/main.rs` 里加上 `#![windows_subsystem = "windows"]`
  之后，**编译不会报错、运行也不会崩**，只是「不再弹窗」。
  唯一能确认的办法是读 PE 头里的 Subsystem 字段。
  所以这条必须自动化，否则下次重构时它会悄悄失效。

★ 顺带说明：引擎的 `--windows-console-mode=disable`
  （Nuitka 参数）管的是**引擎 exe**，与本测试管的
  **桌面端壳 exe** 是两件不同的事，两者都要设。
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MAIN_RS = ROOT / "desktop" / "src-tauri" / "src" / "main.rs"

IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3


def _pe_subsystem(exe: Path) -> int:
    """读 PE 头的 Subsystem 字段（2=GUI，3=Console）。"""
    with exe.open("rb") as f:
        head = f.read(1024)
    pe_offset = struct.unpack_from("<I", head, 0x3C)[0]
    return struct.unpack_from("<H", head, pe_offset + 0x5C)[0]


def _strip_rust_comments(src: str) -> str:
    """剥掉 Rust 行注释与块注释，只留代码。

    ★ 判据匹配前必须做这一步。属性名几乎总会出现在解释它的
      注释里，若连注释一起匹配，任何测试都会永远通过 ——
      那种测试比没有测试更糟：它给人虚假的安全感。
    """
    out = []
    i, n = 0, len(src)
    while i < n:
        two = src[i : i + 2]
        if two == "//":
            end = src.find("\n", i)
            i = n if end == -1 else end
        elif two == "/*":
            # 嵌套块注释是合法的，Rust 也允许，要按深度配对
            depth, i = 1, i + 2
            while i < n and depth:
                if src[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif src[i] == '"':
            # 字符串字面量：**原样保留**。
            # 不能把内容抹掉 —— 判据往往就写在字符串里
            # （如 windows_subsystem = "windows"），
            # 抹掉会让本该命中的断言永远落空。
            # 只跳过其中的 // 与 /*，免得被误当成真注释。
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


class TestNoConsoleWindow:
    def test_main_rs_declares_windows_subsystem(self) -> None:
        """源码必须声明 windows 子系统。

        用 release 条件包裹（cfg_attr(not(debug_assertions))）是有意的：
        调试时保留控制台便于看引擎日志，发布时才隐藏。

        ★★ 判据必须**先剥掉注释**再匹配。
           这个属性名在解释它的注释里必然会出现（不写清楚
           下一个维护者就会删掉它）。直接对原文做 `in` 判断，
           会因注释里的那次出现而永远通过 —— 2026-09-28 写这个
           测试时就是这么自我欺骗的：变异测试删掉真属性，
           3 个用例依然全绿。
        """
        src = MAIN_RS.read_text(encoding="utf-8")
        code = _strip_rust_comments(src)
        assert "windows_subsystem" in code, (
            "main.rs 的**代码**里没有 windows_subsystem —— "
            "发布版会弹出 cmd 黑窗（注释里提到它不算）"
        )
        assert (
            'windows_subsystem = "windows"' in code
        ), '必须设为 "windows"（GUI），不是 "console"'

    def test_release_binary_is_gui_subsystem(self) -> None:
        """产物级判据：release exe 的 PE Subsystem 必须是 2。

        源码里写了不代表生效 —— 属性放错位置、拼写错误、
        或被其它 cfg 条件覆盖，编译都不会报错。
        """
        # cargo 的 target 目录可被 CARGO_TARGET_DIR 或 .cargo/config 改道
        target = _cargo_target_dir()
        exe = target / "release" / "xuandun-personal.exe"
        if not exe.is_file():
            pytest.skip(f"尚未构建 release 产物：{exe}")

        sub = _pe_subsystem(exe)
        assert sub != IMAGE_SUBSYSTEM_WINDOWS_CUI, (
            f"{exe.name} 的 PE Subsystem 仍是 {sub}（Console）—— "
            f"双击启动会弹出 cmd 黑窗。期望 {IMAGE_SUBSYSTEM_WINDOWS_GUI}（GUI）。"
        )
        assert sub == IMAGE_SUBSYSTEM_WINDOWS_GUI

    def test_engine_console_mode_is_set(self) -> None:
        """引擎侧也必须关掉控制台（Nuitka 参数）。

        两处都要设：壳不弹窗、引擎自己不弹窗。
        缺任一个，用户仍会看到黑窗。
        """
        build_engine = ROOT / "desktop" / "build_engine.py"
        src = build_engine.read_text(encoding="utf-8")
        assert (
            "--windows-console-mode=disable" in src
        ), "引擎未关闭控制台（--windows-console-mode=disable）"


def _cargo_target_dir() -> Path:
    """问 cargo 要真实的 target 目录，避免猜错路径。"""
    try:
        out = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            cwd=ROOT / "desktop" / "src-tauri",
            capture_output=True,
            text=True,
            timeout=120,
        )
        if out.returncode == 0:
            import json

            meta = json.loads(out.stdout)
            return Path(meta["target_directory"])
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return ROOT / "desktop" / "src-tauri" / "target"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

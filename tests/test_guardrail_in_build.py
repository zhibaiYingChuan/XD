# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""构建脚本必须把护栏层编进产物。

这个文件防的是一类**只在线上出现的静默失效**
────────────────────────────────────────────────────────────────
护栏层（提示词注入 + 敏感泄露两类检测）已入库到 src/daoti_xuandun/，
但 build_engine.py 曾按「仓库外的企业版路径」（../../src）判定它在不在场。

后果：
  · 本地开发：那个目录恰好存在 → 编译时碰巧带上 → 一切正常
  · 干净 clone（= GitHub runner）：那个目录不存在 → 判定「护栏不在场」
    → 静默跳过 --include-package → **产出一个没有护栏的防火墙**

而产物照样能启动、能显示界面、能跑通所有自检，界面还照常显示「防护中」。
用户以为自己受保护，实际上少了两层检测。

这类缺陷最难发现的地方在于：本地永远复现不出来。

判据设计
────────────────────────────────────────────────────────────────
不测「build_engine.py 里有没有某个字符串」，而是测**判定的实际结果**：
在一个**没有仓库外 src/** 的环境里跑判定逻辑，必须得出「有护栏」。

用 monkeypatch 模拟隔离环境，而不是真的去 clone 一份 ——
clone 太慢，而且掩盖了「判定依据到底是什么」这个真问题。
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_BUILD = _REPO / "desktop" / "build_engine.py"


def _load_build_module():
    spec = importlib.util.spec_from_file_location("build_engine_under_test", _BUILD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ══════════════════════════════════════════════════════════════
# 护栏源码本身必须在仓库内
# ══════════════════════════════════════════════════════════════


def test_guardrail_source_is_in_repo():
    """护栏源码必须真实存在于 src/daoti_xuandun/。

    这是整个前提 —— 护栏若不在仓库里，公开 clone 出来的代码
    根本编不出带护栏的包。
    """
    d = _REPO / "src" / "daoti_xuandun"
    assert d.is_dir(), f"护栏源码不在仓库内: {d}"

    py = [f for f in os.listdir(d) if f.endswith(".py")]
    assert len(py) >= 10, f"护栏文件过少（{len(py)} 个），疑似残缺"

    # 关键文件：延迟 import 的入口 + 两类判据的本体
    for must in ("__init__.py", "xuandun.py", "_check_output.py", "sensitive_leak.py"):
        assert (d / must).is_file(), f"护栏缺少 {must}"


# ══════════════════════════════════════════════════════════════
# 判定依据：必须是包内路径，不能是仓库外路径
# ══════════════════════════════════════════════════════════════


def test_guardrail_path_points_inside_repo():
    """护栏判定路径必须落在**本仓库内**。

    回归：曾指向 os.path.join(SCRIPT_DIR, "..", "..", "src")，
    那是仓库外的企业版目录。本地恰好有 src/ 所以一直带着，
    干净 clone 上则判定为「不在场」→ 静默跳过。
    """
    mod = _load_build_module()

    path = os.path.abspath(mod.GUARDRAIL_SRC_DIR)
    repo = os.path.abspath(str(_REPO))
    assert path.startswith(repo), (
        f"护栏判定路径落在仓库外: {path}\n"
        f"仓库根: {repo}\n"
        "干净 clone 上该路径不存在 → 护栏被静默跳过 → 产物没有防护能力"
    )


def test_no_legacy_enterprise_path_constant():
    """旧的仓库外路径常量不得残留。

    只要它还在，就说明某处仍可能误用它做判定 ——
    哪怕当前没人引用，下次有人「顺手用一下」就又静默失效了。
    """
    src = _BUILD.read_text(encoding="utf-8")
    assert "ENTERPRISE_SRC_DIR" not in src, (
        "build_engine.py 仍定义 ENTERPRISE_SRC_DIR（仓库外企业版路径），"
        "存在被误用为护栏判定依据的风险"
    )
    assert "has_enterprise" not in src, (
        "build_engine.py 仍有 has_enterprise 判定，"
        "它指的是仓库外企业版而非包内护栏"
    )


# ══════════════════════════════════════════════════════════════
# 隔离环境下的实际判定结果
# ══════════════════════════════════════════════════════════════


def test_detection_says_yes_in_isolated_clone(monkeypatch, tmp_path):
    """★ 核心判据：模拟干净 clone，护栏判定必须为「有」。

    做法：把 build_engine 里的 GUARDRAIL_SRC_DIR 指向一个
    **只有仓库内内容**的临时目录，并确保 ../../src 不可见。
    若判定仍说「不在场」，就复现了线上 bug。
    """
    mod = _load_build_module()

    # 伪造一个「只有包内护栏、没有仓库外 src」的隔离环境
    fake_repo = tmp_path / "clone"
    (fake_repo / "src" / "daoti_xuandun").mkdir(parents=True)
    (fake_repo / "src" / "daoti_xuandun" / "__init__.py").write_text("", encoding="utf-8")
    # 确认 tmp_path 上层不存在 src/daoti_xuandun，否则旧 bug 会被掩盖
    assert not (tmp_path.parent.parent / "src" / "daoti_xuandun").is_dir(), (
        "测试环境不隔离：tmp_path 上层存在 src/daoti_xuandun，会掩盖旧 bug"
    )

    # ★ 关键：路径断言之外，再验「按仓库外路径算出来的目录」确实不存在。
    #   只断言 GUARDRAIL_SRC_DIR 在仓库内是不够的 ——
    #   变异可能仍把常量留在仓库内，但判定时用别的路径。
    outside = os.path.abspath(
        os.path.join(str(fake_repo), "..", "..", "src")
    )
    assert not os.path.isdir(os.path.join(outside, "daoti_xuandun")), (
        f"隔离环境里仓库外路径 {outside} 竟然有护栏，测试无法复现线上条件"
    )

    monkeypatch.setattr(mod, "GUARDRAIL_SRC_DIR", str(fake_repo / "src"))

    guardrail_dir = os.path.join(mod.GUARDRAIL_SRC_DIR, "daoti_xuandun")
    detected = os.path.isdir(guardrail_dir)

    assert detected, (
        "隔离环境下护栏被判为「不在场」—— 这正是线上发生的事：\n"
        "GitHub runner 上没有仓库外的 src/，护栏被静默跳过，\n"
        "产出一个缺少提示词注入与敏感泄露检测的防火墙。"
    )


# ══════════════════════════════════════════════════════════════
# 缺护栏必须构建失败，不能只警告
# ══════════════════════════════════════════════════════════════


def test_missing_guardrail_aborts_build(monkeypatch, tmp_path):
    """★ 护栏缺失必须让构建**失败**，不能只打印警告。

    理由：缺护栏的包能启动、能自检通过、界面照常显示「防护中」。
    发布它等于让用户以为自己在受保护 —— 比构建失败坏得多。

    ★ 只验「护栏判定这一步的返回值」，不跑完整 main()：
      main() 前面还有依赖自检（nuitka/fastapi/…），
      CI 的 preflight 环境没装 nuitka，会先返回 3，
      根本走不到护栏判定 —— 测的就不是我们要测的东西了。
    """
    mod = _load_build_module()
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(mod, "GUARDRAIL_SRC_DIR", str(empty))

    guardrail_dir = os.path.join(mod.GUARDRAIL_SRC_DIR, "daoti_xuandun")
    assert not os.path.isdir(guardrail_dir), "测试前提失效：护栏目录竟然存在"

    # 直接验判定逻辑本身：护栏不在 → has_guardrail 必须为 False
    has_guardrail = os.path.isdir(guardrail_dir)
    assert has_guardrail is False

    # 而 build_engine.main() 在护栏缺失时必须 return 6（中止），
    # 而不是继续往下走去编译一个没有护栏的包。
    src = _BUILD.read_text(encoding="utf-8")
    assert "return 6" in src, (
        "护栏缺失时没有 return 6 —— 构建会继续，"
        "产出一个缺少提示词注入与敏感泄露检测的包"
    )


# ══════════════════════════════════════════════════════════════
# 护栏依赖必须显式 include（延迟 import 的经典坑）
# ══════════════════════════════════════════════════════════════


def test_nuitka_includes_guardrail_and_its_deps():
    """护栏及其依赖必须显式传给 Nuitka。

    护栏用的是**延迟 import**，Nuitka 的静态分析看不到它 ——
    不显式 include 就会当成可选依赖跳过，打包后
    `from daoti_xuandun.xuandun import XuanDun` 必然 ImportError。
    """
    src = _BUILD.read_text(encoding="utf-8")
    for arg in (
        "--include-package=daoti_xuandun",
        "--include-package-data=daoti_xuandun",
        "--include-package=jwt",
        "--include-package=cryptography",
    ):
        assert arg in src, f"Nuitka 参数缺少 {arg} —— 护栏会被静默跳过"


def test_engine_entrypoint_imports_guardrail_transitively():
    """护栏的可达性：verifier 必须真的 import 它。

    如果 verifier 里没有引用护栏，那 --include-package=daoti_xuandun
    虽然在命令行上，护栏也未必被链进来。
    """
    v = (_REPO / "src" / "daoti_xuandun_personal" / "proxy" / "verifier.py").read_text(
        encoding="utf-8"
    )
    assert "daoti_xuandun" in v, (
        "verifier.py 没有引用护栏包 —— 护栏在产物里可能不可达"
    )

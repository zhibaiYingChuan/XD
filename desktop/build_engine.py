# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

"""个人版引擎编译脚本 —— 把 Python 代理引擎编译为可随包分发的独立可执行文件。

为什么需要这个脚本
------------------
打包后的桌面端运行在**用户机器**上，那里没有 Python、没有 pip、
更没有 ``daoti_xuandun_personal`` 这个包。若 lib.rs 仍按
``python -m daoti_xuandun_personal.proxy.app`` 启动引擎，
装完即废 —— 应用能开、界面能显示，但引擎永远起不来。

方案沿用企业版已验证的做法：Nuitka ``--standalone`` 编译成
自包含目录，整个目录作为 Tauri ``resources`` 随安装包分发。

刻意不做 ``--onefile``
----------------------
onefile 会把引擎打成单文件并在运行时**自解压到临时目录**执行，
这个「释放可执行文件到磁盘再运行」的行为特征会被杀毒软件判定为
dropper。企业版 v1.3.1 就因��被火绒拦截（Trojan/Intercept.a）。
standalone 是一堆 dll + 主 exe，无自解压，干净得多。

用法
----
    cd personal/desktop
    pip install "nuitka==4.1.3" fastapi uvicorn httpx pydantic
    python build_engine.py
"""

import os
import platform
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PERSONAL_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SRC_DIR = os.path.join(PERSONAL_ROOT, "src")
RESOURCE_ENGINE_DIR = os.path.join(SCRIPT_DIR, "src-tauri", "resources", "engine")

# 引擎入口：Nuitka 编译的入口脚本。
# 内容极简 —— 所有逻辑都在 daoti_xuandun_personal 包内，
# 入口只负责调 run()，便于 Nuitka 静态分析出依赖。
ENGINE_MAIN = os.path.join(SCRIPT_DIR, "engine_main.py")


def _triple() -> str:
    """与 lib.rs engine_binary_name() 保持一致的三元组命名。"""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "windows":
        target = f"{machine}-pc-windows-msvc"
        ext = ".exe"
    elif system == "darwin":
        target = "aarch64-apple-darwin" if machine in ("arm64", "aarch64") else "x86_64-apple-darwin"
        ext = ""
    else:
        target = f"{machine}-unknown-linux-gnu"
        ext = ""
    return f"xuandun-engine-{target}{ext}"


def main() -> int:
    if not os.path.isdir(SRC_DIR):
        print(f"FATAL: 未找到个人版源码目录: {SRC_DIR}", file=sys.stderr)
        return 2

    # 依赖自检：给出可执行的修复指引，而不是让 Nuitka 报一堆 import 错误
    missing = []
    for mod, pkg in (("nuitka", "nuitka==4.1.3"), ("fastapi", "fastapi"),
                     ("uvicorn", "uvicorn"), ("httpx", "httpx"),
                     ("pydantic", "pydantic")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("FATAL: 缺少编译依赖，请先安装：", file=sys.stderr)
        print(f"  pip install {' '.join(missing)}", file=sys.stderr)
        return 3

    target = _triple()
    final_engine_name = target
    # Nuitka 输出名：standalone 模式下主程序名 = <入口脚本名>.exe / .bin
    nuitka_main = "engine_main.exe" if platform.system().lower() == "windows" else "engine_main.bin"

    dist_dir = os.path.join(SCRIPT_DIR, "engine_main.dist")

    # 清理旧产物，避免残留上一版 dll 造成诡异的运行时问题
    if os.path.isdir(dist_dir):
        shutil.rmtree(dist_dir)
        print(f"已清理旧产物: {dist_dir}")
    if os.path.isdir(RESOURCE_ENGINE_DIR):
        shutil.rmtree(RESOURCE_ENGINE_DIR)
        print(f"已清空 resources/engine/")

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        # 禁用 ccache 自动下载：Nuitka 默认会从 nuitka.net 拉 ccache，
        # 网络受限环境会 FATAL 失败。ccache 只影响编译速度，不影响产物。
        "--disable-cache=ccache",
        "--remove-output",
        "--assume-yes-for-download",
        f"--output-dir={SCRIPT_DIR}",
        # 个人版自身的包 + 其运行时依赖
        "--include-package=daoti_xuandun_personal",
        "--include-package=fastapi",
        "--include-package=uvicorn",
        "--include-package=httpx",
        "--include-package=pydantic",
        # ★ v0.1.0 修复：pyyaml 是 rules/detection_rules.yaml 的解析器。
        #   此前未包含，Nuitka 会因延迟导入而静默跳过 ——
        #   结果是规则加载失败、静默回退到内置最小集，
        #   拦截能力大幅下降而用户毫无感知。
        "--include-package=yaml",
        # schema.sql 与 rules/*.yaml 必须随包（--include-package-data 覆盖）
        "--include-package-data=daoti_xuandun_personal",
        # 排除开发/测试期依赖，减小体积
        "--nofollow-import-to=tkinter",
        "--nofollow-import-to=test",
        "--nofollow-import-to=unittest",
        "--nofollow-import-to=pytest",
        "--nofollow-import-to=mypy",
        ENGINE_MAIN,
    ]

    if platform.system().lower() == "windows":
        icon = os.path.join(SCRIPT_DIR, "src-tauri", "icons", "icon.ico")
        cmd.extend([
            # 无 console 窗口：引擎是后台服务，不能弹黑框
            "--windows-console-mode=disable",
            f"--windows-icon-from-ico={icon}",
        ])
    elif platform.system().lower() == "darwin":
        cmd.extend(["--macos-app-mode=background"])

    env = os.environ.copy()
    # 让 Nuitka 能解析到个人版包
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")

    print("编译引擎中（首次约需数分钟）...")
    print("命令:", " ".join(cmd))
    result = subprocess.run(
        cmd, env=env, cwd=SCRIPT_DIR,
        stdout=sys.stdout, stderr=sys.stderr,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        print(f"FATAL: Nuitka 编译失败，退出码 {result.returncode}", file=sys.stderr)
        return result.returncode

    if not os.path.isdir(dist_dir):
        print(f"FATAL: 编译成功但未找到产物目录: {dist_dir}", file=sys.stderr)
        return 4

    # 拷入 resources/engine/（Tauri 会把整个目录打进安装包）
    os.makedirs(RESOURCE_ENGINE_DIR, exist_ok=True)
    for item in os.listdir(dist_dir):
        src = os.path.join(dist_dir, item)
        dst = os.path.join(RESOURCE_ENGINE_DIR, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)

    main_src = os.path.join(RESOURCE_ENGINE_DIR, nuitka_main)
    main_dst = os.path.join(RESOURCE_ENGINE_DIR, final_engine_name)
    if not os.path.isfile(main_src):
        print(f"FATAL: 未找到引擎主程序: {main_src}", file=sys.stderr)
        return 5
    if os.path.exists(main_dst):
        os.remove(main_dst)
    os.rename(main_src, main_dst)

    count = len(os.listdir(RESOURCE_ENGINE_DIR))
    size_mb = sum(
        os.path.getsize(os.path.join(RESOURCE_ENGINE_DIR, f))
        for f in os.listdir(RESOURCE_ENGINE_DIR)
        if os.path.isfile(os.path.join(RESOURCE_ENGINE_DIR, f))
    ) / 1024 / 1024
    print(f"引擎编译完成: {final_engine_name}（{count} 个文件，主程序 {size_mb:.1f} MB）")
    print(f"位置: {RESOURCE_ENGINE_DIR}")
    print("下一步: npm run tauri build")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

    # 本地开发调试、暂不激活时，显式跳过公钥检查：
    python build_engine.py --allow-missing-pubkey
"""

import os
import platform
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PERSONAL_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SRC_DIR = os.path.join(PERSONAL_ROOT, "src")
# 企业版核心算法引擎源码目录（护栏层所在）。
#
# ★ 个人版通过 verifier._try_load_guardrail() 复用企业版的
#   「输出护栏」（提示词注入 + 敏感泄露两层检测）。
#   该复用是**延迟 import**：编译期若不显式 include，
#   Nuitka 会认为它是可选依赖而跳过 → 打包后
#   `from daoti_xuandun.xuandun import XuanDun` 必然 ImportError
#   → _guardrail_available 恒为 False → 两层检测静默失效。
#
#   而个人版没有把这个失效暴露给用户（界面照常显示「防护中」），
#   所以这个缺失是纯静默的 —— 与此前 pyyaml 漏 include
#   导致规则静默回退是同一类错误。
ENTERPRISE_SRC_DIR = os.path.abspath(
    os.path.join(SCRIPT_DIR, "..", "..", "src")
)
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
    # ★ 显式开关，不做「有则拷、无则静默跳过」。
    #   缺公钥的包能启动、能自检通过，唯独所有用户都激活不了 ——
    #   那是发布后才发现的灾难，必须在构建期就拦下。
    _allow_missing_pubkey = "--allow-missing-pubkey" in sys.argv

    if not os.path.isdir(SRC_DIR):
        print(f"FATAL: 未找到个人版源码目录: {SRC_DIR}", file=sys.stderr)
        return 2

    # 依赖自检：给出可执行的修复指引，而不是让 Nuitka 报一堆 import 错误
    missing = []
    for mod, pkg in (("nuitka", "nuitka==4.1.3"), ("fastapi", "fastapi"),
                     ("uvicorn", "uvicorn"), ("httpx", "httpx"),
                     ("pydantic", "pydantic"), ("yaml", "pyyaml"),
                     ("jwt", "pyjwt"), ("cryptography", "cryptography")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("FATAL: 缺少编译依赖，请先安装：", file=sys.stderr)
        print(f"  pip install {' '.join(missing)}", file=sys.stderr)
        return 3

    # 企业版护栏是否可编入。
    #
    # ★ 这里**不强制**：企业版源码不在（独立仓库 / 私有仓库场景）
    #   时个人版仍应能编译，只是护栏层缺失 —— 且该缺失会由
    #   check_degradation.py 与 /api/diagnostics 如实报告，不静默。
    #   宁可少两层检测且如实告知，也不要让构建直接失败。
    has_enterprise = os.path.isdir(
        os.path.join(ENTERPRISE_SRC_DIR, "daoti_xuandun")
    )
    if has_enterprise:
        print("检测到企业版源码 → 护栏层将编入（提示词注入 + 敏感泄露）")
    else:
        print(
            "警告: 未检测到企业版源码 → 本次构建**不含护栏层**，\n"
            f"      提示词注入与敏感泄露两类检测将失效。\n"
            f"      查找路径: {ENTERPRISE_SRC_DIR}",
            file=sys.stderr,
        )

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

    if has_enterprise:
        # ★ 护栏层：企业版核心算法引擎。
        #   不加这两个参数，打包后的个人版就只有「自研检测层」，
        #   prompt_inject 与 sensitive_leak 两类判据完全失效，
        #   而界面照常显示「防护中」—— 用户无从察觉。
        cmd.extend([
            "--include-package=daoti_xuandun",
            "--include-package-data=daoti_xuandun",
            # 护栏的验签与编译期密钥注入需要
            "--include-package=jwt",
            "--include-package=cryptography",
        ])

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
    # 让 Nuitka 能解析到个人版包；企业版源码在场时一并加入，
    # 否则 --include-package=daoti_xuandun 找不到包而编译失败。
    search_path = SRC_DIR
    if has_enterprise:
        search_path = ENTERPRISE_SRC_DIR + os.pathsep + search_path
    env["PYTHONPATH"] = search_path + os.pathsep + env.get("PYTHONPATH", "")

    # ★ 激活码公钥：打进包内，运行期无需外部文件。
    #
    #   放在 resources/engine/ 下（与引擎同级），
    #   引擎按 license.py::load_public_key 的顺序查找：
    #     ① 环境变量 XUANDUN_LICENSE_PUBKEY（CI 可用 secret 覆盖）
    #     ② XUANDUN_LICENSE_PUBKEY_FILE 指定的文件
    #     ③ <引擎目录>/license_pub.pem ← 本拷贝的落点
    #
    #   刻意**不设**第 ① 项：环境变量会进构建日志，
    #   而公钥虽非秘密，也不必在日志里留痕。
    #
    #   ⚠ 缺公钥的后果必须让用户看得见：所有激活码都会判为
    #     「验签组件不可用」而非「码无效」（见 license.py）。
    pub_src = os.path.join(
        PERSONAL_ROOT, "tools", "activation", "xuanDun_personal_public.pem"
    )
    if os.path.isfile(pub_src):
        print(f"激活公钥: {pub_src}")
    else:
        print(
            "警告: 未找到激活公钥，本次构建的客户端**无法激活**。\n"
            f"      生成方式: python tools/activation/gen_activation_keys.py genkeypair",
            file=sys.stderr,
        )

    print("编译引擎中（首次约需数分钟）...")
    print("护栏层:", "已编入" if has_enterprise else "★未编入（检测能力降级）")
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

    # 激活公钥拷入引擎目录（与主程序同级）
    #
    # ★ 放在这里而不是 build 之前：拷贝源若在 tools/activation/，
    #   那里可能被 .gitignore 排除，也可能在干净 CI 上不存在。
    #   拷进产物目录后它随 resources/ 一起进安装包。
    #
    # ★★ 缺公钥必须让构建**失败**，不能只警告。
    #   缺公钥的包能正常启动、能显示界面、能跑通所有自检 ——
    #   唯独每一个用户都激活不了。发布后才发现，等于白发一个版本。
    #   这正是「静默降级」最典型的形态：构建成功，产品完全不可用。
    if os.path.isfile(pub_src):
        shutil.copy2(
            pub_src,
            os.path.join(RESOURCE_ENGINE_DIR, "license_pub.pem"),
        )
    else:
        print()
        print("[FATAL] 找不到激活码公钥，构建中止。", file=sys.stderr)
        print(f"  期望路径: {pub_src}", file=sys.stderr)
        print("  生成方法: python tools/activation/gen_activation_keys.py genkeypair",
              file=sys.stderr)
        print("  没有公钥的包可以启动、可以自检通过，但**所有用户都激活不了**。",
              file=sys.stderr)
        print("  如仅做本地开发调试，可显式跳过：", file=sys.stderr)
        print("    python build_engine.py --allow-missing-pubkey", file=sys.stderr)
        if not _allow_missing_pubkey:
            return 4

    # ══════════════════════════════════════════════════════════
    # 反编译加固：生成构建期密钥
    # ══════════════════════════════════════════════════════════
    #
    #   护栏层原本带两个明文 fallback 密钥：
    #     shell_key  = b"daoti_xuandun_16"
    #     mapping_key = b"ancient_map_16b!"
    #   反编译者一眼就能拿到，动态壳与符号映射的初始化种子失去意义。
    #
    #   这里每次构建生成**随机**密钥写入引擎目录，运行时由
    #   proxy/app.py::_inject_build_secrets 读入。
    #   效果：源码与二进制里都没有固定密钥，且每个版本不同。
    #
    #   ★ 诚实说明：这**不是**绝对防线。密钥仍随包分发，
    #     有能力逆向的人仍可读出后重打包。它抬高的是门槛，
    #     真正的防线在「校验点分散」——改一处校验不生效。
    #     不要把它当成「密钥已保密」。
    import json as _json
    import secrets as _secrets

    _build_secrets = {
        # 32 字节随机，与原 fallback 长度相当（AEAD 类用途需 ≥16 字节）
        "shell_key": _secrets.token_urlsafe(32),
        "mapping_key": _secrets.token_urlsafe(32),
    }
    _secrets_path = os.path.join(RESOURCE_ENGINE_DIR, "build_secrets.json")
    with open(_secrets_path, "w", encoding="utf-8") as _f:
        _json.dump(_build_secrets, _f, ensure_ascii=False, indent=2)

    # 构建产物不得入库（其中的密钥每次都不同，入库等于公开）
    _gitignore = os.path.join(PERSONAL_ROOT, ".gitignore")
    try:
        with open(_gitignore, "r", encoding="utf-8") as _f:
            _gi = _f.read()
        if "build_secrets.json" not in _gi:
            with open(_gitignore, "a", encoding="utf-8") as _f:
                _f.write(
                    "\n# 构建期生成的护栏密钥（每次构建都不同，入库等于公开）\n"
                    "build_secrets.json\n"
                )
            print("已更新 .gitignore：忽略 build_secrets.json")
    except OSError:
        pass

    print("已生成构建期密钥（反编译加固）：build_secrets.json")

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

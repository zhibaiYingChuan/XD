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

import json
import os
import platform
import shutil
import subprocess
import sys
import time

# ★★ Windows 终端默认 GBK 编码，遇到「→」「★」这类字符会抛
#   UnicodeEncodeError 直接把构建打断。GitHub 的 windows-latest
#   runner 就是 GBK，本脚本里的中文提示 + 符号会稳定触发。
#
#   必须在任何输出**之前**设好，且要重配 stdout/stderr ——
#   光设环境变量对已初始化的 TextIOWrapper 无效。
#
#   记忆库同类教训：「Windows GBK 终端打印 ✓✗ 会 UnicodeEncodeError，
#   验证需 PYTHONIOENCODING=utf-8」（企业版 CSCD 踩过）。
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for _s in ("stdout", "stderr"):
        _stream = getattr(sys, _s, None)
        if _stream is not None and hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PERSONAL_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SRC_DIR = os.path.join(PERSONAL_ROOT, "src")
# 护栏层（输出护栏 + 敏感泄露）源码目录。
#
# ★★ 这里指向**本仓库内**的 src/，不是仓库外的企业版路径。
#
#   护栏已入库（src/daoti_xuandun/），它是个人版防护能力的组成部分，
#   不是可选依赖。此前这里指向 ../../src（仓库外的企业版），
#   导致干净 clone 上判定为「护栏不在场」→ 编译时跳过 --include-package
#   → 产物缺提示词注入与敏感泄露两层检测，而界面照常显示「防护中」。
#   本地因为恰好有 ../src 而碰巧带上，线上却是残废的 ——
#   典型的「本地能跑、线上失效」静默降级。
#
#   护栏的 import 是**延迟 import**：编译期若不显式 include，
#   Nuitka 会认为它是可选依赖而跳过 → 打包后
#   `from daoti_xuandun.xuandun import XuanDun` 必然 ImportError
#   → _guardrail_available 恒为 False。
GUARDRAIL_SRC_DIR = SRC_DIR


def has_guardrail_source() -> bool:
    """护栏层源码是否在场（在场才能编进去）。

    ★ 2026-10-29（第三轮审查 P0-2）：把原来的内联判定抽成函数。
      内联时测试只能「先建个目录、再断言这个目录存在」—— 那是
      断言自己的夹具，恒真；护栏真丢了也测不出来。
      抽出来后正反两面都能测：空目录必须 False，真实仓库必须 True。
    """
    return os.path.isdir(os.path.join(GUARDRAIL_SRC_DIR, "daoti_xuandun"))


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


def _git(*args: str) -> str:
    """取仓库事实（失败返回 "unknown"，不抛异常）。

    ★ 构建指纹必须**绝不阻断构建**：拿不到 commit 信息只是指纹残缺，
    而 CI 会因为 sha 不等于本次提交而拦下发布 —— 那才是该报错的地方。
    本地在非 git 目录里构建时不该因此失败。
    """
    try:
        out = subprocess.run(
            ["git", *args], cwd=PERSONAL_ROOT,
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if out.returncode == 0:
            return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def _pe_version_from_cargo() -> str:
    """从 ``src-tauri/Cargo.toml`` 读版本并转成 PE 的四段数字版本。

    ★ 为什么不在本文件里再写一个版本号：
      项目约定「版本只有 Cargo.toml 一个真源」（sync_version.py 会校验
      全项目一致）。构建脚本里另存一份，迟早与发布版本漂移，
      而 PE 版本资源的漂移**不会报错** —— 用户看到的属性页和
      实际版本对不上，售后排查时全靠猜。

    ★ 为什么必须转数字：
      Windows 的 VS_VERSIONINFO 四个字段都是 16 位整数，
      而仓库里的版本形如 ``0.1.21-alpha``：带连字符会被 Nuitka 拒绝，
      或被静默截断。这里只取数字段，不足补 0，多出的部分丢掉。
      语义版本里的 alpha/beta 标记由 Tauri 侧的字符串版本承载。
    """
    import re

    cargo = os.path.join(SCRIPT_DIR, "src-tauri", "Cargo.toml")
    raw = "0.0.0"
    try:
        with open(cargo, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
                if m:
                    raw = m.group(1)
                    break
    except OSError:
        pass
    nums = re.findall(r"\d+", raw)[:4]
    while len(nums) < 4:
        nums.append("0")
    # 每段夹到 0..65535，避免畸形版本号让 Nuitka 直接失败
    return ".".join(str(min(int(n), 65535)) for n in nums)


def _pyinstaller_version_file(path: str) -> str:
    """生成 PyInstaller 的 Windows 版本资源文件，返回路径。

    ★ 与 Nuitka 的 --company-name 等参数是同一件事：给 exe 补上
      发布者 / 产品名 / 版本。杀软的启发式里，「三无可执行文件」
      本身就接近释放器画像，而我们的引擎恰好是常驻后台、
      监听端口、读取全部 API 流量的进程。
    ★ 版本号同样从 Cargo.toml 读（唯一真源），不在这里另写一份。
    """
    ver = _pe_version_from_cargo()  # "0.1.28.0"
    nums = [int(x) for x in ver.split(".")][:4]
    while len(nums) < 4:
        nums.append(0)
    tuple4 = f"({nums[0]}, {nums[1]}, {nums[2]}, {nums[3]})"
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={tuple4}, prodvers={tuple4},
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'DaoTi Research'),
      StringStruct('FileDescription', 'XuanDun Personal Protection Engine'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'xuandun-engine'),
      StringStruct('LegalCopyright', 'Copyright (c) 2026 DaoTi Research'),
      StringStruct('OriginalFilename', 'xuandun-engine.exe'),
      StringStruct('ProductName', 'XuanDun Personal'),
      StringStruct('ProductVersion', '{ver}'),
      StringStruct('Trademarks', 'XuanDun')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _builder_name() -> str:
    """本次使用哪个打包器。默认 pyinstaller，可用 --builder=nuitka 回退。

    ★ 为什么换掉 Nuitka（2026-10-30）：
      Nuitka 要把每个 Python 模块编译成 C 再编译成机器码，
      Linux 上一次要 13~14 分钟。而 GitHub 免费的 ubuntu-22.04
      runner 在这个时长里被回收的概率极高 —— v0.1.28 连续 6 轮
      死在 9.8~14.4 分钟，日志统一是
      `The runner has received a shutdown signal`，与代码无关。

      PyInstaller 不做 C 编译，只做打包与字节码归档，同规模项目
      通常 1~2 分钟；产物同样是 onedir 结构（一堆文件 + 主程序），
      不是自解压单文件，因此**没有** dropper 特征
      （企业版当年被火绒拦截的是 --onefile，不是 onedir）。

    ★ 保留 Nuitka 回退的理由：打包器切换是发布链上的高风险动作，
      一旦 PyInstaller 在某些平台出现兼容问题，需要能一条参数切回去，
      而不是回滚整条流水线。
    """
    for arg in sys.argv:
        if arg.startswith("--builder="):
            value = arg.split("=", 1)[1].strip().lower()
            if value in ("pyinstaller", "nuitka"):
                return value
            print(f"FATAL: 未知打包器 {value!r}（可选 pyinstaller / nuitka）",
                  file=sys.stderr)
            raise SystemExit(2)
    return "pyinstaller"


def _pyinstaller_cmd(version_file: str) -> list:
    """构造 PyInstaller 命令。

    ★ 收集策略说明（每一条都对应一种「产物能启动但功能缺失」）：
      --collect-submodules  延迟 import 的护栏层（daoti_xuandun）不在
                            入口的静态依赖里，不显式收集就会整个缺失；
      --collect-data        rules/*.yaml 与 schema.sql 不在代码里，
                            只在包数据里 —— 缺了会静默回退到内置最小规则集，
                            拦截能力大幅下降而界面照常显示「防护中」。
    """
    work = os.path.join(SCRIPT_DIR, "build", "pyinstaller")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onedir",
        "--name", "engine_main",
        f"--distpath={SCRIPT_DIR}",
        f"--workpath={work}",
        f"--specpath={work}",
        f"--paths={SRC_DIR}",
        "--collect-submodules=daoti_xuandun_personal",
        "--collect-data=daoti_xuandun_personal",
        "--collect-submodules=daoti_xuandun",
        "--collect-data=daoti_xuandun",
        # ★★ 2026-10-30 本地实测：不加这一条，产物能启动、/health 也返回 ok，
        #   但护栏加载时报
        #     No module named 'numpy._core._exceptions'
        #   于是 guardrail_missing_layers = ["system_prompt_inject","sensitive_leak"]
        #   —— 提示词注入与敏感泄露两层检测全部缺失，而界面照常显示「防护中」。
        #   numpy 2.x 把实现搬进了 numpy._core，PyInstaller 的静态分析只看到
        #   numpy 顶层包，子模块必须显式收集。
        "--collect-submodules=numpy._core",
        # 延迟 import 的第三方件，静态分析同样看不见
        "--hidden-import=yaml",
        "--hidden-import=jwt",
        "--hidden-import=cryptography",
        # 开发期依赖不进产物
        "--exclude-module=tkinter",
        "--exclude-module=pytest",
        "--exclude-module=mypy",
        "--exclude-module=unittest",
        "--exclude-module=test",
        # ★★ 2026-10-30 CI 实测：产物在 Linux 上启动即崩，堆栈是
        #     ModuleNotFoundError: No module named 'backports'
        #     [PYI-3465:ERROR] Failed to execute script 'pyi_rth_pkgres'
        #   即 PyInstaller 为 pkg_resources 注入的运行时钩子先于我们的代码
        #   执行，而它在 Python 3.11 + 新版 setuptools 下依赖 backports
        #   （本地是 3.12，不受影响 —— 典型的「本机能跑、CI 挂」）。
        #
        #   本项目的运行时链路（fastapi / uvicorn / httpx / pydantic / yaml /
        #   jwt / cryptography / numpy）都不使用 pkg_resources 的入口点机制，
        #   因此直接排除它，让那个钩子不启用 —— 比补一个空 backports 干净。
        #   ★ 若将来引入依赖 pkg_resources 的库，这里会立刻在运行时验证
        #     （verify_engine_runtime.py）里失败，不会静默降级。
        "--exclude-module=pkg_resources",
    ]
    if platform.system().lower() == "windows":
        icon = os.path.join(SCRIPT_DIR, "src-tauri", "icons", "icon.ico")
        # 无 console 窗口：引擎是后台服务，不能弹黑框
        cmd.extend(["--noconsole", f"--icon={icon}", f"--version-file={version_file}"])
    ENGINE_MAIN_ABS = ENGINE_MAIN
    cmd.append(ENGINE_MAIN_ABS)
    return cmd


def main() -> int:
    # ★ 显式开关，不做「有则拷、无则静默跳过」。
    #   缺公钥的包能启动、能自检通过，唯独所有用户都激活不了 ——
    #   那是发布后才发现的灾难，必须在构建期就拦下。
    _allow_missing_pubkey = "--allow-missing-pubkey" in sys.argv

    if not os.path.isdir(SRC_DIR):
        print(f"FATAL: 未找到个人版源码目录: {SRC_DIR}", file=sys.stderr)
        return 2

    builder = _builder_name()
    print(f"打包器: {builder}")

    # 依赖自检：给出可执行的修复指引，而不是让打包器报一堆 import 错误
    missing = []
    tool = (
        ("PyInstaller", "pyinstaller==6.11.1") if builder == "pyinstaller"
        else ("nuitka", "nuitka==4.1.3")
    )
    for mod, pkg in (tool, ("fastapi", "fastapi"),
                     ("uvicorn", "uvicorn"), ("httpx", "httpx"),
                     ("pydantic", "pydantic"), ("yaml", "pyyaml"),
                     ("jwt", "pyjwt"), ("cryptography", "cryptography"),
                     ("numpy", "numpy")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("FATAL: 缺少编译依赖，请先安装：", file=sys.stderr)
        print(f"  pip install {' '.join(missing)}", file=sys.stderr)
        return 3

    # 护栏层是否可编入。
    #
    # ★★ 缺失必须让构建**失败**，不能只警告。
    #
    #   护栏已在仓库内（src/daoti_xuandun/），它是个人版防护能力的
    #   组成部分，不是可选依赖。缺了它，产物照样能启动、能显示界面、
    #   能跑通所有自检 —— 唯独提示词注入与敏感泄露两类检测静默失效，
    #   而用户界面照常显示「防护中」。
    #
    #   发布一个没有防护能力的防火墙，比构建失败坏得多：
    #   前者让用户以为自己在受保护。
    #
    #   此处曾按「仓库外企业版路径」判定，本地恰好有那个目录所以
    #   一直带上了，干净 clone 上却静默跳过 —— 已修正为包内路径。
    guardrail_dir = os.path.join(GUARDRAIL_SRC_DIR, "daoti_xuandun")
    has_guardrail = has_guardrail_source()
    if has_guardrail:
        print("护栏层已就位 → 将编入（提示词注入 + 敏感泄露）")
    else:
        print(file=sys.stderr)
        print("[FATAL] 找不到护栏层源码，构建中止。", file=sys.stderr)
        print(f"  期望路径: {guardrail_dir}", file=sys.stderr)
        print("  没有护栏层的包能启动、能自检通过，但**提示词注入与", file=sys.stderr)
        print("  敏感泄露两类检测完全失效**，而界面照常显示「防护中」。", file=sys.stderr)
        print("  这不是可降级的依赖 —— 缺了它就不该称为防火墙。", file=sys.stderr)
        return 6

    target = _triple()
    final_engine_name = target
    is_windows = platform.system().lower() == "windows"

    # 两种打包器的产物目录不同，但**输出契约一致**：
    # resources/engine/ 下一堆文件 + 一个已改名的主程序。
    if builder == "pyinstaller":
        dist_dir = os.path.join(SCRIPT_DIR, "engine_main")
        main_bin = "engine_main.exe" if is_windows else "engine_main"
    else:
        dist_dir = os.path.join(SCRIPT_DIR, "engine_main.dist")
        main_bin = "engine_main.exe" if is_windows else "engine_main.bin"

    # 清理旧产物，避免残留上一版 dll 造成诡异的运行时问题
    for _d in (dist_dir, RESOURCE_ENGINE_DIR):
        if os.path.isdir(_d):
            shutil.rmtree(_d)
            print(f"已清理旧产物: {_d}")

    # ★★ 2026-10-30：ccache 只在 Linux 且系统里显式装了时才用。
    #
    #   背景：Linux 上 Nuitka 的 C 编译约占整个 job 的 10.6 分钟，
    #   是构建里最长的一段。job 越长，GitHub 免费 runner 中途被回收的
    #   概率越高 —— Linux AppImage 已连续 4 轮被砍，与代码正确性无关。
    #
    #   ★★ 为什么不是「加一个 --use-ccache」：Nuitka 没有这个选项。
    #     实测 4.1.3 直接 `error: no such option: --use-ccache`，
    #     win-x64 与 linux-appimage 双双在 1 分钟内失败。
    #     Nuitka 的语义是**默认允许** ccache，只有 `--disable-cache=ccache`
    #     才关闭 —— 所以「启用」就是**不传这个参数**。
    #
    #   ★ 为什么限定 Linux：Windows runner 上 Strawberry Perl 自带一个
    #     `C:\Strawberry\c\bin\ccache.EXE`，`which` 会命中它；而 Nuitka 在
    #     Windows 上走 MSVC，ccache 对 MSVC 并无可靠收益，反而多一层不确定。
    #
    #   ★ 安全边界没变：仍然**不允许 Nuitka 自己下载** ccache
    #     （那会让构建期静默抓取第三方可执行文件，见下方 P1-26 注释）。
    #     CI 里由 apt 显式安装、并把 ~/.cache/ccache 缓存起来；
    #     本地没装就退回全量编译，行为与以前完全一致。
    ccache_bin = (
        shutil.which("ccache") if sys.platform.startswith("linux") else None
    )
    if ccache_bin:
        print(f"检测到 ccache，交给 Nuitka 默认启用: {ccache_bin}")
    else:
        print("未启用 ccache，本次为全量 C 编译")

    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        # 有 ccache 就不传（Nuitka 默认启用）；否则显式禁用，
        # 顺带阻止它从 nuitka.net 自行下载 —— 网络受限环境会 FATAL。
        *([] if ccache_bin else ["--disable-cache=ccache"]),
        "--remove-output",
        # ★ P1-26：不再"自动确认下载"（此前显式传过那个参数）。
        #   它让 Nuitka 在构建期**静默**从第三方拉取工具（ccache /
        #   dependencywalker 等）：出网抓可执行文件发生在 CI 的可信构建
        #   链路里，却既不在依赖清单中、也不在审计日志里。
        #   去掉之后，构建期任何"需要下载"的动作都会直接失败 ——
        #   失败可查，静默抓取不可查。需要的工具应在构建前显式安装。
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

    if has_guardrail:
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
        # ★★ 2026-10-27：补齐 PE 版本资源。
        #
        #   为什么这件事优先级很高：
        #     引擎是一个**常驻后台、监听端口、读取全部 API 流量**的 exe。
        #     杀软的启发式评分里，「无厂商信息、无版本、无版权」的三无
        #     可执行文件本身就是高危特征 —— 它和释放器/加载器的画像一致。
        #     补上公司在先、产品名在后，能让静态判据从「行为可疑」
        #     变成「有明确发布者的商业组件」。
        #
        #   版本号统一从 Cargo.toml 读取（项目约定：版本只有这一个真源），
        #   不在这里另写一份，避免两处漂移。
        #
        #   ★ 选项名不带 `windows-` 前缀：Nuitka 把它们归为
        #     跨平台元数据（Windows / macOS 共用），写成
        #     `--windows-company-name` 会直接报 unknown option。
        pe_version = _pe_version_from_cargo()
        cmd.extend([
            "--company-name=DaoTi Research",
            "--product-name=XuanDun Personal",
            "--file-description=XuanDun Personal Protection Engine",
            "--copyright=Copyright (c) 2026 DaoTi Research",
            "--trademarks=XuanDun",
            f"--file-version={pe_version}",
            f"--product-version={pe_version}",
        ])
    elif platform.system().lower() == "darwin":
        cmd.extend(["--macos-app-mode=background"])

    env = os.environ.copy()
    # 让 Nuitka 能解析到包内模块。护栏（daoti_xuandun）与个人版
    # 都在 SRC_DIR 下，同一个路径即可。
    search_path = SRC_DIR
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
    # ★ 公钥随包分发（放在包内而非 tools/ 下）：
    #   tools/ 是签发方内部工具，不进公开仓库 —— 而公钥是客户端
    #   验签必需的公开材料，必须留在会分发的代码里。
    pub_src = os.path.join(
        PERSONAL_ROOT, "src", "daoti_xuandun_personal", "license_pub.pem"
    )
    if os.path.isfile(pub_src):
        print(f"激活公钥: {pub_src}")
    else:
        print(
            "警告: 未找到激活公钥，本次构建的客户端**无法激活**。\n"
            f"      生成方式: python tools/activation/gen_activation_keys.py genkeypair",
            file=sys.stderr,
        )

    # ★ PyInstaller 分支：上面那段 cmd 是为 Nuitka 构造的，这里整体替换。
    #   保留 Nuitka 的构造代码不动，是为了 `--builder=nuitka` 能原样回退。
    if builder == "pyinstaller":
        build_dir = os.path.join(SCRIPT_DIR, "build")
        os.makedirs(build_dir, exist_ok=True)
        vf = ""
        if is_windows:
            vf = _pyinstaller_version_file(
                os.path.join(build_dir, "version_info.txt")
            )
        cmd = _pyinstaller_cmd(vf)

    print("打包引擎中...")
    print("护栏层:", "已编入" if has_guardrail else "★未编入（检测能力降级）")
    print("命令:", " ".join(cmd))
    result = subprocess.run(
        cmd, env=env, cwd=SCRIPT_DIR,
        stdout=sys.stdout, stderr=sys.stderr,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        print(f"FATAL: {builder} 打包失败，退出码 {result.returncode}", file=sys.stderr)
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

    main_src = os.path.join(RESOURCE_ENGINE_DIR, main_bin)
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

    # ══════════════════════════════════════════════════════════
    # Linux AppImage：把 numpy.libs 里的 .so 平铺到引擎目录根部
    # ══════════════════════════════════════════════════════════
    #
    # ★ 2026-09-29 结论：**这一步不足以让 AppImage 通过**，且它
    #   对 AppImage 其实**不起作用** —— 保留它只是因为无法确定
    #   运行时是否依赖这个根目录副本（Nuitka 若未给 numpy/_core/*.so
    #   打上指向根目录的 rpath，它就是运行时的唯一来源）。
    #   **在没有证据前不动它**：删错了会直接弄坏 Linux 上的 numpy。
    #
    #   ★ 曾被记成「引用方就是 libscipy_openblas64_*.so 本身，
    #     属 linuxdeploy 对 numpy 的固有缺陷，产物结构绕不过去」
    #     —— 这是**误判**。2026-09-29 读 v0.1.0-alpha11 的
    #     --verbose 日志，最后两行是：
    #       Deploying dependencies for ELF file .../engine/numpy/_core/_multiarray_umath.so
    #       ERROR: Could not find dependency: libscipy_openblas64_-32a4b2a6.so
    #     即**引用方是 numpy/_core/_multiarray_umath.so**，不是它自己。
    #
    #   真实机制：linuxdeploy 解析 DT_NEEDED 时只在两类位置找
    #     ① 引用方自己所在的目录 ② 系统库路径（ldconfig 列表）。
    #   ①能在同一份日志里验证：引擎根部的 libscipy_openblas64_*.so
    #   需要 libgfortran-*.so.5.0.0，linuxdeploy 就在同一目录找到了。
    #   平铺把 OpenBLAS 放到了**引擎根部**，而引用方在 numpy/_core/
    #   —— 目录不同，①覆盖不到 ⇒ 平铺对 AppImage 无效果。
    #
    #   ⇒ 真正的解法在 CI 侧：release.yml 的
    #     "Register numpy OpenBLAS for linuxdeploy" 步骤把该库注册进
    #     系统库路径，走②让 linuxdeploy 正常解析。
    #     （Linux 主力的 deb 格式本来就不调 linuxdeploy、不扫依赖。）
    #
    #   护栏 9 个模块都 import numpy 是这件事的源头
    #   （Nuitka 因此把 numpy 打进产物）。而 numpy 自带的 OpenBLAS
    #   文件名是 libscipy_openblas64_-<hash>.so —— 名字里的 scipy
    #   是 OpenBLAS 的历史命名（当年由 SciPy 项目维护），
    #   **本项目并未安装 scipy**。
    #
    #   ⚠ 排查提醒：linuxdeploy 的三类失败（FUSE 挂载、strip、
    #     依赖缺失）报出来**全都是**同一句
    #     "failed to run linuxdeploy"，只能靠 --verbose 看最后几行。
    if platform.system().lower() == "linux":
        _libs_dir = os.path.join(RESOURCE_ENGINE_DIR, "numpy.libs")
        if os.path.isdir(_libs_dir):
            _n = 0
            for _f in os.listdir(_libs_dir):
                if not _f.endswith(".so"):
                    continue
                _src = os.path.join(_libs_dir, _f)
                _dst = os.path.join(RESOURCE_ENGINE_DIR, _f)
                if not os.path.isfile(_dst):
                    shutil.copy2(_src, _dst)
                    _n += 1
            if _n:
                print(f"AppImage 兼容：已平铺 {_n} 个 numpy .so 到引擎目录根部")
                print("  注意：这不足以让 AppImage 通过（见上方说明），"
                      "Linux 主力交付格式是 deb。")

    # ══════════════════════════════════════════════════════════
    # 构建指纹：把「这次编译用的是哪个 commit」落成**数据**
    # ══════════════════════════════════════════════════════════
    #
    # ★ 为什么必须换掉「在二进制里 grep 关键字」的做法（2026-10-07）
    #   发布门禁原先是 grep 一串标记字符串，用来防「改完源码没重新
    #   编译」。它在 mac-arm64 上**连续两次误报**，且每次标记都不同：
    #     ① 模块级函数名 `_derive_session_id` 被 Nuitka 内联优化，
    #        名字不再作为字符串存在于二进制；
    #     ② 改用字面量后，短前缀 `sess-` 又被常量折叠/合并吃掉 ——
    #        而同一次构建里 `.corrupt-`、`配置文件解析失败`、
    #        `dangerous_content` **都在位**，即代码确实已编入，
    #        门禁却报「编译的是旧源码」，白跑 30 分钟。
    #
    #   根因不是标记选得不好，而是**判据选错了**：关键字在不在完全由
    #   编译器优化策略支配，随平台与 Nuitka 版本漂移。拿它当门禁，
    #   只能一次次换标记，是打地鼠。
    #
    # ★ 指纹比「关键字存在」更强，且与编译器行为彻底解耦：
    #   它直接回答「产物对应哪个 commit」，而非「大概像新代码」。
    #   没重新编译时，这里留着的是上一次的 SHA → CI 比对必然不一致
    #   → 恰好拦下它本来要拦的那件事，且不会因优化差异误报。
    info = {
        "git_sha": _git("rev-parse", "HEAD"),
        "git_ref": _git("describe", "--tags", "--always", "--dirty"),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "engine": final_engine_name,
        "has_guardrail": bool(has_guardrail),
        "python": platform.python_version(),
        "platform": platform.system(),
    }
    with open(os.path.join(RESOURCE_ENGINE_DIR, "BUILD_INFO.json"), "w",
              encoding="utf-8") as _f:
        json.dump(info, _f, ensure_ascii=False, indent=2)
    print(f"构建指纹: git_sha={info['git_sha'][:12]} ref={info['git_ref']}")

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

# 道体·玄盾 收尾执行计划（Sprint 14.2/14.3 + 15 + 16）

> **版本**：V3（基于 2026-07-09 全局审计验证 + V2 计划继承）
> **状态**：待用户批准后执行
> **前置**：Sprint 13（桌面端严重问题修复）+ Sprint 14.1（Nuitka 跨平台）+ Sprint 14.3 部分（build_engine.py / secure_strings.py）已完成
> **预估总工时**：~22h

---

## 一、全局审计结论（2026-07-09 验证）

### 1.1 Sprint 13 已完成验证（grep 实证）

| 编号 | 修复项 | 验证证据 | 状态 |
|------|--------|---------|------|
| 13.1 | 引擎进程泄漏 | lib.rs 已用 `.build()` + `app.run(callback)`，`RunEvent::ExitRequested/Exit` 调 `stop_engine` | ✅ |
| 13.2 | CORS + /debug/state 鉴权 | engine_flask.py:65-81 已有 `_DEBUG_TOKEN`/`_ALLOWED_ORIGINS`/`_attach_cors`；:132-135 已有 token 校验 | ✅ |
| 13.3 | UTF-8 安全切片 | engine.rs:8 `safe_preview` + 4 个测试（ascii/cjk/emoji/multibyte_boundary）；commands.rs:96 已引用 | ✅ |
| 13.4 | MD5 → SHA-256 | db.rs:305 `sha256_hash`；:60 `hash_version` 列；:86-91 `PRAGMA user_version` 迁移；:31 `legacy_entries` | ✅ |
| 13.5 | 默认拒绝 | engine.rs:112 `unwrap_or(false)`；commands.rs:83/127 `BLOCKED` | ✅ |
| 13.6 | 死依赖清理 | capabilities/default.json 已删 `store:default`；Cargo.toml 已删 store/log/time | ✅ |

**结论**：Sprint 13 全部落地，无回归。检测引擎核心逻辑保持 A+ 级（213/213 + 129/129）。

### 1.2 Sprint 14 已完成部分

| 编号 | 子项 | 验证证据 | 状态 |
|------|------|---------|------|
| 14.1 | Nuitka 跨平台条件化 | build_engine.py:96-108 `if system == "windows"` / `elif system == "darwin"` 分支；:87 `--include-package=daoti_xuandun` | ✅ |
| 14.3a | 编译期 key 注入 | build_engine.py:8-50 `_inject_compile_time_key` 生成 32 字节 key + 12 个预加密阈值，写入 `_key_generated.py` | ✅ |
| 14.3b | secure_strings.py 适配 | secure_strings.py:5-7 `from ._key_generated import COMPILED_KEY, SECURE_VALUES`；:45-49 `secure_value(name, dev_default)` | ✅ |
| 14.3c | config.py 阈值包裹 | **未完成**——dataclass 默认值和 preset 覆盖值仍为明文 | ⏳ |
| 14.2 | anti_debug 三端覆盖 | **未完成**——anti_debug.py:15/27/44/77 仍有 `if sys.platform != "win32": return False` | ⏳ |

### 1.3 剩余工作清单

| Sprint | 子项 | 文件 | 工作量 |
|--------|------|------|--------|
| 14.3c | config.py 阈值包裹（12 处） | src/daoti_xuandun/config.py | ~1h |
| 14.2 | anti_debug.py 三端覆盖 + 基线加固 | desktop/xuandun-desktop/anti_debug.py | ~6h |
| 15.1 | 双许可证文件（LICENSE/LICENSE_CODE/NOTICE） | 根目录 | ~2h |
| 15.2 | 核心文件 SPDX 头（13 个 .py） | src/daoti_xuandun/*.py + desktop/*.py | ~1h |
| 15.3 | .gitignore + 临时脚本归档 + README 重写 | 根目录 | ~2h |
| 15.4 | git init + 推送到 zhibaiYingChuan/xuandun | 根目录 | ~0.5h |
| 16.1 | tauri.conf.json macOS/Linux bundle 段 | src-tauri/tauri.conf.json | ~1h |
| 16.2 | GitHub Actions 三端 CI workflow | .github/workflows/release.yml | ~4h |
| 16.3 | 打 tag 触发 CI + 验证产物 | GitHub | ~2h |

---

## 二、Sprint 14.3c：config.py 阈值包裹

> 预估：~1h

### 2.1 修改文件

[config.py](file:///e:/smallloong/XuanDun/src/daoti_xuandun/config.py)

### 2.2 修改内容

**顶部导入**（line 3 后加）：
```python
from .secure_strings import secure_value
```

**dataclass 默认值**（3 处）：
| 行号 | 当前 | 改为 |
|------|------|------|
| 56 | `prototype_distance_threshold: float = 0.65` | `prototype_distance_threshold: float = float(secure_value("prototype_distance_threshold_default", "0.65"))` |
| 61 | `reject_boundary_multiplier: float = 3.0` | `reject_boundary_multiplier: float = float(secure_value("reject_boundary_multiplier_default", "3.0"))` |
| 62 | `structural_anomaly_threshold: float = 0.35` | `structural_anomaly_threshold: float = float(secure_value("structural_anomaly_threshold_default", "0.35"))` |

**preset BASIC 覆盖**（line 174-188，3 处）：
| 行号 | 当前 | 改为 |
|------|------|------|
| 178 | `prototype_distance_threshold=0.50,` | `prototype_distance_threshold=float(secure_value("prototype_distance_threshold_basic", "0.50")),` |
| 180 | `reject_boundary_multiplier=2.0,` | `reject_boundary_multiplier=float(secure_value("reject_boundary_multiplier_basic", "2.0")),` |
| 181 | `structural_anomaly_threshold=0.40,` | `structural_anomaly_threshold=float(secure_value("structural_anomaly_threshold_basic", "0.40")),` |

**preset STRICT 覆盖**（line 189-204，3 处）：
| 行号 | 当前 | 改为 |
|------|------|------|
| 193 | `prototype_distance_threshold=0.45,` | `prototype_distance_threshold=float(secure_value("prototype_distance_threshold_strict", "0.45")),` |
| 195 | `reject_boundary_multiplier=2.2,` | `reject_boundary_multiplier=float(secure_value("reject_boundary_multiplier_strict", "2.2")),` |
| 196 | `structural_anomaly_threshold=0.30,` | `structural_anomaly_threshold=float(secure_value("structural_anomaly_threshold_strict", "0.30")),` |

**preset STANDARD 覆盖**（line 218-233，3 处）：
| 行号 | 当前 | 改为 |
|------|------|------|
| 222 | `prototype_distance_threshold=0.35,` | `prototype_distance_threshold=float(secure_value("prototype_distance_threshold_standard", "0.35")),` |
| 224 | `reject_boundary_multiplier=2.5,` | `reject_boundary_multiplier=float(secure_value("reject_boundary_multiplier_standard", "2.5")),` |
| 225 | `structural_anomaly_threshold=0.35,` | `structural_anomaly_threshold=float(secure_value("structural_anomaly_threshold_standard", "0.35")),` |

### 2.3 设计说明

- **开发模式**：`_key_generated.py` 不存在 → `secure_value` 返回 `dev_default` → 行为与原明文一致
- **生产模式**：`build_engine.py` 编译前生成 `_key_generated.py`（含 12 个预加密值）→ Nuitka 编译时固化为机器码常量 → `strings xuandun-engine | grep 0.65` 无明文
- **PARANOID 层级**：preset 未覆盖这 3 个阈值（沿用 dataclass 默认值），故无需额外包裹

### 2.4 验证

```bash
# 开发模式（无 _key_generated.py）
python -c "from daoti_xuandun.config import XuanDunConfig, DefenseLevel; c=XuanDunConfig(); print(c.prototype_distance_threshold)"
# 预期输出：0.65

# 生产模式（先运行 build_engine.py 生成 _key_generated.py）
python -c "from daoti_xuandun.config import XuanDunConfig; c=XuanDunConfig(); print(c.prototype_distance_threshold)"
# 预期输出：0.65（解密后值相同）

# Nuitka 编译后
strings xuandun-engine-x86_64-pc-windows-msvc.exe | grep -E "0\.(65|50|45|35|40|30)"
# 预期：无输出（明文已固化）
```

---

## 三、Sprint 14.2：anti_debug.py 三端覆盖

> 预估：~6h

### 3.1 修改文件

[anti_debug.py](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/anti_debug.py)

### 3.2 当前问题

- line 15/27/44/77：`if sys.platform != "win32": return False` → macOS/Linux 完全无检测
- line 120-125：哈希基线存 `tempfile.gettempdir()`，易被覆写篡改
- Windows 检测仅 IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQuery/procdump，缺 x64dbg/ida/Frida/Process Hacker 扫描

### 3.3 修改方案

#### 3.3.1 新增 macOS 检测函数

```python
def _check_macos_ptrace() -> bool:
    """macOS: ptrace(PT_DENY_ATTACH) 防附加。"""
    if sys.platform != "darwin":
        return False
    try:
        libc = ctypes.CDLL("/usr/lib/system/libsystem_kernel.dylib")
        PT_DENY_ATTACH = 31
        libc.ptrace(PT_DENY_ATTACH, 0, 0, 0)
    except Exception:
        # ptrace 失败通常意味着已有调试器附加
        logger.warning("Debugger detected: ptrace(PT_DENY_ATTACH) failed")
        return True
    return False


def _check_macos_sysctl() -> bool:
    """macOS: sysctl 查询 P_TRACED 标志。"""
    if sys.platform != "darwin":
        return False
    try:
        libc = ctypes.CDLL("/usr/lib/libc.dylib")
        KERN_PROC = 1
        KERN_PROC_PID = 14
        P_TRACED = 0x800
        class kinfo_proc(ctypes.Structure):
            _fields_ = [("kp_proc.p_flag", ctypes.c_int)]
        info = kinfo_proc()
        size = ctypes.c_int(ctypes.sizeof(info))
        pid = os.getpid()
        libc.sysctl(
            (ctypes.c_int * 4)(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid),
            4, ctypes.byref(info), ctypes.byref(size), None, 0,
        )
        if info.kp_proc.p_flag & P_TRACED:
            logger.warning("Debugger detected: sysctl P_TRACED")
            return True
    except Exception:
        pass
    return False
```

（注：`CTL_KERN = 1` 需在文件顶部常量区定义）

#### 3.3.2 新增 Linux 检测函数

```python
def _check_linux_tracer_pid() -> bool:
    """Linux: 读 /proc/self/status 的 TracerPid。"""
    if sys.platform != "linux" or not os.path.exists("/proc/self/status"):
        return False
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    pid = int(line.split(":")[1].strip())
                    if pid != 0:
                        logger.warning("Debugger detected: TracerPid=%d", pid)
                        return True
                    break
    except Exception:
        pass
    return False


def _check_linux_debugger_processes() -> bool:
    """Linux: 扫描 /proc/*/exe 匹配 gdb/lldb/frida/ida。"""
    if sys.platform != "linux":
        return False
    debugger_names = ("gdb", "lldb", "frida-server", "ida", "ida64", "strace", "ltrace")
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            exe_link = f"/proc/{entry}/exe"
            try:
                target = os.readlink(exe_link).lower()
                if any(name in target for name in debugger_names):
                    logger.warning("Debugger process detected: %s (pid=%s)", target, entry)
                    return True
            except OSError:
                continue
    except Exception:
        pass
    return False
```

#### 3.3.3 Windows 检测增强

```python
def _check_windows_debugger_processes() -> bool:
    """Windows: EnumProcesses 扫描 x64dbg/ida/Windbg/Frida/Process Hacker。"""
    if sys.platform != "win32":
        return False
    debugger_names = (
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "ida.exe", "ida64.exe", "windbg.exe",
        "frida.exe", "processhacker.exe", "cheatengine-x86_64.exe",
        "cheatengine-i386.exe",
    )
    try:
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        count = 1024
        pids = (ctypes.wintypes.DWORD * count)()
        cb = ctypes.sizeof(pids)
        bytes_returned = ctypes.wintypes.DWORD()
        if not psapi.EnumProcesses(ctypes.byref(pids), cb, ctypes.byref(bytes_returned)):
            return False
        pid_count = bytes_returned.value // ctypes.sizeof(ctypes.wintypes.DWORD)
        for i in range(pid_count):
            pid = pids[i]
            h = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFO | VM_READ
            if not h:
                continue
            try:
                name_buf = ctypes.create_unicode_buffer(260)
                if psapi.GetModuleBaseNameW(h, None, name_buf, 260):
                    if name_buf.value.lower() in debugger_names:
                        logger.warning("Debugger process detected: %s (pid=%d)", name_buf.value, pid)
                        return True
            finally:
                kernel32.CloseHandle(h)
    except Exception:
        pass
    return False
```

#### 3.3.4 哈希基线迁移

```python
def _get_hash_file_path(filename: str) -> str:
    """哈希文件存 ~/.xuandun/sig/，权限 0600，防覆写。"""
    home = os.path.expanduser("~")
    sig_dir = os.path.join(home, ".xuandun", "sig")
    os.makedirs(sig_dir, exist_ok=True)
    safe_name = filename.replace(os.sep, "_").replace(":", "_")
    hash_file = os.path.join(sig_dir, f"{safe_name}.sha256")
    if not os.path.exists(hash_file):
        # 首次创建时设置权限
        open(hash_file, "w").close()
        try:
            os.chmod(hash_file, 0o600)
        except Exception:
            pass  # Windows chmod 无效
    return hash_file
```

#### 3.3.5 is_debugger_present 主函数更新

```python
def is_debugger_present() -> bool:
    # Windows
    if _check_is_debugger_present():
        return True
    if _check_remote_debugger():
        return True
    if _check_nt_query():
        return True
    if _check_windows_debugger_processes():  # 新增
        return True
    if is_memory_dump_attempt():
        return True
    # macOS
    if _check_macos_ptrace():  # 新增
        return True
    if _check_macos_sysctl():  # 新增
        return True
    # Linux
    if _check_linux_tracer_pid():  # 新增
        return True
    if _check_linux_debugger_processes():  # 新增
        return True
    # 通用
    if _check_timing():
        return True
    return False
```

### 3.4 验证

```bash
# 三端运行
python -c "from anti_debug import is_debugger_present; print(is_debugger_present())"
# 预期：False（无调试器时）

# Windows: 启动 x64dbg 附加后运行 → True + 日志
# macOS: lldb -p <pid> 后运行 → True + 日志
# Linux: gdb -p <pid> 后运行 → True + 日志

# 哈希基线位置
ls ~/.xuandun/sig/
# 预期：xuandun-engine-*.sha256，权限 600（Unix）
```

---

## 四、Sprint 15：全开源 + 道体证书

> 预估：~5.5h

### 4.1 双许可证文件（15.1）

#### 4.1.1 LICENSE（替换根目录 MIT）

- **来源**：https://raw.githubusercontent.com/zhibaiYingChuan/DaoTi/main/LICENSE（已获取全文）
- **适配修改**：
  - 标题：`DAO TI RESEARCH LICENSE` → 保留（道体研究许可证适用于玄盾核心算法）
  - Section 1.1 "Repository Assets" 资产清单替换为玄盾文件：
    ```
    (a) src/daoti_xuandun/reject_gate.py（拒绝门核心算法）
    (b) src/daoti_xuandun/preprocessors.py（预处理管道）
    (c) src/daoti_xuandun/config.py（配置对象，含动态活性参数）
    (d) src/daoti_xuandun/xuandun.py（主引擎入口）
    (e) src/daoti_xuandun/luoshu_mapper.py（洛书符号映射器）
    (f) src/daoti_xuandun/secure_strings.py（敏感参数保护）
    (g) src/daoti_xuandun/timing_checker.py（时序一致性校验）
    (h) src/daoti_xuandun/dynamic_shell.py（动态阴阳壳）
    (i) src/daoti_xuandun/ancient_mapper.py（自组织符号映射）
    (j) src/daoti_xuandun/atlas_mapping.py（图谱映射）
    (k) desktop/xuandun-desktop/engine_flask.py（引擎 Flask 服务）
    (l) desktop/xuandun-desktop/anti_debug.py（反逆向检测）
    (m) desktop/xuandun-desktop/build_engine.py（Nuitka 编译脚本）
    ```
  - Section 1.2 "Architecture Source Code" 改为指代"核心算法的明文源码与设计文档"（Nuitka 编译产物为脱敏版本，明文不公开）
  - Section 1.4 "Model Weights" 改为"预加密阈值常量"（_key_generated.py 中的 SECURE_VALUES）
  - Section 2.1 (b) "Model Weights 推理"改为"使用核心算法进行 LLM 输入检测"
  - Section 2.1 (v) "Model Weights 再分发"改为"核心算法二进制再分发"
  - Section 9 联系方式：Repository 改为 `https://github.com/zhibaiYingChuan/xuandun`
  - 版权年份保留 2026，作者保留"独立研究者，知白"

#### 4.1.2 LICENSE_CODE（新增，Apache 2.0）

- **来源**：https://www.apache.org/licenses/LICENSE-2.0.txt
- **适用范围**：除核心算法外的所有源码（Rust 桌面端、TypeScript 前端、配置、文档、测试）

#### 4.1.3 NOTICE（新增）

```
道体·玄盾 (XuanDun)
Copyright (c) 2026 独立研究者，知白

本产品包含两类资产：

1. 核心算法资产（受道体研究许可证 v1.0 约束）：
   - src/daoti_xuandun/ 目录下的核心算法 .py 文件（详见 LICENSE Section 1.1）
   - desktop/xuandun-desktop/engine_flask.py
   - desktop/xuandun-desktop/anti_debug.py
   - desktop/xuandun-desktop/build_engine.py
   核心算法禁止逆向工程和再分发。Nuitka 编译产物为脱敏版本，
   明文源码不公开，作为商业秘密保护。

2. 外围代码资产（受 Apache License 2.0 约束）：
   - 桌面端 Rust 代码（desktop/xuandun-desktop/src-tauri/）
   - 前端 TypeScript/React 代码（desktop/xuandun-desktop/src/）
   - 配置文件、文档、测试代码、构建脚本
   外围代码遵循 Apache 2.0 开源协议，允许自由使用、修改和分发。

详见 LICENSE（道体研究许可证）和 LICENSE_CODE（Apache 2.0）。
```

### 4.2 核心文件 SPDX 头（15.2）

为以下 13 个文件在首行加头部：
```python
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
```

文件清单（基于实际 Glob 结果）：
- `src/daoti_xuandun/reject_gate.py`
- `src/daoti_xuandun/preprocessors.py`
- `src/daoti_xuandun/config.py`
- `src/daoti_xuandun/xuandun.py`
- `src/daoti_xuandun/luoshu_mapper.py`
- `src/daoti_xuandun/secure_strings.py`
- `src/daoti_xuandun/timing_checker.py`
- `src/daoti_xuandun/dynamic_shell.py`
- `src/daoti_xuandun/ancient_mapper.py`
- `src/daoti_xuandun/atlas_mapping.py`
- `desktop/xuandun-desktop/engine_flask.py`
- `desktop/xuandun-desktop/anti_debug.py`
- `desktop/xuandun-desktop/build_engine.py`

**排除**（外围代码，不加 SPDX DaoTi 头）：`__init__.py`、`manage.py`、`setup.py`、`mcp_server.py`、`challenge_api.py`、`types.py`、`build_engine_pyinstaller.py`（归档）、`engine_main.py`、`generate_icons.py`、`test_*.py`

### 4.3 代码清理与 .gitignore（15.3）

#### 4.3.1 创建 .gitignore（根目录）

```gitignore
# Python
__pycache__/
*.pyc
*.pyo
.pytest_cache/
.mypy_cache/
.coverage

# Rust
desktop/xuandun-desktop/src-tauri/target/

# Node
desktop/xuandun-desktop/node_modules/
desktop/xuandun-desktop/dist/

# 构建产物
desktop/xuandun-desktop/src-tauri/binaries/
desktop/xuandun-desktop/build_pyinstaller/

# 临时文件
*.log
*.tmp
desktop/xuandun-desktop/test_output.txt
desktop/xuandun-desktop/test_result.txt

# 敏感数据（核心算法保护）
src/daoti_xuandun/_key_generated.py
industry_benchmarks/feedback/
industry_benchmarks/results/
benchmark_results/

# IDE
.vscode/
.idea/
```

#### 4.3.2 临时脚本归档

创建 `archive/legacy_scripts/` 目录，移动以下 ~30 个临时脚本：
- 反编译相关：`decompile.py`、`decompile2.py`、`reject_gate_decompiled.py`
- 修复脚本：`fix_all.py`、`fix_all2.py`、`fix_all3.py`、`fix_chars.py`、`fix_chars2.py`、`fix_comprehensive.py`、`fix_comprehensive2.py`、`fix_encoding.py`、`fix_final.py`、`fix_ultimate.py`
- 测试脚本：`test_benchmark_attacks.py`、`test_char_deviation.py`、`test_core_perf.py`、`test_core_perf2.py`、`test_extreme_attacks.py`、`test_flask_latency.py`、`test_flask_server.py`、`test_hash.py`、`test_hash2.py`、`test_no_whitelist.py`、`test_session.py`、`test_session2.py`、`test_session3.py`
- 审计/调试：`final_audit.py`、`final_audit2.py`、`debug_test.py`、`demo.py`、`mini_test.py`、`quick_test.py`、`auto_test.py`、`env_check.py`、`cleanup.py`、`cleanup2.py`
- 旧桌面测试：`desktop_xuandun_test.py`、`run_all_desktop_tests.py`、`run_desktop_tests.py`、`detection_rate_test.py`、`mcp_perf_test.py`
- 临时报告：`full_output.txt`、`pylint_output.txt`、`desktop_test_report.txt`、`test_report.json`、`security_stress_report.json`
- 临时脚本：`check_proc.ps1`、`_check_agents.ps1`、`_check_procs.ps1`、`_stop.ps1`、`diag.bat`、`run_industry_benchmarks.ps1`

**保留在根目录**：`README.md`、`LICENSE`、`LICENSE_CODE`、`NOTICE`、`pyproject.toml`、`Dockerfile`、`benchmark.py`、`run_benchmark.py`、`security_stress_test.py`、`serve.py`、`XuanDun.manifest.template`、`.gitignore`

#### 4.3.3 README.md 重写

新增章节：
- **许可证**：说明双许可证架构（道体研究许可证 + Apache 2.0）
- **架构概览**：核心算法 vs 外围代码的分层
- **三端安装**：Windows NSIS / macOS DMG / Linux AppImage 下载链接（占位，待 CI 产物）
- **从源码构建**：`python build_engine.py` + `npx tauri build`

### 4.4 仓库初始化与推送（15.4）

```bash
# 在 e:\smallloong\XuanDun 执行
git init
git add .
git status  # 确认 _key_generated.py 未被追踪
git commit -m "feat: 道体·玄盾 v1.0.0 - 工业级 LLM 防火墙

- 检测引擎 A+ 级（213/213 攻击拦截 + 129/129 良性接纳）
- 桌面端 Tauri v2 + Nuitka 反逆向
- 双许可证：道体研究许可证（核心算法）+ Apache 2.0（外围代码）
- 三端支持：Windows / macOS / Linux"

git remote add origin https://github.com/zhibaiYingChuan/xuandun.git
git branch -M main
git push -u origin main
```

---

## 五、Sprint 16：三端 CI/CD

> 预估：~7h

### 5.1 tauri.conf.json 三端配置（16.1）

#### 5.1.1 修改文件

[tauri.conf.json](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/tauri.conf.json)

#### 5.1.2 修改内容

在 `bundle` 对象内，`windows` 段同级新增 `macOS` 和 `linux` 段：

```json
"macOS": {
  "signingIdentity": null,
  "entitlements": null,
  "exceptionDomain": "",
  "frameworks": [],
  "providerShortName": null,
  "minimumSystemVersion": "10.15",
  "dmg": {
    "appPosition": { "x": 180, "y": 170 },
    "applicationFolderPosition": { "x": 480, "y": 170 },
    "windowSize": { "width": 660, "height": 400 }
  }
},
"linux": {
  "deb": {
    "depends": ["libwebkit2gtk-4.1-0", "libssl3", "libayatana-appindicator3-1"]
  },
  "appImage": {
    "bundleMediaFramework": true
  }
}
```

`externalBin` 保持 `["binaries/xuandun-engine"]`（Tauri 按 target triple 后缀自动匹配，如 `xuandun-engine-x86_64-pc-windows-msvc.exe`、`xuandun-engine-aarch64-apple-darwin`）。

### 5.2 GitHub Actions workflow（16.2）

#### 5.2.1 新建文件

`.github/workflows/release.yml`

#### 5.2.2 内容

```yaml
name: Release 三端构建

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: 道体·玄盾_${{ github.ref_name }}_x64-setup.exe
          - os: macos-latest
            target: aarch64-apple-darwin
            artifact: 道体·玄盾_${{ github.ref_name }}_aarch64.dmg
          - os: macos-latest
            target: x86_64-apple-darwin
            artifact: 道体·玄盾_${{ github.ref_name }}_x64.dmg
          - os: ubuntu-22.04
            target: x86_64-unknown-linux-gnu
            artifact: 道体·玄盾_${{ github.ref_name }}_amd64.AppImage

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - name: 安装 Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: 安装 Nuitka 依赖
        run: pip install nuitka waitress numpy ordered-set

      - name: 安装 Node 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: 安装 Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Linux 系统依赖
        if: matrix.os == 'ubuntu-22.04'
        run: |
          sudo apt-get update
          sudo apt-get install -y libwebkit2gtk-4.1-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev

      - name: 编译核心引擎（Nuitka）
        working-directory: desktop/xuandun-desktop
        run: python build_engine.py
        env:
          PYTHONPATH: ${{ github.workspace }}/src

      - name: 安装前端依赖
        working-directory: desktop/xuandun-desktop
        run: npm ci

      - name: 构建 Tauri 安装包
        working-directory: desktop/xuandun-desktop
        run: npx tauri build -- --target ${{ matrix.target }}

      - name: 上传产物
        uses: softprops/action-gh-release@v2
        with:
          files: |
            desktop/xuandun-desktop/src-tauri/target/${{ matrix.target }}/release/bundle/nsis/*.exe
            desktop/xuandun-desktop/src-tauri/target/${{ matrix.target }}/release/bundle/dmg/*.dmg
            desktop/xuandun-desktop/src-tauri/target/${{ matrix.target }}/release/bundle/appimage/*.AppImage
            desktop/xuandun-desktop/src-tauri/target/${{ matrix.target }}/release/bundle/deb/*.deb
```

### 5.3 触发与验证（16.3）

```bash
# 本地验证 tauri.conf.json 语法
cd desktop/xuandun-desktop
npx tauri info  # 确认三端配置识别

# 打 tag 触发 CI
git tag v1.0.0
git push origin v1.0.0

# 监控 CI
gh run watch

# 验证产物
gh release view v1.0.0
# 预期：4 个产物（Win NSIS + 2 Mac DMG + Linux AppImage + deb）
```

---

## 六、执行顺序与依赖

```
Sprint 14.3c (config.py) ──┐
                           ├─→ Sprint 15.2 (SPDX 头，含 config.py)
Sprint 14.2 (anti_debug) ──┘                 │
                                             ↓
                          Sprint 15.1 (许可证) → Sprint 15.3 (清理) → Sprint 15.4 (推送)
                                                                      ↓
                          Sprint 16.1 (tauri.conf) → Sprint 16.2 (CI workflow)
                                                                      ↓
                                                          Sprint 16.3 (打 tag 验证)
```

**并行机会**：14.3c 与 14.2 可并行；15.1 与 15.2 可并行；15.3 与 16.1 可并行。

---

## 七、验证清单

### 7.1 Sprint 14
- [ ] `python -c "from daoti_xuandun.config import XuanDunConfig; XuanDunConfig()"` 无异常
- [ ] 三端 `python -c "from anti_debug import is_debugger_present; print(is_debugger_present())"` 返回 False
- [ ] Windows + x64dbg 附加 → 返回 True
- [ ] Nuitka 编译后 `strings xuandun-engine | grep 0.65` 无明文

### 7.2 Sprint 15
- [ ] 根目录 LICENSE 识别为道体研究许可证
- [ ] LICENSE_CODE 识别为 Apache 2.0
- [ ] NOTICE 存在且说明双许可证
- [ ] 13 个核心 .py 文件首行有 SPDX 头
- [ ] .gitignore 存在且包含 `_key_generated.py`
- [ ] `archive/legacy_scripts/` 存在且包含 ~30 个临时脚本
- [ ] `git status` 干净，`_key_generated.py` 未追踪
- [ ] GitHub 仓库 `zhibaiYingChuan/xuandun` 可访问

### 7.3 Sprint 16
- [ ] `npx tauri info` 三端配置识别
- [ ] `.github/workflows/release.yml` 语法正确
- [ ] 打 tag `v1.0.0` 后 CI 触发
- [ ] `gh run view` 三端全绿
- [ ] Release 页面有 4+ 个产物
- [ ] 下载各端安装包验证可运行

---

## 八、假设与决策

1. **仓库名**：`xuandun`（V2 计划默认，用户 GitHub 用户名为 zhibaiYingChuan）
2. **Mac 签名**：`signingIdentity: null`（无 Apple Developer ID，用户首次运行需右键打开绕过 Gatekeeper）
3. **核心算法清单**：沿用 V2 计划的 13 个文件，不纳入 engine_main.py（仅是引擎入口，非算法核心）
4. **DaoTi LICENSE 适配**：保留许可证框架，替换资产清单为玄盾文件，"Model Weights" 概念替换为"预加密阈值常量"
5. **临时脚本处理**：归档到 `archive/legacy_scripts/` 而非删除（保留历史可追溯）
6. **Nuitka key 保护范围**：仅 3 个阈值 × 4 层级 = 12 个预加密值（build_engine.py 已实现）
7. **anti_debug 哈希基线**：迁移到 `~/.xuandun/sig/`，权限 0600（Unix），Windows chmod 无效但不报错
8. **GitHub Actions 触发**：`on: push: tags: ['v*']` + `workflow_dispatch`（手动触发备用）
9. **Linux deb 依赖**：`libwebkit2gtk-4.1-0`（Tauri v2 用 4.1，非 4.0）
10. **不修改检测引擎核心逻辑**：Sprint 13 验证 A+ 级，本次仅做工程层加固和开源准备

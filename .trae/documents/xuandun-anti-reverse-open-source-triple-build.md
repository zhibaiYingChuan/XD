# 玄盾反逆向 + 全开源 + 三端编译实施计划 V2

> **版本**：V2（基于 2026-07-09 全新全局审计）
> **状态**：待用户批准后执行
> **预估总工时**：~38h

---

## 一、全局审计结论（2026-07-09 全新审计）

### 1.1 已完成 Sprint 验证

| Sprint | 状态 | 验证证据 |
|--------|------|---------|
| Sprint 1-6（工程层 + 检测引擎初步） | ✅ 完成 | FIX_ROADMAP_20260708.md 记录全部修复 |
| Sprint 7-9（检测引擎强化） | ✅ 完成 | benchmark 三套件 A+（213/213 攻击拦截 + 129/129 良性接纳，0 漏检 0 误拒） |
| Sprint 10（桌面端收尾打包） | ✅ 完成 | NSIS 安装包 51.96 MB，29/29 真机测试通过 |
| Sprint 11（CMD 弹窗根治） | ✅ 完成 | 记忆 #cb1e318a 验证 30 秒密集监控无 CMD 窗口；main.rs 已加 `windows_subsystem = "windows"` |
| Sprint 12（Agent 检测双通道） | ✅ 完成 | agent_discovery.rs 已有 extension_keywords + installed 字段；Trae 进程名修复为 "Trae CN.exe" |

### 1.2 待修复问题清单（本次审计新发现 + 原计划继承）

#### A. 桌面端严重问题（Sprint 13 继承，5 项）

| 编号 | 问题 | 文件:行 | 严重性 |
|------|------|---------|--------|
| A1 | 引擎进程泄漏（lib.rs 用 `.run()` 无退出钩子） | src-tauri/src/lib.rs:70 | HIGH |
| A2 | CORS 全开 + /debug/state 无鉴权 | engine_flask.py:151/185/205/228/104 | HIGH |
| A3 | UTF-8 字节切片 panic | engine.rs:76, commands.rs:96 | HIGH |
| A4 | MD5 哈希链 + hash_input 缺字段 | db.rs:94/279, Cargo.toml:31 | HIGH |
| A5 | 默认放行（unwrap_or(true) + fallback allowed:true） | engine.rs:96, commands.rs:82/126 | HIGH |

#### B. 反逆向保护薄弱（Sprint 14 继承，3 项）

| 编号 | 问题 | 文件 | 严重性 |
|------|------|------|--------|
| B1 | Nuitka `--windows-disable-console` 未跨平台条件化 | build_engine.py:35 | HIGH |
| B2 | anti_debug.py 仅 Windows，缺 macOS/Linux 检测 | anti_debug.py:15-92 | HIGH |
| B3 | secure_strings.py 用 `os.urandom(32)` 运行时生成 key，保护纯装饰（明文仍以字面量传入 `secure()`） | src/daoti_xuandun/secure_strings.py:9 | HIGH |

#### C. 开源准备（Sprint 15 继承 + 本次新发现，6 项）

| 编号 | 问题 | 路径 | 严重性 |
|------|------|------|--------|
| C1 | 根目录 LICENSE 为 MIT，需替换为道体研究许可证 | e:\smallloong\XuanDun\LICENSE | HIGH |
| C2 | 无 LICENSE_CODE（Apache 2.0） | 缺失 | HIGH |
| C3 | 无 NOTICE 声明核心算法范围 | 缺失 | HIGH |
| C4 | 核心算法 .py 文件无 SPDX 头 | src/daoti_xuandun/*.py | MEDIUM |
| C5 | 根目录有 ~30 个临时脚本（decompile*.py、fix_*.py、test_*.py 临时文件）需清理或归档 | e:\smallloong\XuanDun\*.py | MEDIUM |
| C6 | 无 .gitignore，无 .git 目录 | 缺失 | HIGH |

#### D. 三端编译（Sprint 16 继承，2 项）

| 编号 | 问题 | 文件 | 严重性 |
|------|------|------|--------|
| D1 | tauri.conf.json 缺 macOS/Linux bundle 段 | src-tauri/tauri.conf.json | HIGH |
| D2 | 无 GitHub Actions workflow | 缺失 | HIGH |

#### E. 死依赖清理（本次审计新发现，1 项）

| 编号 | 问题 | 文件 | 严重性 |
|------|------|------|--------|
| E1 | `tauri_plugin_store`、`tauri_plugin_log` 注册但从未使用；`time = "0.3"` crate 未被引用（所有 `time::` 实为 `std::time::`） | lib.rs:20-21, Cargo.toml:27/32 | LOW |

### 1.3 审计结论

- 检测引擎核心逻辑：✅ A+ 级，无需改动
- 桌面端工程层：⚠️ 5 个严重问题待修复（A1-A5）
- 反逆向保护：⚠️ 弱（B1-B3）
- 开源准备：⚠️ 不充分（C1-C6，本次审计新发现 4 项）
- 三端编译：⚠️ 仅 Windows 就绪（D1-D2）
- 死依赖：⚠️ 3 处（E1，本次审计新发现）

**确认无误后可进入 Sprint 13-16 执行。**

---

## 二、Sprint 13：桌面端严重问题修复 + 死依赖清理

> 预估：~11h

### 13.1 引擎进程泄漏修复（A1）

- **文件**：[lib.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/lib.rs)
- **当前**：line 70 `.run(tauri::generate_context!())`
- **改为**：
  ```rust
  let app = tauri::Builder::default()
      // ... 现有插件和 setup ...
      .build(tauri::generate_context!())
      .expect("error while building tauri application");
  
  app.run(|app_handle, event| match event {
      tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
          let _ = engine::stop_engine(app_handle);
      }
      _ => {}
  });
  ```
- engine.rs 的 `stop_engine`（line 204）已通过 child_pid 调用 `kill_process`（Win taskkill / Unix kill -9），无需改 `std::mem::forget` 逻辑
- **验证**：关闭窗口后任务管理器确认 xuandun-engine 进程 3 秒内消失

### 13.2 CORS 收紧 + /debug/state 鉴权（A2）

- **文件**：[engine_flask.py](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/engine_flask.py)
- **CORS**：4 处 `Access-Control-Allow-Origin: *`（line 151/185/205/228）改为限定 `tauri://localhost`、`http://tauri.localhost`
- **/debug/state 鉴权**（line 104-144）：
  - 从 `XUANDUN_DEBUG_TOKEN` 环境变量读取 token
  - 请求头 `X-Debug-Token` 匹配才返回数据
  - 无 token 配置时返回 404（隐藏端点存在性）
- **验证**：浏览器跨域请求被拒；无 token 访问 /debug/state 返回 404

### 13.3 UTF-8 安全切片（A3）

- **文件**：[engine.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/engine.rs#L76)、[commands.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/commands.rs#L96)
- **当前**：`&text[..text.len().min(50)]`（字节切片，中文/emoji 多字节会 panic）
- **改为**：抽公共函数 `safe_preview(s: &str, max: usize) -> &str`，用 `char_indices` 切到字符边界
  ```rust
  pub fn safe_preview(s: &str, max: usize) -> &str {
      if s.len() <= max { return s; }
      match s.char_indices().take_while(|(i, _)| *i <= max).last() {
          Some((i, c)) => &s[..i + c.len_utf8()],
          None => &s[..max],
      }
  }
  ```
- 放在 engine.rs 顶部，commands.rs 引用
- **验证**：输入中文/emoji 长文本不 panic；新增 `test_safe_preview_cjk`

### 13.4 MD5 → SHA-256 + hash_input 补全（A4）

- **文件**：[Cargo.toml](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/Cargo.toml)、[db.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/db.rs)
- **Cargo.toml**：删 `md-5 = "0.10"`，加 `sha2 = "0.10"`
- **db.rs hash_input**：line 94 和 line 259 纳入 `reject_stage`、`session_id` 字段
  ```rust
  let hash_input = format!("{}{}{}{}{}{}{}", 
      timestamp, text_preview, allowed as i32, 
      trust_level, reject_stage.unwrap_or(""), 
      session_id.unwrap_or(""), prev_hash);
  ```
- **db.rs md5_hash → sha256_hash**：line 279-284 改用 `sha2::Sha256`
- **旧库迁移**：`PRAGMA user_version` 检测，旧 MD5 记录标记 `chain_legacy`（在 HashChainReport 增加 `legacy_entries` 字段）跳过校验
- **测试**：line 373 `test_md5_known_value` 改为 `test_sha256_known_value`
- **验证**：`test_hash_chain_intact` 通过；篡改记录后 chain 断裂；旧库升级不报错

### 13.5 默认放行改默认拒绝（A5）

- **文件**：[engine.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/engine.rs#L96)、[commands.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/commands.rs#L82)
- **engine.rs line 96**：`result["allowed"].as_bool().unwrap_or(true)` → `unwrap_or(false)`
- **commands.rs line 82**：引擎未运行时 `allowed: true` → `false`，trust_level 改 `"BLOCKED"`
- **commands.rs line 126**：fallback 分支 `allowed: true` → `false`，trust_level 改 `"BLOCKED"`
- **验证**：停引擎后 protect 返回 allowed=false

### 13.6 死依赖清理（E1，本次审计新发现）

- **文件**：[Cargo.toml](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/Cargo.toml)、[lib.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/lib.rs)
- **Cargo.toml**：删 `tauri-plugin-store = "2"`、`tauri-plugin-log = "2"`、`time = "0.3"`
- **lib.rs**：删 line 20-21 的 `.plugin(tauri_plugin_store::Builder::new().build())` 和 `.plugin(tauri_plugin_log::Builder::new().build())`
- **验证**：`cargo check` 通过；`cargo build --release` 通过

---

## 三、Sprint 14：反逆向保护增强

> 预估：~14h

### 14.1 Nuitka 跨平台条件化（B1）

- **文件**：[build_engine.py](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/build_engine.py)
- **当前**：line 35 `--windows-disable-console` 无条件添加（macOS/Linux 会报错）
- **改为**：
  ```python
  if system == "windows":
      cmd.append("--windows-disable-console")
  elif system == "darwin":
      cmd.extend(["--macos-app-mode=gui"])  # macOS GUI 模式
  # Linux 无需控制台屏蔽参数
  ```
- 加 `--include-package=daoti_xuandun`（确保核心算法编译进去）
- 验证 PYTHONPATH 指向 `src` 目录的正确性
- **验证**：`python build_engine.py` 在三端成功；产物运行无 console；`pyinstxtractor` 无法提取

### 14.2 anti_debug.py 三端覆盖（B2）

- **文件**：[anti_debug.py](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/anti_debug.py)
- **macOS 新增**：
  - `ptrace(PT_DENY_ATTACH)` 防附加（`ctypes.CDLL("/usr/lib/system/libsystem_kernel.dylib")`）
  - `sysctl` 扫描 lldb/gdb 进程
- **Linux 新增**：
  - 读 `/proc/self/status` 的 `TracerPid` 非 0 则调试中
  - 扫描 `/proc/*/exe` 匹配 gdb/ida/frida
- **Windows 补充**：
  - `EnumProcesses` 扫描 x64dbg/ida/Windbg/Frida/Process Hacker
- **完整性基线加固**：
  - 从 `tempfile.gettempdir()` 迁移到用户家目录 `~/.xuandun/sig/`（防覆写）
  - 文件权限 0600（仅所有者可读写）
- **验证**：attach 调试器后引擎退出；篡改 exe 后校验失败

### 14.3 核心参数保护加固（B3）

- **文件**：[secure_strings.py](file:///e:/smallloong/XuanDun/src/daoti_xuandun/secure_strings.py)、[config.py](file:///e:/smallloong/XuanDun/src/daoti_xuandun/config.py)
- **当前问题**：`os.urandom(32)` 运行时生成 key，每次启动 key 不同；明文 `value` 以字面量传入 `secure()`，`strings` 二进制仍可见
- **改为编译期常量 key**：
  - `build_engine.py` 编译前生成随机 32 字节，写入 `src/daoti_xuandun/_key_generated.py`（gitignore）
  - `secure_strings.py` 改为 `from ._key_generated import COMPILED_KEY`，移除 `os.urandom`
  - Nuitka 编译时 `_key_generated.py` 被固化为机器码常量
- **config.py 阈值包裹**：
  - 明文阈值（`prototype_distance_threshold`、`reject_boundary_multiplier`、`structural_anomaly_threshold`）经 `secure_strings.secure()` 包裹
  - 使用时 `float(secure_strings.decrypt(secure("threshold_name", "0.35")))`
- **验证**：`strings xuandun-engine | grep threshold` 无明文；运行时阈值正确

---

## 四、Sprint 15：全开源 + 道体证书

> 预估：~6h

### 15.1 双许可证文件（C1/C2/C3）

- **LICENSE**（根，替换现有 MIT）：道体研究许可证 v1.0
  - 从 https://github.com/zhibaiYingChuan/DaoTi/blob/main/LICENSE 获取全文
  - 修改 Section 1.1 "Repository Assets" 列表为玄盾的文件清单：
    - `src/daoti_xuandun/*.py`（核心算法）
    - `desktop/xuandun-desktop/engine_flask.py`、`anti_debug.py`、`build_engine.py`
  - 修改 Section 1.2 "Architecture Source Code" 为"核心算法源码"
  - 保留禁止逆向工程、禁止再分发条款
- **LICENSE_CODE**（新增）：Apache 2.0 全文（从 https://www.apache.org/licenses/LICENSE-2.0.txt）
- **NOTICE**（新增）：
  ```
  道体·玄盾 (XuanDun)
  Copyright (c) 2026 独立研究者，知白
  
  本产品包含两类资产：
  1. 核心算法资产（受道体研究许可证 v1.0 约束）：
     - src/daoti_xuandun/ 目录下所有 .py 文件
     - desktop/xuandun-desktop/engine_flask.py
     - desktop/xuandun-desktop/anti_debug.py
     - desktop/xuandun-desktop/build_engine.py
  
  2. 外围代码资产（受 Apache License 2.0 约束）：
     - 上述核心算法目录之外的所有源码文件
     - 桌面端 Rust 代码（src-tauri/）
     - 前端 TypeScript/React 代码（src/）
     - 配置文件、文档、测试代码
  
  核心算法禁止逆向工程和再分发。外围代码遵循 Apache 2.0 开源协议。
  ```

### 15.2 核心文件 SPDX 头（C4）

为以下文件加头部：
```python
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
```

文件清单：
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

### 15.3 代码清理与 .gitignore（C5/C6，本次审计新发现）

- **创建 .gitignore**：
  ```
  # Python
  __pycache__/
  *.pyc
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
  
  # 敏感数据
  src/daoti_xuandun/_key_generated.py
  industry_benchmarks/feedback/
  industry_benchmarks/results/
  benchmark_results/
  
  # IDE
  .vscode/
  .idea/
  ```
- **临时脚本归档**：根目录 ~30 个临时脚本移入 `archive/legacy_scripts/`
  - `decompile.py`、`decompile2.py`、`reject_gate_decompiled.py`
  - `fix_all*.py`、`fix_chars*.py`、`fix_comprehensive*.py`、`fix_encoding.py`、`fix_final.py`、`fix_ultimate.py`
  - `test_benchmark_attacks.py`、`test_char_deviation.py`、`test_core_perf*.py`、`test_extreme_attacks.py`
  - `final_audit*.py`、`debug_test.py`、`demo.py`、`mini_test.py`、`quick_test.py`
  - `auto_test.py`、`env_check.py`、`cleanup*.py`
- **保留在根目录**：`README.md`、`LICENSE`、`LICENSE_CODE`、`NOTICE`、`pyproject.toml`、`Dockerfile`、`benchmark.py`、`run_benchmark.py`、`run_industry_benchmarks.ps1`、`security_stress_test.py`、`serve.py`、`XuanDun.manifest.template`
- **README.md 重写**：增加许可证章节、架构说明、三端安装说明

### 15.4 仓库初始化与推送

- **默认仓库名**：`xuandun`（如用户指定其他名称可调整）
- **远程**：`github.com/zhibaiYingChuan/xuandun`
- **步骤**：
  1. `git init`
  2. `git add .`（受 .gitignore 约束）
  3. `git commit -m "feat: 道体·玄盾 v1.0.0 - 工业级 LLM 防火墙（检测引擎 A+ 级，全开源 + 道体证书保护核心算法）"`
  4. `git remote add origin https://github.com/zhibaiYingChuan/xuandun.git`
  5. `git push -u origin main`

---

## 五、Sprint 16：三端 CI/CD

> 预估：~8h

### 16.1 tauri.conf.json 三端配置（D1）

- **文件**：[tauri.conf.json](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/tauri.conf.json)
- **macOS 段**（新增）：
  ```json
  "macOS": {
    "signingIdentity": null,
    "entitlements": null,
    "dmg": {
      "appPosition": { "x": 180, "y": 170 },
      "applicationFolderPosition": { "x": 480, "y": 170 },
      "windowSize": { "width": 660, "height": 400 }
    }
  }
  ```
- **Linux 段**（新增）：
  ```json
  "linux": {
    "deb": {
      "depends": ["libwebkit2gtk-4.1-0", "libssl3"]
    },
    "appImage": {
      "bundleMediaFramework": true
    }
  }
  ```
- externalBin 保持 `["binaries/xuandun-engine"]`（Tauri 按 target 后缀自动匹配）

### 16.2 GitHub Actions workflow（D2）

- **文件**：`.github/workflows/release.yml`
- **matrix 策略**（3 端 4 target）：
  | OS | Target | 产物 |
  |----|--------|------|
  | windows-latest | x86_64-pc-windows-msvc | NSIS .exe |
  | macos-latest | aarch64-apple-darwin | DMG (Apple Silicon) |
  | macos-latest | x86_64-apple-darwin | DMG (Intel) |
  | ubuntu-22.04 | x86_64-unknown-linux-gnu | AppImage + .deb |
- **steps**：
  1. `actions/checkout@v4`
  2. `actions/setup-python@v5`（Python 3.11）+ `pip install nuitka waitress numpy`
  3. `actions/setup-node@v4`（Node 20）+ `npm ci`（在 desktop/xuandun-desktop/）
  4. `dtolnay/rust-toolchain@stable` + `rustup target add <target>`
  5. Linux 装系统依赖：`libwebkit2gtk-4.1-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev`
  6. `python build_engine.py`（产 `binaries/xuandun-engine-<target>`）
  7. `npx tauri build -- --target <target>`
  8. `softprops/action-gh-release@v2` 上传产物
- **触发**：`on: push: tags: ['v*']`
- **验证**：打 tag 后三端产物自动上传；`gh run view` 全绿

---

## 六、关键文件清单

| Sprint | 文件 | 修改内容 |
|--------|------|---------|
| 13 | src-tauri/src/lib.rs | 退出钩子调 stop_engine + 删死依赖插件 |
| 13 | engine_flask.py | CORS 收紧 + /debug/state 鉴权 |
| 13 | src-tauri/src/engine.rs | UTF-8 安全切片 + 默认拒绝 + safe_preview 函数 |
| 13 | src-tauri/src/commands.rs | UTF-8 安全切片 + fallback 拒绝 |
| 13 | src-tauri/src/db.rs | MD5→SHA-256 + hash_input 补全 + 旧库迁移 |
| 13 | src-tauri/Cargo.toml | md-5→sha2 + 删死依赖 |
| 14 | build_engine.py | Nuitka 跨平台条件化 + 编译期 key 注入 |
| 14 | anti_debug.py | 三端覆盖 + 检测增强 + 基线加固 |
| 14 | src/daoti_xuandun/secure_strings.py | 编译期常量 key |
| 14 | src/daoti_xuandun/config.py | 阈值加密包裹 |
| 14 | src/daoti_xuandun/_key_generated.py | 新增（gitignore） |
| 15 | LICENSE | 替换 MIT 为道体研究许可证 |
| 15 | LICENSE_CODE | 新增 Apache 2.0 |
| 15 | NOTICE | 新增核心算法范围声明 |
| 15 | 核心算法 .py 文件（13 个） | SPDX 头 |
| 15 | .gitignore | 新增 |
| 15 | archive/legacy_scripts/ | 临时脚本归档 |
| 15 | README.md | 重写许可证 + 架构章节 |
| 16 | src-tauri/tauri.conf.json | macOS/Linux bundle 段 |
| 16 | .github/workflows/release.yml | 三端 matrix CI |

---

## 七、验证方法

1. **Sprint 13**：
   - `cargo check` + `cargo test` 通过
   - 桌面端启动 → 关闭窗口 → 任务管理器确认 xuandun-engine 进程消失
   - 输入中文/emoji 长文本不 panic
   - 停引擎后 protect 返回 allowed=false
   - 浏览器跨域请求被拒；无 token 访问 /debug/state 返回 404
   - 篡改 db 记录后 hash chain 报断裂

2. **Sprint 14**：
   - `python build_engine.py` 三端成功
   - Nuitka 产物运行无 console
   - `pyinstxtractor` 无法提取（非 PyInstaller）
   - `strings xuandun-engine | grep threshold` 无明文
   - attach 调试器后引擎退出

3. **Sprint 15**：
   - GitHub 仓库 LICENSE 识别为道体研究许可证
   - LICENSE_CODE 识别为 Apache 2.0
   - 核心文件 SPDX 头存在
   - `git log` 单次提交，无临时脚本污染

4. **Sprint 16**：
   - 打 tag `v1.0.0` 触发 CI
   - `gh run view` 三端全绿
   - Release 页面有 4 个产物（Win NSIS + 2 Mac DMG + Linux AppImage + deb）
   - 下载各端安装包验证可运行

---

## 八、假设与决策

1. **仓库名**：默认 `xuandun`，可在 Sprint 15 执行前由用户指定其他名称
2. **Mac 架构策略**：分 ARM/Intel 两个 target（用户原计划批准），各自产 DMG；不做 Universal Binary（Tauri 对 Universal 支持尚不完善）
3. **道体许可证**：直接使用 DaoTi 仓库的 LICENSE 全文，修改 Section 1.1 资产清单为玄盾文件；保留禁止逆向/再分发条款
4. **旧库迁移**：用 `PRAGMA user_version` 检测，旧 MD5 记录标记 `chain_legacy` 跳过校验，不强制重新计算（保留历史数据完整性）
5. **临时脚本处理**：归档到 `archive/legacy_scripts/` 而非删除（保留历史可追溯）
6. **死依赖清理**：在 Sprint 13.6 完成，与严重问题修复一起验证

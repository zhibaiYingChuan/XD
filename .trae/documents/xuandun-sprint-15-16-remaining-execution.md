# 道体·玄盾 Sprint 15.2 - 16.2 剩余执行计划

**版本**: V4（基于 2026-07-09 续作探索验证）
**状态**: 待用户批准
**前序**: Sprint 14.3c ✅ / 14.2 ✅ / 15.1 ✅ 已完成

---

## 1. Summary 摘要

本计划覆盖从反逆向保护完成到三端二进制安装包发布的全部剩余工作，共 5 个 Sprint：

- **Sprint 15.2** — 13 个核心 .py 文件 SPDX 许可证头注入
- **Sprint 15.3** — .gitignore 创建 + 根目录临时脚本归档 + README 重写
- **Sprint 15.4** — git init + add remote + 首次提交（不含 push，push 待用户确认远程仓库已创建）
- **Sprint 16.1** — tauri.conf.json 新增 macOS/Linux bundle 段
- **Sprint 16.2** — GitHub Actions 三端 CI/CD workflow 创建

完成后将产出三端安装包（Windows NSIS / macOS DMG ×2 / Linux AppImage+deb）的自动化构建流水线。

---

## 2. Current State Analysis 当前状态分析

基于 Phase 1 探索（2026-07-09）实证验证：

### 2.1 Sprint 15.1 已完成（验证通过）
- `e:\smallloong\XuanDun\LICENSE` — 道体研究许可证 v1.0 适配版（238 行，13 个玄盾文件资产清单）
- `e:\smallloong\XuanDun\LICENSE_CODE` — Apache License 2.0 完整全文
- `e:\smallloong\XuanDun\NOTICE` — 双许可证声明

### 2.2 Sprint 15.2 起点：13 个核心文件均无 SPDX 头
Grep `SPDX-License-Identifier` 在 *.py 中 0 命中。需要为以下 13 个文件在首行注入头部：

**核心算法层（src/daoti_xuandun/，10 个）**:
1. reject_gate.py
2. preprocessors.py
3. config.py
4. xuandun.py
5. luoshu_mapper.py
6. secure_strings.py
7. timing_checker.py
8. dynamic_shell.py
9. ancient_mapper.py
10. atlas_mapping.py

**桌面端引擎层（desktop/xuandun-desktop/，3 个）**:
11. engine_flask.py
12. anti_debug.py
13. build_engine.py

### 2.3 Sprint 15.3 起点：仓库卫生待清理
- `.gitignore` **不存在**，需创建
- 根目录有 **40+ 临时 .py 脚本**（test_*.py / fix_*.py / decompile*.py / cleanup*.py / final_audit*.py / benchmark.py / demo.py / serve.py 等）
- 根目录有 **6 个 PowerShell/BAT 脚本**（_stop.ps1 / _check_procs.ps1 / _check_agents.ps1 / check_proc.ps1 / diag.bat / run_industry_benchmarks.ps1）
- `desktop/xuandun-desktop/tests/` 下有 **11 个临时测试脚本** + 6 个结果 txt
- 缓存目录：`__pycache__/` / `.pytest_cache/` / `.mypy_cache/` / `*.egg-info/` / `src-tauri/target/`
- `README.md` 当前 466 行，是面向 Python SDK 用户的文档，缺少开源元信息（许可证说明、三端下载、构建指南、贡献指南）

### 2.4 Sprint 15.4 起点：Git 仓库未初始化
- 无 `.git` 目录
- 无 remote 配置
- 目标仓库：`https://github.com/zhibaiYingChuan/xuandun`（LICENSE 第 236 行已声明）

### 2.5 Sprint 16.1 起点：tauri.conf.json 仅 Windows
当前 [tauri.conf.json](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/tauri.conf.json) `bundle` 段只有 `windows` 子段，缺 `macos` 和 `linux` 子段。`bundle.targets="all"` 会尝试构建所有平台但配置不全。

### 2.6 Sprint 16.2 起点：无 CI/CD
- `.github/workflows/` 目录不存在
- [build_engine.py](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/build_engine.py) 已支持三端平台检测（windows/darwin/linux），Nuitka 命令完整，含 macOS gui 模式参数
- `src-tauri/binaries/` 当前只有 `xuandun-engine-x86_64-pc-windows-msvc.exe`（CI 会按平台生成对应二进制）
- 图标资源齐全（.ico / .icns / PNG 各尺寸）
- [main.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/main.rs) 已配置 `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`

---

## 3. Proposed Changes 详细变更

### Sprint 15.2: 核心文件 SPDX 头注入

**目标**: 13 个核心 .py 文件首行加道体研究许可证声明，强化法律保护。

**变更**: 对以下 13 个文件，在首行（shebang `#!` 之后，模块 docstring 之前）插入：

```python
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件
```

**文件清单**（13 个，路径基于 e:\smallloong\XuanDun\）:
- src/daoti_xuandun/reject_gate.py
- src/daoti_xuandun/preprocessors.py
- src/daoti_xuandun/config.py
- src/daoti_xuandun/xuandun.py
- src/daoti_xuandun/luoshu_mapper.py
- src/daoti_xuandun/secure_strings.py
- src/daoti_xuandun/timing_checker.py
- src/daoti_xuandun/dynamic_shell.py
- src/daoti_xuandun/ancient_mapper.py
- src/daoti_xuandun/atlas_mapping.py
- desktop/xuandun-desktop/engine_flask.py
- desktop/xuandun-desktop/anti_debug.py
- desktop/xuandun-desktop/build_engine.py

**实现方式**: 用 Edit 工具对每个文件首行做精确替换。若文件以 `"""docstring"""` 开头，则在 docstring 之前插入；若以 `import` 开头，则在首行 import 之前插入。

**验证**: Grep `SPDX-License-Identifier: DaoTi-Research-1.0` 应返回 13 个文件。

---

### Sprint 15.3: 仓库卫生清理

#### 15.3a 创建 .gitignore

**文件**: `e:\smallloong\XuanDun\.gitignore`（新建）

**内容**: 综合 Python + Rust + Tauri + Nuitka + IDE 规则：

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.egg-info/
.eggs/
build/
dist/
.pytest_cache/
.mypy_cache/
.ruff_cache/
*.egg

# Virtual envs
.venv/
venv/
env/

# Nuitka build artifacts
*.build/
*.dist/
*.onefile-build/
src/daoti_xuandun/_key_generated.py

# Rust / Tauri
desktop/xuandun-desktop/src-tauri/target/
desktop/xuandun-desktop/node_modules/
desktop/xuandun-desktop/dist/
desktop/xuandun-desktop/src-tauri/binaries/*
!desktop/xuandun-desktop/src-tauri/binaries/.gitkeep

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
desktop_test_report.txt
test_report.json
security_stress_report.json
pylint_output.txt

# Logs
*.log

# Build outputs (kept out of git, released via GitHub Releases)
benchmark_results/
```

#### 15.3b 临时脚本归档

**目标**: 将根目录 ~40 个临时 .py + 6 个 shell 脚本移动到 `archive/legacy_scripts/`，保留历史但不清空根目录。

**归档清单**（根目录 → archive/legacy_scripts/）:

Python 脚本（40 个）:
- test_*.py (14): test_char_deviation, test_flask_latency, test_no_whitelist, test_core_perf2, test_core_perf, test_session3, test_session2, test_session, test_benchmark_attacks, test_extreme_attacks, test_hash2, test_hash, test_flask_server, desktop_xuandun_test（注：tests/ 目录下的正式 pytest 不动）
- fix_*.py (10): fix_ultimate, fix_all3, fix_comprehensive2, fix_all2, fix_final, fix_comprehensive, fix_all, fix_chars2, fix_chars, fix_encoding
- decompile*.py (3): decompile, decompile2, reject_gate_decompiled
- cleanup*.py (2): cleanup, cleanup2
- final_audit*.py (2): final_audit, final_audit2
- 其他 (9): detection_rate_test, mcp_perf_test, run_all_desktop_tests, mini_test, auto_test, quick_test, run_desktop_tests, env_check, debug_test, security_stress_test, run_benchmark, benchmark, demo, serve

Shell 脚本（6 个）:
- _stop.ps1, _check_procs.ps1, _check_agents.ps1, check_proc.ps1, diag.bat, run_industry_benchmarks.ps1

**desktop/xuandun-desktop/tests/ 清理**（11 个临时脚本 + 6 个 txt）:
- 移动到 `archive/legacy_scripts/desktop_tests/`: quick.py, quick2.py, debug_perf.py, perf_test.py, perf_test2.py, core_perf.py, mini_test.py, run_all_tests.py, test_engine_quick.py, test_mcp_server.py, test_engine_api.py
- 删除结果 txt: final_result.txt, mini_out.txt, mini_result.txt, full_result.txt, result.txt, test_result.txt, test_output.txt（这些是运行产物，无归档价值）

**保留在根目录的文件**:
- LICENSE, LICENSE_CODE, NOTICE, README.md, pyproject.toml, Dockerfile
- XuanDun.manifest.template
- 文档：玄盾.md, 开发计划.md, 6.5计划.md, 安全测试报告.md

**实现方式**: 用 Shell `mv` 命令批量移动（先 mkdir -p archive/legacy_scripts/desktop_tests），用 DeleteFile 删除 txt 产物。

#### 15.3c README 重写

**文件**: `e:\smallloong\XuanDun\README.md`（重写）

**新结构**（面向开源仓库访客，兼顾桌面端用户 + SDK 集成者）:

```markdown
# 道体·玄盾 (Daoti XuanDun)

> 活性防护 LLM 防火墙 — 为 AI 应用提供数据驱动的动态安全防护

[一句话介绍 + 核心特性 bullet]

## 核心特性
- 域距离 + 结构异常 + 4-gram 统计三重检测
- 拒绝门理论 + 洛书映射器 + 动态阴阳壳架构
- 在线学习，防御能力随使用持续增强
- 三端桌面应用（Windows / macOS / Linux）

## 下载安装
### 桌面端（推荐普通用户）
- Windows: 下载 `道体·玄盾_1.0.0_x64-setup.exe`
- macOS (Apple Silicon): 下载 `道体·玄盾_1.0.0_aarch64.dmg`
- macOS (Intel): 下载 `道体·玄盾_1.0.0_x64.dmg`
- Linux: 下载 `道体·玄盾_1.0.0_amd64.AppImage` 或 `.deb`

详见 [Releases](https://github.com/zhibaiYingChuan/xuandun/releases)

### Python SDK（开发者集成）
pip install -e .
（保留原 README 的 30 秒开箱即用 + 场景化配置速查表 + 命令行工具章节）

## 架构
（简要架构说明 + 指向 docs/白皮书.md）

## 性能基准
（保留原 README 的基准测试表 + 反馈回灌验证）

## 双许可证说明
本仓库采用分层许可证：
- **核心算法**（src/daoti_xuandun/*.py + desktop 三个 .py）受 [道体研究许可证 v1.0](LICENSE) 约束
  - 禁止逆向工程、反编译、再分发核心算法二进制
  - 商业使用需另行授权
- **外围代码**（Rust 桌面端、TypeScript 前端、配置、文档）受 [Apache 2.0](LICENSE_CODE) 约束
- 详见 [NOTICE](NOTICE)

## 从源码构建
### 环境要求
- Python 3.11+
- Rust 1.75+
- Node.js 20+
- Nuitka 2.x

### 构建步骤
1. 克隆仓库
2. cd desktop/xuandun-desktop
3. python build_engine.py  # 编译 Nuitka 引擎二进制
4. npm install
5. npm run tauri build  # 构建 Tauri 桌面应用

## 贡献
欢迎提交 Issue 和 PR。注意：核心算法修改需签署 CLA。

## 引用
如需在学术论文中引用本项目：
（BibTeX 条目）

## 联系方式
- 作者：独立研究者，知白
- Email: spring60@vip.qq.com
- Website: sfang.cc

## 安全声明
（保留原 README 的活性防护安全声明）
```

**实现方式**: 用 Write 工具完整重写 README.md，保留原 README 中的 SDK 用法、场景化配置、性能基准等有价值章节，新增开源元信息。

---

### Sprint 15.4: Git 仓库初始化与首次提交

**目标**: 初始化本地 git 仓库，准备推送（但不实际 push，待用户确认远程仓库已创建）。

**步骤**:

1. **初始化仓库**:
   ```bash
   git -C e:\smallloong\XuanDun init
   git -C e:\smallloong\XuanDun branch -M main
   ```

2. **配置 remote**:
   ```bash
   git -C e:\smallloong\XuanDun remote add origin https://github.com/zhibaiYingChuan/xuandun.git
   ```

3. **首次提交**（不 push）:
   ```bash
   git -C e:\smallloong\XuanDun add .
   git -C e:\smallloong\XuanDun commit -m "feat: 道体·玄盾 v1.0.0 开源首发

   - 核心算法：拒绝门 + 洛书映射器 + 动态阴阳壳
   - 桌面端：Tauri v2 + Nuitka 引擎 sidecar
   - 反逆向：三端 anti_debug + 编译期 key 注入 + 阈值加密
   - 双许可证：核心算法受道体研究许可证 v1.0 保护，外围代码 Apache 2.0
   - 三端构建：Windows NSIS / macOS DMG / Linux AppImage+deb"
   ```

4. **push 动作标记为待办**（不执行）:
   - 用户需先在 GitHub 上创建空仓库 `zhibaiYingChuan/xuandun`（不要 init README，避免冲突）
   - 创建后告知 AI，再执行 `git push -u origin main`

**验证**: `git log --oneline` 应显示 1 个 commit；`git remote -v` 应显示 origin 指向 xuandun 仓库。

---

### Sprint 16.1: tauri.conf.json 三端 bundle 配置

**文件**: [e:\smallloong\XuanDun\desktop\xuandun-desktop\src-tauri\tauri.conf.json](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/tauri.conf.json)

**变更**: 在 `bundle` 段新增 `macos` 和 `linux` 子段，保留现有 `windows` 段。

**新 bundle 段**:
```json
"bundle": {
  "active": true,
  "targets": "all",
  "icon": [
    "icons/32x32.png",
    "icons/128x128.png",
    "icons/128x128@2x.png",
    "icons/icon.icns",
    "icons/icon.ico"
  ],
  "externalBin": ["binaries/xuandun-engine"],
  "windows": {
    "certificateThumbprint": null,
    "digestAlgorithm": "sha256",
    "timestampUrl": "",
    "webviewInstallMode": {
      "type": "downloadBootstrapper"
    },
    "nsis": {
      "languages": ["SimpChinese", "English"],
      "displayLanguageSelector": true
    }
  },
  "macos": {
    "signingIdentity": null,
    "providerShortName": null,
    "entitlements": null
  },
  "linux": {
    "deb": {
      "depends": ["libwebkit2gtk-4.1-0", "libgtk-3-0"]
    },
    "appimage": {
      "bundle": true
    }
  }
}
```

**说明**:
- macOS `signingIdentity: null` — 暂不签名（用户未提供 Apple Developer ID），CI 会产出未签名 DMG，用户首次打开需在"系统设置 > 隐私与安全性"中允许
- Linux `deb.depends` — 声明 Tauri v2 所需的 WebKitGTK 4.1 运行时依赖
- `appimage.bundle: true` — 同时产出 AppImage（便携）和 deb（包管理）

**验证**: `npm run tauri build` 在三端 CI 上能识别配置并产出对应格式。

---

### Sprint 16.2: GitHub Actions 三端 CI/CD workflow

**文件**: `e:\smallloong\XuanDun\.github\workflows\release.yml`（新建）

**触发条件**:
- `push` tag `v*`（如 v1.0.0）— 自动发布 release
- `workflow_dispatch` — 手动触发测试构建

**Matrix 矩阵**:

| 平台 | Runner | 产出格式 | 二进制名后缀 |
|------|--------|----------|--------------|
| Windows x64 | `windows-latest` | NSIS .exe | xuandun-engine-x86_64-pc-windows-msvc.exe |
| macOS ARM64 | `macos-latest` (M1) | .dmg | xuandun-engine-aarch64-apple-darwin |
| macOS x64 | `macos-13` (Intel) | .dmg | xuandun-engine-x86_64-apple-darwin |
| Linux x64 | `ubuntu-22.04` | .AppImage + .deb | xuandun-engine-x86_64-unknown-linux-gnu |

**Job 步骤**（每个平台相同结构）:

```yaml
name: Release

on:
  push:
    tags: ['v*']
  workflow_dispatch:

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: windows-latest
            target: x86_64-pc-windows-msvc
          - os: macos-latest
            target: aarch64-apple-darwin
          - os: macos-13
            target: x86_64-apple-darwin
          - os: ubuntu-22.04
            target: x86_64-unknown-linux-gnu

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Setup Node 20
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Setup Rust stable
        uses: dtolnay/rust-toolchain@stable

      - name: Install Nuitka + Python deps (Windows/Linux)
        if: runner.os != 'macOS'
        run: |
          python -m pip install --upgrade pip
          pip install nuitka numpy
          pip install -e .

      - name: Install Nuitka + Python deps (macOS)
        if: runner.os == 'macOS'
        run: |
          python -m pip install --upgrade pip
          pip install nuitka numpy
          pip install -e .

      - name: Install Linux system deps
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev

      - name: Build Nuitka engine
        working-directory: desktop/xuandun-desktop
        run: python build_engine.py

      - name: Install frontend deps
        working-directory: desktop/xuandun-desktop
        run: npm ci

      - name: Build Tauri app
        working-directory: desktop/xuandun-desktop
        run: npm run tauri build
        env:
          TAURI_SIGNING_PRIVATE_KEY: ''

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: xuandun-${{ matrix.target }}
          path: |
            desktop/xuandun-desktop/src-tauri/target/release/bundle/**/*.exe
            desktop/xuandun-desktop/src-tauri/target/release/bundle/**/*.dmg
            desktop/xuandun-desktop/src-tauri/target/release/bundle/**/*.AppImage
            desktop/xuandun-desktop/src-tauri/target/release/bundle/**/*.deb

  release:
    needs: build
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: artifacts
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: artifacts/**/*
```

**关键决策**:
- `fail-fast: false` — 一个平台失败不影响其他平台继续构建
- macOS 分两个 runner（`macos-latest` ARM + `macos-13` Intel）而非用 lipo 合并 universal binary，因为 Nuitka 不原生支持 universal binary，分别构建更稳定
- `TAURI_SIGNING_PRIVATE_KEY: ''` — 暂不启用 updater 签名（updater 配置后续单独处理）
- Linux 用 `ubuntu-22.04` 而非 `ubuntu-latest`，因为 WebKitGTK 4.1 在 22.04 上更稳定
- `release` job 仅在 tag 触发时运行，`workflow_dispatch` 仅产出 artifact 不发 release

**验证**: 
1. `workflow_dispatch` 手动触发，4 个平台均产出 artifact
2. 推送 `v1.0.0` tag，自动创建 GitHub Release 并附带 7 个安装包（1 exe + 2 dmg + 1 AppImage + 1 deb + 2 个其他）

---

## 4. Assumptions & Decisions 假设与决策

### 决策（已定，无需再问）
1. **仓库名**: `xuandun`（LICENSE 第 236 行已声明 `https://github.com/zhibaiYingChuan/xuandun`）
2. **双许可证**: 核心算法道体研究许可证 + 外围代码 Apache 2.0（Sprint 15.1 已完成）
3. **SPDX 标识符**: `DaoTi-Research-1.0`（自定义标识符，与 LICENSE 文件对应）
4. **三端构建**: GitHub Actions matrix CI/CD（用户已批准）
5. **macOS 签名**: 暂不签名（用户未提供 Apple Developer ID），DMG 未签名但可用
6. **Tauri updater**: 暂不启用签名（pubkey 为空），updater 配置保留但 CI 不注入 signing key
7. **临时脚本归档**: 移动到 `archive/legacy_scripts/` 而非删除，保留历史

### 假设（需用户在 NotifyUser 阶段确认）
1. **远程仓库未创建**: 假设用户尚未在 GitHub 上创建 `zhibaiYingChuan/xuandun` 空仓库。Sprint 15.4 会执行 git init + commit + add remote，但 **不执行 push**。用户需手动创建空仓库后，再触发 push。
2. **README 重写方向**: 假设 README 应同时面向桌面端用户（下载安装包）和 SDK 集成者（pip install），但桌面端优先。
3. **benchmark.py / demo.py / serve.py 归档**: 假设这三个文件是临时演示脚本而非核心入口（核心入口是 `python -m daoti_xuandun` 和 `daoti_xuandun.manage`），归档到 archive。若用户认为应保留在根目录，请在 NotifyUser 阶段说明。
4. **tests/ 目录正式 pytest 不动**: 假设 `tests/test_*.py`（test_reject_gate / test_xuandun / test_s6_verify / test_audit_deep / test_ancient_mapper / test_dynamic_shell / test_timing_checker）是正式单元测试，保留在原位。仅移动 `desktop/xuandun-desktop/tests/` 下的临时脚本。

---

## 5. Verification Steps 验证清单

### Sprint 15.2 验证
- [ ] `Grep "SPDX-License-Identifier: DaoTi-Research-1.0"` 返回 13 个文件
- [ ] 每个文件首行均为 SPDX 头，不影响后续 import / docstring

### Sprint 15.3 验证
- [ ] `.gitignore` 存在且包含 Python / Rust / Tauri / Nuitka 规则
- [ ] `archive/legacy_scripts/` 目录存在，包含 ~46 个临时脚本
- [ ] `archive/legacy_scripts/desktop_tests/` 包含 11 个临时测试脚本
- [ ] 根目录仅保留核心文件（LICENSE* / NOTICE / README / pyproject / Dockerfile / 文档 .md）
- [ ] README.md 新增"下载安装""双许可证说明""从源码构建""贡献"章节

### Sprint 15.4 验证
- [ ] `git status` 显示 clean working tree
- [ ] `git log --oneline` 显示 1 个 commit
- [ ] `git remote -v` 显示 origin → https://github.com/zhibaiYingChuan/xuandun.git
- [ ] **push 动作未执行**，待用户确认远程仓库已创建

### Sprint 16.1 验证
- [ ] tauri.conf.json `bundle` 段包含 `windows` + `macos` + `linux` 三个子段
- [ ] JSON 语法有效（`python -c "import json; json.load(open('tauri.conf.json'))"` 无异常）

### Sprint 16.2 验证
- [ ] `.github/workflows/release.yml` 存在
- [ ] YAML 语法有效（`python -c "import yaml; yaml.safe_load(open('release.yml'))"` 无异常）
- [ ] matrix 包含 4 个平台条目
- [ ] release job 有 `permissions: contents: write`

---

## 6. 执行顺序

1. Sprint 15.2（SPDX 头，13 个文件 Edit）
2. Sprint 15.3a（创建 .gitignore）
3. Sprint 15.3b（临时脚本归档，Shell mv + DeleteFile）
4. Sprint 15.3c（README 重写，Write）
5. Sprint 15.4（git init + commit，不 push）
6. Sprint 16.1（tauri.conf.json 新增 macos/linux 段）
7. Sprint 16.2（创建 release.yml）
8. 最终验证 + 通知用户创建远程仓库并 push

每个 Sprint 完成后用 TaskUpdate 标记任务状态，最后统一汇报。

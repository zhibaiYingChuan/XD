# 玄盾（XuanDun）桌面端 HCSE 发布合规检查报告 — Sprint4

> 文档版本：v1.0
> 生成时间：2026-08-01 (Asia/Shanghai)
> 审计范围：Sprint4 修复变更（11 项）+ CI/CD 发布流水线 + 仓库卫生
> 审计依据：HCSE 8 阶段可信交付框架 + 项目通用规则（动态差异范式）
> 审计结论：**禁止发布（BLOCK）** — 存在 5 项 P0 阻断项必须先修复

---

## PHASE 0：HCSE 可信交付基线（强制声明）

本报告以下列 5 条核心原则为唯一裁决基准，所有 PASS/FAIL 判定均追溯至此：

| # | 原则 | 在本项目的具体含义 |
|---|------|------------------|
| 1 | 构建可复现 | 同一 `v*` tag + 同一 commit SHA，在 GitHub-hosted runner 上无论何时构建，必须产出 SHA256 一致的二进制 |
| 2 | 构建可追溯 | 每个 Release 资产必须能追溯到具体 commit SHA、CI Job ID、workflow run URL |
| 3 | 最小权限 | 每个 job/step 仅拥有其必需的最小权限；仅 release job 持有 `contents: write` |
| 4 | 故障隔离 | CI 失败不得污染仓库状态、泄漏 secrets、产生不可逆副作用（如误推 tag、误删分支） |
| 5 | 供应链完整性 | 所有第三方 Actions 必须以 full commit SHA 固定；构建必须产出可验证的 SLSA provenance |

**当前状态：5 条原则中 4 条被违反（仅"故障隔离"基本满足）→ 触发 BLOCK 判定。**

---

## 一、执行摘要

### 1.1 Sprint4 代码修复验证结论：11/11 PASS

所有 Sprint4 修复在代码层面已正确落实，diff 验证通过，逻辑正确。

### 1.2 发布流水线合规结论：BLOCK

虽然代码修复本身合格，但**发布流水线与仓库卫生存在 5 项 P0 阻断项**，若直接打 tag 推送将导致：
- 供应链攻击面（7 个 Actions 未 pin SHA）
- 修复文件未提交（GAP-01 ConfirmModal.tsx、icons/、sync_version.py 等仍是 `??`/`M` 状态）
- 发布资产 SHA256 不可验证
- 无 SLSA provenance，无法满足企业供应链审计要求

### 1.3 阻断项速览

| ID | 类别 | 阻断项 | 风险等级 | 修复成本 |
|----|------|--------|---------|---------|
| B-01 | 仓库卫生 | Sprint4 修复文件未 git add/commit（ConfirmModal.tsx、icons/、sync_version.py 等） | P0 | 低 |
| B-02 | 供应链 | release.yml 中 7 个 Actions 用 `@v5/@v6/@stable/@v2` 标签，未 pin SHA | P0 | 中 |
| B-03 | 安全加固 | 无 `step-security/harden-runner`，无出网过滤 | P0 | 中 |
| B-04 | 完整性 | 无 SHA256 校验文件生成、无 SLSA provenance、无 verify job | P0 | 中 |
| B-05 | 文档治理 | 缺失 SECURITY.md / CODEOWNERS / ci.yml / PR 模板 / PRE_PUSH_CHECKLIST.md | P0 | 中 |

---

## 二、发布合规检查清单（PASS / FAIL）

### 2.1 Sprint4 代码修复验证（11/11 PASS）

| # | 变更项 | 文件 | 验证方法 | 结果 | 证据 |
|---|--------|------|---------|------|------|
| 1 | CSP 根因修复 | `tauri.conf.json:29` | git diff 验证 connect-src | PASS | 已添加 `http://ipc.localhost`（Tauri v2 IPC 自定义协议要求） |
| 2 | GAP-01 ConfirmModal 队列化 | `ConfirmModal.tsx:85-131` | 阅读 useConfirmModal 实现 | PASS | `queueRef` + `showNext` + `handleConfirm/handleCancel` 正确出队，避免并发 Promise 永挂 |
| 3 | GAP-02 引擎超时 15s→60s | `tauriApi.ts:357-358` | 验证 restartEngine/stopEngine 调用 | PASS | 均使用 `TIMEOUT.SLOW` (60_000ms)，匹配引擎实际重启耗时 |
| 4 | GAP-03 restoreSnapshot 防抖守卫 | `Settings.tsx:133,520-535` | 验证 restoringSnapshot 状态守卫 | PASS | 入口 `if (restoringSnapshot) return` + finally 释放 + 按钮 disabled 绑定 |
| 5 | GAP-04 save_notifier_config 不吞错 | `commands.rs:747-776` | 验证 engine_post 错误传播 | PASS | 第 770-774 行：失败时 `eprintln!` + 返回中文 Err，DB 已保存但引擎未同步 |
| 6 | GAP-05 set_mode 不吞错 | `commands.rs:208-228` | 验证 sync_mode_to_engine 错误传播 | PASS | 第 221-228 行：失败时仍写 DB+审计，但返回 Err 让前端感知 |
| 7 | GAP-06 向导跳过统一 DB | `Dashboard.tsx:122-124,349-351` | 验证 localStorage 移除 | PASS | onSkip 改用 `api.setConfig('wizard_completed', 'true')`，消除双套机制 |
| 8 | GAP-07 DB 打开失败中文路径 | `lib.rs:75-84` | 验证错误消息内容 | PASS | 提供 4 条可操作修复建议（磁盘/权限/删除/管理员） |
| 9 | R15 超时提示增强 | `tauriApi.ts:303-307` | 验证 InvokeTimeoutError 分支 | PASS | 提示"可能仍在后台执行，请等待 30 秒后再重试"，避免立即重试引发竞态 |
| 10 | keyring.rs unused variable | `keyring.rs:6-15` | git diff + 阅读源码 | PASS | `Ok(_stored)` 使用下划线前缀消除 warning；附带 NEW-P1-01 存储后验证增强 |
| 11 | icons 重新生成 | `src-tauri/icons/*` | git diff --stat | PASS | 7 个图标文件已重新生成（128x128.png 等），icon.ico 246→145503 bytes |

### 2.2 发布流水线 HCSE 合规（5 PASS / 9 FAIL）

| 检查项 | HCSE 阶段 | 结果 | 详情 |
|--------|----------|------|------|
| 触发条件 `tags: ['v*']` | P3 | PASS | release.yml:5 正确配置 |
| workflow_dispatch 手动触发 | P3 | PASS | release.yml:6 提供 fallback |
| build job 显式 permissions | P4 | **FAIL** | build job 无 permissions 块（仅 release job 有 `contents: write`）→ 默认继承 repo 权限，违反最小权限 |
| 所有 Actions pin SHA | P4 | **FAIL** | 7 个 Actions 全部用标签：`actions/checkout@v5`、`actions/setup-python@v6`、`actions/setup-node@v5`、`dtolnay/rust-toolchain@stable`、`actions/upload-artifact@v6`、`actions/download-artifact@v6`、`softprops/action-gh-release@v2` |
| harden-runner 出网过滤 | P4 | **FAIL** | 0 个 step 使用 `step-security/harden-runner` |
| 跨平台矩阵完整性 | P3 | **FAIL** | 仅 3 个目标（windows-x86_64、macos-arm64、ubuntu-x86_64），缺失 macOS-x86_64、Linux-ARM64、Windows-ARM64 |
| SHA256 校验文件生成 | P0/P5 | **FAIL** | 无 `sha256sum` 步骤，发布资产无法完整性校验 |
| SLSA provenance | P5 | **FAIL** | 未集成 `actions/attest-build-provenance` |
| verify job | P3 | **FAIL** | 无独立的二进制回下载 + SHA256 比对 job |
| release job 权限隔离 | P4 | PASS | release.yml:92-93 仅 release job 持 `contents: write` |
| release 依赖 build 全部通过 | P3 | **WARN** | release.yml:90 使用 `if: always()`，build 部分失败仍会发布 → 违反故障隔离（应改 `needs: build` 默认语义或 `if: success() && ...`） |
| 版本一致性 SSOT 门禁 | P3 | PASS | release.yml:25-27 已加 `python sync_version.py --check`（但 sync_version.py 是未跟踪文件，会 fail） |
| 工具链版本固定 | P3 | **WARN** | Node 24 / Python 3.11 / Rust stable 已指定，但 Rust 用 `stable` 浮动标签（应改为 `1.82.0` 等具体版本） |
| 凭据与 secret 处理 | P4 | PASS | 当前 workflow 未引用任何 secret（macOS/windows 均未签名），无泄漏面 |

### 2.3 仓库卫生与文档治理（3 PASS / 7 FAIL）

| 检查项 | 结果 | 详情 |
|--------|------|------|
| `.gitignore` 非白名单模式 | PASS | 使用标准排除模式，未使用 `*` 通配 |
| 版本号三处一致 | PASS | tauri.conf.json=1.2.3 / package.json=1.2.3 / Cargo.toml=1.2.3 |
| Sprint4 修复文件全部已提交 | **FAIL** | 见 §2.4 |
| `ci.yml` PR 验证流水线 | **FAIL** | `.github/workflows/` 仅 release.yml，无 ci.yml |
| `SECURITY.md` 漏洞披露策略 | **FAIL** | 仓库根目录无此文件 |
| `.github/CODEOWNERS` | **FAIL** | 无此文件，`.github/workflows/` 修改无强制 DevOps 审批 |
| `.github/pull_request_template.md` | **FAIL** | 无此文件，PR 无自检清单约束 |
| `PRE_PUSH_CHECKLIST.md` | **FAIL** | 无此文件 |
| `docs/HCSE_RELEASE_PROTOCOL.md` | **FAIL** | 项目专属检查清单文档缺失 |
| 工作树无开发垃圾文件 | **FAIL** | 50+ 个 `??` 文件（cdp_*.py、cargo_build_log*.txt、daoti-xuandun.zip、target/ 等） |

### 2.4 Sprint4 修复文件 git 状态（B-01 阻断详情）

> 审计时间点工作树状态：所有 Sprint4 修复**均未 commit**，打 tag 前必须先完成提交。

| 文件 | 状态 | 影响 |
|------|------|------|
| `desktop/xuandun-desktop/src-tauri/tauri.conf.json` | M | CSP 修复未提交 → tag 构建仍是旧 CSP |
| `desktop/xuandun-desktop/src-tauri/src/commands.rs` | M | GAP-04/05 未提交 → tag 构建仍吞错 |
| `desktop/xuandun-desktop/src-tauri/src/lib.rs` | M | GAP-07 未提交 |
| `desktop/xuandun-desktop/src-tauri/src/keyring.rs` | M | unused variable 修复未提交 |
| `desktop/xuandun-desktop/src/services/tauriApi.ts` | M | GAP-02/R15 未提交 |
| `desktop/xuandun-desktop/src/pages/Settings.tsx` | M | GAP-03 未提交 |
| `desktop/xuandun-desktop/src/pages/Dashboard.tsx` | M | GAP-06 未提交 |
| `desktop/xuandun-desktop/src-tauri/icons/*` | M/?? | 7 个图标已改 + 14 个新图标未跟踪 → **打包会缺失图标** |
| `desktop/xuandun-desktop/src/components/ConfirmModal.tsx` | **??** | GAP-01 修复文件未 git add → tag 构建会编译失败（被 import） |
| `desktop/xuandun-desktop/src/pages/YinYangGate.tsx` | **??** | 新页面未 git add → 路由引用会编译失败 |
| `desktop/xuandun-desktop/sync_version.py` | **??** | release.yml:27 调用此脚本，未跟踪 → **CI 必 fail** |
| `desktop/xuandun-desktop/public/logo.jpg` | **??** | icons 重新生成的源文件未跟踪 |

---

## 三、变更影响分析（Sprint4 11 项修复）

### 3.1 影响分级

| 等级 | 定义 | Sprint4 项数 |
|------|------|-------------|
| 高（发布阻断） | 不修复会导致编译失败/运行时崩溃/安全漏洞 | 4 |
| 中（用户体验） | 不修复会导致 UX 异常但可运行 | 5 |
| 低（代码质量） | 不影响功能，仅影响可维护性 | 2 |

### 3.2 逐项影响分析

#### 3.2.1 CSP 根因修复（高，发布阻断）
- **变更**：`tauri.conf.json` connect-src 新增 `http://ipc.localhost`
- **根因**：Tauri v2 在 Windows WebView2 上使用 `http://ipc.localhost` 作为 IPC 端点，缺失会导致所有 `invoke()` 调用被 CSP 阻断
- **影响范围**：所有 Tauri 命令调用（约 40 个 invoke 点）
- **验证建议**：构建后用 WebView2 DevTools 检查 Console 无 CSP 违规
- **回归风险**：低（仅放宽 connect-src，未触碰 script-src）

#### 3.2.2 GAP-01 ConfirmModal 队列化（高，发布阻断）
- **变更**：`useConfirmModal` 由单实例改为 `queueRef` 队列
- **根因**：并发 confirm 调用时第二个会覆盖第一个的 resolve，导致首个 Promise 永挂
- **影响范围**：Settings.tsx 6 处 confirm 调用、Dashboard.tsx 1 处
- **验证建议**：自动化测试连续触发 3 个 confirm，验证全部 resolve
- **回归风险**：低（API 兼容，`modalProps`/`confirm` 签名不变）

#### 3.2.3 GAP-02 引擎超时 60s（中，用户体验）
- **变更**：restartEngine/stopEngine 从 15s → 60s
- **根因**：Nuitka 打包的引擎冷启动 + Flask 初始化实际耗时 20-40s，15s 必然超时
- **影响范围**：Settings.tsx 引擎管理卡片
- **验证建议**：冷启动场景实测耗时，确认 60s 足够
- **回归风险**：低（仅延长超时阈值）

#### 3.2.4 GAP-03 restoreSnapshot 防抖守卫（中，用户体验）
- **变更**：新增 `restoringSnapshot` state，入口守卫 + 按钮 disabled
- **根因**：恢复快照期间用户重复点击会触发并发恢复，配置被互相覆盖
- **影响范围**：Settings.tsx 快照恢复按钮
- **验证建议**：连续双击恢复按钮，验证只触发一次
- **回归风险**：极低

#### 3.2.5 GAP-04 save_notifier_config 不吞错（高，发布阻断）
- **变更**：engine_post 失败时返回 Err
- **根因**：原代码 `let _ = engine_post(...)` 吞掉错误，DB 已保存但引擎未同步，用户误以为配置生效
- **影响范围**：通知渠道配置（钉钉/飞书/邮件/webhook/syslog）
- **验证建议**：停用引擎后保存通知配置，验证前端显示"引擎同步失败"提示
- **回归风险**：中（错误传播路径变化，需确认前端 catch 块正确处理）

#### 3.2.6 GAP-05 set_mode 不吞错（高，发布阻断）
- **变更**：sync_mode_to_engine 失败时返回 Err，但仍写 DB
- **根因**：同 GAP-04，吞错导致用户误以为模式已切换
- **影响范围**：Settings.tsx 模式切换 + Dashboard 模式显示
- **验证建议**：停用引擎后切换模式，验证前端回滚 + 错误提示
- **回归风险**：中（DB 已写但返回 Err，需确认前端不会错误回滚 DB 状态）

#### 3.2.7 GAP-06 向导跳过统一 DB（中，用户体验）
- **变更**：onSkip 改用 `api.setConfig('wizard_completed', 'true')`，移除 localStorage
- **根因**：localStorage 与 DB config 双套机制不同步，导致向导重复弹出
- **影响范围**：Dashboard.tsx 向导显示逻辑
- **验证建议**：点击跳过后重启应用，验证向导不再弹出
- **回归风险**：低

#### 3.2.8 GAP-07 DB 打开失败中文路径（中，用户体验）
- **变更**：lib.rs setup 闭包中 DB open 失败返回中文修复建议
- **根因**：原代码直接 `exit(1)`，用户无任何提示
- **影响范围**：应用启动流程
- **验证建议**：故意损坏 DB 文件，验证启动失败时显示中文提示
- **回归风险**：极低

#### 3.2.9 R15 超时提示增强（低，代码质量）
- **变更**：formatInvokeError 在 InvokeTimeoutError 分支增加"30 秒后重试"提示
- **根因**：超时后底层 Promise 仍可能执行，立即重试会引发竞态
- **影响范围**：所有 invoke 调用的错误提示
- **回归风险**：极低

#### 3.2.10 keyring.rs unused variable（低，代码质量）
- **变更**：`Ok(stored)` → `Ok(_stored)` 消除 warning + 附带 NEW-P1-01 存储后验证
- **根因**：clippy/rustc warning 影响构建清洁度
- **影响范围**：密钥存储流程
- **验证建议**：`cargo build --release` 无 warning
- **回归风险**：低（新增验证逻辑，可能因系统凭据管理器异常导致误报）

#### 3.2.11 icons 重新生成（高，发布阻断）
- **变更**：用 `public/logo.jpg` 通过 `npx tauri icon` 重新生成全尺寸图标
- **根因**：旧图标为占位符，发布包视觉不专业
- **影响范围**：Windows 安装包 NSIS 图标、macOS .dmg、Linux AppImage、任务栏图标、托盘图标
- **验证建议**：构建后检查安装包图标显示正确
- **回归风险**：低（仅替换资源文件）

---

## 四、依赖完整性验证

### 4.1 修改的 CI 步骤前置依赖

| CI 步骤 | 前置依赖 | 验证状态 |
|---------|---------|---------|
| `python sync_version.py --check` (release.yml:25-27) | 文件 `desktop/xuandun-desktop/sync_version.py` 存在且可执行 | **FAIL** — 文件为 `??` 未跟踪，CI checkout 后不存在，必 fail |
| `npm run tauri build` (release.yml:64) | `dist/` 前端产物 + `src-tauri/icons/*` 图标 + `src-tauri/binaries/xuandun-engine-*.exe` | **WARN** — icons 14 个新文件未跟踪；engine 二进制为 134 bytes 占位符（实际 47MB） |
| `python build_engine.py` (release.yml:56) | `engine_flask.py` + Nuitka + waitress + Flask + numpy | PASS — pyproject.toml `[engine]` extras 已配置 |
| `npm ci` (release.yml:60) | `package-lock.json` | PASS — lockfile 已存在 |
| `cargo build` (隐式于 tauri build) | `Cargo.lock` + Rust toolchain | PASS — Cargo.lock 已存在 |

### 4.2 构建产物链路验证

```
[源码]
  ├─ npm run build (tsc && vite build)
  │   └─ dist/                    → 前端静态资源
  │       └─ 注入 tauri.conf.json CSP 到 HTML meta
  │
  ├─ python build_engine.py (Nuitka)
  │   └─ src-tauri/binaries/xuandun-engine-x86_64-pc-windows-msvc.exe
  │       └─ engine_flask.py + waitress + Flask 打包
  │
  └─ npm run tauri build
      ├─ cargo build --release
      │   └─ src-tauri/target/release/xuandun-desktop.exe
      └─ tauri bundler
          ├─ NSIS (Windows)   → .exe 安装包
          ├─ dmg (macOS)       → .dmg
          ├─ appimage (Linux)  → .AppImage
          └─ deb (Linux)       → .deb
```

**链路断点**：
1. `sync_version.py` 未跟踪 → CI 第一步 fail
2. 14 个图标文件未跟踪 → tauri bundler 找不到图标资源
3. `xuandun-engine-*.exe` 在仓库中是 134 bytes 占位符（应为 47MB Nuitka 产物）→ 需 CI 现场构建，但 build_engine.py 输出路径需与 `externalBin` 配置匹配

### 4.3 引擎依赖验证

| 依赖 | 本地 | CI | 一致性 |
|------|------|-----|-------|
| Python | 3.x | 3.11 (setup-python@v6) | WARN — 本地版本未固定，可能 3.12+，Nuitka 兼容性需验证 |
| waitress | 本地装 | `pip install -e ".[engine]"` | PASS — pyproject.toml 已声明 |
| Flask | 本地装 | 同上 | PASS |
| numpy | 本地装 | `pip install nuitka numpy` 显式 | PASS |
| Nuitka | 本地装 | 同上 | PASS |
| Node.js | 本地装 | 24 (setup-node@v5) | PASS |
| Rust | 本地 1.x | stable (dtolnay/rust-toolchain@stable) | **WARN** — stable 浮动，应固定为 1.82.0 |
| libwebkit2gtk-4.1 | N/A | apt 安装 | PASS |

---

## 五、环境差异风险清单

### 5.1 本地 vs CI 环境差异

| 维度 | 本地环境 | CI 环境 | 风险 | 缓解建议 |
|------|---------|--------|------|---------|
| OS | Windows + PowerShell | ubuntu-22.04/macos-latest/windows-latest | 低 | 已有 matrix 覆盖 |
| Rust 版本 | 本地 1.x（未固定） | stable 浮动 | 中 | 改为 `1.82.0` 固定版本 |
| Cargo 缓存 | `G:\rust-target` 本地缓存 | 无缓存，全量编译 | 中 | 加 `Swatinem/rust-cache@<sha>` 加速 |
| Python venv | 本地 `.venv/` | CI 临时 venv | 低 | setup-python 自动管理 |
| 系统凭据管理器 | Windows Credential Manager | CI 无（GitHub-hosted） | 低 | keyring 在 CI 无需可用，仅运行时需要 |
| 引擎二进制 | 本地 47MB | CI 现场构建 | 中 | build_engine.py 必须在 CI 可重现 |
| 图标资源 | 本地已生成 | CI 从 git 读取 | **高** | 14 个图标未 git add，CI 构建会缺图标 |
| Node modules | 本地 `node_modules/` | CI `npm ci` 全新装 | 低 | lockfile 保证一致 |
| Tauri CLI | 本地 `@tauri-apps/cli@^2.11.4` | 同 | 低 | lockfile 固定 |

### 5.2 本地有但 CI 无的关键资源（B-01 根因）

以下文件本地存在但**未提交 git**，CI checkout 后不存在：

| 文件 | 类型 | CI 影响 |
|------|------|--------|
| `desktop/xuandun-desktop/sync_version.py` | Python 脚本 | release.yml:27 调用必 fail |
| `desktop/xuandun-desktop/src/components/ConfirmModal.tsx` | TSX 组件 | Dashboard/Settings import 必编译失败 |
| `desktop/xuandun-desktop/src/pages/YinYangGate.tsx` | TSX 页面 | 路由 import 必编译失败 |
| `desktop/xuandun-desktop/src-tauri/icons/Square*.png` (14 个) | 图标资源 | tauri bundler 找不到 Windows 商店图标 |
| `desktop/xuandun-desktop/src-tauri/icons/android/*` | Android 图标 | Android 构建失败（当前 matrix 无 Android，影响小） |
| `desktop/xuandun-desktop/src-tauri/icons/ios/*` | iOS 图标 | iOS 构建失败（当前 matrix 无 iOS，影响小） |
| `desktop/xuandun-desktop/public/logo.jpg` | 图标源 | 重新生成图标时缺失 |

---

## 六、CI/CD 安全加固建议

### 6.1 P0 必须修复（发布前）

#### 6.1.1 B-01：提交所有 Sprint4 修复文件

```powershell
# 在 h:\XuanDun 目录执行
git add desktop/xuandun-desktop/src-tauri/tauri.conf.json `
        desktop/xuandun-desktop/src-tauri/src/commands.rs `
        desktop/xuandun-desktop/src-tauri/src/lib.rs `
        desktop/xuandun-desktop/src-tauri/src/keyring.rs `
        desktop/xuandun-desktop/src-tauri/src/engine.rs `
        desktop/xuandun-desktop/src-tauri/src/proxy.rs `
        desktop/xuandun-desktop/src-tauri/Cargo.toml `
        desktop/xuandun-desktop/src-tauri/Cargo.lock `
        desktop/xuandun-desktop/src-tauri/icons/ `
        desktop/xuandun-desktop/src/services/tauriApi.ts `
        desktop/xuandun-desktop/src/components/ConfirmModal.tsx `
        desktop/xuandun-desktop/src/pages/Settings.tsx `
        desktop/xuandun-desktop/src/pages/Dashboard.tsx `
        desktop/xuandun-desktop/src/pages/YinYangGate.tsx `
        desktop/xuandun-desktop/sync_version.py `
        desktop/xuandun-desktop/public/logo.jpg `
        desktop/xuandun-desktop/package.json `
        desktop/xuandun-desktop/package-lock.json `
        desktop/xuandun-desktop/src/App.tsx `
        desktop/xuandun-desktop/src/App.css `
        .github/workflows/release.yml
```

**禁止 `git add -A`**：工作树有 50+ 个开发垃圾文件（cdp_*.py、cargo_build_log*.txt、daoti-xuandun.zip），全量添加会污染仓库。

#### 6.1.2 B-02：所有 Actions 改为 full commit SHA 固定

需替换的 7 个 Actions（示例 SHA 为参考值，**发布前必须自行验证最新稳定 commit**）：

```yaml
# 替换前（不安全）
- uses: actions/checkout@v5
# 替换后（安全）
- uses: actions/checkout@<full-40-char-SHA>  # v5.x
```

| Action | 当前标签 | 建议固定方式 |
|--------|---------|------------|
| `actions/checkout` | @v5 | 查询 releases，取最新 v5.x 的 commit SHA |
| `actions/setup-python` | @v6 | 同上 |
| `actions/setup-node` | @v5 | 同上 |
| `dtolnay/rust-toolchain` | @stable | 改为 `@<sha>` 并显式指定 `toolchain: 1.82.0` |
| `actions/upload-artifact` | @v6 | 同上 |
| `actions/download-artifact` | @v6 | 同上 |
| `softprops/action-gh-release` | @v2 | 同上 |

新增建议 Actions（同样需 pin SHA）：
- `step-security/harden-runner@<sha>`
- `actions/attest-build-provenance@<sha>`
- `Swatinem/rust-cache@<sha>`

#### 6.1.3 B-03：每个 job 首步加 harden-runner

```yaml
jobs:
  build:
    runs-on: ${{ matrix.os }}
    permissions:
      contents: read
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@<sha>
        with:
          egress-policy: audit
          allowed-endpoints: >
            github.com:443
            static.rust-lang.org:443
            crates.io:443
            index.crates.io:443
            registry.npmjs.org:443
            pypi.org:443
            files.pythonhosted.org:443
            objects.githubusercontent.com:443
      - uses: actions/checkout@<sha>
```

#### 6.1.4 B-04：补全 SHA256 + SLSA + verify job

在 build job 末尾增加：

```yaml
      - name: Generate SHA256 checksums
        shell: bash
        run: |
          cd desktop/xuandun-desktop/src-tauri/target/release/bundle
          find . -type f \( -name "*.exe" -o -name "*.dmg" -o -name "*.AppImage" -o -name "*.deb" \) \
            -exec sha256sum {} \; > checksums-${{ matrix.target }}.txt
          cat checksums-${{ matrix.target }}.txt

      - name: Upload checksums
        uses: actions/upload-artifact@<sha>
        with:
          name: checksums-${{ matrix.target }}
          path: desktop/xuandun-desktop/src-tauri/target/release/bundle/checksums-*.txt
```

在 release job 增加 SLSA attestation：

```yaml
  release:
    needs: build
    if: success() && startsWith(github.ref, 'refs/tags/v')  # 改 always() → success()
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write      # SLSA attestation 必需
      attestations: write  # SLSA attestation 必需
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/download-artifact@<sha>
        with:
          path: artifacts
      - name: Create GitHub Release
        uses: softprops/action-gh-release@<sha>
        with:
          generate_release_notes: true
          files: |
            artifacts/**/*.exe
            artifacts/**/*.dmg
            artifacts/**/*.AppImage
            artifacts/**/*.deb
            artifacts/**/checksums-*.txt
      - name: Generate SLSA build provenance
        uses: actions/attest-build-provenance@<sha>
        with:
          subject-path: artifacts/**/*.exe
```

新增 verify job：

```yaml
  verify:
    needs: release
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha>
      - name: Download release assets
        uses: dsaltares/fetch-gh-release-asset@<sha>
        with:
          version: ${{ github.ref_name }}
          target: ./downloads/
      - name: Verify SHA256 matches CI-generated checksums
        shell: bash
        run: |
          set -euo pipefail
          for f in downloads/checksums-*.txt; do
            (cd downloads && sha256sum -c "$(basename $f)")
          done
```

#### 6.1.5 B-05：补全治理文件

需新建以下 6 个文件（位置与内容要求见 §八）：
1. `.github/workflows/ci.yml`
2. `.github/CODEOWNERS`
3. `.github/pull_request_template.md`
4. `SECURITY.md`
5. `PRE_PUSH_CHECKLIST.md`
6. `docs/HCSE_RELEASE_PROTOCOL.md`

### 6.2 P1 建议修复（下个 Sprint）

| 项 | 建议 |
|----|------|
| 矩阵补全 | 增加 `macos-13` (x86_64)、`ubuntu-22.04-arm` (ARM64)、`windows-11-arm` |
| Cargo 缓存 | 集成 `Swatinem/rust-cache@<sha>` 加速构建 |
| Rust 版本固定 | `dtolnay/rust-toolchain@<sha>` + `toolchain: 1.82.0` |
| release `if: always()` | 改为 `if: success() && startsWith(github.ref, 'refs/tags/v')`，避免 build 失败仍发布 |
| 二进制签名 | macOS 启用 `signingIdentity`，Windows 启用 `certificateThumbprint`（需 secrets） |
| 引擎二进制占位符 | `xuandun-engine-x86_64-pc-windows-msvc.exe` 仅 134 bytes，应在 .gitignore 中排除并在 CI 现场构建 |
| 开发垃圾清理 | 工作树 50+ 个 `??` 文件（cdp_*.py、cargo_build_log*.txt、daoti-xuandun.zip）应加入 .gitignore 或删除 |

---

## 七、SLSA 供应链合规评估

### 7.1 当前 SLSA 等级：Level 0（不达标）

| SLSA L3 要求 | 当前状态 | 缺口 |
|-------------|---------|------|
| 构建在隔离环境（GitHub-hosted runner） | 部分满足 | 使用 hosted runner，但无 egress 过滤 |
| 构建来源可追溯 | 不满足 | 无 provenance attestation |
| 构建过程不可篡改 | 不满足 | Actions 未 pin SHA，存在供应链劫持风险 |
| 依赖固定 | 不满足 | Rust `stable` 浮动、Actions 标签浮动 |
| 输出完整性 | 不满足 | 无 SHA256 校验文件 |

### 7.2 升级路径

**Level 1**（最低门槛）：
- [ ] 所有 Actions pin full commit SHA（B-02）
- [ ] 生成 SHA256 校验文件（B-04）

**Level 2**：
- [ ] Level 1 全部 +
- [ ] 集成 `actions/attest-build-provenance`（B-04）
- [ ] harden-runner egress 过滤（B-03）

**Level 3**（企业级）：
- [ ] Level 2 全部 +
- [ ] 二进制签名（macOS notarization + Windows Authenticode）
- [ ] verify job 自动校验（B-04）
- [ ] 依赖锁文件（Cargo.lock 已有，npm `package-lock.json` 已有）

---

## 八、敏感信息历史清理

### 8.1 当前仓库 secrets 扫描

| 检查项 | 结果 | 详情 |
|--------|------|------|
| 仓库历史扫描 | 未执行 | 建议打 tag 前运行 `gitleaks` 或 `trufflehog` 全量扫描 |
| 工作树未跟踪文件 | WARN | `cdp_test/`、`cdp_sprint4_artifacts/` 含截图与 JSON，可能含敏感路径 |
| 配置文件 | PASS | `config/models.yaml.example` 为示例文件，无真实密钥 |
| `.env` 文件 | PASS | .gitignore 已排除 `.venv/`、`venv/`、`env/` |
| 引擎密钥 | PASS | keyring.rs 使用系统凭据管理器，密钥不入仓库 |

### 8.2 BFG Repo-Cleaner 使用指引（仅在发现历史泄漏时执行）

> 警告：此操作会重写 git 历史，需协调所有开发者重新 clone 仓库。

```powershell
# 1. 备份仓库
git clone --mirror h:\XuanDun xuandun-backup.git

# 2. 准备 secrets 替换映射文件 secrets.txt（每行一个正则）
#    例如：API_KEY=REDACTED_API_KEY

# 3. 运行 BFG（替换敏感字符串）
java -jar bfg.jar --replace-text secrets.txt xuandun-backup.git

# 4. 清理过期 ref
cd xuandun-backup.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# 5. 强推（需协调团队）
git push --force
```

### 8.3 CI 历史 secrets 扫描建议

在 ci.yml 中集成：

```yaml
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@<sha>
        with:
          fetch-depth: 0  # 全历史扫描
      - name: Run gitleaks
        uses: gitleaks/gitleaks-action@<sha>
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## 九、Pre-Push 检查清单（必须在打 tag 前逐项确认）

> 此清单为可打印版本，建议打印后逐项打勾。任何一项未通过即禁止 `git tag` / `git push --tags`。

### 9.1 代码完整性（5 项）

- [ ] **1. Sprint4 11 项修复全部已 commit**（运行 `git status` 确认无 `M`/`??` 的 Sprint4 文件）
  - 验证命令：`git status --short desktop/xuandun-desktop/src-tauri/tauri.conf.json desktop/xuandun-desktop/src/components/ConfirmModal.tsx desktop/xuandun-desktop/sync_version.py`
  - 期望输出：空（无任何行）

- [ ] **2. 版本号三处一致**（tauri.conf.json / package.json / Cargo.toml）
  - 验证命令：`python desktop/xuandun-desktop/sync_version.py --check`
  - 期望输出：`版本一致` 或退出码 0

- [ ] **3. 图标资源全部已 git add**
  - 验证命令：`git ls-files desktop/xuandun-desktop/src-tauri/icons/ | Measure-Object | Select-Object -ExpandProperty Count`
  - 期望：≥ 21（原 7 + 新 14）

- [ ] **4. 本地 cargo build --release 无 warning 无 error**
  - 验证命令：`cd desktop/xuandun-desktop/src-tauri; cargo build --release 2>&1 | Select-String "warning|error"`
  - 期望：空输出

- [ ] **5. 本地 npm run build 通过**
  - 验证命令：`cd desktop/xuandun-desktop; npm run build`
  - 期望：`vite build` 成功，`dist/` 生成

### 9.2 CI/CD 合规（3 项）

- [ ] **6. release.yml 所有 Actions 已 pin full commit SHA**
  - 验证：在 release.yml 中搜索 `@v` 或 `@stable`，应为 0 个匹配
  - 验证命令：`Select-String -Path .github/workflows/release.yml -Pattern '@v\d|@stable'`
  - 期望：空输出

- [ ] **7. 每个 job 首步为 `step-security/harden-runner`**
  - 验证：肉眼检查 release.yml 每个 job 的第一个 step

- [ ] **8. release job 持 `contents: write`，其他 job 仅 `contents: read`**
  - 验证：肉眼检查 permissions 块

### 9.3 完整性与可追溯（2 项）

- [ ] **9. CI 生成 SHA256 校验文件并随 Release 发布**
  - 验证：Release 资产列表含 `checksums-*.txt`

- [ ] **10. CI 集成 `actions/attest-build-provenance` 生成 SLSA attestation**
  - 验证：Release 页面 "Attestations" 区有构建来源记录

---

## 十、发布决策

### 10.1 当前决策：**BLOCK（禁止发布）**

**阻断原因**：5 项 P0 阻断项（B-01 ~ B-05）均未解决，直接打 tag 将导致：
1. CI 第一步 `sync_version.py --check` 失败（文件未跟踪）
2. 即便跳过 SSOT 门禁，Tauri 构建会因 ConfirmModal.tsx/YinYangGate.tsx 未跟踪而编译失败
3. 即便编译通过，发布资产无 SHA256、无 SLSA，不满足企业供应链审计要求
4. 7 个 Actions 未 pin SHA，存在供应链劫持风险

### 10.2 解除阻断的最小行动集（按顺序执行）

```
步骤 1：B-01 提交 Sprint4 修复文件（§6.1.1）
步骤 2：本地验证 §9.1 第 1-5 项全部 PASS
步骤 3：B-02/B-03/B-04 重写 release.yml（§6.1.2-6.1.4）
步骤 4：B-05 创建 6 个治理文件（§6.1.5）
步骤 5：本地验证 §9.2-9.3 全部 PASS
步骤 6：提交 CI 改动，触发一次 workflow_dispatch 测试构建
步骤 7：CI 构建通过 + verify job SHA256 比对通过
步骤 8：打 tag `git tag v1.2.3 && git push origin v1.2.3`
```

### 10.3 风险接受声明（仅在企业内部发布且用户明确接受时适用）

若用户明确接受以下风险，可在仅完成 B-01 后打 tag：
- 供应链攻击面（Actions 未 pin SHA）
- 无 SHA256 完整性校验
- 无 SLSA provenance

**强烈不建议**此路径，除非是内部测试构建。

---

## 附录 A：项目专属检查清单引用

| 文档 | 路径 | 状态 |
|------|------|------|
| HCSE 发布协议 | `docs/HCSE_RELEASE_PROTOCOL.md` | **缺失**（建议本报告作为 v1.0 基线，后续迭代为正式协议） |
| 项目记忆 | `c:\Users\Administrator\.trae-cn\memory\projects\-h-XuanDun\project_memory.md` | 已检索，含 Sprint 2b 网关记忆 |
| LRC 记忆库 | `mcp_lrc-memory` | 已检索，3202 条记忆，本次审计结论将同步 |

## 附录 B：审计工具与命令速查

```powershell
# 1. 查看 Sprint4 修复文件 git 状态
git status --short desktop/xuandun-desktop/

# 2. 验证版本一致性
python desktop/xuandun-desktop/sync_version.py --check

# 3. 本地构建验证
cd desktop/xuandun-desktop
npm run build
cd src-tauri
cargo build --release

# 4. 检查 Actions pin SHA
Select-String -Path .github/workflows/*.yml -Pattern '@v\d|@stable'

# 5. 检查 harden-runner 覆盖
Select-String -Path .github/workflows/*.yml -Pattern 'harden-runner'

# 6. 全量 secrets 扫描（需安装 gitleaks）
gitleaks detect --source . --report-path leaks.json

# 7. 验证图标文件数
git ls-files desktop/xuandun-desktop/src-tauri/icons/ | Measure-Object
```

---

**报告结束。决策：BLOCK。请按 §10.2 最小行动集解除阻断后重新审计。**

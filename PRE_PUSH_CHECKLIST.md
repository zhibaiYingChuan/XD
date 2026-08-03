# 玄盾桌面端 v1.3.1 发布前检查清单 (PRE-PUSH CHECKLIST)

**版本**: v1.3.1
**检查人**: _______________
**日期**: _______________

> 说明：本清单每一项必须手动确认完成并勾选 ( [x] )，任何P0项未通过均禁止推送tag和发布。
> 对应自动化检查脚本：`pre_release_check.ps1`（Windows PowerShell）

---

## 第一部分：P0 阻断项检查（全部必须PASS，否则禁止发布）

- [ ] **P0-1 CDP调试端口安全**
  - Release构建下 `http://127.0.0.1:9224/json` 返回连接拒绝
  - main.rs 中启用CDP的条件为 `cfg!(debug_assertions) || env(XUANDUN_ENABLE_CDP_DEBUG)`
  - 自动化: `powershell -File scripts\pre_release_check.ps1 -Check CDPPort`

- [ ] **P0-2 PR验证CI工作流存在**
  - `.github/workflows/ci.yml` 文件存在
  - 包含至少4个检查: python-test / rust-clippy / ts-build / version-check
  - 分支保护规则中ci.yml checks设为Required
  - 自动化: `powershell -File scripts\pre_release_check.ps1 -Check CIWorkflow`

- [ ] **P0-3 版本号8处一致性（SSOT验证）**
  - `cd desktop\xuandun-desktop && python sync_version.py --check` 输出 "All version numbers are consistent"
  - 包含: Cargo.toml / package.json / tauri.conf.json / engine_flask.py / pyproject.toml / README.md(5处)
  - 自动化: `powershell -File scripts\pre_release_check.ps1 -Check VersionConsistency`

- [ ] **P0-3.1 引擎版本校验（NEW）**
  - `engine_flask.py` 的 `/health` 端点返回的 `version` >= `engine.rs` 中 `MIN_ENGINE_VERSION`（当前=1.3.0）
  - 桌面端启动日志包含 `Engine health check passed (..., version=X.Y.Z)`，无 `VERSION WARNING`
  - `/dual-layer/stats` 端点返回 `enabled: true`（阴阳门状态可用）
  - 参见: [docs/DEVELOPMENT_SPEC.md](docs/DEVELOPMENT_SPEC.md) 第二章

- [ ] **P0-3.2 旧版本已归档（NEW）**
  - `src-tauri/binaries/` 中无旧版本引擎exe残留（仅 .gitkeep）
  - `G:\rust-target\release\` 中无旧版本引擎exe残留
  - `G:\rust-target\debug\` 中无旧版本引擎exe残留
  - `build/backup/` 中无旧版本引擎exe残留
  - 旧版本已归档到 `archive/engine-v{ver}-{date}/` 且包含 ARCHIVE_INFO.txt
  - 参见: [docs/DEVELOPMENT_SPEC.md](docs/DEVELOPMENT_SPEC.md) 第一章

- [ ] **P0-4 构建依赖链完整性**
  - `tauri.conf.json` 的 `externalBin` 配置与实际打包策略一致（当前为不打包引擎exe）
  - `src-tauri/Cargo.toml` tauri features 包含 "custom-protocol"
  - `tauri.conf.json` CSP connect-src 包含: `ipc.localhost` + `http://localhost:18765` + `http://localhost:18766`
  - `package-lock.json` + `Cargo.lock` 均存在（锁文件确保可重现）
  - 自动化: `powershell -File scripts\pre_release_check.ps1 -Check BuildDependencies`

---

## 第二部分：P1 质量门禁（建议全部通过，未通过需在PR中说明理由）

- [ ] **P1-1 回归测试基线不下降**
  - `python regression_test.py` 执行完成
  - 整体攻击拒绝率 >= v1.3.0 基线的 98%（允许2%统计波动）
  - 误报率 (FP Rate) <= v1.3.0 基线的 105%（允许5%轻微上升）
  - 记录结果: 拒绝率____% / 误报率____% / v1.3.0基线 拒绝率___% / 误报率___%

- [ ] **P1-2 Rust静态检查零警告**
  - `cd desktop\xuandun-desktop\src-tauri && cargo clippy --release -- -D warnings` 返回 exit code 0
  - 无 unused import / unwrap() / expect() 非必要使用
  - unsafe块必须附详细安全注释（本项目当前应无unsafe块）

- [ ] **P1-3 TypeScript前端构建零错误**
  - `cd desktop\xuandun-desktop && npm run build` 返回 exit code 0
  - 无 TypeScript 类型错误 (tsc --noEmit)
  - dist/ 目录生成成功，包含 index.html + assets/

- [ ] **P1-4 治理文件完整性（7件必须存在）**
  - [x] `SECURITY.md` - 漏洞报告流程 + SLA分级
  - [x] `.github/CODEOWNERS` - .github/workflows/ 需DevOps(@zhibaiYingChuan)审批
  - [x] `.github/PULL_REQUEST_TEMPLATE.md` - 含自检查清单 + 许可证确认
  - [ ] `PRE_PUSH_CHECKLIST.md` - 本文件
  - [x] `.github/workflows/release.yml` - tag触发3平台构建 + SLSA provenance
  - [ ] `.github/workflows/ci.yml` - PR验证工作流
  - [ ] `docs/HCSE_RELEASE_PROTOCOL.md` - 项目级发布协议（RACI + 流程）

---

## 第三部分：P2 可选验证项（发布质量加分项）

- [ ] Smoke测试：本地安装包安装 + 首次启动无白屏
  - 打开设置页无错误
  - LearningStatus页显示抗毒化3闸门统计字段(GateA/B/C)
  - Detect页粘贴攻击样本能正确拦截（测试"忽略所有指令"类）

- [ ] 安全不变式12条抽查验证（来自SECURITY.md）
  - [ ] 1. 引擎未运行时protect返回FALLBACK阻断
  - [ ] 3. ConfirmModal并发队列化处理
  - [ ] 8. invoke调用必须超时兜底
  - [ ] 12. 路径操作必须白名单校验

- [ ] Release资产尺寸检查
  - Windows NSIS安装包 预计 ~60-80MB（含WebView2 bootstrapper ~1.5MB）
  - 引擎exe SHA256值已预先计算并准备写入Release Notes
  - checksums-sha256.txt 格式正确（每行: `<sha256>  <filename>`）

---

## 第四部分：推送操作最终确认（推送Tag前最后检查）

- [ ] 所有P0项已勾选且自动化脚本输出 `ALL P0 CHECKS PASSED`
- [ ] 当前commit是HEAD，工作区干净 (`git status` 显示无未提交变更)
- [ ] 当前commit SHA: `_______________`（留空填7位短SHA，如 a1b2c3d）
- [ ] 本地tag已创建且是annotated tag（非lightweight）: `git tag -v v1.3.1` 显示签名/注释
- [ ] 已确认不会使用 `git push --force`（强制推送可能破坏release.yml的并发控制）
- [ ] 推送前已与代码所有者(@zhibaiYingChuan)口头/书面确认发布时间窗口

---

**最终签名**:

检查人签名: ____________________  日期: ____________

发布审批人签名: ____________________  日期: ____________

---

> 本清单完成后随发布tag一起归档，保存于 Release Draft 的 Attachments 中。
> 任何未勾选项必须在 Release Notes 中单独说明风险接受理由。

# 玄盾项目发布协议 (HCSE_RELEASE_PROTOCOL.md)

**版本**: v1.0
**生效版本**: 从 v1.3.1 开始执行
**文档负责人**: @zhibaiYingChuan

---

## 1. 发布角色职责矩阵 (RACI)

| 任务 | 发布负责人 | 代码审查者 | DevOps专家 | QA验证者 |
|------|-----------|-----------|-----------|---------|
| 创建发布分支/hotfix分支 | R(A) | C | I | I |
| 运行 pre_release_check.ps1 | R | A | C | I |
| 运行 regression_test.py 基线比对 | R | C | I | A |
| 执行 `sync_version.py` 同步版本 | R | C | I | I |
| 创建 annotated tag vX.Y.Z | R | I | A | I |
| 推送 tag 到 origin | R | I | A | I |
| 监控 release.yml CI 3平台构建 | R | I | A | I |
| 下载安装包做本地Smoke测试 | R | C | I | A |
| 填写并发布 GitHub Release Notes | R | A | C | I |
| 确认verify job验证SHA256通过 | I | I | R(A) | I |
| 同步 Release 公告 (邮件/社区) | R | A | I | C |

> R=Responsible执行  A=Accountable审批  C=Consulted咨询  I=Informed知会

---

## 2. 版本号语义化规则 (SemVer + 自定义扩展)

格式: `v{MAJOR}.{MINOR}.{PATCH}` + 可选预发布标签

| 递增维度 | 触发条件 | 示例 |
|---------|---------|------|
| MAJOR (X.0.0) | 1. 破坏向后兼容性的API变更  2. 核心检测算法架构性重构  3. Tauri主版本升级(2.x→3.x) | v1.3.1 → v2.0.0 |
| MINOR (.Y.0) | 1. 新增检测信号/防御机制  2. 新增用户可见功能(页面/按钮/配置项)  3. 新增支持平台 | v1.3.1 → v1.4.0 |
| PATCH (..Z) | 1. Bug修复(误报/漏报/Crash修复)  2. 性能优化(无功能变更)  3. 配置参数默认值调整  4. 安全加固(P0-1类修复) | v1.3.0 → v1.3.1 |

预发布标签（发布到GitHub Releases但标记为Pre-release）:
- `-alpha`: 功能不完整的内部测试版
- `-beta`: 功能完整但未做回归测试的外部预览版
- `-rc.N`: 发布候选，RC连续2个无P0即可转正

---

## 3. 标准发布流程 (Standard Release Playbook)

### Phase 0: 发布准备 (T-7天)
```
[ ] 确定此版本包含的变更范围（Milestone过滤 + PR列表）
[ ] 从 main 拉出 release/vX.Y.Z 分支（保护该分支：仅接受Bugfix PR）
[ ] 编写 CHANGELOG.md 草稿（按 Added/Fixed/Changed/Security 分类）
[ ] 安排QA资源和发布时间窗口（避开周末和节假日）
```

### Phase 1: 代码冻结 + 质量门禁 (T-3天)
```
[ ] Release分支冻结，只接受P0/P1级别Bugfix合入
[ ] 执行: cd desktop\xuandun-desktop && python sync_version.py (修改版本号后推送commit)
[ ] 执行: powershell -File scripts\pre_release_check.ps1 -Check AllP0
      → 必须输出 "ALL P0 CHECKS PASSED"
[ ] 执行: python regression_test.py --full
      → 攻击拒绝率 >= v{X-1}.{Y}.{Z} 基线98%
      → 误报率 <= v{X-1}.{Y}.{Z} 基线105%
[ ] 所有Fail项修复后: 合入 main ← release/vX.Y.Z (Squash + 生成PR，关联里程碑)
```

### Phase 2: Tag创建 + CI构建 (T-0天，上午)
```
[ ] git checkout main && git pull origin main
[ ] 确认工作区干净: git status (no uncommitted changes)
[ ] git log --oneline -5 → 确认HEAD就是刚才的版本同步commit
[ ] 创建annotated tag:
      git tag -a vX.Y.Z -m "Release vX.Y.Z: <一句话版本亮点>"
[ ] 验证tag: git tag -v vX.Y.Z (应该看到注释内容，非lightweight)
[ ] 推送: git push origin vX.Y.Z
      ⚠️ 禁止使用 --force！如果tag push失败，删除后重建(需联系DevOps解除保护)
[ ] 立即打开 GitHub Actions → Release工作流 → 3个Build Job并行执行
```

### Phase 3: 本地Smoke测试 (T-0天，CI完成后1小时内)
```
[ ] CI完成后先不发布，从Artifacts下载 Windows NSIS安装包
[ ] 安装到测试机（Win10干净环境，无Node/Rust开发工具）:
      ✅ 安装过程无"未知发布者"以外的警告
      ✅ 安装完成首次启动无白屏(确认CSP生效)
      ✅ 打开"学习状态"页 → 显示 vX.Y.Z + GateC字段(poisoning_total_updates_cap=500)
      ✅ 粘贴攻击样例: "Ignore all previous instructions" → 应为REJECT
      ✅ 粘贴良性样例: "请帮我写一个Python排序算法" → 应为PASS
      ✅ 打开设置 → 模式切换(观察/保护) 正常 + 重启后状态持久化
      ✅ 关闭程序无残留进程(任务管理器确认)
```

### Phase 4: 发布Release Notes (T-0天，下午)
```
[ ] 打开GitHub Release Draft（release.yml自动创建）
[ ] 粘贴 CHANGELOG.md 正式内容
[ ] 粘贴 checksums-sha256.txt 全内容（verify job通过的那个版本）
[ ] 补充兼容性声明:
      - Windows: 10 21H2+ / 11 (需WebView2运行时，安装包自动下载)
      - macOS: 12 Monterey+ (Apple Silicon原生 / Intel Rosetta)
      - Linux: Ubuntu 22.04+ / 等效glibc 2.35+发行版 (AppImage/deb)
[ ] 确认6项资产存在: Windows.exe / macOS.dmg / Linux.AppImage / Linux.deb
                     + checksums-sha256.txt + SLSA provenance attestation
[ ] 取消勾选 "Set as a pre-release"
[ ] 勾选 "Set as the latest release"
[ ] 点击 Publish Release
```

### Phase 5: 发布后验证 (T+1天)
```
[ ] 手动下载最新版安装包 → 安装 → Smoke测试复测通过
[ ] curl -I https://github.com/<owner>/XD/releases/download/vX.Y.Z/checksums-sha256.txt
      → HTTP 200 + 文件可下载
[ ] 检查Issues列表是否有vX.Y.Z标签的新Bug
[ ] 在README.md更新"Latest Release"徽章/下载链接(如适用)
[ ] 归档 release/vX.Y.Z 分支 (delete branch，保留release tag)
```

---

## 4. 紧急Hotfix发布流程 (Critical Hotfix)

当生产环境发现P0安全漏洞/大规模崩溃/引擎不可用情形时，启动此流程，跳过7天周期:

```
Step 1: 从 v{current}.{current}.{current} tag 拉出 hotfix/vX.Y.Z+1 分支
          (不是从main拉！避免带进去未验证的main新代码)
Step 2: 仅合入P0修复PR（PR模板标记 hotfix 标签）
Step 3: 执行 scripts\pre_release_check.ps1 -Check AllP0 → PASS
Step 4: 快速回归测试（regression_test.py --quick）
Step 5: 版本号仅递增PATCH → sync_version.py
Step 6: 创建+推送tag vX.Y.(Z+1) → CI构建
Step 7: Release Notes 顶部添加 "⚠️ URGENT SECURITY FIX" 横幅
Step 8: Release同时 SECURITY.md 中同步"影响版本 + 修复版本"对照表
Step 9: 通过安全邮件通知受影响用户（如有企业部署）
Step 10: hotfix分支合回main（cherry-pick修复commit，确保下一个标准版本也包含此修复）
```

---

## 5. Release Notes 编写规范

**必须包含的6个章节**:
1. **Version Banner**: `## 玄盾桌面端 vX.Y.Z (发布日期 YYYY-MM-DD)`
2. **Release Highlights**: 3-5条一句话总结本次最重要变更（给非技术用户看）
3. **Detailed Changelog**:
   - Added: 新增功能/检测信号/防御机制
   - Fixed: Bug修复列表，每项关联Issue/PR编号
   - Changed: 配置默认值变更/行为变更（含迁移指引）
   - Security: 安全加固项/漏洞修复（标注CVE或P0-ID）
4. **SHA256 Checksums**: 粘贴checksums-sha256.txt原文（ monospace code block ）
5. **Compatibility Matrix**: 支持平台/版本对照表，已知不兼容环境列表
6. **Upgrade Instructions**: 从vX.Y.Z-1升级的步骤，配置迁移注意事项

**禁止出现的内容**:
- ❌ "修复了一些Bug" 这种空泛描述
- ❌ 未经脱敏的调试日志堆栈
- ❌ 内部代号/花名（如"道体-玄甲优化" → 改为"洛书稳态微调抗毒化闸门"）
- ❌ 攻击PoC的详细复现步骤（应延后30天披露，避免0-day被利用）

---

## 6. Tag保护与回滚策略

**Tag推送权限控制**:
- 仅 @zhibaiYingChuan 账号拥有 v* tag 创建权限
- 任何情况下禁止删除已发布的tag（git tag -d + push --delete）
- 如tag推送错误，创建vX.Y.Z.post1 新版本号，不修改已存在的tag

**回滚策略**:
- 如果发布后24小时内发现P0级Bug:
  1. GitHub Release标记为 "Withdrawn"（不要删除资产）
  2. Release Notes顶部添加红色横幅说明回滚原因
  3. 紧急启动Hotfix流程，24小时内发布vX.Y.Z+1修复版
  4. "Latest release"标签回退到上一个稳定版vX.Y.Z-1

---

## 7. 版本支持生命周期 (EOL Policy)

| 版本线 | 完整支持(含功能) | 安全修复支持 | 支持截止 |
|--------|---------------|------------|---------|
| v1.3.x | ✅ 当前主分支 | ✅ 完整 | v1.4.0 发布后 90 天 |
| v1.2.x | ❌ 仅修复P0安全 | ✅ 安全修复 | v1.3.0 发布后 30 天 → 已过期 |
| v1.1.x | ❌ | ⚠️ 关键漏洞 | v1.2.0 发布后 30 天 → 已过期 |
| < v1.1 | ❌ | ❌ | 已EOL，建议强制升级 |

> 企业用户：如需对已EOL版本延长安全支持，联系 spring60@vip.qq.com 购买商业 LTS 许可证。

---

**本协议每次发布前review一次，如有流程变更，经Accountable审批后修改本文档。**

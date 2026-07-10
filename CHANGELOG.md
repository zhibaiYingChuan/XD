# 变更日志

本项目变更遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

## [1.2.0] - 2026-07-11

### 新增

#### Dashboard 可视化增强
- 趋势图支持时间范围选择（1小时/24小时/7天/30天）
- 攻击类型分布可视化（饼图 + 雷达图）
- 实时监控指标网格卡片（请求数/拦截数/延迟/学习状态）
- 周度对比柱状图
- 数据层新增 `stats_hourly`/`stats_daily`/`reports` 三张聚合表
- `logs` 表新增 `attack_category`/`latency_ms`/`domain_distance` 字段

#### 安全报告定期推送
- Rust 侧 `render_report_html()` 生成 HTML 报告（含 CSS 柱状图）
- Python 侧 `report_generator.py` 支持 matplotlib 图表渲染
- 报告归档到 SQLite `reports` 表，支持周报/月报/自定义周期
- 新增「安全报告」页面（生成/预览/删除）

#### 企业系统集成告警系统
- 告警抽象层 `BaseNotifier` + 5 通道实现：
  - 钉钉（加签 + @手机号 + Markdown 消息）
  - 飞书（签名 + 交互式卡片 + 颜色分级）
  - 邮件（SMTP_SSL/TLS + HTML 正文）
  - Webhook（模板变量 + 指数退避重试 3 次）
  - Syslog（RFC 5424 + UDP/TCP + Facility/Severity 映射）
- `AlertManager` 负责去重（5 分钟冷却）和分级过滤
- 拦截时自动异步分发告警（trust_level=LOW → critical）
- 设置页面新增告警通道配置 UI

#### 接入向导
- 分步骤向导组件 `OnboardingWizard`（4 步流程）
- 支持代理/SDK/模拟测试三种接入方式引导
- 步骤进度指示器 + 勾选清单 + 连通性自动检测
- 跳过后记忆状态，可通过 Dashboard 重新触发

#### 灰度验证工具
- 灰度监控脚本 `scripts/graymon.py`（持续探测 + JSONL 日志 + 分析模式）
- 灰度验证方案文档 `docs/灰度验证方案.md`
- 支持可用率统计、延迟分布分析、异常 Webhook 告警

#### 告警通道端到端测试
- `tests/test_alerts_e2e.py` 新增 62 个测试用例
- 覆盖 5 通道配置验证、消息发送、AlertManager 去重/分级过滤、集成流程

### 修复

- **飞书签名 Bug**：`hmac.new()` 的 msg 参数从空字符串 `""` 修正为 `b""`，修复 Python 3.11+ 下签名计算抛出 `TypeError`
- **Webhook 重试逻辑失效**：`_post_json` 内部捕获异常不抛出导致重试永不触发，改为检查返回值触发重试

### 变更

- `engine_flask.py` /protect 响应新增 `attack_category` 和 `latency_ms` 字段
- `ProtectResult` / `ProtectResponse` / `LogEntry` 数据结构同步新增字段
- `db.rs` `insert_log` 签名从 5 参数扩展为 8 参数
- 版本号从 1.1.0 升级到 1.2.0

---

## [1.1.0] - 2026-07-10

### 新增

- 活性防护架构（观察 → 学习 → 自动切换两阶段状态机）
- 模拟测试模块（200+ 攻击样本 + 30 良性样本）
- 学习词汇展示增强（原型典型输入示例）
- 接入引导 banner（Dashboard 未接入流量时显示）
- 部署指南、端到端验证清单、产品迭代规划文档
- 安装验证脚本 `scripts/verify_installation.py`

### 变更

- 版本号从 1.0.0 升级到 1.1.0
- 白皮书更新至 v1.4
- README 更新安装说明和功能列表

---

## [1.0.0] - 2026-07-08

### 首次发布

- 道体·玄盾核心引擎（基于阴气域感知的提示注入检测）
- Tauri 桌面端应用（Windows/macOS/Linux 三平台）
- Python SDK（`pip install daoti-xuandun`）
- 代理模式（HTTP 代理拦截 AI 工具流量）
- MCP Server 模式（Claude Desktop 集成）
- 哈希链审计日志（防篡改）
- 三级防护策略（高安全/平衡/低误报）
- GitHub Actions CI/CD（三平台自动构建）

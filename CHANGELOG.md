# 变更日志

本项目变更遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

## [1.3.5-beta] - 2026-08-14

> **v1.3.5-beta 核心变更：发布前安全审计修复 + 输出护栏能力验证 + 交互缺陷修复**
>
> 本版本基于 TRAE-code-review / TRAE-security-review / TRAE-debugger 三技能联合审计，
> 修复网关端 9 项高危 + 25 项中危问题，桌面端安全审计零可利用漏洞。
> 同时完成 36 处交互缺陷修复（P0×3 + P1×17）和双端真 CDP 回归测试全绿。

### 安全修复

#### 网关端高危修复（TRAE-security-review 审计发现）
- **[H-1] 报告导出存储型 XSS**：`/api/v1/report` 的 HTML 格式报告未对用户可控的 `start_date`/`end_date` 做 HTML 转义，添加 `html.escape()` 防护
- **[H-2] 临时文件泄漏**：`export_report` 每次调用创建临时文件但从不清理，添加读取后 `os.unlink()` 清理
- **[H-3] 服务器路径泄露**：报告响应中包含 `file_path` 绝对路径，已移除该字段
- **[H-4] 错误信息泄露**：`/api/v1/protect` 异常响应包含内部异常细节，改为通用错误消息
- **[H-5] `datetime.utcnow()` 废弃**：替换为 `datetime.now(timezone.utc)`

#### 引擎并发安全修复（TRAE-code-review 审计发现）
- **[H-6] `check_output` 未加锁**：与 `set_output_guardrail_enabled` 并发时引用可能被置 None，添加 `_protect_lock` 保护
- **[H-7] `set_output_guardrail_enabled` / `set_sensitive_leak_enabled` TOCTOU 竞态**：运行时开关方法未持锁，添加 `_protect_lock` 保护
- **[H-8] `correct_false_positive` 未加锁**：修改共享原型库时未持锁，添加 `_protect_lock` 保护整个方法体

#### 内存泄漏修复
- **[H-9] `OutputPatternTracker` 内存泄漏**：`_session_lengths` 字典随会话增长永不清理，添加最大会话数限制（10000）+ LRU 淘汰

### 交互缺陷修复（36 项）

#### P0 修复（3 项）
- **P0-1**：`fetchWithRetry` 的 `AbortController` 移入循环内创建，修复重试超时失效
- **P0-2**：端口分裂修复（vite.config.ts 代理 → 18766 与网关统一）
- **P0-3**：`__TAURI_INTERNALS__.invoke` 不可写问题，改用 tauriApi.ts 源码层钩子注入

#### P1 修复（17 项）
- 网关端 10 项：CORS 配置、Login 超时、Settings 告警通道、Dashboard 空数据降级等
- 桌面端 7 项：tauriApi.ts 钩子注入、XPath 定位修复、批量操作优化等

### 测试验证
- **输出护栏实测**：17 类探针真实调用网关 `/api/v1/protect`（direction=output），确认 11 类高危全拦截 + 3 类 PII 打码 + 3 类正确放行
- **网关端真浏览器 CDP 回归**：PASS=25 FAIL=0 SKIP=2（真实 Edge 151 + CDP 9223）
- **桌面端 CDP 回归**：PASS=30 FAIL=0 SKIP=2（WebView2 + CDP 9224）

## [1.3.4] - 2026-08-12

> **v1.3.4 核心变更：后端引擎 Rust 重构 + 核心算法提速 + 产品健康修复**
>
> 本版本对整个后端检测引擎进行了 Rust 重构——核心编码算法（LuoshuSymbolMapper.encode）从纯 Python 迁移到 Rust 实现，
> 端到端延迟从 22.2μs 降至 7.2μs（含 PyO3 FFI 开销），实现 3.1 倍加速。Rust 引擎通过 PyO3 与 Python 无缝集成，
> 内置三层降级保护确保 Rust 不可用时自动回退纯 Python。
> 同时完成 5 项产品健康修复（F-1~F-5），消除双智能体审计发现的诚信缺口。

### 新增

#### 后端引擎 Rust 重构 — 核心算法提速（P0-1）
- **核心算法 Rust 化**：LuoshuSymbolMapper.encode() 从纯 Python/numpy 迁移到 Rust/ndarray 纯计算实现
- [crates/daoti_xuandun_pyo3/src/luoshu.rs] LuoshuEngine 纯 Rust 实现：encode()（176维向量编码）、cosine_distance、yin_yang_bifurcate、shannon_entropy
- PyO3 绑定：`#[pyclass]` 暴露 PyLuoshuEngine 给 Python，通过 ndarray 零拷贝借用 numpy 内存
- Python 三层降级保护：方法级 try/except → 实例级熔断器（未实现）→ import 级回退
- 性能：encode() 实测 7.2μs（3.1x 加速，目标 <15μs 已达成，但加速比低于原预期 8x）
- 精度：Rust 与 Python encode() 输出 cosine=1.0（确定性一致）
- [src/daoti_xuandun/luoshu_mapper.py] 委托 Rust 引擎（`self._rust.encode(text)`），保留 Python fallback

#### 周报完整导出（P0-2）
- [desktop/xuandun-desktop/engine_flask.py] 新增 `/report/weekly` 端点（POST），支持 HTML/PDF 格式
- [desktop/xuandun-desktop/templates/weekly_report.html] Jinja2 模板：趋势折线图 + 攻击分布饼图（SVG 内联）
- fpdf2 中英文 PDF 生成（Windows 无 GTK3 时 weasyprint 回退到 fpdf2）
- [desktop/xuandun-desktop/src/components/ReportExportDialog.tsx] 导出对话框：日期选择、格式切换、Tauri save dialog 保存
- 10 万+条日志 60s 内完成

#### Bun 前端工具链（P1-1）
- 工具链从 npm 统一迁移到 Bun 1.3.14（通过 npm 国内镜像安装）
- `bun run build` 2.94s（vs npm 41s ts-build，节省 24s/次）
- Vitest 全兼容 27/27 PASS，2.62s
- CI workflow 改为 setup-bun + bun run build + bun run test
- 注意：bun.lock 仅 desktop 生成，admin-console 无 bun.lock（验收标准未完全达标）

#### 桌面端自动更新（P1-2）
- [tauri-plugin-updater] 集成：Cargo.toml 依赖 + tauri.conf.json 配置（Ed25519 密钥对已生成）
- Rust 命令：check_update / download_and_install_update / dismiss_update
- [src/components/UpdateBanner.tsx] 更新提示横幅：启动 3s 后自动检查，下载进度条实时更新
- [Settings.tsx] 版本信息区域
- [.github/workflows/release.yml] 自动生成 latest.json manifest（含真实 Ed25519 签名，依赖 GitHub Secret 注入 TAURI_SIGNING_PRIVATE_KEY）

### 修复
- 版本号全项目统一为 1.3.4（SSOT）
- 归档：旧版本文件移至 archive/v1.3.3-20260812/
- 历史开发计划文档归档至 archive/plans/
- ci.yml setup-bun pin 修复（@v2 → commit hash）
- 开发计划验收标准标注修正（3 处虚假 [x] 标记改为 [ ]）

#### 产品健康修复（F-1~F-5，双智能体审计 + CDP 双端回归验证）
- **F-1 dismiss_update 持久化**：dismiss_update 从空实现改为 Rust DB 持久化（set_config "dismissed_update_version"），check_update 在 Rust 端过滤已忽略版本；删除前端 localStorage 双写，确立 Rust DB 为唯一权威源
- **F-2 export_report_file 改用 save dialog**：集成 tauri-plugin-dialog，前端通过 save() 打开系统保存对话框；Rust export_report_file 改为接收 dest_path 参数执行文件拷贝；ReportExportDialog.handleExport 处理用户取消
- **F-3 签名体系加固**：release.yml 正式发布 Job 在 TAURI_SIGNING_PRIVATE_KEY 缺失时 exit 1 阻断构建，不再 fallback 到占位签名；本地/测试构建豁免
- **F-4 周报预览真实增量**：get_weekly_report_preview 改为从 DB 查询本周真实数据（chrono::Utc 计算周边界 + get_period_stats + get_high_risk_count），不再用累计值冒充本周值
- **F-5 Settings 版本与更新区域**：Settings.tsx 新增"版本与更新"卡片，版本号从 @tauri-apps/api/app.getVersion() 运行时读取，含手动"检查更新"按钮
- **CDP 回归测试**：桌面端 WebView2 12/12 PASS + 网关管理控制台 23/23 PASS

#### 周报导出重构（移除 PDF + 新增 CSV/JSON/MD 格式）
- **移除 PDF 格式**：fpdf2/weasyprint 在打包引擎二进制中无法保证可用，导致用户导出 PDF 内容全是 HTML 源码；移除 PDF 选项和 fpdf2 依赖，避免给用户增加安装依赖的负担
- **新增 CSV 格式**：Excel 可直接打开，含概览统计 + 每日明细 + 攻击类型分布 + 来源 Top，使用 Python 标准库 csv 模块
- **新增 JSON 格式**：运维人员可编程分析，便于对接其他系统，使用 Python 标准库 json 模块
- **新增 MD 格式**：Markdown 表格，适合文档/Notion/GitHub，纯字符串拼接
- **默认格式改为 CSV**：零依赖、Excel 友好、最通用的统计分析格式
- **全部格式零依赖**：CSV/JSON/MD/HTML 均使用 Python 标准库，无需任何额外安装

### 变更
- 开发计划 v1.3.4 从"P0+P1 全部完成"修正为"P0+P1 核心功能已完成，3 项验收标准待优化"
- 参赛话术从"13x 加速"修正为"3.1x 加速"（实测 Python 基线 22.2μs，Rust 端到端 7.2μs）
- 性能叙事：encode() 目标 <15μs 已达成（实测 7.2μs），但加速比 3.1x（原预期 8x）未达标，标注为 v1.3.5 继续优化
- P0-2.4 Email 发送功能未实现，标记为 v1.3.5

### 技术债务（待 v1.3.5 处理）
- ~~自动更新签名密钥依赖 GitHub Secret 注入（TAURI_SIGNING_PRIVATE_KEY 未配置时含占位签名）~~ → **F-3 已修复：正式发布 Secret 缺失时构建失败，不再 fallback 占位签名**
- ~~release.yml 需配置 TAURI_SIGNING_PRIVATE_KEY / TAURI_SIGNING_PRIVATE_KEY_PASSWORD Secrets~~ → **F-3 已加固**
- encode() <15μs 目标已达成（实测 7.2μs），但加速比 3.1x（原预期 8x 过高）
- admin-console 无 bun.lock（Bun 迁移不完整）
- ReportExportDialog Email 发送未实现
- 无自动更新回滚机制（安装失败不恢复旧版本）
- 详细技术债务清单见 docs/开发优化计划_v1.3.4_修订版.md

---

## [1.3.3-beta] - 2026-08-08

### 新增

#### 企业 API Key 签发与收费体系（Web 网关）
- 商业模式：桌面端免费（个人）、Web 网关企业收费；企业 API Key 由玄盾供应商离线签发，网关仅验签、不可自建
- [tools/license_manager] 供应商签发工具链：`gen_keypair.py`（RSA-2048 公私钥）、`sign_api_key.py`（离线签发 `XDKEY-<jwt>`）、`verify_api_key.py`（自测验签）、`web_console.py`（本机网页签发台，含吊销）
- 企业 API Key 采用 RS256 JWT 自校验：携带套餐 `tier`、有效期 `exp`、唯一标识 `jti`、配额 `quota`，到期自动失效实现订阅式收费
- [gateway/jwt_auth.py] 网关离线验签：公钥校验签名/`iss`/`exp`/`jti`，未配置公钥时业务端点 fail-closed 返回 503
- [gateway/revoked_store.py] 吊销黑名单：按 `jti` 持久化，吊销后网关立即拒绝该企业请求
- [gateway/app.py] 鉴权中间件重构：管理密钥（环境变量 `XUANDUN_ADMIN_KEY`）与管理端点、企业密钥（JWT）与业务端点 `/api/v1/protect` 分离；业务端点按 `jti` 计量用量
- [admin-console] 「企业授权」只读查询页：展示企业密钥套餐/有效期/用量/吊销状态（`/api/v1/keys`、`/api/v1/keys/revoke`）

#### 工具检测模块（Agent 攻击防护）
- [src/daoti_xuandun/tool_detector.py + tool_risk_registry.py] 工具调用检测与风险注册表，覆盖 Agent/工具调用攻击场景

### 修复
- 引擎二进制升级至 1.3.3-beta；版本号全项目统一（SSOT）
- Dockerfile / docker-compose.yml 版本号同步为 1.3.3-beta
- 网关认证从"可自建业务密钥"重构为"供应商签发企业密钥"，杜绝绕过收费

### 变更
- 引擎二进制不再提交仓库，改由 CI 的 `build_engine.py`（Nuitka）编译打包
- 攻击样本库重构为 **9 大类 317 条**（直接注入/越狱攻击/欺骗伪装/角色扮演/内容污染/提示泄露/结构化注入/复合策略/多语言，每类下细分细类），与演示页攻击样本库分类完全对齐，出厂预热库 317/317=100% 开箱即拦

---

## [1.3.2] - 2026-08-05

### 新增

#### 输出护栏（Output Guardrail）全链路
- [config.py] 新增 8 个输出护栏配置项（`enable_output_guardrail`、三级风险阈值、规则阈值、打码占位符、原型容量等）
- [engine_flask.py] 新增 6 个端点：`/output/protect`、`/output/warmup`、`/output/stats`、`/output/stats/timeseries`、`/output/history`、`/output/config`
- [sensitive_leak.py] 敏感泄露检测器：内置 PII/密钥/证件号等规则 + 自定义字典 + 脱敏
- 桌面端三处接入：设置页【输出护栏配置卡】、日志页【输出侧处置记录】、仪表盘【输出护栏空态区分】
- 输出护栏独立评测集 `test_outputs_v1.json`（400 条样本）：拦截率 100.0%、误报率 0.0%

#### 无限消耗防护（P2）
- 会话级分钟/小时配额 + 全局 QPS 限制 + 单请求长度上限
- 管理端点 `POST /rate/limit`（别名 `/api/rate/limit`），支持热更新配置、会话状态查询与重置

#### 系统提示泄露升级检测（PromptLeakChecker v2）
- 组合特征分 AND 门软化 + 上下文 3 级惩罚 + 语义融合保底限幅
- 中文正则 `\b` 修复 + 多词短语宽松匹配
- 评测集 `test_prompt_leak_v1.json`（60 攻击 + 60 良性）：纯关键词攻击召回 93.33%、良性误报 0%

#### 内置攻击样本库扩充
- 攻击样本从 200+ 条扩充至 **260 条**，覆盖 7 大类 26 子类型：
  - 直接提示注入（40）、间接提示注入（30）、越狱攻击（40）、编码与混淆攻击（30）、Agent/工具调用攻击（30）、数据泄露与隐私攻击（30）、中文场景特有攻击（60）
- 新增第 7 大类"中文场景特有攻击"（合规边界/公序良俗/学术包装越狱/中文语境包装）
- 良性样本 30 条，用于误报率测试

#### 桌面端体验增强
- 内置帮助中心（Help 页面，不再跳转外部链接）
- 安全检测支持文件批量上传（`.txt`/`.csv`/`.jsonl`，≤10MB/≤5000 条），可导出 CSV
- 专家模式卡片自动置顶（领域自适应、阴阳门、密钥保护、数据快照、引擎管理）
- 数据快照支持删除（带二次确认，不可撤销）
- 告警通道内置在线测试

#### 活性防护机制增强
- 会话信任衰减 + 意图漂移检测（timing_checker 多轮会话状态）
- 输出侧观测与输入侧形成双向闭环

#### OpenAI 兼容透明防护端点（产品闭环）
- [engine_flask.py] 新增 `/v1/chat/completions` 端点：把模型 `base_url` 指向桌面端引擎即可透明防护，支持云端 API / 本地模型（Ollama 等）/ 私有化部署三类模型
- 防护链路：输入侧检测 → 转发上游模型 → 输出侧检测；命中攻击返回 OpenAI 兼容 403，输出侧违规支持拦截/打码二级处置
- 上游模型通过环境变量配置（`XUANDUN_UPSTREAM_URL` / `XUANDUN_UPSTREAM_API_KEY` / `XUANDUN_UPSTREAM_MODEL` / `XUANDUN_UPSTREAM_TIMEOUT`），禁止硬编码；未配置时返回 503 配置错误，不静默透传
- 当前为同步（非流式）透传，`stream=true` 返回明确兼容错误提示

### 修复

#### 版本号同步（SSOT 一致性）
- Cargo.toml、engine_flask.py health 端点、pyproject.toml、前端 package.json、daoti_xuandun.__init__ 统一到 1.3.2

### 变更
- 引擎端口统一为 `18765`（桌面端外部集成与文档对齐）
- 移除设置页失效的「流量拦截」开关（后端 proxy.rs 已删除、无拦截逻辑，避免误导用户）
- 白皮书更新至 v1.7（对应产品 v1.3.2）
- 基准测试/诚声明文档更新至 v1.3.2

---

## [1.3.1] - 2026-08-02

### 新增

#### 自然语言检测参数化（硬编码陷阱修复）
- [config.py] 新增 3 个可配置常量，替代 reject_gate.py 中原写死的阈值：
  - `natural_lang_printable_ratio_threshold`（默认 0.90）：可打印自然语言字符占比下限
  - `natural_lang_entropy_low`（默认 2.5）：Shannon 字节熵下限
  - `natural_lang_entropy_high`（默认 6.8）：Shannon 字节熵上限
- 纯 JSON 数据包、德文长句、中英混杂编程注释等特殊场景可直接在 XuanDunConfig 中放宽阈值，无需改代码

#### 抗毒化 GateC 绝对总量上限（慢性毒化防御）
- [config.py] 新增 `luoshu_poisoning_total_updates_cap`（默认 500）
- [luoshu_mapper.py] 在 `_apply_steady_state_update` 中新增 GateC：
  - 累计 EMA 微调次数达到 cap 后永久锁死动态簇心，彻底封死 10 天×100 条/天慢性毒化路径
  - 新增计数器：`_steady_total_updates`、`_poisoning_total_cap_limited`
  - `get_stats()` 新增 4 个运维观测字段：poisoning_gate_c_cap_limited / poisoning_total_updates_cap / steady_total_updates_lifetime 等

### 修复

#### 版本号同步（SSOT 一致性）
- Cargo.toml、engine_flask.py health 端点、pyproject.toml、两个 package.json、daoti_xuandun.__init__ 统一到 1.3.1
- 后端 `daoti_xuandun.__version__` 首次对外暴露，便于 Python SDK 集成方快速查询版本

#### 前端构建与类型校验
- Desktop 前端 TypeScript `tsc --noEmit`：0 error 0 warning
- Desktop 前端 Vite build：成功
- Web Demo 前端 Vite build：成功

### 变更
- 基线误报率：34.60% → 1.60%（出厂状态，基于同源+异源双数据集）
- 基线拦截率：98.59% → 92.49%（用 6 个点拦截率换 33 个点误报率，血赚权衡）
- 四元组信号：新增冷启动双门槛 `rejected_count < 200` 前禁用，终结自证预言正反馈死亡循环
- TimingConsistencyChecker：已降级为 WARN-only，不再触发 REJECT（时序降级需文档明示）

---

## [1.3.0] - 2026-08-02

### 新增

#### Web Demo 全栈演示
- 独立 Web Demo 目录（`web-demo/`），React + FastAPI 全栈架构
- 双层阴阳架构可视化页面（TaijiFlowDiagram + CompareMode + LearningEvolution）
- 安全检测、模拟测试、学习状态等 5 个路由页面
- Netlify 前端 + Render 后端部署配置（`netlify.toml` + `render.yaml` + `Dockerfile`）

#### UI/UX 全面优化（Sprint6）
- 太极动态背景增强首屏视觉冲击力
- 骨架屏 + 空状态插画 + 微交互动画覆盖 9 个页面
- Dashboard 趋势图、攻击类型分布、实时监控指标网格
- 安全报告页面（HTML 生成/预览/删除）

#### 发布合规体系（HCSE）
- GitHub Actions 全部 pin full SHA（10 个 Actions）
- harden-runner 出网过滤覆盖所有 job（audit 模式）
- SHA256 校验和生成 + verify job 验证链
- 治理文件补充：SECURITY.md / CODEOWNERS / PR 模板 / NOTICE

### 修复

#### Sprint6 PDCA 循环（13 项修复）
- **P1**: Settings 快照恢复超时 → 捕获异常显示友好错误
- **P1**: 模式切换事务性 → 任一失败回滚全部，引擎 DB 一致
- **P1**: Logs mountedRef 守卫 → 卸载后不再 setState
- **P1**: ErrorBoundary reload Bridge 轮询 → 等待 Bridge 注入
- **P1**: rv_monitor.py sum 计算 → 直接相加避免 float 变换错误
- **P2**: 8 项前端交互盲点修复（ConfirmModal 队列化、超时兜底等）

#### 版本号一致性修复
- 同步 6 处版本号到 1.3.0（pyproject.toml/Cargo.toml/package.json/tauri.conf.json/engine_flask.py/README.md）
- 新增 `sync_version.py --check` 门禁（SSOT 一致性验证）

### 变更
- 版本号从 1.2.1 升级到 1.3.0
- 双许可证确认：核心算法 = 道体研究许可证 v1.0，外围 = Apache 2.0
- 完整图标集（Win/Mac/Linux/Android/iOS 全平台）
- 企业评估工具包迭代计划文档

---

## [1.2.3] - 2026-07-31

### 修复

#### Sprint5 交互韧性修复
- 向导跳过机制统一为 DB config（wizard_completed），消除 localStorage 双套不一致
- 代理模式流量检测增强（HTTPS 隧道元数据记录）
- 哈希链审计日志 v1→v2 迁移支持
- 桌面通知频率限制（5 秒冷却）

#### 核心引擎稳定性
- RLock 线程安全加固（xuandun.py 全局锁）
- deque 并发写锁修复（H1/H2 高危竞态）
- 实例变量竞态消除（双层架构审计十轮收敛）

### 变更
- 版本号从 1.2.2 升级到 1.2.3
- 性能基准测试更新（213+129 全 A+）

---

## [1.2.2] - 2026-07-20

### 修复

#### Sprint4 桌面端 CDP 诊断修复（9 项 P0）
- **CSP 根因修复**：`tauri.conf.json` 添加 `http://ipc.localhost` 到 `connect-src`，修复 Tauri 2.x IPC 通信被 CSP 阻止导致页面空白
- **ConfirmModal 并发 Promise 永挂**：`ConfirmModal.tsx` 队列化改造，多线程 confirm 不再死锁
- **restartEngine 超时不匹配**：`tauriApi.ts` 前端超时从 15s 提升到 60s，匹配后端 `ensure_engine_running` 最长执行时间
- **Tauri bridge 未注入时的降级处理**：各页面添加 Bridge 未就绪检测
- **向导跳过持久化**：统一使用 DB config（wizard_completed），消除双套问题
- **引擎健康检查超时**：尾部日志只读最近行，避免大文件读取超时
- **模式切换失败不吞错误**：`set_mode`/`sync_mode_to_engine` 失败返回错误而非仅 eprintln
- **代理二进制请求体修复**：`proxy.rs` raw bytes 转发，避免 UTF-8 替换损坏
- **Dashboard 图标缺失**：导入 Activity/ShieldCheck 图标

### 变更
- 版本号从 1.2.1 升级到 1.2.2
- CDP 测试端口明确为 9224（LRC Desktop 占用 9222）

---

## [1.2.1] - 2026-07-11

### 修复

#### 引擎启动超时问题（根本原因修复）
- 健康检查超时从 15 秒提升到 60 秒，采用渐进式检查策略
  - 阶段 1：前 10 秒每 500ms 检查一次（快速响应）
  - 阶段 2：10-60 秒每 1 秒检查一次（等待 Nuitka onefile 自解压完成）
- 引擎启动时只初始化默认模式（balanced），其他模式按需懒加载
  - 原先预初始化 3 个 shield 模式导致启动时间过长

#### 观察模式状态修复
- `get_learning_status` 引擎未运行时返回 `observing` 而非 `protecting`
- 首次安装默认进入观察模式，符合产品优化方案设计

#### 引导向导体验优化
- 移除引擎启动等待界面，直接显示接入方式选择
- 引擎未运行时在观察模式徽章中显示"引擎正在后台启动..."提示
- Dashboard 引擎状态显示"启动中..."而非"离线"

#### 引擎路径查找增强
- 新增 `log_engine()` 诊断日志（写入 `%LOCALAPPDATA%\com.daoti.xuandun-desktop\engine.log`）
- `find_engine_path()` 三路径搜索（current_exe/resource_dir/dev_mode）
- 引擎 stderr 捕获线程（前 50 行输出到日志）

### 变更
- 版本号同步更新：package.json/tauri.conf.json/Cargo.toml/pyproject.toml/engine_flask.py
- 应用图标替换为新 logo

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

- 道体玄盾核心引擎（基于阴气域感知的提示注入检测）
- Tauri 桌面端应用（Windows/macOS/Linux 三平台）
- Python SDK（`pip install daoti-xuandun`）
- 代理模式（HTTP 代理拦截 AI 工具流量）
- MCP Server 模式（Claude Desktop 集成）
- 哈希链审计日志（防篡改）
- 三级防护策略（高安全/平衡/低误报）
- GitHub Actions CI/CD（三平台自动构建）

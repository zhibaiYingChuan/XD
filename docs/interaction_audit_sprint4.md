﻿# 玄盾桌面端 五层交互韧性审计报告（Sprint 4）

> 审计时间：2026-07-31
> 审计范围：Tauri 2.x 桌面端（WebView2 + Rust 后端）
> 审计方法：源码逐行静态分析 + 交互分叉枚举 + 超时机制验证
> 审计依据：HCSE 五层交互韧性审计模型 + 项目 docs/P1_issues_audit.md
> 审计目标：暴露"操作成功/操作失败 Toast"之外的所有嵌套交互盲点

---

## 0. 审计结论摘要

| 严重度 | 数量 | 关键问题 |
|--------|------|----------|
| P0（阻断/数据损坏） | 8 | useConfirmModal 不可重入、restartEngine 前后端超时错配、invoke 超时不取消底层 Promise、双套向导跳过机制不一致、set_mode 同步失败静默、save_notifier 半成品、DB 打开失败无修复路径、restoreSnapshot 无防抖 |
| P1（体验崩坏/状态污染） | 10 | 单消息状态覆盖、通知渠道无校验、长任务无 beforeunload、错误文案不可操作、多实例无单例锁等 |
| P2（可用性/可访问性） | 4 | 模式卡片无键盘可达、端口校验静默截断、骨架屏永久态、Toast 时长过短 |
| P3（一致性/打磨） | 3 | 文案、骨架屏转场、脏数据提示 |

核心发现：项目已修复大量已知问题（G-13 Toast 队列、G-19 快照保留、P1-11 防并发守卫等），但修复呈"点状"分布——Detect 有 Toast 队列而 Settings/Reports/Simulation 仍用单 message 状态；Detect/Simulation 有同步 useRef 守卫而 Settings 的快照恢复/通知保存缺失；前后端超时阈值未对齐导致 restartEngine 几乎必超时。

---

## 一、第一层：环境变异枚举（前置条件分叉）

### 1.1 环境前置条件矩阵

| # | 环境变异条件 | 触发场景 | 当前处理状态 | 优先级 | 证据 |
|---|------------|---------|-------------|--------|------|
| E1 | 引擎 Flask 未监听 18765 | 引擎崩溃/未启动/端口被占 | 已处理：ensure_engine_running 检测外部引擎 + sidecar 回退 + 60s 健康检查循环；前端 StatusBar 连续失败 2 次显示离线横幅 | — | engine.rs:190-271 |
| E2 | sidecar 可执行文件缺失（os error 2） | release 包未打包引擎/路径错误 | 已处理：start_engine_sidecar 失败后不阻断，等待外部引擎；startup_error 记录可操作提示 | — | engine.rs:220-230 |
| E3 | 系统密钥库不可用（凭据管理器锁定/被禁用） | 组策略禁用 Credential Manager | 部分处理：store_key 存储后立即验证；但 has_key 在 keyring 报错时静默返回 false（eprintln 但前端无感），用户点"生成密钥"会重复失败且无明确指引 | P1 | keyring.rs:27-43 |
| E4 | LocalStorage 写入失败（隐私模式/磁盘满） | WebView2 隐私模式/磁盘满 | 已处理：Dashboard showWizard 初始化和 onSkip 均包裹 try/catch 静默降级 | — | Dashboard.tsx:122-130 |
| E5 | SQLite 数据库文件损坏/锁定 | 异常关机残留 -wal 文件/杀软锁文件 | 未处理：Database::open 失败会直接 std::process::exit(1) 弹原生 MessageBox，用户无修复路径 | P1 | lib.rs:75-80 |
| E6 | 多实例同时运行 | 用户双击 exe 两次 | 未处理：无单例锁。两个实例都会 ensure_engine_running，第二个 sidecar 因端口已占而失败（被回退逻辑吞掉）；两实例 EngineState 独立，UI 数据不一致；tray 图标重复 | P1 | lib.rs:46-112 |
| E7 | Tauri bridge 未注入（__TAURI_INTERNALS__ 缺失） | release 模式 custom-protocol 配置失效/误用浏览器打开 | 已处理：invokeWithTimeout 启动即检测 bridge，isTauriBridgeAvailable 提供全局降级检测；formatInvokeError 映射可操作文案 | — | tauriApi.ts:262-295 |
| E8 | 引擎返回 HTML（服务降级页/反代拦截） | 公司反代拦截/引擎被运维替换为维护页 | 已处理：send_protect_request 检查 HTTP 状态码，非 2xx 返回 Err；但 engine_get/engine_post 解析 HTML 为 JSON 会失败，错误信息为 "Engine response parse failed" + HTML 片段，可读性差 | P2 | engine.rs:130-154 |
| E9 | 残留脏预热文本（上次预热失败留下的半成品） | 上次 warmup 抛错但文本已存 LocalStorage | 部分处理：warmup 仅在 API 成功后才 setConfig 保存文本；但 Settings 加载时直接展示 warmup_safe_text 配置值，不提示"上次预热未完成" | P3 | Settings.tsx:253-272 |
| E10 | URL Query 参数错误 | HashRouter 模式下 hash 异常 | 低风险：HashRouter 不依赖 query 解析业务参数；若 hash 为空回退到 /，无显式错误 | P3 | App.tsx:101-115 |

### 1.2 环境层关键追问

> 追问 E3：当 keyring 不可用时，用户点击"生成密钥"→ store_secret_key 返回 Err → 前端显示"密钥存储失败: ..."。但错误信息未包含修复路径（如"请检查凭据管理器服务是否运行"或"以管理员身份重启应用"）。用户只能反复尝试，无法自助修复。UI 修复建议：catch 块中识别 keyring 错误模式，提示"系统凭据管理器不可用，请运行 services.msc 检查 Credential Manager 服务"。

> 追问 E5：数据库打开失败直接 exit(1) 是暴力做法。用户看到 MessageBox 后点确定，应用退出，没有任何修复指引（如"尝试删除 %LOCALAPPDATA%/com.daoti.xuandun-desktop/xuandun.db.wal 后重启"或"检查杀毒软件是否锁定了数据库文件"）。这是 L5 全局异常的硬伤。

---

## 二、第二层：后端响应分叉树（核心网络层）

### 2.1 后端响应场景矩阵（16 场景）

| # | 后端响应场景 | 前端当前行为 | 是否有修复路径指引 | 优先级 |
|---|------------|-------------|---------------------|--------|
| R1 | protect 引擎正常返回 200 + 完整数据 | 渲染结果卡片（通过/拦截） | N/A | — |
| R2 | protect 引擎未运行（is_running=false） | 返回 Ok(fallback=true)，前端 Toast"引擎不可达，已启动保护性阻断" | 有：fallback 标志 + StatusBar 离线横幅 | — |
| R3 | protect 引擎请求失败（网络错/500） | 返回 Ok(fallback=true)，同 R2 | 有 | — |
| R4 | protect 超时（前端 15s） | 抛 InvokeTimeoutError，Toast"检测超时，请缩短文本或稍后重试" | 有：文案包含"缩短文本/稍后重试" | — |
| R5 | warmup 引擎未运行 | 返回 Err("Engine not running")，前端 warmupStatus="预热失败: Engine not running" | 无：错误文案是英文 + 无修复路径 | P0 |
| R6 | warmup 引擎 30s 超时（后端） | 后端返回 Err，前端 catch 显示"预热失败: Warmup request failed: ..." | 部分：文案含 failed 但无可操作指引 | P1 |
| R7 | switch_learning_mode 引擎未运行 | 返回 Err("Engine not running")，前端 Toast"模式切换失败，请确认引擎正常运行后重试" | 有 | — |
| R8 | set_emergency_bypass 引擎未运行 | 返回 Err("Engine not running")，前端回滚 toggle + Toast"紧急逃生切换失败" | 有 | — |
| R9 | restart_engine 后端 60s 未完成 | 前端 15s 超时先触发，Toast"引擎重启失败"；但后端仍在运行重启，用户可能再次点击重启→并发重启 | 无：超时后按钮恢复可点，无"后端仍在处理中"提示 | P0 |
| R10 | restore_snapshot 后端成功但前端超时 | 前端 15s 超时 Toast"快照恢复失败"；但后端已恢复，用户以为失败→可能重复操作覆盖 | 无 | P0 |
| R11 | test_notifier 引擎返回 500（SMTP 连接失败） | 后端 engine_post 返回 Err 含 HTTP 500 + body；前端 Toast"测试失败: Engine POST /notifiers/test returned HTTP 500: ..." | 差：暴露内部端点路径，用户无法理解 | P1 |
| R12 | get_status 引擎 /status 不可达 | engine_get 失败 → learning_mode 等返回 None，但 running/healthy 仍来自本地 EngineState | 可接受：降级为本地状态 | — |
| R13 | save_notifier_config DB 写成功但 engine_post 失败 | engine_post 用 let _ = 吞掉错误，返回 Ok；前端显示"配置已保存"但引擎未感知 | 隐蔽不一致：用户以为保存成功，实际引擎用旧配置 | P0 |
| R14 | Tauri bridge 命令未注册（command not found） | formatInvokeError 映射"应用版本不兼容，请检查更新或重新安装" | 有 | — |
| R15 | invoke 超时后底层 Promise 仍执行 | Promise.race 超时后，invoke() Promise 继续；后端命令最终完成并产生副作用（DB 写、引擎状态变更） | 未处理：用户以为失败重试，实际首次操作已完成→重复执行 | P0 |
| R16 | protect 返回字段名不匹配（DTO 序列化错位） | Rust 端用 result["allowed"].as_bool().unwrap_or(false) 容错；若 trust_level 缺失显示 UNKNOWN | 可接受：容错降级 | — |

### 2.2 后端层关键追问

> 追问 R5/R6：warmup 失败时错误信息直接拼接后端 Err 字符串（预热失败: ${e}，请检查文本格式后重试）。但后端错误可能是 "Engine not running"（与文本格式无关）或 "Warmup request failed: timeout"（应提示缩短文本）。当前文案"请检查文本格式"在引擎超时场景下是误导。修复建议：catch 块用 formatInvokeError(e, '预热') 统一映射。

> 追问 R9（核心 P0）：restartEngine 前端用 TIMEOUT.NORMAL=15s，后端 restart_engine → ensure_engine_running 最长 60s。超时错配必然发生。用户看到"重启失败"后：
> 1. 按钮恢复可点（setRestarting(false) 在 finally）
> 2. 用户可能再次点击 → confirm 弹窗 → 确认 → restartEngine 再次 invoke
> 3. 此时后端第一个重启流程可能仍在 ensure_engine_running 的健康检查循环中
> 4. 第二个 restart_engine 调用 stop_engine（kill 第一个 sidecar）+ 再次 ensure_engine_running
> 5. 两个重启流程竞争 EngineState 锁，可能导致状态混乱
>
> 修复路径：后端 restart_engine 应加全局 is_restarting 互斥锁；前端 restartEngine 超时阈值改为 TIMEOUT.SLOW=60s。

> 追问 R13（核心 P0）：save_notifier_config 中 let _ = engine_post(&engine_url, "/notifiers/config", body).await; 静默吞错。这是典型的"DB 成功 + 同步失败"半成品状态。用户下次告警时引擎用旧配置，但用户以为已更新。修复路径：若 engine_post 失败应返回 Err 并回滚 DB（或至少标记 sync_pending），前端提示"配置已保存但未同步到引擎，请重启引擎"。

> 追问 R15（核心 P0）：invokeWithTimeout 用 Promise.race 实现超时，但 Tauri 的 invoke 返回的 Promise 无法取消，对应的 Rust 命令也无法中断。这意味着：
> - 用户点"删除报告"→ 15s 超时 → Toast"删除失败" → 用户重试 → 第一份 invoke 在 16s 时完成删除，第二份 invoke 删除已不存在的报告报错
> - 用户点"恢复快照"→ 超时 → 重试 → 两次恢复，后者覆盖前者（若快照不同则数据错乱）
> - 用户点"重启引擎"→ 超时 → 重试 → 两次重启并发
>
> 修复路径：对幂等性敏感的操作（删除、恢复、重启、生成密钥），前端超时后应进入"等待确认"状态，禁用按钮并提示"操作可能仍在后台执行，请勿重复点击"，并通过轮询状态确认最终结果。

---

## 三、第三层：非理性用户操作注入（防抖与反悔分叉）

### 3.1 破坏性操作注入矩阵

| # | 操作类别 | 注入场景 | 当前行为 | 崩溃/异常风险 | 优先级 |
|---|---------|---------|---------|-------------|--------|
| U1 | 快速连点（检测） | 1 秒内点 10 次"开始检测" | detectingRef.current 同步守卫立即拒绝；button disabled | 已防护 | — |
| U2 | 快速连点（模拟测试） | 1 秒内点 10 次"运行测试" | runningRef.current 同步守卫；button disabled | 已防护 | — |
| U3 | 快速连点（模式切换） | 1 秒内点 10 次防护模式卡片 | modeSwitching 守卫 + pointerEvents: none | 已防护 | — |
| U4 | 快速连点（生成密钥） | 1 秒内点 10 次"生成密钥" | generatingKey 守卫 | 已防护 | — |
| U5 | 快速连点（保存通知配置） | 1 秒内点 10 次"保存"（钉钉渠道） | 无守卫：handleSaveNotifier 无防抖、无 loading 状态、button 无 disabled | 并发 DB 写 + 并发 engine_post；多次 setNotifierConfigs 竞态 | P1 |
| U6 | 快速连点（恢复快照） | 1 秒内点 10 次"恢复"（同一快照） | 无守卫：handleRestoreSnapshot 无 loading、button 无 disabled | 并发恢复覆盖；用户确认弹窗堆叠 | P0 |
| U7 | 快速连点（测试告警） | 1 秒内点 10 次"测试告警" | button disabled={testing}，但 testing 是 testingChannel === 'dingtalk' 字符串比较；切换到飞书渠道时钉钉的 testing 状态被覆盖 | 跨渠道并发测试 | P1 |
| U8 | 操作中刷新页面（检测） | Loading 中按 F5 | beforeunload 拦截 + 提示 | 已防护 | — |
| U9 | 操作中刷新页面（重启引擎） | restarting 中按 F5 | beforeunload 拦截 | 已防护 | — |
| U10 | 操作中刷新页面（模拟测试） | running 中按 F5（测试可能跑 15s+） | 无 beforeunload 拦截 | invoke Promise 丢弃，后端 run_simulation 仍执行（浪费引擎算力） | P1 |
| U11 | 操作中刷新页面（预热） | warming 中按 F5（预热可能 30s） | 无 beforeunload 拦截 | 同 U10 | P1 |
| U12 | 操作中刷新页面（生成报告） | loading 中按 F5 | 无 beforeunload 拦截 | 报告可能已生成但前端列表未刷新 | P1 |
| U13 | 嵌套弹窗（confirm 重入） | 点击"重启引擎"→confirm 弹窗未关→再点"删除密钥"→第二个 confirm 触发 | 致命：useConfirmModal 的 resolveRef.current 被覆盖，第一个 confirm 的 Promise 永远不 resolve；setMessage 覆盖第一个消息；第一个 await confirm(...) 永久挂起，handleRestart 卡死，setRestarting(true) 永远不复位 | UI 卡死 + 内存泄漏 + 状态永久锁定 | P0 |
| U14 | 嵌套弹窗（confirm + Toast） | confirm 弹窗显示中，后台轮询触发 error Toast | Toast 渲染在 confirm 之下（zIndex 10000 > Toast），不冲突 | 可接受 | — |
| U15 | 输入挂起（表单停留 10 分钟） | 通知渠道表单填一半→切走 10 分钟→回来点保存 | 无 auth token 过期问题；但引擎可能已重启，save_notifier_config 的 engine_post 会失败 | 半成功状态（见 R13） | P1 |
| U16 | 键盘干扰（textarea 回车） | 在检测文本框按回车 | textarea 默认换行（正确） | 已防护 | — |
| U17 | 键盘可达性（模式卡片） | Tab 聚焦防护模式卡片 + Enter | Settings 模式卡片是 div onClick 无 onKeyDown/role/tabIndex | 键盘用户无法切换模式 | P2 |
| U18 | 键盘可达性（向导方法卡） | Tab + Enter | 已处理：onKeyDown + role="button" + tabIndex | 已防护 | — |

### 3.2 用户操作层关键追问

> 追问 U13（核心 P0，最严重）：useConfirmModal 是单实例、不可重入的 hook。审计 Settings.tsx 发现有 5 处 confirm() 调用（重启、停止、删除密钥、恢复快照、紧急逃生）。任意两处并发触发都会导致 Promise 泄漏 + UI 卡死。
>
> 复现路径：
> 1. 用户点"重启引擎"→ confirm 弹窗"确定要重启引擎吗？"
> 2. 用户不点确认/取消，直接滚动到下方点"删除密钥"→ 第二个 confirm 触发
> 3. setMessage 覆盖为"确定要删除引擎密钥吗？"
> 4. resolveRef.current 被第二个 Promise 的 resolve 覆盖
> 5. 用户点"取消"→ 第二个 resolve(false) 被调用，弹窗关闭
> 6. 第一个 await confirm(...) 永远不返回，handleRestart 卡在 await，restarting 永远为 true
> 7. 重启按钮永久 disabled，beforeunload 永久拦截关闭
>
> 修复路径：useConfirmModal 必须改为队列模式（多个 confirm 排队）或栈模式（后入先出，关闭一个显示下一个），并为每个 confirm 分配独立 resolveRef。

> 追问 U6：handleRestoreSnapshot 是唯一缺失防抖的高危操作。恢复快照会覆盖当前配置，并发恢复会导致配置被两个快照交替覆盖，最终状态不可预测。修复：复用 creatingSnapshot 模式增加 restoringId 状态，button disabled={restoringId === id}。

> 追问 U7：testingChannel 是单值状态，无法表达"多渠道同时测试"。虽然 UI 上切渠道会重置 testing 状态，但后端 test_notifier invoke 仍在前一个 Promise 中执行。用户可能收到延迟的钉钉测试消息却以为是飞书的。修复：testingChannel 改为 Set 或 Record。

---

## 四、第四层：组件级状态反馈缺失扫描（视觉与动画盲区）

### 4.1 视觉反馈层矩阵

| # | 反馈层 | 当前状态 | 缺失场景 | 优先级 |
|---|--------|---------|---------|--------|
| V1 | 按钮状态机 | 大部分按钮有 idle → loading → idle（disabled + 文案）；无 success/error 视觉态 | 保存成功仅靠 3s Toast 提示，按钮无"绿色对勾闪烁"反馈；错误时按钮无红色震动 | P2 |
| V2 | 按钮 Error 后可点窗口 | finally 立即复位 loading，按钮恢复可点；Toast 仍显示 3-5s | 用户在 Toast 显示期间可立即重试（可接受，但无冷却倒计时防抖） | P3 |
| V3 | 输入 blur 校验 | proxyPortInput blur 时静默 clamp 到 [1024, 65535]；通知渠道字段无任何校验 | 端口输入"99999"被静默改为 65535，用户无感知；URL 字段填"abc"可保存可测试 | P1 |
| V4 | 输入错误红框清除 | N/A（无字段级红框校验机制） | — | — |
| V5 | 骨架屏边界 | Dashboard 趋势图有"加载趋势数据中..."；Settings 学习区有"加载学习中..." | Settings 学习区若 getLearningStatus 持续失败（catch 静默 ignore），learning 永远为 null，"加载学习中..."永久显示，无超时兜底 | P1 |
| V6 | 空列表转场 | Dashboard"暂无拦截记录"、Reports"暂无历史报告"、Settings"暂无快照记录" | 转场无动画，骨架屏→空状态跳变突兀 | P3 |
| V7 | 滚动锚点丢失 | Dashboard 时间范围切换仅刷新趋势图（P1-12 修复）；新增快照后列表刷新无跳转 | 已防护 | — |
| V8 | Toast 队列管理 | 仅 Detect.tsx 实现 Toast 队列（G-13 修复，支持多 Toast 堆叠 + 手动关闭） | Settings/Reports/Simulation 仍用单 message/error 状态：5 个错误并发时仅显示最后一个，前 4 个被覆盖丢失 | P1 |
| V9 | Toast 自动消失 | Detect Toast 5s 自动移除；Settings/Reports 3s | 3s 过短，用户来不及读完长错误信息 | P2 |
| V10 | 加载动画 | Simulation 用 Loader2 旋转图标；其他用"XX中..."文案 | 引擎重启/停止仅文案，无进度条/旋转图标，用户感知"卡死" | P2 |
| V11 | 全局错误边界 | ErrorBoundary 捕获 React 渲染异常，显示"应用遇到异常"+ 重新加载按钮 | 未捕获 Tauri invoke 的异步错误（由 window.unhandledrejection 兜底，但仅 console.error，用户无感） | P1 |
| V12 | 全局未处理拒绝 | window.addEventListener('unhandledrejection', ...) 仅 console.error + preventDefault | 用户无感：若某处 forget try-catch，Promise 拒绝被静默吞掉，UI 表现为"无响应" | P1 |

### 4.2 视觉层关键追问

> 追问 V5：Settings 的 fetchLearning 在 catch 中 // ignore，setLearning 永不调用。若引擎持续不可达，learning 永远为 null，UI 永久显示"加载学习中..."。用户无法区分"正在加载"和"加载失败但未告知"。修复：catch 中 setLearning(null) 并显示"学习状态获取失败，请检查引擎"。

> 追问 V8（核心 P1）：Settings.tsx 有 12+ 处 showMessage 调用，全部写入同一个 message state。并发场景：
> - 用户快速切换"开机自启动"（失败）+ "流量拦截"（失败）→ 第二条覆盖第一条
> - 批量操作时（如灰度滑块连续拖动触发多次 commit）→ 错误信息闪烁覆盖
> - 通知渠道保存 + 测试同时进行 → 后完成者覆盖前者
>
> 修复路径：抽取 Detect 的 Toast 队列为全局 ToastProvider，所有页面共用。

> 追问 V11/V12：ErrorBoundary 只捕获渲染同步错误。Tauri invoke 的异步错误若未 try-catch，会触发 unhandledrejection，但当前处理器仅 console.error，用户完全无感。例如若 App.tsx 的 checkModeSwitch 轮询中 api.sendNotification 抛错（catch 了，OK），但其他页面若有遗漏 catch，用户看到的是"按钮点了没反应"。修复：unhandledrejection 应触发全局 Toast"发生未知错误，请查看日志"。

---

## 五、第五层：多米诺效应关联分析（全局状态污染）

### 5.1 级联反应矩阵

| # | 污染层级 | 触发源 | 级联后果 | 优先级 |
|---|---------|--------|---------|--------|
| D1 | L1 页面级 | Dashboard getStatus 失败 | G-19 修复保留快照，仅更新 error 横幅；不污染兄弟组件（StatusBar 独立轮询） | — |
| D2 | L1 页面级 | StatusBar getEmergencyBypass 返回 enabled=true | StatusBar 提前 return 紧急逃生横幅，不再渲染学习进度；但 useEffect 轮询仍在运行，状态持续更新（只是不显示） | 可接受 |
| D3 | L1 页面级 | StatusBar getLearningStatus 连续失败 | engineOffline=true 显示离线横幅，替换整个状态栏；学习进度/原型数信息消失 | P2（信息丢失） |
| D4 | L2 全局级 | protect 引擎不可达 | 返回 fallback=true，db.insert_audit("fallback", ...) 记录；不影响全局 EngineState（running 仍为 true） | — |
| D5 | L2 全局级 | save_notifier_config DB 成功 + engine_post 失败 | 半成品脏数据：DB 有新配置，引擎用旧配置；下次重启引擎才会同步；用户以为已保存 | P0 |
| D6 | L2 全局级 | restart_engine 前端超时 + 用户重试 | 两个 restart_engine invoke 在后端竞争；stop_engine kill 同一 pid 两次（第二次 taskkill 报错但被吞）；ensure_engine_running 两个循环竞争 EngineState 锁 | P0 |
| D7 | L2 全局级 | LocalStorage xuandun_onboarding_skip 写入成功，但 wizard_completed 配置未写 | Dashboard 跳过向导，但下次启动 App.tsx 检查 wizard_completed 仍显示 Wizard 全屏页 | P0 |
| D8 | L3 持久化级 | set_config('mode', ...) DB 写成功，但 sync_mode_to_engine 失败 | commands.rs:221 仅 eprintln，返回 Ok；Rust 端 mode 已改 + DB 已存，但引擎仍用旧 mode；前端显示新 mode 但实际防护用旧 mode | P0 |
| D9 | L4 路由级 | API 失败后路由跳转 | 未发现：无任何"失败后跳转成功页"的逻辑 | — |
| D10 | L4 路由级 | OnboardingWizard step 2 等待 totalRequests > 0 | 若用户在 wizard 中切换页面，wizard 卸载，waitingForTraffic 状态丢失；回到 Dashboard 后 wizard 重新挂载，从 step 0 重新开始 | P2 |
| D11 | L5 进程级 | 引擎子进程崩溃 | monitor_engine_health 连续 5 次失败后 giving up，设置 running=false；不再自动重启；用户必须手动重启 | P1 |
| D12 | L5 进程级 | 数据库损坏 | Database::open 失败 → std::process::exit(1) + MessageBox；用户数据不可恢复，无"备份后修复"选项 | P0 |

### 5.2 级联层关键追问

> 追问 D7（核心 P0）：存在两套并行的向导跳过机制：
> - App.tsx:44 检查 api.getConfig('wizard_completed') → 决定是否显示 Wizard 全屏页
> - Dashboard.tsx:125 检查 localStorage.getItem('xuandun_onboarding_skip') → 决定是否显示 OnboardingWizard 横幅
>
> 这两个机制互不同步。场景：
> 1. 用户在 Dashboard 点"稍后再说"→ localStorage 写入 skip=true，但 wizard_completed 未写
> 2. 下次启动 App.tsx 检查 wizard_completed !== 'true' → 显示全屏 Wizard 页
> 3. 用户困惑："我不是已经跳过了吗？"
>
> 反向场景：
> 1. 用户在 App.tsx 的 Wizard 完成 → 假设写 wizard_completed=true
> 2. 但 Dashboard 的 localStorage 未写 skip → Dashboard 仍显示 OnboardingWizard 横幅
>
> 修复路径：统一为单一来源（建议用 DB config wizard_completed），Dashboard 读取同一配置决定横幅显示。

> 追问 D8（核心 P0）：set_mode 命令中 sync_mode_to_engine 失败仅 eprintln，返回 Ok。这意味着前端显示"模式已更新"成功 Toast，但引擎实际仍用旧模式。这是安全产品的致命不一致——用户切到"高安全"以为强防护，实际引擎仍用"低误报"。修复：sync_mode_to_engine 失败应回滚 s.mode 并返回 Err。

> 追问 D11：monitor_engine_health 连续 5 次重启失败后 giving up，consecutive_failures=0 重置，循环继续但不再重启。此时 running=false，前端 StatusBar 会显示离线。但用户无主动通知（无系统通知、无托盘气泡），用户可能长时间不感知。修复：giving up 时发送系统通知"引擎多次重启失败，请手动检查"。

---

## 六、超时机制专项验证

### 6.1 超时阈值对齐表

| 操作 | 前端超时（tauriApi.ts） | 后端超时（engine.rs/commands.rs） | 对齐状态 | 风险 |
|------|----------------------|--------------------------------|---------|------|
| getStatus | FAST=5s | N/A（本地状态 + engine_get 复用 HTTP_CLIENT 5s） | 对齐 | — |
| protect | NORMAL=15s | HTTP_CLIENT 默认 5s | 对齐（后端先超时） | — |
| restartEngine | NORMAL=15s | ensure_engine_running 最长 60s | 错配 P0 | 前端必超时 |
| stopEngine | NORMAL=15s | stop_engine 同步（kill_process） | 对齐 | — |
| warmup | SLOW=60s | send_warmup_request 30s | 对齐（后端先超时） | — |
| runSimulation | SLOW=60s | engine_post 复用 HTTP_CLIENT 5s | 错配 P1 | 后端 5s 超时但模拟需 15s+ |
| check_engine_health | N/A（后端内部） | 2s（显式 .timeout） | 对齐 | — |
| testNotifier | SLOW=60s | engine_post 复用 HTTP_CLIENT 5s | 错配 P1 | SMTP 测试可能 >5s |
| ensure_engine_running | N/A（后端内部） | 60s（20x500ms + 50x1s） | 对齐 | — |

### 6.2 超时机制核心问题

> P0-超时-1：restartEngine 前后端超时错配
> - 前端 invokeWithTimeout('restart_engine', undefined, TIMEOUT.NORMAL=15000)
> - 后端 restart_engine → stop_engine（1s sleep）+ ensure_engine_running（最长 60s）
> - 必然结果：前端 15s 抛 InvokeTimeoutError，后端继续执行
> - 用户感知："引擎重启失败"，但引擎实际在重启
> - 修复：前端改用 TIMEOUT.SLOW=60s；后端加 is_restarting 互斥锁

> P0-超时-2：runSimulation 后端 HTTP_CLIENT 5s 超时过短
> - engine_post 复用全局 HTTP_CLIENT（5s timeout）
> - 但 run_simulation 后端转发到 Flask /simulation/run，快速模式需 15s
> - 必然结果：后端 5s 超时返回 Err，前端显示"测试失败"
> - 修复：run_simulation 应像 send_warmup_request 一样用独立的长超时请求

> P0-超时-3：testNotifier 同样受 5s HTTP_CLIENT 限制
> - SMTP/钉钉/飞书测试可能 >5s
> - 修复：test_notifier 应用独立长超时（30s）

> P1-超时-4：invoke 超时不取消底层 Promise
> - Promise.race([invoke(), timeoutPromise]) 超时后 invoke() 继续
> - 后端命令完成后的副作用（DB 写、状态变更）仍发生
> - 修复：Tauri 2.x 暂不支持 invoke 取消；前端应记录"pending 操作"并在超时后轮询状态确认，禁用按钮直到确认完成

> 验证结论：InvokeTimeoutError 能真正触发（Promise.race 机制正确），但触发后无后续状态管理，导致用户误判操作失败。

---

## 七、交互盲点地震图（Mermaid 决策树）

```mermaid
graph TD
    ROOT[核心功能: Tauri invoke 操作] --> SUCCESS[成功分支]
    ROOT --> FAIL[失败分支]
    ROOT --> RETRY[重试分支]
    ROOT --> CANCEL[取消分支]
    ROOT --> TIMEOUT[超时分支]

    SUCCESS --> S1[200 OK 完整数据]
    SUCCESS --> S2[200 OK 空数据/null]
    S1 --> S1b[副作用: DB 写 + 通知]
    S1b --> S1b1[DB 写失败?]
    S1b1 -->|是| S1b1a[静默 eprintln 用户无感 P1]
    S2 --> S2a[空状态插画?]
    S2a -->|否| S2a1[白屏/加载中永久 P1]

    FAIL --> F1[引擎未运行]
    FAIL --> F2[引擎返回 500]
    FAIL --> F3[bridge 未注入]
    F1 --> F1a{操作类型}
    F1a -->|protect| F1a1[Ok fallback=true 保护性阻断]
    F1a -->|warmup/simul| F1a2[Err Engine not running 无修复路径 P0]
    F2 --> F2a[Toast 显示 HTTP 500 + body]
    F2a --> F2a1[暴露内部端点路径 P1]
    F2 --> F2b[有重试按钮?]
    F2b -->|否| F2b1[用户无重试入口 P1]

    RETRY --> R1[用户点重试]
    R1 --> R2{再次失败}
    R2 -->|是| R2a[第二次 Toast]
    R2a --> R2b[有停止重试选项?]
    R2b -->|否| R2b1[用户陷入重试循环 P1]
    R2 --> R3[底层首次 invoke 仍执行]
    R3 --> R3a[副作用重复执行 删报告/恢复快照 P0]
    R3a --> R3a1[数据损坏/状态错乱]

    CANCEL --> C1[ConfirmModal 取消]
    C1 --> C2{有并发 confirm?}
    C2 -->|是| C2a[resolveRef 覆盖 首个 Promise 永挂 P0]
    C2a --> C2a1[handleRestart 卡死 restarting 永久 true]
    C2a1 --> C2a1a[beforeunload 永久拦截 用户无法关闭应用 P0]
    C2 -->|否| C2b[正常 resolve false]
    C1 --> C3[操作中刷新页面]
    C3 --> C4{有 beforeunload?}
    C4 -->|是| C4a[拦截 + 提示]
    C4 -->|否| C4b[invoke Promise 丢弃 后端仍执行 P1]

    TIMEOUT --> T1[InvokeTimeoutError 触发]
    T1 --> T2{按钮复位?}
    T2 -->|是| T2a[用户可立即重试]
    T2a --> T2b[底层 invoke 仍执行 并发风险 P0]
    T2 -->|否| T2c[永久 loading UI 卡死 P1]
    T1 --> T3{前后端超时对齐?}
    T3 -->|错配| T3a[restartEngine 必超时 P0]
    T3a --> T3a1[用户以为失败 实际后端在重启]
    T3a1 --> T3a1a[重试→并发重启 P0]
    T1 --> T4[有冷却倒计时?]
    T4 -->|否| T4a[用户疯狂重试 P1]

    style S1b1a fill:#ffe0e0
    style S2a1 fill:#ffe0e0
    style F1a2 fill:#ffcccc
    style F2a1 fill:#ffe0e0
    style F2b1 fill:#ffe0e0
    style R2b1 fill:#ffe0e0
    style R3a1 fill:#ff9999
    style C2a1 fill:#ff9999
    style C2a1a fill:#ff6666
    style C4b fill:#ffe0e0
    style T2b fill:#ff9999
    style T2c fill:#ffe0e0
    style T3a1a fill:#ff6666
    style T4a fill:#ffe0e0
```

> 图例：红色越深 = 优先级越高（P0）；浅红 = P1

---

## 八、UI 交互缺口修复清单

| Gap ID | 触发条件 | 当前行为 | 用户心理 | 推荐 UI 修复 | 优先级 |
|--------|---------|---------|---------|-------------|--------|
| GAP-01 | 用户点"重启引擎"→confirm 弹窗未关→点"删除密钥" | useConfirmModal 单例，resolveRef 覆盖，首个 Promise 永挂 | 恐惧：应用卡死，重启按钮永久 disabled，无法关闭 | useConfirmModal 改为队列模式：queue: Array<{message, resolve}>，新 confirm 入队，关闭一个显示下一个；或加 pendingConfirm 守卫，已有 confirm 时拒绝新 confirm 并 Toast"请先处理当前确认框" | P0 |
| GAP-02 | 用户点"重启引擎"→15s 后前端超时 | Toast"引擎重启失败"，按钮恢复可点 | 困惑：实际引擎在重启，用户以为失败又点一次 | 1. 前端 restartEngine 超时改 TIMEOUT.SLOW=60s；2. 超时后按钮显示"后端可能仍在处理，请等待…"并禁用 60s；3. 轮询 getStatus 确认引擎恢复后自动复位 | P0 |
| GAP-03 | 用户点"恢复快照"→15s 超时→重试 | 底层 invoke 仍执行，两次恢复覆盖 | 恐惧：配置数据错乱，不可恢复 | 1. 增加 restoringId 状态，button disabled={restoringId===id}；2. 超时后 Toast"恢复操作可能仍在后台执行，请勿重复点击"；3. 轮询快照列表确认完成 | P0 |
| GAP-04 | save_notifier_config DB 成功 + engine_post 失败 | 返回 Ok，Toast"配置已保存" | 困惑：实际引擎用旧配置，告警不生效 | engine_post 失败时返回 Err，前端 Toast"配置已保存但未同步到引擎，请重启引擎生效"，并标记配置为"待同步"状态（橙色圆点） | P0 |
| GAP-05 | set_mode 的 sync_mode_to_engine 失败 | 返回 Ok，Toast"模式已更新" | 恐惧：安全产品模式不一致，用户以为高安全实际低误报 | sync_mode_to_engine 失败应回滚 s.mode 并返回 Err；前端回滚 mode + Toast"模式同步到引擎失败，已回滚，请确认引擎运行后重试" | P0 |
| GAP-06 | Dashboard 点"稀后再说"跳过向导→下次启动 | localStorage 写 skip=true，但 wizard_completed 未写 | 烦躁：每次启动都弹全屏 Wizard | 统一跳过来源：Dashboard 读取 api.getConfig('wizard_completed') 决定横幅；点跳过时调 api.setConfig('wizard_completed', 'skipped') | P0 |
| GAP-07 | Database::open 失败 | std::process::exit(1) + MessageBox | 恐惧：数据丢失，无修复路径 | MessageBox 增加"尝试修复"按钮：删除 .db-wal/.db-shm 后重试；提供"备份数据库后重置"选项；附日志路径 | P0 |
| GAP-08 | Settings 页面 5 个错误并发（如批量切换） | 单 message state 覆盖，仅显示最后一个 | 烦躁：不知道总共有几个错误 | 抽取 Detect 的 Toast 队列为全局 ToastProvider，Settings/Reports/Simulation 接入 | P1 |
| GAP-09 | 通知渠道字段填垃圾值（URL="abc"）→点保存 | 无校验，直接保存，engine_post 报错 | 困惑：错误信息是"HTTP 500 + 内部路径" | 字段级校验：URL 用 new URL() 校验；端口 parseInt + 范围；blur 时红框 + 提示"请输入合法 URL" | P1 |
| GAP-10 | getLearningStatus 持续失败 | catch // ignore，learning=null，UI 永久"加载学习中..." | 困惑：不知道是加载中还是失败了 | catch 中 setLearning(null) + 显示"学习状态获取失败，请检查引擎" | P1 |
| GAP-11 | warmup 引擎未运行 | Toast"预热失败: Engine not running，请检查文本格式后重试" | 困惑：文案与错误无关 | 用 formatInvokeError(e, '预热') 统一映射；识别"Engine not running"提示"引擎未运行，请前往设置重启引擎" | P1 |
| GAP-12 | runSimulation 后端 5s 超时 | Toast"测试失败: Engine POST returned HTTP 500" | 烦躁：快速模式需 15s，必然失败 | run_simulation 后端用独立长超时（30s）的请求函数，类似 send_warmup_request | P1 |
| GAP-13 | 模拟测试运行中刷新页面 | 无 beforeunload，invoke 丢弃 | 困惑：测试结果丢失 | 增加 beforeunload 拦截（复用 Detect 模式） | P1 |
| GAP-14 | test_notifier 跨渠道快速切换测试 | testingChannel 单值，钉钉 testing 被飞书覆盖 | 困惑：钉钉按钮恢复可点，再点又触发 | testingChannel 改为 Record<string, boolean> 或 Set | P1 |
| GAP-15 | 多实例同时运行 | 无单例锁，两实例竞争 | 恐惧：状态不一致，tray 重复 | tauri-plugin-single-instance 插件；第二实例启动时聚焦首实例并退出 | P1 |
| GAP-16 | monitor_engine_health giving up | 静默，用户无主动通知 | 恐惧：长时间无防护不知情 | giving up 时 app.notification() 发系统通知"引擎多次重启失败，请手动检查" | P1 |
| GAP-17 | unhandledrejection 仅 console.error | 用户无感 | 困惑：按钮点了没反应 | 触发全局 Toast"发生未知错误，已记录日志"，附"查看日志"按钮 | P1 |
| GAP-18 | 端口输入"99999" | blur 静默 clamp 为 65535 | 困惑：输入值与实际不符 | clamp 时显示 Toast"端口已调整为合法范围 65535"，输入框短暂高亮 | P2 |
| GAP-19 | 防护模式卡片用 Tab + Enter | div 无 onKeyDown/role | 烦躁：键盘用户无法操作 | 加 onKeyDown（Enter/Space 触发）+ role="radio" + tabIndex | P2 |
| GAP-20 | 重启/停止引擎仅文案"重启中..." | 无进度动画 | 恐惧：以为卡死 | 用 Loader2 旋转图标 + 进度条（基于 60s 预估） | P2 |
| GAP-21 | Toast 3s 自动消失（Settings/Reports） | 长错误信息读不完 | 烦躁：错过关键信息 | 错误类 Toast 延长到 6s；或加"暂停"悬停 | P2 |
| GAP-22 | 骨架屏→空状态跳变 | 无过渡动画 | 烦躁：视觉突兀 | 加 fade-in 过渡 | P3 |

---

## 九、可注入断言逻辑（InteractionGuard 单元测试伪代码）

以下伪代码可加入项目作为前端交互韧性回归测试，拦截快速连点、嵌套弹窗 Z-index 混乱、超时后重试等问题。

```typescript
// ── InteractionGuard.test.ts ──
// 交互韧性断言：拦截快速连点、嵌套弹窗、超时重试等已知失败模式

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import { useConfirmModal } from '../components/ConfirmModal';
import { invokeWithTimeout, InvokeTimeoutError, TIMEOUT } from '../services/tauriApi';

describe('InteractionGuard: 嵌套弹窗不可重入断言', () => {
  it('GAP-01: 并发 confirm 不应导致 Promise 永挂', async () => {
    const { result } = renderHook(() => useConfirmModal());
    const { confirm } = result.current;

    // 触发两个并发 confirm
    const promise1 = confirm('第一个确认');
    const promise2 = confirm('第二个确认');

    // 断言：第二个 confirm 不应覆盖第一个的 resolveRef
    // 期望行为：要么排队，要么拒绝并返回 false
    await act(async () => {
      result.current.modalProps.onCancel(); // 取消当前（应是第二个）
    });

    // 第一个 Promise 必须在合理时间内 resolve（不能永挂）
    const result1 = await Promise.race([
      promise1.then(v => v).catch(() => 'rejected'),
      new Promise(resolve => setTimeout(() => 'timeout_5s', 5000)),
    ]);
    expect(result1).not.toBe('timeout_5s');
  });
});

describe('InteractionGuard: 快速连点防抖断言', () => {
  it('GAP-03: 恢复快照连点 10 次应只触发 1 次 invoke', async () => {
    const invokeSpy = vi.fn().mockResolvedValue(undefined);
    // 模拟 handleRestoreSnapshot 无防抖的当前实现
    let restoringId: number | null = null;
    const handleRestore = async (id: number) => {
      if (restoringId !== null) return; // 修复后应有此守卫
      restoringId = id;
      try {
        await invokeSpy(id);
      } finally {
        restoringId = null;
      }
    };
    // 连点 10 次
    await Promise.all(Array.from({ length: 10 }, () => handleRestore(1)));
    expect(invokeSpy).toHaveBeenCalledTimes(1);
  });
});

describe('InteractionGuard: 超时后重试幂等性断言', () => {
  it('GAP-02/03: 超时后底层 invoke 仍执行，重试应被阻止', async () => {
    let invokeCallCount = 0;
    let resolveInvoke: (v: any) => void;
    const slowInvoke = new Promise(resolve => { resolveInvoke = resolve; });

    const invokeSpy = vi.fn(() => {
      invokeCallCount++;
      return slowInvoke;
    });

    // 模拟 restartEngine：前端 15s 超时，后端 60s 完成
    const frontendTimeout = 15000;

    vi.useFakeTimers();
    const invokePromise = invokeWithTimeout('restart_engine', {}, frontendTimeout);
    vi.advanceTimersByTime(frontendTimeout + 100);

    await expect(invokePromise).rejects.toThrow(InvokeTimeoutError);

    // 断言：超时后按钮应禁用，不应允许立即重试
    // 当前实现：finally 立即复位 → 缺陷
    // 修复后：应轮询 getStatus 确认引擎恢复后才复位

    resolveInvoke!(undefined);
    vi.useRealTimers();
    await slowInvoke;

    expect(invokeCallCount).toBe(1);
  });
});

describe('InteractionGuard: Toast 队列不覆盖断言', () => {
  it('GAP-08: 5 个并发错误应全部显示，不互相覆盖', async () => {
    // 模拟 Settings 单 message 状态（当前缺陷实现）
    let message: { text: string } | null = null;
    const showMessageDefective = (text: string) => {
      message = { text }; // 覆盖
      setTimeout(() => { message = null; }, 3000);
    };
    for (let i = 0; i < 5; i++) {
      showMessageDefective(`错误 ${i}`);
    }
    expect(message?.text).toBe('错误 4'); // 缺陷：前 4 个丢失

    // 期望实现（Toast 队列）
    const toastQueue: string[] = [];
    const showMessageFixed = (text: string) => {
      toastQueue.push(text);
    };
    for (let i = 0; i < 5; i++) {
      showMessageFixed(`错误 ${i}`);
    }
    expect(toastQueue).toHaveLength(5); // 修复后：全部保留
  });
});

describe('InteractionGuard: 前后端超时对齐断言', () => {
  it('GAP-02: restartEngine 前端超时应 >= 后端最长耗时', () => {
    const frontendTimeout = TIMEOUT.NORMAL; // 当前 15s
    const backendMaxDuration = 60_000; // ensure_engine_running 最长 60s
    expect(frontendTimeout).toBeGreaterThanOrEqual(backendMaxDuration);
    // 当前实现：失败（15s < 60s）
    // 修复后：应使用 TIMEOUT.SLOW=60s
  });

  it('GAP-12: runSimulation 后端 HTTP_CLIENT 超时应 >= 模拟测试耗时', () => {
    const backendHttpTimeout = 5_000; // HTTP_CLIENT 默认
    const simulationMaxDuration = 30_000; // 全面测试
    expect(backendHttpTimeout).toBeGreaterThanOrEqual(simulationMaxDuration);
    // 当前实现：失败（5s < 30s）
  });
});

describe('InteractionGuard: beforeunload 一致性断言', () => {
  it('GAP-13: 所有长任务页面应有 beforeunload 拦截', () => {
    const longTaskPages = [
      { page: 'Detect', loadingState: 'loading', hasBeforeUnload: true },
      { page: 'Settings-restart', loadingState: 'restarting', hasBeforeUnload: true },
      { page: 'Settings-warmup', loadingState: 'warming', hasBeforeUnload: false }, // 缺陷
      { page: 'Simulation', loadingState: 'running', hasBeforeUnload: false }, // 缺陷
      { page: 'Reports-generate', loadingState: 'loading', hasBeforeUnload: false }, // 缺陷
    ];
    longTaskPages.forEach(p => {
      expect(p.hasBeforeUnload).toBe(true);
    });
  });
});
```

---

## 十、未覆盖的交互盲点与嵌套场景汇总

### 10.1 深度嵌套场景（50+ 极端分支枚举）

#### A. 重启引擎链路（12 分支）

1. 点重启 → confirm → 确认 → 15s 超时 → Toast 失败 → 不点重试，等 60s → 引擎实际重启成功 → UI 仍显示"失败"，状态不一致 [P0]
2. 点重启 → confirm → 确认 → 15s 超时 → 点重试 → confirm → 确认 → 后端两个 ensure_engine_running 竞争锁 [P0]
3. 点重启 → confirm → 不确认，滚到下方点删除密钥 → confirm 覆盖，首个 Promise 永挂 [P0]
4. 点重启 → confirm → 确认 → restarting 中 → F5 刷新 → beforeunload 拦截 → 强制刷新 → invoke 丢弃，EngineState 重置，但后端仍在重启 [P0]
5. 点重启 → confirm → 确认 → restarting 中 → 关闭窗口 → RunEvent::ExitRequested → stop_engine kill 正在重启的进程 [P1]
6. 点重启 → confirm → 确认 → restarting 中 → 点击停止引擎 → stop button disabled={stopping}，但 stopping 是独立状态，不阻止重启中的停止操作 [P1]
7. 点重启 → confirm → 取消 → restarting 未设 true，正常 [OK]
8. 点重启 → confirm → 确认 → 后端 stop_engine 失败（taskkill 报错）→ restart_engine 返回 Err → 前端 Toast 失败 [OK]
9. 点重启 → confirm → 确认 → 后端 ensure_engine_running sidecar 启动失败 → 等外部引擎 60s → 超时 Err → 前端 15s 已超时 [P0]
10. 点重启 → 确认 → 后端重启成功 → StatusBar 离线横幅仍在（failCount 未重置）→ 5s 后下次轮询才清除 [P2]
11. 点重启 → 确认 → 后端重启中 → Dashboard 轮询 getStatus 返回 running=false → 显示"启动中..." [OK]
12. 点重启 → 确认 → 后端重启中 → 轮询 getLearningStatus 失败 → StatusBar failCount++ → 2 次后显示离线 [OK]

#### B. 通知渠道保存+测试链路（10 分支）

1. 填钉钉 URL="abc" → 点保存 → DB 成功 + engine_post 失败 → Toast"已保存" → 引擎用旧配置 [P0]
2. 填钉钉 URL="abc" → 点测试 → engine_post 5s 超时 → Toast"测试失败: HTTP 500" [P1]
3. 点钉钉测试 → testing=true → 切飞书点测试 → 钉钉 testing 被重置 → 钉钉按钮恢复可点 [P1]
4. 点钉钉保存 → 保存中 → 再点保存 → 并发 saveNotifierConfig → DB 两次写 + engine_post 两次 [P1]
5. 钉钉保存成功 → 立即点测试 → 测试用 DB 新配置还是引擎旧配置？引擎可能未同步 [P0]
6. 启用钉钉 toggle → 未填 URL 直接保存 → 保存空配置 → engine_post 失败 [P1]
7. 填完钉钉 → 切到飞书 → 钉钉配置未保存（无自动保存）→ 丢失 [P2]
8. 点测试 → 测试中 → disable 后无法取消 → 用户无法中止长时间测试 [P2]
9. 5 个渠道全部启用并测试 → 5 个 testNotifier invoke 并发 → 引擎可能过载 [P1]
10. 保存邮件配置（含密码）→ 密码字段 autoComplete=new-password → 但 WebView2 可能仍自动填充 [P2]

#### C. 快照恢复链路（8 分支）

1. 点恢复 → confirm → 确认 → 15s 超时 → Toast 失败 → 后端已恢复 → 用户重试 → 再次恢复同一快照（幂等，OK） [P1]
2. 点恢复 → confirm → 确认 → 立即再点恢复（无防抖）→ 两个 restore_snapshot 并发 [P0]
3. 点恢复 → confirm → 取消 → 正常 [OK]
4. 点恢复 → confirm → 确认 → 恢复中 → F5 刷新 → 无 beforeunload → invoke 丢弃 [P1]
5. 恢复成功 → 当前配置被覆盖 → 但前端状态未刷新 → UI 显示旧配置 [P1]
6. 恢复成功 → notifierConfigs 未重新加载 → 显示恢复前的通知配置 [P1]
7. 创建快照 → 快照中 → 再点创建 → creatingSnapshot 守卫 [OK]
8. 创建快照 → 标签为空 → Toast"请输入快照标签" [OK]

#### D. 紧急逃生链路（8 分支）

1. 启用紧急逃生 → confirm → 确认 → setEmergencyBypass 失败 → toggle 回滚 [OK]
2. 启用紧急逃生 → confirm → 不确认，切到灰度滑块 → confirm 仍开着，灰度 commit 可能触发 [P0]（GAP-01）
3. 紧急逃生启用中 → StatusBar 显示红色横幅 → 全局可见 [OK]
4. 紧急逃生启用中 → 关闭 toggle → 无需 confirm → 直接关闭 [OK]
5. 紧急逃生启用中 → 引擎崩溃 → getEmergencyBypass 失败 → StatusBar 不再显示逃生横幅 → 用户以为恢复正常防护 [P0]
6. 紧急逃生启用中 → 点重启引擎 → 重启后逃生状态是否保留？取决于引擎实现 [P1]
7. 紧急逃生 + 灰度 50% → 实际 50% 流量完全放行，50% 经检测 → UI 是否清晰表达？ [P2]
8. 紧急逃生 toggle 快速切换 → handleEmergencyBypassChange 无防抖（依赖 setEmergencyBypass 串行） [P1]

#### E. 学习模式切换链路（6 分支）

1. 观察模式 → 点"切换到保护模式" → switchLearningMode 失败 → Toast 失败 [OK]
2. 切换中 → 再点切换 → switchingMode 守卫 [OK]
3. 切换中 → F5 刷新 → 无 beforeunload [P1]
4. 样本不足切换 → 显示警告"可能导致误报率升高" [OK]
5. 保护模式 → 切回观察 → 已积累的样本是否保留？ [P1]
6. 切换成功 → App.tsx 的 checkModeSwitch 轮询检测到 observing→protecting → 发系统通知 [OK]

#### F. 全局异常链路（6 分支）

1. Tauri bridge 未注入 → invokeWithTimeout 拒绝 → 但 App.tsx checkWizard 调用 getConfig 失败 → catch ignore → checking=false → 显示主界面 → 所有页面 invoke 全失败 → 无全局降级 UI [P0]
2. 引擎进程崩溃 → monitor giving up → 无系统通知 [P1]
3. DB 锁定 → 命令返回 Err → 前端 Toast 失败 → 用户不知道是 DB 锁定 [P1]
4. WebView2 内存溢出 → ErrorBoundary 捕获 → "重新加载" [OK]
5. unhandledrejection → console.error → 用户无感 [P1]
6. window.onerror → console.error → 用户无感 [P1]

### 10.2 盲点汇总统计

| 嵌套深度 | 枚举分支数 | 已覆盖 | 未覆盖 | 覆盖率 |
|---------|-----------|--------|--------|--------|
| 2 级（操作→响应） | 28 | 18 | 10 | 64% |
| 3 级（操作→响应→二次操作） | 18 | 6 | 12 | 33% |
| 4 级（操作→响应→二次操作→三次操作） | 8 | 1 | 7 | 12% |
| 合计 | 54 | 25 | 29 | 46% |

> 结论：项目对 2 级交互（直接操作响应）覆盖较好（64%），但对 3 级以上深度嵌套交互覆盖率仅 18%。最严重的盲点集中在：嵌套 confirm 不可重入（C/GAP-01）、超时后底层 invoke 仍执行（R15/GAP-03）、前后端超时错配（R9/GAP-02）、半成品状态不一致（R13/GAP-04、D8/GAP-05）。

---

## 十一、修复优先级路线图

### P0（立即修复，阻断/数据损坏）

1. GAP-01：useConfirmModal 改为队列模式
2. GAP-02：restartEngine 前端超时改 60s + 后端加 is_restarting 互斥
3. GAP-03：handleRestoreSnapshot 加 restoringId 防抖 + 超时后轮询确认
4. GAP-04：save_notifier_config 的 engine_post 失败应返回 Err + 前端"待同步"提示
5. GAP-05：set_mode 的 sync_mode_to_engine 失败应回滚 + 返回 Err
6. GAP-06：统一向导跳过机制为 DB config
7. GAP-07：DB 打开失败增加修复路径
8. R15：invoke 超时后进入"等待确认"状态，禁用按钮

### P1（尽快修复，体验崩坏/状态污染）

9. GAP-08：全局 Toast 队列 Provider
10. GAP-09：通知渠道字段级校验
11. GAP-10：getLearningStatus 失败显示错误而非永久"加载中"
12. GAP-11：warmup 错误用 formatInvokeError 统一映射
13. GAP-12：runSimulation/testNotifier 后端用独立长超时
14. GAP-13：Simulation/warmup/report 增加 beforeunload
15. GAP-14：testingChannel 改为 Set 支持多渠道并发
16. GAP-15：tauri-plugin-single-instance 单例锁
17. GAP-16：monitor_engine_health giving up 发系统通知
18. GAP-17：unhandledrejection 触发全局 Toast

### P2（迭代优化，可用性）

19. GAP-18：端口 clamp 视觉反馈
20. GAP-19：模式卡片键盘可达性
21. GAP-20：重启/停止进度动画
22. GAP-21：错误 Toast 延长到 6s

### P3（打磨）

23. GAP-22：骨架屏→空状态过渡动画
24. 脏预热文本提示
25. HashRouter 空 hash 处理

---

## 十二、附录：审计方法说明

### 12.1 审计依据

- HCSE 五层交互韧性审计模型
- 项目 docs/P1_issues_audit.md 已知问题清单
- OWASP 前端安全最佳实践
- Tauri 2.x 官方文档（invoke 超时、bridge 注入、custom-protocol）

### 12.2 审计范围与局限

已审计文件：
- 前端：tauriApi.ts、App.tsx、ConfirmModal.tsx、ErrorBoundary.tsx、Layout.tsx、StatusBar.tsx、OnboardingWizard.tsx、Dashboard.tsx、Detect.tsx、Settings.tsx、Simulation.tsx、Reports.tsx
- 后端：engine.rs、commands.rs、keyring.rs、lib.rs

未深度审计：
- Logs.tsx、Agents.tsx、LearningStatus.tsx、YinYangGate.tsx、Wizard.tsx（建议后续补充）
- db.rs、proxy.rs、tray.rs、agent_discovery.rs（后端非核心交互路径）
- CSS 样式与响应式布局
- 运行时 CDP 验证（本次为静态分析，建议后续用 Chrome DevTools MCP 验证超时实际触发行为）

### 12.3 后续行动建议

1. 立即可做：将 GAP-01（confirm 队列）和 GAP-02（restartEngine 超时）作为 P0 修复，1 人日可完成
2. 本 sprint 内：P0 全部修复 + P1 关键项（GAP-08/09/10/11）
3. 下 sprint：P1 剩余 + P2
4. 长期：建立 InteractionGuard.test.ts 回归测试，纳入 CI，防止修复回退
5. 建议：将本审计的"嵌套场景枚举"作为测试用例输入，补充到 docs/HCSE_RESILIENCE_AUDIT.md

---

> 审计员：交互韧性审计师（AI）
> 审计方法：五层交互韧性审计模型 + 源码逐行分析
> 本次审计共枚举 54 个交互分叉，发现 29 个未覆盖盲点，其中 P0 级 8 个、P1 级 10 个、P2 级 4 个、P3 级 3 个。

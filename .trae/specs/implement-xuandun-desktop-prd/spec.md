# 道体·玄盾桌面端缺陷修复与功能完善 Spec

## Why

上一轮实现标记所有任务为完成，但实际代码验证发现多个关键缺陷：4 个 Tauri 命令未注册导致前端调用失败、Flask 引擎缺少 `/set-mode` 端点导致模式同步失败、`stop_engine` 不终止 Sidecar 进程、托盘模式切换不同步引擎、流量代理无法实际转发请求等。这些问题导致桌面端应用无法正常运行，需要系统性修复。

## What Changes

### 关键缺陷修复
- **BREAKING**: `lib.rs` 补注册 `get_config`、`set_config`、`restart_engine`、`stop_engine` 四个命令
- **BREAKING**: `engine_flask.py` 添加 `/set-mode` 端点，否则 Rust 层 `sync_mode_to_engine` 调用 404
- **BREAKING**: `engine.rs` 的 `stop_engine` 需实际终止 Sidecar 进程而非仅设标志

### 功能完善
- `tray.rs` 模式切换需同步到引擎并持久化到 SQLite
- `proxy.rs` 实现真正的 HTTP 正向代理（解析请求 → 检查 → 转发/拦截）
- `engine_flask.py` 移除已废弃的 `@app.before_first_request`
- `build_engine.py` 添加 `--windows-disable-console` 避免引擎弹出控制台窗口
- `db.rs` 修复 `md5_hash` 函数名误导（改用 md5 crate 或重命名）
- `db.rs` 修复 `query_logs`/`count_logs` 中 SQL 拼接的注入风险
- `agent_discovery.rs` 修复 Aider/Open Interpreter 匹配 python.exe 导致误报

## Impact

- Affected specs: 全部桌面端功能
- Affected code:
  - `desktop/xuandun-desktop/src-tauri/src/lib.rs` — 补注册命令
  - `desktop/xuandun-desktop/src-tauri/src/engine.rs` — stop_engine 实际终止进程
  - `desktop/xuandun-desktop/src-tauri/src/tray.rs` — 模式同步与持久化
  - `desktop/xuandun-desktop/src-tauri/src/proxy.rs` — 实现真正的 HTTP 代理
  - `desktop/xuandun-desktop/src-tauri/src/db.rs` — 修复哈希函数和 SQL 注入
  - `desktop/xuandun-desktop/src-tauri/src/agent_discovery.rs` — 修复误报
  - `desktop/xuandun-desktop/src-tauri/Cargo.toml` — 添加 md-5 crate
  - `desktop/xuandun-desktop/engine_flask.py` — 添加 /set-mode 端点、移除废弃 API
  - `desktop/xuandun-desktop/build_engine.py` — 添加 --windows-disable-console

## ADDED Requirements

### Requirement: Tauri 命令完整注册

系统 SHALL 在 `lib.rs` 的 `invoke_handler` 中注册所有已定义的 Tauri 命令，确保前端可调用。

#### Scenario: 前端调用 get_config
- **WHEN** 前端通过 `invoke("get_config", { key })` 调用
- **THEN** 命令正常执行，返回配置值
- **AND** 不出现 "Command not found" 错误

#### Scenario: 前端调用 restart_engine
- **WHEN** 前端通过 `invoke("restart_engine")` 调用
- **THEN** 引擎实际重启并恢复运行

### Requirement: Flask 引擎 /set-mode 端点

系统 SHALL 在 Flask 引擎中提供 `/set-mode` 端点，接收模式变更请求。

#### Scenario: Rust 后端同步模式到引擎
- **WHEN** 用户切换防护模式
- **THEN** Rust 后端调用 `POST /set-mode` 成功
- **AND** 引擎切换到对应防护模式

### Requirement: Sidecar 进程实际终止

系统 SHALL 在 `stop_engine` 时实际终止 Sidecar 子进程。

#### Scenario: 停止引擎
- **WHEN** 用户点击"停止引擎"
- **THEN** Sidecar 子进程被终止
- **AND** 不留下孤儿进程

### Requirement: 托盘模式切换同步

系统 SHALL 在托盘菜单切换模式时同步到引擎并持久化。

#### Scenario: 托盘切换模式
- **WHEN** 用户通过托盘菜单切换防护模式
- **THEN** 模式变更同步到 Python 引擎
- **AND** 模式变更持久化到 SQLite
- **AND** 托盘菜单的勾选状态更新

### Requirement: 真正的 HTTP 正向代理

系统 SHALL 实现完整的 HTTP 正向代理，能够解析请求、检查安全、转发或拦截。

#### Scenario: 正常请求转发
- **WHEN** 代理拦截到发往 LLM API 的正常请求
- **THEN** 请求被完整转发到目标服务器
- **AND** 目标服务器的响应被返回给客户端
- **AND** 延迟增加 < 10ms

#### Scenario: 恶意请求拦截
- **WHEN** 代理拦截到包含恶意注入的请求
- **THEN** 请求被阻止，返回 403 响应
- **AND** 弹出桌面通知

### Requirement: SQL 参数化查询

系统 SHALL 使用参数化查询构建 SQL，防止 SQL 注入。

#### Scenario: 日志查询
- **WHEN** 调用 `query_logs` 或 `count_logs`
- **THEN** SQL 使用参数化查询而非字符串拼接

## MODIFIED Requirements

### Requirement: Agent 进程发现精确匹配

Agent 发现 SHALL 使用更精确的匹配规则，避免将普通 Python 进程误识别为 Aider 或 Open Interpreter。

## REMOVED Requirements

### Requirement: @app.before_first_request
**Reason**: Flask 2.3+ 已移除此装饰器
**Migration**: 使用 `with app.app_context()` 或在启动时直接执行初始化逻辑

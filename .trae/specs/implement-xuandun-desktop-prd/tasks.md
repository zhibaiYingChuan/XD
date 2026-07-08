# Tasks

## Phase 1: 关键缺陷修复（阻塞性问题）

- [x] Task 1: 补注册 Tauri 命令
  - [x] 1.1 在 `lib.rs` 的 `invoke_handler` 中添加 `commands::get_config`
  - [x] 1.2 在 `lib.rs` 的 `invoke_handler` 中添加 `commands::set_config`
  - [x] 1.3 在 `lib.rs` 的 `invoke_handler` 中添加 `commands::restart_engine`
  - [x] 1.4 在 `lib.rs` 的 `invoke_handler` 中添加 `commands::stop_engine`
  - [x] 1.5 验证前端调用 `getConfig`、`setConfig`、`restartEngine`、`stopEngine` 不再报错

- [x] Task 2: Flask 引擎添加 /set-mode 端点
  - [x] 2.1 在 `engine_flask.py` 中添加 `POST /set-mode` 路由
  - [x] 2.2 端点接收 `{"mode": "high_security|balanced|low_false_positive"}` 请求体
  - [x] 2.3 更新 `_default_mode` 变量并预热新模式对应的 XuanDun 实例
  - [x] 2.4 返回 `{"status": "ok", "mode": "<new_mode>"}` 响应
  - [x] 2.5 验证 Rust 后端 `sync_mode_to_engine` 调用成功

- [x] Task 3: 修复 stop_engine 实际终止 Sidecar 进程
  - [x] 3.1 在 `EngineState` 中添加 `child_pid: Option<u32>` 字段
  - [x] 3.2 在 `start_engine_sidecar` 中记录子进程 PID
  - [x] 3.3 在 `stop_engine` 中通过 PID 终止子进程（Windows: `taskkill`，Unix: `kill`）
  - [x] 3.4 验证停止引擎后无孤儿进程残留

## Phase 2: 功能完善

- [x] Task 4: 托盘模式切换同步与持久化
  - [x] 4.1 修改 `tray.rs` 的模式切换事件处理，调用 `sync_mode_to_engine`
  - [x] 4.2 修改 `tray.rs` 的模式切换事件处理，调用 `db.set_config("mode", mode)`
  - [x] 4.3 更新托盘菜单 CheckMenuItem 的勾选状态
  - [x] 4.4 验证托盘切换模式后引擎实际切换

- [x] Task 5: 实现真正的 HTTP 正向代理
  - [x] 5.1 重写 `proxy.rs` 的 `handle_proxy_connection`，解析完整 HTTP 请求
  - [x] 5.2 提取目标主机和端口，建立到目标服务器的 TCP 连接
  - [x] 5.3 对 LLM API 请求提取 prompt 并调用引擎检查
  - [x] 5.4 正常请求：将原始请求转发到目标服务器，将响应返回客户端
  - [x] 5.5 恶意请求：返回 403 拦截响应并弹出通知
  - [x] 5.6 支持 HTTPS CONNECT 方法（隧道模式）
  - [x] 5.7 验证代理可正常转发请求到 OpenAI/Anthropic API

- [x] Task 6: 修复 db.rs 哈希函数和 SQL 注入
  - [x] 6.1 在 `Cargo.toml` 中添加 `md-5` crate
  - [x] 6.2 将 `md5_hash` 函数改用真正的 MD5 算法
  - [x] 6.3 修复 `query_logs` 中 SQL 拼接为参数化查询
  - [x] 6.4 修复 `count_logs` 中 SQL 拼接为参数化查询
  - [x] 6.5 验证日志查询和计数功能正常

## Phase 3: 质量修复

- [x] Task 7: 修复 engine_flask.py 废弃 API
  - [x] 7.1 移除 `@app.before_first_request` 装饰器
  - [x] 7.2 将初始化逻辑移到 `main()` 函数中（启动时直接执行）
  - [x] 7.3 验证引擎正常启动无警告

- [x] Task 8: 修复 build_engine.py 控制台窗口
  - [x] 8.1 在 Nuitka 编译参数中添加 `--windows-disable-console`
  - [x] 8.2 验证编译后的引擎不弹出控制台窗口

- [x] Task 9: 修复 agent_discovery.rs 误报
  - [x] 9.1 移除 Aider 匹配规则中的 `python.exe`/`python3`
  - [x] 9.2 移除 Open Interpreter 匹配规则中的 `python.exe`/`python3`
  - [x] 9.3 仅保留 `aider.exe`/`interpreter.exe` 精确匹配
  - [x] 9.4 验证普通 Python 进程不再被误识别

## 额外修复：Tauri 2 API 兼容性

- [x] Task 10: 修复 Tauri 2 API 兼容性问题
  - [x] 10.1 修复 `tray.rs` — `TrayIconBuilder::with_id` 参数、`set_tooltip` 签名、CheckMenuItem 直接引用
  - [x] 10.2 修复 `engine.rs` — 添加 `use tauri::Manager`、`ShellExt` trait、PID 类型
  - [x] 10.3 修复 `proxy.rs` — 添加 `use tauri::Manager`、`NotificationExt` trait
  - [x] 10.4 修复 `commands.rs` — `NotificationExt` trait 替换
  - [x] 10.5 修复 `lib.rs` — `create_tray(app.handle())`
  - [x] 10.6 修复 `db.rs` — 模式解构类型注解
  - [x] 10.7 修复 `agent_discovery.rs` — sysinfo 0.33 `refresh_processes` API
  - [x] 10.8 修复 `cookie`/`time` crate 版本冲突 — 添加 `time = "=0.3.36"`
  - [x] 10.9 创建 Sidecar 占位文件以通过编译检查

# Task Dependencies

- Task 1 无依赖，可立即执行
- Task 2 无依赖，可立即执行
- Task 3 无依赖，可立即执行
- Task 4 依赖 Task 2（需要 /set-mode 端点可用）
- Task 5 无依赖，可立即执行
- Task 6 无依赖，可立即执行
- Task 7 无依赖，可立即执行
- Task 8 无依赖，可立即执行
- Task 9 无依赖，可立即执行
- Task 10 依赖 Task 1-9（需要所有代码修改完成后再修复编译问题）

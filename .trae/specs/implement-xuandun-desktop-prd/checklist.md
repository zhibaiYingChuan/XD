# 道体·玄盾桌面端缺陷修复 Checklist

## Phase 1: 关键缺陷修复

- [x] `lib.rs` 的 `invoke_handler` 包含 `commands::get_config`
- [x] `lib.rs` 的 `invoke_handler` 包含 `commands::set_config`
- [x] `lib.rs` 的 `invoke_handler` 包含 `commands::restart_engine`
- [x] `lib.rs` 的 `invoke_handler` 包含 `commands::stop_engine`
- [x] 前端调用 `getConfig` 返回正确配置值（非 Command not found）
- [x] 前端调用 `setConfig` 成功写入配置
- [x] 前端调用 `restartEngine` 引擎实际重启
- [x] 前端调用 `stopEngine` 引擎实际停止
- [x] `engine_flask.py` 包含 `POST /set-mode` 路由
- [x] `/set-mode` 端点接受 `{"mode": "high_security|balanced|low_false_positive"}` 请求体
- [x] `/set-mode` 端点更新 `_default_mode` 并预热对应 XuanDun 实例
- [x] Rust 后端 `sync_mode_to_engine` 调用 `/set-mode` 返回 200
- [x] `EngineState` 包含 `child_pid` 字段
- [x] `start_engine_sidecar` 记录子进程 PID
- [x] `stop_engine` 通过 PID 终止子进程
- [x] 停止引擎后无孤儿进程残留

## Phase 2: 功能完善

- [x] 托盘模式切换调用 `sync_mode_to_engine` 同步到引擎
- [x] 托盘模式切换调用 `db.set_config("mode", mode)` 持久化
- [x] 托盘菜单 CheckMenuItem 勾选状态随模式切换更新
- [x] 代理可解析完整 HTTP 请求（方法、URL、头部、请求体）
- [x] 代理可建立到目标服务器的 TCP 连接并转发请求
- [x] 代理将目标服务器响应返回客户端
- [x] 代理对恶意请求返回 403 拦截响应
- [x] 代理支持 HTTPS CONNECT 隧道模式
- [x] `Cargo.toml` 包含 `md-5` crate
- [x] `db.rs` 的哈希函数使用真正的 MD5 算法
- [x] `query_logs` 使用参数化查询（无 SQL 拼接）
- [x] `count_logs` 使用参数化查询（无 SQL 拼接）

## Phase 3: 质量修复

- [x] `engine_flask.py` 不包含 `@app.before_first_request`
- [x] 引擎启动无 Flask 废弃 API 警告
- [x] `build_engine.py` 包含 `--windows-disable-console` 参数
- [x] Aider 匹配规则不包含 `python.exe`/`python3`
- [x] Open Interpreter 匹配规则不包含 `python.exe`/`python3`
- [x] 普通 Python 进程不被误识别为 Aider 或 Open Interpreter

## Tauri 2 API 兼容性

- [x] `tray.rs` 使用 `TrayIconBuilder::with_id("xuandun-tray")` 正确签名
- [x] `tray.rs` 使用 CheckMenuItem 直接引用更新勾选状态
- [x] `tray.rs` 使用 `set_tooltip(Some(...))` 正确签名
- [x] `engine.rs` 使用 `use tauri::Manager` 和 `ShellExt` trait
- [x] `engine.rs` 使用 `app.shell()` 替代 `Shell::new(app)`
- [x] `proxy.rs` 使用 `use tauri::Manager` 和 `NotificationExt` trait
- [x] `proxy.rs` 使用 `app.notification().builder()` 替代 `Notification::new(app)`
- [x] `commands.rs` 使用 `NotificationExt` trait
- [x] `lib.rs` 使用 `create_tray(app.handle())` 正确传参
- [x] `db.rs` 模式解构类型注解正确
- [x] `agent_discovery.rs` 使用 sysinfo 0.33 `refresh_processes` API
- [x] `Cargo.toml` 包含 `time = "=0.3.36"` 修复版本冲突

## 编译验证

- [x] `cargo check` 编译通过无错误（仅 3 个无害 warning）
- [x] `npm run build` 前端构建通过

// Tauri 命令通过 IPC 从 JS 调用，编译器无法静态追踪调用链，因此允许 dead_code
#![allow(dead_code)]

use tauri::Manager;

mod commands;
mod db;
mod engine;
mod tray;
mod keyring;

#[cfg(target_os = "windows")]
pub fn show_message_box(title: &str, body: &str) {
    use std::ffi::CString;
    let title_c = match CString::new(title) { Ok(s) => s, Err(_) => return };
    let body_c = match CString::new(body) { Ok(s) => s, Err(_) => return };
    unsafe {
        #[link(name = "user32")]
        extern "system" {
            fn MessageBoxA(hwnd: *mut std::ffi::c_void, text: *const i8, caption: *const i8, utype: u32) -> i32;
        }
        MessageBoxA(std::ptr::null_mut(), body_c.as_ptr(), title_c.as_ptr(), 0x10);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn show_message_box(title: &str, body: &str) {
    eprintln!("{}: {}", title, body);
}

fn setup_log(msg: &str) {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("com.daoti.xuandun-desktop");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("crash.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = writeln!(f, "[{}] {}", chrono::Utc::now().to_rfc3339(), msg);
    }
    eprintln!("[XuanDun] {}", msg);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // PB-10 修复：第二个实例启动时聚焦主窗口，防止多实例状态不一致
            let _ = app.get_webview_window("main").map(|w| {
                let _ = w.show();
                let _ = w.set_focus();
            });
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(std::sync::Mutex::new(engine::EngineState::new()))
        .setup(|app| {
            setup_log("Setup: start");

            let app_data_dir = app.path().app_data_dir()
                .map_err(|e| {
                    let msg = format!("Failed to get app data dir: {}", e);
                    setup_log(&msg);
                    msg
                })?;
            setup_log(&format!("Setup: app_data_dir = {}", app_data_dir.display()));

            std::fs::create_dir_all(&app_data_dir)
                .map_err(|e| {
                    let msg = format!("Failed to create app data dir: {}", e);
                    setup_log(&msg);
                    msg
                })?;

            let db_path = app_data_dir.join("xuandun.db");
            setup_log(&format!("Setup: db_path = {}", db_path.display()));

            let database = db::Database::open(&db_path)
                .map_err(|e| {
                    // GAP-07 修复：DB 打开失败时提供可操作的修复路径，而非直接 exit(1)
                    let msg = format!(
                        "数据库打开失败：{}\n\n数据库路径：{}\n\n修复建议：\n1. 检查磁盘空间是否充足\n2. 检查文件权限（右键→属性→安全）\n3. 删除损坏的数据库文件后重启（注意：历史日志将丢失）\n4. 以管理员身份运行应用",
                        e, db_path.display()
                    );
                    setup_log(&msg);
                    msg
                })?;
            app.manage(database);
            setup_log("Setup: database opened");

            match tray::create_tray(app.handle()) {
                Ok(_tray) => setup_log("Setup: tray created"),
                Err(e) => {
                    let msg = format!("Setup: tray creation failed (non-fatal): {}", e);
                    setup_log(&msg);
                }
            }

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = engine::ensure_engine_running(&handle).await {
                    // 引擎启动失败时更新 EngineState，让前端知道启动出错了
                    if let Ok(mut s) = handle.state::<std::sync::Mutex<engine::EngineState>>().lock() {
                        s.startup_error = Some(e.clone());
                    }
                    let log_path = std::env::var_os("LOCALAPPDATA")
                        .map(|p| format!("{:?}\\com.daoti.xuandun-desktop\\engine.log", p))
                        .unwrap_or_else(|| "engine.log".to_string());
                    eprintln!("[XuanDun] Engine start error: {}", e);
                    eprintln!("[XuanDun] See {} for engine crash diagnostics", log_path);
                }
            });
            let health_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                engine::monitor_engine_health(&health_handle).await;
            });
            setup_log("Setup: complete");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::protect,
            commands::check_output,
            commands::set_mode,
            commands::get_logs,
            commands::get_config,
            commands::set_config,
            commands::restart_engine,
            commands::stop_engine,
            commands::warmup,
            commands::verify_audit,
            commands::store_secret_key,
            commands::get_secret_key,
            commands::delete_secret_key,
            commands::has_secret_key,
            commands::create_snapshot,
            commands::list_snapshots,
            commands::restore_snapshot,
            commands::delete_snapshot,
            commands::get_learning_status,
            commands::get_dual_layer_stats,
            commands::get_output_stats,
            commands::get_output_history,
            commands::get_output_trend,
            commands::get_output_config,
            commands::set_output_config,
            commands::set_emergency_bypass,
            commands::get_emergency_bypass,
            commands::set_gray_deploy_ratio,
            commands::get_gray_deploy_ratio,
            commands::get_bypass_stats,
            commands::send_notification,
            commands::get_trend_stats,
            commands::get_attack_distribution,
            commands::get_realtime_metrics,
            commands::get_comparison_stats,
            commands::save_notifier_config,
            commands::get_notifier_config,
            commands::test_notifier,
            // 上游模型可视化配置（设置页表单，引擎启动时注入环境变量）
            commands::get_upstream_config,
            commands::set_upstream_config,
            // Sprint1-P0-7: IPC析构散落报错修复——noop心跳命令注册
            commands::noop_heartbeat,
            // UI修复：打开引擎日志文件（Dashboard启动失败时可点击跳转）
            commands::open_engine_log,
        ])
        .build(tauri::generate_context!());

    let app = match app {
        Ok(a) => a,
        Err(e) => {
            let msg = format!("Failed to build tauri application: {}", e);
            setup_log(&msg);
            show_message_box(
                "XuanDun Startup Error",
                &format!(
                    "Application failed to start:\n\n{}\n\nCrash log: %LOCALAPPDATA%\\com.daoti.xuandun-desktop\\crash.log",
                    e
                ),
            );
            std::process::exit(1);
        }
    };

    app.run(|app_handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
            let _ = engine::stop_engine(app_handle);
        }
        _ => {}
    });
}

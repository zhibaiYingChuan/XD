use tauri::Manager;

mod commands;
mod db;
mod engine;
mod tray;
mod agent_discovery;
mod proxy;
mod keyring;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(std::sync::Mutex::new(engine::EngineState::new()))
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()
                .map_err(|e| format!("Failed to get app data dir: {}", e))?;
            std::fs::create_dir_all(&app_data_dir)
                .map_err(|e| format!("Failed to create app data dir: {}", e))?;
            let db_path = app_data_dir.join("xuandun.db");
            let database = db::Database::open(&db_path)
                .map_err(|e| format!("Failed to open database: {}", e))?;
            app.manage(database);

            tray::create_tray(app.handle())?;
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = engine::ensure_engine_running(&handle).await {
                    eprintln!("Engine start error: {}", e);
                }
            });
            let health_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                engine::monitor_engine_health(&health_handle).await;
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::protect,
            commands::set_mode,
            commands::discover_agents,
            commands::get_logs,
            commands::start_proxy_cmd,
            commands::stop_proxy_cmd,
            commands::is_proxy_running_cmd,
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
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
            let _ = engine::stop_engine(app_handle);
        }
        _ => {}
    });
}

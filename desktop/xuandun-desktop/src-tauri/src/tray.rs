use tauri::{
    AppHandle, Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu, CheckMenuItem},
    tray::{TrayIcon, TrayIconBuilder},
};

pub fn create_tray(app: &AppHandle) -> Result<TrayIcon, String> {
    let show = MenuItem::with_id(app, "show", "显示主界面", true, None::<&str>)
        .map_err(|e| e.to_string())?;

    let mode_high = CheckMenuItem::with_id(app, "mode_high", "高安全", true, false, None::<&str>)
        .map_err(|e| e.to_string())?;
    let mode_balanced = CheckMenuItem::with_id(app, "mode_balanced", "平衡", true, true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let mode_low = CheckMenuItem::with_id(app, "mode_low", "低误报", true, false, None::<&str>)
        .map_err(|e| e.to_string())?;

    let mode_submenu = Submenu::with_items(
        app,
        "防护模式",
        true,
        &[&mode_high, &mode_balanced, &mode_low],
    ).map_err(|e| e.to_string())?;

    let separator = PredefinedMenuItem::separator(app).map_err(|e| e.to_string())?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)
        .map_err(|e| e.to_string())?;

    let menu = Menu::with_items(app, &[&show, &mode_submenu, &separator, &quit])
        .map_err(|e| e.to_string())?;

    let tray = TrayIconBuilder::with_id("xuandun-tray")
        .icon(app.default_window_icon().cloned().unwrap_or_else(|| {
            tauri::image::Image::new(&[0u8; 4], 1, 1)
        }))
        .tooltip("道体·玄盾 - 守护中")
        .menu(&menu)
        .on_menu_event(move |app, event| {
            match event.id.as_ref() {
                "show" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "mode_high" => {
                    if let Ok(mut s) = app.state::<std::sync::Mutex<crate::engine::EngineState>>().lock() {
                        let _ = s.set_mode("high_security");
                    }
                    let engine_url = app.state::<std::sync::Mutex<crate::engine::EngineState>>().lock().ok().map(|s| s.get_engine_url()).unwrap_or_default();
                    tauri::async_runtime::spawn(async move {
                        let _ = crate::engine::sync_mode_to_engine(&engine_url, "high_security").await;
                    });
                    if let Some(db) = app.try_state::<crate::db::Database>() {
                        let _ = db.set_config("mode", "high_security");
                    }
                    let _ = mode_high.set_checked(true);
                    let _ = mode_balanced.set_checked(false);
                    let _ = mode_low.set_checked(false);
                }
                "mode_balanced" => {
                    if let Ok(mut s) = app.state::<std::sync::Mutex<crate::engine::EngineState>>().lock() {
                        let _ = s.set_mode("balanced");
                    }
                    let engine_url = app.state::<std::sync::Mutex<crate::engine::EngineState>>().lock().ok().map(|s| s.get_engine_url()).unwrap_or_default();
                    tauri::async_runtime::spawn(async move {
                        let _ = crate::engine::sync_mode_to_engine(&engine_url, "balanced").await;
                    });
                    if let Some(db) = app.try_state::<crate::db::Database>() {
                        let _ = db.set_config("mode", "balanced");
                    }
                    let _ = mode_high.set_checked(false);
                    let _ = mode_balanced.set_checked(true);
                    let _ = mode_low.set_checked(false);
                }
                "mode_low" => {
                    if let Ok(mut s) = app.state::<std::sync::Mutex<crate::engine::EngineState>>().lock() {
                        let _ = s.set_mode("low_false_positive");
                    }
                    let engine_url = app.state::<std::sync::Mutex<crate::engine::EngineState>>().lock().ok().map(|s| s.get_engine_url()).unwrap_or_default();
                    tauri::async_runtime::spawn(async move {
                        let _ = crate::engine::sync_mode_to_engine(&engine_url, "low_false_positive").await;
                    });
                    if let Some(db) = app.try_state::<crate::db::Database>() {
                        let _ = db.set_config("mode", "low_false_positive");
                    }
                    let _ = mode_high.set_checked(false);
                    let _ = mode_balanced.set_checked(false);
                    let _ = mode_low.set_checked(true);
                }
                "quit" => {
                    app.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)
        .map_err(|e| e.to_string())?;

    Ok(tray)
}

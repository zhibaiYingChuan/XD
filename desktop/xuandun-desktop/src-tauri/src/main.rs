#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

fn crash_log_path() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("com.daoti.xuandun-desktop");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("crash.log")
}

fn write_crash_log(msg: &str) {
    let path = crash_log_path();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{}] {}", chrono::Utc::now().to_rfc3339(), msg);
    }
    eprintln!("{}", msg);
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = info.payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("<non-string panic payload>");
        let msg = format!(
            "PANIC at {}\n  Message: {}\n  Backtrace:\n{}",
            location, payload, std::backtrace::Backtrace::force_capture()
        );
        write_crash_log(&msg);

        #[cfg(target_os = "windows")]
        {
            xuandun_desktop_lib::show_message_box(
                "XuanDun Crash",
                &format!(
                    "Application crashed. Crash log saved to:\n{}\n\n{}",
                    crash_log_path().display(),
                    payload
                ),
            );
        }
    }));
}

fn main() {
    // P0-CDPAudit (FIXED): 仅在debug构建或显式设置XUANDUN_ENABLE_CDP_DEBUG环境变量时启用CDP端口
    // Release版本默认关闭，防止本地恶意程序通过CDP协议注入JS操纵安全检测结果
    // 风险说明：CDP端口9224开放 -> 任意本地进程可通过http://127.0.0.1:9224/json枚举页面
    //          -> 通过Runtime.evalute注入JS，绕过Tauri IPC权限控制 -> 伪造检测结果
    let enable_cdp = cfg!(debug_assertions)
        || std::env::var("XUANDUN_ENABLE_CDP_DEBUG").is_ok();

    if enable_cdp {
        // WebView2 149+ 强制校验 WebSocket 握手的 Origin header；
        // 仅设 --remote-debugging-port=9224 会导致 Python/Node 客户端全部 403，
        // 必须同时加 --remote-allow-origins=*（仅本地回环调试端口，非对外）
        std::env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--remote-debugging-port=9224 --remote-allow-origins=*");
        // 优先稳定通道，避免Canary通道调试端口行为不一致
        std::env::set_var("WEBVIEW2_RELEASE_CHANNEL_PREFERENCE", "1");
        install_panic_hook();
        write_crash_log("Application starting");
        write_crash_log("[WARN] CDP debug port ENABLED: 9224 (debug build or XUANDUN_ENABLE_CDP_DEBUG set)");
    } else {
        install_panic_hook();
        write_crash_log("Application starting");
        write_crash_log("CDP debug port DISABLED in release build (security hardening P0-1)");
    }
    xuandun_desktop_lib::run()
}

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

fn crash_log_path() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
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
    install_panic_hook();
    write_crash_log("Application starting");
    xuandun_desktop_lib::run()
}

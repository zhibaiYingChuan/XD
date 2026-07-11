use serde::{Deserialize, Serialize};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;
use once_cell::sync::Lazy;

pub fn safe_preview(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = 0;
    for (i, c) in s.char_indices() {
        let next_end = i + c.len_utf8();
        if next_end <= max {
            end = next_end;
        } else {
            break;
        }
    }
    &s[..end]
}

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

#[derive(Serialize, Deserialize, Clone)]
pub struct ProtectResult {
    pub allowed: bool,
    pub trust_level: String,
    pub reject_stage: Option<String>,
    pub domain_distance: Option<f64>,
    pub timing_distance: Option<f64>,
    pub attack_category: Option<String>,
    pub latency_ms: Option<f64>,
}

pub struct EngineState {
    pub running: bool,
    pub healthy: bool,
    pub mode: String,
    pub total_requests: u64,
    pub total_blocked: u64,
    started_at: Option<Instant>,
    engine_url: String,
    child_pid: Option<u32>,
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            running: false,
            healthy: false,
            mode: "balanced".to_string(),
            total_requests: 0,
            total_blocked: 0,
            started_at: None,
            engine_url: "http://localhost:18765".to_string(),
            child_pid: None,
        }
    }

    pub fn uptime_secs(&self) -> f64 {
        self.started_at.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0)
    }

    pub fn block_rate(&self) -> f64 {
        if self.total_requests == 0 { 0.0 } else { self.total_blocked as f64 / self.total_requests as f64 }
    }

    pub fn set_mode(&mut self, mode: &str) -> Result<(), String> {
        match mode {
            "high_security" | "balanced" | "low_false_positive" => {
                self.mode = mode.to_string();
                Ok(())
            }
            _ => Err(format!("Invalid mode: {}", mode)),
        }
    }

    pub fn get_engine_url(&self) -> String { self.engine_url.clone() }

    pub fn record_result(&mut self, _text: &str, result: &ProtectResult) {
        self.total_requests += 1;
        if !result.allowed { self.total_blocked += 1; }
    }
}

pub async fn send_protect_request(engine_url: &str, text: &str, session: &str, mode: &str) -> Result<ProtectResult, String> {
    let url = format!("{}/protect", engine_url);
    let body = serde_json::json!({ "text": text, "session": session, "mode": mode });
    let resp = HTTP_CLIENT.post(&url).json(&body).send().await.map_err(|e| format!("Engine request failed: {}", e))?;
    let result: serde_json::Value = resp.json().await.map_err(|e| format!("Engine response parse failed: {}", e))?;
    let allowed = result["allowed"].as_bool().unwrap_or(false);
    Ok(ProtectResult {
        allowed,
        trust_level: result["trust_level"].as_str().unwrap_or("UNKNOWN").to_string(),
        reject_stage: result["reject_stage"].as_str().map(|s| s.to_string()),
        domain_distance: result["domain_distance"].as_f64(),
        timing_distance: result["timing_distance"].as_f64(),
        attack_category: result["attack_category"].as_str().map(|s| s.to_string()),
        latency_ms: result["latency_ms"].as_f64(),
    })
}

pub async fn sync_mode_to_engine(engine_url: &str, mode: &str) -> Result<(), String> {
    let url = format!("{}/set-mode", engine_url);
    let body = serde_json::json!({ "mode": mode });
    let resp = HTTP_CLIENT.post(&url).json(&body).send().await
        .map_err(|e| format!("Sync mode failed: {}", e))?;
    if !resp.status().is_success() {
        return Err("Failed to sync mode".to_string());
    }
    Ok(())
}

pub async fn engine_get(engine_url: &str, path: &str) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", engine_url, path);
    let resp = HTTP_CLIENT.get(&url).send().await
        .map_err(|e| format!("Engine GET failed: {}", e))?;
    resp.json().await.map_err(|e| format!("Engine response parse failed: {}", e))
}

pub async fn engine_post(engine_url: &str, path: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", engine_url, path);
    let resp = HTTP_CLIENT.post(&url).json(&body).send().await
        .map_err(|e| format!("Engine POST failed: {}", e))?;
    resp.json().await.map_err(|e| format!("Engine response parse failed: {}", e))
}

pub async fn check_engine_health(engine_url: &str) -> bool {
    let url = format!("{}/health", engine_url);
    match HTTP_CLIENT.get(&url).timeout(Duration::from_secs(2)).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

pub async fn ensure_engine_running(app: &AppHandle) -> Result<(), String> {
    let (engine_url, is_running) = {
        let state = app.state::<StdMutex<EngineState>>();
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.engine_url.clone(), s.running)
    };

    if is_running && check_engine_health(&engine_url).await {
        return Ok(());
    }

    if is_running {
        let _ = stop_engine(app);
    }

    start_engine_sidecar(app)?;

    // 渐进式健康检查：Nuitka onefile 134MB 自解压需要较长时间
    // 阶段1：前10秒，每500ms检查一次（快速响应）
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if check_engine_health(&engine_url).await {
            let state = app.state::<StdMutex<EngineState>>();
            let mut s = state.lock().map_err(|e| e.to_string())?;
            s.running = true;
            s.healthy = true;
            s.started_at = Some(Instant::now());
            log_engine("Engine health check passed (phase 1)");
            return Ok(());
        }
    }
    // 阶段2：10-60秒，每1秒检查一次（等待自解压完成）
    for i in 0..50 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if check_engine_health(&engine_url).await {
            let state = app.state::<StdMutex<EngineState>>();
            let mut s = state.lock().map_err(|e| e.to_string())?;
            s.running = true;
            s.healthy = true;
            s.started_at = Some(Instant::now());
            log_engine(&format!("Engine health check passed (phase 2, attempt {})", i + 1));
            return Ok(());
        }
    }

    log_engine("Engine failed to start within 60 seconds");
    Err("Engine failed to start within 60 seconds".to_string())
}

fn log_engine(msg: &str) {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());
    let dir = base.join("com.daoti.xuandun-desktop");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("engine.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = writeln!(f, "[{}] {}", chrono::Utc::now().to_rfc3339(), msg);
    }
    eprintln!("[XuanDun:engine] {}", msg);
}

fn find_engine_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    let mut searched: Vec<String> = Vec::new();

    // 1. current_exe 同级目录（打包模式主路径）
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cands = [
                dir.join("xuandun-engine-x86_64-pc-windows-msvc.exe"),
                dir.join("xuandun-engine.exe"),
                dir.join("xuandun-engine"),
            ];
            for c in &cands {
                searched.push(c.display().to_string());
                if c.exists() {
                    log_engine(&format!("Engine found at: {}", c.display()));
                    return Some(c.clone());
                }
            }
        }
    }

    // 2. Tauri resource_dir（macOS/Linux 打包模式）
    if let Ok(res_dir) = app.path().resource_dir() {
        let cands = [
            res_dir.join("xuandun-engine-x86_64-pc-windows-msvc.exe"),
            res_dir.join("xuandun-engine"),
        ];
        for c in &cands {
            searched.push(c.display().to_string());
            if c.exists() {
                log_engine(&format!("Engine found at: {}", c.display()));
                return Some(c.clone());
            }
        }
    }

    // 3. 开发模式：src-tauri/binaries/
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if let Some(src_tauri) = dir.parent() {
                let dev_path = src_tauri.join("src-tauri").join("binaries").join("xuandun-engine-x86_64-pc-windows-msvc.exe");
                searched.push(dev_path.display().to_string());
                if dev_path.exists() {
                    log_engine(&format!("Engine found at (dev): {}", dev_path.display()));
                    return Some(dev_path);
                }
            }
        }
    }

    log_engine(&format!("Engine NOT found. Searched paths:\n  {}", searched.join("\n  ")));
    None
}

fn start_engine_sidecar(app: &AppHandle) -> Result<(), String> {
    log_engine("start_engine_sidecar: begin");

    #[cfg(target_os = "windows")]
    {
        use std::process::{Command, Stdio};
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        if let Some(path) = find_engine_path(app) {
            log_engine(&format!("Spawning engine: {}", path.display()));
            let mut child = Command::new(&path)
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    let msg = format!("Failed to spawn engine at {:?}: {}", path, e);
                    log_engine(&msg);
                    msg
                })?;
            let pid = child.id();

            // 在独立线程中读取 stderr 输出到日志（帮助诊断引擎崩溃）
            if let Some(stderr) = child.stderr.take() {
                std::thread::spawn(move || {
                    use std::io::BufRead;
                    let reader = std::io::BufReader::new(stderr);
                    for line in reader.lines().take(50) {
                        if let Ok(line) = line {
                            log_engine(&format!("engine stderr: {}", line));
                        }
                    }
                });
            }

            std::mem::forget(child);

            if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                s.child_pid = Some(pid);
            }
            log_engine(&format!("Engine spawned, pid={}", pid));
            return Ok(());
        }
        log_engine("Engine binary not found via std::process, falling back to sidecar API");
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(path) = find_engine_path(app) {
            use std::process::{Command, Stdio};
            log_engine(&format!("Spawning engine: {}", path.display()));
            let mut child = Command::new(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    let msg = format!("Failed to spawn engine at {:?}: {}", path, e);
                    log_engine(&msg);
                    msg
                })?;
            let pid = child.id();
            if let Some(stderr) = child.stderr.take() {
                std::thread::spawn(move || {
                    use std::io::BufRead;
                    let reader = std::io::BufReader::new(stderr);
                    for line in reader.lines().take(50) {
                        if let Ok(line) = line {
                            log_engine(&format!("engine stderr: {}", line));
                        }
                    }
                });
            }
            std::mem::forget(child);
            if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                s.child_pid = Some(pid);
            }
            log_engine(&format!("Engine spawned, pid={}", pid));
            return Ok(());
        }
    }

    // 回退到 tauri-plugin-shell sidecar API
    log_engine("Falling back to tauri-plugin-shell sidecar API");
    let sidecar_command = app.shell()
        .sidecar("xuandun-engine")
        .map_err(|e| {
            let msg = format!("Failed to create sidecar: {}", e);
            log_engine(&msg);
            msg
        })?;
    let (_rx, child) = sidecar_command.spawn().map_err(|e| {
        let msg = format!("Failed to spawn engine via sidecar: {}", e);
        log_engine(&msg);
        msg
    })?;
    let pid = child.pid();
    if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
        s.child_pid = Some(pid);
    }
    log_engine(&format!("Engine spawned via sidecar, pid={}", pid));
    Ok(())
}

pub async fn restart_engine(app: &AppHandle) -> Result<(), String> {
    stop_engine(app)?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    ensure_engine_running(app).await
}

pub fn stop_engine(app: &AppHandle) -> Result<(), String> {
    let pid = {
        let state = app.state::<StdMutex<EngineState>>();
        let mut s = state.lock().map_err(|e| e.to_string())?;
        s.running = false;
        s.healthy = false;
        s.child_pid.take()
    };
    if let Some(child_pid) = pid {
        kill_process(child_pid)?;
    }
    Ok(())
}

fn kill_process(pid: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to kill process {}: {}", pid, e))?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::process::Command;
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
            .map_err(|e| format!("Failed to kill process {}: {}", pid, e))?;
    }
    Ok(())
}

pub async fn monitor_engine_health(app: &AppHandle) {
    let mut consecutive_failures: u32 = 0;
    const MAX_FAILURES: u32 = 5;

    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let engine_url = {
            let state = app.state::<StdMutex<EngineState>>();
            let s = state.lock().ok();
            s.map(|s| s.engine_url.clone()).unwrap_or_default()
        };
        if engine_url.is_empty() { continue; }

        let healthy = check_engine_health(&engine_url).await;
        let was_running = {
            let state = app.state::<StdMutex<EngineState>>();
            let s = state.lock().ok();
            s.map(|s| s.running).unwrap_or(false)
        };

        if was_running && !healthy {
            if consecutive_failures >= MAX_FAILURES {
                eprintln!("[XuanDun] Engine restart failed {} times, giving up", MAX_FAILURES);
                if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                    s.running = false;
                    s.healthy = false;
                }
                consecutive_failures = 0;
                continue;
            }

            eprintln!("[XuanDun] Engine health check failed, attempting restart ({}/{})...",
                consecutive_failures + 1, MAX_FAILURES);
            let _ = stop_engine(app);
            if let Ok(()) = start_engine_sidecar(app) {
                tokio::time::sleep(Duration::from_secs(3)).await;
                if check_engine_health(&engine_url).await {
                    eprintln!("[XuanDun] Engine restarted successfully");
                    consecutive_failures = 0;
                    if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                        s.healthy = true;
                        s.started_at = Some(Instant::now());
                    }
                    continue;
                }
            }
            consecutive_failures += 1;
        }

        if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
            s.healthy = healthy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_state_new() {
        let state = EngineState::new();
        assert!(!state.running);
        assert!(!state.healthy);
        assert_eq!(state.mode, "balanced");
        assert_eq!(state.total_requests, 0);
        assert_eq!(state.total_blocked, 0);
        assert!(state.child_pid.is_none());
    }

    #[test]
    fn test_set_mode_valid() {
        let mut state = EngineState::new();
        assert!(state.set_mode("high_security").is_ok());
        assert_eq!(state.mode, "high_security");
        assert!(state.set_mode("balanced").is_ok());
        assert!(state.set_mode("low_false_positive").is_ok());
    }

    #[test]
    fn test_set_mode_invalid() {
        let mut state = EngineState::new();
        assert!(state.set_mode("invalid").is_err());
        assert_eq!(state.mode, "balanced");
    }

    #[test]
    fn test_block_rate() {
        let mut state = EngineState::new();
        assert_eq!(state.block_rate(), 0.0);
        state.total_requests = 100;
        state.total_blocked = 10;
        assert!((state.block_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_get_engine_url() {
        let state = EngineState::new();
        assert_eq!(state.get_engine_url(), "http://localhost:18765");
    }

    #[test]
    fn test_record_result() {
        let mut state = EngineState::new();
        let r = ProtectResult {
            allowed: false,
            trust_level: "LOW".to_string(),
            reject_stage: Some("reject_gate".to_string()),
            domain_distance: Some(0.9),
            timing_distance: Some(0.8),
            attack_category: Some("prompt_injection".to_string()),
            latency_ms: Some(12.5),
        };
        state.record_result("attack", &r);
        assert_eq!(state.total_requests, 1);
        assert_eq!(state.total_blocked, 1);
    }

    #[test]
    fn test_safe_preview_ascii() {
        assert_eq!(safe_preview("hello world", 50), "hello world");
        assert_eq!(safe_preview("hello world", 5), "hello");
    }

    #[test]
    fn test_safe_preview_cjk() {
        let text = "你好世界，这是一个测试文本";
        let preview = safe_preview(text, 10);
        assert!(!preview.is_empty());
        let bytes = preview.as_bytes();
        assert_eq!(bytes.len() % 3, 0);
        assert!(bytes.len() <= 10);
        let original_bytes = text.as_bytes();
        assert!(original_bytes.starts_with(bytes));
    }

    #[test]
    fn test_safe_preview_emoji() {
        let text = "👋🌍你好";
        let preview = safe_preview(text, 10);
        assert!(!preview.is_empty());
        let bytes = preview.as_bytes();
        assert!(bytes.len() <= 10);
        let original_bytes = text.as_bytes();
        assert!(original_bytes.starts_with(bytes));
    }

    #[test]
    fn test_safe_preview_no_panic_on_multibyte_boundary() {
        let text = "你好";
        let _ = safe_preview(text, 1);
        let _ = safe_preview(text, 2);
        let _ = safe_preview(text, 3);
        let _ = safe_preview(text, 4);
        let _ = safe_preview(text, 100);
    }
}

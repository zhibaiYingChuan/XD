use serde::{Deserialize, Serialize};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
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
    // P0 修复：管理接口鉴权链路。
    // 引擎端 _require_admin_auth() 要求管理端点 Origin ∈ {tauri://localhost, http://tauri.localhost}，
    // 否则返回 403。此前 HTTP_CLIENT 从不发送 Origin 头，导致紧急逃生/灰度部署/模式切换/告警/
    // 预热等 9 个管理端点全部 403 失效（用户可见：逃生状态/灰度比例"获取失败"）。
    // 统一作为默认头携带 Origin，覆盖所有请求（非管理端点不校验 Origin，无副作用）。
    let mut default_headers = reqwest::header::HeaderMap::new();
    default_headers.insert(
        reqwest::header::ORIGIN,
        reqwest::header::HeaderValue::from_static("tauri://localhost"),
    );
    reqwest::Client::builder()
        .default_headers(default_headers)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// 引擎管理令牌（与引擎端 XUANDUN_ADMIN_TOKEN 对齐）。
/// 若配置了该令牌，桌面端转发管理请求时必须透传 X-Admin-Token，否则引擎返回 401。
/// 未配置时返回 None（引擎端 _ADMIN_TOKEN 为空，仅需 Origin 同源即可）。
fn admin_token() -> Option<String> {
    std::env::var("XUANDUN_ADMIN_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 为管理端点请求透传 X-Admin-Token 头（若配置了引擎管理令牌）。
/// 引擎端配置 XUANDUN_ADMIN_TOKEN 后，管理端点即使 Origin 同源也必须携带
/// 匹配的 X-Admin-Token，否则返回 401。未配置时透传为空，不影响现有逻辑。
fn attach_admin_token(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(token) = admin_token() {
        req.header("X-Admin-Token", token)
    } else {
        req
    }
}

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
    pub startup_error: Option<String>,
    started_at: Option<Instant>,
    engine_url: String,
    child_pid: Option<u32>,
    // P0-5 修复：存储 ChildHandle，替代 std::mem::forget
    // P1-A 修复：已实现 Drop trait（见下方 impl Drop），drop 时自动 kill+wait 回收子进程
    child_handle: Option<std::process::Child>,
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            running: false,
            healthy: false,
            mode: "balanced".to_string(),
            total_requests: 0,
            total_blocked: 0,
            startup_error: None,
            started_at: None,
            engine_url: "http://localhost:18765".to_string(),
            child_pid: None,
            child_handle: None,
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

// P1-A 修复：实现 Drop trait，确保引擎子进程被 kill + wait 回收
// 原 EngineState 第 52-53 行注释声称"由 Drop 自动 wait 回收"，但实际未实现 Drop trait
// std::process::Child 的默认 Drop 只关闭 stdin/stdout/stderr handle，不会调用 kill() 或 wait()
// 不实现 Drop 会导致：应用退出时引擎子进程成为孤儿进程继续运行，退出后成为僵尸进程
impl Drop for EngineState {
    fn drop(&mut self) {
        // take() 取出 child_handle，避免 Drop 重复执行
        if let Some(mut child) = self.child_handle.take() {
            // kill() 发送终止信号，wait() 回收子进程资源
            // 两个操作都用 let _ = 忽略错误，避免 Drop 中 panic（Drop 中 panic 会导致双 panic）
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub async fn send_protect_request(engine_url: &str, text: &str, session: &str, mode: &str) -> Result<ProtectResult, String> {
    let url = format!("{}/protect", engine_url);
    let body = serde_json::json!({ "text": text, "session": session, "mode": mode });
    // P0-1 修复：protect 冷启动最坏 28s（拒绝门四元组+KMeans初始化），使用 30s 独立超时
    // 原继承 HTTP_CLIENT 5s 默认超时，与前端 PROTECT_COLD=35s 冲突，冷启动场景必然失败
    let resp = HTTP_CLIENT.post(&url)
        .json(&body)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Engine request failed: {}", e))?;
    // P1修复：必须检查HTTP状态码，否则引擎返回500时会尝试解析错误响应为JSON导致解析失败
    let status = resp.status();
    if !status.is_success() {
        let status_code = status.as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Engine returned HTTP {}: {}", status_code, body_text));
    }
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

/// 输出护栏单次检测：转发到引擎 /output/protect。
/// 返回引擎原始 JSON（含 action / risk_level / reason / output：打码后的文本）。
/// 与输入侧 protect 一样使用 30s 独立超时，覆盖冷启动。
pub async fn send_output_protect_request(engine_url: &str, text: &str, session: &str) -> Result<serde_json::Value, String> {
    let url = format!("{}/output/protect", engine_url);
    let body = serde_json::json!({ "text": text, "session": session });
    let resp = HTTP_CLIENT.post(&url)
        .json(&body)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Engine request failed: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Engine returned HTTP {}: {}", status.as_u16(), body_text));
    }
    resp.json().await.map_err(|e| format!("Engine response parse failed: {}", e))
}

pub async fn sync_mode_to_engine(engine_url: &str, mode: &str) -> Result<(), String> {
    let url = format!("{}/set-mode", engine_url);
    let body = serde_json::json!({ "mode": mode });
    let resp = attach_admin_token(HTTP_CLIENT.post(&url).json(&body)).send().await
        .map_err(|e| format!("Sync mode failed: {}", e))?;

    // 引擎set-mode可能在加载新模式检测器时抛异常返回500，但mode状态已更新
    // 修复：HTTP失败时不直接报错，而是查询引擎/status确认实际模式
    if !resp.status().is_success() {
        // 容错：等待引擎处理完模式切换，然后查询实际模式
        tokio::time::sleep(Duration::from_millis(500)).await;
        match engine_get(engine_url, "/status").await {
            Ok(status) => {
                let actual_mode = status.get("mode").and_then(|v| v.as_str()).unwrap_or("");
                if actual_mode == mode {
                    // 引擎实际已切换到目标模式，视为成功
                    return Ok(());
                }
                return Err(format!(
                    "引擎模式同步失败：期望={}，实际={}（HTTP {}）",
                    mode, actual_mode, resp.status().as_u16()
                ));
            }
            Err(e) => {
                return Err(format!("Sync mode failed (HTTP {}) and status check also failed: {}", resp.status().as_u16(), e));
            }
        }
    }
    Ok(())
}

pub async fn engine_get(engine_url: &str, path: &str) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", engine_url, path);
    let resp = attach_admin_token(HTTP_CLIENT.get(&url)).send().await
        .map_err(|e| format!("Engine GET failed: {}", e))?;
    // P1修复：必须检查HTTP状态码，避免解析错误响应为JSON
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Engine GET {} returned HTTP {}: {}", path, status.as_u16(), body_text));
    }
    resp.json().await.map_err(|e| format!("Engine response parse failed: {}", e))
}

pub async fn engine_post(engine_url: &str, path: &str, body: serde_json::Value) -> Result<serde_json::Value, String> {
    let url = format!("{}{}", engine_url, path);
    let resp = attach_admin_token(HTTP_CLIENT.post(&url).json(&body)).send().await
        .map_err(|e| format!("Engine POST failed: {}", e))?;
    // P1修复：必须检查HTTP状态码，避免解析错误响应为JSON
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Engine POST {} returned HTTP {}: {}", path, status.as_u16(), body_text));
    }
    resp.json().await.map_err(|e| format!("Engine response parse failed: {}", e))
}

/// 最低引擎版本要求
/// v1.3.0 引入了 /dual-layer/stats 端点（阴阳门状态），低于此版本将导致：
/// 1. 阴阳门状态卡片 404 错误
/// 2. /set-mode 可能在创建新模式 shield 时返回 HTTP 500
/// 3. 缺少最新的抗毒化 GateC 500 次上限
const MIN_ENGINE_VERSION: &str = "1.3.2";

/// 解析单个版本段，仅取数字前缀，忽略 -beta/-rc 等预发布后缀。
/// 例如 "3-beta" -> 3，"2" -> 2。
/// 修复：此前直接 p.parse() 遇 "3-beta" 失败被 filter_map 丢弃，导致
/// "1.3.3-beta" 被解析成 [1,3]，与 "1.3.2"=[1,3,2] 比较时误判版本过低，触发错误告警/闪退。
fn parse_version_segment(seg: &str) -> u32 {
    seg.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// 语义化版本比较：返回 -1(a<b) / 0(a==b) / 1(a>b)
fn compare_versions(a: &str, b: &str) -> i32 {
    let va: Vec<u32> = a.split('.').map(parse_version_segment).collect();
    let vb: Vec<u32> = b.split('.').map(parse_version_segment).collect();
    for i in 0..va.len().max(vb.len()) {
        let na = *va.get(i).unwrap_or(&0);
        let nb = *vb.get(i).unwrap_or(&0);
        if na != nb {
            return if na < nb { -1 } else { 1 };
        }
    }
    0
}

/// 检查引擎版本是否满足最低要求
/// 返回 Ok(version) 或 Err(warning_msg)
async fn check_engine_version(engine_url: &str) -> Result<String, String> {
    let health = engine_get(engine_url, "/health").await
        .map_err(|e| format!("引擎健康检查失败：{}", e))?;
    let version = health.get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    if compare_versions(version, MIN_ENGINE_VERSION) < 0 {
        return Err(format!(
            "引擎版本过低：当前={}，最低要求={}。旧版本缺少 /dual-layer/stats 端点，请重新打包引擎exe（python build_engine.py）或手动启动最新源码（python engine_flask.py）",
            version, MIN_ENGINE_VERSION
        ));
    }
    Ok(version.to_string())
}

/// 标记引擎已运行 + 版本校验（不阻断启动，版本过低仅警告）
async fn mark_engine_running_and_verify(app: &AppHandle, engine_url: &str, phase: &str) -> Result<(), String> {
    {
        let state = app.state::<StdMutex<EngineState>>();
        let mut s = state.lock().map_err(|e| e.to_string())?;
        s.running = true;
        s.healthy = true;
        s.started_at = Some(Instant::now());
        s.startup_error = None;
    }
    // 版本校验（不阻断启动，仅警告）
    match check_engine_version(engine_url).await {
        Ok(ver) => {
            log_engine(&format!("Engine health check passed ({}, version={})", phase, ver));
        }
        Err(warn) => {
            log_engine(&format!("Engine health check passed ({}) but VERSION WARNING: {}", phase, warn));
            if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                s.startup_error = Some(warn);
            }
        }
    }
    Ok(())
}

pub async fn check_engine_health(engine_url: &str) -> bool {
    let url = format!("{}/health", engine_url);
    match HTTP_CLIENT.get(&url).timeout(Duration::from_secs(2)).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// P1修复：warmup 专用请求函数，使用更长超时（30秒），复用连接池
pub async fn send_warmup_request(
    engine_url: &str,
    safe_texts: &[String],
    attack_texts: &[String],
) -> Result<serde_json::Value, String> {
    let url = format!("{}/warmup", engine_url);
    let body = serde_json::json!({
        "safe_texts": safe_texts,
        "attack_texts": attack_texts,
    });
    let resp = attach_admin_token(HTTP_CLIENT.post(&url).json(&body))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Warmup request failed: {}", e))?;
    // P1修复：必须检查HTTP状态码
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("Engine warmup returned HTTP {}: {}", status.as_u16(), body_text));
    }
    resp.json().await.map_err(|e| format!("Warmup response parse failed: {}", e))
}

pub async fn ensure_engine_running(app: &AppHandle) -> Result<(), String> {
    let (engine_url, is_running) = {
        let state = app.state::<StdMutex<EngineState>>();
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.engine_url.clone(), s.running)
    };

    if is_running && check_engine_health(&engine_url).await {
        // P0 修复：即使引擎已在运行且健康，也必须执行版本校验。
        // 修复前此处直接 return Ok(())，会静默复用旧引擎进程而不检查版本——
        // 当二进制已更新为 v1.3.2 但旧引擎进程仍在监听时，用户拿到的仍是旧行为
        // （如阴阳门统计为零），且用户可能没有第二次启动应用的机会。
        // 改为 mark_engine_running_and_verify 后，版本过低会写入 startup_error 提示用户。
        return mark_engine_running_and_verify(app, &engine_url, "already running").await;
    }

    // P0-1 修复：在尝试启动 sidecar 之前，先检测是否有外部 Flask 引擎已在运行
    // 场景：用户/开发环境已手动启动 python engine_flask.py 监听 18765
    // 此时 sidecar 路径可能不存在（os error 2），但引擎实际可用
    if !is_running && check_engine_health(&engine_url).await {
        log_engine("Detected externally running engine (Flask already listening on engine_url)");
        return mark_engine_running_and_verify(app, &engine_url, "external detection").await;
    }

    if is_running {
        let _ = stop_engine(app);
    }

    // P0-1 修复：sidecar 启动失败不应直接阻断，回退到等待外部引擎
    if let Err(e) = start_engine_sidecar(app) {
        log_engine(&format!("start_engine_sidecar failed (will wait for external engine): {}", e));
        // 不立即返回错误，继续进入健康检查循环，等待外部引擎就绪
        // 将错误记入 startup_error 但不阻断（允许用户手动启动引擎后恢复）
        {
            let state = app.state::<StdMutex<EngineState>>();
            if let Ok(mut s) = state.lock() {
                s.startup_error = Some(format!("Sidecar 启动失败：{}。请手动启动引擎（python engine_flask.py）或检查可执行文件路径。", e));
            };
        }
    }

    // 渐进式健康检查：Nuitka onefile 134MB 自解压需要较长时间
    // 阶段1：前10秒，每500ms检查一次（快速响应）
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if check_engine_health(&engine_url).await {
            return mark_engine_running_and_verify(app, &engine_url, "phase 1").await;
        }
    }
    // 阶段2：10-60秒，每1秒检查一次（等待自解压完成或外部引擎启动）
    for i in 0..50 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if check_engine_health(&engine_url).await {
            return mark_engine_running_and_verify(app, &engine_url, &format!("phase 2, attempt {}", i + 1)).await;
        }
    }

    log_engine("Engine failed to start within 60 seconds");
    let msg = "Engine failed to start within 60 seconds".to_string();
    {
        let state = app.state::<StdMutex<EngineState>>();
        if let Ok(mut s) = state.lock() {
            s.startup_error = Some(msg.clone());
        };
    }
    Err(msg)
}

fn log_engine(msg: &str) {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("com.daoti.xuandun-desktop");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("engine.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = writeln!(f, "[{}] {}", chrono::Utc::now().to_rfc3339(), msg);
        let _ = f.flush();
    }
    eprintln!("[XuanDun:engine] {}", msg);
}

/// 返回当前平台引擎二进制文件名（与 build_engine.py 的 output-name 保持一致）。
///
/// 命名规则：`xuandun-engine-{target-triple}`，Windows 追加 `.exe`。
/// 与 tauri.conf.json 的 externalBin（`binaries/xuandun-engine`）产出的
/// `xuandun-engine-{target-triple}.exe` 对齐。目标三元组用 `cfg!` 拼接，
/// 覆盖 release.yml 的三种构建目标（Windows x86_64 / macOS aarch64 / Linux x86_64）。
fn engine_binary_name() -> String {
    #[cfg(target_os = "windows")]
    let triple = "x86_64-pc-windows-msvc";
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let triple = "aarch64-apple-darwin";
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    let triple = "x86_64-apple-darwin";
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let triple = "x86_64-unknown-linux-gnu";
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let triple = "aarch64-unknown-linux-gnu";
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
    format!("xuandun-engine-{}{}", triple, ext)
}

fn find_engine_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    let mut searched: Vec<String> = Vec::new();
    let engine_name = engine_binary_name();

    // 1. current_exe 同级目录（打包模式主路径）
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cands = [
                dir.join(&engine_name),
                dir.join("xuandun-engine.exe"),
                dir.join("xuandun-engine"),
                // Windows/MSIX 打包：资源目录在同级 resources/engine/ 下
                // NSIS 默认安装结构：<install_dir>/xuandun-desktop.exe + resources/engine/
                dir.join("resources").join("engine").join(&engine_name),
                dir.join("resources").join("engine").join("xuandun-engine.exe"),
                dir.join("resources").join("engine").join("xuandun-engine"),
                // 兼容开发/便携版结构：直接在 exe 同级的 engine/ 子目录
                dir.join("engine").join(&engine_name),
                dir.join("engine").join("xuandun-engine.exe"),
                dir.join("engine").join("xuandun-engine"),
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

    // 2. Tauri resource_dir（macOS/Linux 打包模式，Windows sidecar-less 模式）
    if let Ok(res_dir) = app.path().resource_dir() {
        let cands = [
            res_dir.join(&engine_name),
            res_dir.join("xuandun-engine"),
            // P0 误报治理修复：standalone 目录模式，主引擎在 resources/engine 子目录
            res_dir.join("engine").join(&engine_name),
            res_dir.join("engine").join("xuandun-engine.exe"),
            res_dir.join("engine").join("xuandun-engine"),
        ];
        for c in &cands {
            searched.push(c.display().to_string());
            if c.exists() {
                log_engine(&format!("Engine found at: {}", c.display()));
                return Some(c.clone());
            }
        }
    }

    // 3. 开发模式：src-tauri/resources/engine/（新 standalone 构建产物位置）
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if let Some(src_tauri) = dir.parent() {
                let dev_new = src_tauri.join("src-tauri").join("resources").join("engine").join(&engine_name);
                searched.push(dev_new.display().to_string());
                if dev_new.exists() {
                    log_engine(&format!("Engine found at (dev-standalone): {}", dev_new.display()));
                    return Some(dev_new);
                }
                // 兼容旧 binaries 目录产物
                let dev_old = src_tauri.join("src-tauri").join("binaries").join(&engine_name);
                searched.push(dev_old.display().to_string());
                if dev_old.exists() {
                    log_engine(&format!("Engine found at (dev-onefile): {}", dev_old.display()));
                    return Some(dev_old);
                }
            }
        }
    }

    log_engine(&format!("Engine NOT found. Searched paths:\n  {}", searched.join("\n  ")));
    None
}

/// 从 DB 读取上游模型配置，并注入到引擎子进程环境变量（XUANDUN_UPSTREAM_*）。
/// 用户无需手动设置系统环境变量，只需在设置页表单填写，引擎启动时自动注入。
fn apply_upstream_env(app: &AppHandle, cmd: &mut std::process::Command) {
    let (url, api_key, model, timeout) = {
        let db = app.state::<crate::db::Database>();
        let url = db.get_config("upstream_url").ok().flatten().unwrap_or_default();
        let api_key = db.get_config("upstream_api_key").ok().flatten().unwrap_or_default();
        let model = db.get_config("upstream_model").ok().flatten().unwrap_or_default();
        let timeout = db.get_config("upstream_timeout").ok().flatten()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(300.0);
        (url, api_key, model, timeout)
    };
    if !url.is_empty() {
        cmd.env("XUANDUN_UPSTREAM_URL", &url);
    }
    if !api_key.is_empty() {
        cmd.env("XUANDUN_UPSTREAM_API_KEY", &api_key);
    }
    if !model.is_empty() {
        cmd.env("XUANDUN_UPSTREAM_MODEL", &model);
    }
    cmd.env("XUANDUN_UPSTREAM_TIMEOUT", timeout.to_string());
    log_engine(&format!(
        "Upstream env applied: url={} model={} timeout={}",
        if url.is_empty() { "(空)" } else { "已配置" },
        if model.is_empty() { "(空)" } else { &model },
        timeout
    ));
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
            // P1修复：stdout/stderr 都必须被读取，否则管道缓冲区满时子进程会挂起
            // 引擎通过HTTP API通信，stdout/stderr 仅用于诊断日志
            let mut cmd = Command::new(&path);
            cmd.creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            apply_upstream_env(app, &mut cmd);
            let mut child = cmd.spawn()
                .map_err(|e| {
                    let msg = format!("Failed to spawn engine at {:?}: {}", path, e);
                    log_engine(&msg);
                    msg
                })?;
            let pid = child.id();

            // P1修复：在独立线程中读取 stdout 输出到日志（防止管道阻塞导致引擎挂起）
            if let Some(stdout) = child.stdout.take() {
                std::thread::spawn(move || {
                    use std::io::BufRead;
                    let reader = std::io::BufReader::new(stdout);
                    for line in reader.lines().take(100).filter_map(|r| r.ok()) {
                            log_engine(&format!("engine stdout: {}", line));
                    }
                });
            }

            // 在独立线程中读取 stderr 输出到日志（帮助诊断引擎崩溃）
            if let Some(stderr) = child.stderr.take() {
                std::thread::spawn(move || {
                    use std::io::BufRead;
                    let reader = std::io::BufReader::new(stderr);
                    for line in reader.lines().take(100).filter_map(|r| r.ok()) {
                            log_engine(&format!("engine stderr: {}", line));
                    }
                });
            }

            // P0-5 修复：存储 ChildHandle 替代 forget，EngineState drop 时自动回收
            if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                s.child_pid = Some(pid);
                s.child_handle = Some(child);
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
            let mut cmd = Command::new(&path);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            apply_upstream_env(app, &mut cmd);
            let mut child = cmd.spawn()
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
            // P0-5 修复：存储 ChildHandle 替代 forget
            if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                s.child_pid = Some(pid);
                s.child_handle = Some(child);
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
                // P0-6 修复：达到 MAX 后不再重置为 0 继续重试，而是真正放弃并派发事件
                eprintln!("[XuanDun] Engine restart failed {} times, giving up permanently", MAX_FAILURES);
                if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                    s.running = false;
                    s.healthy = false;
                    s.startup_error = Some(format!("引擎连续 {} 次重启失败，已放弃自动重试", MAX_FAILURES));
                }
                // 派发全局事件通知前端
                let _ = app.emit("engine-permanently-failed", ());
                break;
            }

            eprintln!("[XuanDun] Engine health check failed, attempting restart ({}/{})...",
                consecutive_failures + 1, MAX_FAILURES);
            let _ = stop_engine(app);
            if let Ok(()) = start_engine_sidecar(app) {
                tokio::time::sleep(Duration::from_secs(3)).await;
                if check_engine_health(&engine_url).await {
                    eprintln!("[XuanDun] Engine restarted successfully");
                    consecutive_failures = 0;
                    // P0修复：重启成功后必须设置 running=true，否则所有依赖 is_running 的命令失效
                    if let Ok(mut s) = app.state::<StdMutex<EngineState>>().lock() {
                        s.running = true;
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

    // P1-A TDD：Drop trait 测试用例
    #[test]
    fn test_drop_no_panic_when_child_handle_is_none() {
        // 验证 child_handle=None 时 Drop 不 panic
        let state = EngineState::new();
        assert!(state.child_handle.is_none());
        // state 在此作用域结束时 drop，不应 panic
    }

    #[test]
    fn test_compare_versions_beta_suffix_not_lower() {
        // 回归：1.3.3-beta 必须高于 1.3.2（此前 -beta 后缀导致误判版本过低触发错误告警）
        assert_eq!(compare_versions("1.3.3-beta", "1.3.2"), 1);
        assert_eq!(compare_versions("1.3.2", "1.3.3-beta"), -1);
    }

    #[test]
    fn test_compare_versions_basic() {
        assert_eq!(compare_versions("1.3.2", "1.3.2"), 0);
        assert_eq!(compare_versions("1.3.3", "1.3.2"), 1);
        assert_eq!(compare_versions("1.2.9", "1.3.0"), -1);
        assert_eq!(compare_versions("1.3.2-rc1", "1.3.2"), 0);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), 1);
        assert_eq!(compare_versions("unknown", "1.3.2"), -1); // 无法解析按 0 处理
    }

    #[test]
    fn test_drop_kills_real_subprocess() {
        // 验证 Drop 真正 kill 子进程
        // 启动一个长时间运行的子进程
        let child = if cfg!(target_os = "windows") {
            std::process::Command::new("cmd")
                .args(["/c", "ping -n 30 127.0.0.1 > nul"])
                .spawn()
                .expect("failed to spawn test subprocess")
        } else {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("failed to spawn test subprocess")
        };
        let pid = child.id();

        // 将子进程 handle 存入 EngineState
        let mut state = EngineState::new();
        state.child_handle = Some(child);

        // 验证子进程当前正在运行
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let output = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()
                .expect("failed to run tasklist");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains(&pid.to_string()), "subprocess should be running before drop");
        }

        // state 在此作用域结束时 drop，应 kill + wait 子进程
        drop(state);

        // 验证子进程已被 kill（给操作系统一点时间回收）
        std::thread::sleep(std::time::Duration::from_millis(500));
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let output = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()
                .expect("failed to run tasklist");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(!stdout.contains(&pid.to_string()), "subprocess should be killed after drop");
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Unix: kill -0 检查进程是否存在，返回非零表示进程已不存在
            let result = std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status();
            assert!(result.is_err() || !result.unwrap().success(), "subprocess should be killed after drop");
        }
    }
}

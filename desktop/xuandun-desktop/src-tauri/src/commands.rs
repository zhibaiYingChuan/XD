use serde::{Deserialize, Serialize};
// Tauri 2.x: emit方法定义在Emitter trait中，必须显式导入
use tauri::{Emitter, Manager, State};
use tauri_plugin_notification::NotificationExt;
use std::sync::Mutex;

use crate::engine::{EngineState, send_protect_request, send_output_protect_request, send_warmup_request, sync_mode_to_engine, restart_engine as engine_restart, stop_engine as engine_stop, safe_preview, engine_get, engine_post};
use crate::db::Database;

// 深层安全审计：输入长度上限（防止 DoS 攻击）
const MAX_PROTECT_TEXT_LEN: usize = 100_000;     // 100KB — protect/check_output/mark_as_safe
const MAX_WARMUP_ITEMS: usize = 1_000;          // 预热数组最大条目数
const MAX_WARMUP_ITEM_LEN: usize = 10_000;      // 预热单条最大10KB

#[derive(Serialize)]
pub struct StatusResponse {
    pub running: bool,
    pub healthy: bool,
    pub mode: String,
    pub uptime: f64,
    pub total_requests: u64,
    pub total_blocked: u64,
    pub block_rate: f64,
    pub startup_error: Option<String>,
    // 学习状态字段（从 Flask /status 补充，与前端 TS StatusResponse 对齐）
    pub learning_mode: Option<String>,
    pub learning_progress: Option<f64>,
    pub sample_count: Option<u64>,
}

#[derive(Deserialize)]
pub struct ProtectRequest {
    pub text: String,
    #[serde(default = "default_session")]
    pub session: String,
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_session() -> String { "default".to_string() }
fn default_mode() -> String { "balanced".to_string() }

#[derive(Serialize)]
pub struct ProtectResponse {
    pub allowed: bool,
    pub trust_level: String,
    pub reject_stage: Option<String>,
    pub domain_distance: Option<f64>,
    pub timing_distance: Option<f64>,
    pub attack_category: Option<String>,
    pub latency_ms: Option<f64>,
    pub fallback: bool,
}

#[derive(Serialize)]
pub struct LogResponse {
    pub entries: Vec<crate::db::LogEntry>,
    pub total: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WarmupRequest {
    pub safe_texts: Vec<String>,
    pub attack_texts: Vec<String>,
}

#[tauri::command]
pub async fn get_status(state: State<'_, Mutex<EngineState>>) -> Result<StatusResponse, String> {
    let (s_running, s_healthy, s_mode, s_uptime, s_total_req, s_total_blk, s_block_rate, s_startup_err, engine_url) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (
            s.running, s.healthy, s.mode.clone(), s.uptime_secs(),
            s.total_requests, s.total_blocked, s.block_rate(),
            s.startup_error.clone(), s.get_engine_url(),
        )
    };

    // 学习状态字段从 Flask /status 补充（与前端 TS StatusResponse 对齐）
    let (learning_mode, learning_progress, sample_count) = if s_running {
        match engine_get(&engine_url, "/status").await {
            Ok(v) => (
                v.get("learning_mode").and_then(|x| x.as_str()).map(|s| s.to_string()),
                v.get("learning_progress").and_then(|x| x.as_f64()),
                v.get("sample_count").and_then(|x| x.as_u64()),
            ),
            Err(_) => (None, None, None),
        }
    } else {
        (None, None, None)
    };

    Ok(StatusResponse {
        running: s_running,
        healthy: s_healthy,
        mode: s_mode,
        uptime: s_uptime,
        total_requests: s_total_req,
        total_blocked: s_total_blk,
        block_rate: s_block_rate,
        startup_error: s_startup_err,
        learning_mode,
        learning_progress,
        sample_count,
    })
}

#[tauri::command]
pub async fn protect(
    app: tauri::AppHandle,
    state: State<'_, Mutex<EngineState>>,
    db: State<'_, Database>,
    req: ProtectRequest,
) -> Result<ProtectResponse, String> {
    // GAP-L4-01 修复：空文本防御性校验，避免空文本被误判为"引擎不可达"
    if req.text.trim().is_empty() {
        return Err("检测文本不能为空".to_string());
    }
    // 深层安全审计：输入长度上限，防止 DoS 攻击
    if req.text.len() > MAX_PROTECT_TEXT_LEN {
        return Err(format!("检测文本过长（{}字节），上限为 {} 字节", req.text.len(), MAX_PROTECT_TEXT_LEN));
    }

    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };

    if !is_running {
        // R-01 修复：引擎未运行分支补充审计记录，与 Err 分支保持审计一致性
        if let Err(e) = db.insert_audit("fallback", "engine_not_running") {
            eprintln!("[xuandun] [ERROR] insert_audit(fallback/not_running) failed: {}", e);
        }
        // G-14 修复：引擎未运行时使用 FALLBACK 而非 BLOCKED，避免前端误展示为"已拦截"
        return Ok(ProtectResponse {
            allowed: false,
            trust_level: "FALLBACK".to_string(),
            reject_stage: Some("engine_not_running".to_string()),
            domain_distance: None,
            timing_distance: None,
            attack_category: None,
            latency_ms: None,
            fallback: true,
        });
    }

    let result = send_protect_request(&engine_url, &req.text, &req.session, &req.mode).await;

    match result {
        Ok(r) => {
            // Sprint1-P0-6: SQLite损坏黑洞修复——insert_log失败不再仅eprintln吞掉，
            // 派发xuandun:db_corrupt全局事件到前端，显示顶层红色横幅告知用户
            // 数据库损坏（可能需要重启/重装），避免日志静默丢失
            if let Err(e) = db.insert_log(
                safe_preview(&req.text, 50),
                r.allowed,
                &r.trust_level,
                r.reject_stage.as_deref(),
                Some(&req.session),
                r.attack_category.as_deref(),
                r.latency_ms,
                r.domain_distance,
            ) {
                eprintln!("[xuandun] [ERROR] insert_log failed: {}", e);
                let err_msg = format!("insert_log: {}", e);
                let _ = app.emit("xuandun:db_corrupt", serde_json::json!({
                    "operation": "insert_log",
                    "error": err_msg,
                    "hint": "本地数据库可能损坏，建议重启应用或重置数据目录"
                }));
            }
            {
                let mut s = state.lock().map_err(|e| e.to_string())?;
                s.record_result(&req.text, &r);
            }
            if !r.allowed {
                let _ = app.notification()
                    .builder()
                    .title("道体玄盾 - 攻击拦截")
                    .body(format!("检测到恶意输入，信任等级: {}", r.trust_level))
                    .show();
                // Sprint1-P0-6: 同样对insert_audit失败派发DB_CORRUPT
                if let Err(e) = db.insert_audit("block", &format!("trust_level={}", r.trust_level)) {
                    eprintln!("[xuandun] [ERROR] insert_audit(block) failed: {}", e);
                    let err_msg = format!("insert_audit: {}", e);
                    let _ = app.emit("xuandun:db_corrupt", serde_json::json!({
                        "operation": "insert_audit",
                        "error": err_msg,
                        "hint": "本地数据库可能损坏，建议重启应用或重置数据目录"
                    }));
                }
                let alert_body = serde_json::json!({
                    "event_type": "block",
                    "severity": if r.trust_level == "LOW" { "critical" } else { "info" },
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "attack_category": r.attack_category,
                    "trust_level": r.trust_level,
                    "reject_stage": r.reject_stage,
                    "text_preview": safe_preview(&req.text, 80),
                    "engine_mode": "",
                });
                let alert_engine_url = engine_url.clone();
                tauri::async_runtime::spawn(async move {
                    // P1-6 修复：fire-and-forget 不再静默吞错，记录失败日志便于排障
                    if let Err(e) = engine_post(&alert_engine_url, "/alert/dispatch", alert_body).await {
                        eprintln!("[XuanDun] [ERROR] alert dispatch failed: {}", e);
                    }
                });
            }
            Ok(ProtectResponse {
                allowed: r.allowed,
                trust_level: r.trust_level,
                reject_stage: r.reject_stage,
                domain_distance: r.domain_distance,
                timing_distance: r.timing_distance,
                attack_category: r.attack_category.clone(),
                latency_ms: r.latency_ms,
                fallback: false,
            })
        }
        Err(e) => {
            eprintln!("[xuandun] Engine protect error: {}", e);
            if let Err(audit_err) = db.insert_audit("fallback", "engine_unavailable") {
                eprintln!("[xuandun] [ERROR] insert_audit(fallback) failed: {}", audit_err);
            }
            // G-14 修复：引擎不可达时使用 FALLBACK 而非 BLOCKED，避免前端误展示为"已拦截"
            Ok(ProtectResponse {
                allowed: false,
                trust_level: "FALLBACK".to_string(),
                reject_stage: Some("engine_unavailable".to_string()),
                domain_distance: None,
                timing_distance: None,
                attack_category: None,
                latency_ms: None,
                fallback: true,
            })
        }
    }
}

/// 输出护栏单次检测：转发到引擎 /output/protect。
/// 返回引擎原始 JSON（含 action/risk_level/reason/output=打码后文本）。
/// 供前端 Detect 页"输出侧护栏"标签调用，让用户直接看到打码/拦截/告警的实际效果。
#[tauri::command]
pub async fn check_output(
    state: State<'_, Mutex<EngineState>>,
    text: String,
    session: Option<String>,
) -> Result<serde_json::Value, String> {
    if text.trim().is_empty() {
        return Err("输出文本不能为空".to_string());
    }
    // 深层安全审计：输入长度上限
    if text.len() > MAX_PROTECT_TEXT_LEN {
        return Err(format!("输出文本过长（{}字节），上限为 {} 字节", text.len(), MAX_PROTECT_TEXT_LEN));
    }
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Ok(serde_json::json!({
            "allowed": false,
            "fallback": true,
            "reject_stage": "engine_not_running",
            "error": "引擎未运行"
        }));
    }
    let session = session.unwrap_or_else(|| "default".to_string());
    send_output_protect_request(&engine_url, &text, &session).await
}

#[tauri::command]
pub async fn set_mode(
    state: State<'_, Mutex<EngineState>>,
    db: State<'_, Database>,
    mode: String,
) -> Result<(), String> {
    // P1 修复：记录旧模式，用于引擎同步失败时回滚内存态，避免"界面显示新、引擎实际旧"的状态分裂。
    let old_mode = {
        let s = state.lock().map_err(|e| e.to_string())?;
        s.mode.clone()
    };
    {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        s.set_mode(&mode)?;
    }
    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        s.get_engine_url()
    };
    // GAP-05 修复：安全产品模式同步失败必须返回错误，避免前端误认为模式已切换
    if let Err(e) = sync_mode_to_engine(&engine_url, &mode).await {
        eprintln!("[xuandun] [ERROR] sync_mode_to_engine failed: {}", e);
        // 回滚 Rust 内存态到旧模式，消除"内存已改、引擎未改"的状态分裂
        if let Ok(mut s) = state.lock() {
            let _ = s.set_mode(&old_mode);
        }
        // 回滚——保存旧模式到 DB，确保 DB/内存/引擎三方一致
        // 之前 bug: 保存了新模式导致三态分裂
        let _ = db.set_config("mode", &old_mode);
        let _ = db.insert_audit("mode_change", &format!("{} (engine sync failed: {})", mode, e));
        return Err(format!("防护模式已保存但引擎同步失败：{}。请检查引擎是否正常运行。", e));
    }
    if let Err(e) = db.set_config("mode", &mode) {
        eprintln!("[xuandun] [ERROR] set_config(mode) failed: {}", e);
    }
    if let Err(e) = db.insert_audit("mode_change", &mode) {
        eprintln!("[xuandun] [ERROR] insert_audit(mode_change) failed: {}", e);
    }
    Ok(())
}

#[tauri::command]
pub async fn get_logs(
    db: State<'_, Database>,
    filter_allowed: Option<bool>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<LogResponse, String> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);
    let entries = db.query_logs(filter_allowed, limit, offset)?;
    let total = db.count_logs(filter_allowed)?;
    Ok(LogResponse { entries, total })
}

#[tauri::command]
pub async fn get_config(db: State<'_, Database>, key: String) -> Result<Option<String>, String> {
    // P1 修复：空 key 校验
    if key.trim().is_empty() {
        return Err("配置键不能为空".to_string());
    }
    db.get_config(&key)
}

#[tauri::command]
pub async fn set_config(db: State<'_, Database>, key: String, value: String) -> Result<(), String> {
    // P1 修复：空 key 校验
    if key.trim().is_empty() {
        return Err("配置键不能为空".to_string());
    }
    db.set_config(&key, &value)
}

#[tauri::command]
pub async fn restart_engine(app: tauri::AppHandle) -> Result<(), String> {
    engine_restart(&app).await
}

#[tauri::command]
pub async fn stop_engine(app: tauri::AppHandle) -> Result<(), String> {
    engine_stop(&app)
}

/// 打开引擎日志文件（用系统默认关联程序打开）。
/// 日志路径：%LOCALAPPDATA%/com.daoti.xuandun-desktop/engine.log
#[tauri::command]
pub async fn open_engine_log() -> Result<String, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("com.daoti.xuandun-desktop");
    let path = dir.join("engine.log");

    // 若日志文件不存在，先创建空文件避免 open 报错
    if !path.exists() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::File::create(&path);
    }

    let path_str = path.to_string_lossy().to_string();

    // 用系统默认程序打开日志文件（Windows: notepad/默认编辑器）
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("cmd")
            .args(["/C", "start", "", &path_str])
            .spawn()
            .map_err(|e| format!("打开日志失败: {}", e))?;
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        Command::new("open").arg(&path).spawn().map_err(|e| format!("打开日志失败: {}", e))?;
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        Command::new("xdg-open").arg(&path).spawn().map_err(|e| format!("打开日志失败: {}", e))?;
    }

    Ok(path_str)
}

#[tauri::command]
pub async fn warmup(
    app: tauri::AppHandle,
    state: State<'_, Mutex<EngineState>>,
    req: WarmupRequest,
) -> Result<serde_json::Value, String> {
    // 深层安全审计：数组大小上限防止 DoS
    if req.safe_texts.len() > MAX_WARMUP_ITEMS || req.attack_texts.len() > MAX_WARMUP_ITEMS {
        return Err(format!("预热条目过多，单类上限 {} 条", MAX_WARMUP_ITEMS));
    }
    for text in req.safe_texts.iter().chain(req.attack_texts.iter()) {
        if text.len() > MAX_WARMUP_ITEM_LEN {
            return Err(format!("预热文本过长（{}字节），单条上限 {} 字节", text.len(), MAX_WARMUP_ITEM_LEN));
        }
    }
    // P1修复：检查引擎运行状态，而非仅检查 engine_url 是否为空
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Err("Engine not running".to_string());
    }

    // P1修复：复用全局 HTTP_CLIENT 连接池，检查HTTP状态码
    let result = send_warmup_request(&engine_url, &req.safe_texts, &req.attack_texts).await?;

    if let Err(e) = app.state::<Database>().insert_audit("warmup", &format!("safe={}, attack={}", req.safe_texts.len(), req.attack_texts.len())) {
        eprintln!("[xuandun] [ERROR] insert_audit(warmup) failed: {}", e);
    }
    Ok(result)
}

#[tauri::command]
pub fn verify_audit(db: State<'_, Database>) -> Result<crate::db::HashChainReport, String> {
    db.verify_hash_chain()
}

#[tauri::command]
pub fn store_secret_key(key: String) -> Result<(), String> {
    crate::keyring::store_key(&key)
}

#[tauri::command]
pub fn get_secret_key() -> Result<String, String> {
    crate::keyring::retrieve_key()
}

#[tauri::command]
pub fn delete_secret_key() -> Result<(), String> {
    crate::keyring::delete_key()
}

#[tauri::command]
pub fn has_secret_key() -> Result<bool, String> {
    Ok(crate::keyring::has_key())
}

#[tauri::command]
pub fn create_snapshot(db: State<'_, Database>, label: String) -> Result<i64, String> {
    db.create_snapshot(&label)
}

#[tauri::command]
pub fn list_snapshots(db: State<'_, Database>) -> Result<Vec<(i64, String, String)>, String> {
    db.list_snapshots()
}

#[tauri::command]
pub fn restore_snapshot(db: State<'_, Database>, snapshot_id: i64) -> Result<(), String> {
    db.restore_snapshot(snapshot_id)
}

#[tauri::command]
pub fn delete_snapshot(db: State<'_, Database>, snapshot_id: i64) -> Result<(), String> {
    db.delete_snapshot(snapshot_id)
}

#[tauri::command]
pub async fn get_learning_status(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Ok(serde_json::json!({
            "mode": "observing",
            "learning_progress": 0.0,
            "sample_count": 0,
            "min_samples_for_switch": 1000,
            "safe_prototypes": 0,
            "attack_prototypes": 0,
            "builtin_attacks_loaded": 0,
            "would_block_count": 0,
            "would_block_preview": [],
            "switched_at": null,
            "call_count": 0,
        }));
    }
    engine_get(&engine_url, "/learning/status").await
}

// ── 双层架构（外门/内门）指标查询 ──

#[tauri::command]
pub async fn get_dual_layer_stats(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    // 引擎未运行时返回空状态，保持前端字段完整性
    if !is_running {
        return Ok(serde_json::json!({
            "enabled": false,
            "outer_gate": {
                "total": 0, "rejects": 0, "passes": 0, "forwards": 0,
                "reject_rate": 0.0, "pass_rate": 0.0, "forward_rate": 0.0,
                "avg_latency_ms": 0.0,
                "learned_attack_count": 0, "learned_safe_count": 0
            },
            "inner_gate": {
                "total": 0, "rejects": 0, "passes": 0, "learning_events": 0,
                "reject_rate": 0.0, "avg_latency_ms": 0.0
            }
        }));
    }

    // 尝试调用引擎的/dual-layer/stats端点
    // 引擎exe（v1.2.3）可能不支持此端点，404时从/status提取基本信息
    match engine_get(&engine_url, "/dual-layer/stats").await {
        Ok(data) => Ok(data),
        // P1修复：不再使用 unwrap_or 静默吞错，分叉处理：/status 成功则构建降级数据，双端点均失败则注入 error 字段
        Err(_) => {
            let status_result = engine_get(&engine_url, "/status").await;
            match status_result {
                Ok(status) => {
                    let total_requests = status.get("total_requests").and_then(|v| v.as_u64()).unwrap_or(0);
                    let total_blocked = status.get("total_blocked").and_then(|v| v.as_u64()).unwrap_or(0);
                    let block_rate = status.get("block_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let learning_mode = status.get("learning_mode").and_then(|v| v.as_str()).unwrap_or("unknown");

                    Ok(serde_json::json!({
                        "enabled": true,
                        "note": "引擎版本不支持/dual-layer/stats端点，以下为从/status提取的汇总数据",
                        "engine_version": status.get("version").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "learning_mode": learning_mode,
                "outer_gate": {
                    "total": total_requests,
                    "rejects": total_blocked,
                    "passes": total_requests.saturating_sub(total_blocked),
                    "forwards": total_requests.saturating_sub(total_blocked),
                    "reject_rate": block_rate,
                    "pass_rate": if total_requests > 0 { 1.0 - block_rate } else { 0.0 },
                    "forward_rate": if total_requests > 0 { 1.0 - block_rate } else { 0.0 },
                    "avg_latency_ms": 0.0,
                    "learned_attack_count": 0,
                    "learned_safe_count": status.get("sample_count").and_then(|v| v.as_u64()).unwrap_or(0)
                },
                "inner_gate": {
                    "total": total_requests,
                    "rejects": total_blocked,
                    "passes": total_requests.saturating_sub(total_blocked),
                    "learning_events": 0,
                    "reject_rate": block_rate,
                    "avg_latency_ms": 0.0
                }
            }))
                }
                Err(e) => {
                    // 双端点均失败，注入 error 字段让前端感知异常
                    Ok(serde_json::json!({
                        "enabled": false,
                        "error": format!("引擎双端点均不可达: {}", e),
                        "outer_gate": { "total": 0, "rejects": 0, "passes": 0, "forwards": 0, "reject_rate": 0.0, "pass_rate": 0.0, "forward_rate": 0.0, "avg_latency_ms": 0.0, "learned_attack_count": 0, "learned_safe_count": 0 },
                        "inner_gate": { "total": 0, "rejects": 0, "passes": 0, "learning_events": 0, "reject_rate": 0.0, "avg_latency_ms": 0.0 }
                    }))
                }
            }
        }
    }
}

// ── 输出护栏（模型→用户）：stats / history / trend ──
// 数据由引擎侧内存按分钟桶采集（准实时、重启清空），前端呈现时需标注来源。

#[tauri::command]
pub async fn get_output_stats(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        // 字段对齐前端 OutputStats 接口，保证前端字段完整
        return Ok(serde_json::json!({
            "total_checks": 0, "blocked": 0, "redacted": 0, "alerted": 0
        }));
    }
    engine_get(&engine_url, "/output/stats").await
}

#[tauri::command]
pub async fn get_output_history(
    state: State<'_, Mutex<EngineState>>,
    limit: Option<u32>,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Ok(serde_json::json!({ "history": [] }));
    }
    let limit = limit.unwrap_or(20).clamp(1, 200);
    engine_get(&engine_url, &format!("/output/history?limit={}", limit)).await
}

/// 读取输出护栏当前生效配置（引擎 /output/config GET）。
/// 供 Settings 专家模式「输出护栏配置卡」回显。
#[tauri::command]
pub async fn get_output_config(
    state: State<'_, Mutex<EngineState>>,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Err("引擎未运行".to_string());
    }
    engine_get(&engine_url, "/output/config").await
}

/// 动态调校输出护栏配置（引擎 /output/config POST）。
/// config: 白名单内可调参数 {enable_output_guardrail, *_threshold, redact_token, ...}
/// 返回引擎生效快照。失败必须返回错误，不得静默吞掉（安全产品硬约束）。
#[tauri::command]
pub async fn set_output_config(
    state: State<'_, Mutex<EngineState>>,
    config: serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Err("引擎未运行".to_string());
    }
    if config.is_empty() {
        return Err("配置不能为空".to_string());
    }
    let body = serde_json::json!({ "config": config });
    engine_post(&engine_url, "/output/config", body).await
}

#[tauri::command]
pub async fn get_output_trend(
    state: State<'_, Mutex<EngineState>>,
    granularity: String,
    start: Option<String>,
    end: Option<String>,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Ok(serde_json::json!({ "points": [] }));
    }
    let mut path = format!("/output/stats/timeseries?granularity={}", granularity);
    if let Some(s) = start {
        path.push_str(&format!("&start={}", s));
    }
    if let Some(e) = end {
        path.push_str(&format!("&end={}", e));
    }
    engine_get(&engine_url, &path).await
}

// ── 企业级运维：逃生通道 + 灰度部署 ──

#[tauri::command]
pub async fn set_emergency_bypass(
    state: State<'_, Mutex<EngineState>>,
    enabled: bool,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Err("Engine not running".to_string());
    }
    let body = serde_json::json!({ "enabled": enabled });
    engine_post(&engine_url, "/emergency/bypass", body).await
}

#[tauri::command]
pub async fn get_emergency_bypass(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        // 字段对齐前端 EmergencyBypassState 接口
        return Ok(serde_json::json!({ "enabled": false }));
    }
    engine_get(&engine_url, "/emergency/bypass").await
}

#[tauri::command]
pub async fn set_gray_deploy_ratio(
    state: State<'_, Mutex<EngineState>>,
    ratio: f64,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Err("Engine not running".to_string());
    }
    let body = serde_json::json!({ "ratio": ratio });
    engine_post(&engine_url, "/gray/deploy", body).await
}

#[tauri::command]
pub async fn get_gray_deploy_ratio(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        // 字段对齐前端 GrayDeployState 接口
        return Ok(serde_json::json!({ "ratio": 1.0 }));
    }
    engine_get(&engine_url, "/gray/deploy").await
}

#[tauri::command]
pub async fn get_bypass_stats(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Ok(serde_json::json!({
            "emergency_bypass": false,
            "gray_deploy_ratio": 1.0,
            "gray_bypass_count": 0,
            "bypass_log": []
        }));
    }
    engine_get(&engine_url, "/bypass/stats").await
}

#[tauri::command]
pub async fn send_notification(
    app: tauri::AppHandle,
    title: String,
    body: String,
) -> Result<(), String> {
    app.notification()
        .builder()
        .title(&title)
        .body(&body)
        .show()
        .map_err(|e| format!("Notification failed: {}", e))
}

#[derive(Serialize)]
pub struct TrendStatsResponse {
    pub granularity: String,
    pub points: Vec<crate::db::TrendPoint>,
}

#[tauri::command]
pub async fn get_trend_stats(
    db: State<'_, Database>,
    granularity: String,
    start: String,
    end: String,
) -> Result<TrendStatsResponse, String> {
    let points = db.get_trend_stats(&start, &end)?;
    Ok(TrendStatsResponse { granularity, points })
}

#[tauri::command]
pub async fn get_attack_distribution(
    db: State<'_, Database>,
    start: String,
    end: String,
) -> Result<Vec<crate::db::AttackCategoryStat>, String> {
    db.get_attack_distribution(&start, &end)
}

#[derive(Serialize)]
pub struct RealtimeMetrics {
    pub total_requests: u64,
    pub total_blocked: u64,
    pub block_rate: f64,
    pub uptime_secs: f64,
    pub qps: f64,
    pub mode: String,
    pub healthy: bool,
}

#[tauri::command]
pub async fn get_realtime_metrics(
    state: State<'_, Mutex<EngineState>>,
) -> Result<RealtimeMetrics, String> {
    let s = state.lock().map_err(|e| e.to_string())?;
    let uptime = s.uptime_secs();
    let qps = if uptime > 0.0 { s.total_requests as f64 / uptime } else { 0.0 };
    Ok(RealtimeMetrics {
        total_requests: s.total_requests,
        total_blocked: s.total_blocked,
        block_rate: s.block_rate(),
        uptime_secs: uptime,
        qps,
        mode: s.mode.clone(),
        healthy: s.healthy,
    })
}

#[derive(Serialize)]
pub struct ComparisonStats {
    pub current: crate::db::PeriodStats,
    pub baseline: crate::db::PeriodStats,
}

#[tauri::command]
pub async fn get_comparison_stats(
    db: State<'_, Database>,
    current_start: String,
    current_end: String,
    baseline_start: String,
    baseline_end: String,
) -> Result<ComparisonStats, String> {
    let current = db.get_period_stats(&current_start, &current_end)?;
    let baseline = db.get_period_stats(&baseline_start, &baseline_end)?;
    Ok(ComparisonStats { current, baseline })
}

#[tauri::command]
pub async fn save_notifier_config(
    db: State<'_, Database>,
    state: State<'_, Mutex<EngineState>>,
    channel: String,
    config: serde_json::Value,
) -> Result<(), String> {
    let config_str = serde_json::to_string(&config).map_err(|e| e.to_string())?;
    db.set_config(&format!("notifier_{}", channel), &config_str)?;

    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        s.get_engine_url()
    };

    let mut channels = serde_json::Map::new();
    for ch in &["dingtalk", "feishu", "email", "webhook", "syslog"] {
        if let Ok(Some(cfg)) = db.get_config(&format!("notifier_{}", ch)) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&cfg) {
                channels.insert(ch.to_string(), val);
            }
        }
    }
    let body = serde_json::json!({ "channels": channels });
    // GAP-04 修复：不再吞掉 engine_post 错误，DB 成功但引擎未同步会导致配置不一致
    if let Err(e) = engine_post(&engine_url, "/notifiers/config", body).await {
        eprintln!("[xuandun] [ERROR] save_notifier_config: engine_post failed (DB saved but engine not synced): {}", e);
        return Err(format!("通知配置已保存到数据库，但引擎同步失败：{}。请重启引擎或检查引擎状态。", e));
    }
    Ok(())
}

#[tauri::command]
pub async fn get_notifier_config(
    db: State<'_, Database>,
    channel: String,
) -> Result<Option<serde_json::Value>, String> {
    let key = format!("notifier_{}", channel);
    match db.get_config(&key)? {
        Some(s) => {
            let val: serde_json::Value = serde_json::from_str(&s).map_err(|e| e.to_string())?;
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn test_notifier(
    state: State<'_, Mutex<EngineState>>,
    channel: String,
    config: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        s.get_engine_url()
    };
    let body = serde_json::json!({ "channel": channel, "config": config });
    engine_post(&engine_url, "/notifiers/test", body).await
}

// Sprint1-P0-7: IPC析构散落报错修复——noop心跳命令
// 前端每10s调用一次，3s超时快速失败。用于快速检测Tauri IPC桥接是否仍然存活，
// 避免桥接析构后各组件散落报错无法统一处理。返回ok=true + 当前时间戳
#[tauri::command]
pub fn noop_heartbeat() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "ok": true,
        "ts": chrono::Utc::now().timestamp_millis()
    }))
}

// ── 修复4：健康历史时间线查询 ──

/// 返回引擎健康历史时间线（timestamp_ms, event），最多 100 条
#[tauri::command]
pub fn get_health_history(state: State<'_, Mutex<EngineState>>) -> Result<Vec<(i64, String)>, String> {
    let s = state.lock().map_err(|e| e.to_string())?;
    Ok(s.get_health_history())
}

// ── 上游模型配置（可视化表单）──
// 配置存 DB config 表（upstream_url / upstream_api_key / upstream_model / upstream_timeout），
// 引擎启动时由 start_engine_sidecar 读取并注入环境变量（XUANDUN_UPSTREAM_*）。
// 用户无需修改代码/设置系统环境变量，直接在设置页表单填写即可。

fn default_upstream_timeout() -> f64 { 300.0 }

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamConfig {
    /// 上游模型 OpenAI 兼容地址（如 https://api.openai.com/v1）
    pub url: String,
    /// 上游 API Key（可空，私有化模型无需鉴权）
    pub api_key: String,
    /// 默认模型名（可空，缺省用请求里的 model）
    pub model: String,
    /// 请求上游超时秒数（默认 300）
    #[serde(default = "default_upstream_timeout")]
    pub timeout: f64,
}

impl UpstreamConfig {
    fn from_db(db: &Database) -> Result<Self, String> {
        let url = db.get_config("upstream_url")?.unwrap_or_default();
        let api_key = db.get_config("upstream_api_key")?.unwrap_or_default();
        let model = db.get_config("upstream_model")?.unwrap_or_default();
        let timeout = db.get_config("upstream_timeout")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(300.0);
        Ok(Self { url, api_key, model, timeout })
    }
}

/// 读取上游模型配置（设置页回显）
#[tauri::command]
pub fn get_upstream_config(db: State<'_, Database>) -> Result<UpstreamConfig, String> {
    UpstreamConfig::from_db(&db)
}

/// 保存上游模型配置到 DB。校验 URL 格式；配置需重启引擎后生效（engine.rs 启动时注入）。
#[tauri::command]
pub fn set_upstream_config(
    db: State<'_, Database>,
    config: UpstreamConfig,
) -> Result<(), String> {
    let url = config.url.trim().to_string();
    if url.is_empty() {
        return Err("上游模型地址不能为空".to_string());
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("上游模型地址必须以 http:// 或 https:// 开头".to_string());
    }
    let timeout = if config.timeout <= 0.0 { 300.0 } else { config.timeout };
    db.set_config("upstream_url", &url)?;
    db.set_config("upstream_api_key", config.api_key.trim())?;
    db.set_config("upstream_model", config.model.trim())?;
    db.set_config("upstream_timeout", &timeout.to_string())?;
    Ok(())
}

// ── P2 平面端新命令（桌面端前端重构 V2）──

/// 模型服务器扫描结果
#[derive(Serialize)]
pub struct ModelScanResult {
    pub success: bool,
    pub models: Vec<ModelInfo>,
    pub error: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ModelInfo {
    pub name: String,
    pub port: u16,
    #[serde(rename = "type")]
    pub model_type: String,
}

/// 扫描 GPU 服务器 IP 上的常见模型端口，尝试识别模型名称
#[tauri::command]
pub async fn scan_model_server(ip: String) -> Result<ModelScanResult, String> {
    let ip = ip.trim().to_string();
    if ip.is_empty() {
        return Err("IP 地址不能为空".to_string());
    }

    let ports: Vec<(u16, &str)> = vec![
        (11434, "Ollama"),
        (8000, "vLLM"),
        (8080, "TGI"),
    ];

    let mut models: Vec<ModelInfo> = Vec::new();

    for (port, service_type) in &ports {
        let url = format!("http://{}:{}/api/tags", ip, port);
        // P1 修复：设置 3s 超时，防止端口半开（SYN无响应）挂起
        match crate::engine::HTTP_CLIENT.get(&url).timeout(std::time::Duration::from_secs(3)).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    // Ollama 格式：{"models": [{"name": "llama3:8b"}, ...]}
                    if let Some(models_arr) = json.get("models").and_then(|m| m.as_array()) {
                        for m in models_arr {
                            if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                                models.push(ModelInfo {
                                    name: name.to_string(),
                                    port: *port,
                                    model_type: service_type.to_string(),
                                });
                            }
                        }
                    }
                    // vLLM/TGI 格式：{"data": [{"id": "llama3"}, ...]}
                    else if let Some(data_arr) = json.get("data").and_then(|d| d.as_array()) {
                        for m in data_arr {
                            if let Some(name) = m.get("id").and_then(|n| n.as_str()) {
                                models.push(ModelInfo {
                                    name: name.to_string(),
                                    port: *port,
                                    model_type: service_type.to_string(),
                                });
                            }
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.is_connect() || e.is_timeout() => {
                // 端口不可达或超时，跳过
            }
            Err(_) => {}
        }

        // 如果 /api/tags 失败，尝试 /v1/models（OpenAI 兼容端点）
        if models.is_empty() {
            let v1_url = format!("http://{}:{}/v1/models", ip, port);
            if let Ok(resp) = crate::engine::HTTP_CLIENT.get(&v1_url).timeout(std::time::Duration::from_secs(3)).send().await {
                if resp.status().is_success() {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if let Some(data_arr) = json.get("data").and_then(|d| d.as_array()) {
                            for m in data_arr {
                                if let Some(name) = m.get("id").and_then(|n| n.as_str()) {
                                    // 避免重复
                                    if !models.iter().any(|existing| existing.name == name) {
                                        models.push(ModelInfo {
                                            name: name.to_string(),
                                            port: *port,
                                            model_type: service_type.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(ModelScanResult {
        success: true,
        models,
        error: None,
    })
}

/// 连接指定模型：构造 upstream URL 并保存到 DB
/// P1 修复：接受可选 ip 参数，默认 127.0.0.1（本地引擎），
/// 扫描远程 GPU 服务器时自动填入对应 IP
#[tauri::command]
pub fn connect_model(
    db: State<'_, Database>,
    model_name: String,
    port: u16,
    ip: Option<String>,
) -> Result<(), String> {
    let model_name = model_name.trim();
    if model_name.is_empty() {
        return Err("模型名不能为空".to_string());
    }
    if port == 0 {
        return Err("端口号不能为0".to_string());
    }
    let host = ip.as_deref().unwrap_or("127.0.0.1").trim();
    if host.is_empty() {
        return Err("IP 地址不能为空".to_string());
    }
    let upstream_url = format!("http://{}:{}/v1", host, port);
    db.set_config("upstream_url", &upstream_url)?;
    db.set_config("upstream_model", model_name)?;
    // API key 留空（本地模型通常无需鉴权）
    db.set_config("upstream_api_key", "")?;
    db.set_config("upstream_timeout", "300")?;
    Ok(())
}

/// "标记为安全" — 将文本发送给引擎的 /learn/safe 端点，
/// 让引擎将该样本加入良性原型库
#[tauri::command]
pub async fn mark_as_safe(
    state: State<'_, Mutex<EngineState>>,
    text: String,
) -> Result<serde_json::Value, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("文本不能为空".to_string());
    }
    // 深层安全审计：输入长度上限
    if text.len() > MAX_PROTECT_TEXT_LEN {
        return Err(format!("文本过长（{}字节），上限为 {} 字节", text.len(), MAX_PROTECT_TEXT_LEN));
    }
    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.running {
            return Err("引擎未运行".to_string());
        }
        s.get_engine_url()
    };
    let body = serde_json::json!({ "text": text });
    engine_post(&engine_url, "/learn/safe", body).await
}

/// 周报预览 — 从引擎获取本周统计数据摘要
#[tauri::command]
pub async fn get_weekly_report_preview(
    state: State<'_, Mutex<EngineState>>,
) -> Result<serde_json::Value, String> {
    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.running {
            return Err("引擎未运行".to_string());
        }
        s.get_engine_url()
    };
    // 引擎 /status 返回累计数据，/metrics/realtime 返回实时指标
    // 周报依赖状态端点，并计算本周近似值（假设引擎持续运行）
    let status = engine_get(&engine_url, "/status").await?;
    let total_requests = status.get("total_requests").and_then(|v| v.as_u64()).unwrap_or(0);
    let total_blocked = status.get("total_blocked").and_then(|v| v.as_u64()).unwrap_or(0);
    let block_rate = if total_requests > 0 {
        total_blocked as f64 / total_requests as f64
    } else {
        0.0
    };
    // 攻击分布总和：统计 attack_distribution 下所有类别的攻击计数
    // 前端字段名 high_risk_count 保持不变以兼容接口，但语义为所有攻击分布的总和（非仅高危）
    let total_attack_distribution = status.get("attack_distribution")
        .and_then(|v| v.as_object())
        .map(|dist| {
            dist.values()
                .filter_map(|v| v.as_u64())
                .sum::<u64>()
        })
        .unwrap_or(0);

    Ok(serde_json::json!({
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "block_rate": block_rate,
        "high_risk_count": total_attack_distribution,
    }))
}

/// 生成安全周报 — 调用引擎 /report/weekly 端点生成 PDF
#[tauri::command]
pub async fn generate_weekly_report(
    state: State<'_, Mutex<EngineState>>,
) -> Result<serde_json::Value, String> {
    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.running {
            return Err("引擎未运行".to_string());
        }
        s.get_engine_url()
    };
    // POST 触发周报生成，引擎返回文件路径
    engine_post(&engine_url, "/report/weekly", serde_json::json!({})).await
}

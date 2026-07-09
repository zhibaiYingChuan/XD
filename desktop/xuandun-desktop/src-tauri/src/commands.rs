use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tauri_plugin_notification::NotificationExt;
use std::sync::Mutex;

use crate::engine::{EngineState, send_protect_request, sync_mode_to_engine, restart_engine as engine_restart, stop_engine as engine_stop, safe_preview};
use crate::db::Database;

#[derive(Serialize)]
pub struct StatusResponse {
    pub running: bool,
    pub healthy: bool,
    pub mode: String,
    pub uptime: f64,
    pub total_requests: u64,
    pub total_blocked: u64,
    pub block_rate: f64,
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
    let s = state.lock().map_err(|e| e.to_string())?;
    Ok(StatusResponse {
        running: s.running,
        healthy: s.healthy,
        mode: s.mode.clone(),
        uptime: s.uptime_secs(),
        total_requests: s.total_requests,
        total_blocked: s.total_blocked,
        block_rate: s.block_rate(),
    })
}

#[tauri::command]
pub async fn protect(
    app: tauri::AppHandle,
    state: State<'_, Mutex<EngineState>>,
    db: State<'_, Database>,
    req: ProtectRequest,
) -> Result<ProtectResponse, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };

    if !is_running {
        return Ok(ProtectResponse {
            allowed: false,
            trust_level: "BLOCKED".to_string(),
            reject_stage: Some("engine_not_running".to_string()),
            domain_distance: None,
            timing_distance: None,
            fallback: true,
        });
    }

    let result = send_protect_request(&engine_url, &req.text, &req.session, &req.mode).await;

    match result {
        Ok(r) => {
            if let Err(e) = db.insert_log(
                safe_preview(&req.text, 50),
                r.allowed,
                &r.trust_level,
                r.reject_stage.as_deref(),
                Some(&req.session),
            ) {
                eprintln!("[xuandun] insert_log failed: {}", e);
            }
            {
                let mut s = state.lock().map_err(|e| e.to_string())?;
                s.record_result(&req.text, &r);
            }
            if !r.allowed {
                let _ = app.notification()
                    .builder()
                    .title("道体·玄盾 - 攻击拦截")
                    .body(&format!("检测到恶意输入，信任等级: {}", r.trust_level))
                    .show();
                if let Err(e) = db.insert_audit("block", &format!("trust_level={}", r.trust_level)) {
                    eprintln!("[xuandun] insert_audit(block) failed: {}", e);
                }
            }
            Ok(ProtectResponse {
                allowed: r.allowed,
                trust_level: r.trust_level,
                reject_stage: r.reject_stage,
                domain_distance: r.domain_distance,
                timing_distance: r.timing_distance,
                fallback: false,
            })
        }
        Err(_) => {
            if let Err(e) = db.insert_audit("fallback", "engine_unavailable") {
                eprintln!("[xuandun] insert_audit(fallback) failed: {}", e);
            }
            Ok(ProtectResponse {
                allowed: false,
                trust_level: "BLOCKED".to_string(),
                reject_stage: Some("engine_unavailable".to_string()),
                domain_distance: None,
                timing_distance: None,
                fallback: true,
            })
        }
    }
}

#[tauri::command]
pub async fn set_mode(
    state: State<'_, Mutex<EngineState>>,
    db: State<'_, Database>,
    mode: String,
) -> Result<(), String> {
    {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        s.set_mode(&mode)?;
    }
    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        s.get_engine_url()
    };
    if let Err(e) = sync_mode_to_engine(&engine_url, &mode).await {
        eprintln!("[xuandun] sync_mode_to_engine failed: {}", e);
    }
    if let Err(e) = db.set_config("mode", &mode) {
        eprintln!("[xuandun] set_config(mode) failed: {}", e);
    }
    if let Err(e) = db.insert_audit("mode_change", &mode) {
        eprintln!("[xuandun] insert_audit(mode_change) failed: {}", e);
    }
    Ok(())
}

#[tauri::command]
pub async fn discover_agents() -> Result<Vec<crate::agent_discovery::AgentInfo>, String> {
    crate::agent_discovery::discover().await
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
pub async fn start_proxy_cmd(app: tauri::AppHandle, port: u16) -> Result<(), String> {
    crate::proxy::start_proxy(app, port).await
}

#[tauri::command]
pub async fn stop_proxy_cmd() -> Result<(), String> {
    crate::proxy::stop_proxy()
}

#[tauri::command]
pub fn is_proxy_running_cmd() -> bool {
    crate::proxy::is_proxy_running()
}

#[tauri::command]
pub async fn get_config(db: State<'_, Database>, key: String) -> Result<Option<String>, String> {
    db.get_config(&key)
}

#[tauri::command]
pub async fn set_config(db: State<'_, Database>, key: String, value: String) -> Result<(), String> {
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

#[tauri::command]
pub async fn warmup(
    app: tauri::AppHandle,
    state: State<'_, Mutex<EngineState>>,
    req: WarmupRequest,
) -> Result<serde_json::Value, String> {
    let engine_url = {
        let s = state.lock().map_err(|e| e.to_string())?;
        s.get_engine_url()
    };
    if engine_url.is_empty() {
        return Err("Engine not running".to_string());
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/warmup", engine_url))
        .json(&serde_json::json!({
            "safe_texts": req.safe_texts,
            "attack_texts": req.attack_texts,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Warmup request failed: {}", e))?;

    let result: serde_json::Value = resp.json().await.map_err(|e| format!("Parse response failed: {}", e))?;
    if let Err(e) = app.state::<Database>().insert_audit("warmup", &format!("safe={}, attack={}", req.safe_texts.len(), req.attack_texts.len())) {
        eprintln!("[xuandun] insert_audit(warmup) failed: {}", e);
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

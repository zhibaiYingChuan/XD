use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tauri_plugin_notification::NotificationExt;
use std::sync::Mutex;

use crate::engine::{EngineState, send_protect_request, send_warmup_request, sync_mode_to_engine, restart_engine as engine_restart, stop_engine as engine_stop, safe_preview, engine_get, engine_post};
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
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };

    if !is_running {
        // R-01 修复：引擎未运行分支补充审计记录，与 Err 分支保持审计一致性
        if let Err(e) = db.insert_audit("fallback", "engine_not_running") {
            eprintln!("[xuandun] insert_audit(fallback/not_running) failed: {}", e);
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
                    let _ = engine_post(&alert_engine_url, "/alert/dispatch", alert_body).await;
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
                eprintln!("[xuandun] insert_audit(fallback) failed: {}", audit_err);
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
    // GAP-05 修复：安全产品模式同步失败必须返回错误，避免前端误认为模式已切换
    if let Err(e) = sync_mode_to_engine(&engine_url, &mode).await {
        eprintln!("[xuandun] sync_mode_to_engine failed: {}", e);
        // 仍然保存到 DB 和审计日志，但返回错误让前端知道引擎未同步
        let _ = db.set_config("mode", &mode);
        let _ = db.insert_audit("mode_change", &format!("{} (engine sync failed: {})", mode, e));
        return Err(format!("防护模式已保存但引擎同步失败：{}。请检查引擎是否正常运行。", e));
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

#[tauri::command]
pub async fn switch_learning_mode(
    state: State<'_, Mutex<EngineState>>,
    mode: String,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Err("Engine not running".to_string());
    }
    let body = serde_json::json!({ "mode": mode });
    engine_post(&engine_url, "/mode/switch", body).await
}

#[tauri::command]
pub async fn get_learning_details(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Ok(serde_json::json!({}));
    }
    engine_get(&engine_url, "/learning/details").await
}

// ── 双层架构（外门/内门）指标查询 ──

#[tauri::command]
pub async fn get_dual_layer_stats(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        // 引擎未运行时返回空状态，保持前端字段完整性
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
    engine_get(&engine_url, "/dual-layer/stats").await
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
pub async fn run_simulation(
    state: State<'_, Mutex<EngineState>>,
    mode: String,
    categories: Option<Vec<String>>,
    custom_texts: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Err("Engine not running".to_string());
    }
    let mut body = serde_json::json!({ "mode": mode });
    if let Some(cats) = categories {
        body["categories"] = serde_json::json!(cats);
    }
    if let Some(texts) = custom_texts {
        body["custom_texts"] = serde_json::json!(texts);
    }
    engine_post(&engine_url, "/simulation/run", body).await
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

fn attack_category_name_cn(key: &str) -> &'static str {
    match key {
        "direct_prompt_injection" => "直接提示注入",
        "indirect_prompt_injection" => "间接提示注入",
        "jailbreak" => "越狱攻击",
        "encoding_obfuscation" => "编码混淆",
        "agent_attack" => "Agent攻击",
        "data_leakage" => "数据泄露",
        "other" => "其他",
        _ => "未知",
    }
}

/// HTML 实体转义，防止 XSS 攻击。
/// 对所有插入 HTML 的用户输入必须调用此函数。
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            '/' => out.push_str("&#x2f;"),
            _ => out.push(ch),
        }
    }
    out
}

/// 按字符边界安全截断字符串，避免中文字符被字节切片切断导致 panic。
/// 返回截断后的字符串（不含省略号），调用方按需追加 "..."。
fn safe_truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

fn render_report_html(data: &crate::db::ReportData, report_type: &str, start: &str, end: &str) -> String {
    let type_label = match report_type { "weekly" => "周报", "monthly" => "月报", _ => "自定义报告" };
    let now = chrono::Utc::now().to_rfc3339();

    let cat_rows: String = data.categories.iter().take(10).map(|c| {
        let pct = if data.total_blocked > 0 { c.count as f64 / data.total_blocked as f64 * 100.0 } else { 0.0 };
        format!("<tr><td>{}</td><td>{}</td><td>{:.1}%</td></tr>", html_escape(attack_category_name_cn(&c.category)), c.count, pct)
    }).collect::<Vec<_>>().join("");
    let cat_rows = if cat_rows.is_empty() { "<tr><td colspan=\"3\">无攻击记录</td></tr>".to_string() } else { cat_rows };

    let sample_rows: String = data.samples.iter().map(|s| {
        let cat = s.attack_category.as_deref().map(attack_category_name_cn).unwrap_or("未知");
        let stage = s.reject_stage.as_deref().unwrap_or("--");
        // 安全截断：按字符边界，避免中文切片 panic
        let truncated = safe_truncate_chars(&s.text_preview, 50);
        let text_display = if s.text_preview.chars().count() > 50 {
            format!("{}...", html_escape(&truncated))
        } else {
            html_escape(&truncated)
        };
        format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>", text_display, html_escape(cat), html_escape(stage))
    }).collect::<Vec<_>>().join("");
    let sample_rows = if sample_rows.is_empty() { "<tr><td colspan=\"3\">无拦截样本</td></tr>".to_string() } else { sample_rows };

    let cat_bars: String = data.categories.iter().take(6).map(|c| {
        let pct = if data.total_blocked > 0 { c.count as f64 / data.total_blocked as f64 * 100.0 } else { 0.0 };
        format!("<div style=\"margin:4px 0\"><span style=\"display:inline-block;width:120px\">{}</span><div style=\"display:inline-block;width:200px;height:16px;background:#e0e0e0;border-radius:4px\"><div style=\"width:{:.0}%;height:100%;background:#4ecdc4;border-radius:4px\"></div></div><span style=\"margin-left:8px\">{} ({:.1}%)</span></div>", html_escape(attack_category_name_cn(&c.category)), pct, c.count, pct)
    }).collect::<Vec<_>>().join("");

    // 安全截断日期字符串，避免边界 panic
    let start_date = safe_truncate_chars(start, 10);
    let end_date = safe_truncate_chars(end, 10);

    format!("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><title>道体·玄盾 安全{type_label}</title><style>body{{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px;color:#333}}h1{{color:#4ecdc4;border-bottom:2px solid #4ecdc4;padding-bottom:8px}}h2{{color:#45b7d1;margin-top:24px}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid #ddd;padding:8px;font-size:13px;text-align:left}}th{{background:#f5f5f5}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}.item{{background:#f9f9f9;padding:12px;border-radius:8px;text-align:center}}.val{{font-size:24px;font-weight:700;color:#4ecdc4}}.lbl{{font-size:12px;color:#999}}.footer{{margin-top:32px;padding-top:12px;border-top:1px solid #ddd;font-size:12px;color:#999}}</style></head><body><h1>道体·玄盾 安全{type_label}</h1><p>报告周期：{} 至 {} | 生成时间：{}</p><h2>1. 概要摘要</h2><div class=\"grid\"><div class=\"item\"><div class=\"val\">{}</div><div class=\"lbl\">总请求数</div></div><div class=\"item\"><div class=\"val\" style=\"color:#ff6b6b\">{}</div><div class=\"lbl\">拦截次数</div></div><div class=\"item\"><div class=\"val\">{:.1}%</div><div class=\"lbl\">拦截率</div></div><div class=\"item\"><div class=\"val\">{}</div><div class=\"lbl\">放行次数</div></div></div><h2>2. 攻击类型分布</h2>{}<table><thead><tr><th>攻击类型</th><th>拦截量</th><th>占比</th></tr></thead><tbody>{}</tbody></table><h2>3. 代表性拦截样本</h2><table><thead><tr><th>文本摘要</th><th>攻击分类</th><th>拦截阶段</th></tr></thead><tbody>{}</tbody></table><div class=\"footer\"><p>本报告由道体·玄盾自动生成 | SPDX-License-Identifier: DaoTi-Research-1.0</p></div></body></html>",
        html_escape(&start_date), html_escape(&end_date), html_escape(&now),
        data.total_requests, data.total_blocked, data.block_rate, data.total_allowed,
        cat_bars, cat_rows, sample_rows)
}

#[tauri::command]
pub async fn generate_report(
    db: State<'_, Database>,
    report_type: String,
    start: String,
    end: String,
) -> Result<i64, String> {
    let data = db.get_report_data(&start, &end)?;
    let html = render_report_html(&data, &report_type, &start, &end);
    let summary = format!("{{\"total\":{},\"blocked\":{},\"block_rate\":{:.2}}}", data.total_requests, data.total_blocked, data.block_rate);
    let report_id = db.insert_report(&report_type, &start, &end, "html", html.as_bytes(), Some(&summary), Some("manual"))?;
    Ok(report_id)
}

#[tauri::command]
pub async fn list_reports(
    db: State<'_, Database>,
    limit: Option<usize>,
) -> Result<Vec<crate::db::ReportSummary>, String> {
    db.list_reports(limit.unwrap_or(50))
}

#[tauri::command]
pub async fn get_report(
    db: State<'_, Database>,
    report_id: i64,
) -> Result<serde_json::Value, String> {
    let reports = db.list_reports(1000)?;
    let summary = reports.iter().find(|r| r.id == report_id).cloned();
    let (content, format) = db.get_report_content(report_id)?;
    let content_str = String::from_utf8(content).map_err(|e| format!("Report content decode failed: {}", e))?;
    Ok(serde_json::json!({
        "summary": summary,
        "content": content_str,
        "format": format,
    }))
}

#[tauri::command]
pub async fn delete_report(
    db: State<'_, Database>,
    report_id: i64,
) -> Result<(), String> {
    db.delete_report(report_id)
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
        eprintln!("[xuandun] save_notifier_config: engine_post failed (DB saved but engine not synced): {}", e);
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

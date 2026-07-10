use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tauri_plugin_notification::NotificationExt;
use std::sync::Mutex;

use crate::engine::{EngineState, send_protect_request, sync_mode_to_engine, restart_engine as engine_restart, stop_engine as engine_stop, safe_preview, engine_get, engine_post};
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
            Ok(ProtectResponse {
                allowed: false,
                trust_level: "BLOCKED".to_string(),
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

#[tauri::command]
pub async fn get_learning_status(state: State<'_, Mutex<EngineState>>) -> Result<serde_json::Value, String> {
    let (engine_url, is_running) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.get_engine_url(), s.running)
    };
    if !is_running {
        return Ok(serde_json::json!({
            "mode": "protecting",
            "learning_progress": 1.0,
            "sample_count": 0,
            "safe_prototypes": 0,
            "attack_prototypes": 0,
            "would_block_count": 0,
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

fn render_report_html(data: &crate::db::ReportData, report_type: &str, start: &str, end: &str) -> String {
    let type_label = match report_type { "weekly" => "周报", "monthly" => "月报", _ => "自定义报告" };
    let now = chrono::Utc::now().to_rfc3339();

    let cat_rows: String = data.categories.iter().take(10).map(|c| {
        let pct = if data.total_blocked > 0 { c.count as f64 / data.total_blocked as f64 * 100.0 } else { 0.0 };
        format!("<tr><td>{}</td><td>{}</td><td>{:.1}%</td></tr>", attack_category_name_cn(&c.category), c.count, pct)
    }).collect::<Vec<_>>().join("");
    let cat_rows = if cat_rows.is_empty() { "<tr><td colspan=\"3\">无攻击记录</td></tr>".to_string() } else { cat_rows };

    let sample_rows: String = data.samples.iter().map(|s| {
        let cat = s.attack_category.as_deref().map(attack_category_name_cn).unwrap_or("未知");
        let stage = s.reject_stage.as_deref().unwrap_or("--");
        let text = if s.text_preview.len() > 50 { &s.text_preview[..50] } else { &s.text_preview };
        format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>", text, cat, stage)
    }).collect::<Vec<_>>().join("");
    let sample_rows = if sample_rows.is_empty() { "<tr><td colspan=\"3\">无拦截样本</td></tr>".to_string() } else { sample_rows };

    let cat_bars: String = data.categories.iter().take(6).map(|c| {
        let pct = if data.total_blocked > 0 { c.count as f64 / data.total_blocked as f64 * 100.0 } else { 0.0 };
        format!("<div style=\"margin:4px 0\"><span style=\"display:inline-block;width:120px\">{}</span><div style=\"display:inline-block;width:200px;height:16px;background:#e0e0e0;border-radius:4px\"><div style=\"width:{:.0}%;height:100%;background:#4ecdc4;border-radius:4px\"></div></div><span style=\"margin-left:8px\">{} ({:.1}%)</span></div>", attack_category_name_cn(&c.category), pct, c.count, pct)
    }).collect::<Vec<_>>().join("");

    format!("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><title>道体·玄盾 安全{type_label}</title><style>body{{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px;color:#333}}h1{{color:#4ecdc4;border-bottom:2px solid #4ecdc4;padding-bottom:8px}}h2{{color:#45b7d1;margin-top:24px}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid #ddd;padding:8px;font-size:13px;text-align:left}}th{{background:#f5f5f5}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}.item{{background:#f9f9f9;padding:12px;border-radius:8px;text-align:center}}.val{{font-size:24px;font-weight:700;color:#4ecdc4}}.lbl{{font-size:12px;color:#999}}.footer{{margin-top:32px;padding-top:12px;border-top:1px solid #ddd;font-size:12px;color:#999}}</style></head><body><h1>道体·玄盾 安全{type_label}</h1><p>报告周期：{} 至 {} | 生成时间：{}</p><h2>1. 概要摘要</h2><div class=\"grid\"><div class=\"item\"><div class=\"val\">{}</div><div class=\"lbl\">总请求数</div></div><div class=\"item\"><div class=\"val\" style=\"color:#ff6b6b\">{}</div><div class=\"lbl\">拦截次数</div></div><div class=\"item\"><div class=\"val\">{:.1}%</div><div class=\"lbl\">拦截率</div></div><div class=\"item\"><div class=\"val\">{}</div><div class=\"lbl\">放行次数</div></div></div><h2>2. 攻击类型分布</h2>{}<table><thead><tr><th>攻击类型</th><th>拦截量</th><th>占比</th></tr></thead><tbody>{}</tbody></table><h2>3. 代表性拦截样本</h2><table><thead><tr><th>文本摘要</th><th>攻击分类</th><th>拦截阶段</th></tr></thead><tbody>{}</tbody></table><div class=\"footer\"><p>本报告由道体·玄盾自动生成 | SPDX-License-Identifier: DaoTi-Research-1.0</p></div></body></html>",
        &start[..10], &end[..10], &now,
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
    let _ = engine_post(&engine_url, "/notifiers/config", body).await;
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

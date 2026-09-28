// SPDX-License-Identifier: DaoTi-Research-1.0
// Copyright (c) 2026 独立研究者，知白
// 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
//
// 个人版 Tauri 后端 — 命令实现 + 引擎 Sidecar 生命周期管理
//
// 架构：
//   React 前端
//      │ invoke(Tauri IPC)
//      ▼
//   本文件（HTTP 转发到本地 Python 代理 127.0.0.1:18765）
//      │ HTTP
//      ▼
//   Python FastAPI 代理（personal/src/daoti_xuandun_personal/proxy/app.py）
//      │
//      ├─ 【第一层】sanitizer.py 请求侧脱敏
//      ├─ 【第二层】verifier.py  响应侧完整性验证
//      ├─ 【第三层】restorer.py  脱敏内容恢复
//      └─ 转发到第三方中转站
//
// 设计约束：
//   1. 引擎只监听 127.0.0.1，不对外暴露
//   2. 前端永远拿不到 API Key 明文（后端只在保存时接收）
//   3. 引擎崩溃时前端显示"代理未运行"，而非静默放行

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, WindowEvent};
use tokio::time::timeout;

pub mod license;
pub mod tray;

use license::LicenseStatus;
use tray::TrayController;

// ══════════════════════════════════════════════════════════════
// 常量
// ══════════════════════════════════════════════════════════════

/// 本地代理默认端口（仅本机监听，★ 安全底线：绝不监听 0.0.0.0）
const DEFAULT_PROXY_PORT: u16 = 18765;

/// HTTP 请求超时（前端侧）
const REQ_FAST: Duration = Duration::from_secs(5);
const REQ_NORMAL: Duration = Duration::from_secs(15);

/// 引擎启动等待上限
const ENGINE_WAIT_TOTAL: Duration = Duration::from_secs(60);
const ENGINE_PHASE1_STEPS: u32 = 20; // 20 × 500ms = 10s（快速响应）
const ENGINE_PHASE1_INTERVAL: Duration = Duration::from_millis(500);
const ENGINE_PHASE2_STEPS: u32 = 50; // 50 × 1s = 50s（Nuitka onefile 自解压）
const ENGINE_PHASE2_INTERVAL: Duration = Duration::from_secs(1);

/// 连续失败达到此值判定引擎永久失效
const ENGINE_MAX_FAILURES: u32 = 5;

// ══════════════════════════════════════════════════════════════
// 代理端口解析
// ══════════════════════════════════════════════════════════════

/// 从 Python 侧配置文件读出监听端口。
///
/// 为什么需要读配置（★ P1-10）：
///   端口在产品文档 4.4 中是用户可配置项（默认 18765，用于解决端口冲突）。
///   若 Rust 侧把 18765 写死，用户改端口后引擎会按新端口监听，
///   而桌面端仍连 18765 → 全盘失联，且用户无从判断原因。
///
/// 注意：本函数只在进程启动时调用一次（见 lock_proxy_port），不热重读。
/// 读取失败回退默认端口：配置文件不存在是正常情况（首次运行）。
fn proxy_port() -> u16 {
    let base = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join(".config")
        })
        .join("com.daoti.xuandun-personal")
        .join("config.json");

    let Ok(text) = std::fs::read_to_string(&base) else {
        return DEFAULT_PROXY_PORT;
    };

    // ★ 必须与 Python 侧 config.load() 对同一份文件得出相同结论。
    //   Python: ServerConfig(**raw["server"]) —— 字段类型不符会抛 TypeError，
    //           捕获后回退「整个默认配置」（含端口 18765）。
    //   若这里用字符串扫描提取数字，"port": "19999"（字符串）会被解析成 19999，
    //   而 Python 回退到 18765 → 两侧端口不一致 → 桌面端连不上引擎，且无从恢复。
    //   故此处只接受 JSON 数字类型的 port，其余一律回退默认。
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return DEFAULT_PROXY_PORT;
    };
    v.get("server")
        .and_then(|s| s.get("port"))
        .and_then(|p| p.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p >= 1024)
        .unwrap_or(DEFAULT_PROXY_PORT)
}

/// 本轮进程内实际生效的端口。
///
/// ★ 关键设计：不能每次请求都重读配置。
///   场景：用户在设置页把端口从 18765 改成 18800，配置立即落盘，
///   但引擎仍监听 18765（监听端口在进程启动时确定，不热生效）。
///   若此时 proxy_call 改去连 18800 → 永远连不上 → 用户彻底失联，
///   连「改回旧端口」这个自救操作都做不到（所有请求都发往错误端口）。
///   正确做法：进程启动时锁定一个端口，本进程内始终用它；
///   用户重启应用后自然读到新端口。
static ACTIVE_PORT: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

/// 锁定本进程使用的代理端口（首次调用时读配置，之后不变）
pub fn lock_proxy_port() -> u16 {
    *ACTIVE_PORT.get_or_init(proxy_port)
}

/// 本地代理基础地址（使用本进程锁定的端口）
fn proxy_base() -> String {
    format!("http://127.0.0.1:{}", lock_proxy_port())
}

// ══════════════════════════════════════════════════════════════
// 激活
// ══════════════════════════════════════════════════════════════
//
// 具体的机器码采集、状态存储、时钟回拨逻辑都在 license.rs，
// 这里只做「调引擎验签 + 编排 + 暴露 Tauri 命令」。

/// 调引擎的 /api/license/verify（真实验签在引擎侧）。
///
/// ★ 不再传 machine_code —— 引擎自己采集。
///   旧契约是「Rust 采集 → 传给引擎」，那份采集既不稳定
///   （取磁盘卷标，插拔硬盘就变）又与签发工具算法漂移，
///   线上表现为「按界面机器码申请的码激活失败」。
async fn engine_verify(app: &tauri::AppHandle, code: &str) -> Result<license::VerifyOutcome, String> {
    ensure_engine_running(app).await?;
    let body = serde_json::json!({
        "code": code,
        "now": license::now_unix(),
    });
    let v = proxy_call(
        reqwest::Method::POST,
        "/api/license/verify",
        Some(body),
        REQ_NORMAL,
    )
    .await?;
    serde_json::from_value(v).map_err(|e| format!("验签结果解析失败: {e}"))
}

/// 向引擎索取本机机器码（哈希形式）。
///
/// ★ 引擎不可达时返回空串。此时界面显示「暂时无法确认激活状态」，
///   而不是给一个错误的机器码 —— 后者会让用户拿它去申请，
///   结果必然不匹配，而报错还会指向完全错误的方向。
pub async fn machine_code_via_engine() -> String {
    let v = match proxy_call(
        reqwest::Method::GET,
        "/api/license/machine_code",
        None,
        REQ_NORMAL,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    v.get("machineCode")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

/// 组装对外的激活状态。
///
/// ★ 每次都重新验签，不只读磁盘上的字段：
///   攻击者改掉 license.json 里的 expires_at 就能绕过「只读盘」的检查。
async fn build_license_status(app: &tauri::AppHandle) -> LicenseStatus {
    // ★ machine_code() 返回的已经是哈希，不要再哈希一次。
    let mch = license::machine_code().await;
    let now = license::now_unix();
    let st = license::load();

    if st.code.is_empty() {
        return LicenseStatus::inactive("尚未激活", mch);
    }

    // 时钟回拨检测。
    //
    // ★ 这里查它**不是为了「双侧校验」**——AI 流量不经过 Rust，
    //   这段代码只影响 UI 显示的状态，不是流量路径上的关卡。
    //   真正在流量路径上做判定的是引擎的 _protection_enabled()。
    //   这里查的实质价值是：用户看到的状态与引擎一致，
    //   不会出现「界面说已激活、引擎却在只读」这种自相矛盾。
    if let Err(msg) = license::check_clock_rollback(
        if st.last_seen > 0 { Some(st.last_seen) } else { None },
        now,
    ) {
        return LicenseStatus {
            activated: false,
            expires_at: None,
            tier: None,
            subject: None,
            jti: None,
            reason: Some(msg.to_string()),
            machine_code: mch,
            remaining_days: 0,
            verifier_available: true,
        };
    }

    match engine_verify(app, &st.code).await {
        Ok(o) if o.ok => LicenseStatus {
            activated: true,
            expires_at: o.exp,
            tier: o.tier,
            subject: o.subject,
            jti: o.jti,
            reason: None,
            machine_code: mch,
            remaining_days: o.exp.map(|e| (e - now) / 86400).unwrap_or(0),
            verifier_available: o.verifier_available,
        },
        Ok(o) => LicenseStatus {
            activated: false,
            expires_at: None,
            tier: None,
            subject: None,
            jti: None,
            reason: o.message.or_else(|| Some("激活码无效".into())),
            machine_code: mch,
            remaining_days: 0,
            verifier_available: o.verifier_available,
        },
        // ★ 引擎不可达时**不能**当成「已激活」，也不能当成「未激活」——
        //   必须如实报「暂时无法确认」，否则会出现两种谎报：
        //   谎报已激活 = 白嫖；谎报未激活 = 引擎一抖动用户就被要求重激活。
        Err(e) => LicenseStatus {
            activated: false,
            expires_at: None,
            tier: None,
            subject: None,
            jti: None,
            reason: Some(format!("暂时无法确认激活状态：{e}")),
            machine_code: mch,
            remaining_days: 0,
            verifier_available: false,
        },
    }
}

// ══════════════════════════════════════════════════════════════
// Tauri 命令：激活
// ══════════════════════════════════════════════════════════════

/// 查询激活状态。
#[tauri::command]
async fn get_license_status(app: tauri::AppHandle) -> LicenseStatus {
    build_license_status(&app).await
}

/// 提交激活码。
#[tauri::command]
async fn activate_license(app: tauri::AppHandle, code: String) -> Result<LicenseStatus, String> {
    let trimmed = code.trim().to_string();
    if trimmed.is_empty() {
        return Err("请输入激活码".into());
    }

    let outcome = engine_verify(&app, &trimmed).await?;
    if !outcome.ok {
        // 验签组件不可用 ≠ 码无效，必须分开说，
        // 否则用户会反复换码却永远激活不了。
        if !outcome.verifier_available {
            return Err(outcome.message.unwrap_or_else(|| "激活校验组件不可用".into()));
        }
        return Err(outcome.message.unwrap_or_else(|| "激活码无效".into()));
    }

    license::save(&license::LicenseState {
        code: trimmed,
        last_seen: license::now_unix(),
    })?;

    Ok(build_license_status(&app).await)
}

/// 清除激活信息（换机或售后重置时用）。
#[tauri::command]
async fn clear_license(app: tauri::AppHandle) -> Result<LicenseStatus, String> {
    let _ = std::fs::remove_file(license::license_file());
    Ok(build_license_status(&app).await)
}

/// 换绑请求串（用户换电脑后发给售后即可完成换绑）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RebindRequest {
    /// XDRB.<base64url(json)>，整段发给售后
    request: String,
    /// 本机机器码哈希（报障时可直接发这一段）
    machine_code_hash: String,
}

/// 生成换绑请求串。
///
/// ★ 为什么是「客户端生成、售后重签」而不是纯自助：
///   一码一机意味着新机必然验不过（码里绑的是旧机器），
///   而新机上没有任何东西能证明「我拥有这张码」——除了签名本身。
///   所以只要把「原码 + 新机器码」交给售后，售后验签后改机器码重签。
#[tauri::command]
async fn build_rebind_request(app: tauri::AppHandle, code: String) -> Result<RebindRequest, String> {
    ensure_engine_running(&app).await?;
    let trimmed = code.trim().to_string();
    if trimmed.is_empty() {
        return Err("请先填写原激活码".into());
    }
    let body = serde_json::json!({
        "code": trimmed,
    });
    let v = proxy_call(
        reqwest::Method::POST,
        "/api/license/rebind_request",
        Some(body),
        REQ_NORMAL,
    )
    .await?;
    serde_json::from_value(v).map_err(|e| format!("换绑请求串生成失败: {e}"))
}

// ══════════════════════════════════════════════════════════════
// 引擎状态
// ══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct EngineStatus {
    pub running: bool,
    pub healthy: bool,
    pub startup_error: Option<String>,
    pub started_at: Option<u64>, // Unix 秒
    pub last_check: Option<u64>,
}

impl Default for EngineStatus {
    fn default() -> Self {
        Self {
            running: false,
            healthy: false,
            startup_error: None,
            started_at: None,
            last_check: None,
        }
    }
}

pub struct EngineState {
    status: parking_lot::Mutex<EngineStatus>,
    child: parking_lot::Mutex<Option<Child>>,
    pid: parking_lot::Mutex<Option<u32>>,
    /// 用户主动停止引擎的意图位。
    ///
    /// ★ 没有它就无法区分「引擎挂了，该自动拉起」和「用户主动停了，别拉起」：
    ///   两者都是 `running == false` + health 探测失败。
    ///   若一律自动重启，用户点了停止也会被立刻复活 —— 托盘转瞬回绿，
    ///   「防护已停」这个事实只存在了不到一秒。
    user_stopped: std::sync::atomic::AtomicBool,
    /// 启动/停止引擎的互斥锁。
    ///
    /// ★★ 只保护「决策 + 拉起」这个临界区，**不保护健康等待**。
    ///   曾经的回归（勿改回）：
    ///   原实现让 ensure_engine_running 全程持锁，而它内部有最长
    ///   60s 的渐进式健康等待。而全部 19 个命令都先调 ensure，
    ///   于是首页一次加载（get_state + get_stats + get_logs）会把
    ///   三个请求完全串行化，引擎故障时各等 60s ——
    ///   用「修双拉起的锁」制造了比原 bug 更严重的队头阻塞。
    ///
    ///   现在改为：持锁只做「判断 + spawn」，等就绪在锁外进行；
    ///   并发调用方靠 starting 标志避免重复 spawn（等同一个引擎就绪）。
    lifecycle: tokio::sync::Mutex<()>,

    /// 是否正处在「拉起后等待就绪」的阶段。
    ///
    /// ★ 与 lifecycle 锁配套：锁保证同一时刻只有一个 spawn，
    ///   本标志保证后来者知道「已经有人在拉了，直接等就行」，
    ///   而不是自己也去 spawn 一个抢端口。
    starting: std::sync::atomic::AtomicBool,
}

// Drop 时回收子进程（避免孤儿进程）
impl Drop for EngineState {
    fn drop(&mut self) {
        // 锁顺序与 stop_engine 保持一致（pid → child），避免潜在死锁
        let pid = *self.pid.lock();
        if let Some(mut child) = self.child.lock().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // 兜底：kill() 对 Nuitka 引擎无效（实测），必须按 pid 强杀，
        // 否则应用崩溃/被强杀时会留下监听 18765 的孤儿引擎。
        if let Some(p) = pid {
            for _ in 0..10 {
                if !process_alive(p) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            kill_cmd("/T", "/F", p);
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HTTP 客户端（共享连接池）
// ══════════════════════════════════════════════════════════════

fn http_client(timeout_s: u64) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_s))
        // ★ 安全：个人版代理只应被本机访问，禁止跟随重定向到外部
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP 客户端创建失败: {e}"))
}

/// 托盘菜单等内部逻辑用的简化 POST（字符串 body，无返回值消费）
pub async fn post_local(
    app: &tauri::AppHandle,
    path: &str,
    body: &str,
) -> Result<(), String> {
    ensure_engine_running(app).await?;
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    proxy_call(reqwest::Method::POST, path, Some(v), REQ_NORMAL).await?;
    Ok(())
}

/// 真正退出：停引擎 + 退进程。
/// 与「关闭窗口」的区分至关重要 —— 关闭窗口只隐藏，托盘常驻继续防护。
pub fn shutdown<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    // ★ 必须用 taskkill 强杀，不能只 child.kill()：
    //   实测 Nuitka 引擎用 Child::kill() 杀不掉，会留下监听 18765 的孤儿进程。
    //
    // ★★ 顺序必须是「先 taskkill，再谈 child」：
    //   原来先 child.kill() + child.wait()，而 wait() 是**阻塞**的，
    //   且发生在 taskkill 兜底之前。于是当 kill() 无效（正是本文件的
    //   实测结论）时，主线程会无限期卡在这里 —— 而唯一有效的
    //   taskkill 因为写在其后，永远得不到执行机会。
    //   后果：应用整体假死，用户连「退出」都做不到。
    //
    //   故改为：先在后台线程做「确认存活 → taskkill」，
    //   主线程只做非阻塞的 child.kill() 且**不 wait()**
    //   （进程即将退出，wait 的语义由后台线程的存活轮询覆盖）。
    let pid = app
        .try_state::<EngineState>()
        .and_then(|s| *s.pid.lock());

    // 取 child 也要小心：此处不能跨 .await（没有 await，但要避免守卫过长存活）
    if let Some(mut child) = app
        .try_state::<EngineState>()
        .and_then(|s| s.child.lock().take())
    {
        let _ = child.kill();
        // ★ 不调 child.wait()：它会阻塞调用线程（UI 线程），
        //   而本文件多处注释已确认 kill() 对该引擎无效 → 必然空等。
    }

    if let Some(p) = pid {
        std::thread::spawn(move || {
            for _ in 0..10 {
                if !process_alive(p) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            // 唯一有效的手段：杀进程树
            kill_cmd("/T", "/F", p);
        });
    }
    app.exit(0);
}

/// 跨平台强杀进程树
#[cfg(target_os = "windows")]
fn kill_cmd(flag_tree: &str, flag_force: &str, pid: u32) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), flag_tree, flag_force])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(target_os = "windows"))]
fn kill_cmd(_flag_tree: &str, _flag_force: &str, pid: u32) {
    let _ = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// 调用本地代理 API（GET/POST/PUT/DELETE）
async fn proxy_call(
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
    tmo: Duration,
) -> Result<serde_json::Value, String> {
    let client = http_client(tmo.as_secs().max(5))?;
    let url = format!("{}{path}", proxy_base());

    let mut req = client.request(method, &url);
    if let Some(b) = body {
        req = req.json(&b);
    }

    let fut = req.send();
    let resp = timeout(tmo, fut)
        .await
        .map_err(|_| format!("本地代理请求超时（{}s）", tmo.as_secs()))?
        .map_err(|e| format!("无法连接本地代理: {e}"))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        // 尽量提取后端 detail
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(detail) = v.get("detail") {
                let msg = match detail {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                return Err(msg);
            }
        }
        return Err(format!("本地代理返回 HTTP {status}"));
    }

    if text.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(&text).map_err(|e| format!("响应解析失败: {e}"))
}

// ══════════════════════════════════════════════════════════════
// 引擎健康检查 + 生命周期
// ══════════════════════════════════════════════════════════════

async fn check_engine_health() -> bool {
    let Ok(client) = http_client(2) else {
        return false;
    };
    let health_url = format!("{}/health", proxy_base());
    let Ok(Ok(resp)) = timeout(Duration::from_secs(2), client.get(health_url).send()).await
    else {
        return false;
    };
    resp.status().is_success()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 定位引擎可执行文件。
///
/// ★ 打包后用户机器上没有 Python，必须优先用随包分发的独立引擎；
///   找不到时才回退到系统 Python（开发模式）。
///
/// 返回 (可执行文件, 是否需要 `-m 包名` 参数)。
fn resolve_engine() -> Option<(std::path::PathBuf, bool)> {
    // ① 随包资源目录（Tauri 把 bundle.resources 放在可执行文件同级）
    //    开发模式下该目录不存在，自然跳过。
    if let Ok(dir) = std::env::current_exe() {
        if let Some(parent) = dir.parent() {
            let res_dir = parent.join("resources").join("engine");
            if let Ok(entries) = std::fs::read_dir(&res_dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with("xuandun-engine-") {
                        let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
                        if name.ends_with(ext) {
                            return Some((e.path(), false));
                        }
                    }
                }
            }
        }
    }

    // ② 开发模式：系统 Python
    for exe in ["python", "python3"] {
        if which(exe) {
            return Some((std::path::PathBuf::from(exe), true));
        }
    }
    None
}

/// 极简 which：只查 PATH，不引入依赖
fn which(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    let exts: Vec<String> = if cfg!(target_os = "windows") {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT".into())
            .split(';')
            .map(|s| s.to_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in path.split(if cfg!(target_os = "windows") { ';' } else { ':' }) {
        if dir.is_empty() {
            continue;
        }
        for ext in &exts {
            let p = std::path::Path::new(dir).join(format!("{name}{ext}"));
            if p.is_file() {
                return true;
            }
        }
    }
    false
}

/// 启动引擎进程（跨平台）
fn start_engine_process(app: &tauri::AppHandle) -> Result<u32, String> {
    // Windows CREATE_NO_WINDOW 标志（0x08000000）：隐藏引擎的 console 窗口。
    // 直接写 `std::os::windows::process::CommandExt::CREATE_NO_WINDOW` 会报
    // "expected a type, found a trait"（它是 trait 而非类型），故用字面量常量。
    #[cfg(target_os = "windows")]
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Some((exe, need_module)) = resolve_engine() else {
        return Err(
            "未找到引擎：安装包可能损坏（缺少 resources/engine），\
             或系统未安装 Python（仅开发模式需要）"
                .to_string(),
        );
    };

    let port = lock_proxy_port();
    let mut cmd = Command::new(&exe);
    if need_module {
        cmd.args(["-m", "daoti_xuandun_personal.proxy.app"]);
    }
    cmd.args([
        "--port",
        // ★ P1-10：必须传本进程锁定的端口，与 proxy_base() 保持一致，
        //   否则会出现「引擎听 A 端口、桌面端连 B 端口」的双向失联
        &port.to_string(),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    // 冻结后的引擎需要 DLL 搜索路径指向自身目录（standalone 模式下
    // Nuitka 会把 python3xx.dll 等放在 exe 同级）
    .current_dir(
        exe.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from(".")),
    )
    .env("PYTHONUNBUFFERED", "1")
    .env("PYTHONIOENCODING", "utf-8");

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    {
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return Err(format!("启动引擎 {exe:?} 失败: {e}")),
        };
        let pid = child.id();

        // ★ 必须消费 stdout/stderr，否则管道缓冲区满会导致引擎挂起
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader};
                for line in BufReader::new(stdout).lines().map_while(Result::ok).take(200) {
                    eprintln!("[engine] {line}");
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader};
                for line in BufReader::new(stderr).lines().map_while(Result::ok).take(200) {
                    eprintln!("[engine:err] {line}");
                }
            });
        }

        let state = app.state::<EngineState>();
        let mut child_guard = state.child.lock();
        *child_guard = Some(child);
        drop(child_guard);
        *state.pid.lock() = Some(pid);
        Ok(pid)
    }
}

/// 停止引擎（自行获取 lifecycle 锁）。
async fn stop_engine(app: &tauri::AppHandle) {
    // 与 ensure_engine_running 互斥：否则「停止」与「拉起」交错，
    // 会出现 stop 刚杀掉进程、ensure 又拉起一个，或反之 ——
    // 两种顺序下 state.pid 都可能指向已死进程。
    //
    // ★ 必须先把 State 绑定到具名变量：app.state::<T>() 返回的是
    //   临时值，守卫借用它，语句结束即析构 → 编译期 E0716。
    let state = app.state::<EngineState>();
    let _guard = state.lifecycle.lock().await;
    stop_engine_locked(app).await
}

/// 停止引擎（调用方必须已持有 lifecycle 锁）。
///
/// ★ 拆成两个函数是因为锁不可重入：
///   restart_engine 需要「先停后起」的原子性，若它先调 stop_engine
///   （拿锁→放锁）再调 ensure_engine_running（再拿锁），两者之间
///   存在一个窗口：健康监控可能抢进来把引擎拉起，
///   于是 restart 变成「停→被别人拉起→再停→再拉起」，
///   pid 归属在窗口期里可能错乱。
///   故 restart 走 restart_engine_locked，全程持锁。
async fn stop_engine_locked(app: &tauri::AppHandle) {
    // 先取 pid 再取 child：kill 失败时仍能用 pid 兜底
    let pid = *app.state::<EngineState>().pid.lock();

    if let Some(mut child) = app.state::<EngineState>().child.lock().take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    // ★ 必须确认引擎真的退出了。
    //   实测：Nuitka 引擎用 Child::kill() 杀不掉（进程仍在、端口仍监听），
    //   而 taskkill /T /F 有效。若不在此确认，会留下监听 18765 的孤儿进程。
    if let Some(p) = pid {
        force_kill_engine(p).await;
    }

    {
        let state = app.state::<EngineState>();
        // 记下「用户主动停止」：否则下一次 API 调用会走 ensure_engine_running
        // 把引擎重新拉起，用户点的停止等于没点。
        state.user_stopped.store(true, std::sync::atomic::Ordering::SeqCst);
        *state.pid.lock() = None;
        let mut st = state.status.lock();
        st.running = false;
        st.healthy = false;
    }

    // 用户主动停止 = 防护失效，托盘必须立刻转灰
    if let Some(ctrl) = app.try_state::<TrayController>() {
        ctrl.force_paused(&app);
    }
}

/// 强制结束引擎进程（先常规终止，必要时强杀进程树）
async fn force_kill_engine(pid: u32) {
    for _ in 0..10 {
        if !process_alive(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // 仍未退出 → 强杀进程树
    kill_cmd("/T", "/F", pid);
}

/// 进程是否仍存活。
///
/// ★ 不用 `tasklist /FI "PID eq N"` —— 该过滤器作为独立参数传递时会被拆分，
///   tasklist 报「无效的参数」并返回空输出，导致判定恒为「已退出」。
///   改为拉全量列表（tasklist /NH）后按行首第二列比对 PID。
#[cfg(target_os = "windows")]
fn process_alive(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Ok(o) = Command::new("tasklist")
        .arg("/NH")
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return true; // 查不到就保守认为还活着
    };

    let text = String::from_utf8_lossy(&o.stdout);
    // 行格式："xuandun-engine-amd64-pc-windows-msvc.exe   24580 Console ..."
    text.lines().any(|line| {
        line.split_whitespace()
            .nth(1)
            .and_then(|p| p.parse::<u32>().ok())
            == Some(pid)
    })
}

#[cfg(not(target_os = "windows"))]
fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// 确保引擎运行（必要时启动，并等待就绪）。
///
/// ★ 并发模型（关键，勿简化）：
///   lifecycle 锁只保护「判断 + spawn」这一小段临界区，
///   最长 60s 的就绪等待在**锁外**进行。
///   否则 19 个命令各自先调 ensure，首页一次加载的三个并发请求
///   会被完全串行化、引擎故障时各等 60s —— 那是更严重的队头阻塞。
///
///   不重复 spawn 靠两件事协作：
///     · 锁保证同一时刻只有一个执行者能走到 spawn
///     · starting 标志让后来的执行者知道「已有人在拉」，转为等待
async fn ensure_engine_running(app: &tauri::AppHandle) -> Result<(), String> {
    // 第一段：持锁做「快速路径 + 决定是否 spawn」
    {
        let state = app.state::<EngineState>();
        let _guard = state.lifecycle.lock().await;

        // ★ 用户主动停止过 → 不再自动拉起（见 ensure_engine_running_locked）
        if state
            .user_stopped
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("本地代理已被手动停止，请先在设置中重新启动".to_string());
        }

        // 已在运行且健康 → 直接返回
        // parking_lot 守卫非 Send，必须在 await 前显式释放
        let running = state.status.lock().running;
        if running && check_engine_health().await {
            return Ok(());
        }

        // 端口上的引擎已就绪（外部引擎，或我们拉起但 status 滞后）
        if check_engine_health().await {
            let mut st = state.status.lock();
            st.running = true;
            st.healthy = true;
            if st.started_at.is_none() {
                st.started_at = Some(unix_now());
            }
            st.startup_error = None;
            return Ok(());
        }

        // 已经有人在拉起 → 不重复 spawn，交给下面的等待段
        if state.starting.load(std::sync::atomic::Ordering::SeqCst) {
            // 释放锁后进入等待段
        } else {
            // 启动新进程（持锁，保证只有一个 spawn）
            if let Err(e) = start_engine_process(app) {
                let st = &mut *state.status.lock();
                st.startup_error = Some(format!("引擎启动失败: {e}"));
                return Err(format!("引擎启动失败: {e}"));
            }
            {
                let mut st = state.status.lock();
                st.running = true;
                st.started_at = Some(unix_now());
                st.startup_error = None;
            }
            state.starting.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    // 第二段：锁外等待就绪（最长 60s），不阻塞其他请求的快速路径
    let ok = wait_engine_ready().await;

    // 无论成败都要清标志，否则引擎之后彻底失去自动拉起能力
    let state = app.state::<EngineState>();
    state.starting.store(false, std::sync::atomic::Ordering::SeqCst);

    if ok {
        let mut st = state.status.lock();
        st.healthy = true;
        st.last_check = Some(unix_now());
        Ok(())
    } else {
        let msg = "引擎在 60 秒内未就绪".to_string();
        state.status.lock().healthy = false;
        state.status.lock().startup_error = Some(msg.clone());
        Err(msg)
    }
}

/// 渐进式等待引擎就绪（调用方不得持有 lifecycle 锁）。
///
/// 为什么要两段式等待：Nuitka onefile 首次启动需自解压，实测 10~50s。
/// 单段 500ms×20 覆盖快速场景，长等待留给自解压。
///
/// 不需要 AppHandle：就绪与否只取决于健康探测，不涉及任何状态读写
/// （状态由调用方在等待结束后统一更新）。
async fn wait_engine_ready() -> bool {
    let start = Instant::now();
    for (steps, interval) in [
        (ENGINE_PHASE1_STEPS, ENGINE_PHASE1_INTERVAL),
        (ENGINE_PHASE2_STEPS, ENGINE_PHASE2_INTERVAL),
    ] {
        for _ in 0..steps {
            if start.elapsed() > ENGINE_WAIT_TOTAL {
                return false;
            }
            if check_engine_health().await {
                return true;
            }
            tokio::time::sleep(interval).await;
        }
    }
    false
}

/// 后台健康监控循环
fn spawn_health_monitor(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut fail_streak: u32 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let running = app
                .try_state::<EngineState>()
                .map(|s| s.status.lock().running)
                .unwrap_or(false);

            // ★ 用户主动停止过 → 引擎状态一律按「不可用」处理。
            //   这一分支必须排在 health 探测之前：实测 stop_engine 后
            //   端口仍短暂可连，healthy 会被误判为 true，
            //   托盘刚转灰就又回绿，「防护已停」只存在了几秒。
            let user_stopped = app
                .try_state::<EngineState>()
                .map(|s| s.user_stopped.load(std::sync::atomic::Ordering::SeqCst))
                .unwrap_or(false);
            if user_stopped {
                if let Some(ctrl) = app.try_state::<TrayController>() {
                    if !ctrl.is_paused() {
                        ctrl.force_paused(&app);
                    }
                }
                continue;
            }

            let healthy = check_engine_health().await;

            if healthy {
                fail_streak = 0;
                if let Some(state) = app.try_state::<EngineState>() {
                    let mut st = state.status.lock();
                    st.healthy = true;
                    st.last_check = Some(unix_now());
                }
                // ★ 引擎「活着」不等于「在防护」：暂停到期自动恢复、或用户绕过
                //   桌面端直接调引擎 API 暂停时，托盘必须跟着变。
                //   这里由 Rust 独立同步，不依赖前端是否停在 Dashboard ——
                //   托盘是「唯一感知通道」，不能挂在某个页面的生命周期上。
                //
                //   恢复条件统一为「引擎可用且未暂停」：灰态只有两个来源
                //   （引擎故障 / 用户暂停），两者的恢复都指向这个条件。
                if let Some(ctrl) = app.try_state::<TrayController>() {
                    if is_engine_paused().await == Some(true) {
                        if !ctrl.is_paused() {
                            ctrl.set_steady(&app, "paused", "防护已暂停");
                        }
                    } else if ctrl.is_paused() {
                        ctrl.set_steady(&app, "safe", "防护运行中");
                    }
                }
                continue;
            }

            if !running {
                // 引擎未运行（用户可能主动关闭）→ 托盘转灰
                // ★ 关键：不能静默。防护失效时用户必须看得见灰态，
                //   否则「透明防火墙」会退化成「静默失效的防火墙」。
                if let Some(ctrl) = app.try_state::<TrayController>() {
                    ctrl.force_paused(&app);
                }
                continue;
            }

            fail_streak += 1;

            // 前 2 次不重启（允许自愈）
            if fail_streak <= 2 {
                continue;
            }

            if fail_streak >= ENGINE_MAX_FAILURES {
                if let Some(state) = app.try_state::<EngineState>() {
                    let mut st = state.status.lock();
                    st.running = false;
                    st.healthy = false;
                    st.startup_error =
                        Some("引擎连续多次无响应".to_string());
                }
                if let Some(ctrl) = app.try_state::<TrayController>() {
                    ctrl.force_paused(&app);
                }
                let _ = app.emit("engine-unavailable", "引擎无响应");

                // ★★ 这里原来 break，直接终止整个健康监控循环。
                //   三个问题叠加，构成「静默失效」：
                //     ① spawn_health_monitor 只在 setup 里启动一次，
                //        break 之后**再无任何自动恢复**
                //     ② 只清了 status，pid 残留 → ensure 的 pid 归属
                //        判断会误以为「自己拉起的引擎还活着」
                //     ③ 残留进程可能仍占用 18765，挡住后续任何重启
                //   对安全产品而言，看门狗自己躺下 = 防护静默消失。
                //
                //   改为：彻底清理（杀进程 + 清 pid）+ 退避后继续监控。
                //   引擎出故障时最需要的就是有人一直盯着。
                {
                    let state2 = app.state::<EngineState>();
                    let _guard = state2.lifecycle.lock().await;
                    stop_engine_locked(&app).await;
                }
                // 退避 60s 再试，避免疯狂重启刷屏；不 break，监控继续。
                fail_streak = 0;
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }

            // 尝试重启
            // ★ 必须整段持锁：原来这里是 stop_engine（自己拿锁再放）
            //   然后裸调 start_engine_process（不持锁），
            //   两步之间存在窗口 —— 并发的 ensure 会看到引擎已停而
            //   自己也去拉起，于是和这里的 spawn 撞车抢端口。
            //   这正是「两个引擎 + Errno 10048 + pid 指向死进程」
            //   那条链路的起点。
            let app2 = app.clone();
            {
                let state2 = app2.state::<EngineState>();
                let _guard = state2.lifecycle.lock().await;
                stop_engine_locked(&app2).await;
                state2
                    .user_stopped
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                if let Err(e) = start_engine_process(&app2) {
                    eprintln!("[XuanDun Personal] 引擎自动重启失败: {e}");
                    if let Some(ctrl) = app2.try_state::<TrayController>() {
                        ctrl.force_paused(&app2);
                    }
                    continue;
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            if check_engine_health().await {
                fail_streak = 0;
                if let Some(state) = app.try_state::<EngineState>() {
                    let mut st = state.status.lock();
                    st.running = true;
                    st.healthy = true;
                    st.started_at = Some(unix_now());
                    st.startup_error = None;
                }
            }
        }
    });
}

// ══════════════════════════════════════════════════════════════
// 托盘瞬时脉冲监控
// ══════════════════════════════════════════════════════════════

/// 轮询最新日志，发现「新增的高危阻断」时触发托盘红色脉冲。
///
/// 为什么需要它（产品定位：透明防火墙）：
///   用户对中转站返回了什么完全无感。文档 3.1 写的「在 AI 工具旁边显示状态点」
///   在透明代理架构下不可实现（无法控制第三方工具的 UI）。
///   托盘是唯一可行的感知通道 —— 但若只靠前端轮询今日统计，
///   红色会一直亮到第二天，用户分不清「刚被攻击」和「今天有过攻击」。
///   所以由 Rust 侧独立轮询日志增量，精确捕捉「刚刚发生」。
///
/// 增量判定用 (count, latest_id) 元组：
///   只看 count 会在同日多次「删日志」后误判为新增；
///   只看 latest_id 在并发写入时可能漏。
fn spawn_tray_pulse_monitor(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        // 首次采样只建立基线，不触发脉冲（否则启动即误报）
        let mut seen: Option<(u64, u64)> = None;

        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;

            if !check_engine_health().await {
                continue;
            }

            let Ok(v) = proxy_call(
                reqwest::Method::GET,
                "/api/logs?limit=1&action=block",
                None,
                REQ_FAST,
            )
            .await
            else {
                continue;
            };

            let total = v.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
            let latest_id = v
                .get("entries")
                .and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .and_then(|e| e.get("id"))
                .and_then(|x| x.as_u64())
                .unwrap_or(0);

            let Some(prev) = seen else {
                seen = Some((total, latest_id));
                continue;
            };

            let (prev_total, prev_latest) = prev;
            let grew = total > prev_total || (total > 0 && latest_id > prev_latest);
            seen = Some((total, latest_id));

            if !grew {
                continue;
            }

            // 取最新阻断日志的摘要作为脉冲文案
            let summary = v
                .get("entries")
                .and_then(|x| x.as_array())
                .and_then(|a| a.first())
                .and_then(|e| e.get("summary"))
                .and_then(|x| x.as_str())
                .unwrap_or("检测到危险响应")
                .to_string();

            if let Some(ctrl) = app.try_state::<TrayController>() {
                ctrl.pulse(&app, &summary);
            }
        }
    });
}

// ══════════════════════════════════════════════════════════════
// Tauri 命令（前端 IPC）
// ══════════════════════════════════════════════════════════════

#[tauri::command]
async fn get_engine_status(app: tauri::AppHandle) -> Result<EngineStatus, String> {
    ensure_engine_running(&app).await.ok();
    let state = app.state::<EngineState>();
    let snapshot = state.status.lock().clone();
    Ok(snapshot)
}

#[tauri::command]
async fn restart_engine(app: tauri::AppHandle) -> Result<(), String> {
    // ★ 全程持锁，让「停 + 起」成为一次原子操作。
    //   若分两次加锁（stop 一次、ensure 一次），中间会有窗口让
    //   健康监控抢先把引擎拉起，导致 pid 归属错乱。
    // ★ State 必须绑定具名变量：app.state::<T>() 是临时值，
    //   守卫借用它，语句结束即析构（E0716）。
    let state = app.state::<EngineState>();
    let _guard = state.lifecycle.lock().await;

    stop_engine_locked(&app).await;
    // 清除「用户主动停止」意图，让 ensure 真正拉起
    state
        .user_stopped
        .store(false, std::sync::atomic::Ordering::SeqCst);

    // ★ 本函数已持有 lifecycle 锁，不能再调 ensure_engine_running
    //   （它自己会加锁 → 立即自死锁）。
    //   故这里内联「拉起 + 锁外等待」这段逻辑。
    if let Err(e) = start_engine_process(&app) {
        let err = format!("引擎启动失败: {e}");
        state.status.lock().startup_error = Some(err.clone());
        return Err(err);
    }
    {
        let mut st = state.status.lock();
        st.running = true;
        st.started_at = Some(unix_now());
        st.startup_error = None;
    }
    state.starting.store(true, std::sync::atomic::Ordering::SeqCst);
    // 放锁后再等就绪：等待期间不应阻塞其他请求的快速路径
    drop(_guard);

    let ok = wait_engine_ready().await;

    let state = app.state::<EngineState>();
    state.starting.store(false, std::sync::atomic::Ordering::SeqCst);
    if ok {
        let mut st = state.status.lock();
        st.healthy = true;
        st.last_check = Some(unix_now());
        Ok(())
    } else {
        // ★ 必须把错误原样抛给前端，不能静默返回成功。
        //   吞掉它 = 用户点了「重启引擎」看到「已重启」，
        //   而实际跑着的还是重启前那个进程。
        //   对安全产品而言，谎报操作成功比操作失败危险得多。
        let msg = "引擎重启后未能在 60 秒内就绪".to_string();
        let mut st = state.status.lock();
        st.healthy = false;
        st.startup_error = Some(msg.clone());
        Err(msg)
    }
}

#[tauri::command]
async fn stop_engine_command(app: tauri::AppHandle) -> Result<(), String> {
    stop_engine(&app).await;
    Ok(())
}

// ── 以下命令均为对本地代理的薄封装 ──

#[derive(Debug, Deserialize)]
pub struct Payload(pub serde_json::Value);

#[tauri::command]
async fn get_state(app: tauri::AppHandle, payload: Option<Payload>) -> Result<serde_json::Value, String> {
    let _ = &payload;
    ensure_engine_running(&app).await?;
    proxy_call(reqwest::Method::GET, "/api/state", None, REQ_FAST).await
}

#[tauri::command]
async fn get_stats(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    let _ = &payload;
    ensure_engine_running(&app).await?;
    proxy_call(reqwest::Method::GET, "/api/stats?days=7", None, REQ_NORMAL).await
}

#[tauri::command]
async fn get_diagnostics(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    let _ = &payload;
    ensure_engine_running(&app).await?;
    proxy_call(reqwest::Method::GET, "/api/diagnostics", None, REQ_NORMAL).await
}

#[tauri::command]
async fn get_logs(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    // ★ P0-3 修复：原实现只读 payload.__path（前端从未设置），
    //   导致桌面端永远请求无参数 /api/logs，筛选/搜索/分页全部失效。
    //   现改为从 payload 逐字段读取并拼装 query string。
    let p = payload.as_ref().map(|p| &p.0);

    let mut qs: Vec<String> = Vec::new();
    let mut push = |k: &str, v: Option<&serde_json::Value>| {
        if let Some(val) = v.and_then(|x| x.as_u64()) {
            qs.push(format!("{k}={val}"));
        }
    };
    push("limit", p.and_then(|x| x.get("limit")));
    push("offset", p.and_then(|x| x.get("offset")));
    push("days", p.and_then(|x| x.get("days")));
    for key in ["log_type", "action", "search"] {
        if let Some(s) = p.and_then(|x| x.get(key)).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                // 简单 URL 编码（仅需处理空格与特殊符号）
                let enc: String = s
                    .bytes()
                    .map(|b| match b {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                            (b as char).to_string()
                        }
                        _ => format!("%{b:02X}"),
                    })
                    .collect();
                qs.push(format!("{key}={enc}"));
            }
        }
    }

    let path = if qs.is_empty() {
        "/api/logs".to_string()
    } else {
        format!("/api/logs?{}", qs.join("&"))
    };

    proxy_call(reqwest::Method::GET, &sanitize_local_path(&path), None, REQ_NORMAL).await
}

#[tauri::command]
async fn mark_log_safe(app: tauri::AppHandle, id: u64) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    proxy_call(
        reqwest::Method::POST,
        &format!("/api/logs/{id}/mark-safe"),
        Some(serde_json::json!({})),
        REQ_NORMAL,
    )
    .await
}

#[tauri::command]
async fn export_logs(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    let body = payload
        .as_ref()
        .map(|p| {
            let mut v = p.0.clone();
            if v.get("format").is_none() {
                v["format"] = serde_json::json!("csv");
            }
            v
        })
        .unwrap_or_else(|| serde_json::json!({ "format": "csv" }));
    proxy_call(
        reqwest::Method::POST,
        "/api/logs/export",
        Some(body),
        Duration::from_secs(60),
    )
    .await
}

#[tauri::command]
async fn get_log_detail(
    app: tauri::AppHandle,
    id: u64,
) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    proxy_call(
        reqwest::Method::GET,
        &format!("/api/logs/{id}"),
        None,
        REQ_NORMAL,
    )
    .await
}

#[tauri::command]
async fn delete_log(app: tauri::AppHandle, id: u64) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    proxy_call(
        reqwest::Method::DELETE,
        &format!("/api/logs/{id}"),
        None,
        REQ_NORMAL,
    )
    .await
}

#[tauri::command]
async fn clear_logs(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    let body = payload
        .as_ref()
        .map(|p| {
            let mut v = p.0.clone();
            if v.get("before_days").is_none() {
                v["before_days"] = serde_json::json!(0);
            }
            v
        })
        .unwrap_or_else(|| serde_json::json!({ "before_days": 0 }));
    proxy_call(reqwest::Method::POST, "/api/logs/clear", Some(body), REQ_NORMAL).await
}

#[tauri::command]
async fn get_relays(app: tauri::AppHandle, payload: Option<Payload>) -> Result<serde_json::Value, String> {
    let _ = &payload;
    ensure_engine_running(&app).await?;
    proxy_call(reqwest::Method::GET, "/api/relays", None, REQ_NORMAL).await
}

/// 中转站静态风险预检（Phase 7）。
///
/// ★ 为何需要独立端点而不是查 /api/relays：
///   信誉记录只在真正转发过一次请求后建立。用户刚在设置页填完地址、
///   还没发过任何对话时，列表里根本没有这个域名 —— 此时若展示默认视图，
///   用户会以为「查不到 = 没问题」。预检让风险在配置那一刻就摆出来。
#[tauri::command]
async fn precheck_relay(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    // 空地址也照样转发：让引擎返回 400 与明确的 detail，
    // 错误文案只有一处来源，避免桌面端另写一套提示而与后端不一致。
    let body = payload.map(|p| p.0).unwrap_or_else(|| serde_json::json!({}));
    ensure_engine_running(&app).await?;
    proxy_call(
        reqwest::Method::POST,
        "/api/relay/precheck",
        Some(body),
        REQ_FAST,
    )
    .await
}

#[tauri::command]
async fn clear_reputation(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    let _ = &payload;
    ensure_engine_running(&app).await?;
    proxy_call(
        reqwest::Method::POST,
        "/api/reputation/clear",
        Some(serde_json::json!({})),
        REQ_NORMAL,
    )
    .await
}

/// 返回本进程实际使用的代理端口。
///
/// ★ P1-10：前端需要区分「配置里的端口」和「实际跑着的端口」——
///   用户改端口后未重启时两者不同。界面若显示配置值，
///   用户照着去改 AI 工具配置就会填到一个还没生效的地址。
#[tauri::command]
fn get_active_port() -> u16 {
    lock_proxy_port()
}

#[tauri::command]
async fn get_config(app: tauri::AppHandle, payload: Option<Payload>) -> Result<serde_json::Value, String> {
    let _ = &payload;
    ensure_engine_running(&app).await?;
    proxy_call(reqwest::Method::GET, "/api/config", None, REQ_FAST).await
}

#[tauri::command]
async fn update_config(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    let body = payload.map(|p| p.0).unwrap_or(serde_json::json!({}));
    proxy_call(reqwest::Method::PUT, "/api/config", Some(body), REQ_NORMAL).await
}

/// 查询引擎是否处于「用户主动暂停」。
///
/// 返回 None 表示查不到（引擎未运行）—— 此时不能把托盘切回绿色。
/// 灰态有两个来源：用户主动暂停、引擎失效。恢复时必须区分：
/// 前者该回绿，后者要等引擎真的起来。
async fn is_engine_paused() -> Option<bool> {
    let v = proxy_call(reqwest::Method::GET, "/api/state", None, REQ_FAST)
        .await
        .ok()?;
    Some(v.get("state").and_then(|s| s.as_str()) == Some("paused"))
}

#[tauri::command]
async fn pause_protection(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    ensure_engine_running(&app).await?;
    let body = payload.unwrap_or(Payload(serde_json::json!({ "duration_min": 30 }))).0;
    let r = proxy_call(reqwest::Method::POST, "/api/pause", Some(body), REQ_NORMAL).await?;

    // ★ 暂停后必须让托盘转灰：防护停了却显示绿色「防护中」，
    //   等于对用户谎报状态 —— 而用户对防护是否在跑完全无感。
    if let Some(ctrl) = app.try_state::<TrayController>() {
        let mins = r.get("paused_minutes").and_then(|v| v.as_i64()).unwrap_or(0);
        ctrl.set_steady(&app, "paused", &format!("防护已暂停 {mins} 分钟"));
    }
    Ok(r)
}

#[tauri::command]
async fn resume_protection(
    app: tauri::AppHandle,
    payload: Option<Payload>,
) -> Result<serde_json::Value, String> {
    let _ = &payload;
    ensure_engine_running(&app).await?;
    let r = proxy_call(
        reqwest::Method::POST,
        "/api/resume",
        Some(serde_json::json!({})),
        REQ_NORMAL,
    )
    .await?;

    // 恢复后交回持续态实值：引擎是否真健康由实际探测决定，
    // 避免在引擎仍失效时误报绿色。
    if let Some(ctrl) = app.try_state::<TrayController>() {
        if check_engine_health().await {
            ctrl.set_steady(&app, "safe", "防护已恢复");
        } else {
            ctrl.force_paused(&app);
        }
    }
    Ok(r)
}

/// 校验路径只能是 `/api/logs` 前缀（防路径穿越）
fn sanitize_local_path(path: &str) -> String {
    if path.starts_with("/api/logs") && !path.contains("..") {
        path.to_string()
    } else {
        "/api/logs".to_string()
    }
}

// ══════════════════════════════════════════════════════════════
// 应用入口
// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
// CDP 调试端口门禁（安全加固）
// ══════════════════════════════════════════════════════════════
//
// 为什么要加这个：CDP 测试需要直连 WebView2 才能做真实交互验证，
// 但开放该端口等于让**任意本地进程**通过 http://127.0.0.1:9224/json
// 枚举页面并注入 JS —— 对一个安全产品而言这是严重风险：
// 本地恶意程序可以篡改界面显示的检测结果，让用户以为"防护中"。
//
// 因此采用与个人版防护理念一致的策略：
//   · debug 构建自动开启（开发期便利）
//   · release 构建默认关闭，需显式设置环境变量才开启
//   · 开启时写日志留痕，不静默
//
// 环境变量：XUANDUN_ENABLE_CDP_DEBUG=1
fn enable_cdp_debug_port() -> bool {
    let enable = cfg!(debug_assertions)
        || std::env::var("XUANDUN_ENABLE_CDP_DEBUG").is_ok();
    if enable {
        // ★ --remote-allow-origins=* 不可省略：
        //   WebView2 仅设 --remote-debugging-port 会导致 Playwright/Node/Python
        //   客户端全部被拒（403），且报错信息不会提示缺这个参数。
        std::env::set_var(
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
            "--remote-debugging-port=9224 --remote-allow-origins=*",
        );
        eprintln!("[WARN] CDP 调试端口已开启: 9224（debug 构建或设置了 XUANDUN_ENABLE_CDP_DEBUG）");
        eprintln!("[WARN] 任意本地进程可通过 CDP 注入 JS 篡改界面显示，仅限调试环境使用");
    }
    enable
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    enable_cdp_debug_port();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(EngineState {
            status: parking_lot::Mutex::new(EngineStatus::default()),
            child: parking_lot::Mutex::new(None),
            pid: parking_lot::Mutex::new(None),
            user_stopped: std::sync::atomic::AtomicBool::new(false),
            lifecycle: tokio::sync::Mutex::new(()),
            starting: std::sync::atomic::AtomicBool::new(false),
        })
        .manage(TrayController::default())
        .invoke_handler(tauri::generate_handler![
            // ── 激活 ──
            get_license_status,
            activate_license,
            clear_license,
            build_rebind_request,
            get_engine_status,
            restart_engine,
            stop_engine_command,
            get_state,
            get_stats,
            get_diagnostics,
            get_logs,
            get_log_detail,
            delete_log,
            mark_log_safe,
            export_logs,
            clear_logs,
            get_relays,
            precheck_relay,
            clear_reputation,
            get_config,
            get_active_port,
            update_config,
            pause_protection,
            resume_protection,
            // ── 托盘 ──
            tray::set_tray_state,
            tray::pulse_tray,
            tray::get_tray_state,
        ])
        .on_window_event(|window, event| {
            // ★ 核心行为：关闭窗口 ≠ 退出应用。
            //   若让窗口关闭带走进程，用户一关窗口防护就静默失效 ——
            //   而用户对「防护是否还在跑」完全无感，这会让产品核心承诺
            //   在用户不知情时失效。改为隐藏到托盘，由托盘「退出玄盾」
            //   才是真正的退出。
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            let handle = app.handle().clone();

            // 托盘必须先于引擎启动就绪 ——
            // 否则引擎启动失败时用户看不到任何提示，
            // 「静默失效」正是托盘要消灭的状态，不能自己先犯。
            if let Err(e) = tray::build(&handle) {
                eprintln!("[XuanDun Personal] 托盘创建失败: {e}");
            }

            // 启动时拉起引擎（异步，不阻塞窗口显示）
            let h = handle.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = ensure_engine_running(&h).await {
                    eprintln!("[XuanDun Personal] 引擎启动失败: {e}");
                    if let Some(ctrl) = h.try_state::<TrayController>() {
                        ctrl.force_paused(&h);
                    }
                }
            });
            spawn_health_monitor(handle.clone());
            spawn_tray_pulse_monitor(handle);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("个人版启动失败")
        .run(|_app, _event| {
            // run 回调在应用退出时触发，此时托盘与引擎随之清理
        });
}

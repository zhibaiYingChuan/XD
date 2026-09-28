// SPDX-License-Identifier: DaoTi-Research-1.0
// Copyright (c) 2026 独立研究者，知白
// 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发

//! 个人版激活码 —— 机器码采集、状态存储与流程编排。
//!
//! # 架构决策：为什么验签放在 Python 引擎侧
//! ────────────────────────────────────────────────────────────
//! 本文件**不做** RSA 验签，验签由 Python 引擎的
//! `license.py` 完成，Rust 通过既有 IPC 通道调用。
//!
//! 三个原因：
//! 1. **依赖可及性**：本机网络被策略阻断（证书吊销检查失败），
//!    拉不到 `rsa` / `pkcs8` crate。而 `cryptography` 在 Python
//!    侧本就已就位，无需新增任何依赖。
//! 2. **更难绕过**：引擎是 Nuitka 编译产物，其内的校验逻辑不是
//!    明文 Python 源码。改 Rust 侧的校验点只需改几行 Rust；
//!    改引擎侧的则要先反编译二进制。
//! 3. **单一事实源**：机器码必须在 Rust 侧采集（sysinfo 现成），
//!    但验签规则只应有一份实现。两边各写一份必然漂移。

//! # 安全模型（诚实说明强度）
//! ────────────────────────────────────────────────────────────
//! 能防住：
//!   · 伪造激活码 —— 私钥只在签发方，从未进入任何客户端产物
//!   · 改写有效期 / 档位 —— 都在签名覆盖范围内，改动即验签失败
//!   · 复制到另一台机器 —— `mch`（机器码哈希）不匹配
//!   · `alg: none` 绕过 —— 引擎侧显式限定 algorithms=["RS256"]
//!
//! 防不住（抬高门槛而非绝对防线）：
//!   · 给校验函数打补丁后重新打包
//!   · 运行时 hook 跳过校验
//!
//! ★★ 关于「校验点分散」——**本项目实际并没有做到**，别被这句旧注释误导
//! ────────────────────────────────────────────────────────────
//! 早期注释曾声称「Rust 侧在关键命令入口独立复核，两处都通过才算激活」。
//! 那是错的，已核实并更正：
//!
//!   用户的 AI 工具 ──HTTP──▶ 引擎 (127.0.0.1:18765) ──▶ 中转站
//!                             ▲
//!                             └── Rust 只在 UI 查询时调它
//!
//! AI 流量**完全不经过 Rust**（代理型产品的必然设计：用户把 AI 工具的
//! API 地址填成 127.0.0.1:18765，请求直达引擎；Rust 只是看护进程 + WebView 壳）。
//! 所以在 Rust 侧加校验点对流量路径毫无作用 —— 只在引擎里有一个校验点。
//!
//! 那「防不住」这一栏该怎么理解：
//!   攻击者改掉引擎的 `_compute_protection_enabled()` 即可让防护全开，
//!   这确实是单点失效。**不存在让客户端校验不可绕过的方案** ——
//!   校验发生在用户机器上，用户拥有那台机器。
//!
//! 真正的价值来自不可逆的部分 + 流程管控，而非校验点数量：
//!   · RS256 私钥从不出现在任何客户端产物里（伪造码不可行，改代码也没用）
//!   · 换机必须走签发方换绑 → 每次换绑都留痕
//!   · jti 可吊销 → 泄露的码能作废
//!   · 签发日志可做异常检测（如同一 jti 在多台机器换绑）

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ══════════════════════════════════════════════════════════════
// 机器码
// ══════════════════════════════════════════════════════════════

/// 采集本机机器码（原始串，不哈希）。
///
/// ★ sysinfo 0.33 的实际 API（写这行时踩过坑，勿凭印象改）：
///   · `Component` 只有 `label()`，**没有** `serial_number()`
///   · `Disk` 也**没有** `serial_number()`（该方法在此版本不存在）
///   · `System` 没有 `disks()` / `motherboard()` 方法，
///     磁盘与硬件组件要分别用 `Disks` / `Component` 结构体
///   所以可用的稳定标识只有：CPU 品牌 + 核心数、内存容量、
///   磁盘的**名称/挂载点/总容量**。这比「序列号」弱，
///   但好在这些量对同一台机器足够稳定，且不涉及隐私。
///
/// ★ 强度说明（如实告知，不夸大）：
///   这类「规格型」标识**不是**硬件唯一标识 —— 同型号两台机器会相同。
///   它挡得住「把码复制到另一台配置不同的机器」，
///   挡不住「复制到同型号机器」。要做到严格一机一码，
///   需要平台相关的系统调用（Windows WMI / macOS IOPlatformUUID），
///   本版未实现 —— 见下方 TODO 与文档说明。
pub fn machine_code() -> String {
    use sysinfo::{Disks, System};

    let mut sys = System::new();
    sys.refresh_cpu_all();
    sys.refresh_memory();

    let mut parts: Vec<String> = Vec::new();

    // CPU 品牌 + 核心数
    if let Some(cpu) = sys.cpus().first() {
        parts.push(format!(
            "cpu:{}:{}",
            cpu.brand().trim(),
            sys.cpus().len()
        ));
    }

    // 内存总容量（字节）
    parts.push(format!("mem:{}", sys.total_memory()));

    // 第一块非移动磁盘：名称 + 总容量（0.33 无序列号可用）
    let disks = Disks::new_with_refreshed_list();
    for d in disks.list() {
        if d.is_removable() {
            continue;
        }
        parts.push(format!(
            "disk:{}:{}",
            d.name().to_string_lossy(),
            d.total_space()
        ));
        break;
    }

    if parts.is_empty() {
        parts.push("degraded:no-hardware-id".to_string());
    }

    parts.join("|")
}

/// 机器码哈希。
///
/// ★ 算法必须与 Python 侧 `license.py::machine_code_hash` 完全一致，
///   也与签发工具 `gen_activation_keys.py::machine_code_hash` 一致：
///   `sha256(trim + 大写)` 的十六进制前 32 字符。
///
///   两侧失配 = 用户拿到的码永远激活不了，且极难排查。
///   `tests` 里有与 Python 向量的对齐断言，改算法时会立刻红。
pub fn machine_code_hash(raw: &str) -> String {
    use sha2::{Digest, Sha256};

    let normalized = raw.trim().to_ascii_uppercase();
    let digest = Sha256::digest(normalized.as_bytes());
    let mut out = String::with_capacity(32);
    for b in digest.iter().take(16) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ══════════════════════════════════════════════════════════════
// 状态
// ══════════════════════════════════════════════════════════════

/// 激活状态（对外可见，UI 依赖它渲染）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LicenseStatus {
    pub activated: bool,
    pub expires_at: Option<i64>,
    pub tier: Option<String>,
    pub subject: Option<String>,
    pub jti: Option<String>,
    /// 未激活原因（已激活时为 None）
    pub reason: Option<String>,
    /// 本机机器码哈希 —— 用户报障时要报给签发方的东西
    pub machine_code: String,
    pub remaining_days: i64,
    /// 验签是否可用（引擎不可达时为 false）
    pub verifier_available: bool,
}

impl LicenseStatus {
    pub fn inactive(reason: impl Into<String>, mch: String) -> Self {
        Self {
            activated: false,
            expires_at: None,
            tier: None,
            subject: None,
            jti: None,
            reason: Some(reason.into()),
            machine_code: mch,
            remaining_days: 0,
            verifier_available: true,
        }
    }
}

/// 持久化的激活信息。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseState {
    pub code: String,
    /// 上次校验通过的 Unix 秒（时钟回拨检测用）
    pub last_seen: i64,
}

pub fn license_file() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
        })
        .join("com.daoti.xuandun-personal")
        .join("license.json")
}

pub fn load() -> LicenseState {
    std::fs::read_to_string(license_file())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(st: &LicenseState) -> Result<(), String> {
    let p = license_file();
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&p, serde_json::to_string_pretty(st).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// 引擎验签返回的结果。
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyOutcome {
    pub ok: bool,
    /// 失败原因码：malformed / bad_signature / expired /
    ///            machine_mismatch / bad_claims / clock_rollback
    pub reason: Option<String>,
    /// 面向用户的中文提示
    pub message: Option<String>,
    pub subject: Option<String>,
    pub tier: Option<String>,
    pub jti: Option<String>,
    pub exp: Option<i64>,
    /// 引擎是否成功执行了校验（false = 引擎不可达，结论不可信）
    pub verifier_available: bool,
}

/// 时钟回拨检测。
///
/// ★ 为什么需要：只查 `exp` 的话，用户把系统时间调回过去
///   就能无限续期 —— 成本几乎为零，且改时间是合法系统功能。
///
///   这是**尽力**检测而非强防：删掉 license.json 即可重置。
///   但它能挡住「随手改时间续期」这个最常见的情况。
pub fn check_clock_rollback(last_seen: Option<i64>, now: i64) -> Result<(), &'static str> {
    if let Some(prev) = last_seen {
        // 容忍 5 分钟正常漂移（NTP 校时、网络抖动）
        if now < prev - 300 {
            return Err("检测到系统时间被回拨，请校准系统时间后重试");
        }
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════
// 测试
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_hash_stable_across_case_and_space() {
        // 用户手抄机器码时多一个空格就激活失败 = 真实投诉来源
        let a = machine_code_hash("8a4f-2b7c");
        let b = machine_code_hash("  8A4F-2B7C  ");
        assert_eq!(a, b, "大小写/空白差异导致哈希不同");
        assert_eq!(a.len(), 32, "必须是 32 个十六进制字符");
    }

    #[test]
    fn machine_hash_matches_python_reference() {
        // 与 gen_activation_keys.py::machine_code_hash 的已知向量对齐。
        // ★ 改算法时这个断言会红 —— 那正是要的（两侧失配 = 全部激活失败）
        assert_eq!(
            machine_code_hash("8A4F-2B7C-D1E9-3366"),
            "6554f2074c659354acff2fa078d4bb6c"
        );
    }

    #[test]
    fn clock_rollback_detected_but_tolerates_drift() {
        assert!(check_clock_rollback(Some(1_000_000), 999_000).is_err());
        assert!(check_clock_rollback(Some(1_000_000), 999_800).is_ok());
        assert!(check_clock_rollback(None, 1).is_ok());
    }

    #[test]
    fn machine_code_is_nonempty_and_stable() {
        let a = machine_code();
        assert!(!a.is_empty(), "机器码不能为空");
        assert_eq!(a, machine_code(), "同一进程内两次采集必须一致");
    }
}

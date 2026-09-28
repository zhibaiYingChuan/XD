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
//! 3. **单一事实源**：机器码由 Python 侧 `license.py::machine_code`
//!    采集（调系统自带 WMI / ioreg），本文件只做转发与哈希。
//!    验签规则只应有一份实现，两边各写一份必然漂移 ——
//!    2026-09-28 线上激活失败正是这么来的。

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

/// 取本机机器码**哈希**（引擎采集，本函数只转发）。
///
/// ★★ 2026-09-28 起本函数**不再自行采集**，一律转发给引擎。
///
///   旧实现用 sysinfo 拼「CPU 品牌 + 内存 + 第一块非移动磁盘的
///   卷标与容量」。它有两个致命问题：
///     1. **不稳定** —— 磁盘卷标会变（改名/重装/换盘符），
///        枚举顺序也不保证，插拔一块移动硬盘就能改变「第一块」是谁。
///        实测：用户按界面上显示的机器码申请了码，装好却提示
///        「与本机不匹配」—— 签发时与验证时算出的值不同。
///     2. **与签发方必然漂移** —— 签发工具、引擎、Rust 各写一份算法，
///        没有任何机制保证三者长期一致。
///
///   现在机器码的唯一实现在 Python 侧 ``license.py::machine_code``：
///   它调系统自带的 WMI / ioreg 取硬件序列号，零新增依赖
///   （引 `windows` crate 做不到 —— 本机网络被策略阻断，
///   证书吊销检查失败拉不到新依赖，而「本机跑不通的代码」
///   比「多一个依赖」危险得多）。
///
///   单一实现的收益：签发工具与验签引擎 import 的是同一个函数，
///   不存在漂移的可能；这段代码还会被 Nuitka 编进二进制，
///   比改几行 Rust 更难下手。
///
/// ★ 返回的已经是**哈希**，不是原始串。调用方不要再哈希一次。
///
/// ★ 引擎不可达时返回空串。
///   这里绝不自造一个「看起来像机器码」的值：那会让界面显示
///   一个与实际签发依据不同的码，用户拿它去申请必然失败，
///   而报错还会指向错误的方向（提示「码不匹配」而非「引擎未启动」）。
pub async fn machine_code() -> String {
    crate::machine_code_via_engine().await
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
    fn machine_code_hash_is_stable_and_case_insensitive() {
        // ★ 不再测试 machine_code() 本身 —— 它已改为转发引擎，
        //   而引擎在单元测试里不存在，测它只会得到空串通过，
        //   属于「测了个没用的东西」。真正需要守住的是哈希：
        //   它必须与 Python 侧 license.py::machine_code_hash
        //   逐字节一致，否则用户永远激活不了。
        //
        //   这组向量与 tests/test_license_python_rust_parity.py 里的
        //   Python 侧向量成对存在，改算法时两边会一起红。
        assert_eq!(
            machine_code_hash("005927501CSG|191059577904885"),
            machine_code_hash("  005927501csg|191059577904885  "),
            "大小写与首尾空白差异不应改变哈希"
        );
        assert_eq!(
            machine_code_hash("abc").len(),
            32,
            "必须是 sha256 十六进制的前 32 个字符"
        );
        assert_ne!(
            machine_code_hash("disk-a"),
            machine_code_hash("disk-b"),
            "不同机器必须算出不同哈希"
        );
    }
}

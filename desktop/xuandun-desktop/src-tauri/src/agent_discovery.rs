use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub process_name: String,
    pub pid: Option<u32>,
    pub running: bool,
    pub installed: bool,
    pub policy_mode: Option<String>,
}

struct AgentPattern {
    name: &'static str,
    windows_names: &'static [&'static str],
    unix_names: &'static [&'static str],
    extension_keywords: &'static [&'static str],
    default_mode: &'static str,
}

const KNOWN_AGENTS: &[AgentPattern] = &[
    // 国内主流 AI 编程工具（主力支持）
    AgentPattern {
        name: "Trae",
        windows_names: &["Trae CN.exe", "Trae.exe", "trae.exe", "trae cn.exe"],
        unix_names: &["Trae CN", "Trae", "trae"],
        extension_keywords: &[],
        default_mode: "balanced",
    },
    AgentPattern {
        name: "豆包 MarsCode",
        windows_names: &["MarsCode.exe", "marscode.exe"],
        unix_names: &["MarsCode", "marscode"],
        extension_keywords: &["marscode", "doubao.marscode"],
        default_mode: "balanced",
    },
    AgentPattern {
        name: "通义灵码",
        windows_names: &["tongyi-lingma.exe", "lingma.exe", "tylm.exe"],
        unix_names: &["tongyi-lingma", "lingma"],
        extension_keywords: &["tongyi-lingma", "alibaba.tongyi-lingma", "lingma"],
        default_mode: "balanced",
    },
    AgentPattern {
        name: "CodeGeeX",
        windows_names: &["codegeex.exe", "CodeGeeX.exe"],
        unix_names: &["codegeex", "CodeGeeX"],
        extension_keywords: &["codegeex"],
        default_mode: "balanced",
    },
    AgentPattern {
        name: "文心快码 Comate",
        windows_names: &["comate.exe", "Comate.exe"],
        unix_names: &["comate", "Comate"],
        extension_keywords: &["comate", "baidu.comate"],
        default_mode: "balanced",
    },
    AgentPattern {
        name: "腾讯云 AI 代码助手",
        windows_names: &["codebuddy.exe", "CodeBuddy.exe"],
        unix_names: &["codebuddy", "CodeBuddy"],
        extension_keywords: &["codebuddy", "tencent.codebuddy"],
        default_mode: "balanced",
    },
    AgentPattern {
        name: "iFlyCode",
        windows_names: &["iflycode.exe", "iFlyCode.exe"],
        unix_names: &["iflycode", "iFlyCode"],
        extension_keywords: &["iflycode", "iflytek.iflycode"],
        default_mode: "high_security",
    },
    // 国外常见 AI 编程工具（保留少量常见）
    AgentPattern {
        name: "Cursor",
        windows_names: &["cursor.exe"],
        unix_names: &["Cursor", "cursor"],
        extension_keywords: &[],
        default_mode: "balanced",
    },
    AgentPattern {
        name: "VS Code",
        windows_names: &["code.exe", "Code.exe"],
        unix_names: &["Code", "code"],
        extension_keywords: &[],
        default_mode: "low_false_positive",
    },
    AgentPattern {
        name: "Claude Desktop",
        windows_names: &["claude.exe", "Claude.exe"],
        unix_names: &["Claude", "claude"],
        extension_keywords: &[],
        default_mode: "balanced",
    },
];

fn get_extension_dirs() -> Vec<std::path::PathBuf> {
    let home = match std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        Some(h) => std::path::PathBuf::from(h),
        None => return vec![],
    };
    let subdirs = [
        ".vscode/extensions",
        ".vscode-insiders/extensions",
        ".trae-cn/extensions",
        ".trae/extensions",
        ".cursor/extensions",
    ];
    subdirs.iter().map(|s| home.join(s)).collect()
}

fn check_extension_installed(keywords: &[&str]) -> bool {
    if keywords.is_empty() {
        return false;
    }
    for dir in get_extension_dirs() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                for kw in keywords {
                    if name.contains(&kw.to_lowercase()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub async fn discover() -> Result<Vec<AgentInfo>, String> {
    tokio::task::spawn_blocking(|| {
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let mut results = Vec::new();
        let is_windows = cfg!(target_os = "windows");

        for agent in KNOWN_AGENTS {
            let names = if is_windows { agent.windows_names } else { agent.unix_names };
            let mut found = false;
            let mut found_pid: Option<u32> = None;
            let mut found_proc_name = String::new();

            for (_, process) in sys.processes() {
                let proc_name = process.name().to_string_lossy().to_string();
                let proc_name_lower = proc_name.to_lowercase();

                for name in names {
                    if proc_name_lower == name.to_lowercase() {
                        found_pid = Some(process.pid().as_u32());
                        found_proc_name = proc_name.clone();
                        found = true;
                        break;
                    }
                }
                if found { break; }
            }

            let installed = found || check_extension_installed(agent.extension_keywords);

            results.push(AgentInfo {
                name: agent.name.to_string(),
                process_name: found_proc_name,
                pid: found_pid,
                running: found,
                installed,
                policy_mode: Some(agent.default_mode.to_string()),
            });
        }

        Ok(results)
    }).await.map_err(|e| e.to_string())?
}

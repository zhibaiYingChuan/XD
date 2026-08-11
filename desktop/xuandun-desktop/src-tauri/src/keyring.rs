use keyring::Entry;

const SERVICE_NAME: &str = "XuanDun";
const KEY_NAME: &str = "engine_secret_key";

/// 修复1：密钥体系统一入口 —— 通过 service 参数区分不同密钥
/// service 映射：
///   - "engine_key"       → 引擎密钥（兼容旧版）
///   - "upstream_api_key" → 上游 API Key
///   - "notifier_config"  → 通知配置中的密钥（webhook token 等）
///   - 未识别的 service 回退到通用存储（keyring）
pub fn store_key_with_service(service: &str, key: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, service).map_err(|e| e.to_string())?;
    entry.set_password(key).map_err(|e| e.to_string())?;
    // 存储后立即验证
    match entry.get_password() {
        Ok(stored) if stored == key => Ok(()),
        Ok(_stored) => Err("密钥验证失败：存储内容不匹配".to_string()),
        Err(e) => Err(format!("密钥存储后验证失败：{}。可能需要管理员权限或系统凭据管理器不可用。", e)),
    }
}

pub fn get_key_by_service(service: &str) -> Result<String, String> {
    let entry = Entry::new(SERVICE_NAME, service).map_err(|e| e.to_string())?;
    entry.get_password().map_err(|e| e.to_string())
}

pub fn delete_key_by_service(service: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, service).map_err(|e| e.to_string())?;
    entry.delete_credential().map_err(|e| e.to_string())
}

/// 检查以指定 service 存储的密钥是否存在
pub fn has_key_for_service(service: &str) -> bool {
    let entry = match Entry::new(SERVICE_NAME, service) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[XuanDun] [ERROR] Keyring entry creation failed for '{}': {}", service, e);
            return false;
        }
    };
    match entry.get_password() {
        Ok(_) => true,
        Err(keyring::Error::NoEntry) => false,
        Err(e) => {
            eprintln!("[XuanDun] [WARN] Keyring access error for '{}' (treating as no key): {}", service, e);
            false
        }
    }
}

// ── 兼容旧版 API（无 service 参数，使用默认 KEY_NAME）──

pub fn store_key(key: &str) -> Result<(), String> {
    store_key_with_service(KEY_NAME, key)
}

pub fn retrieve_key() -> Result<String, String> {
    get_key_by_service(KEY_NAME)
}

pub fn delete_key() -> Result<(), String> {
    delete_key_by_service(KEY_NAME)
}

pub fn has_key() -> bool {
    has_key_for_service(KEY_NAME)
}

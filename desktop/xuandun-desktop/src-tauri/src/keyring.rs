use keyring::Entry;

const SERVICE_NAME: &str = "XuanDun";
const KEY_NAME: &str = "engine_secret_key";

pub fn store_key(key: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, KEY_NAME).map_err(|e| e.to_string())?;
    entry.set_password(key).map_err(|e| e.to_string())
}

pub fn retrieve_key() -> Result<String, String> {
    let entry = Entry::new(SERVICE_NAME, KEY_NAME).map_err(|e| e.to_string())?;
    entry.get_password().map_err(|e| e.to_string())
}

pub fn delete_key() -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, KEY_NAME).map_err(|e| e.to_string())?;
    entry.delete_credential().map_err(|e| e.to_string())
}

pub fn has_key() -> bool {
    let entry = match Entry::new(SERVICE_NAME, KEY_NAME) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[XuanDun] Keyring entry creation failed: {}", e);
            return false;
        }
    };
    match entry.get_password() {
        Ok(_) => true,
        Err(keyring::Error::NoEntry) => false,
        Err(e) => {
            eprintln!("[XuanDun] Keyring access error (treating as no key): {}", e);
            false
        }
    }
}

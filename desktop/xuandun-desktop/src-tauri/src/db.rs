use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: i64,
    pub timestamp: String,
    pub text_preview: String,
    pub allowed: bool,
    pub trust_level: String,
    pub reject_stage: Option<String>,
    pub session_id: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashChainReport {
    pub total_entries: u64,
    pub verified_entries: u64,
    pub broken_links: Vec<(i64, String)>,
    pub chain_intact: bool,
    pub legacy_entries: u64,
}

pub struct Database {
    pub(crate) conn: Mutex<Connection>,
}

impl Database {
    pub fn open(db_path: &Path) -> Result<Self, String> {
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;").map_err(|e| e.to_string())?;
        let db = Self { conn: Mutex::new(conn) };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                text_preview TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                trust_level TEXT NOT NULL,
                reject_stage TEXT,
                session_id TEXT,
                prev_hash TEXT NOT NULL DEFAULT '',
                hash TEXT NOT NULL DEFAULT '',
                hash_version INTEGER NOT NULL DEFAULT 2
            );
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_allowed ON logs(allowed);
            CREATE INDEX IF NOT EXISTS idx_logs_hash_version ON logs(hash_version);

            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS config_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                label TEXT NOT NULL,
                config_json TEXT NOT NULL
            );
        ").map_err(|e| e.to_string())?;

        let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);
        if user_version < 2 {
            if let Err(e) = conn.execute("UPDATE logs SET hash_version = 1 WHERE hash_version = 2 AND length(hash) = 32", []) {
                eprintln!("[xuandun] hash_version migration failed: {}", e);
            }
            conn.execute_batch("PRAGMA user_version = 2;").map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn insert_log(&self, text_preview: &str, allowed: bool, trust_level: &str, reject_stage: Option<&str>, session_id: Option<&str>) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let timestamp = chrono::Utc::now().to_rfc3339();

        let prev_hash: String = conn.query_row(
            "SELECT hash FROM logs ORDER BY id DESC LIMIT 1",
            [], |row| row.get(0)
        ).unwrap_or_default();

        let hash_input = format!("{}{}{}{}{}{}{}",
            timestamp, text_preview, allowed as i32,
            trust_level, reject_stage.unwrap_or(""),
            session_id.unwrap_or(""), prev_hash);
        let hash = sha256_hash(&hash_input);

        conn.execute(
            "INSERT INTO logs (timestamp, text_preview, allowed, trust_level, reject_stage, session_id, prev_hash, hash, hash_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 2)",
            params![timestamp, text_preview, allowed as i32, trust_level, reject_stage, session_id, prev_hash, hash],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn insert_audit(&self, event_type: &str, detail: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let timestamp = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO audit (timestamp, event_type, detail) VALUES (?1, ?2, ?3)",
            params![timestamp, event_type, detail],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn query_logs(&self, filter_allowed: Option<bool>, limit: usize, offset: usize) -> Result<Vec<LogEntry>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let (sql, params): (_, Vec<Box<dyn rusqlite::types::ToSql>>) = match filter_allowed {
            Some(a) => (
                "SELECT id, timestamp, text_preview, allowed, trust_level, reject_stage, session_id, prev_hash, hash FROM logs WHERE allowed = ?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3".to_string(),
                vec![Box::new(a as i32), Box::new(limit as i64), Box::new(offset as i64)],
            ),
            None => (
                "SELECT id, timestamp, text_preview, allowed, trust_level, reject_stage, session_id, prev_hash, hash FROM logs ORDER BY id DESC LIMIT ?1 OFFSET ?2".to_string(),
                vec![Box::new(limit as i64), Box::new(offset as i64)],
            ),
        };
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(LogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                text_preview: row.get(2)?,
                allowed: row.get::<_, i32>(3)? != 0,
                trust_level: row.get(4)?,
                reject_stage: row.get(5)?,
                session_id: row.get(6)?,
                prev_hash: row.get(7)?,
                hash: row.get(8)?,
            })
        }).map_err(|e| e.to_string())?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| e.to_string())?);
        }
        Ok(result)
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        match conn.query_row(
            "SELECT value FROM config WHERE key = ?1",
            [key], |row| row.get(0)
        ) {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn create_snapshot(&self, label: &str) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut stmt = conn.prepare("SELECT key, value FROM config").map_err(|e| e.to_string())?;
        let rows: Vec<(String, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok()).collect();
        let config_json = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO config_snapshots (timestamp, label, config_json) VALUES (?1, ?2, ?3)",
            params![timestamp, label, config_json],
        ).map_err(|e| e.to_string())?;
        let id = conn.last_insert_rowid();
        Ok(id)
    }

    pub fn list_snapshots(&self) -> Result<Vec<(i64, String, String)>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare("SELECT id, timestamp, label FROM config_snapshots ORDER BY id DESC")
            .map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok()).collect();
        Ok(rows)
    }

    pub fn restore_snapshot(&self, snapshot_id: i64) -> Result<(), String> {
        let mut conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let config_json: String = tx.query_row(
            "SELECT config_json FROM config_snapshots WHERE id = ?1",
            [snapshot_id], |row| row.get(0)
        ).map_err(|e| format!("Snapshot not found: {}", e))?;
        let pairs: Vec<(String, String)> = serde_json::from_str(&config_json)
            .map_err(|e| format!("Invalid snapshot data: {}", e))?;
        tx.execute("DELETE FROM config", []).map_err(|e| e.to_string())?;
        for (key, value) in &pairs {
            tx.execute("INSERT INTO config (key, value) VALUES (?1, ?2)", params![key, value])
                .map_err(|e| e.to_string())?;
        }
        let timestamp = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO audit (timestamp, event_type, detail) VALUES (?1, ?2, ?3)",
            params![timestamp, "snapshot_restore", format!("Restored snapshot id={}", snapshot_id)],
        ).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn count_logs(&self, filter_allowed: Option<bool>) -> Result<usize, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let count: i64 = match filter_allowed {
            Some(a) => conn.query_row(
                "SELECT COUNT(*) FROM logs WHERE allowed = ?1",
                [a as i32], |row| row.get(0)
            ).map_err(|e| e.to_string())?,
            None => conn.query_row(
                "SELECT COUNT(*) FROM logs",
                [], |row| row.get(0)
            ).map_err(|e| e.to_string())?,
        };
        Ok(count as usize)
    }

    pub fn verify_hash_chain(&self) -> Result<HashChainReport, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(
            "SELECT id, prev_hash, hash, timestamp, text_preview, allowed, trust_level, reject_stage, session_id, hash_version FROM logs ORDER BY id ASC"
        ).map_err(|e| e.to_string())?;

        let rows: Vec<(i64, String, String, String, String, bool, String, Option<String>, Option<String>, i64)> = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i32>(5)? != 0,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
            ))
        }).map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

        let mut broken_links: Vec<(i64, String)> = Vec::new();
        let mut prev_hash = String::new();
        let mut verified_count = 0u64;
        let mut legacy_count = 0u64;

        for (id, stored_prev, stored_hash, timestamp, text_preview, allowed, trust_level, reject_stage, session_id, hash_version) in &rows {
            if *hash_version == 1 {
                legacy_count += 1;
                prev_hash = stored_hash.clone();
                continue;
            }
            if stored_prev != &prev_hash {
                broken_links.push((*id, format!("prev_hash mismatch: expected {}, got {}", prev_hash, stored_prev)));
                prev_hash = stored_hash.clone();
                continue;
            }
            let hash_input = format!("{}{}{}{}{}{}{}",
                timestamp, text_preview, *allowed as i32, trust_level,
                reject_stage.as_deref().unwrap_or(""),
                session_id.as_deref().unwrap_or(""), stored_prev);
            let computed_hash = sha256_hash(&hash_input);
            if &computed_hash != stored_hash {
                broken_links.push((*id, format!("hash mismatch: expected {}, got {}", computed_hash, stored_hash)));
            } else {
                verified_count += 1;
            }
            prev_hash = stored_hash.clone();
        }

        let chain_intact = broken_links.is_empty();
        Ok(HashChainReport {
            total_entries: rows.len() as u64,
            verified_entries: verified_count,
            broken_links,
            chain_intact,
            legacy_entries: legacy_count,
        })
    }
}

pub fn sha256_hash(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_db() -> Database {
        let dir = std::env::temp_dir().join("xuandun_test_db");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join(format!("test_{}_{}.db", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = std::fs::remove_file(&db_path);
        Database::open(&db_path).expect("Failed to open test database")
    }

    #[test]
    fn test_insert_and_query_log() {
        let db = test_db();
        db.insert_log("hello world", true, "HIGH", None, Some("sess1")).unwrap();
        db.insert_log("malicious input", false, "LOW", Some("reject_gate"), Some("sess2")).unwrap();
        let all = db.query_logs(None, 10, 0).unwrap();
        assert_eq!(all.len(), 2);
        assert!(!all[0].allowed);
        assert!(all[1].allowed);
    }

    #[test]
    fn test_query_logs_filter() {
        let db = test_db();
        db.insert_log("safe", true, "HIGH", None, None).unwrap();
        db.insert_log("attack", false, "LOW", Some("reject_gate"), None).unwrap();
        let blocked = db.query_logs(Some(false), 10, 0).unwrap();
        assert_eq!(blocked.len(), 1);
        let allowed = db.query_logs(Some(true), 10, 0).unwrap();
        assert_eq!(allowed.len(), 1);
    }

    #[test]
    fn test_pagination() {
        let db = test_db();
        for i in 0..5 { db.insert_log(&format!("e{}", i), true, "HIGH", None, None).unwrap(); }
        assert_eq!(db.query_logs(None, 2, 0).unwrap().len(), 2);
        assert_eq!(db.query_logs(None, 2, 4).unwrap().len(), 1);
    }

    #[test]
    fn test_count_logs() {
        let db = test_db();
        db.insert_log("a", true, "HIGH", None, None).unwrap();
        db.insert_log("b", false, "LOW", Some("reject_gate"), None).unwrap();
        assert_eq!(db.count_logs(None).unwrap(), 2);
        assert_eq!(db.count_logs(Some(true)).unwrap(), 1);
        assert_eq!(db.count_logs(Some(false)).unwrap(), 1);
    }

    #[test]
    fn test_config_crud() {
        let db = test_db();
        assert_eq!(db.get_config("mode").unwrap(), None);
        db.set_config("mode", "balanced").unwrap();
        assert_eq!(db.get_config("mode").unwrap(), Some("balanced".to_string()));
        db.set_config("mode", "high_security").unwrap();
        assert_eq!(db.get_config("mode").unwrap(), Some("high_security".to_string()));
    }

    #[test]
    fn test_hash_chain_intact() {
        let db = test_db();
        db.insert_log("entry1", true, "HIGH", None, None).unwrap();
        db.insert_log("entry2", false, "LOW", Some("reject_gate"), None).unwrap();
        let report = db.verify_hash_chain().unwrap();
        assert!(report.chain_intact);
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.verified_entries, 2);
    }

    #[test]
    fn test_hash_chain_broken() {
        let db = test_db();
        db.insert_log("entry1", true, "HIGH", None, None).unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute("UPDATE logs SET text_preview = 'tampered' WHERE id = 1", []).unwrap();
        }
        let report = db.verify_hash_chain().unwrap();
        assert!(!report.chain_intact);
    }

    #[test]
    fn test_sha256_known_value() {
        assert_eq!(sha256_hash(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hash("hello world"), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }
}

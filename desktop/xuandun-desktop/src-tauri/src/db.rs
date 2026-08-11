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
    pub attack_category: Option<String>,
    pub latency_ms: Option<f64>,
    pub domain_distance: Option<f64>,
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
    db_path: std::path::PathBuf,
}

impl Database {
    pub fn open(db_path: &Path) -> Result<Self, String> {
        let db_path_buf = db_path.to_path_buf();

        // 修复5：SQLite 自动恢复 —— 启动时校验数据库完整性
        let conn = match Connection::open(db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[XuanDun] [ERROR] DB open failed: {} — attempting backup recovery", e);
                if let Some(restored) = Self::try_restore_from_backup(&db_path_buf) {
                    restored
                } else {
                    eprintln!("[XuanDun] [ERROR] DB backup also unavailable, creating fresh database");
                    Self::create_fresh(&db_path_buf)?
                }
            }
        };

        // 执行完整性检查
        let integrity_ok = conn.query_row("PRAGMA integrity_check", [], |row| {
            let val: String = row.get(0)?;
            Ok(val == "ok")
        }).unwrap_or(false);

        if !integrity_ok {
            eprintln!("[XuanDun] [WARN] DB integrity_check failed, attempting WAL cleanup and recovery...");
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            let retry_ok = conn.query_row("PRAGMA integrity_check", [], |row| {
                let val: String = row.get(0)?;
                Ok(val == "ok")
            }).unwrap_or(false);
            if !retry_ok {
                eprintln!("[XuanDun] [ERROR] DB still corrupted after WAL cleanup, attempting backup recovery");
                drop(conn);
                let _ = std::fs::remove_file(&db_path_buf);
                if let Some(restored) = Self::try_restore_from_backup(&db_path_buf) {
                    let db = Self { conn: Mutex::new(restored), db_path: db_path_buf.clone() };
                    db.init_tables()?;
                    if let Err(e) = db.insert_audit("db_recovery", "数据库从备份恢复，部分近期数据可能丢失") {
                        eprintln!("[XuanDun] [WARN] Failed to log db_recovery audit: {}", e);
                    }
                    return Ok(db);
                }
                // 全部失败，创建新数据库
                let new_conn = Self::create_fresh(&db_path_buf)?;
                let db = Self { conn: Mutex::new(new_conn), db_path: db_path_buf.clone() };
                db.init_tables()?;
                if let Err(e) = db.insert_audit("db_recovery", "数据库已损坏且备份不可用，已创建全新数据库") {
                    eprintln!("[XuanDun] [WARN] Failed to log db_reset audit: {}", e);
                }
                return Ok(db);
            }
        }

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;").map_err(|e| e.to_string())?;
        let db = Self { conn: Mutex::new(conn), db_path: db_path_buf };
        db.init_tables()?;
        Ok(db)
    }

    /// 尝试从备份文件恢复数据库
    fn try_restore_from_backup(db_path: &Path) -> Option<Connection> {
        let backup_path = db_path.parent().map(|p| p.join("xuandun.db.bak"))?;
        if !backup_path.exists() {
            eprintln!("[XuanDun] [WARN] No backup file found at {}", backup_path.display());
            return None;
        }
        eprintln!("[XuanDun] [INFO] Found backup at {}, attempting restore", backup_path.display());
        // 删除损坏的数据库文件
        let _ = std::fs::remove_file(db_path);
        match std::fs::copy(&backup_path, db_path) {
            Ok(_) => {
                eprintln!("[XuanDun] [INFO] Database restored from backup");
                Connection::open(db_path).ok()
            }
            Err(e) => {
                eprintln!("[XuanDun] [ERROR] Failed to copy backup: {}", e);
                None
            }
        }
    }

    /// 创建全新的空数据库
    fn create_fresh(db_path: &Path) -> Result<Connection, String> {
        // 删除损坏的文件
        let _ = std::fs::remove_file(db_path);
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;").map_err(|e| e.to_string())?;
        eprintln!("[XuanDun] [INFO] Created fresh database at {}", db_path.display());
        Ok(conn)
    }

    /// 创建数据库备份（修复5：在写入失败或关键操作后自动备份）
    fn backup_db(&self) {
        let backup_path = self.db_path.with_extension("db.bak");
        match std::fs::copy(&self.db_path, &backup_path) {
            Ok(_) => {
                eprintln!("[XuanDun] [INFO] Database backup created at {}", backup_path.display());
            }
            Err(e) => {
                eprintln!("[XuanDun] [ERROR] Failed to create database backup: {}", e);
            }
        }
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

        let has_hash_version: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info(logs)").map_err(|e| e.to_string())?;
            let rows = stmt.query_map([], |row| {
                let name: String = row.get(1)?;
                Ok(name)
            }).map_err(|e| e.to_string())?;
            // 收集到 Vec 避免 filter_map 临时值与 stmt 的生命周期冲突
            #[allow(clippy::unnecessary_filter_map)]
            let names: Vec<String> = rows.filter_map(|r| r.ok()).collect();
            names.iter().any(|name| name == "hash_version")

        };

        if !has_hash_version {
            conn.execute("ALTER TABLE logs ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 2", [])
                .map_err(|e| format!("Failed to add hash_version column: {}", e))?;
            eprintln!("[xuandun] [INFO] Added hash_version column to logs table");
        }

        conn.execute_batch("
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_allowed ON logs(allowed);
            CREATE INDEX IF NOT EXISTS idx_logs_hash_version ON logs(hash_version);
        ").map_err(|e| e.to_string())?;

        // v1.2.0 迁移：logs 表新增 attack_category / latency_ms / domain_distance
        let has_attack_category: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info(logs)").map_err(|e| e.to_string())?;
            let rows = stmt.query_map([], |row| {
                let name: String = row.get(1)?;
                Ok(name)
            }).map_err(|e| e.to_string())?;
            // 收集到 Vec 避免 filter_map 临时值与 stmt 的生命周期冲突
            #[allow(clippy::unnecessary_filter_map)]
            let names: Vec<String> = rows.filter_map(|r| r.ok()).collect();
            names.iter().any(|name| name == "attack_category")
        };
        if !has_attack_category {
            conn.execute_batch("
                ALTER TABLE logs ADD COLUMN attack_category TEXT;
                ALTER TABLE logs ADD COLUMN latency_ms REAL;
                ALTER TABLE logs ADD COLUMN domain_distance REAL;
            ").map_err(|e| format!("Failed to add v1.2.0 columns: {}", e))?;
            eprintln!("[xuandun] [INFO] Added attack_category/latency_ms/domain_distance columns to logs table");
        }

        // v1.2.0 聚合表
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS stats_hourly (
                hour TEXT PRIMARY KEY,
                total_requests INTEGER NOT NULL,
                total_blocked INTEGER NOT NULL,
                total_allowed INTEGER NOT NULL,
                avg_latency_ms REAL,
                category_breakdown TEXT,
                block_rate REAL,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS stats_daily (
                day TEXT PRIMARY KEY,
                total_requests INTEGER,
                total_blocked INTEGER,
                category_breakdown TEXT,
                simulation_results TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                generated_at TEXT NOT NULL,
                report_type TEXT NOT NULL,
                period_start TEXT NOT NULL,
                period_end TEXT NOT NULL,
                format TEXT NOT NULL,
                content BLOB NOT NULL,
                summary TEXT,
                created_by TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_logs_attack_category ON logs(attack_category);
            CREATE INDEX IF NOT EXISTS idx_stats_hourly_hour ON stats_hourly(hour);
            CREATE INDEX IF NOT EXISTS idx_stats_daily_day ON stats_daily(day);
            CREATE INDEX IF NOT EXISTS idx_reports_generated ON reports(generated_at);
        ").map_err(|e| e.to_string())?;

        let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);
        if user_version < 2 {
            if let Err(e) = conn.execute("UPDATE logs SET hash_version = 1 WHERE hash_version = 2 AND length(hash) = 32", []) {
                eprintln!("[xuandun] [ERROR] hash_version migration failed: {}", e);
            }
            conn.execute_batch("PRAGMA user_version = 2;").map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_log(&self, text_preview: &str, allowed: bool, trust_level: &str, reject_stage: Option<&str>, session_id: Option<&str>, attack_category: Option<&str>, latency_ms: Option<f64>, domain_distance: Option<f64>) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let timestamp = chrono::Utc::now().to_rfc3339();

        let prev_hash: String = match conn.query_row(
            "SELECT hash FROM logs ORDER BY id DESC LIMIT 1",
            [], |row| row.get(0)
        ) {
            Ok(hash) => hash,
            Err(rusqlite::Error::QueryReturnedNoRows) => String::new(),
            Err(e) => {
                eprintln!("[XuanDun] [ERROR] DB error fetching prev_hash: {}", e);
                return Err(format!("DB error: {}", e));
            }
        };

        let hash_input = format!("{}{}{}{}{}{}{}",
            timestamp, text_preview, allowed as i32,
            trust_level, reject_stage.unwrap_or(""),
            session_id.unwrap_or(""), prev_hash);
        let hash = sha256_hash(&hash_input);

        conn.execute(
            "INSERT INTO logs (timestamp, text_preview, allowed, trust_level, reject_stage, session_id, prev_hash, hash, hash_version, attack_category, latency_ms, domain_distance) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 2, ?9, ?10, ?11)",
            params![timestamp, text_preview, allowed as i32, trust_level, reject_stage, session_id, prev_hash, hash, attack_category, latency_ms, domain_distance],
        ).map_err(|e| {
            // 修复5：写入失败时自动创建备份，保留恢复机会
            eprintln!("[XuanDun] [ERROR] insert_log failed, creating backup: {}", e);
            self.backup_db();
            e.to_string()
        })?;
        Ok(())
    }

    pub fn insert_audit(&self, event_type: &str, detail: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let timestamp = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO audit (timestamp, event_type, detail) VALUES (?1, ?2, ?3)",
            params![timestamp, event_type, detail],
        ).map_err(|e| {
            // 修复5：写入失败时自动创建备份
            eprintln!("[XuanDun] [ERROR] insert_audit failed, creating backup: {}", e);
            self.backup_db();
            e.to_string()
        })?;
        Ok(())
    }

    pub fn query_logs(&self, filter_allowed: Option<bool>, limit: usize, offset: usize) -> Result<Vec<LogEntry>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let (sql, params): (_, Vec<Box<dyn rusqlite::types::ToSql>>) = match filter_allowed {
            Some(a) => (
                "SELECT id, timestamp, text_preview, allowed, trust_level, reject_stage, session_id, prev_hash, hash, attack_category, latency_ms, domain_distance FROM logs WHERE allowed = ?1 ORDER BY id DESC LIMIT ?2 OFFSET ?3".to_string(),
                vec![Box::new(a as i32), Box::new(limit as i64), Box::new(offset as i64)],
            ),
            None => (
                "SELECT id, timestamp, text_preview, allowed, trust_level, reject_stage, session_id, prev_hash, hash, attack_category, latency_ms, domain_distance FROM logs ORDER BY id DESC LIMIT ?1 OFFSET ?2".to_string(),
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
                attack_category: row.get(9).unwrap_or(None),
                latency_ms: row.get(10).unwrap_or(None),
                domain_distance: row.get(11).unwrap_or(None),
            })
        }).map_err(|e| e.to_string())?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| e.to_string())?);
        }
        Ok(result)
    }
}

// ── 修复1：密钥体系 —— Keyring 占位符与敏感字段判断 ──

const KEYRING_PLACEHOLDER: &str = "[KEYRING_PROTECTED]";
const DB_SERVICE_NAME: &str = "XuanDun";

/// 判断数据库配置 key 是否为敏感字段（需要 keyring 保护）
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("api_key")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
}

/// 将 DB config key 映射到 Keyring service 名称
fn db_key_to_keyring_service(key: &str) -> String {
    format!("{}_{}", DB_SERVICE_NAME, key)
}

impl Database {
    pub fn get_config(&self, key: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        match conn.query_row(
            "SELECT value FROM config WHERE key = ?1",
            [key], |row| row.get(0)
        ) {
            Ok(value) => {
                // 修复1：若 DB 中的值是 keyring 占位符，则从系统 Keyring 读取真实值
                if value == KEYRING_PLACEHOLDER {
                    let service = db_key_to_keyring_service(key);
                    match crate::keyring::get_key_by_service(&service) {
                        Ok(real_value) => Ok(Some(real_value)),
                        Err(e) => {
                            eprintln!("[XuanDun] [WARN] Keyring lookup failed for '{}': {}, returning placeholder", key, e);
                            Ok(Some(value))
                        }
                    }
                } else {
                    Ok(Some(value))
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), String> {
        // 修复1：敏感 key 的值通过系统 Keyring 存储，DB 中仅写入占位符
        let (db_value, should_store_in_keyring) = if is_sensitive_key(key) && !value.is_empty() {
            (KEYRING_PLACEHOLDER.to_string(), true)
        } else {
            (value.to_string(), false)
        };

        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, db_value],
        ).map_err(|e| e.to_string())?;

        if should_store_in_keyring {
            let service = db_key_to_keyring_service(key);
            if let Err(e) = crate::keyring::store_key_with_service(&service, value) {
                eprintln!("[XuanDun] [ERROR] Failed to store '{}' in keyring: {}", key, e);
            }
        }

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

    pub fn delete_snapshot(&self, snapshot_id: i64) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let affected = conn.execute(
            "DELETE FROM config_snapshots WHERE id = ?1",
            params![snapshot_id],
        ).map_err(|e| e.to_string())?;
        if affected == 0 {
            return Err(format!("Snapshot not found: id={}", snapshot_id));
        }
        Ok(())
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

        #[allow(clippy::type_complexity)]
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

    /// 按小时粒度获取趋势数据
    pub fn get_trend_stats(&self, start: &str, end: &str) -> Result<Vec<TrendPoint>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(
            "SELECT hour, total_requests, total_blocked, avg_latency_ms, block_rate FROM stats_hourly WHERE hour >= ?1 AND hour < ?2 ORDER BY hour"
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![start, end], |row| {
            Ok(TrendPoint {
                time: row.get(0)?,
                total_requests: row.get(1)?,
                total_blocked: row.get(2)?,
                avg_latency_ms: row.get(3).unwrap_or(0.0),
                block_rate: row.get(4).unwrap_or(0.0),
            })
        }).map_err(|e| e.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| e.to_string())?);
        }
        Ok(result)
    }

    /// 获取攻击类型分布
    pub fn get_attack_distribution(&self, start: &str, end: &str) -> Result<Vec<AttackCategoryStat>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(
            "SELECT COALESCE(attack_category, 'unknown') as cat, COUNT(*) as total, SUM(CASE WHEN allowed = 0 THEN 1 ELSE 0 END) as blocked FROM logs WHERE timestamp >= ?1 AND timestamp < ?2 AND allowed = 0 GROUP BY cat ORDER BY total DESC"
        ).map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![start, end], |row| {
            Ok(AttackCategoryStat {
                category: row.get(0)?,
                total: row.get(1)?,
                blocked: row.get(2)?,
            })
        }).map_err(|e| e.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| e.to_string())?);
        }
        Ok(result)
    }

    /// 获取周期对比统计
    pub fn get_period_stats(&self, start: &str, end: &str) -> Result<PeriodStats, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let row = conn.query_row(
            "SELECT COUNT(*) as total, SUM(CASE WHEN allowed = 0 THEN 1 ELSE 0 END) as blocked FROM logs WHERE timestamp >= ?1 AND timestamp < ?2",
            params![start, end],
            |row| {
                Ok(PeriodStats {
                    total_requests: row.get::<_, i64>(0).unwrap_or(0),
                    total_blocked: row.get::<_, i64>(1).unwrap_or(0),
                })
            }
        ).map_err(|e| e.to_string())?;
        Ok(row)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPoint {
    pub time: String,
    pub total_requests: i64,
    pub total_blocked: i64,
    pub avg_latency_ms: f64,
    pub block_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackCategoryStat {
    pub category: String,
    pub total: i64,
    pub blocked: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodStats {
    pub total_requests: i64,
    pub total_blocked: i64,
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
        db.insert_log("hello world", true, "HIGH", None, Some("sess1"), None, None, None).unwrap();
        db.insert_log("malicious input", false, "LOW", Some("reject_gate"), Some("sess2"), None, None, None).unwrap();
        let all = db.query_logs(None, 10, 0).unwrap();
        assert_eq!(all.len(), 2);
        assert!(!all[0].allowed);
        assert!(all[1].allowed);
    }

    #[test]
    fn test_query_logs_filter() {
        let db = test_db();
        db.insert_log("safe", true, "HIGH", None, None, None, None, None).unwrap();
        db.insert_log("attack", false, "LOW", Some("reject_gate"), None, None, None, None).unwrap();
        let blocked = db.query_logs(Some(false), 10, 0).unwrap();
        assert_eq!(blocked.len(), 1);
        let allowed = db.query_logs(Some(true), 10, 0).unwrap();
        assert_eq!(allowed.len(), 1);
    }

    #[test]
    fn test_pagination() {
        let db = test_db();
        for i in 0..5 { db.insert_log(&format!("e{}", i), true, "HIGH", None, None, None, None, None).unwrap(); }
        assert_eq!(db.query_logs(None, 2, 0).unwrap().len(), 2);
        assert_eq!(db.query_logs(None, 2, 4).unwrap().len(), 1);
    }

    #[test]
    fn test_count_logs() {
        let db = test_db();
        db.insert_log("a", true, "HIGH", None, None, None, None, None).unwrap();
        db.insert_log("b", false, "LOW", Some("reject_gate"), None, None, None, None).unwrap();
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
        db.insert_log("entry1", true, "HIGH", None, None, None, None, None).unwrap();
        db.insert_log("entry2", false, "LOW", Some("reject_gate"), None, None, None, None).unwrap();
        let report = db.verify_hash_chain().unwrap();
        assert!(report.chain_intact);
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.verified_entries, 2);
    }

    #[test]
    fn test_hash_chain_broken() {
        let db = test_db();
        db.insert_log("entry1", true, "HIGH", None, None, None, None, None).unwrap();
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

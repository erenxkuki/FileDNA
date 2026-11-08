use crate::error::Result;
use crate::types::*;
use rusqlite::{Connection, params};
use std::path::Path;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(crate::FileDnaError::Io)?;
        }
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );
            INSERT OR IGNORE INTO schema_version (version) VALUES (1);

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                name TEXT,
                extension TEXT,
                size INTEGER,
                modified INTEGER,
                format_id TEXT,
                mime_type TEXT,
                confidence TEXT,
                content_hash TEXT,
                structural_fp TEXT,
                metadata_fp TEXT,
                integrity_state TEXT,
                profile_json TEXT NOT NULL,
                discovered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                root TEXT,
                status TEXT,
                files_discovered INTEGER,
                files_completed INTEGER,
                bytes_processed INTEGER,
                errors INTEGER,
                started TEXT,
                finished TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
            CREATE INDEX IF NOT EXISTS idx_files_hash ON files(content_hash);
            CREATE INDEX IF NOT EXISTS idx_files_format ON files(format_id);
            "#,
        )?;
        Ok(())
    }

    pub fn save_profile(&self, profile: &FileProfile) -> Result<FileId> {
        let path = profile.discovered.path.to_string_lossy().to_string();
        let name = profile.discovered.name.clone();
        let ext = profile.discovered.extension.clone();
        let size = profile.discovered.size as i64;
        let modified = profile
            .discovered
            .modified
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);
        let format_id = profile
            .identification
            .as_ref()
            .and_then(|i| i.primary.as_ref().map(|p| p.format_id.clone()));
        let mime = profile
            .identification
            .as_ref()
            .and_then(|i| i.primary.as_ref().and_then(|p| p.mime_type.clone()));
        let conf = profile.identification.as_ref().and_then(|i| {
            i.primary
                .as_ref()
                .map(|p| p.confidence.as_str().to_string())
        });
        let hash = profile.content_fingerprint.as_ref().map(|f| f.hex.clone());
        let sfp = profile
            .structural_fingerprint
            .as_ref()
            .map(|f| f.value.clone());
        let mfp = profile
            .metadata_fingerprint
            .as_ref()
            .map(|f| f.value.clone());
        let istate = profile
            .integrity
            .as_ref()
            .map(|i| i.state.as_str().to_string());
        let json = serde_json::to_string(profile)
            .map_err(|e| crate::FileDnaError::Unknown(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();

        self.conn.execute(
            r#"INSERT INTO files (path,name,extension,size,modified,format_id,mime_type,confidence,content_hash,structural_fp,metadata_fp,integrity_state,profile_json,discovered_at)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
               ON CONFLICT(path) DO UPDATE SET
                 name=excluded.name, extension=excluded.extension, size=excluded.size, modified=excluded.modified,
                 format_id=excluded.format_id, mime_type=excluded.mime_type, confidence=excluded.confidence,
                 content_hash=excluded.content_hash, structural_fp=excluded.structural_fp, metadata_fp=excluded.metadata_fp,
                 integrity_state=excluded.integrity_state, profile_json=excluded.profile_json, discovered_at=excluded.discovered_at"#,
            params![path, name, ext, size, modified, format_id, mime, conf, hash, sfp, mfp, istate, json, now],
        )?;
        let id = self.conn.last_insert_rowid();
        // If conflict, last_insert_rowid may be 0? retrieve by path
        let actual: i64 =
            self.conn
                .query_row("SELECT id FROM files WHERE path = ?1", params![path], |r| {
                    r.get(0)
                })?;
        Ok(FileId(actual.max(id)))
    }

    pub fn list_files(&self) -> Result<Vec<(i64, String, Option<String>, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, path, format_id, content_hash FROM files ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_profile(&self, id: i64) -> Result<Option<FileProfile>> {
        let mut stmt = self
            .conn
            .prepare("SELECT profile_json FROM files WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let profile: FileProfile = serde_json::from_str(&json)
                .map_err(|e| crate::FileDnaError::Unknown(e.to_string()))?;
            Ok(Some(profile))
        } else {
            Ok(None)
        }
    }

    pub fn get_profile_by_path(&self, path: &str) -> Result<Option<FileProfile>> {
        let mut stmt = self
            .conn
            .prepare("SELECT profile_json FROM files WHERE path = ?1")?;
        let mut rows = stmt.query(params![path])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let profile: FileProfile = serde_json::from_str(&json)
                .map_err(|e| crate::FileDnaError::Unknown(e.to_string()))?;
            Ok(Some(profile))
        } else {
            Ok(None)
        }
    }

    pub fn save_job(&self, job: &AnalysisJob) -> Result<()> {
        self.conn.execute(
            r#"INSERT INTO jobs (id,root,status,files_discovered,files_completed,bytes_processed,errors,started,finished)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
               ON CONFLICT(id) DO UPDATE SET
                 status=excluded.status, files_discovered=excluded.files_discovered, files_completed=excluded.files_completed,
                 bytes_processed=excluded.bytes_processed, errors=excluded.errors, finished=excluded.finished"#,
            params![
                job.id,
                job.root.to_string_lossy().to_string(),
                format!("{:?}", job.status),
                job.files_discovered as i64,
                job.files_completed as i64,
                job.bytes_processed as i64,
                job.errors as i64,
                job.started.to_rfc3339(),
                job.finished.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub fn stats(&self) -> Result<(i64, i64, i64, i64)> {
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))?;
        let bytes: i64 = self
            .conn
            .query_row("SELECT IFNULL(SUM(size),0) FROM files", [], |r| r.get(0))?;
        let unknown: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM files WHERE format_id IS NULL",
            [],
            |r| r.get(0),
        )?;
        let dup_groups: i64 = 0;
        Ok((total, bytes, unknown, dup_groups))
    }
}

use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::models::{
    AuthType, BatchTaskSummary, ServerProfile, ServerUpsertPayload, TaskItemResult, TaskItemStatus,
    TaskResultPayload,
};

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|error| format!("Failed to open SQLite database: {error}"))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| format!("Failed to enable SQLite foreign keys: {error}"))?;
        let database = Self { conn };
        database.init_schema()?;
        Ok(database)
    }

    fn init_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS servers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    remember_password INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS host_keys (
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(host, port)
                );

                CREATE TABLE IF NOT EXISTS task_runs (
                    task_id TEXT PRIMARY KEY,
                    total INTEGER NOT NULL,
                    success INTEGER NOT NULL,
                    failed INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT
                );

                CREATE TABLE IF NOT EXISTS task_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    server_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    extracted_urls_json TEXT NOT NULL,
                    raw_log_ref TEXT NOT NULL,
                    raw_log TEXT NOT NULL,
                    error_code TEXT,
                    error_message TEXT,
                    FOREIGN KEY(task_id) REFERENCES task_runs(task_id) ON DELETE CASCADE
                );
                "#,
            )
            .map_err(|error| format!("Failed to initialize schema: {error}"))
    }

    pub fn list_servers(&self) -> Result<Vec<ServerProfile>, String> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                SELECT id, name, host, port, username, auth_type, remember_password, created_at, updated_at
                FROM servers
                ORDER BY created_at DESC
                "#,
            )
            .map_err(|error| format!("Failed to prepare list_servers query: {error}"))?;
        let mut rows = statement
            .query([])
            .map_err(|error| format!("Failed to query servers: {error}"))?;

        let mut servers = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|error| format!("Failed to iterate servers: {error}"))?
        {
            let parsed = Self::server_from_row(row)
                .map_err(|error| format!("Failed to parse server row: {error}"))?;
            servers.push(parsed);
        }
        Ok(servers)
    }

    pub fn get_server(&self, server_id: &str) -> Result<ServerProfile, String> {
        self.conn
            .query_row(
                r#"
                SELECT id, name, host, port, username, auth_type, remember_password, created_at, updated_at
                FROM servers
                WHERE id = ?1
                "#,
                params![server_id],
                Self::server_from_row,
            )
            .map_err(|error| format!("Failed to get server `{server_id}`: {error}"))
    }

    pub fn insert_server(
        &self,
        server_id: &str,
        payload: &ServerUpsertPayload,
        now: DateTime<Utc>,
    ) -> Result<ServerProfile, String> {
        self.conn
            .execute(
                r#"
                INSERT INTO servers (id, name, host, port, username, auth_type, remember_password, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    server_id,
                    payload.name.trim(),
                    payload.host.trim(),
                    i64::from(payload.port),
                    payload.username.trim(),
                    auth_type_to_db(&payload.auth_type),
                    payload.remember_password as i64,
                    now.to_rfc3339(),
                    now.to_rfc3339(),
                ],
            )
            .map_err(|error| format!("Failed to insert server `{server_id}`: {error}"))?;
        self.get_server(server_id)
    }

    pub fn update_server(
        &self,
        server_id: &str,
        payload: &ServerUpsertPayload,
        now: DateTime<Utc>,
    ) -> Result<ServerProfile, String> {
        self.conn
            .execute(
                r#"
                UPDATE servers
                SET name = ?2,
                    host = ?3,
                    port = ?4,
                    username = ?5,
                    auth_type = ?6,
                    remember_password = ?7,
                    updated_at = ?8
                WHERE id = ?1
                "#,
                params![
                    server_id,
                    payload.name.trim(),
                    payload.host.trim(),
                    i64::from(payload.port),
                    payload.username.trim(),
                    auth_type_to_db(&payload.auth_type),
                    payload.remember_password as i64,
                    now.to_rfc3339(),
                ],
            )
            .map_err(|error| format!("Failed to update server `{server_id}`: {error}"))?;
        self.get_server(server_id)
    }

    pub fn delete_server(&self, server_id: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM servers WHERE id = ?1", params![server_id])
            .map_err(|error| format!("Failed to delete server `{server_id}`: {error}"))?;
        Ok(())
    }

    pub fn get_host_key(&self, host: &str, port: u16) -> Result<Option<String>, String> {
        self.conn
            .query_row(
                "SELECT fingerprint FROM host_keys WHERE host = ?1 AND port = ?2",
                params![host.trim(), i64::from(port)],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| format!("Failed to read host key for {host}:{port}: {error}"))
    }

    pub fn upsert_host_key(&self, host: &str, port: u16, fingerprint: &str) -> Result<(), String> {
        self.conn
            .execute(
                r#"
                INSERT INTO host_keys (host, port, fingerprint, created_at)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(host, port)
                DO UPDATE SET fingerprint = excluded.fingerprint, created_at = excluded.created_at
                "#,
                params![
                    host.trim(),
                    i64::from(port),
                    fingerprint,
                    Utc::now().to_rfc3339()
                ],
            )
            .map_err(|error| format!("Failed to upsert host key for {host}:{port}: {error}"))?;
        Ok(())
    }

    pub fn save_task_result(
        &self,
        summary: &BatchTaskSummary,
        items: &[TaskItemResult],
        raw_logs: &std::collections::HashMap<String, String>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                r#"
                INSERT INTO task_runs (task_id, total, success, failed, started_at, finished_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(task_id)
                DO UPDATE SET
                    total = excluded.total,
                    success = excluded.success,
                    failed = excluded.failed,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at
                "#,
                params![
                    summary.task_id,
                    summary.total as i64,
                    summary.success as i64,
                    summary.failed as i64,
                    summary.started_at.to_rfc3339(),
                    summary.finished_at.map(|value| value.to_rfc3339())
                ],
            )
            .map_err(|error| format!("Failed to save task summary: {error}"))?;

        self.conn
            .execute(
                "DELETE FROM task_items WHERE task_id = ?1",
                params![summary.task_id],
            )
            .map_err(|error| format!("Failed to clear old task items: {error}"))?;

        for item in items {
            let urls_json = serde_json::to_string(&item.extracted_urls)
                .map_err(|error| format!("Failed to serialize extracted URLs: {error}"))?;
            let raw_log = raw_logs.get(&item.server_id).cloned().unwrap_or_default();
            self.conn
                .execute(
                    r#"
                    INSERT INTO task_items (
                        task_id,
                        server_id,
                        status,
                        phase,
                        extracted_urls_json,
                        raw_log_ref,
                        raw_log,
                        error_code,
                        error_message
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                    "#,
                    params![
                        summary.task_id,
                        item.server_id,
                        task_status_to_db(&item.status),
                        item.phase,
                        urls_json,
                        item.raw_log_ref,
                        raw_log,
                        item.error_code,
                        item.error_message,
                    ],
                )
                .map_err(|error| format!("Failed to save task item: {error}"))?;
        }

        Ok(())
    }

    pub fn get_task_result(&self, task_id: &str) -> Result<Option<TaskResultPayload>, String> {
        let summary_row: Option<(String, i64, i64, i64, String, Option<String>)> = self
            .conn
            .query_row(
                r#"
                SELECT task_id, total, success, failed, started_at, finished_at
                FROM task_runs
                WHERE task_id = ?1
                "#,
                params![task_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| format!("Failed to load task summary for `{task_id}`: {error}"))?;

        let Some((task_id, total, success, failed, started_at, finished_at)) = summary_row else {
            return Ok(None);
        };

        let started_at = DateTime::parse_from_rfc3339(&started_at)
            .map_err(|error| format!("Invalid task started_at: {error}"))?
            .with_timezone(&Utc);
        let finished_at = finished_at
            .map(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|error| format!("Invalid task finished_at: {error}"))
            })
            .transpose()?;

        let summary = BatchTaskSummary {
            task_id,
            total: total as usize,
            success: success as usize,
            failed: failed as usize,
            started_at,
            finished_at,
        };

        let mut statement = self
            .conn
            .prepare(
                r#"
                SELECT server_id, status, phase, extracted_urls_json, raw_log_ref, error_code, error_message
                FROM task_items
                WHERE task_id = ?1
                ORDER BY id ASC
                "#,
            )
            .map_err(|error| format!("Failed to prepare task items query: {error}"))?;

        let mut rows = statement
            .query(params![summary.task_id.clone()])
            .map_err(|error| format!("Failed to query task items: {error}"))?;
        let mut items = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|error| format!("Failed to iterate task items: {error}"))?
        {
            let extracted_urls_json: String = row
                .get(3)
                .map_err(|error| format!("Failed to read extracted URLs JSON: {error}"))?;
            let extracted_urls: Vec<String> = serde_json::from_str(&extracted_urls_json)
                .map_err(|error| format!("Failed to decode extracted URLs: {error}"))?;

            items.push(TaskItemResult {
                server_id: row
                    .get(0)
                    .map_err(|error| format!("Failed to read server_id from task item: {error}"))?,
                status: task_status_from_db(
                    &row.get::<_, String>(1)
                        .map_err(|error| format!("Failed to read task status: {error}"))?,
                )?,
                phase: row
                    .get(2)
                    .map_err(|error| format!("Failed to read task phase: {error}"))?,
                extracted_urls,
                raw_log_ref: row.get(4).map_err(|error| {
                    format!("Failed to read raw_log_ref from task item: {error}")
                })?,
                error_code: row.get(5).map_err(|error| {
                    format!("Failed to read error_code from task item: {error}")
                })?,
                error_message: row.get(6).map_err(|error| {
                    format!("Failed to read error_message from task item: {error}")
                })?,
            });
        }

        Ok(Some(TaskResultPayload { summary, items }))
    }

    fn server_from_row(row: &rusqlite::Row<'_>) -> Result<ServerProfile, rusqlite::Error> {
        let auth_type: String = row.get(5)?;
        let created_at: String = row.get(7)?;
        let updated_at: String = row.get(8)?;
        Ok(ServerProfile {
            id: row.get(0)?,
            name: row.get(1)?,
            host: row.get(2)?,
            port: row.get::<_, i64>(3)? as u16,
            username: row.get(4)?,
            auth_type: auth_type_from_db(&auth_type).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                )
            })?,
            remember_password: row.get::<_, i64>(6)? != 0,
            created_at: parse_rfc3339_to_utc(&created_at).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                )
            })?,
            updated_at: parse_rfc3339_to_utc(&updated_at).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                )
            })?,
        })
    }
}

fn parse_rfc3339_to_utc(input: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(input)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| format!("Failed to parse timestamp `{input}`: {error}"))
}

fn auth_type_to_db(value: &AuthType) -> &'static str {
    match value {
        AuthType::Password => "password",
        AuthType::Key => "key",
    }
}

fn auth_type_from_db(value: &str) -> Result<AuthType, String> {
    match value {
        "password" => Ok(AuthType::Password),
        "key" => Ok(AuthType::Key),
        _ => Err(format!("Unknown auth type in database: {value}")),
    }
}

fn task_status_to_db(value: &TaskItemStatus) -> &'static str {
    match value {
        TaskItemStatus::Success => "success",
        TaskItemStatus::Failed => "failed",
        TaskItemStatus::Skipped => "skipped",
    }
}

fn task_status_from_db(value: &str) -> Result<TaskItemStatus, String> {
    match value {
        "success" => Ok(TaskItemStatus::Success),
        "failed" => Ok(TaskItemStatus::Failed),
        "skipped" => Ok(TaskItemStatus::Skipped),
        _ => Err(format!("Unknown task status in database: {value}")),
    }
}

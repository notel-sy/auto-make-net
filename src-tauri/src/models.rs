use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Password,
    Key,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: AuthType,
    pub remember_password: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerUpsertPayload {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: AuthType,
    pub remember_password: bool,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAuth {
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub sudo_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Ok,
    UntrustedHost,
    HostKeyMismatch,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshPreflightResponse {
    pub status: PreflightStatus,
    pub fingerprint: Option<String>,
    pub is_root: Option<bool>,
    pub has_bash: Option<bool>,
    pub has_curl_or_wget: Option<bool>,
    pub can_sudo: Option<bool>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskMode {
    ListOnly,
    ListThenDeploy,
}

impl std::str::FromStr for TaskMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "list_only" => Ok(Self::ListOnly),
            "list_then_deploy" => Ok(Self::ListThenDeploy),
            _ => Err(format!("Unsupported task mode: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskItemStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskItemResult {
    pub server_id: String,
    pub status: TaskItemStatus,
    pub phase: String,
    pub extracted_urls: Vec<String>,
    pub raw_log_ref: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchTaskSummary {
    pub task_id: String,
    pub total: usize,
    pub success: usize,
    pub failed: usize,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResultPayload {
    pub summary: BatchTaskSummary,
    pub items: Vec<TaskItemResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvImportError {
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsvImportResult {
    pub imported: usize,
    pub failed: usize,
    pub errors: Vec<CsvImportError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskEvent {
    pub task_id: String,
    pub server_id: Option<String>,
    pub phase: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustHostPayload {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskRunAccepted {
    pub task_id: String,
    pub total: usize,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyArchiveImportResult {
    pub extracted_dir: String,
    pub file_count: usize,
    pub key_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedRuntimeAuth {
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub sudo_password: Option<String>,
}

impl ResolvedRuntimeAuth {
    pub fn to_secret_list(&self) -> Vec<String> {
        let mut values = Vec::new();
        if let Some(value) = &self.password {
            values.push(value.clone());
        }
        if let Some(value) = &self.private_key_passphrase {
            values.push(value.clone());
        }
        if let Some(value) = &self.sudo_password {
            values.push(value.clone());
        }
        values
    }
}

pub type RuntimeAuthMap = HashMap<String, RuntimeAuth>;

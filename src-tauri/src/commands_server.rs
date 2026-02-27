use tauri::State;

use crate::auth::{
    import_csv_record, resolve_runtime_auth, sync_saved_password, validate_csv_headers,
    validate_server_payload,
};
use crate::models::{
    CsvImportError, CsvImportResult, PreflightStatus, RuntimeAuth, ServerProfile,
    ServerUpsertPayload, SshPreflightResponse, TrustHostPayload,
};
use crate::security::redact_text;
use crate::ssh_client::{connect_ssh, run_preflight_checks};
use crate::state::AppState;

#[tauri::command]
pub async fn server_list(state: State<'_, AppState>) -> Result<Vec<ServerProfile>, String> {
    let db = state
        .database
        .lock()
        .map_err(|_| "Database lock poisoned".to_string())?;
    db.list_servers()
}

#[tauri::command]
pub async fn server_create(
    state: State<'_, AppState>,
    payload: ServerUpsertPayload,
) -> Result<ServerProfile, String> {
    validate_server_payload(&payload)?;

    let now = chrono::Utc::now();
    let server_id = uuid::Uuid::new_v4().to_string();
    let server = {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        db.insert_server(&server_id, &payload, now)?
    };

    sync_saved_password(&server.id, &payload)?;
    Ok(server)
}

#[tauri::command]
pub async fn server_update(
    state: State<'_, AppState>,
    server_id: String,
    payload: ServerUpsertPayload,
) -> Result<ServerProfile, String> {
    validate_server_payload(&payload)?;

    let now = chrono::Utc::now();
    let server = {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        db.update_server(&server_id, &payload, now)?
    };

    sync_saved_password(&server_id, &payload)?;
    Ok(server)
}

#[tauri::command]
pub async fn server_delete(state: State<'_, AppState>, server_id: String) -> Result<(), String> {
    {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        db.delete_server(&server_id)?;
    }
    crate::security::delete_server_password(&server_id)?;
    Ok(())
}

#[tauri::command]
pub async fn servers_import_csv(
    state: State<'_, AppState>,
    file_path: String,
) -> Result<CsvImportResult, String> {
    let mut reader = csv::Reader::from_path(&file_path)
        .map_err(|error| format!("Failed to open CSV file `{file_path}`: {error}"))?;

    let headers = reader
        .headers()
        .map_err(|error| format!("Failed to read CSV headers: {error}"))?
        .clone();
    validate_csv_headers(&headers)?;

    let mut imported = 0usize;
    let mut failed = 0usize;
    let mut errors = Vec::new();

    for (index, record_result) in reader.records().enumerate() {
        let line = index + 2;
        let record = match record_result {
            Ok(value) => value,
            Err(error) => {
                failed += 1;
                errors.push(CsvImportError {
                    line,
                    message: format!("Invalid CSV row: {error}"),
                });
                continue;
            }
        };

        match import_csv_record(state.inner(), &record) {
            Ok(_) => imported += 1,
            Err(message) => {
                failed += 1;
                errors.push(CsvImportError { line, message });
            }
        }
    }

    Ok(CsvImportResult {
        imported,
        failed,
        errors,
    })
}

#[tauri::command]
pub async fn hostkey_trust(
    state: State<'_, AppState>,
    payload: TrustHostPayload,
) -> Result<(), String> {
    let db = state
        .database
        .lock()
        .map_err(|_| "Database lock poisoned".to_string())?;
    db.upsert_host_key(&payload.host, payload.port, &payload.fingerprint)
}

#[tauri::command]
pub async fn ssh_preflight(
    state: State<'_, AppState>,
    server_id: String,
    runtime_auth: Option<RuntimeAuth>,
) -> Result<SshPreflightResponse, String> {
    let server = {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        db.get_server(&server_id)?
    };

    let resolved_auth = resolve_runtime_auth(&server, runtime_auth.as_ref())?;
    let secrets = resolved_auth.to_secret_list();

    let connection_result = tokio::task::spawn_blocking({
        let server = server.clone();
        let resolved_auth = resolved_auth.clone();
        move || connect_ssh(&server, &resolved_auth)
    })
    .await
    .map_err(|error| format!("Preflight join error: {error}"))??;

    let known_fingerprint = {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        db.get_host_key(&server.host, server.port)?
    };

    if known_fingerprint.is_none() {
        return Ok(SshPreflightResponse {
            status: PreflightStatus::UntrustedHost,
            fingerprint: Some(connection_result.fingerprint),
            is_root: None,
            has_bash: None,
            has_curl_or_wget: None,
            can_sudo: None,
            message: Some("First connection requires host fingerprint confirmation".to_string()),
        });
    }

    if known_fingerprint != Some(connection_result.fingerprint.clone()) {
        return Ok(SshPreflightResponse {
            status: PreflightStatus::HostKeyMismatch,
            fingerprint: Some(connection_result.fingerprint),
            is_root: None,
            has_bash: None,
            has_curl_or_wget: None,
            can_sudo: None,
            message: Some(
                "Host key mismatch detected; possible reinstalled host or MITM".to_string(),
            ),
        });
    }

    let checks = tokio::task::spawn_blocking({
        let auth = resolved_auth.clone();
        move || run_preflight_checks(&connection_result, &auth)
    })
    .await
    .map_err(|error| format!("Preflight checks join error: {error}"))??;

    let mut status = PreflightStatus::Ok;
    let mut message = None;

    if !checks.has_bash {
        status = PreflightStatus::Failed;
        message = Some("Remote system is missing `bash`".to_string());
    } else if !checks.has_curl_or_wget {
        status = PreflightStatus::Failed;
        message = Some("Remote system is missing both `curl` and `wget`".to_string());
    } else if !checks.is_root && !checks.can_sudo {
        status = PreflightStatus::Failed;
        message = Some("Remote user is not root and sudo is unavailable".to_string());
    }

    Ok(SshPreflightResponse {
        status,
        fingerprint: known_fingerprint,
        is_root: Some(checks.is_root),
        has_bash: Some(checks.has_bash),
        has_curl_or_wget: Some(checks.has_curl_or_wget),
        can_sudo: Some(checks.can_sudo),
        message: message.map(|value| redact_text(&value, &secrets)),
    })
}

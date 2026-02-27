use csv::StringRecord;
use uuid::Uuid;

use chrono::Utc;

use crate::models::{
    AuthType, ResolvedRuntimeAuth, RuntimeAuth, ServerProfile, ServerUpsertPayload,
};
use crate::security::{delete_server_password, get_server_password, set_server_password};
use crate::state::AppState;

pub fn validate_server_payload(payload: &ServerUpsertPayload) -> Result<(), String> {
    if payload.name.trim().is_empty() {
        return Err("Server name cannot be empty".to_string());
    }
    if payload.host.trim().is_empty() {
        return Err("Server host cannot be empty".to_string());
    }
    if payload.username.trim().is_empty() {
        return Err("Server username cannot be empty".to_string());
    }
    if payload.port == 0 {
        return Err("Server port must be greater than 0".to_string());
    }
    Ok(())
}

pub fn sync_saved_password(server_id: &str, payload: &ServerUpsertPayload) -> Result<(), String> {
    if payload.remember_password && matches!(payload.auth_type, AuthType::Password) {
        let Some(password) = payload.password.as_deref() else {
            return Err("rememberPassword=true requires password value".to_string());
        };
        if password.trim().is_empty() {
            return Err("Password cannot be empty when rememberPassword=true".to_string());
        }
        set_server_password(server_id, password)
    } else {
        delete_server_password(server_id)
    }
}

pub fn resolve_runtime_auth(
    server: &ServerProfile,
    runtime_auth: Option<&RuntimeAuth>,
) -> Result<ResolvedRuntimeAuth, String> {
    let runtime_auth = runtime_auth.cloned().unwrap_or_default();

    let saved_password = if server.remember_password {
        get_server_password(&server.id)?
    } else {
        None
    };

    let password = runtime_auth
        .password
        .clone()
        .or(saved_password.clone())
        .filter(|value| !value.trim().is_empty());

    let private_key_path = runtime_auth
        .private_key_path
        .clone()
        .filter(|value| !value.trim().is_empty());
    let private_key_passphrase = runtime_auth
        .private_key_passphrase
        .clone()
        .filter(|value| !value.trim().is_empty());

    let sudo_password = runtime_auth
        .sudo_password
        .clone()
        .or(password.clone())
        .filter(|value| !value.trim().is_empty());

    match server.auth_type {
        AuthType::Password => {
            if password.is_none() {
                return Err(format!(
                    "Server `{}` requires password at runtime or saved credential",
                    server.name
                ));
            }
        }
        AuthType::Key => {
            if private_key_path.is_none() {
                return Err(format!(
                    "Server `{}` requires runtime privateKeyPath",
                    server.name
                ));
            }
        }
    }

    Ok(ResolvedRuntimeAuth {
        password,
        private_key_path,
        private_key_passphrase,
        sudo_password,
    })
}

pub fn validate_csv_headers(headers: &StringRecord) -> Result<(), String> {
    let expected = [
        "name",
        "host",
        "port",
        "username",
        "auth_type",
        "password",
        "key_path",
    ];
    if headers.len() != expected.len() {
        return Err(format!(
            "CSV headers mismatch, expected `{}`",
            expected.join(",")
        ));
    }
    for (actual, expected_header) in headers.iter().zip(expected.iter()) {
        if actual.trim() != *expected_header {
            return Err(format!(
                "CSV header mismatch: expected `{expected_header}`, got `{actual}`"
            ));
        }
    }
    Ok(())
}

pub fn import_csv_record(state: &AppState, record: &StringRecord) -> Result<(), String> {
    let name = record.get(0).unwrap_or_default().trim().to_string();
    let host = record.get(1).unwrap_or_default().trim().to_string();
    let port = record
        .get(2)
        .unwrap_or_default()
        .trim()
        .parse::<u16>()
        .map_err(|error| format!("Invalid port: {error}"))?;
    let username = record.get(3).unwrap_or_default().trim().to_string();
    let auth_type_raw = record.get(4).unwrap_or_default().trim().to_lowercase();
    let password = record.get(5).unwrap_or_default().to_string();
    let key_path = record.get(6).unwrap_or_default().trim().to_string();

    let auth_type = match auth_type_raw.as_str() {
        "password" => AuthType::Password,
        "key" => AuthType::Key,
        other => return Err(format!("Invalid auth_type `{other}`")),
    };

    match auth_type {
        AuthType::Password if password.trim().is_empty() => {
            return Err("auth_type=password requires a non-empty password column".to_string());
        }
        AuthType::Key if key_path.is_empty() => {
            return Err("auth_type=key requires a non-empty key_path column".to_string());
        }
        _ => {}
    }

    let payload = ServerUpsertPayload {
        name,
        host,
        port,
        username,
        auth_type: auth_type.clone(),
        remember_password: matches!(auth_type, AuthType::Password) && !password.trim().is_empty(),
        password: if password.trim().is_empty() {
            None
        } else {
            Some(password)
        },
    };

    validate_server_payload(&payload)?;

    let now = Utc::now();
    let server_id = Uuid::new_v4().to_string();
    {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        let _ = db.insert_server(&server_id, &payload, now)?;
    }
    sync_saved_password(&server_id, &payload)?;
    Ok(())
}

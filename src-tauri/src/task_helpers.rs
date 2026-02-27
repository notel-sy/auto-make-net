use crate::models::TaskEvent;
use crate::ssh_client::{run_privileged_command, CommandResult, PreflightFacts};
use crate::task_types::{KnownHostEntry, TrustCheckResult};
use crate::utils::{append_command_log, FALLBACK_LIST_COMMAND, PRIMARY_LIST_COMMAND};
use tauri::Emitter;

pub fn emit_task_event(app: &tauri::AppHandle, task_id: &str, event: TaskEvent) {
    let _ = app.emit(&crate::utils::task_event_name(task_id), event);
}

pub fn verify_known_host(
    known_host: &KnownHostEntry,
    current_fingerprint: &str,
) -> TrustCheckResult {
    match &known_host.fingerprint {
        Some(saved) if saved == current_fingerprint => TrustCheckResult {
            is_trusted: true,
            is_mismatch: false,
        },
        Some(_) => TrustCheckResult {
            is_trusted: false,
            is_mismatch: true,
        },
        None => TrustCheckResult {
            is_trusted: false,
            is_mismatch: false,
        },
    }
}

pub fn preflight_fail_reason(preflight: &PreflightFacts) -> Option<String> {
    if !preflight.has_bash {
        return Some("Remote system is missing bash".to_string());
    }
    if !preflight.has_curl_or_wget {
        return Some("Remote system is missing both curl and wget".to_string());
    }
    if !preflight.is_root && !preflight.can_sudo {
        return Some("Remote user is not root and sudo is unavailable".to_string());
    }
    None
}

pub fn execute_list_command(
    connection: &crate::ssh_client::ConnectedSession,
    is_root: bool,
    sudo_password: Option<&str>,
    collected_log: &mut String,
) -> Result<CommandResult, String> {
    let primary = run_privileged_command(connection, PRIMARY_LIST_COMMAND, is_root, sudo_password)
        .map_err(|error| format!("Primary list command failed: {error}"))?;
    append_command_log(collected_log, &primary);

    if primary.exit_status == 0 {
        return Ok(primary);
    }

    let fallback = run_privileged_command(connection, FALLBACK_LIST_COMMAND, is_root, sudo_password)
        .map_err(|error| format!("Fallback list command failed: {error}"))?;
    append_command_log(collected_log, &fallback);

    if fallback.exit_status == 0 {
        Ok(fallback)
    } else {
        Err(format!(
            "Both list commands failed. primary_exit={} fallback_exit={}",
            primary.exit_status, fallback.exit_status
        ))
    }
}

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use tauri::AppHandle;
use tokio::sync::{mpsc, Semaphore};

use crate::auth::resolve_runtime_auth;
use crate::models::{RuntimeAuth, TaskEvent, TaskItemResult, TaskItemStatus, TaskMode};
use crate::security::redact_text;
use crate::ssh_client::{connect_ssh, run_preflight_checks, run_privileged_command};
use crate::state::{AppState, TaskRuntimeHandle};
use crate::task_helpers::{
    emit_task_event, execute_list_command, preflight_fail_reason, verify_known_host,
};
use crate::task_types::{KnownHostEntry, RunServerFailure, RunServerOutcome, RunServerSuccess};
use crate::utils::{
    extract_subscription_links, output_contains_deploy_failed_marker,
    output_contains_not_installed_marker, raw_log_ref, DEFAULT_DEPLOY_COMMAND,
    DEPLOY_DIAGNOSTIC_COMMAND, DEPLOY_PORT_RESET_COMMAND, MANUAL_RECOVERY_START_COMMAND,
};

fn push_progress_event(
    tx: &mpsc::UnboundedSender<(String, String)>,
    phase: &str,
    message: impl Into<String>,
) {
    let _ = tx.send((phase.to_string(), message.into()));
}

pub async fn run_batch_task(
    app: AppHandle,
    state: AppState,
    task_id: String,
    servers: Vec<crate::models::ServerProfile>,
    known_hosts: Vec<KnownHostEntry>,
    mode: TaskMode,
    runtime_auths: crate::models::RuntimeAuthMap,
    parallel_limit: usize,
    runtime_handle: TaskRuntimeHandle,
) {
    emit_task_event(
        &app,
        &task_id,
        TaskEvent {
            task_id: task_id.clone(),
            server_id: None,
            phase: "queued".to_string(),
            message: format!("Task accepted for {} server(s)", servers.len()),
            timestamp: Utc::now(),
        },
    );

    let semaphore = Arc::new(Semaphore::new(parallel_limit));
    let mut handles = Vec::new();

    for (index, server) in servers.into_iter().enumerate() {
        let Some(known_host) = known_hosts.get(index).cloned() else {
            continue;
        };

        let app = app.clone();
        let state = state.clone();
        let task_id = task_id.clone();
        let mode = mode.clone();
        let runtime_handle = runtime_handle.clone();
        let runtime_auth = runtime_auths.get(&server.id).cloned();
        let semaphore = semaphore.clone();

        handles.push(tauri::async_runtime::spawn(async move {
            let permit = semaphore.acquire_owned().await;
            if permit.is_err() {
                return;
            }
            let _permit = permit.expect("semaphore permit should exist");

            let outcome = run_server_task(
                &app,
                &state,
                &task_id,
                &server,
                &known_host,
                mode,
                runtime_auth,
                runtime_handle.cancelled.clone(),
            )
            .await;

            apply_server_outcome(&runtime_handle, server.id.clone(), outcome).await;
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    {
        let mut data = runtime_handle.data.lock().await;
        data.summary.finished_at = Some(Utc::now());
        let mut success = 0usize;
        let mut failed = 0usize;
        for item in data.items.values() {
            match item.status {
                TaskItemStatus::Success => success += 1,
                TaskItemStatus::Failed => failed += 1,
                TaskItemStatus::Skipped => {}
            }
        }
        data.summary.success = success;
        data.summary.failed = failed;

        if let Ok(db) = state.database.lock() {
            let items = data.items.values().cloned().collect::<Vec<_>>();
            let raw_logs = data
                .raw_logs
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<HashMap<_, _>>();
            let _ = db.save_task_result(&data.summary, &items, &raw_logs);
        }
    }

    emit_task_event(
        &app,
        &task_id,
        TaskEvent {
            task_id: task_id.clone(),
            server_id: None,
            phase: "done".to_string(),
            message: "Task finished".to_string(),
            timestamp: Utc::now(),
        },
    );
}

async fn run_server_task(
    app: &AppHandle,
    state: &AppState,
    task_id: &str,
    server: &crate::models::ServerProfile,
    known_host: &KnownHostEntry,
    mode: TaskMode,
    runtime_auth: Option<RuntimeAuth>,
    cancelled: Arc<AtomicBool>,
) -> RunServerOutcome {
    if cancelled.load(Ordering::SeqCst) {
        return RunServerOutcome::Skipped;
    }

    let resolved_auth = match resolve_runtime_auth(server, runtime_auth.as_ref()) {
        Ok(value) => value,
        Err(message) => {
            return RunServerOutcome::Failure(RunServerFailure {
                phase: "connecting".to_string(),
                code: "AUTH_RESOLVE_FAILED".to_string(),
                message,
                raw_log: String::new(),
            });
        }
    };

    emit_task_event(
        app,
        task_id,
        TaskEvent {
            task_id: task_id.to_string(),
            server_id: Some(server.id.clone()),
            phase: "connecting".to_string(),
            message: format!("Connecting {}:{}", server.host, server.port),
            timestamp: Utc::now(),
        },
    );

    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<(String, String)>();
    let app_for_progress = app.clone();
    let task_id_for_progress = task_id.to_string();
    let server_id_for_progress = server.id.clone();
    let progress_forwarder = tauri::async_runtime::spawn(async move {
        while let Some((phase, message)) = progress_rx.recv().await {
            emit_task_event(
                &app_for_progress,
                &task_id_for_progress,
                TaskEvent {
                    task_id: task_id_for_progress.clone(),
                    server_id: Some(server_id_for_progress.clone()),
                    phase,
                    message,
                    timestamp: Utc::now(),
                },
            );
        }
    });

    let secrets = resolved_auth.to_secret_list();
    let outcome = tokio::task::spawn_blocking({
        let database = state.database.clone();
        let server = server.clone();
        let known_host = known_host.clone();
        let resolved_auth = resolved_auth.clone();
        let cancelled = cancelled.clone();
        let progress_tx = progress_tx.clone();
        move || {
            run_server_task_blocking(
                &server,
                &known_host,
                mode,
                &resolved_auth,
                cancelled,
                database,
                progress_tx,
            )
        }
    })
    .await;

    drop(progress_tx);
    let _ = progress_forwarder.await;

    match outcome {
        Ok(RunServerOutcome::Success(mut success)) => {
            success.raw_log = redact_text(&success.raw_log, &secrets);
            emit_task_event(
                app,
                task_id,
                TaskEvent {
                    task_id: task_id.to_string(),
                    server_id: Some(server.id.clone()),
                    phase: success.final_phase.clone(),
                    message: format!("Completed with {} extracted URL(s)", success.urls.len()),
                    timestamp: Utc::now(),
                },
            );
            RunServerOutcome::Success(success)
        }
        Ok(RunServerOutcome::Failure(mut failure)) => {
            failure.raw_log = redact_text(&failure.raw_log, &secrets);
            failure.message = redact_text(&failure.message, &secrets);
            emit_task_event(
                app,
                task_id,
                TaskEvent {
                    task_id: task_id.to_string(),
                    server_id: Some(server.id.clone()),
                    phase: failure.phase.clone(),
                    message: failure.message.clone(),
                    timestamp: Utc::now(),
                },
            );
            RunServerOutcome::Failure(failure)
        }
        Ok(RunServerOutcome::Skipped) => {
            emit_task_event(
                app,
                task_id,
                TaskEvent {
                    task_id: task_id.to_string(),
                    server_id: Some(server.id.clone()),
                    phase: "skipped".to_string(),
                    message: "Skipped due to cancellation".to_string(),
                    timestamp: Utc::now(),
                },
            );
            RunServerOutcome::Skipped
        }
        Err(error) => {
            let failure = RunServerFailure {
                phase: "connecting".to_string(),
                code: "TASK_JOIN_FAILED".to_string(),
                message: format!("Task execution join failed: {error}"),
                raw_log: String::new(),
            };
            emit_task_event(
                app,
                task_id,
                TaskEvent {
                    task_id: task_id.to_string(),
                    server_id: Some(server.id.clone()),
                    phase: failure.phase.clone(),
                    message: failure.message.clone(),
                    timestamp: Utc::now(),
                },
            );
            RunServerOutcome::Failure(failure)
        }
    }
}

fn run_server_task_blocking(
    server: &crate::models::ServerProfile,
    known_host: &KnownHostEntry,
    mode: TaskMode,
    auth: &crate::models::ResolvedRuntimeAuth,
    cancelled: Arc<AtomicBool>,
    database: Arc<Mutex<crate::db::Database>>,
    progress_tx: mpsc::UnboundedSender<(String, String)>,
) -> RunServerOutcome {
    let mut collected_log = String::new();

    if cancelled.load(Ordering::SeqCst) {
        return RunServerOutcome::Skipped;
    }

    let connected = match connect_ssh(server, auth) {
        Ok(value) => value,
        Err(message) => {
            return RunServerOutcome::Failure(RunServerFailure {
                phase: "connecting".to_string(),
                code: "SSH_CONNECT_FAILED".to_string(),
                message,
                raw_log: collected_log,
            });
        }
    };
    push_progress_event(
        &progress_tx,
        "preflight",
        format!("SSH connected. fingerprint={}", connected.fingerprint),
    );

    let trust_check = verify_known_host(known_host, &connected.fingerprint);
    if !trust_check.is_trusted {
        if trust_check.is_mismatch {
            let expected = known_host
                .fingerprint
                .clone()
                .unwrap_or_else(|| "<none>".to_string());
            return RunServerOutcome::Failure(RunServerFailure {
                phase: "preflight".to_string(),
                code: "HOST_KEY_MISMATCH".to_string(),
                message: format!(
                    "Host key mismatch. expected={} actual={}",
                    expected, connected.fingerprint
                ),
                raw_log: collected_log,
            });
        }

        let save_result = database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())
            .and_then(|db| db.upsert_host_key(&server.host, server.port, &connected.fingerprint));
        if let Err(error) = save_result {
            return RunServerOutcome::Failure(RunServerFailure {
                phase: "preflight".to_string(),
                code: "UNTRUSTED_HOST".to_string(),
                message: format!(
                    "Host key first-seen auto trust failed: {} (fingerprint={})",
                    error, connected.fingerprint
                ),
                raw_log: collected_log,
            });
        }

        collected_log.push_str(&format!(
            "[info] First-seen host key auto-trusted: {}:{} => {}\n",
            server.host, server.port, connected.fingerprint
        ));
        push_progress_event(
            &progress_tx,
            "preflight",
            "首次连接指纹已自动信任（TOFU）",
        );
    }

    push_progress_event(&progress_tx, "preflight", "执行远端环境预检");
    let preflight = match run_preflight_checks(&connected, auth) {
        Ok(value) => value,
        Err(message) => {
            return RunServerOutcome::Failure(RunServerFailure {
                phase: "preflight".to_string(),
                code: "PREFLIGHT_FAILED".to_string(),
                message,
                raw_log: collected_log,
            });
        }
    };
    if let Some(reason) = preflight_fail_reason(&preflight) {
        return RunServerOutcome::Failure(RunServerFailure {
            phase: "preflight".to_string(),
            code: "PREFLIGHT_INVALID".to_string(),
            message: reason,
            raw_log: collected_log,
        });
    }
    push_progress_event(
        &progress_tx,
        "preflight",
        "预检通过，开始执行 list",
    );

    let sudo_password = auth.sudo_password.as_deref().or(auth.password.as_deref());
    push_progress_event(&progress_tx, "list", "执行初次 list 查询");
    let initial_list = match execute_list_command(
        &connected,
        preflight.is_root,
        sudo_password,
        &mut collected_log,
    ) {
        Ok(value) => value,
        Err(message) => {
            return RunServerOutcome::Failure(RunServerFailure {
                phase: "list".to_string(),
                code: "LIST_FAILED".to_string(),
                message,
                raw_log: collected_log,
            });
        }
    };

    if matches!(mode, TaskMode::ListOnly)
        && output_contains_not_installed_marker(&initial_list.stdout, &initial_list.stderr)
    {
        return RunServerOutcome::Failure(RunServerFailure {
            phase: "list".to_string(),
            code: "ARGOSBX_NOT_INSTALLED".to_string(),
            message: "Argosbx script appears to be not installed on remote host".to_string(),
            raw_log: collected_log,
        });
    }

    let mut deploy_had_warning = false;
    let mut deploy_warning_message = String::new();

    if matches!(mode, TaskMode::ListThenDeploy) {
        push_progress_event(&progress_tx, "deploy", "执行部署命令");
        match run_privileged_command(
            &connected,
            DEFAULT_DEPLOY_COMMAND,
            preflight.is_root,
            sudo_password,
        ) {
            Ok(result) => {
                crate::utils::append_command_log(&mut collected_log, &result);
                if output_contains_deploy_failed_marker(&result.stdout, &result.stderr) {
                    deploy_had_warning = true;
                    deploy_warning_message =
                        "Argosbx script output indicates deploy failure".to_string();
                } else if result.exit_status != 0 {
                    deploy_had_warning = true;
                    deploy_warning_message = format!("Deploy exit status {}", result.exit_status);
                }
                if deploy_had_warning {
                    collected_log.push_str(&format!(
                        "[warn] {}. Will verify with list and retry deploy once if still not installed.\n",
                        deploy_warning_message
                    ));
                    push_progress_event(
                        &progress_tx,
                        "deploy",
                        format!("部署警告：{}", deploy_warning_message),
                    );
                }
            }
            Err(message) => {
                return RunServerOutcome::Failure(RunServerFailure {
                    phase: "deploy".to_string(),
                    code: "DEPLOY_FAILED".to_string(),
                    message,
                    raw_log: collected_log,
                });
            }
        }
    }

    push_progress_event(&progress_tx, "list", "执行部署后 list 验证");
    let mut final_list = match execute_list_command(
        &connected,
        preflight.is_root,
        sudo_password,
        &mut collected_log,
    ) {
        Ok(value) => value,
        Err(message) => {
            return RunServerOutcome::Failure(RunServerFailure {
                phase: "list".to_string(),
                code: "LIST_FAILED".to_string(),
                message,
                raw_log: collected_log,
            });
        }
    };

    if matches!(mode, TaskMode::ListThenDeploy)
        && output_contains_not_installed_marker(&final_list.stdout, &final_list.stderr)
    {
        collected_log
            .push_str("[warn] Post-deploy list indicates not installed. Retrying deploy once.\n");
        push_progress_event(
            &progress_tx,
            "deploy",
            "部署后未安装，执行重试部署",
        );

        let retry_result = match run_privileged_command(
            &connected,
            DEFAULT_DEPLOY_COMMAND,
            preflight.is_root,
            sudo_password,
        ) {
            Ok(result) => result,
            Err(message) => {
                return RunServerOutcome::Failure(RunServerFailure {
                    phase: "deploy".to_string(),
                    code: "DEPLOY_FAILED".to_string(),
                    message: format!("Retry deploy failed: {message}"),
                    raw_log: collected_log,
                });
            }
        };
        crate::utils::append_command_log(&mut collected_log, &retry_result);
        if output_contains_deploy_failed_marker(&retry_result.stdout, &retry_result.stderr) {
            collected_log.push_str("[warn] Retry deploy output still indicates failure.\n");
        }
        if retry_result.exit_status != 0 {
            collected_log.push_str(&format!(
                "[warn] Retry deploy exit status {}.\n",
                retry_result.exit_status
            ));
        }

        final_list = match execute_list_command(
            &connected,
            preflight.is_root,
            sudo_password,
            &mut collected_log,
        ) {
            Ok(value) => value,
            Err(message) => {
                return RunServerOutcome::Failure(RunServerFailure {
                    phase: "list".to_string(),
                    code: "LIST_FAILED".to_string(),
                    message,
                    raw_log: collected_log,
                });
            }
        };
    }

    if matches!(mode, TaskMode::ListThenDeploy)
        && output_contains_not_installed_marker(&final_list.stdout, &final_list.stderr)
    {
        collected_log
            .push_str("[warn] Deploy still appears incomplete. Waiting and re-checking list.\n");
        push_progress_event(
            &progress_tx,
            "list",
            "部署疑似未完成，等待后重查",
        );
        for wait_seconds in [8u8, 12u8] {
            let wait_command = format!("sleep {wait_seconds}");
            if let Ok(wait_result) = run_privileged_command(
                &connected,
                &wait_command,
                preflight.is_root,
                sudo_password,
            ) {
                crate::utils::append_command_log(&mut collected_log, &wait_result);
            }

            let delayed_list = match execute_list_command(
                &connected,
                preflight.is_root,
                sudo_password,
                &mut collected_log,
            ) {
                Ok(value) => value,
                Err(message) => {
                    return RunServerOutcome::Failure(RunServerFailure {
                        phase: "list".to_string(),
                        code: "LIST_FAILED".to_string(),
                        message,
                        raw_log: collected_log,
                    });
                }
            };

            if !output_contains_not_installed_marker(&delayed_list.stdout, &delayed_list.stderr) {
                final_list = delayed_list;
                break;
            }
        }
    }

    if matches!(mode, TaskMode::ListThenDeploy)
        && output_contains_not_installed_marker(&final_list.stdout, &final_list.stderr)
    {
        collected_log.push_str("[warn] Attempting manual process start recovery.\n");
        push_progress_event(&progress_tx, "deploy", "尝试手动拉起核心进程恢复");
        match run_privileged_command(
            &connected,
            MANUAL_RECOVERY_START_COMMAND,
            preflight.is_root,
            sudo_password,
        ) {
            Ok(result) => crate::utils::append_command_log(&mut collected_log, &result),
            Err(message) => {
                collected_log.push_str(&format!(
                    "[warn] Manual process start command failed: {message}\n"
                ));
            }
        }

        let recovered_list = match execute_list_command(
            &connected,
            preflight.is_root,
            sudo_password,
            &mut collected_log,
        ) {
            Ok(value) => value,
            Err(message) => {
                return RunServerOutcome::Failure(RunServerFailure {
                    phase: "list".to_string(),
                    code: "LIST_FAILED".to_string(),
                    message,
                    raw_log: collected_log,
                });
            }
        };
        final_list = recovered_list;
    }

    if matches!(mode, TaskMode::ListThenDeploy)
        && output_contains_not_installed_marker(&final_list.stdout, &final_list.stderr)
    {
        collected_log.push_str(
            "[warn] Manual recovery did not recover install state. Resetting ports/config and redeploying once.\n",
        );
        push_progress_event(
            &progress_tx,
            "deploy",
            "手动恢复失败，重置端口配置并再次部署",
        );
        match run_privileged_command(
            &connected,
            DEPLOY_PORT_RESET_COMMAND,
            preflight.is_root,
            sudo_password,
        ) {
            Ok(result) => crate::utils::append_command_log(&mut collected_log, &result),
            Err(message) => {
                collected_log.push_str(&format!(
                    "[warn] Deploy reset command failed: {message}\n"
                ));
            }
        }

        match run_privileged_command(
            &connected,
            DEFAULT_DEPLOY_COMMAND,
            preflight.is_root,
            sudo_password,
        ) {
            Ok(result) => {
                crate::utils::append_command_log(&mut collected_log, &result);
                if output_contains_deploy_failed_marker(&result.stdout, &result.stderr) {
                    collected_log.push_str(
                        "[warn] Redeploy after reset still reports deploy failure marker.\n",
                    );
                }
                if result.exit_status != 0 {
                    collected_log.push_str(&format!(
                        "[warn] Redeploy after reset exit status {}.\n",
                        result.exit_status
                    ));
                }
            }
            Err(message) => {
                collected_log.push_str(&format!(
                    "[warn] Redeploy after reset command failed: {message}\n"
                ));
            }
        }

        final_list = match execute_list_command(
            &connected,
            preflight.is_root,
            sudo_password,
            &mut collected_log,
        ) {
            Ok(value) => value,
            Err(message) => {
                return RunServerOutcome::Failure(RunServerFailure {
                    phase: "list".to_string(),
                    code: "LIST_FAILED".to_string(),
                    message,
                    raw_log: collected_log,
                });
            }
        };
    }

    if matches!(mode, TaskMode::ListThenDeploy)
        && output_contains_not_installed_marker(&final_list.stdout, &final_list.stderr)
    {
        collected_log.push_str("[warn] Collecting remote diagnostics before failing.\n");
        push_progress_event(&progress_tx, "deploy", "采集远端诊断日志");
        match run_privileged_command(
            &connected,
            DEPLOY_DIAGNOSTIC_COMMAND,
            preflight.is_root,
            sudo_password,
        ) {
            Ok(result) => crate::utils::append_command_log(&mut collected_log, &result),
            Err(message) => {
                collected_log.push_str(&format!(
                    "[warn] Diagnostic command failed: {message}\n"
                ));
            }
        }
    }

    if output_contains_not_installed_marker(&final_list.stdout, &final_list.stderr) {
        let message = if matches!(mode, TaskMode::ListThenDeploy) {
            if deploy_had_warning {
                format!(
                    "Argosbx still not installed after deploy verify/retry/recovery. Initial warning: {}",
                    deploy_warning_message
                )
            } else {
                "Argosbx script not installed or not initialized after deploy/recovery".to_string()
            }
        } else {
            "Argosbx script appears to be not installed on remote host".to_string()
        };
        return RunServerOutcome::Failure(RunServerFailure {
            phase: "list".to_string(),
            code: "ARGOSBX_NOT_INSTALLED".to_string(),
            message,
            raw_log: collected_log,
        });
    }

    push_progress_event(&progress_tx, "parse", "解析订阅/节点链接");
    let urls = extract_subscription_links(&format!("{}\n{}", final_list.stdout, final_list.stderr));

    RunServerOutcome::Success(RunServerSuccess {
        urls,
        raw_log: collected_log,
        final_phase: "done".to_string(),
    })
}

async fn apply_server_outcome(
    runtime_handle: &TaskRuntimeHandle,
    server_id: String,
    outcome: RunServerOutcome,
) {
    let mut data = runtime_handle.data.lock().await;
    match outcome {
        RunServerOutcome::Success(success) => {
            let raw_log_ref = raw_log_ref(&data.summary.task_id, &server_id);
            data.items.insert(
                server_id.clone(),
                TaskItemResult {
                    server_id: server_id.clone(),
                    status: TaskItemStatus::Success,
                    phase: success.final_phase,
                    extracted_urls: success.urls,
                    raw_log_ref,
                    error_code: None,
                    error_message: None,
                },
            );
            data.raw_logs.insert(server_id, success.raw_log);
        }
        RunServerOutcome::Failure(failure) => {
            let raw_log_ref = raw_log_ref(&data.summary.task_id, &server_id);
            data.items.insert(
                server_id.clone(),
                TaskItemResult {
                    server_id: server_id.clone(),
                    status: TaskItemStatus::Failed,
                    phase: failure.phase,
                    extracted_urls: Vec::new(),
                    raw_log_ref,
                    error_code: Some(failure.code),
                    error_message: Some(failure.message),
                },
            );
            data.raw_logs.insert(server_id, failure.raw_log);
        }
        RunServerOutcome::Skipped => {
            let raw_log_ref = raw_log_ref(&data.summary.task_id, &server_id);
            data.items.insert(
                server_id.clone(),
                TaskItemResult {
                    server_id: server_id.clone(),
                    status: TaskItemStatus::Skipped,
                    phase: "skipped".to_string(),
                    extracted_urls: Vec::new(),
                    raw_log_ref,
                    error_code: Some("TASK_CANCELLED".to_string()),
                    error_message: Some("Task cancelled".to_string()),
                },
            );
            data.raw_logs
                .entry(server_id)
                .or_insert_with(|| "Task cancelled before completion".to_string());
        }
    }
}

use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use chrono::Utc;
use tauri::{AppHandle, State};
use tokio::sync::Mutex as AsyncMutex;

use crate::models::{
    BatchTaskSummary, RuntimeAuthMap, TaskMode, TaskResultPayload, TaskRunAccepted,
};
use crate::state::{AppState, TaskRuntimeData, TaskRuntimeHandle};
use crate::task_types::KnownHostEntry;
use crate::task_worker::run_batch_task;
use crate::utils::{resolve_export_path, status_label, task_event_name, DEFAULT_PARALLEL_LIMIT};

#[tauri::command]
pub fn task_stream_subscribe(task_id: String) -> Result<String, String> {
    if task_id.trim().is_empty() {
        return Err("task_id cannot be empty".to_string());
    }
    Ok(task_event_name(&task_id))
}

#[tauri::command]
pub async fn task_run(
    app: AppHandle,
    state: State<'_, AppState>,
    server_ids: Vec<String>,
    mode: String,
    runtime_auths: Option<RuntimeAuthMap>,
    parallel_limit: Option<usize>,
) -> Result<TaskRunAccepted, String> {
    if server_ids.is_empty() {
        return Err("At least one server_id is required".to_string());
    }

    let parsed_mode = TaskMode::from_str(mode.trim())?;

    let servers = {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;

        let mut values = Vec::new();
        for server_id in &server_ids {
            values.push(db.get_server(server_id)?);
        }
        values
    };

    let known_hosts = {
        let db = state
            .database
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        servers
            .iter()
            .map(|server| {
                db.get_host_key(&server.host, server.port)
                    .map(|fingerprint| KnownHostEntry { fingerprint })
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    let task_id = uuid::Uuid::new_v4().to_string();
    let started_at = Utc::now();
    let summary = BatchTaskSummary {
        task_id: task_id.clone(),
        total: servers.len(),
        success: 0,
        failed: 0,
        started_at,
        finished_at: None,
    };

    let runtime_handle = TaskRuntimeHandle {
        data: Arc::new(AsyncMutex::new(TaskRuntimeData {
            summary: summary.clone(),
            items: std::collections::BTreeMap::new(),
            raw_logs: std::collections::BTreeMap::new(),
        })),
        cancelled: Arc::new(AtomicBool::new(false)),
    };

    {
        let mut tasks = state.tasks.lock().await;
        tasks.insert(task_id.clone(), runtime_handle.clone());
    }

    let state_clone = state.inner().clone();
    let app_clone = app.clone();
    let runtime_auths = runtime_auths.unwrap_or_default();
    let task_id_clone = task_id.clone();
    let limit = parallel_limit.unwrap_or(DEFAULT_PARALLEL_LIMIT).max(1);

    tauri::async_runtime::spawn(async move {
        run_batch_task(
            app_clone,
            state_clone,
            task_id_clone,
            servers,
            known_hosts,
            parsed_mode,
            runtime_auths,
            limit,
            runtime_handle,
        )
        .await;
    });

    Ok(TaskRunAccepted {
        task_id,
        total: summary.total,
        started_at,
    })
}

#[tauri::command]
pub async fn task_cancel(state: State<'_, AppState>, task_id: String) -> Result<(), String> {
    let tasks = state.tasks.lock().await;
    let Some(task) = tasks.get(&task_id) else {
        return Err(format!("Task `{task_id}` not found"));
    };
    task.cancelled
        .store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
pub async fn result_get(
    state: State<'_, AppState>,
    task_id: String,
) -> Result<TaskResultPayload, String> {
    if let Some(result) = snapshot_task_result(state.inner().clone(), &task_id).await? {
        return Ok(result);
    }

    let db = state
        .database
        .lock()
        .map_err(|_| "Database lock poisoned".to_string())?;
    db.get_task_result(&task_id)?
        .ok_or_else(|| format!("Task result `{task_id}` not found"))
}

#[tauri::command]
pub async fn result_export_txt(
    state: State<'_, AppState>,
    task_id: String,
    output_path: Option<String>,
) -> Result<String, String> {
    let result =
        if let Some(snapshot) = snapshot_task_result(state.inner().clone(), &task_id).await? {
            snapshot
        } else {
            let db = state
                .database
                .lock()
                .map_err(|_| "Database lock poisoned".to_string())?;
            db.get_task_result(&task_id)?
                .ok_or_else(|| format!("Task result `{task_id}` not found"))?
        };

    let destination = resolve_export_path(output_path)?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create export directory `{}`: {error}",
                parent.display()
            )
        })?;
    }

    let db = state
        .database
        .lock()
        .map_err(|_| "Database lock poisoned".to_string())?;

    let mut output = String::new();
    output.push_str(&format!(
        "Task: {}\nStarted: {}\nFinished: {}\nTotal: {} Success: {} Failed: {}\n\n",
        result.summary.task_id,
        result.summary.started_at.to_rfc3339(),
        result
            .summary
            .finished_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "running".to_string()),
        result.summary.total,
        result.summary.success,
        result.summary.failed,
    ));

    for item in result.items {
        let server_name = db
            .get_server(&item.server_id)
            .map(|server| format!("{} ({})", server.name, server.host))
            .unwrap_or_else(|_| item.server_id.clone());

        output.push_str(&format!(
            "[{}] {}\n",
            status_label(&item.status),
            server_name
        ));
        for url in &item.extracted_urls {
            output.push_str(&format!("  {url}\n"));
        }
        if let Some(message) = &item.error_message {
            output.push_str(&format!("  error: {message}\n"));
        }
        output.push('\n');
    }

    std::fs::write(&destination, output).map_err(|error| {
        format!(
            "Failed to write export file `{}`: {error}",
            destination.display()
        )
    })?;

    Ok(destination.to_string_lossy().to_string())
}

async fn snapshot_task_result(
    state: AppState,
    task_id: &str,
) -> Result<Option<TaskResultPayload>, String> {
    let handle = {
        let tasks = state.tasks.lock().await;
        tasks.get(task_id).cloned()
    };

    let Some(handle) = handle else {
        return Ok(None);
    };

    let data = handle.data.lock().await;
    let items = data.items.values().cloned().collect::<Vec<_>>();
    Ok(Some(TaskResultPayload {
        summary: data.summary.clone(),
        items,
    }))
}

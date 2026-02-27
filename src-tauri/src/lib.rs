mod auth;
mod commands_key;
mod commands_server;
mod commands_task;
mod db;
mod models;
mod security;
mod ssh_client;
mod state;
mod task_helpers;
mod task_types;
mod task_worker;
mod utils;

use std::path::Path;
use std::sync::{Arc, Mutex};

use state::AppState;
use tauri::Manager;
use tokio::sync::Mutex as AsyncMutex;

fn initialize_database(app: &tauri::AppHandle) -> Result<db::Database, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Failed to resolve app data directory: {error}"))?;
    std::fs::create_dir_all(&app_data_dir).map_err(|error| {
        format!(
            "Failed to create app data directory `{}`: {error}",
            app_data_dir.display()
        )
    })?;

    let db_path = Path::new(&app_data_dir).join("auto_make_net.sqlite");
    db::Database::open(&db_path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let database = initialize_database(app.handle())?;
            app.manage(AppState {
                database: Arc::new(Mutex::new(database)),
                tasks: Arc::new(AsyncMutex::new(std::collections::HashMap::new())),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands_server::server_list,
            commands_server::server_create,
            commands_server::server_update,
            commands_server::server_delete,
            commands_server::servers_import_csv,
            commands_server::hostkey_trust,
            commands_server::ssh_preflight,
            commands_key::key_archive_import,
            commands_task::task_stream_subscribe,
            commands_task::task_run,
            commands_task::task_cancel,
            commands_task::result_get,
            commands_task::result_export_txt
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

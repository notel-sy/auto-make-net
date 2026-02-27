use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;

use crate::db::Database;
use crate::models::{BatchTaskSummary, TaskItemResult};

#[derive(Clone)]
pub struct AppState {
    pub database: Arc<Mutex<Database>>,
    pub tasks: Arc<AsyncMutex<HashMap<String, TaskRuntimeHandle>>>,
}

#[derive(Clone)]
pub struct TaskRuntimeHandle {
    pub data: Arc<AsyncMutex<TaskRuntimeData>>,
    pub cancelled: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct TaskRuntimeData {
    pub summary: BatchTaskSummary,
    pub items: BTreeMap<String, TaskItemResult>,
    pub raw_logs: BTreeMap<String, String>,
}

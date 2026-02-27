use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager};

use crate::models::KeyArchiveImportResult;

#[tauri::command]
pub async fn key_archive_import(
    app: AppHandle,
    archive_path: String,
) -> Result<KeyArchiveImportResult, String> {
    let archive_path = archive_path.trim();
    if archive_path.is_empty() {
        return Err("ZIP 路径不能为空".to_string());
    }

    let archive_path = PathBuf::from(archive_path);
    if !archive_path.exists() {
        return Err(format!("ZIP 文件不存在: {}", archive_path.display()));
    }

    let target_dir = build_extract_dir(&app)?;
    fs::create_dir_all(&target_dir)
        .map_err(|error| format!("创建解压目录失败 `{}`: {error}", target_dir.display()))?;

    let file = File::open(&archive_path)
        .map_err(|error| format!("无法打开 ZIP 文件 `{}`: {error}", archive_path.display()))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|error| format!("ZIP 文件格式无效 `{}`: {error}", archive_path.display()))?;

    let mut extracted_files: Vec<PathBuf> = Vec::new();

    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|error| format!("读取 ZIP 条目失败: {error}"))?;

        let Some(enclosed_path) = entry.enclosed_name().map(|value| value.to_owned()) else {
            continue;
        };

        let output_path = target_dir.join(enclosed_path);
        if entry.is_dir() {
            fs::create_dir_all(&output_path).map_err(|error| {
                format!("创建目录失败 `{}`: {error}", output_path.display())
            })?;
            continue;
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("创建目录失败 `{}`: {error}", parent.display()))?;
        }

        let mut output_file = File::create(&output_path)
            .map_err(|error| format!("创建文件失败 `{}`: {error}", output_path.display()))?;
        std::io::copy(&mut entry, &mut output_file)
            .map_err(|error| format!("写入解压文件失败 `{}`: {error}", output_path.display()))?;

        extracted_files.push(output_path);
    }

    let mut key_paths: Vec<String> = Vec::new();
    for path in &extracted_files {
        if is_likely_private_key(path) {
            key_paths.push(path.to_string_lossy().to_string());
        }
    }
    key_paths.sort_by_key(|path| key_path_priority(Path::new(path)));

    Ok(KeyArchiveImportResult {
        extracted_dir: target_dir.to_string_lossy().to_string(),
        file_count: extracted_files.len(),
        key_paths,
    })
}

fn build_extract_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("获取应用数据目录失败: {error}"))?;

    let folder = format!(
        "key-archive-{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        uuid::Uuid::new_v4().simple()
    );

    Ok(app_data_dir.join("imported_keys").join(folder))
}

fn is_likely_private_key(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if file_name.starts_with("id_")
        || file_name.contains("private")
        || file_name.ends_with(".pem")
        || file_name.ends_with(".key")
        || file_name.ends_with(".ppk")
    {
        return true;
    }

    let mut buffer = [0u8; 4096];
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let Ok(read_len) = file.read(&mut buffer) else {
        return false;
    };

    let text = String::from_utf8_lossy(&buffer[..read_len]).to_string();
    text.contains("PRIVATE KEY")
}

fn key_path_priority(path: &Path) -> i32 {
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if file_name.ends_with(".pem") || file_name.ends_with(".key") {
        return 0;
    }
    if file_name.starts_with("id_") {
        return 1;
    }
    if file_name.ends_with(".ppk") {
        return 10;
    }
    5
}

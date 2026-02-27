use std::collections::HashSet;
use std::path::{PathBuf, MAIN_SEPARATOR};

use chrono::Utc;
use regex::Regex;

use crate::models::TaskItemStatus;
use crate::ssh_client::CommandResult;

pub const DEFAULT_DEPLOY_COMMAND: &str =
    "vlpt=\"\" xhpt=\"\" hypt=\"\" tupt=\"\" bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/argosbx/main/argosbx.sh)";
pub const PRIMARY_LIST_COMMAND: &str = "agsbx list";
pub const FALLBACK_LIST_COMMAND: &str =
    "bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/argosbx/main/argosbx.sh) list";
pub const MANUAL_RECOVERY_START_COMMAND: &str = "if [ -x \"$HOME/agsbx/sing-box\" ] && [ -f \"$HOME/agsbx/sb.json\" ]; then nohup \"$HOME/agsbx/sing-box\" run -c \"$HOME/agsbx/sb.json\" > \"$HOME/agsbx/sb.manual.log\" 2>&1 & fi; if [ -x \"$HOME/agsbx/xray\" ] && [ -f \"$HOME/agsbx/xr.json\" ]; then nohup \"$HOME/agsbx/xray\" run -c \"$HOME/agsbx/xr.json\" > \"$HOME/agsbx/xr.manual.log\" 2>&1 & fi; sleep 8; pgrep -af 'agsbx/(s|x)|/agsbx/(sing-box|xray)' || true";
pub const DEPLOY_PORT_RESET_COMMAND: &str = "pkill -f 'agsbx/(s|x|c)' >/dev/null 2>&1 || true; rm -f \"$HOME/agsbx\"/port_* \"$HOME/agsbx/sb.json\" \"$HOME/agsbx/xr.json\"";
pub const DEPLOY_DIAGNOSTIC_COMMAND: &str = "echo '[diag] uname'; uname -a; echo '[diag] os-release'; cat /etc/os-release 2>/dev/null || true; echo '[diag] agsbx tree'; ls -lah \"$HOME/agsbx\" 2>/dev/null || true; echo '[diag] sing-box version'; [ -x \"$HOME/agsbx/sing-box\" ] && \"$HOME/agsbx/sing-box\" version 2>&1 || true; echo '[diag] xray version'; [ -x \"$HOME/agsbx/xray\" ] && \"$HOME/agsbx/xray\" version 2>&1 || true; echo '[diag] sing-box check'; [ -x \"$HOME/agsbx/sing-box\" ] && [ -f \"$HOME/agsbx/sb.json\" ] && \"$HOME/agsbx/sing-box\" check -c \"$HOME/agsbx/sb.json\" 2>&1 || true; echo '[diag] xray test'; [ -x \"$HOME/agsbx/xray\" ] && [ -f \"$HOME/agsbx/xr.json\" ] && \"$HOME/agsbx/xray\" run -test -config \"$HOME/agsbx/xr.json\" 2>&1 || true; echo '[diag] sb.manual.log'; tail -n 80 \"$HOME/agsbx/sb.manual.log\" 2>/dev/null || true; echo '[diag] xr.manual.log'; tail -n 80 \"$HOME/agsbx/xr.manual.log\" 2>/dev/null || true";
pub const TASK_EVENT_PREFIX: &str = "task://";
pub const DEFAULT_PARALLEL_LIMIT: usize = 3;

pub fn append_command_log(log: &mut String, result: &CommandResult) {
    log.push_str(&format!(
        "\n$ {}\n[exit={}]\n[stdout]\n{}\n[stderr]\n{}\n",
        result.command, result.exit_status, result.stdout, result.stderr
    ));
}

pub fn raw_log_ref(task_id: &str, server_id: &str) -> String {
    format!("task:{task_id}:server:{server_id}")
}

fn normalize_link(value: &str) -> String {
    value
        .trim_end_matches(['.', ',', ';', ')', ']', '>'])
        .to_string()
}

fn is_known_non_subscription_http(url: &str) -> bool {
    let value = url.to_lowercase();
    value.contains("raw.githubusercontent.com/yonggekkk/argosbx/main/argosbx.sh")
        || value.contains("yonggekkk.github.io/argosbx")
        || value.contains("github.com/yonggekkk")
        || value.contains("ygkkk.blogspot.com")
        || value.contains("youtube.com/@ygkkk")
}

pub fn extract_subscription_links(text: &str) -> Vec<String> {
    let http_regex = Regex::new(r#"https?://[^\s"'<>]+"#).expect("HTTP URL regex should compile");
    let protocol_regex =
        Regex::new(r#"(?i)(?:vmess|vless|trojan|ss|ssr|hysteria2?|tuic)://[^\s"'<>]+"#)
            .expect("Protocol URI regex should compile");
    let mut dedup = HashSet::new();
    let mut http_urls = Vec::new();
    let mut protocol_urls = Vec::new();

    for capture in http_regex.find_iter(text) {
        let value = normalize_link(capture.as_str());
        if value.is_empty() || is_known_non_subscription_http(&value) {
            continue;
        }
        if dedup.insert(value.clone()) {
            http_urls.push(value);
        }
    }

    for capture in protocol_regex.find_iter(text) {
        let value = normalize_link(capture.as_str());
        if value.is_empty() {
            continue;
        }
        if dedup.insert(value.clone()) {
            protocol_urls.push(value);
        }
    }

    let mut links = Vec::new();
    links.extend(http_urls);
    links.extend(protocol_urls);
    links
}

pub fn output_contains_not_installed_marker(stdout: &str, stderr: &str) -> bool {
    let joined = format!("{}\n{}", stdout, stderr).to_lowercase();
    joined.contains("未安装argosbx脚本")
        || joined.contains("not installed")
        || joined.contains("command not found")
}

pub fn output_contains_deploy_failed_marker(stdout: &str, stderr: &str) -> bool {
    let joined = format!("{}\n{}", stdout, stderr).to_lowercase();
    joined.contains("安装失败")
        || joined.contains("脚本进程未启动")
        || joined.contains("process not started")
}

fn fallback_export_file_name() -> String {
    format!("results_{}.txt", Utc::now().format("%Y%m%d_%H%M"))
}

fn default_export_base_dir() -> Result<PathBuf, String> {
    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(user_profile)
            .join("Downloads")
            .join("auto-make-net")
            .join("exports"));
    }

    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join("Downloads").join("auto-make-net").join("exports"));
    }

    std::env::current_dir()
        .map(|path| path.join("exports"))
        .map_err(|error| format!("Failed to determine export directory: {error}"))
}

pub fn resolve_export_path(output_path: Option<String>) -> Result<PathBuf, String> {
    let fallback_name = fallback_export_file_name();

    if let Some(path) = output_path {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed);
            let looks_like_dir = trimmed.ends_with(MAIN_SEPARATOR)
                || trimmed.ends_with('/')
                || trimmed.ends_with('\\');
            if looks_like_dir || candidate.is_dir() {
                return Ok(candidate.join(&fallback_name));
            }
            return Ok(candidate);
        }
    }

    let base = default_export_base_dir()?;
    Ok(base.join(fallback_name))
}

pub fn task_event_name(task_id: &str) -> String {
    format!("{TASK_EVENT_PREFIX}{task_id}")
}

pub fn status_label(status: &TaskItemStatus) -> &'static str {
    match status {
        TaskItemStatus::Success => "SUCCESS",
        TaskItemStatus::Failed => "FAILED",
        TaskItemStatus::Skipped => "SKIPPED",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_subscription_links, output_contains_deploy_failed_marker,
        output_contains_not_installed_marker,
    };

    #[test]
    fn extract_subscription_links_filters_docs_and_keeps_protocol_uris() {
        let sample = r#"
https://yonggekkk.github.io/argosbx/
https://raw.githubusercontent.com/yonggekkk/argosbx/main/argosbx.sh
vless://user@example.com:443?type=tcp#name
hysteria2://user@example.com:8443?insecure=1#hy
        "#;
        let links = extract_subscription_links(sample);

        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|item| item.starts_with("vless://")));
        assert!(links.iter().any(|item| item.starts_with("hysteria2://")));
    }

    #[test]
    fn markers_detect_not_installed_and_deploy_failure() {
        assert!(output_contains_not_installed_marker(
            "提示：未安装argosbx脚本，请在脚本前至少设置一个协议变量哦，再见！💣",
            ""
        ));
        assert!(output_contains_deploy_failed_marker(
            "Argosbx脚本进程未启动，安装失败",
            ""
        ));
    }
}

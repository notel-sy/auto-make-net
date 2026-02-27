use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use ssh2::Session;

use crate::models::{AuthType, ResolvedRuntimeAuth, ServerProfile};

pub const SSH_TIMEOUT_SECONDS: u64 = 30;
pub const REMOTE_COMMAND_TIMEOUT_SECONDS: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_status: i32,
}

#[derive(Debug, Clone)]
pub struct PreflightFacts {
    pub is_root: bool,
    pub has_bash: bool,
    pub has_curl_or_wget: bool,
    pub can_sudo: bool,
}

pub struct ConnectedSession {
    backend: SessionBackend,
    pub fingerprint: String,
}

enum SessionBackend {
    LibSsh2(Session),
    SystemSsh(SystemSshContext),
    SystemPlink(SystemPlinkContext),
}

struct SystemSshContext {
    host: String,
    port: u16,
    username: String,
    key_path: PathBuf,
}

struct SystemPlinkContext {
    plink_path: PathBuf,
    host: String,
    port: u16,
    username: String,
    key_path: PathBuf,
}

pub fn connect_ssh(
    server: &ServerProfile,
    auth: &ResolvedRuntimeAuth,
) -> Result<ConnectedSession, String> {
    let socket_address = format!("{}:{}", server.host, server.port);
    let resolved_socket = socket_address
        .to_socket_addrs()
        .map_err(|error| format!("Failed to resolve server host `{socket_address}`: {error}"))?
        .next()
        .ok_or_else(|| format!("No resolved socket address for `{socket_address}`"))?;

    let tcp_stream =
        TcpStream::connect_timeout(&resolved_socket, Duration::from_secs(SSH_TIMEOUT_SECONDS))
            .map_err(|error| {
                format!("Failed to establish TCP connection to `{socket_address}`: {error}")
            })?;
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(REMOTE_COMMAND_TIMEOUT_SECONDS)))
        .map_err(|error| format!("Failed to configure TCP read timeout: {error}"))?;
    tcp_stream
        .set_write_timeout(Some(Duration::from_secs(REMOTE_COMMAND_TIMEOUT_SECONDS)))
        .map_err(|error| format!("Failed to configure TCP write timeout: {error}"))?;

    let mut session =
        Session::new().map_err(|error| format!("Failed to initialize SSH session: {error}"))?;
    session.set_tcp_stream(tcp_stream);
    session
        .handshake()
        .map_err(|error| format!("SSH handshake failed for `{socket_address}`: {error}"))?;

    let fingerprint = host_key_fingerprint(&session)?;

    match server.auth_type {
        AuthType::Password => {
            let password = auth.password.as_deref().ok_or_else(|| {
                "Password authentication requires a runtime password or saved credential"
                    .to_string()
            })?;
            session
                .userauth_password(&server.username, password)
                .map_err(|error| format!("SSH password authentication failed: {error}"))?;
        }
        AuthType::Key => {
            let key_path = auth.private_key_path.as_deref().ok_or_else(|| {
                "Key authentication requires privateKeyPath at runtime".to_string()
            })?;
            let key_path = Path::new(key_path);
            if !key_path.exists() {
                return Err(format!(
                    "Private key file does not exist: {}",
                    key_path.display()
                ));
            }

            let mut ppk_plink_error: Option<String> = None;
            if is_ppk_path(key_path) {
                match try_connect_with_plink(server, key_path) {
                    Ok(plink_context) => {
                        return Ok(ConnectedSession {
                            backend: SessionBackend::SystemPlink(plink_context),
                            fingerprint,
                        });
                    }
                    Err(plink_error) => {
                        ppk_plink_error = Some(plink_error);
                    }
                }
            }

            let prepared_key = prepare_private_key_for_auth(key_path).map_err(|conversion_error| {
                if let Some(plink_error) = &ppk_plink_error {
                    format!(
                        "SSH private-key authentication failed for `.ppk` key. plink fallback error: {plink_error}; key conversion error: {conversion_error}"
                    )
                } else {
                    conversion_error
                }
            })?;
            let key_path_for_auth = prepared_key.path.as_path();
            let libssh2_passphrase = auth.private_key_passphrase.as_deref();

            let libssh2_result = session.userauth_pubkey_file(
                &server.username,
                None,
                key_path_for_auth,
                libssh2_passphrase,
            );

            if libssh2_result.is_err() || !session.authenticated() {
                let libssh2_error = libssh2_result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "authentication rejected".to_string());

                let system_ssh_fallback = try_connect_with_system_ssh(server, key_path_for_auth);
                match system_ssh_fallback {
                    Ok(system_context) => {
                        return Ok(ConnectedSession {
                            backend: SessionBackend::SystemSsh(system_context),
                            fingerprint,
                        });
                    }
                    Err(system_error) => {
                        if let Some(plink_error) = ppk_plink_error {
                            return Err(format!(
                                "SSH private-key authentication failed for `.ppk` key. plink fallback error: {plink_error}; libssh2={libssh2_error}; ssh.exe fallback={system_error}"
                            ));
                        }
                        return Err(format!(
                            "SSH private-key authentication failed. libssh2={libssh2_error}; ssh.exe fallback={system_error}"
                        ));
                    }
                }
            }
        }
    }

    if !session.authenticated() {
        return Err("SSH authentication was rejected by the server".to_string());
    }

    Ok(ConnectedSession {
        backend: SessionBackend::LibSsh2(session),
        fingerprint,
    })
}

pub fn run_preflight_checks(
    connection: &ConnectedSession,
    auth: &ResolvedRuntimeAuth,
) -> Result<PreflightFacts, String> {
    let whoami = run_command(connection, "whoami", false, None)?;
    let is_root = whoami.stdout.trim() == "root";

    let has_bash = run_command(
        connection,
        "command -v bash >/dev/null && echo ok || echo missing",
        false,
        None,
    )?
    .stdout
    .trim()
        == "ok";
    let has_curl_or_wget = run_command(
        connection,
        "(command -v curl >/dev/null || command -v wget >/dev/null) && echo ok || echo missing",
        false,
        None,
    )?
    .stdout
    .trim()
        == "ok";

    let can_sudo = if is_root {
        true
    } else {
        let password = auth.sudo_password.as_deref().or(auth.password.as_deref());
        let no_password_check = run_raw_command(connection, "sudo -n true", None)?;
        if no_password_check.exit_status == 0 {
            true
        } else {
            let with_password = run_raw_command(connection, "sudo -S -p '' true", password)?;
            with_password.exit_status == 0
        }
    };

    Ok(PreflightFacts {
        is_root,
        has_bash,
        has_curl_or_wget,
        can_sudo,
    })
}

pub fn run_privileged_command(
    connection: &ConnectedSession,
    command: &str,
    is_root: bool,
    sudo_password: Option<&str>,
) -> Result<CommandResult, String> {
    if is_root {
        run_command(connection, command, false, None)
    } else {
        run_command(connection, command, true, sudo_password)
    }
}

pub fn run_command(
    connection: &ConnectedSession,
    command: &str,
    use_sudo: bool,
    sudo_password: Option<&str>,
) -> Result<CommandResult, String> {
    let wrapped_command = if use_sudo {
        format!("sudo -S -p '' bash -lc '{}'", single_quote_escape(command))
    } else {
        format!("bash -lc '{}'", single_quote_escape(command))
    };

    run_raw_command(connection, &wrapped_command, sudo_password).map(|result| CommandResult {
        command: command.to_string(),
        ..result
    })
}

fn run_raw_command(
    connection: &ConnectedSession,
    command: &str,
    stdin_password: Option<&str>,
) -> Result<CommandResult, String> {
    match &connection.backend {
        SessionBackend::LibSsh2(session) => {
            run_raw_command_via_libssh2(session, command, stdin_password)
        }
        SessionBackend::SystemSsh(context) => {
            run_raw_command_via_system_ssh(context, command, stdin_password)
        }
        SessionBackend::SystemPlink(context) => {
            run_raw_command_via_plink(context, command, stdin_password)
        }
    }
}

fn run_raw_command_via_libssh2(
    session: &Session,
    command: &str,
    stdin_password: Option<&str>,
) -> Result<CommandResult, String> {
    let mut channel = session
        .channel_session()
        .map_err(|error| format!("Failed to open SSH channel: {error}"))?;
    channel
        .request_pty("xterm", None, None)
        .map_err(|error| format!("Failed to request PTY: {error}"))?;
    channel
        .exec(command)
        .map_err(|error| format!("Failed to execute remote command: {error}"))?;

    if let Some(password) = stdin_password {
        channel
            .write_all(format!("{password}\n").as_bytes())
            .map_err(|error| format!("Failed to send sudo password: {error}"))?;
        channel
            .flush()
            .map_err(|error| format!("Failed to flush sudo password to remote channel: {error}"))?;
    }

    let mut stdout = String::new();
    let mut stderr = String::new();

    channel
        .read_to_string(&mut stdout)
        .map_err(|error| format!("Failed to read SSH stdout: {error}"))?;
    channel
        .stderr()
        .read_to_string(&mut stderr)
        .map_err(|error| format!("Failed to read SSH stderr: {error}"))?;

    channel
        .wait_close()
        .map_err(|error| format!("Failed while waiting for SSH command close: {error}"))?;

    let exit_status = channel
        .exit_status()
        .map_err(|error| format!("Failed to obtain SSH exit status: {error}"))?;

    Ok(CommandResult {
        command: command.to_string(),
        stdout,
        stderr,
        exit_status,
    })
}

fn run_raw_command_via_system_ssh(
    context: &SystemSshContext,
    command: &str,
    stdin_password: Option<&str>,
) -> Result<CommandResult, String> {
    let mut ssh = Command::new("ssh");
    ssh.arg("-tt");

    for arg in build_system_ssh_args(context) {
        ssh.arg(arg);
    }
    ssh.arg(command);

    ssh.stdout(Stdio::piped());
    ssh.stderr(Stdio::piped());
    ssh.stdin(if stdin_password.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    let mut child = ssh
        .spawn()
        .map_err(|error| format!("Failed to launch ssh.exe fallback process: {error}"))?;

    if let Some(password) = stdin_password {
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(format!("{password}\n").as_bytes())
                .map_err(|error| format!("Failed to pass sudo password into ssh.exe stdin: {error}"))?;
            stdin
                .flush()
                .map_err(|error| format!("Failed to flush sudo password into ssh.exe stdin: {error}"))?;
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("Failed to collect ssh.exe fallback output: {error}"))?;

    Ok(CommandResult {
        command: command.to_string(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_status: output.status.code().unwrap_or(255),
    })
}

fn run_raw_command_via_plink(
    context: &SystemPlinkContext,
    command: &str,
    stdin_password: Option<&str>,
) -> Result<CommandResult, String> {
    let mut plink = Command::new(&context.plink_path);
    plink.arg("-batch");
    plink.arg("-P").arg(context.port.to_string());
    plink.arg("-i").arg(&context.key_path);
    plink.arg("-l").arg(&context.username);
    plink.arg(&context.host);
    plink.arg(command);

    plink.stdout(Stdio::piped());
    plink.stderr(Stdio::piped());
    plink.stdin(if stdin_password.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    let mut child = plink
        .spawn()
        .map_err(|error| format!("Failed to launch plink fallback process: {error}"))?;

    if let Some(password) = stdin_password {
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(format!("{password}\n").as_bytes())
                .map_err(|error| format!("Failed to pass sudo password into plink stdin: {error}"))?;
            stdin
                .flush()
                .map_err(|error| format!("Failed to flush sudo password into plink stdin: {error}"))?;
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("Failed to collect plink fallback output: {error}"))?;

    Ok(CommandResult {
        command: command.to_string(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_status: output.status.code().unwrap_or(255),
    })
}

fn host_key_fingerprint(session: &Session) -> Result<String, String> {
    let (host_key, _host_key_type) = session
        .host_key()
        .ok_or_else(|| "SSH session did not provide host key bytes".to_string())?;
    let digest = Sha256::digest(host_key);
    let encoded = STANDARD_NO_PAD.encode(digest);
    Ok(format!("SHA256:{encoded}"))
}

fn single_quote_escape(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}

struct PreparedPrivateKey {
    path: PathBuf,
}

fn prepare_private_key_for_auth(key_path: &Path) -> Result<PreparedPrivateKey, String> {
    if !is_ppk_path(key_path) {
        return Ok(PreparedPrivateKey {
            path: key_path.to_path_buf(),
        });
    }

    let converted = convert_ppk_to_openssh(key_path)?;
    Ok(PreparedPrivateKey {
        path: converted,
    })
}

fn is_ppk_path(path: &Path) -> bool {
    path.extension()
        .map(|value| value.to_string_lossy().eq_ignore_ascii_case("ppk"))
        .unwrap_or(false)
}

fn convert_ppk_to_openssh(ppk_path: &Path) -> Result<PathBuf, String> {
    let target_dir = std::env::temp_dir().join("auto-make-net").join("converted-keys");
    std::fs::create_dir_all(&target_dir).map_err(|error| {
        format!(
            "Failed to create temporary directory for PPK conversion `{}`: {error}",
            target_dir.display()
        )
    })?;

    let output_path = target_dir.join(format!("{}.pem", uuid::Uuid::new_v4().simple()));

    let puttygen_path = find_puttygen_executable().ok_or_else(|| {
        "`.ppk` key is unsupported directly and `puttygen.exe` was not found. Install PuTTY (includes puttygen) or convert `.ppk` to OpenSSH private key first.".to_string()
    })?;

    let output_path_text = output_path.to_string_lossy().to_string();
    let ppk_path_text = ppk_path.to_string_lossy().to_string();
    let arg_candidates: Vec<Vec<String>> = vec![
        vec![
            ppk_path_text.clone(),
            "-O".to_string(),
            "private-openssh".to_string(),
            "-o".to_string(),
            output_path_text.clone(),
        ],
        vec![
            "-O".to_string(),
            "private-openssh".to_string(),
            "-o".to_string(),
            output_path_text.clone(),
            ppk_path_text.clone(),
        ],
        vec![
            ppk_path_text.clone(),
            "-o".to_string(),
            output_path_text.clone(),
            "-O".to_string(),
            "private-openssh".to_string(),
        ],
        vec![
            ppk_path_text,
            "-o".to_string(),
            output_path_text,
        ],
    ];

    let mut attempt_errors = Vec::new();
    for args in arg_candidates {
        let _ = std::fs::remove_file(&output_path);

        let mut command = Command::new(&puttygen_path);
        for arg in &args {
            command.arg(arg);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = match command.output() {
            Ok(value) => value,
            Err(error) => {
                attempt_errors.push(format!(
                    "args={:?}: start failed: {error}",
                    args
                ));
                continue;
            }
        };

        if output.status.success()
            && output_path.exists()
            && is_private_key_pem_like_file(&output_path)
        {
            return Ok(output_path);
        }

        attempt_errors.push(format!(
            "args={:?}: exit={} stdout=`{}` stderr=`{}`",
            args,
            output.status.code().unwrap_or(255),
            truncate_for_log(&String::from_utf8_lossy(&output.stdout)),
            truncate_for_log(&String::from_utf8_lossy(&output.stderr))
        ));
    }

    Err(format!(
        "Failed to convert `.ppk` key with puttygen `{}`. attempts={}",
        puttygen_path.display(),
        attempt_errors.join(" | ")
    ))
}

fn is_private_key_pem_like_file(path: &Path) -> bool {
    let Ok(content) = std::fs::read(path) else {
        return false;
    };
    let text = String::from_utf8_lossy(&content);
    text.contains("PRIVATE KEY")
}

fn find_puttygen_executable() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("PUTTYGEN_PATH") {
        let path = PathBuf::from(custom.trim());
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        let path = current_dir.join("tools").join("puttygen.exe");
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            let nearby = exe_dir.join("puttygen.exe");
            if nearby.exists() {
                return Some(nearby);
            }

            let sibling_tools = exe_dir.join("tools").join("puttygen.exe");
            if sibling_tools.exists() {
                return Some(sibling_tools);
            }

            // For development runs, current executable may be under src-tauri/target/**.
            let mut probe = exe_dir.to_path_buf();
            for _ in 0..6 {
                let candidate = probe.join("tools").join("puttygen.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
                if !probe.pop() {
                    break;
                }
            }
        }
    }

    let common = [
        r"C:\Program Files\PuTTY\puttygen.exe",
        r"C:\Program Files (x86)\PuTTY\puttygen.exe",
    ];
    for candidate in common {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let path = PathBuf::from(local_app_data)
            .join("Programs")
            .join("PuTTY")
            .join("puttygen.exe");
        if path.exists() {
            return Some(path);
        }
    }

    let where_result = Command::new("where")
        .arg("puttygen")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    if let Ok(output) = where_result {
        if output.status.success() {
            let lines = String::from_utf8_lossy(&output.stdout);
            for line in lines.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let path = PathBuf::from(trimmed);
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}

fn find_plink_executable() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("PLINK_PATH") {
        let path = PathBuf::from(custom.trim());
        if path.exists() {
            return Some(path);
        }
    }

    if let Some(puttygen) = find_puttygen_executable() {
        if let Some(parent) = puttygen.parent() {
            let sibling = parent.join("plink.exe");
            if sibling.exists() {
                return Some(sibling);
            }
        }
    }

    let common = [
        r"C:\Program Files\PuTTY\plink.exe",
        r"C:\Program Files (x86)\PuTTY\plink.exe",
    ];
    for candidate in common {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let path = PathBuf::from(local_app_data)
            .join("Programs")
            .join("PuTTY")
            .join("plink.exe");
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        let path = current_dir.join("tools").join("plink.exe");
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            let nearby = exe_dir.join("plink.exe");
            if nearby.exists() {
                return Some(nearby);
            }

            let sibling_tools = exe_dir.join("tools").join("plink.exe");
            if sibling_tools.exists() {
                return Some(sibling_tools);
            }

            let mut probe = exe_dir.to_path_buf();
            for _ in 0..6 {
                let candidate = probe.join("tools").join("plink.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
                if !probe.pop() {
                    break;
                }
            }
        }
    }

    let where_result = Command::new("where")
        .arg("plink")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    if let Ok(output) = where_result {
        if output.status.success() {
            let lines = String::from_utf8_lossy(&output.stdout);
            for line in lines.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let path = PathBuf::from(trimmed);
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}

fn try_connect_with_system_ssh(
    server: &ServerProfile,
    key_path: &Path,
) -> Result<SystemSshContext, String> {
    Command::new("ssh")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("ssh.exe is not available in PATH: {error}"))?;

    let context = SystemSshContext {
        host: server.host.clone(),
        port: server.port,
        username: server.username.clone(),
        key_path: key_path.to_path_buf(),
    };

    let verification = run_raw_command_via_system_ssh(
        &context,
        "bash -lc 'echo __AUTO_MAKE_NET_SSH_OK__'",
        None,
    )?;

    if verification.exit_status != 0
        || (!verification.stdout.contains("__AUTO_MAKE_NET_SSH_OK__")
            && !verification.stderr.contains("__AUTO_MAKE_NET_SSH_OK__"))
    {
        return Err(format!(
            "ssh.exe auth check failed (exit={}). stdout=`{}` stderr=`{}`",
            verification.exit_status,
            truncate_for_log(&verification.stdout),
            truncate_for_log(&verification.stderr)
        ));
    }

    Ok(context)
}

fn try_connect_with_plink(
    server: &ServerProfile,
    key_path: &Path,
) -> Result<SystemPlinkContext, String> {
    let plink_path = find_plink_executable().ok_or_else(|| {
        "plink.exe is required for `.ppk` key fallback but was not found".to_string()
    })?;

    let context = SystemPlinkContext {
        plink_path,
        host: server.host.clone(),
        port: server.port,
        username: server.username.clone(),
        key_path: key_path.to_path_buf(),
    };

    let verification = run_raw_command_via_plink(
        &context,
        "bash -lc 'echo __AUTO_MAKE_NET_SSH_OK__'",
        None,
    )?;

    if verification.exit_status != 0
        || (!verification.stdout.contains("__AUTO_MAKE_NET_SSH_OK__")
            && !verification.stderr.contains("__AUTO_MAKE_NET_SSH_OK__"))
    {
        return Err(format!(
            "plink auth check failed (exit={}). stdout=`{}` stderr=`{}`",
            verification.exit_status,
            truncate_for_log(&verification.stdout),
            truncate_for_log(&verification.stderr)
        ));
    }

    Ok(context)
}

fn build_system_ssh_args(context: &SystemSshContext) -> Vec<String> {
    let mut args = Vec::new();
    args.push("-p".to_string());
    args.push(context.port.to_string());
    args.push("-i".to_string());
    args.push(context.key_path.to_string_lossy().to_string());
    args.push("-o".to_string());
    args.push("BatchMode=yes".to_string());
    args.push("-o".to_string());
    args.push(format!("ConnectTimeout={SSH_TIMEOUT_SECONDS}"));
    args.push("-o".to_string());
    args.push("PreferredAuthentications=publickey".to_string());
    args.push("-o".to_string());
    args.push("PubkeyAuthentication=yes".to_string());
    args.push("-o".to_string());
    args.push("StrictHostKeyChecking=no".to_string());
    args.push("-o".to_string());
    args.push(format!("UserKnownHostsFile={}", null_device_path()));
    args.push("-o".to_string());
    args.push("LogLevel=ERROR".to_string());
    args.push(format!("{}@{}", context.username, context.host));
    args
}

fn null_device_path() -> &'static str {
    if cfg!(windows) {
        "NUL"
    } else {
        "/dev/null"
    }
}

fn truncate_for_log(value: &str) -> String {
    const LIMIT: usize = 500;
    if value.len() <= LIMIT {
        value.to_string()
    } else {
        format!("{}...(truncated)", &value[..LIMIT])
    }
}

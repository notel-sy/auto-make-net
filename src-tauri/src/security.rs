use std::sync::OnceLock;

#[cfg(not(target_os = "windows"))]
use keyring::Entry;
use regex::Regex;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, FILETIME, GetLastError};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW,
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

const KEYRING_SERVICE: &str = "auto-make-net";

#[cfg(target_os = "windows")]
const WINDOWS_CREDENTIAL_TARGET_PREFIX: &str = "auto-make-net/server";
#[cfg(target_os = "windows")]
const WINDOWS_CREDENTIAL_COMMENT: &str = "Auto Make Net server password";

#[cfg(target_os = "windows")]
fn windows_credential_targets(server_id: &str) -> [String; 2] {
    [
        format!("{WINDOWS_CREDENTIAL_TARGET_PREFIX}/{server_id}"),
        format!("{server_id}.{KEYRING_SERVICE}"),
    ]
}

#[cfg(target_os = "windows")]
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn os_error_message(prefix: &str) -> String {
    let code = unsafe { GetLastError() } as i32;
    let error = std::io::Error::from_raw_os_error(code);
    format!("{prefix}: {error} (code {code})")
}

#[cfg(target_os = "windows")]
fn decode_password_bytes(bytes: &[u8]) -> Result<String, String> {
    if let Ok(value) = String::from_utf8(bytes.to_vec()) {
        return Ok(value);
    }

    if bytes.len() % 2 != 0 {
        return Err("Failed to decode saved password bytes".to_string());
    }

    let utf16 = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16).map_err(|error| format!("Failed to decode saved password bytes: {error}"))
}

#[cfg(target_os = "windows")]
fn read_windows_password_by_target(target: &str) -> Result<Option<String>, String> {
    let target_wide = to_wide(target);
    let mut credential_ptr: *mut CREDENTIALW = std::ptr::null_mut();
    let read_result = unsafe { CredReadW(target_wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential_ptr) };

    if read_result == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_NOT_FOUND {
            return Ok(None);
        }
        return Err(os_error_message(&format!(
            "Failed to read password from Windows Credential Manager for `{target}`"
        )));
    }

    let password_result = unsafe {
        let credential = &*credential_ptr;
        let blob = std::slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        );
        decode_password_bytes(blob).map(Some)
    };

    unsafe { CredFree(credential_ptr.cast()) };
    password_result
}

#[cfg(target_os = "windows")]
pub fn set_server_password(server_id: &str, password: &str) -> Result<(), String> {
    let target = windows_credential_targets(server_id)[0].clone();
    let mut target_wide = to_wide(&target);
    let mut comment_wide = to_wide(WINDOWS_CREDENTIAL_COMMENT);
    let mut username_wide = to_wide(server_id);
    let mut password_bytes = password.as_bytes().to_vec();

    if password_bytes.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        return Err(format!(
            "Password is too long for Windows Credential Manager ({} bytes > {} bytes)",
            password_bytes.len(),
            CRED_MAX_CREDENTIAL_BLOB_SIZE
        ));
    }

    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_wide.as_mut_ptr(),
        Comment: comment_wide.as_mut_ptr(),
        LastWritten: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        CredentialBlobSize: password_bytes.len() as u32,
        CredentialBlob: password_bytes.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: std::ptr::null_mut(),
        UserName: username_wide.as_mut_ptr(),
    };

    let write_result = unsafe { CredWriteW(&credential, 0) };
    password_bytes.fill(0);

    if write_result == 0 {
        return Err(os_error_message(&format!(
            "Failed to store password in Windows Credential Manager for server `{server_id}`"
        )));
    }

    match read_windows_password_by_target(&target)? {
        Some(_) => Ok(()),
        None => Err(format!(
            "Password for server `{server_id}` was written, but could not be read back from Windows Credential Manager"
        )),
    }
}

#[cfg(target_os = "windows")]
pub fn get_server_password(server_id: &str) -> Result<Option<String>, String> {
    for target in windows_credential_targets(server_id) {
        if let Some(password) = read_windows_password_by_target(&target)? {
            return Ok(Some(password));
        }
    }
    Ok(None)
}

#[cfg(target_os = "windows")]
pub fn has_server_password(server_id: &str) -> Result<bool, String> {
    get_server_password(server_id).map(|password| password.is_some())
}

#[cfg(target_os = "windows")]
pub fn delete_server_password(server_id: &str) -> Result<(), String> {
    for target in windows_credential_targets(server_id) {
        let target_wide = to_wide(&target);
        let delete_result = unsafe { CredDeleteW(target_wide.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if delete_result == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND {
                return Err(os_error_message(&format!(
                    "Failed to delete password from Windows Credential Manager for `{target}`"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn set_server_password(server_id: &str, password: &str) -> Result<(), String> {
    let entry = Entry::new(KEYRING_SERVICE, server_id)
        .map_err(|error| format!("Failed to create keyring entry: {error}"))?;
    entry
        .set_password(password)
        .map_err(|error| format!("Failed to store password in keyring: {error}"))
}

#[cfg(not(target_os = "windows"))]
pub fn get_server_password(server_id: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(KEYRING_SERVICE, server_id)
        .map_err(|error| format!("Failed to create keyring entry: {error}"))?;
    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("Failed to read password from keyring: {error}")),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn has_server_password(server_id: &str) -> Result<bool, String> {
    get_server_password(server_id).map(|password| password.is_some())
}

#[cfg(not(target_os = "windows"))]
pub fn delete_server_password(server_id: &str) -> Result<(), String> {
    let entry = Entry::new(KEYRING_SERVICE, server_id)
        .map_err(|error| format!("Failed to create keyring entry: {error}"))?;
    match entry.delete_credential() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("Failed to delete password from keyring: {error}")),
    }
}

pub fn redact_text(input: &str, secrets: &[String]) -> String {
    let mut output = input.to_string();

    for secret in secrets {
        if !secret.trim().is_empty() {
            output = output.replace(secret, "***");
        }
    }

    for regex in redaction_regexes() {
        output = regex.replace_all(&output, "$1***").to_string();
    }

    private_key_block_regex()
        .replace_all(&output, "[REDACTED_PRIVATE_KEY]")
        .to_string()
}

fn redaction_regexes() -> &'static [Regex] {
    static REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();
    REGEXES
        .get_or_init(|| {
            vec![
                Regex::new(r#"(?i)(password\s*[:=]\s*)[^\s"']+"#).expect("invalid password regex"),
                Regex::new(r#"(?i)(token\s*[:=]\s*)[^\s"']+"#).expect("invalid token regex"),
                Regex::new(r#"(?i)(uuid\s*[:=]\s*)[^\s"']+"#).expect("invalid uuid regex"),
                Regex::new(r#"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s"']+"#)
                    .expect("invalid authorization regex"),
            ]
        })
        .as_slice()
}

fn private_key_block_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
            .expect("invalid private key block regex")
    })
}

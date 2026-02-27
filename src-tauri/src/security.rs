use std::sync::OnceLock;

use keyring::Entry;
use regex::Regex;

const KEYRING_SERVICE: &str = "auto-make-net";

pub fn set_server_password(server_id: &str, password: &str) -> Result<(), String> {
    let entry = Entry::new(KEYRING_SERVICE, server_id)
        .map_err(|error| format!("Failed to create keyring entry: {error}"))?;
    entry
        .set_password(password)
        .map_err(|error| format!("Failed to store password in keyring: {error}"))
}

pub fn get_server_password(server_id: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(KEYRING_SERVICE, server_id)
        .map_err(|error| format!("Failed to create keyring entry: {error}"))?;
    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("Failed to read password from keyring: {error}")),
    }
}

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

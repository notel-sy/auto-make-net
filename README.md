# Auto Make Net (Windows Desktop)

Tauri + React desktop app for managing VPS servers over SSH and automating Argosbx deployment.

## Features

- Manage multiple VPS servers (create/update/delete)
- CSV bulk import (`name,host,port,username,auth_type,password,key_path`)
- SSH auth with password or private key
- TOFU host key trust workflow (first connect requires fingerprint trust)
- Preflight checks (`bash`, `curl/wget`, `root/sudo`)
- Batch task execution with default concurrency `3`
- Task modes:
  - `list_only`
  - `list_then_deploy` (default deploy command: `vlpt+xhpt+hypt+tupt`)
- Extract and deduplicate `http(s)` subscription URLs
- Copy URLs and export TXT results
- Password storage via system keyring (private key path is runtime-only)
- Redacted logs for sensitive values

## Requirements

- Node.js 20+
- Rust toolchain (stable)
- Windows desktop environment (WebView2)

## Development

```bash
npm install
npm run tauri dev
```

## Build

```bash
npm run tauri build -- --bundles nsis
```

Output installer:

- `src-tauri/target/release/bundle/nsis/tauri-app_0.1.0_x64-setup.exe`

## Core Tauri Commands

- `server_create(payload)`
- `server_update(server_id, payload)`
- `server_delete(server_id)`
- `servers_import_csv(file_path)`
- `ssh_preflight(server_id, runtime_auth)`
- `task_run(server_ids, mode, runtime_auths, parallel_limit)`
- `task_cancel(task_id)`
- `task_stream_subscribe(task_id)`
- `result_get(task_id)`
- `result_export_txt(task_id, output_path)`
- `hostkey_trust(payload)`

## Security Note

Use only with servers you own or have explicit authorization to administer.

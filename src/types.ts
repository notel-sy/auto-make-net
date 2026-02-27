export type AuthType = "password" | "key";

export interface ServerProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authType: AuthType;
  rememberPassword: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ServerUpsertPayload {
  name: string;
  host: string;
  port: number;
  username: string;
  authType: AuthType;
  rememberPassword: boolean;
  password?: string;
}

export interface RuntimeAuth {
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  sudoPassword?: string;
}

export type PreflightStatus = "ok" | "untrusted_host" | "host_key_mismatch" | "failed";

export interface SshPreflightResponse {
  status: PreflightStatus;
  fingerprint?: string | null;
  isRoot?: boolean | null;
  hasBash?: boolean | null;
  hasCurlOrWget?: boolean | null;
  canSudo?: boolean | null;
  message?: string | null;
}

export interface TaskRunAccepted {
  taskId: string;
  total: number;
  startedAt: string;
}

export type TaskMode = "list_only" | "list_then_deploy";

export type TaskItemStatus = "success" | "failed" | "skipped";

export interface TaskItemResult {
  serverId: string;
  status: TaskItemStatus;
  phase: string;
  extractedUrls: string[];
  rawLogRef: string;
  errorCode?: string | null;
  errorMessage?: string | null;
}

export interface BatchTaskSummary {
  taskId: string;
  total: number;
  success: number;
  failed: number;
  startedAt: string;
  finishedAt?: string | null;
}

export interface TaskResultPayload {
  summary: BatchTaskSummary;
  items: TaskItemResult[];
}

export interface TaskEvent {
  taskId: string;
  serverId?: string | null;
  phase: string;
  message: string;
  timestamp: string;
}

export interface CsvImportError {
  line: number;
  message: string;
}

export interface CsvImportResult {
  imported: number;
  failed: number;
  errors: CsvImportError[];
}

export interface TrustHostPayload {
  host: string;
  port: number;
  fingerprint: string;
}

export interface KeyArchiveImportResult {
  extractedDir: string;
  fileCount: number;
  keyPaths: string[];
}

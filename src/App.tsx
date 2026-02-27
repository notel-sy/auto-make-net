import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./App.css";
import {
  CsvImportResult,
  KeyArchiveImportResult,
  RuntimeAuth,
  ServerProfile,
  ServerUpsertPayload,
  SshPreflightResponse,
  TaskEvent,
  TaskMode,
  TaskResultPayload,
  TaskRunAccepted,
  TrustHostPayload,
} from "./types";

type ProgressStatus = "idle" | "running" | "success" | "failed" | "skipped";

type ServerProgress = {
  percent: number;
  phase: string;
  message: string;
  status: ProgressStatus;
  logs: string[];
  updatedAt: string;
};

type FormState = {
  id?: string;
  name: string;
  host: string;
  port: string;
  username: string;
  authType: "password" | "key";
  rememberPassword: boolean;
  password: string;
};

const emptyForm = (): FormState => ({
  name: "",
  host: "",
  port: "22",
  username: "root",
  authType: "password",
  rememberPassword: true,
  password: "",
});

const preflightLabel: Record<string, string> = {
  ok: "通过",
  untrusted_host: "未信任",
  host_key_mismatch: "指纹不匹配",
  failed: "失败",
};

const taskStatusLabel: Record<string, string> = {
  success: "成功",
  failed: "失败",
  skipped: "已跳过",
};

const progressStatusLabel: Record<ProgressStatus, string> = {
  idle: "等待中",
  running: "进行中",
  success: "成功",
  failed: "失败",
  skipped: "已跳过",
};

const phaseProgressMap: Record<string, number> = {
  queued: 0,
  connecting: 10,
  preflight: 24,
  list: 42,
  deploy: 72,
  parse: 88,
  done: 100,
  skipped: 100,
};

function phaseToProgress(phase: string, current = 0) {
  const normalized = phase.trim().toLowerCase();
  const direct = phaseProgressMap[normalized];
  if (typeof direct === "number") {
    return direct;
  }
  return Math.min(current + 7, 96);
}

function isFailureSignal(message: string) {
  const value = message.toLowerCase();
  const keywords = [
    "failed",
    "error",
    "mismatch",
    "not installed",
    "timeout",
    "denied",
    "失败",
    "错误",
    "未安装",
    "不匹配",
  ];
  return keywords.some((keyword) => value.includes(keyword));
}

function nowText() {
  return new Date().toISOString();
}

function defaultProgress(message = "等待执行"): ServerProgress {
  return {
    percent: 0,
    phase: "queued",
    message,
    status: "idle",
    logs: [],
    updatedAt: nowText(),
  };
}

function App() {
  const [servers, setServers] = useState<ServerProfile[]>([]);
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>([]);
  const [runtimeAuths, setRuntimeAuths] = useState<Record<string, RuntimeAuth>>({});
  const [form, setForm] = useState<FormState>(emptyForm());
  const [formModalOpen, setFormModalOpen] = useState(false);

  const [loading, setLoading] = useState(false);
  const [statusText, setStatusText] = useState<string>("");

  const [importPath, setImportPath] = useState<string>("");
  const [importedKeyPaths, setImportedKeyPaths] = useState<string[]>([]);
  const [exportPath, setExportPath] = useState<string>("");
  const [parallelLimit, setParallelLimit] = useState<string>("3");

  const [preflightByServer, setPreflightByServer] = useState<Record<string, SshPreflightResponse>>({});
  const [taskEvents, setTaskEvents] = useState<string[]>([]);
  const [taskServerProgress, setTaskServerProgress] = useState<Record<string, ServerProgress>>({});
  const [activeTaskId, setActiveTaskId] = useState<string>("");
  const [taskResult, setTaskResult] = useState<TaskResultPayload | null>(null);
  const unlistenRef = useRef<UnlistenFn | null>(null);

  const serverById = useMemo(
    () =>
      servers.reduce<Record<string, ServerProfile>>((acc, server) => {
        acc[server.id] = server;
        return acc;
      }, {}),
    [servers],
  );

  const selectedServers = useMemo(
    () => servers.filter((server) => selectedServerIds.includes(server.id)),
    [servers, selectedServerIds],
  );

  const progressList = useMemo(
    () =>
      Object.entries(taskServerProgress).sort((a, b) => {
        const aName = serverById[a[0]]?.name ?? a[0];
        const bName = serverById[b[0]]?.name ?? b[0];
        return aName.localeCompare(bName, "zh-CN");
      }),
    [taskServerProgress, serverById],
  );

  const allServersSelected = servers.length > 0 && selectedServerIds.length === servers.length;
  const hasSelectedServers = selectedServerIds.length > 0;
  const hasAnyServer = servers.length > 0;

  useEffect(() => {
    void refreshServers();
    return () => {
      if (unlistenRef.current) {
        unlistenRef.current();
        unlistenRef.current = null;
      }
    };
  }, []);

  async function refreshServers() {
    const data = await invoke<ServerProfile[]>("server_list");
    setServers(data);
  }

  function updateRuntimeAuth(serverId: string, patch: Partial<RuntimeAuth>) {
    setRuntimeAuths((prev) => ({
      ...prev,
      [serverId]: {
        ...prev[serverId],
        ...patch,
      },
    }));
  }

  function toggleServer(serverId: string) {
    setSelectedServerIds((prev) =>
      prev.includes(serverId) ? prev.filter((id) => id !== serverId) : [...prev, serverId],
    );
  }

  function selectAllServers() {
    if (allServersSelected) {
      setSelectedServerIds([]);
      return;
    }
    setSelectedServerIds(servers.map((server) => server.id));
  }

  function resolveParallelLimit() {
    const parsed = Number.parseInt(parallelLimit.trim(), 10);
    if (Number.isNaN(parsed) || parsed < 1) {
      return 3;
    }
    return Math.min(parsed, 32);
  }

  function exportFileNameSuggestion() {
    const now = new Date();
    const p2 = (value: number) => String(value).padStart(2, "0");
    return `results_${now.getFullYear()}${p2(now.getMonth() + 1)}${p2(now.getDate())}_${p2(now.getHours())}${p2(now.getMinutes())}.txt`;
  }

  function startEdit(server: ServerProfile) {
    setForm({
      id: server.id,
      name: server.name,
      host: server.host,
      port: String(server.port),
      username: server.username,
      authType: server.authType,
      rememberPassword: server.rememberPassword,
      password: "",
    });
    setFormModalOpen(true);
  }

  function startCreate() {
    setForm(emptyForm());
    setFormModalOpen(true);
  }

  function closeFormModal() {
    setForm(emptyForm());
    setFormModalOpen(false);
  }

  function resolvePayload(): ServerUpsertPayload {
    return {
      name: form.name.trim(),
      host: form.host.trim(),
      port: Number(form.port),
      username: form.username.trim(),
      authType: form.authType,
      rememberPassword: form.rememberPassword,
      password: form.password.trim() || undefined,
    };
  }

  async function onSaveServer(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    try {
      const payload = resolvePayload();
      if (form.id) {
        await invoke("server_update", { serverId: form.id, payload });
        setStatusText(`已更新服务器：${payload.name}`);
      } else {
        await invoke("server_create", { payload });
        setStatusText(`已新增服务器：${payload.name}`);
      }
      closeFormModal();
      await refreshServers();
    } catch (error) {
      setStatusText(`保存失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function importCsvByPath(filePath: string) {
    setLoading(true);
    try {
      const result = await invoke<CsvImportResult>("servers_import_csv", {
        filePath: filePath.trim(),
      });
      const firstError = result.errors.length
        ? `，首个错误在第 ${result.errors[0].line} 行：${result.errors[0].message}`
        : "";

      setStatusText(`CSV 导入完成，成功 ${result.imported}，失败 ${result.failed}${firstError}`);
      await refreshServers();
    } catch (error) {
      setStatusText(`CSV 导入失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function pickCsvFilePath() {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "CSV 文件", extensions: ["csv"] }],
    });
    if (typeof selected === "string") {
      return selected;
    }
    return null;
  }

  async function onPickAndImportCsv() {
    const picked = await pickCsvFilePath();
    if (!picked) {
      return;
    }
    setImportPath(picked);
    await importCsvByPath(picked);
  }

  async function pickZipFilePath() {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "ZIP 压缩包", extensions: ["zip"] }],
    });
    if (typeof selected === "string") {
      return selected;
    }
    return null;
  }

  async function pickPrivateKeyFilePath() {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [
        { name: "私钥文件", extensions: ["pem", "key", "ppk", "txt"] },
        { name: "所有文件", extensions: ["*"] },
      ],
    });
    if (typeof selected === "string") {
      return selected;
    }
    return null;
  }

  function applyPrivateKeyPathToServers(targetServerIds: string[], privateKeyPath: string) {
    const targetKeyServers = servers.filter(
      (server) => targetServerIds.includes(server.id) && server.authType === "key",
    );

    if (targetKeyServers.length > 0) {
      setRuntimeAuths((prev) => {
        const next = { ...prev };
        for (const server of targetKeyServers) {
          next[server.id] = {
            ...next[server.id],
            privateKeyPath,
          };
        }
        return next;
      });
    }

    return targetKeyServers.length;
  }

  async function importKeyZipByPath(zipPath: string, targetServerIds: string[]) {
    setLoading(true);
    try {
      const result = await invoke<KeyArchiveImportResult>("key_archive_import", {
        archivePath: zipPath,
      });

      setImportedKeyPaths(result.keyPaths);
      if (result.keyPaths.length === 0) {
        setStatusText(`ZIP 已解压（${result.fileCount} 个文件），但未识别到私钥文件`);
        return;
      }

      const firstKeyPath =
        result.keyPaths.find((path) => !path.toLowerCase().endsWith(".ppk")) ?? result.keyPaths[0];
      const targetKeyServers = servers.filter(
        (server) => targetServerIds.includes(server.id) && server.authType === "key",
      );

      if (targetKeyServers.length > 0) {
        setRuntimeAuths((prev) => {
          const next = { ...prev };
          for (const server of targetKeyServers) {
            next[server.id] = {
              ...next[server.id],
              privateKeyPath: firstKeyPath,
            };
          }
          return next;
        });
      }

      setStatusText(
        `ZIP 导入成功，识别到 ${result.keyPaths.length} 个私钥。已为 ${targetKeyServers.length} 台密钥服务器自动填入第一个私钥路径。`,
      );
    } catch (error) {
      setStatusText(`ZIP 导入失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function onPickZipForSelectedServers() {
    if (!hasSelectedServers) {
      setStatusText("请先勾选服务器");
      return;
    }
    const zipPath = await pickZipFilePath();
    if (!zipPath) {
      return;
    }
    await importKeyZipByPath(zipPath, selectedServerIds);
  }

  async function onPickZipForServer(serverId: string) {
    const zipPath = await pickZipFilePath();
    if (!zipPath) {
      return;
    }
    await importKeyZipByPath(zipPath, [serverId]);
  }

  async function onPickPrivateKeyForSelectedServers() {
    if (!hasSelectedServers) {
      setStatusText("请先勾选服务器");
      return;
    }
    const privateKeyPath = await pickPrivateKeyFilePath();
    if (!privateKeyPath) {
      return;
    }

    const assignedCount = applyPrivateKeyPathToServers(selectedServerIds, privateKeyPath);
    if (assignedCount === 0) {
      setStatusText("已选择私钥文件，但当前选中项里没有“私钥登录”服务器");
      return;
    }
    setStatusText(`已为 ${assignedCount} 台服务器设置私钥：${privateKeyPath}`);
  }

  async function onPickPrivateKeyForServer(serverId: string) {
    const privateKeyPath = await pickPrivateKeyFilePath();
    if (!privateKeyPath) {
      return;
    }

    const assignedCount = applyPrivateKeyPathToServers([serverId], privateKeyPath);
    if (assignedCount === 0) {
      setStatusText("该服务器不是私钥登录类型，请先编辑为“私钥登录”");
      return;
    }
    setStatusText(`已设置私钥路径：${privateKeyPath}`);
  }

  async function onPreflight(server: ServerProfile) {
    setLoading(true);
    try {
      const runtimeAuth = runtimeAuths[server.id];
      const result = await invoke<SshPreflightResponse>("ssh_preflight", {
        serverId: server.id,
        runtimeAuth,
      });
      setPreflightByServer((prev) => ({ ...prev, [server.id]: result }));

      if (result.status === "ok") {
        setStatusText(`预检通过：${server.name}`);
      } else {
        setStatusText(`预检 ${preflightLabel[result.status] ?? result.status}：${result.message ?? ""}`);
      }
    } catch (error) {
      setStatusText(`预检失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function onTrustHost(server: ServerProfile) {
    const preflight = preflightByServer[server.id];
    if (!preflight?.fingerprint) {
      setStatusText("当前没有可确认的主机指纹");
      return;
    }

    const payload: TrustHostPayload = {
      host: server.host,
      port: server.port,
      fingerprint: preflight.fingerprint,
    };

    setLoading(true);
    try {
      await invoke("hostkey_trust", { payload });
      setStatusText(`已信任 ${server.name} 指纹，正在重新预检...`);
      await onPreflight(server);
    } catch (error) {
      setStatusText(`信任指纹失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  function initializeProgress(serverIds: string[]) {
    const next: Record<string, ServerProgress> = {};
    for (const serverId of serverIds) {
      next[serverId] = {
        ...defaultProgress(),
        status: "running",
        message: "等待调度",
      };
    }
    setTaskServerProgress(next);
  }

  async function subscribeTaskEvents(taskId: string) {
    if (unlistenRef.current) {
      unlistenRef.current();
      unlistenRef.current = null;
    }

    const eventName = await invoke<string>("task_stream_subscribe", { taskId });
    unlistenRef.current = await listen<TaskEvent>(eventName, async (event) => {
      const payload = event.payload;
      const text = `[${payload.timestamp}] ${payload.serverId ?? "批量任务"} ${payload.phase}: ${payload.message}`;
      setTaskEvents((prev) => [text, ...prev].slice(0, 300));

      if (payload.serverId) {
        setTaskServerProgress((prev) => {
          const current = prev[payload.serverId!] ?? defaultProgress();
          const nextPercent =
            payload.phase === "done" || payload.phase === "skipped"
              ? 100
              : phaseToProgress(payload.phase, current.percent);
          const eventLine = `[${payload.timestamp}] ${payload.phase}: ${payload.message}`;

          let nextStatus = current.status;
          if (payload.phase === "done") {
            nextStatus = "success";
          } else if (payload.phase === "skipped") {
            nextStatus = "skipped";
          } else if (isFailureSignal(payload.message)) {
            nextStatus = "failed";
          } else if (nextStatus === "idle") {
            nextStatus = "running";
          }

          return {
            ...prev,
            [payload.serverId!]: {
              percent: nextPercent,
              phase: payload.phase,
              message: payload.message,
              status: nextStatus,
              logs: [eventLine, ...current.logs].slice(0, 120),
              updatedAt: payload.timestamp,
            },
          };
        });
      }

      if (payload.phase === "done" && !payload.serverId) {
        await loadTaskResult(taskId);
      }
    });
  }

  async function runTask(mode: TaskMode, useAllServers = false) {
    const targetServerIds = useAllServers ? servers.map((server) => server.id) : selectedServerIds;
    if (targetServerIds.length === 0) {
      setStatusText(useAllServers ? "当前没有服务器可执行任务" : "请至少选择一台服务器");
      return;
    }

    const effectiveParallel = resolveParallelLimit();
    setLoading(true);
    try {
      initializeProgress(targetServerIds);
      const accepted = await invoke<TaskRunAccepted>("task_run", {
        serverIds: targetServerIds,
        mode,
        runtimeAuths,
        parallelLimit: effectiveParallel,
      });
      setActiveTaskId(accepted.taskId);
      setTaskResult(null);
      setTaskEvents([]);
      await subscribeTaskEvents(accepted.taskId);
      setStatusText(
        `任务已启动：${accepted.taskId}，目标 ${targetServerIds.length} 台，并发 ${effectiveParallel}`,
      );
    } catch (error) {
      setStatusText(`启动任务失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function cancelTask() {
    if (!activeTaskId) {
      return;
    }
    setLoading(true);
    try {
      await invoke("task_cancel", { taskId: activeTaskId });
      setStatusText(`已请求取消任务：${activeTaskId}`);
    } catch (error) {
      setStatusText(`取消任务失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function loadTaskResult(taskId?: string) {
    const targetTaskId = taskId ?? activeTaskId;
    if (!targetTaskId) {
      setStatusText("当前没有任务 ID");
      return;
    }

    setLoading(true);
    try {
      const result = await invoke<TaskResultPayload>("result_get", { taskId: targetTaskId });
      setTaskResult(result);
      setTaskServerProgress((prev) => {
        const next = { ...prev };
        for (const item of result.items) {
          const current = next[item.serverId] ?? defaultProgress();
          const status = (item.status as ProgressStatus) ?? "running";
          const resultMessage =
            item.errorMessage ??
            (item.extractedUrls.length > 0
              ? `已提取 ${item.extractedUrls.length} 条链接`
              : "执行完成，无可展示链接");
          const resultLine = `[result] ${item.phase}: ${resultMessage}`;
          next[item.serverId] = {
            percent: 100,
            phase: item.phase,
            message: resultMessage,
            status,
            logs: [resultLine, ...current.logs].slice(0, 120),
            updatedAt: nowText(),
          };
        }
        return next;
      });
      setStatusText(`已加载任务结果：${targetTaskId}`);
    } catch (error) {
      setStatusText(`加载任务结果失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function exportTaskResultWithPicker() {
    if (!activeTaskId) {
      setStatusText("当前没有任务 ID");
      return;
    }

    const selected = await save({
      defaultPath: exportPath.trim() || exportFileNameSuggestion(),
      filters: [{ name: "文本文件", extensions: ["txt"] }],
    });
    if (typeof selected !== "string" || !selected.trim()) {
      return;
    }

    setExportPath(selected);
    setLoading(true);
    try {
      const path = await invoke<string>("result_export_txt", {
        taskId: activeTaskId,
        outputPath: selected,
      });
      setStatusText(`TXT 导出成功：${path}`);
    } catch (error) {
      setStatusText(`导出失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function copyUrls(serverId?: string) {
    if (!taskResult) {
      setStatusText("当前没有可复制的结果");
      return;
    }

    const items = serverId
      ? taskResult.items.filter((item) => item.serverId === serverId)
      : taskResult.items;

    const urls = items.flatMap((item) => item.extractedUrls);
    if (urls.length === 0) {
      setStatusText("没有提取到可复制的订阅/节点链接");
      return;
    }

    await navigator.clipboard.writeText(urls.join("\n"));
    setStatusText(`已复制 ${urls.length} 条订阅/节点链接`);
  }

  function renderPreflightCell(server: ServerProfile) {
    const info = preflightByServer[server.id];
    if (!info) {
      return <span className="dim">未检查</span>;
    }

    return (
      <div className="preflight-cell">
        <span className={`pill ${info.status}`}>{preflightLabel[info.status] ?? info.status}</span>
        {info.fingerprint ? <code>{info.fingerprint}</code> : null}
        {info.message ? <small>{info.message}</small> : null}
        {info.status === "untrusted_host" || info.status === "host_key_mismatch" ? (
          <button className="btn tiny" onClick={() => onTrustHost(server)}>
            {info.status === "host_key_mismatch" ? "更新指纹" : "信任指纹"}
          </button>
        ) : null}
      </div>
    );
  }

  function runtimeAuthFor(serverId: string): RuntimeAuth {
    return runtimeAuths[serverId] ?? {};
  }

  return (
    <main className="layout">
      <header className="hero">
        <h1>Auto Make Net</h1>
        <p>Windows 桌面端：SSH 批量部署 Argosbx，提取并导出订阅/节点链接</p>
        <div className="hero-metrics">
          <span className="meta-chip">服务器 {servers.length} 台</span>
          <span className="meta-chip">已选 {selectedServerIds.length} 台</span>
          <span className="meta-chip">并发 {resolveParallelLimit()}</span>
          {activeTaskId ? <span className="meta-chip">任务进行中</span> : null}
        </div>
      </header>

      <section className="card">
        <div className="section-head">
          <h2>服务器列表与批量操作</h2>
          <span className="dim">新增/编辑使用弹窗。CSV 导入仅新增，不做删除。</span>
        </div>

        <div className="toolbar">
          <div className="toolbar-row">
            <button className="btn" onClick={startCreate} disabled={loading}>新增服务器</button>
            <button className="btn ghost" onClick={refreshServers} disabled={loading}>刷新服务器</button>
            <button className="btn ghost" onClick={selectAllServers} disabled={loading || !hasAnyServer}>全选 / 取消全选</button>
            <button className="btn ghost" onClick={onPickAndImportCsv} disabled={loading}>选择 CSV 并导入</button>
            <button className="btn ghost" onClick={onPickZipForSelectedServers} disabled={loading || !hasSelectedServers}>导入ZIP到已选</button>
            <button className="btn ghost" onClick={onPickPrivateKeyForSelectedServers} disabled={loading || !hasSelectedServers}>选择私钥到已选</button>
            <span className="dim">已选择 {selectedServerIds.length} / {servers.length} 台</span>
            {importPath ? <code>{importPath}</code> : null}
          </div>

          <div className="toolbar-row">
            <label className="dim" htmlFor="parallelLimitInput">并发</label>
            <input
              id="parallelLimitInput"
              className="parallel-input"
              value={parallelLimit}
              onChange={(e) => setParallelLimit(e.target.value)}
              placeholder="3"
            />
            <button className="btn" onClick={() => runTask("list_only")} disabled={loading || !hasSelectedServers}>已选 list</button>
            <button className="btn" onClick={() => runTask("list_then_deploy")} disabled={loading || !hasSelectedServers}>已选 list+部署</button>
            <button className="btn ghost" onClick={() => runTask("list_only", true)} disabled={loading || !hasAnyServer}>全部 list</button>
            <button className="btn ghost" onClick={() => runTask("list_then_deploy", true)} disabled={loading || !hasAnyServer}>全部 list+部署</button>
            <button className="btn ghost" onClick={() => loadTaskResult()} disabled={loading || !activeTaskId}>刷新结果</button>
            <button className="btn ghost" onClick={() => copyUrls()} disabled={loading || !taskResult}>复制全部链接</button>
            <button className="btn" onClick={exportTaskResultWithPicker} disabled={loading || !activeTaskId}>导出TXT（选择位置）</button>
            <button className="btn danger" onClick={cancelTask} disabled={loading || !activeTaskId}>取消任务</button>
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>
                <label className="checkbox-row">
                  <input type="checkbox" checked={allServersSelected} onChange={selectAllServers} />
                  全选
                </label>
              </th>
              <th>名称</th>
              <th>地址</th>
              <th>用户</th>
              <th>认证</th>
              <th>预检</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {servers.map((server) => (
              <tr key={server.id}>
                <td>
                  <input
                    type="checkbox"
                    checked={selectedServerIds.includes(server.id)}
                    onChange={() => toggleServer(server.id)}
                  />
                </td>
                <td>{server.name}</td>
                <td>{server.host}:{server.port}</td>
                <td>{server.username}</td>
                <td>{server.authType === "password" ? "密码" : "私钥"}</td>
                <td>{renderPreflightCell(server)}</td>
                <td>
                  <button className="btn tiny" onClick={() => startEdit(server)}>编辑</button>
                  <button className="btn tiny" onClick={() => onPreflight(server)}>预检</button>
                  <button className="btn tiny" onClick={() => onPickZipForServer(server.id)} disabled={loading}>导入ZIP</button>
                  <button className="btn tiny ghost" onClick={() => onPickPrivateKeyForServer(server.id)} disabled={loading}>选择私钥</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {activeTaskId ? <p className="dim">当前任务：<code>{activeTaskId}</code></p> : null}
      </section>

      <section className="card">
        <h2>运行时认证（已选服务器）</h2>
        {selectedServers.length === 0 ? <p className="dim">请先勾选服务器。</p> : null}
        {selectedServers.map((server) => {
          const auth = runtimeAuthFor(server.id);
          return (
            <div className="runtime-row" key={server.id}>
              <strong>{server.name}</strong>
              {server.authType === "password" ? (
                <input
                  type="password"
                  placeholder="运行时密码（如未勾选保存密码）"
                  value={auth.password ?? ""}
                  onChange={(e) => updateRuntimeAuth(server.id, { password: e.target.value })}
                />
              ) : (
                <>
                  <select
                    value={auth.privateKeyPath ?? ""}
                    onChange={(e) => updateRuntimeAuth(server.id, { privateKeyPath: e.target.value })}
                  >
                    <option value="">从已导入密钥中选择（可选）</option>
                    {importedKeyPaths.map((path) => (
                      <option key={path} value={path}>{path}</option>
                    ))}
                  </select>
                  <div className="inline-actions">
                    <input
                      placeholder="私钥文件路径（可手填覆盖）"
                      value={auth.privateKeyPath ?? ""}
                      onChange={(e) => updateRuntimeAuth(server.id, { privateKeyPath: e.target.value })}
                    />
                    <button
                      className="btn tiny ghost"
                      type="button"
                      disabled={loading}
                      onClick={() => onPickPrivateKeyForServer(server.id)}
                    >
                      选择私钥文件
                    </button>
                  </div>
                  <input
                    type="password"
                    placeholder="私钥口令（可选）"
                    value={auth.privateKeyPassphrase ?? ""}
                    onChange={(e) => updateRuntimeAuth(server.id, { privateKeyPassphrase: e.target.value })}
                  />
                </>
              )}
              <input
                type="password"
                placeholder="sudo 密码（可选）"
                value={auth.sudoPassword ?? ""}
                onChange={(e) => updateRuntimeAuth(server.id, { sudoPassword: e.target.value })}
              />
            </div>
          );
        })}
      </section>

      <section className="split-grid">
        <article className="card">
          <h2>任务进度与实时日志</h2>
          {progressList.length === 0 ? <p className="dim">暂无进行中的服务器进度。</p> : null}
          <div className="progress-list">
            {progressList.map(([serverId, progress]) => {
              const serverName = serverById[serverId]?.name ?? serverId;
              return (
                <div className="progress-item" key={serverId}>
                  <div className="progress-head">
                    <strong>{serverName}</strong>
                    <span className={`pill ${progress.status}`}>{progressStatusLabel[progress.status]}</span>
                    <span className="dim">{Math.round(progress.percent)}%</span>
                  </div>
                  <div className="progress-track">
                    <div
                      className={`progress-fill ${progress.status}`}
                      style={{ width: `${Math.max(2, Math.min(100, progress.percent))}%` }}
                    />
                  </div>
                  <div className="progress-meta">
                    <span>{progress.phase}</span>
                    <span>{progress.message}</span>
                  </div>
                  <details>
                    <summary>查看实时日志</summary>
                    <div className="inline-log">
                      {progress.logs.length === 0 ? <div className="dim">暂无日志</div> : null}
                      {progress.logs.map((line, idx) => <div key={`${serverId}-${idx}`}>{line}</div>)}
                    </div>
                  </details>
                </div>
              );
            })}
          </div>
        </article>

        <article className="card">
          <h2>任务结果</h2>
          {!taskResult ? <p className="dim">暂无结果。</p> : null}
          {taskResult ? (
            <>
              <p className="dim">
                总数={taskResult.summary.total} 成功={taskResult.summary.success} 失败={taskResult.summary.failed}
              </p>
              {taskResult.items.map((item) => (
                <div className="result-item" key={`${item.serverId}-${item.rawLogRef}`}>
                  <div className="result-head">
                    <strong>{serverById[item.serverId]?.name ?? item.serverId}</strong>
                    <span className={`pill ${item.status}`}>{taskStatusLabel[item.status] ?? item.status}</span>
                    <button className="btn tiny" onClick={() => copyUrls(item.serverId)}>复制</button>
                  </div>
                  <div className="urls">
                    {item.extractedUrls.length === 0 ? <span className="dim">未提取到订阅/节点链接。</span> : null}
                    {item.extractedUrls.map((url) => <code key={url}>{url}</code>)}
                    {item.errorMessage ? <small>{item.errorMessage}</small> : null}
                  </div>
                </div>
              ))}
            </>
          ) : null}
        </article>
      </section>

      <section className="card">
        <h2>任务事件</h2>
        <div className="log-view">
          {taskEvents.length === 0 ? <div className="dim">暂无事件。</div> : null}
          {taskEvents.map((line, idx) => <div key={`${line}-${idx}`}>{line}</div>)}
        </div>
      </section>

      <footer className="notice">仅用于你拥有或明确授权管理的服务器。</footer>
      <div className="status">{statusText}</div>

      {formModalOpen ? (
        <div className="modal-mask" onClick={closeFormModal}>
          <div className="modal-panel" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <h3>{form.id ? "编辑服务器" : "新增服务器"}</h3>
              <button className="btn tiny ghost" onClick={closeFormModal}>关闭</button>
            </div>
            <form onSubmit={onSaveServer} className="grid-form">
              <input value={form.name} placeholder="名称" onChange={(e) => setForm((v) => ({ ...v, name: e.target.value }))} />
              <input value={form.host} placeholder="IP / 域名" onChange={(e) => setForm((v) => ({ ...v, host: e.target.value }))} />
              <input value={form.port} placeholder="端口" onChange={(e) => setForm((v) => ({ ...v, port: e.target.value }))} />
              <input value={form.username} placeholder="SSH 用户名" onChange={(e) => setForm((v) => ({ ...v, username: e.target.value }))} />
              <select value={form.authType} onChange={(e) => setForm((v) => ({ ...v, authType: e.target.value as "password" | "key" }))}>
                <option value="password">密码登录</option>
                <option value="key">私钥登录</option>
              </select>
              <label className="checkbox-row">
                <input type="checkbox" checked={form.rememberPassword} onChange={(e) => setForm((v) => ({ ...v, rememberPassword: e.target.checked }))} />
                将密码保存在系统加密凭据中
              </label>
              <input
                type="password"
                value={form.password}
                placeholder={form.id ? "新密码（可留空）" : "密码"}
                onChange={(e) => setForm((v) => ({ ...v, password: e.target.value }))}
              />
              <div className="inline-actions">
                <button className="btn" type="submit" disabled={loading}>{form.id ? "保存更新" : "创建"}</button>
                <button className="btn ghost" type="button" onClick={closeFormModal}>取消</button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </main>
  );
}

export default App;

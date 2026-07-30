"use strict";

const cp = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const readline = require("readline");
const vscode = require("vscode");

const DEFAULT_SESSION_LIMIT = 100;
const DEFAULT_OVERVIEW_LIMIT = 50;
const OTHER_HISTORY_WORKSPACE_LIMIT = 5;
const ACTIVE_SESSION_STALE_MS = 12 * 60 * 60 * 1000;
const CANONICAL_STORE_SUBDIRS = [
  "codex/sessions",
  "claude/sessions"
];
const CANONICAL_STORE_GLOB_DIRS = ["codex/sessions/v2", "claude/sessions/v2"];
const CAUSHELL_CLI_ENV_NAMES = [
  "CAUSHELL_CODEX_RUNTIME_PATH",
  "CAUSHELL_CLAUDE_RUNTIME_PATH",
  "CODEX_PLUGIN_OPTION_RUNTIME_PATH",
  "CLAUDE_PLUGIN_OPTION_RUNTIME_PATH"
];
const PANE_CURRENT_RUNNING = "current_running";
const PANE_OTHER_RUNNING = "other_running";
const PANE_CURRENT_HISTORY = "current_history";
const PANE_OTHER_HISTORY = "other_history";
const SESSION_PANES = [
  { viewId: "caushell.currentRunningSessions", paneId: PANE_CURRENT_RUNNING },
  { viewId: "caushell.otherRunningSessions", paneId: PANE_OTHER_RUNNING },
  { viewId: "caushell.currentHistorySessions", paneId: PANE_CURRENT_HISTORY },
  { viewId: "caushell.otherHistorySessions", paneId: PANE_OTHER_HISTORY }
];

function activate(context) {
  const client = new CaushellClient(context);
  const modelStore = new SidebarModelStore(client);
  const sessionProviders = SESSION_PANES.map(
    (pane) => new SessionPaneProvider(modelStore, pane.paneId)
  );
  const refreshSessions = () => {
    modelStore.refresh();
    for (const provider of sessionProviders) {
      provider.refresh();
    }
  };

  context.subscriptions.push(
    ...SESSION_PANES.map((pane, index) =>
      vscode.window.registerTreeDataProvider(pane.viewId, sessionProviders[index])
    ),
    vscode.commands.registerCommand("caushell.refreshSessions", refreshSessions),
    vscode.commands.registerCommand("caushell.openSessionTimeline", (item) =>
      openSessionTimeline(context, client, item)
    ),
    vscode.commands.registerCommand("caushell.configureStoreRoot", () => configureStoreRoot()),
    vscode.commands.registerCommand("caushell.openConfig", () => openConfig(client)),
    vscode.commands.registerCommand("caushell.setFailureAction", () =>
      setFailureAction(client)
    ),
    vscode.workspace.onDidChangeWorkspaceFolders(refreshSessions),
    vscode.window.onDidChangeActiveTextEditor(refreshSessions),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("caushell")) {
        refreshSessions();
      }
    })
  );
}

function deactivate() {}

class CaushellClient {
  constructor(context) {
    this.context = context;
    this.titleResolver = new RuntimeSessionTitleResolver();
  }

  async queryStore(storeRoot, payload) {
    const cliPath = this.cliPath();
    return runQueryProcess(cliPath, storeRoot, payload);
  }

  async configPath() {
    return runCliProcess(this.cliPath(), ["config", "path"]);
  }

  async initializeConfig() {
    return runCliProcess(this.cliPath(), ["config", "init"]);
  }

  async setFailureAction(action) {
    return runCliProcess(this.cliPath(), [
      "config",
      "set",
      "failure_action",
      action
    ]);
  }

  storeDescriptors() {
    const configured = vscode.workspace
      .getConfiguration("caushell")
      .get("storeRoot", "")
      .trim();

    if (configured) {
      return [storeDescriptor(requireExistingConfiguredStoreRoot(expandHome(configured)))];
    }

    return canonicalStoreRoots().map((storeRoot) => storeDescriptor(storeRoot));
  }

  cliPath() {
    const configured = vscode.workspace
      .getConfiguration("caushell")
      .get("cliPath", "")
      .trim();

    if (configured) {
      return expandHome(configured);
    }

    const executable = process.platform === "win32" ? "caushell.exe" : "caushell";
    for (const envName of CAUSHELL_CLI_ENV_NAMES) {
      const value = envOption(envName);
      if (value) {
        return expandHome(value);
      }
    }

    const pathExecutable = findExecutableOnPath(executable);
    if (pathExecutable) {
      return pathExecutable;
    }

    for (const candidate of cliCandidates(this.context.extensionPath, executable)) {
      if (fileExists(candidate)) {
        return candidate;
      }
    }

    return executable;
  }

  clearSessionCaches() {
    this.titleResolver.clear();
  }
}

class RuntimeSessionTitleResolver {
  constructor() {
    this.titleCache = new Map();
    this.filePathCache = new Map();
    this.fileMissCache = new Set();
  }

  clear() {
    this.titleCache.clear();
  }

  async resolve(descriptor, session) {
    const cacheKey = sessionCacheKey(descriptor, session);
    const cached = this.titleCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const runtimeKind = runtimeKindForSession(session.runtime_name, descriptor.storeKind);
    let resolved = null;

    if (runtimeKind === "claude") {
      resolved = await this.resolveClaudeTitle(session.session_id);
    } else if (runtimeKind === "codex") {
      resolved = await this.resolveCodexTitle(session.session_id);
    }

    const result =
      resolved && resolved.displayTitle ? resolved : fallbackSessionTitle(session.session_id);
    this.titleCache.set(cacheKey, result);
    return result;
  }

  async resolveClaudeTitle(sessionId) {
    const filePath = this.resolveSessionFile("claude", sessionId);
    if (!filePath) {
      return null;
    }

    const displayTitle = await firstJsonlValue(filePath, (record) => {
      if (
        record &&
        record.type === "ai-title" &&
        record.sessionId === sessionId &&
        record.aiTitle
      ) {
        return normalizeSessionTitle(record.aiTitle);
      }
      return "";
    });

    if (!displayTitle) {
      return null;
    }

    return {
      displayTitle,
      titleSource: "claude_ai_title"
    };
  }

  async resolveCodexTitle(sessionId) {
    const filePath = this.resolveSessionFile("codex", sessionId);
    if (!filePath) {
      return null;
    }

    const displayTitle = await firstJsonlValue(filePath, (record) => {
      if (
        record &&
        record.type === "event_msg" &&
        record.payload &&
        record.payload.type === "user_message" &&
        record.payload.message
      ) {
        return derivePromptTitle(record.payload.message);
      }
      return "";
    });

    if (!displayTitle) {
      return null;
    }

    return {
      displayTitle,
      titleSource: "codex_first_user_message"
    };
  }

  resolveSessionFile(runtimeKind, sessionId) {
    const cacheKey = `${runtimeKind}:${sessionId}`;
    if (this.filePathCache.has(cacheKey)) {
      return this.filePathCache.get(cacheKey);
    }
    if (this.fileMissCache.has(cacheKey)) {
      return null;
    }

    let filePath = null;
    if (runtimeKind === "claude") {
      filePath = findSessionFile(
        path.join(os.homedir(), ".claude", "projects"),
        `${sessionId}.jsonl`,
        2
      );
    } else if (runtimeKind === "codex") {
      filePath = findSessionFile(
        path.join(os.homedir(), ".codex", "sessions"),
        `-${sessionId}.jsonl`,
        4
      );
    }

    if (!filePath) {
      this.fileMissCache.add(cacheKey);
      return null;
    }

    this.filePathCache.set(cacheKey, filePath);
    return filePath;
  }
}

class SidebarModelStore {
  constructor(client) {
    this.client = client;
    this.model = null;
    this.loading = null;
    this.error = null;
  }

  refresh() {
    this.client.clearSessionCaches();
    this.model = null;
    this.loading = null;
    this.error = null;
  }

  async getModel() {
    if (this.model) {
      return this.model;
    }
    if (!this.loading) {
      this.loading = loadSidebarModel(this.client)
        .then((model) => {
          this.model = model;
          this.error = null;
          return model;
        })
        .catch((error) => {
          this.error = error;
          this.model = emptySidebarModel(error);
          return this.model;
        })
        .finally(() => {
          this.loading = null;
        });
    }
    return this.loading;
  }
}

class SessionPaneProvider {
  constructor(modelStore, paneId) {
    this.modelStore = modelStore;
    this.paneId = paneId;
    this.changeEmitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this.changeEmitter.event;
  }

  refresh() {
    this.changeEmitter.fire();
  }

  getTreeItem(item) {
    return item;
  }

  async getChildren(item) {
    if (
      item instanceof SessionTreeItem ||
      item instanceof MessageTreeItem
    ) {
      return [];
    }

    try {
      const model = await this.modelStore.getModel();
      if (item instanceof RuntimeGroupTreeItem) {
        return item.sessions.map((session) => new SessionTreeItem(session));
      }
      if (item instanceof WorkspaceSummaryTreeItem) {
        return groupSessionsByRuntime(item.sessions).map(
          (group) => new RuntimeGroupTreeItem(group, this.paneId)
        );
      }
      return this.paneChildren(model);
    } catch (error) {
      return this.paneChildren(emptySidebarModel(error));
    }
  }

  paneChildren(model) {
    if (this.paneId === PANE_CURRENT_RUNNING) {
      return runtimeGroupItemsOrMessage(
        model.currentRunningGroups,
        this.paneId,
        "No running sessions matched the current VS Code workspace."
      );
    }

    if (this.paneId === PANE_OTHER_RUNNING) {
      return runtimeGroupItemsOrMessage(
        model.otherRunningGroups,
        this.paneId,
        "No running sessions matched other workspaces."
      );
    }

    if (this.paneId === PANE_CURRENT_HISTORY) {
      return runtimeGroupItemsOrMessage(
        model.currentHistoryGroups,
        this.paneId,
        "No historical sessions matched the current VS Code workspace."
      );
    }

    if (this.paneId === PANE_OTHER_HISTORY) {
      return otherHistorySummaryItems(model);
    }

    return [new MessageTreeItem("Unknown Caushell session pane.", "warning")];
  }
}

class SessionTreeItem extends vscode.TreeItem {
  constructor(session) {
    super(sessionIdentityLabel(session), vscode.TreeItemCollapsibleState.None);
    this.session = session;
    this.contextValue = "caushellSession";
    this.description = [
      decisionShortLabel(session.last_decision),
      `${session.check_count || 0} checks`
    ].filter(Boolean).join(" · ");
    this.tooltip = sessionTooltip(session);
    this.iconPath = new vscode.ThemeIcon(iconForSession(session.last_decision));
    this.command = {
      command: "caushell.openSessionTimeline",
      title: "Open Session Detail",
      arguments: [this]
    };
  }
}

class RuntimeGroupTreeItem extends vscode.TreeItem {
  constructor(group, paneId) {
    const expanded =
      paneId === PANE_CURRENT_RUNNING
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.Collapsed;
    super(`${group.label} (${group.sessions.length})`, expanded);
    this.paneId = paneId;
    this.sessions = group.sessions;
    this.contextValue = "caushellRuntimeGroup";
    this.description = "";
    this.tooltip = `${group.label}: ${sessionCountLabel(group.sessions.length)}`;
    this.iconPath = new vscode.ThemeIcon(iconForRuntimeKind(group.runtimeKind));
  }
}

class WorkspaceSummaryTreeItem extends vscode.TreeItem {
  constructor(group) {
    super(group.label, vscode.TreeItemCollapsibleState.Collapsed);
    this.sessions = group.sessions;
    this.contextValue = "caushellWorkspaceSummary";
    this.description = sessionCountLabel(group.sessions.length);
    this.tooltip = [
      group.workspaceRoot || group.label,
      runtimeMixLabel(group.sessions)
    ].filter(Boolean).join("\n");
    this.iconPath = new vscode.ThemeIcon("folder");
  }
}

class MessageTreeItem extends vscode.TreeItem {
  constructor(message, iconName, label) {
    super(label || message, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "caushellMessage";
    this.description = label ? message : "";
    this.tooltip = message;
    this.iconPath = new vscode.ThemeIcon(iconName || "info");
  }
}

async function loadSidebarModel(client) {
  const [sessionResult, runtimeRecords, activeSessionRecords, processCounts] = await Promise.all([
    loadSidebarSessions(client),
    Promise.resolve(discoverRuntimeRecords()),
    Promise.resolve(discoverActiveSessionRecords()),
    Promise.resolve(detectProcessCounts())
  ]);
  return buildSidebarModel({
    sessions: sessionResult.sessions,
    warnings: sessionResult.warnings,
    runtimeRecords,
    activeSessionRecords,
    processCounts
  });
}

async function loadSidebarSessions(client) {
  let descriptors = [];
  const warnings = [];

  try {
    descriptors = client.storeDescriptors();
  } catch (error) {
    warnings.push(error.message || String(error));
  }

  const results = await Promise.all(
    descriptors.map(async (descriptor) => {
      try {
        const response = await client.queryStore(descriptor.storeRoot, {
          query: "session_list",
          limit: DEFAULT_SESSION_LIMIT,
          scope: "all",
          order: "desc"
        });
        const sessions = await Promise.all(
          (response.sessions || []).map((session) =>
            decorateSession(descriptor, session, client.titleResolver)
          )
        );
        return { sessions, warning: "" };
      } catch (error) {
        return {
          sessions: [],
          warning: `${descriptor.label}: ${error.message || String(error)}`
        };
      }
    })
  );

  for (const result of results) {
    if (result.warning) {
      warnings.push(result.warning);
    }
  }

  return {
    sessions: dedupeSessions(results.flatMap((result) => result.sessions)).sort(compareSessionsDesc),
    warnings
  };
}

function buildSidebarModel({
  sessions,
  warnings,
  runtimeRecords,
  activeSessionRecords,
  processCounts
}) {
  const currentWorkspaceRoot = defaultWorkspaceRoot();
  const liveRuntimeRecords = runtimeRecords.filter((record) => record.alive);
  const liveActiveSessionRecords = activeSessionRecords.filter((record) => record.alive);
  const runningSessions = selectRunningSessions(sessions, liveActiveSessionRecords);
  const runningKeys = new Set(runningSessions.map((session) => session.session_key));
  const currentRunning = runningSessions.filter((session) =>
    workspaceMatchesCurrent(session.workspace_root, currentWorkspaceRoot)
  );
  const otherRunning = runningSessions.filter(
    (session) => !workspaceMatchesCurrent(session.workspace_root, currentWorkspaceRoot)
  );
  const currentHistorical = sessions.filter(
    (session) =>
      !runningKeys.has(session.session_key) &&
      workspaceMatchesCurrent(session.workspace_root, currentWorkspaceRoot)
  );
  const otherHistory = sessions.filter(
    (session) =>
      !runningKeys.has(session.session_key) &&
      !workspaceMatchesCurrent(session.workspace_root, currentWorkspaceRoot)
  );
  const runtimeCount = liveRuntimeRecords.length || processCounts.runtime;
  const otherHistoryGroups = groupSessionsByWorkspace(otherHistory, currentWorkspaceRoot);
  const visibleOtherHistoryGroups = otherHistoryGroups.slice(0, OTHER_HISTORY_WORKSPACE_LIMIT);

  return {
    generatedAt: new Date().toISOString(),
    currentWorkspaceRoot,
    totalSessionCount: sessions.length,
    processCounts: {
      ...processCounts,
      runtime: runtimeCount
    },
    warnings,
    runtimeRecords,
    activeSessionRecords,
    currentRunningGroups: groupSessionsByRuntime(currentRunning),
    otherRunningGroups: groupSessionsByRuntime(otherRunning),
    currentHistoryGroups: groupSessionsByRuntime(currentHistorical),
    otherHistoryGroups: visibleOtherHistoryGroups,
    hiddenOtherHistoryWorkspaceCount: Math.max(
      otherHistoryGroups.length - visibleOtherHistoryGroups.length,
      0
    ),
    currentRunningCount: currentRunning.length,
    otherRunningCount: otherRunning.length,
    currentHistoryCount: currentHistorical.length,
    otherHistoryCount: otherHistory.length
  };
}

function emptySidebarModel(error) {
  return {
    generatedAt: new Date().toISOString(),
    currentWorkspaceRoot: defaultWorkspaceRoot(),
    totalSessionCount: 0,
    processCounts: { codex: 0, claude: 0, runtime: 0 },
    warnings: error ? [error.message || String(error)] : [],
    runtimeRecords: [],
    activeSessionRecords: [],
    currentRunningGroups: [],
    otherRunningGroups: [],
    currentHistoryGroups: [],
    otherHistoryGroups: [],
    hiddenOtherHistoryWorkspaceCount: 0,
    currentRunningCount: 0,
    otherRunningCount: 0,
    currentHistoryCount: 0,
    otherHistoryCount: 0
  };
}

function runtimeGroupItemsOrMessage(groups, paneId, emptyMessage) {
  if (groups.length === 0) {
    return [new MessageTreeItem(emptyMessage, "info")];
  }
  return groups.map((group) => new RuntimeGroupTreeItem(group, paneId));
}

function otherHistorySummaryItems(model) {
  if (model.otherHistoryCount === 0) {
    return [new MessageTreeItem("No history from other workspaces.", "info")];
  }

  const items = model.otherHistoryGroups.map((group) => new WorkspaceSummaryTreeItem(group));
  if (model.hiddenOtherHistoryWorkspaceCount > 0) {
    items.push(
      new MessageTreeItem(
        `and ${model.hiddenOtherHistoryWorkspaceCount} more workspaces`,
        "ellipsis",
        "..."
      )
    );
  }
  return items;
}

function selectRunningSessions(sessions, liveActiveSessionRecords) {
  const selected = [];
  const selectedKeys = new Set();

  for (const record of liveActiveSessionRecords) {
    if (!record.sessionId) {
      continue;
    }
    const candidate = sessions.find(
      (session) =>
        !selectedKeys.has(session.session_key) &&
        runtimeRecordMatchesSession(record, session)
    );
    if (candidate) {
      selected.push(candidate);
      selectedKeys.add(candidate.session_key);
    }
  }

  return selected.sort(compareSessionsDesc);
}

function runtimeRecordMatchesSession(record, session) {
  if (!record.sessionId || record.sessionId !== session.session_id) {
    return false;
  }

  const sessionRuntimeKind = runtimeKindForSession(session.runtime_name, session.storeKind);
  if (record.runtimeKind && sessionRuntimeKind !== record.runtimeKind) {
    return false;
  }

  if (
    record.workspaceRoot &&
    session.workspace_root &&
    !workspaceRootsMatch(session.workspace_root, record.workspaceRoot)
  ) {
    return false;
  }

  const recordStoreGroup = storeIdentityGroupForRoot(
    record.storeRoot || record.filePath || "",
    record.runtimeKind
  );
  if (session.storeIdentityGroup && recordStoreGroup !== session.storeIdentityGroup) {
    return false;
  }

  return true;
}

function groupSessionsByWorkspace(sessions, currentWorkspaceRoot) {
  const groups = new Map();
  for (const session of sessions) {
    const workspaceRoot = session.workspace_root || "";
    const key = workspaceRoot || "__unknown_workspace__";
    if (!groups.has(key)) {
      groups.set(key, {
        workspaceRoot,
        label: workspaceScopeLabel(workspaceRoot),
        isCurrent: workspaceMatchesCurrent(workspaceRoot, currentWorkspaceRoot),
        latestObservedAtMs: 0,
        sessions: []
      });
    }
    const group = groups.get(key);
    group.sessions.push(session);
    group.latestObservedAtMs = Math.max(
      group.latestObservedAtMs,
      session.last_observed_at_ms || 0
    );
  }

  return [...groups.values()]
    .map((group) => ({
      ...group,
      sessions: group.sessions.sort(compareSessionsDesc)
    }))
    .sort((left, right) => {
      if (left.isCurrent !== right.isCurrent) {
        return left.isCurrent ? -1 : 1;
      }
      if (left.latestObservedAtMs !== right.latestObservedAtMs) {
        return right.latestObservedAtMs - left.latestObservedAtMs;
      }
      return left.label.localeCompare(right.label);
    });
}

function groupSessionsByRuntime(sessions) {
  const groups = new Map();
  for (const session of sessions) {
    const runtimeKind = session.runtimeKind || runtimeKindForSession(session.runtime_name, session.storeKind);
    const key = runtimeKind || "unknown";
    if (!groups.has(key)) {
      groups.set(key, {
        runtimeKind: key,
        label: runtimeGroupLabel(key, session.runtimeLabel),
        latestObservedAtMs: 0,
        sessions: []
      });
    }
    const group = groups.get(key);
    group.sessions.push(session);
    group.latestObservedAtMs = Math.max(
      group.latestObservedAtMs,
      session.last_observed_at_ms || 0
    );
  }

  return [...groups.values()]
    .map((group) => ({
      ...group,
      sessions: group.sessions.sort(compareSessionsDesc)
    }))
    .sort((left, right) => {
      const orderDiff = runtimeGroupOrder(left.runtimeKind) - runtimeGroupOrder(right.runtimeKind);
      if (orderDiff !== 0) {
        return orderDiff;
      }
      if (left.latestObservedAtMs !== right.latestObservedAtMs) {
        return right.latestObservedAtMs - left.latestObservedAtMs;
      }
      return left.label.localeCompare(right.label);
    });
}

function dedupeSessions(sessions) {
  const selected = new Map();
  for (const session of sessions) {
    const key = session.session_key;
    const current = selected.get(key);
    if (!current || isBetterSessionRepresentative(session, current)) {
      selected.set(key, session);
    }
  }
  return [...selected.values()];
}

function isBetterSessionRepresentative(candidate, current) {
  for (const field of [
    "last_observed_at_ms",
    "check_count",
    "event_count",
    "last_event_index",
    "last_sequence_no"
  ]) {
    const left = numericSessionValue(candidate[field]);
    const right = numericSessionValue(current[field]);
    if (left !== right) {
      return left > right;
    }
  }

  const candidateHasWorkspace = Boolean(candidate.workspace_root);
  const currentHasWorkspace = Boolean(current.workspace_root);
  if (candidateHasWorkspace !== currentHasWorkspace) {
    return candidateHasWorkspace;
  }

  const candidateHasTitle = candidate.titleSource && candidate.titleSource !== "session_id";
  const currentHasTitle = current.titleSource && current.titleSource !== "session_id";
  if (candidateHasTitle !== currentHasTitle) {
    return candidateHasTitle;
  }

  const candidateRank = storeRootPreferenceRank(candidate.storeRoot);
  const currentRank = storeRootPreferenceRank(current.storeRoot);
  if (candidateRank !== currentRank) {
    return candidateRank < currentRank;
  }

  return String(candidate.storeRoot || "").localeCompare(String(current.storeRoot || "")) < 0;
}

function numericSessionValue(value) {
  const parsed = Number(value || 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

function storeRootPreferenceRank(storeRoot) {
  const text = String(storeRoot || "");
  if (text.includes(`${path.sep}sessions${path.sep}v2${path.sep}`)) {
    return 0;
  }
  if (text.endsWith(`${path.sep}sessions`)) {
    return 1;
  }
  if (text.endsWith(`${path.sep}sessions-v2`)) {
    return 2;
  }
  return 3;
}

function discoverRuntimeRecords() {
  const records = [];
  const seen = new Set();
  for (const root of runtimeRecordRoots()) {
    for (const filePath of findFilesNamed(root, "daemon.json", 6)) {
      const record = readJsonFile(filePath);
      if (!record) {
        continue;
      }
      const pid = Number(record.pid || 0);
      const key = `${pid}:${record.instance_id || ""}:${record.socket_path || filePath}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      records.push({
        filePath,
        pid,
        alive: pid > 0 && runtimeProcessAlive(pid, record),
        runtimeKind: runtimeKindForRecord(record, filePath),
        workspaceHash: record.workspace_hash || "",
        storeRoot: record.store_root || "",
        socketPath: record.socket_path || "",
        runtimeFingerprint: record.runtime_fingerprint || "",
        instanceId: record.instance_id || "",
        status: record.status || "",
        startedAtMs: Number(record.started_at_ms || 0)
      });
    }
  }
  return records;
}

function discoverActiveSessionRecords() {
  const records = [];
  const seen = new Set();
  for (const root of runtimeRecordRoots()) {
    for (const filePath of findFilesNamed(root, "active-session.json", 8)) {
      const record = readJsonFile(filePath);
      if (!record || record.record_type !== "active_session") {
        continue;
      }
      const pid = Number(record.daemon_pid || 0);
      const key = `${record.runtime_name || ""}:${record.session_id || ""}:${filePath}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      records.push({
        filePath,
        pid,
        alive: activeSessionRecordAlive(record, pid),
        sessionId: String(record.session_id || ""),
        runtimeKind: runtimeKindForSession(record.runtime_name || "", ""),
        workspaceRoot: normalizeWorkspaceRoot(record.workspace_root || ""),
        workspaceHash: record.workspace_hash || "",
        storeRoot: record.store_root || "",
        socketPath: record.socket_path || "",
        daemonInstanceId: record.daemon_instance_id || "",
        runtimeFingerprint: record.runtime_fingerprint || "",
        heartbeatAtMs: Number(record.heartbeat_at_ms || 0),
        heartbeatAt: record.heartbeat_at || "",
        startedAt: record.started_at || "",
        lastEventName: record.last_event_name || ""
      });
    }
  }
  return records;
}

function runtimeRecordRoots() {
  const roots = [];
  const seen = new Set();
  const xdgRuntimeDir = envOption("XDG_RUNTIME_DIR");
  if (xdgRuntimeDir) {
    pushUnique(roots, seen, path.join(expandHome(xdgRuntimeDir), "caushell"));
  }
  pushUnique(roots, seen, path.join(os.tmpdir(), `caushell-${currentUid()}`));
  return roots.filter((root) => fileExists(root));
}

function currentUid() {
  if (typeof process.getuid === "function") {
    return process.getuid();
  }
  return "unknown";
}

function findFilesNamed(rootPath, fileName, maxDepth) {
  if (!fileExists(rootPath)) {
    return [];
  }
  const matches = [];
  const stack = [{ directory: rootPath, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || current.depth > maxDepth) {
      continue;
    }

    let entries = [];
    try {
      entries = fs.readdirSync(current.directory, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const entryPath = path.join(current.directory, entry.name);
      if (entry.isFile() && entry.name === fileName) {
        matches.push(entryPath);
      } else if (entry.isDirectory() && current.depth < maxDepth) {
        stack.push({ directory: entryPath, depth: current.depth + 1 });
      }
    }
  }
  return matches;
}

function readJsonFile(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function runtimeProcessAlive(pid, record) {
  if (!processAlive(pid)) {
    return false;
  }

  const cmdline = processCmdline(pid);
  if (!cmdline) {
    return true;
  }

  if (!isCaushellRuntimeProcess(cmdline.toLowerCase())) {
    return false;
  }
  if (record.socket_path && !cmdline.includes(record.socket_path)) {
    return false;
  }
  if (record.store_root && !cmdline.includes(record.store_root)) {
    return false;
  }
  return true;
}

function activeSessionRecordAlive(record, pid) {
  if (!record || !record.session_id || pid <= 0) {
    return false;
  }
  const heartbeatAtMs = Number(record.heartbeat_at_ms || 0);
  if (!heartbeatAtMs || Date.now() - heartbeatAtMs > ACTIVE_SESSION_STALE_MS) {
    return false;
  }
  return runtimeProcessAlive(pid, record);
}

function processCmdline(pid) {
  if (process.platform !== "linux" || !fileExists("/proc")) {
    return "";
  }
  try {
    return fs
      .readFileSync(path.join("/proc", String(pid), "cmdline"))
      .toString("utf8")
      .replace(/\0/g, " ")
      .trim();
  } catch {
    return "";
  }
}

function runtimeKindForRecord(record, filePath) {
  const text = [
    record.runtime_name,
    record.adapter_path,
    record.runtime_path,
    record.store_root,
    filePath
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (text.includes("claude")) {
    return "claude";
  }
  if (text.includes("codex")) {
    return "codex";
  }
  return "";
}

function detectProcessCounts() {
  const counts = { codex: 0, claude: 0, runtime: 0 };
  for (const cmdline of readProcessCmdlines()) {
    const text = cmdline.toLowerCase();
    if (!text) {
      continue;
    }
    if (isCodexProcess(text)) {
      counts.codex += 1;
    }
    if (isClaudeProcess(text)) {
      counts.claude += 1;
    }
    if (isCaushellRuntimeProcess(text)) {
      counts.runtime += 1;
    }
  }
  return counts;
}

function readProcessCmdlines() {
  if (process.platform !== "linux" || !fileExists("/proc")) {
    return [];
  }

  const result = [];
  let entries = [];
  try {
    entries = fs.readdirSync("/proc", { withFileTypes: true });
  } catch {
    return result;
  }

  for (const entry of entries) {
    if (!entry.isDirectory() || !/^\d+$/.test(entry.name)) {
      continue;
    }
    try {
      const raw = fs.readFileSync(path.join("/proc", entry.name, "cmdline"));
      const text = raw.toString("utf8").replace(/\0/g, " ").trim();
      if (text) {
        result.push(text);
      }
    } catch {
      // Process exited or is unreadable; ignore it.
    }
  }

  return result;
}

function isCodexProcess(text) {
  return (
    /\bcodex\b/.test(text) &&
    !text.includes("caushell-codex") &&
    !text.includes("caushell-adapter-codex")
  );
}

function isClaudeProcess(text) {
  return (
    (/\bclaude\b/.test(text) || text.includes("claude-code")) &&
    !text.includes("caushell-claude") &&
    !text.includes("caushell-adapter-claude")
  );
}

function isCaushellRuntimeProcess(text) {
  return (
    text.includes("caushell") ||
    text.includes("caushell-adapter-") ||
    text.includes("caushell-codex-hook") ||
    text.includes("caushell-claude-hook")
  );
}

function workspaceRootsMatch(left, right) {
  if (!left || !right) {
    return false;
  }
  return pathEquals(left, right);
}

function workspaceMatchesCurrent(workspaceRoot, currentWorkspaceRoot) {
  if (!workspaceRoot) {
    return false;
  }
  const roots = workspaceRoots();
  if (roots.length > 0) {
    return roots.some((root) => pathEquals(root, workspaceRoot));
  }
  return pathEquals(workspaceRoot, currentWorkspaceRoot);
}

function sessionIdentityLabel(session) {
  return truncateText(session.displayTitle || session.session_id || "unknown-session", 72);
}

function runtimeMixLabel(sessions) {
  const counts = new Map();
  for (const session of sessions || []) {
    const runtimeKind = session.runtimeKind || runtimeKindForSession(session.runtime_name, session.storeKind);
    const key = runtimeKind || "unknown";
    if (!counts.has(key)) {
      counts.set(key, {
        runtimeKind: key,
        label: runtimeGroupLabel(key, session.runtimeLabel),
        count: 0
      });
    }
    counts.get(key).count += 1;
  }

  const showCounts = (sessions || []).length > 1;
  return [...counts.values()]
    .sort((left, right) => {
      const orderDiff = runtimeGroupOrder(left.runtimeKind) - runtimeGroupOrder(right.runtimeKind);
      if (orderDiff !== 0) {
        return orderDiff;
      }
      return left.label.localeCompare(right.label);
    })
    .map((entry) => (showCounts ? `${entry.label} ${entry.count}` : entry.label))
    .join(" · ");
}

function decisionShortLabel(decision) {
  if (decision === "allow") {
    return "ALLOW";
  }
  if (decision === "need_approval") {
    return "NEED";
  }
  if (decision === "deny") {
    return "DENY";
  }
  return "UNKNOWN";
}

function iconForSession(decision) {
  if (decision === "deny") {
    return "error";
  }
  if (decision === "need_approval") {
    return "warning";
  }
  return "terminal";
}

function iconForRuntimeKind(kind) {
  if (kind === "codex") {
    return "hubot";
  }
  if (kind === "claude") {
    return "sparkle";
  }
  if (kind === "runtime") {
    return "circle-filled";
  }
  return "terminal";
}

function formatDateTime(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return String(value || "");
  }
}

async function openSessionTimeline(context, client, item) {
  const session = item && item.session ? item.session : item;
  if (!session || !session.session_id || !session.storeRoot) {
    vscode.window.showWarningMessage("No Caushell session selected.");
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    "caushellSessionTimeline",
    sessionPanelLabel(session),
    vscode.ViewColumn.One,
    {
      enableScripts: true,
      retainContextWhenHidden: true
    }
  );

  panel.webview.html = loadingHtml(panel.webview, "Loading Caushell session detail...");

  try {
    panel.webview.onDidReceiveMessage(async (message) => {
      if (!message || typeof message !== "object") {
        return;
      }

      try {
        if (message.type === "loadDetail") {
          const detail = await loadSessionCheckDetail(client, session, message.sequenceNo);
          await panel.webview.postMessage({
            type: "detailLoaded",
            detail
          });
          return;
        }

        if (message.type === "loadMoreTimeline") {
          const overview = await loadSessionOverviewPage(client, session, {
            beforeSequence: message.beforeSequence,
            afterSequence: message.afterSequence,
            order: "desc"
          });
          await panel.webview.postMessage({
            type: "timelinePageLoaded",
            overview
          });
        }
      } catch (error) {
        await panel.webview.postMessage({
          type: "queryError",
          operation: message.type,
          sequenceNo: message.sequenceNo || null,
          message: error.message || String(error)
        });
      }
    });

    const overview = await loadSessionOverviewPage(client, session, {
      order: "desc"
    });
    panel.webview.html = timelineHtml(panel.webview, {
      session,
      overview,
      storeLabel: session.storeLabel
    });
  } catch (error) {
    panel.webview.html = errorHtml(panel.webview, error);
  }
}

async function loadSessionOverviewPage(client, session, options = {}) {
  const payload = {
    query: "session_overview",
    session_id: session.session_id,
    limit: DEFAULT_OVERVIEW_LIMIT,
    order: options.order || "desc"
  };

  if (options.beforeSequence != null) {
    payload.before_sequence = options.beforeSequence;
  }

  if (options.afterSequence != null) {
    payload.after_sequence = options.afterSequence;
  }

  return client.queryStore(session.storeRoot, payload);
}

async function loadSessionCheckDetail(client, session, sequenceNo) {
  return client.queryStore(session.storeRoot, {
    query: "session_check_detail",
    session_id: session.session_id,
    sequence_no: sequenceNo
  });
}

async function configureStoreRoot() {
  const current = vscode.workspace.getConfiguration("caushell").get("storeRoot", "");
  const value = await vscode.window.showInputBox({
    title: "Caushell Store Root",
    prompt: "Optional override for a single Caushell store root",
    value: current
  });

  if (value === undefined) {
    return;
  }

  await vscode.workspace
    .getConfiguration("caushell")
    .update("storeRoot", value, vscode.ConfigurationTarget.Workspace);
}

async function openConfig(client) {
  try {
    const configPath = await client.configPath();
    if (!fs.existsSync(configPath)) {
      try {
        await client.initializeConfig();
      } catch (error) {
        if (!fs.existsSync(configPath)) {
          throw error;
        }
      }
    }
    const document = await vscode.workspace.openTextDocument(vscode.Uri.file(configPath));
    await vscode.window.showTextDocument(document);
  } catch (error) {
    vscode.window.showErrorMessage(`Caushell config: ${error.message || error}`);
  }
}

async function setFailureAction(client) {
  const selected = await vscode.window.showQuickPick(
    [
      {
        label: "Allow",
        description: "Do not interrupt the agent when Caushell cannot produce a decision.",
        value: "allow"
      },
      {
        label: "Need approval",
        description: "Ask in Claude Code; defer to Codex host behavior.",
        value: "need_approval"
      },
      {
        label: "Deny",
        description: "Block when Caushell cannot produce a decision.",
        value: "deny"
      }
    ],
    {
      title: "Caushell Failure Action",
      placeHolder: "Choose how Agent hooks behave when analysis is unavailable"
    }
  );
  if (!selected) {
    return;
  }

  try {
    await client.setFailureAction(selected.value);
    vscode.window.showInformationMessage(
      `Caushell failure action set to ${selected.value}.`
    );
  } catch (error) {
    vscode.window.showErrorMessage(`Caushell config: ${error.message || error}`);
  }
}

function runQueryProcess(cliPath, storeRoot, payload) {
  return new Promise((resolve, reject) => {
    const child = cp.spawn(cliPath, ["query-stdio", "--store", storeRoot], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
    let settled = false;

    const stdout = [];
    const stderr = [];

    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", (error) => {
      if (settled) {
        return;
      }
      settled = true;
      if (error && error.code === "ENOENT") {
        reject(
          new Error(
            `caushell not found at ${cliPath}; set caushell.cliPath explicitly or install caushell on PATH`
          )
        );
        return;
      }
      reject(error);
    });
    child.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      const stderrText = Buffer.concat(stderr).toString("utf8").trim();
      const stdoutText = Buffer.concat(stdout).toString("utf8").trim();

      if (code !== 0) {
        reject(new Error(stderrText || `caushell exited with code ${code}`));
        return;
      }

      const lines = stdoutText.split(/\r?\n/).filter(Boolean);
      if (lines.length === 0) {
        reject(new Error("caushell returned no query response"));
        return;
      }

      try {
        resolve(JSON.parse(lines[lines.length - 1]));
      } catch (error) {
        reject(new Error(`invalid caushell JSON response: ${error.message}`));
      }
    });

    child.stdin.end(`${JSON.stringify(payload)}\n`);
  });
}

function runCliProcess(cliPath, args) {
  return new Promise((resolve, reject) => {
    const child = cp.spawn(cliPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    let settled = false;

    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      const stdoutText = Buffer.concat(stdout).toString("utf8").trim();
      const stderrText = Buffer.concat(stderr).toString("utf8").trim();
      if (code !== 0) {
        reject(new Error(stderrText || `caushell exited with code ${code}`));
        return;
      }
      resolve(stdoutText);
    });
  });
}

function timelineHtml(webview, model) {
  const nonce = nonceValue();
  const dataJson = JSON.stringify(model).replace(/</g, "\\u003c");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Caushell Session</title>
  <style>
    :root {
      --surface: #10161d;
      --surface-lowest: #0c1117;
      --surface-low: #141b24;
      --surface-container: #17212b;
      --surface-high: #1d2733;
      --surface-bright: #202b38;
      --surface-active: #17283e;
      --line: #26323f;
      --line-strong: #344555;
      --text: #e8edf4;
      --muted: #8d98a6;
      --variant: #c5cfdd;
      --primary: #6aa8ff;
      --primary-strong: #2f80ed;
      --green: #37d778;
      --red: #ffb4ab;
      --red-border: #7f1d1d;
      --gold: #facc15;
      --gold-border: #854d0e;
      --shadow: 0 18px 44px rgba(0, 0, 0, 0.24);
      --font-ui: Inter, var(--vscode-font-family), system-ui, sans-serif;
      --font-mono: "JetBrains Mono", "Cascadia Code", "SFMono-Regular", monospace;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      height: 100vh;
      color: var(--text);
      font-family: var(--font-ui);
      font-size: 13px;
      line-height: 18px;
      background: var(--surface);
      overflow: hidden;
      -webkit-font-smoothing: antialiased;
    }

    button,
    input {
      font: inherit;
    }

    button {
      color: inherit;
    }

    .shell {
      height: 100vh;
      display: flex;
      flex-direction: column;
      min-height: 0;
      background: var(--surface-lowest);
    }

    .top-anchor {
      height: 35px;
      flex: 0 0 35px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 16px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-low);
      box-shadow: inset 0 -1px 0 rgba(255, 255, 255, 0.02);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 4px;
      min-width: 0;
    }

    .terminal-mark {
      width: 16px;
      height: 14px;
      border: 1px solid var(--primary);
      color: var(--primary);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
      font-size: 10px;
      line-height: 1;
    }

    .brand-label {
      color: var(--primary);
      font-size: 11px;
      line-height: 16px;
      font-weight: 700;
      letter-spacing: 0.05em;
    }

    .settings-mark {
      position: relative;
      display: inline-flex;
      width: 16px;
      height: 16px;
      align-items: center;
      justify-content: center;
      color: var(--muted);
    }

    .settings-mark::before {
      content: "";
      width: 12px;
      height: 12px;
      border: 2px solid currentColor;
      border-radius: 999px;
      opacity: 0.9;
    }

    .settings-mark::after {
      content: "";
      position: absolute;
      width: 4px;
      height: 4px;
      border-radius: 999px;
      background: currentColor;
    }

    .detail-layout {
      flex: 1;
      min-height: 0;
      display: flex;
      overflow: hidden;
      background: var(--surface-lowest);
    }

    .panel {
      min-height: 0;
      overflow: hidden;
    }

    .stream-panel {
      flex: 1 1 0;
      min-width: 300px;
      display: flex;
      flex-direction: column;
      border-right: 1px solid var(--line);
      background: var(--surface);
    }

    .inspection-panel {
      flex: 2 1 0;
      display: flex;
      flex-direction: column;
      min-width: 0;
      background: var(--surface-lowest);
    }

    .pane-header {
      flex: 0 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 36px;
      padding: 0 12px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-bright);
      box-shadow: inset 0 -1px 0 rgba(255, 255, 255, 0.02);
    }

    .pane-title {
      color: var(--muted);
      text-transform: uppercase;
      font-size: 11px;
      line-height: 16px;
      font-weight: 700;
      letter-spacing: 0.06em;
    }

    .pane-meta {
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: 11px;
      line-height: 14px;
      text-transform: uppercase;
      white-space: nowrap;
    }

    .timeline {
      flex: 1;
      min-height: 0;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
    }

    .timeline-item {
      position: relative;
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 2px;
      padding: 9px 12px;
      margin: 0;
      color: var(--text);
      border: 0;
      border-bottom: 1px solid var(--line);
      background: transparent;
      cursor: pointer;
      text-align: left;
      transition: background 120ms ease;
    }

    .timeline-item:hover {
      background: rgba(29, 39, 51, 0.72);
    }

    .timeline-item.active {
      background: var(--surface-active);
    }

    .timeline-item.active::before {
      content: "";
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 3px;
      background: var(--primary);
    }

    .timeline-meta {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding-left: 4px;
      min-width: 0;
    }

    .timeline-meta-left {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }

    .seq,
    .time {
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: 11px;
      line-height: 14px;
      white-space: nowrap;
    }

    .cmd {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      padding-left: 4px;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 18px;
      font-weight: 600;
    }

    .timeline-item.active .cmd {
      color: var(--primary);
    }

    .timeline-item.decision-deny:not(.active) .cmd {
      color: var(--red);
    }

    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 0;
      padding: 1px 6px;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 10px;
      font-weight: 600;
      line-height: 14px;
      text-transform: uppercase;
      border: 1px solid currentColor;
      white-space: nowrap;
      background: transparent;
    }

    .allow { color: var(--green); }
    .need_approval { color: var(--gold); background: rgba(113, 63, 18, 0.2); border-color: rgba(133, 77, 14, 0.55); }
    .deny { color: var(--red); background: rgba(127, 29, 29, 0.2); border-color: rgba(127, 29, 29, 0.55); }
    .unknown { color: var(--muted); }

    .timeline-footer {
      flex: 0 0 auto;
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 4px;
      border-top: 1px solid var(--line);
      background: var(--surface-lowest);
    }

    .filter-chevron {
      color: var(--primary);
      font-family: var(--font-mono);
      font-size: 14px;
      line-height: 1;
      padding: 0 2px;
    }

    .timeline-filter {
      min-width: 0;
      flex: 1;
      height: 24px;
      padding: 0 2px;
      border: 0;
      outline: 0;
      background: transparent;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 11px;
      line-height: 14px;
    }

    .timeline-filter::placeholder {
      color: var(--muted);
    }

    .status-note {
      max-width: 28%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--muted);
      font-size: 11px;
      line-height: 14px;
    }

    .inspection-content {
      flex: 1;
      min-height: 0;
      overflow-y: auto;
      padding: 18px;
    }

    .detail-stack {
      display: flex;
      flex-direction: column;
      gap: 16px;
      width: 100%;
      min-height: 100%;
    }

    .detail-tabs {
      display: flex;
      align-items: center;
      gap: 0;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--surface-lowest);
      overflow: hidden;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02);
    }

    .detail-tab {
      flex: 1;
      min-width: 0;
      height: 42px;
      border: 0;
      border-right: 1px solid var(--line);
      background: transparent;
      color: var(--muted);
      cursor: pointer;
      font-size: 13px;
      line-height: 18px;
      font-weight: 600;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .detail-tab:last-child {
      border-right: 0;
    }

    .detail-tab:hover {
      background: var(--surface-container);
      color: var(--text);
    }

    .detail-tab.active {
      background: rgba(47, 128, 237, 0.22);
      color: var(--primary);
    }

    .inspection-hero {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .inspection-heading-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-width: 0;
    }

    .inspection-title {
      margin: 0;
      color: var(--text);
      font-size: 18px;
      line-height: 24px;
      font-weight: 700;
      letter-spacing: 0;
    }

    .inspection-nav {
      display: flex;
      align-items: center;
      gap: 8px;
      flex: 0 0 auto;
    }

    .seq-pill,
    .nav-button {
      height: 34px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgba(23, 33, 43, 0.78);
      color: var(--primary);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 18px;
      font-weight: 700;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.025);
    }

    .seq-pill {
      padding: 0 12px;
      text-transform: uppercase;
    }

    .nav-button {
      width: 34px;
      color: var(--muted);
      cursor: pointer;
    }

    .nav-button:hover:not(:disabled) {
      color: var(--text);
      background: var(--surface-high);
    }

    .nav-button:disabled {
      opacity: 0.45;
      cursor: default;
    }

    .command-line-row {
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 12px;
      align-items: stretch;
      min-width: 0;
    }

    .hero-decision {
      min-width: 90px;
      padding: 0 12px;
      border-radius: 7px;
      font-size: 16px;
      line-height: 20px;
      font-weight: 700;
    }

    .hero-command {
      min-width: 0;
      min-height: 48px;
      display: flex;
      align-items: center;
      padding: 12px 16px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: rgba(29, 39, 51, 0.74);
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 16px;
      line-height: 22px;
      font-weight: 700;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.025);
    }

    .hero-meta {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px 30px;
      padding: 0 8px;
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 18px;
    }

    .meta-key {
      color: var(--muted);
    }

    .meta-value {
      color: var(--variant);
      margin-left: 4px;
    }

    .inspection-tab-panel {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .signal-item {
      border: 1px solid var(--line);
      border-radius: 7px;
      background: rgba(18, 25, 33, 0.92);
      padding: 12px;
      min-width: 0;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02);
    }

    .signal-kind {
      color: var(--muted);
      text-transform: uppercase;
      font-size: 11px;
      line-height: 14px;
      letter-spacing: 0.05em;
    }

    .decision-overview {
      border-color: var(--line-strong);
    }

    .decision-metrics {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .decision-metric {
      min-width: 0;
      padding: 14px 26px;
      border-right: 1px solid var(--line);
    }

    .decision-metric:last-child {
      border-right: 0;
    }

    .decision-label,
    .kv-key {
      color: var(--muted);
      font-size: 13px;
      line-height: 18px;
      font-weight: 600;
    }

    .decision-value {
      margin-top: 6px;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 16px;
      line-height: 20px;
      font-weight: 700;
    }

    .decision-reason {
      border-top: 1px solid var(--line);
      padding: 12px 28px;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }

    .state-card {
      min-height: 150px;
    }

    .state-card .detail-card-body {
      gap: 10px;
    }

    .context-detail-card .detail-card-body {
      gap: 14px;
    }

    .state-card-title {
      color: var(--variant);
      font-size: 15px;
      line-height: 20px;
      font-weight: 700;
    }

    .kv-grid {
      display: grid;
      gap: 6px;
    }

    .kv-row {
      display: grid;
      grid-template-columns: minmax(105px, 0.72fr) minmax(0, 1fr);
      gap: 12px;
      min-width: 0;
      color: var(--variant);
    }

    .kv-value {
      min-width: 0;
      color: var(--text);
      font-family: var(--font-mono);
      overflow-wrap: anywhere;
    }

    .inline-link {
      width: fit-content;
      border: 0;
      padding: 0;
      background: transparent;
      color: var(--primary);
      cursor: pointer;
      font-size: 13px;
      line-height: 18px;
      font-weight: 600;
    }

    .inline-link:hover {
      color: var(--text);
    }

    .binding-groups {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .binding-card {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: rgba(23, 33, 43, 0.72);
      overflow: hidden;
    }

    .binding-header {
      min-height: 42px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
    }

    .binding-title {
      color: var(--variant);
      font-size: 14px;
      line-height: 18px;
      font-weight: 700;
    }

    .binding-card pre {
      max-height: 180px;
      border: 0;
      border-radius: 0;
      background: transparent;
    }

    .execution-hero-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr);
      gap: 14px;
    }

    .execution-inventory-card {
      border-color: var(--line-strong);
    }

    .execution-primary-block {
      min-width: 0;
      padding: 11px 12px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: rgba(12, 17, 23, 0.52);
    }

    .execution-primary-command {
      display: block;
      margin-top: 6px;
      padding: 0;
      border: 0;
      background: transparent;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 18px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }

    .execution-metrics {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      border-top: 1px solid var(--line);
    }

    .execution-metric {
      min-width: 0;
      padding: 12px 16px;
      border-right: 1px solid var(--line);
    }

    .execution-metric:last-child {
      border-right: 0;
    }

    .execution-signal-list {
      display: grid;
      gap: 8px;
    }

    .execution-signal {
      min-width: 0;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: rgba(23, 33, 43, 0.72);
    }

    .execution-signal.is-warning {
      border-color: rgba(133, 77, 14, 0.62);
      background: rgba(113, 63, 18, 0.18);
    }

    .execution-signal.is-info {
      border-color: rgba(106, 168, 255, 0.38);
      background: rgba(23, 40, 62, 0.5);
    }

    .execution-signal-name {
      color: var(--variant);
      font-size: 13px;
      line-height: 18px;
      font-weight: 700;
    }

    .execution-signal-value {
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 18px;
      font-weight: 700;
    }

    .execution-signal.is-warning .execution-signal-value {
      color: var(--gold);
    }

    .execution-signal.is-info .execution-signal-value {
      color: var(--primary);
    }

    .execution-detail-card .detail-card-body {
      gap: 14px;
    }

    .execution-detail-groups {
      display: grid;
      gap: 14px;
    }

    .execution-detail-group {
      display: grid;
      gap: 8px;
      min-width: 0;
    }

    .execution-group-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-width: 0;
      padding: 0 2px;
    }

    .execution-group-title {
      min-width: 0;
      color: var(--variant);
      font-size: 14px;
      line-height: 18px;
      font-weight: 700;
    }

    .execution-record-list {
      display: grid;
      gap: 8px;
    }

    .execution-record-list .record {
      background: rgba(23, 33, 43, 0.64);
    }

    .execution-record-list .record-title > span:first-child {
      min-width: 0;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 18px;
      overflow-wrap: anywhere;
    }

    .execution-preview-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }

    .preview-card .detail-card-body {
      gap: 12px;
    }

    .preview-title {
      color: var(--variant);
      font-size: 16px;
      line-height: 22px;
      font-weight: 700;
    }

    .preview-list {
      display: grid;
      gap: 0;
    }

    .preview-row {
      display: grid;
      grid-template-columns: 30px minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      min-width: 0;
      padding: 10px 0;
      border-bottom: 1px solid rgba(38, 50, 63, 0.72);
    }

    .preview-row:last-child {
      border-bottom: 0;
    }

    .row-index {
      width: 24px;
      height: 24px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line-strong);
      border-radius: 5px;
      color: var(--variant);
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 16px;
      background: rgba(23, 33, 43, 0.88);
    }

    .preview-command {
      min-width: 0;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 18px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }

    .preview-meta {
      margin-top: 3px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      color: var(--muted);
      font-size: 11px;
      line-height: 14px;
    }

    .preview-badge {
      padding: 2px 7px;
      border: 1px solid var(--line-strong);
      border-radius: 5px;
      color: var(--green);
      font-family: var(--font-mono);
      font-size: 10px;
      line-height: 14px;
      font-weight: 700;
      text-transform: uppercase;
      white-space: nowrap;
      background: rgba(10, 42, 25, 0.22);
    }

    .collapsed-row summary {
      display: flex;
      align-items: center;
      gap: 12px;
      color: var(--variant);
      font-size: 15px;
      line-height: 20px;
      font-weight: 700;
    }

    .count-pill {
      min-width: 26px;
      height: 22px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0 8px;
      border-radius: 999px;
      color: var(--muted);
      background: var(--surface-high);
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 16px;
    }

    .reason-list,
    .signal-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .reason-item {
      display: flex;
      gap: 8px;
      align-items: flex-start;
      color: var(--text);
      font-size: 13px;
      line-height: 18px;
    }

    .reason-index {
      flex: 0 0 auto;
      color: var(--primary);
      font-family: var(--font-mono);
      font-size: 11px;
      line-height: 18px;
    }

    .signal-title {
      margin-top: 4px;
      color: var(--text);
      font-size: 13px;
      line-height: 18px;
      overflow-wrap: anywhere;
    }

    .signal-meta {
      margin-top: 6px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px 10px;
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: 11px;
      line-height: 14px;
    }

    .detail-section {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .section-label,
    .detail-card-title,
    .subsection-title {
      color: var(--muted);
      text-transform: uppercase;
      font-size: 11px;
      line-height: 14px;
      font-weight: 400;
      letter-spacing: 0.05em;
    }

    .detail-card {
      border: 1px solid var(--line);
      border-radius: 7px;
      background: rgba(18, 25, 33, 0.94);
      overflow: hidden;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.025);
    }

    .detail-card-body {
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .mono,
    code,
    pre {
      font-family: var(--font-mono);
    }

    details.detail-card summary::-webkit-details-marker {
      display: none;
    }

    details.detail-card summary {
      cursor: pointer;
      list-style: none;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-high);
    }

    pre {
      margin: 0;
      padding: 12px;
      border-radius: 6px;
      background: var(--surface-container);
      border: 1px solid var(--line);
      overflow: auto;
      color: var(--text);
      font-size: 12px;
      line-height: 16px;
    }

    code {
      border-radius: 4px;
      padding: 1px 4px;
      overflow-wrap: anywhere;
    }

    .stack {
      display: grid;
      gap: 8px;
    }

    .record {
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 10px 12px;
      background: rgba(23, 33, 43, 0.72);
    }

    .record-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 6px;
      font-weight: 600;
    }

    .record-meta {
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      margin-top: 6px;
      font-size: 11px;
      line-height: 14px;
    }

    .flow {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
      gap: 8px;
      align-items: center;
    }

    .flow-arrow {
      color: var(--primary);
      font-weight: 700;
    }

    .empty {
      color: var(--muted);
      padding: 16px;
      font-size: 13px;
      line-height: 18px;
    }

    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }

    ::-webkit-scrollbar-track {
      background: transparent;
    }

    ::-webkit-scrollbar-thumb {
      background: #4b4b51;
      border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
      background: #777677;
    }

    @media (max-width: 860px) {
      body { overflow: auto; }
      .shell { height: auto; min-height: 100vh; }
      .detail-layout { flex-direction: column; }
      .stream-panel { flex: none; min-width: 0; min-height: 320px; border-right: 0; border-bottom: 1px solid var(--line); }
      .inspection-panel { min-width: 0; border-left: 0; }
      .pane-header { min-height: 34px; }
      .section-label,
      .detail-card-title,
      .subsection-title { font-size: 11px; line-height: 14px; }
      .summary-grid,
      .binding-groups,
      .execution-hero-grid,
      .execution-preview-grid,
      .decision-metrics,
      .execution-metrics { grid-template-columns: 1fr; }
      .decision-metric { border-right: 0; border-bottom: 1px solid var(--line); }
      .decision-metric:last-child { border-bottom: 0; }
      .execution-metric { border-right: 0; border-bottom: 1px solid var(--line); }
      .execution-metric:last-child { border-bottom: 0; }
      .command-line-row { grid-template-columns: 1fr; }
      .hero-decision { min-height: 42px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="top-anchor">
      <div class="brand">
        <span class="terminal-mark">&gt;_</span>
        <span class="brand-label">CAUSHELL</span>
      </div>
      <span class="settings-mark" aria-hidden="true"></span>
    </header>

    <main class="detail-layout">
      <section class="panel stream-panel">
        <div class="pane-header">
          <span class="pane-title">Terminal Feed</span>
          <span class="pane-meta" id="timeline-count"></span>
        </div>
        <div class="timeline" id="timeline"></div>
        <div class="timeline-footer">
          <span class="filter-chevron">&gt;</span>
          <input class="timeline-filter" id="timeline-filter" placeholder="Filter commands..." type="text" />
          <span class="status-note" id="timeline-status"></span>
        </div>
      </section>

      <section class="panel inspection-panel">
        <div class="inspection-content" id="inspection-content"></div>
      </section>
    </main>
  </div>

  <script nonce="${nonce}">
    const model = ${dataJson};
    const vscodeApi = acquireVsCodeApi();
    let activeItem = (model.overview.items || [])[0] || null;
    const detailCache = {};
    let loadingMore = false;
    let timelineError = null;
    let filterText = "";
    let activeInspectionTab = "analysis";
    const autoLoadThresholdPx = 180;

    function renderTimeline() {
      const container = document.getElementById("timeline");
      const previousScrollTop = container.scrollTop;
      const allItems = model.overview.items || [];
      const items = filteredTimelineItems(allItems);
      document.getElementById("timeline-count").textContent = \`\${items.length} SHOWN\`;
      const statusNode = document.getElementById("timeline-status");
      if (items.length === 0) {
        container.innerHTML = filterText
          ? '<div class="empty">No commands match this filter.</div>'
          : '<div class="empty">No check events found for this session.</div>';
        statusNode.textContent = timelineStatusText();
        return;
      }

      container.innerHTML = "";
      for (const item of items) {
        const button = document.createElement("button");
        const itemDecisionClass = decisionClass(item.decision);
        button.className = \`timeline-item decision-\${itemDecisionClass} \${activeItem && activeItem.sequence_no === item.sequence_no ? "active" : ""}\`;
        button.innerHTML = \`
          <div class="timeline-meta">
            <div class="timeline-meta-left">
              <span class="seq">\${padSequence(item.sequence_no)}</span>
              <span class="badge"></span>
            </div>
            <span class="time">\${escapeHtml(formatTime(item.observed_at_ms))}</span>
          </div>
          <div class="cmd"></div>
        \`;
        button.querySelector(".cmd").textContent = item.raw_text;
        const badge = button.querySelector(".badge");
        badge.textContent = decisionLabel(item.decision);
        badge.classList.add(decisionClass(item.decision));
        button.addEventListener("click", () => {
          activeItem = item;
          ensureDetailLoaded(item.sequence_no);
          renderTimeline();
          renderDetails();
        });
        container.appendChild(button);
      }

      container.scrollTop = previousScrollTop;
      statusNode.textContent = timelineStatusText();
      window.requestAnimationFrame(maybeRequestMoreTimeline);
    }

    function renderDetails() {
      setText("active-seq", activeItem ? \`SEQ \${padSequence(activeItem.sequence_no)}\` : "");
      const container = document.getElementById("inspection-content");
      if (!activeItem) {
        container.innerHTML = '<div class="empty">No command checks were recorded for this session.</div>';
        return;
      }

      container.innerHTML = commandDetailHtml(activeItem, detailStateFor(activeItem.sequence_no));
      bindDetailTabs();
    }

    function commandDetailHtml(item, detailState) {
      if (detailState && detailState.status === "error") {
        return \`
          <div class="detail-stack">
            \${commandInspectionHero(item, detailState)}
            <div class="empty">\${escapeHtml(detailState.message)}</div>
          </div>
        \`;
      }

      if (!detailState || detailState.status === "loading") {
        return \`
          <div class="detail-stack">
            \${commandInspectionHero(item, detailState)}
            <div class="empty">Loading command detail...</div>
          </div>
        \`;
      }

      const detail = detailState.detail;
      return \`
        <div class="detail-stack">
          \${commandInspectionHero(item, detailState)}
          \${detailTabsHtml()}
          \${inspectionTabContent(item, detailState)}
        </div>
      \`;
    }

    function commandInspectionHero(item, detailState) {
      const detail = detailState && detailState.status === "loaded" ? detailState.detail : null;
      const request = detail ? detail.request || {} : {};
      const command = request.command || item.raw_text || "";
      const decision = detail && detail.response ? detail.response.decision : item.decision;
      const previous = adjacentTimelineItem(item, 1);
      const next = adjacentTimelineItem(item, -1);

      return \`
        <section class="inspection-hero">
          <div class="inspection-heading-row">
            <h1 class="inspection-title">Command Inspection</h1>
            <div class="inspection-nav">
              <span class="seq-pill">SEQ \${escapeHtml(padSequence(item.sequence_no))}</span>
              <button class="nav-button" data-sequence="\${previous ? previous.sequence_no : ""}" type="button" \${previous ? "" : "disabled"} aria-label="Previous command">&lt;</button>
              <button class="nav-button" data-sequence="\${next ? next.sequence_no : ""}" type="button" \${next ? "" : "disabled"} aria-label="Next command">&gt;</button>
            </div>
          </div>
          <div class="command-line-row">
            <span class="badge hero-decision \${decisionClass(decision)}">\${escapeHtml(decisionLabel(decision))}</span>
            <code class="hero-command">\${escapeHtml(command)}</code>
          </div>
          <div class="hero-meta">\${heroMetaHtml(item, detail)}</div>
        </section>
      \`;
    }

    function detailTabsHtml() {
      const tabs = [
        ["analysis", "ANALYSIS"],
        ["context", "CONTEXT"],
        ["execution", "EXECUTION"],
        ["raw", "RAW"]
      ];
      return \`
        <nav class="detail-tabs" aria-label="Inspection detail sections">
          \${tabs.map(([id, label]) => \`
            <button class="detail-tab \${activeInspectionTab === id ? "active" : ""}" data-tab="\${id}" type="button">\${label}</button>
          \`).join("")}
        </nav>
      \`;
    }

    function inspectionTabContent(item, detailState) {
      const detail = detailState.detail;
      if (activeInspectionTab === "context") {
        return contextTabHtml(item, detail);
      }
      if (activeInspectionTab === "execution") {
        return executionTabHtml(item, detailState);
      }
      if (activeInspectionTab === "raw") {
        return rawInspectionCard(item, detailState);
      }
      return analysisTabHtml(item, detail);
    }

    function bindDetailTabs() {
      document.querySelectorAll(".detail-tab").forEach((button) => {
        button.addEventListener("click", () => {
          activeInspectionTab = button.getAttribute("data-tab") || "analysis";
          renderDetails();
        });
      });
      document.querySelectorAll("[data-tab-target]").forEach((button) => {
        button.addEventListener("click", () => {
          activeInspectionTab = button.getAttribute("data-tab-target") || "analysis";
          renderDetails();
        });
      });
      document.querySelectorAll(".nav-button[data-sequence]:not(:disabled)").forEach((button) => {
        button.addEventListener("click", () => {
          const sequenceNo = Number(button.getAttribute("data-sequence"));
          const target = (model.overview.items || []).find((candidate) => candidate.sequence_no === sequenceNo);
          if (!target) {
            return;
          }
          activeItem = target;
          ensureDetailLoaded(target.sequence_no);
          renderTimeline();
          renderDetails();
        });
      });
    }

    function heroMetaHtml(item, detail) {
      const eventIndex = detail && detail.event_index != null ? detail.event_index : item.event_index;
      const observedAtMs = detail && detail.observed_at_ms != null ? detail.observed_at_ms : item.observed_at_ms;
      const fields = [
        ["event_index", eventIndex],
        ["observed_at_ms", observedAtMs]
      ].filter(([, value]) => value != null && value !== "");

      if (fields.length === 0) {
        return '<span class="meta-key">No timing metadata recorded.</span>';
      }

      return fields.map(([label, value]) => \`
        <span><span class="meta-key">\${escapeHtml(label)}:</span><span class="meta-value">\${escapeHtml(formatMetaValue(value))}</span></span>
      \`).join("");
    }

    function adjacentTimelineItem(item, offset) {
      const items = model.overview.items || [];
      const index = items.findIndex((candidate) => candidate.sequence_no === item.sequence_no);
      if (index < 0) {
        return null;
      }
      return items[index + offset] || null;
    }

    function analysisTabHtml(item, detail) {
      const trace = decisionTrace(detail);
      const findings = trace.findings || [];
      const evidence = trace.evidence || [];
      const proposals = trace.decision_proposals || [];
      const reasons = responseReasons(detail);
      const findingCount = item.finding_count || findings.length || 0;
      const evidenceCount = evidence.length;
      const proposalCount = proposals.length;

      return \`
        <div class="inspection-tab-panel">
          \${decisionOverviewCard(item, detail, reasons, findingCount, evidenceCount + proposalCount)}
          \${signalSection(findings, evidence, proposals)}
          <div class="summary-grid">
            \${executionContextSummaryCard(item, detail)}
            \${ruleEnforcementSummaryCard(item, detail, findings, proposals)}
            \${shellStateSummaryCard(detail)}
          </div>
          \${executionPreviewGrid(detail)}
          \${decisionProposalsSection(proposals)}
        </div>
      \`;
    }

    function decisionOverviewCard(item, detail, reasons, findingCount, evidenceCount) {
      const decision = ((detail || {}).response || {}).decision || item.decision;
      const rows = reasons.length ? reasons : ["No decision reason recorded."];
      return \`
        <section class="detail-card decision-overview">
          <div class="decision-metrics">
            \${decisionMetric("Decision", decisionLabel(decision), decisionClass(decision))}
            \${decisionMetric("Findings", formatCount(findingCount), "")}
            \${decisionMetric("Evidence", formatCount(evidenceCount), "")}
          </div>
          <div class="decision-reason">
            <div class="detail-card-title">Reason</div>
            <div class="reason-list">
              \${rows.map((reason, index) => \`
                <div class="reason-item">
                  <span class="reason-index">\${String(index + 1).padStart(2, "0")}</span>
                  <span>\${escapeHtml(reason)}</span>
                </div>
              \`).join("")}
            </div>
          </div>
        </section>
      \`;
    }

    function decisionMetric(label, value, valueClass) {
      return \`
        <div class="decision-metric">
          <div class="decision-label">\${escapeHtml(label)}</div>
          <div class="decision-value \${valueClass || ""}">\${escapeHtml(value)}</div>
        </div>
      \`;
    }

    function executionContextSummaryCard(item, detail) {
      const request = detail ? detail.request || {} : {};
      const runtime = request.runtime || {};
      const shellState = request.shell_state_before || {};
      return stateCardHtml("Execution Context", [
        ["runtime_name", runtime.runtime_name || model.session.runtime_name || "unknown"],
        ["tool", runtime.tool_name || "unknown"],
        ["shell_kind", request.shell_kind || "unknown"],
        ["workspace_root", request.workspace_root || model.session.workspace_root || "unknown"],
        ["cwd_before", shellState.cwd || "unknown"]
      ]);
    }

    function ruleEnforcementSummaryCard(item, detail, findings, proposals) {
      const decision = ((detail || {}).response || {}).decision || item.decision;
      const firstFinding = findings[0] || {};
      const firstProposal = proposals[0] || {};
      return stateCardHtml("Rule / Enforcement", [
        ["rule_id", firstFinding.rule_id || firstProposal.rule_id || "none"],
        ["enforcement_class", firstFinding.enforcement_class || firstProposal.decision || decision || "unknown"],
        ["source_pass", firstFinding.source_pass || firstProposal.source_pass || "unknown"]
      ]);
    }

    function shellStateSummaryCard(detail) {
      const request = detail ? detail.request || {} : {};
      const shellState = request.shell_state_before || {};
      return stateCardHtml("Shell State Before", [
        ["variables", countEntries(shellState.variables)],
        ["positional_args", countEntries(shellState.positional_args)],
        ["aliases", countEntries(shellState.aliases)],
        ["functions", countEntries(shellState.functions)]
      ], '<button class="inline-link" data-tab-target="context" type="button">View details</button>');
    }

    function stateCardHtml(title, rows, footerHtml) {
      return \`
        <section class="detail-card state-card">
          <div class="detail-card-body">
            <div class="state-card-title">\${escapeHtml(title)}</div>
            <div class="kv-grid">
              \${rows.map(([key, value]) => \`
                <div class="kv-row">
                  <span class="kv-key">\${escapeHtml(key)}</span>
                  <span class="kv-value">\${escapeHtml(value == null || value === "" ? "unknown" : String(value))}</span>
                </div>
              \`).join("")}
            </div>
            \${footerHtml || ""}
          </div>
        </section>
      \`;
    }

    function executionPreviewGrid(detail) {
      const explain = (detail || {}).explain || {};
      const units = explain.execution_units || [];
      const semantics = explain.execution_semantics || [];
      const cards = [
        executionPreviewCard("Execution Units", units, executionUnitPreviewRecord),
        executionPreviewCard("Execution Semantics", semantics, semanticPreviewRecord)
      ].filter(Boolean);
      if (cards.length === 0) {
        return "";
      }
      return \`<div class="execution-preview-grid">\${cards.join("")}</div>\`;
    }

    function executionPreviewCard(title, records, renderer) {
      if (!records || records.length === 0) {
        return "";
      }
      return \`
        <section class="detail-card preview-card">
          <div class="detail-card-body">
            <div class="preview-title">\${escapeHtml(title)} (\${formatCount(records.length)})</div>
            <div class="preview-list">
              \${records.slice(0, 4).map((record, index) => renderer(record, index)).join("")}
            </div>
          </div>
        </section>
      \`;
    }

    function executionUnitPreviewRecord(unit, index) {
      const meta = [
        unit.shell_kind ? \`shell \${unit.shell_kind}\` : "",
        unit.depth != null ? \`depth \${unit.depth}\` : "",
        unit.root_sequence_no != null ? \`root #\${unit.root_sequence_no}\` : ""
      ].filter(Boolean);
      return previewRecord(index, unit.raw_text || unit.node_id || "execution unit", meta, unit.execution_kind || "");
    }

    function semanticPreviewRecord(entry, index) {
      const title = (entry.source && entry.source.raw_text) || entry.normalized_command_name || entry.node_id || "execution semantic";
      return previewRecord(index, title, semanticFlags(entry).slice(0, 3), entry.normalized_command_name || "");
    }

    function previewRecord(index, title, meta, badge) {
      return \`
        <article class="preview-row">
          <span class="row-index">\${index + 1}</span>
          <div>
            <div class="preview-command">\${escapeHtml(title)}</div>
            \${meta.length ? \`<div class="preview-meta">\${meta.map((entry) => \`<span>\${escapeHtml(entry)}</span>\`).join("")}</div>\` : ""}
          </div>
          \${badge ? \`<span class="preview-badge">\${escapeHtml(String(badge).toUpperCase())}</span>\` : ""}
        </article>
      \`;
    }

    function decisionProposalsSection(proposals) {
      return \`
        <details class="detail-card collapsed-row">
          <summary>Decision Proposals <span class="count-pill">\${formatCount((proposals || []).length)}</span></summary>
          \${proposals && proposals.length ? \`<div class="detail-card-body">\${recordList("Decision proposals", proposals.map((proposal) => ({
            title: proposal.reason || proposal.rule_id || "proposal",
            badge: proposal.decision || "",
            badgeClass: proposal.decision || "unknown",
            meta: [
              proposal.rule_id ? \`rule \${proposal.rule_id}\` : "",
              proposal.source_pass ? \`pass \${proposal.source_pass}\` : ""
            ].filter(Boolean)
          })))}</div>\` : ""}
        </details>
      \`;
    }

    function contextTabHtml(item, detail) {
      const request = detail ? detail.request || {} : {};
      const runtime = request.runtime || {};
      const shellState = request.shell_state_before || {};
      return \`
        <div class="inspection-tab-panel">
          <div class="summary-grid">
            \${stateCardHtml("Execution Context", [
              ["runtime_name", runtime.runtime_name || model.session.runtime_name || model.session.runtimeLabel || "unknown"],
              ["tool", runtime.tool_name || "unknown"],
              ["shell_kind", request.shell_kind || "unknown"],
              ["observed", formatDateTime(detail ? detail.observed_at_ms : item.observed_at_ms)]
            ])}
            \${stateCardHtml("Workspace", [
              ["workspace_root", request.workspace_root || model.session.workspace_root || "unknown"],
              ["cwd_before", shellState.cwd || "unknown"],
              ["store", model.storeLabel || model.session.storeLabel || "unknown"],
              ["session", model.session.session_id || "unknown"]
            ])}
            \${stateCardHtml("Shell State Before", [
              ["variables", countEntries(shellState.variables)],
              ["positional_args", countEntries(shellState.positional_args)],
              ["aliases", countEntries(shellState.aliases)],
              ["functions", countEntries(shellState.functions)]
            ])}
          </div>
          \${shellBindingsCard(detail)}
        </div>
      \`;
    }

    function shellBindingsCard(detail) {
      const request = detail ? detail.request || {} : {};
      const shellState = request.shell_state_before || {};
      const groups = [
        bindingGroupHtml("Variables", variableBindingRows(shellState.variables)),
        bindingGroupHtml("Positional Args", positionalArgRows(shellState.positional_args)),
        bindingGroupHtml("Aliases", aliasBindingRows(shellState.aliases)),
        bindingGroupHtml("Functions", functionBindingRows(shellState.functions))
      ].filter(Boolean);

      return \`
        <section class="detail-card context-detail-card">
          <div class="detail-card-body">
            <div class="state-card-title">Shell Bindings</div>
            \${groups.length ? \`<div class="binding-groups">\${groups.join("")}</div>\` : '<div class="empty">No shell bindings recorded for this sequence.</div>'}
          </div>
        </section>
      \`;
    }

    function bindingGroupHtml(title, rows) {
      const cleaned = (rows || []).filter(Boolean);
      if (cleaned.length === 0) {
        return "";
      }
      return \`
        <article class="binding-card">
          <div class="binding-header">
            <span class="binding-title">\${escapeHtml(title)}</span>
            <span class="count-pill">\${formatCount(cleaned.length)}</span>
          </div>
          <pre>\${escapeHtml(cleaned.join("\\n"))}</pre>
        </article>
      \`;
    }

    function variableBindingRows(variables) {
      if (!variables) {
        return [];
      }
      if (!Array.isArray(variables)) {
        if (typeof variables === "object") {
          return Object.entries(variables).map(([key, entry]) => \`\${key}=\${redactedShellValue(key, entry)}\`);
        }
        return [\`var=\${shellValueText(variables)}\`];
      }
      return variables.map((entry, index) => {
        if (entry && typeof entry === "object" && entry.name != null) {
          return \`\${entry.name}=\${redactedShellValue(entry.name, entry.value)}\`;
        }
        return bindingEntryText(entry, index, "var");
      });
    }

    function positionalArgRows(args) {
      if (!Array.isArray(args)) {
        return genericBindingRows(args, "arg");
      }
      return args.map((entry, index) => {
        if (entry && typeof entry === "object" && entry.name != null) {
          return \`\${entry.name}=\${shellValueText(entry.value)}\`;
        }
        if (entry && typeof entry === "object" && entry.index != null) {
          return \`\${entry.index}=\${shellValueText(entry.value)}\`;
        }
        return \`\${index + 1}=\${shellValueText(entry)}\`;
      });
    }

    function aliasBindingRows(aliases) {
      if (!Array.isArray(aliases)) {
        return genericBindingRows(aliases, "alias");
      }
      return aliases.map((entry, index) => {
        if (entry && typeof entry === "object" && entry.name != null) {
          return \`\${entry.name}=\${entry.body || ""}\`;
        }
        return bindingEntryText(entry, index, "alias");
      });
    }

    function functionBindingRows(functions) {
      if (!Array.isArray(functions)) {
        return genericBindingRows(functions, "function");
      }
      return functions.map((entry, index) => {
        if (entry && typeof entry === "object" && entry.name != null) {
          return \`\${entry.name}() \${entry.body || ""}\`;
        }
        return bindingEntryText(entry, index, "function");
      });
    }

    function genericBindingRows(value, prefix) {
      if (!value) {
        return [];
      }
      if (typeof value === "object") {
        return Object.entries(value).map(([key, entry]) => \`\${key}=\${shellValueText(entry)}\`);
      }
      return [\`\${prefix}=\${shellValueText(value)}\`];
    }

    function bindingEntryText(entry, index, prefix) {
      if (entry && typeof entry === "object") {
        return \`\${prefix}\${index + 1}=\${JSON.stringify(entry)}\`;
      }
      return \`\${prefix}\${index + 1}=\${shellValueText(entry)}\`;
    }

    function signalSection(findings, evidence, proposals) {
      const records = [
        ...findings.map((finding) => ({
          kind: finding.enforcement_class || finding.rule_id || "finding",
          title: finding.message || finding.summary || finding.rule_id || "finding",
          meta: [
            finding.rule_id ? \`rule \${finding.rule_id}\` : "",
            finding.source_pass ? \`pass \${finding.source_pass}\` : "",
            finding.enforcement_class ? \`class \${finding.enforcement_class}\` : ""
          ].filter(Boolean)
        })),
        ...evidence.slice(0, 5).map((entry) => ({
          kind: entry.rule_id || "evidence",
          title: entry.summary || entry.rule_id || "evidence",
          meta: [
            entry.kind ? \`kind \${kindName(entry.kind)}\` : "",
            entry.source ? \`source \${sourceName(entry.source)}\` : ""
          ].filter(Boolean)
        })),
        ...proposals.slice(0, 3).map((proposal) => ({
          kind: proposal.decision || "proposal",
          title: proposal.reason || proposal.rule_id || "proposal",
          meta: [
            proposal.rule_id ? \`rule \${proposal.rule_id}\` : "",
            proposal.source_pass ? \`pass \${proposal.source_pass}\` : ""
          ].filter(Boolean)
        }))
      ];

      if (records.length === 0) {
        return \`
          <section class="detail-section">
            <span class="section-label">Signals</span>
            <div class="detail-card"><div class="empty">No findings or evidence recorded for this sequence.</div></div>
          </section>
        \`;
      }

      return \`
        <section class="detail-section">
          <span class="section-label">Signals</span>
          <div class="signal-list">
            \${records.map(signalItem).join("")}
          </div>
        </section>
      \`;
    }

    function signalItem(record) {
      return \`
        <article class="signal-item">
          <div class="signal-kind">\${escapeHtml(record.kind)}</div>
          <div class="signal-title">\${escapeHtml(record.title)}</div>
          \${record.meta && record.meta.length ? \`<div class="signal-meta">\${record.meta.map((entry) => \`<span>\${escapeHtml(entry)}</span>\`).join("")}</div>\` : ""}
        </article>
      \`;
    }

    function executionTabHtml(item, detailState) {
      if (!detailState || detailState.status === "loading" || detailState.status === "error") {
        return \`
          <div class="inspection-tab-panel">
            <section class="detail-card execution-detail-card">
              <div class="detail-card-body">
                \${executionHtml(item, detailState)}
              </div>
            </section>
          </div>
        \`;
      }

      const detail = detailState.detail;
      return \`
        <div class="inspection-tab-panel">
          \${executionOverviewHtml(item, detail)}
          \${executionPreviewGrid(detail)}
          <section class="detail-card execution-detail-card">
            <div class="detail-card-body">
              <div class="state-card-title">Execution Detail</div>
              \${executionDetailGroupsHtml(item, detailState)}
            </div>
          </section>
        </div>
      \`;
    }

    function executionOverviewHtml(item, detail) {
      const explain = (detail || {}).explain || {};
      const units = explain.execution_units || [];
      const derived = explain.derived_invocations || [];
      const flows = explain.execution_unit_flows || [];
      const nestedPayloads = explain.nested_payloads || [];
      const semantics = explain.execution_semantics || [];
      const primaryUnit = units[0] || {};
      const primarySemantic = semantics[0] || {};
      const signalCounts = executionSignalCounts(item, semantics);

      return \`
        <div class="execution-hero-grid">
          <section class="detail-card execution-inventory-card">
            <div class="detail-card-body">
              <div class="state-card-title">Execution Inventory</div>
              <div class="execution-primary-block">
                <div class="decision-label">Primary Unit</div>
                <code class="execution-primary-command">\${escapeHtml(primaryUnit.raw_text || primaryUnit.node_id || "unknown")}</code>
              </div>
              <div class="kv-grid">
                \${kvRowHtml("normalized_command", primarySemantic.normalized_command_name || "unknown")}
                \${kvRowHtml("form", primarySemantic.form_id || "unknown")}
                \${kvRowHtml("payload_mode", primarySemantic.payload_mode || "none")}
              </div>
            </div>
            <div class="execution-metrics">
              \${executionMetricHtml("units", units.length)}
              \${executionMetricHtml("semantics", semantics.length)}
              \${executionMetricHtml("derived", derived.length)}
            </div>
          </section>
          <section class="detail-card">
            <div class="detail-card-body">
              <div class="state-card-title">Execution Signals</div>
              <div class="execution-signal-list">
                \${executionSignalHtml("payload sinks", signalCounts.payload, signalTone(signalCounts.payload, "warning"))}
                \${executionSignalHtml("remote commands", signalCounts.remote, signalTone(signalCounts.remote, "warning"))}
                \${executionSignalHtml("interactive escapes", signalCounts.interactive, signalTone(signalCounts.interactive, "warning"))}
                \${executionSignalHtml("flows / nested", flows.length + nestedPayloads.length, signalTone(flows.length + nestedPayloads.length, "info"))}
              </div>
            </div>
          </section>
        </div>
      \`;
    }

    function executionMetricHtml(label, value) {
      return \`
        <div class="execution-metric">
          <div class="decision-label">\${escapeHtml(label)}</div>
          <div class="decision-value">\${formatCount(value)}</div>
        </div>
      \`;
    }

    function executionSignalHtml(label, value, tone) {
      return \`
        <div class="execution-signal \${tone ? \`is-\${tone}\` : ""}">
          <span class="execution-signal-name">\${escapeHtml(label)}</span>
          <span class="execution-signal-value">\${formatCount(value)}</span>
        </div>
      \`;
    }

    function signalTone(value, tone) {
      return Number(value || 0) > 0 ? tone : "";
    }

    function executionSignalCounts(item, semantics) {
      const payloadCount = countSemanticMatches(semantics, (entry) => entry.executes_payload);
      const interactiveCount = countSemanticMatches(semantics, (entry) => entry.opens_interactive_escape_surface);
      return {
        payload: Math.max(payloadCount, item.has_execution_payload_sink ? 1 : 0),
        remote: countSemanticMatches(semantics, (entry) => entry.executes_remote_command),
        interactive: Math.max(interactiveCount, item.has_interactive_escape ? 1 : 0)
      };
    }

    function countSemanticMatches(semantics, predicate) {
      return (semantics || []).reduce((count, entry) => count + (predicate(entry || {}) ? 1 : 0), 0);
    }

    function kvRowHtml(key, value) {
      return \`
        <div class="kv-row">
          <span class="kv-key">\${escapeHtml(key)}</span>
          <span class="kv-value">\${escapeHtml(value == null || value === "" ? "unknown" : String(value))}</span>
        </div>
      \`;
    }

    function rawInspectionCard(item, detailState) {
      return \`
        <section class="detail-section">
          <span class="section-label">Raw JSON</span>
          <div class="detail-card">
          <div class="detail-card-body">
            \${rawHtml(item, detailState)}
          </div>
          </div>
        </section>
      \`;
    }

    function findingsHtml(item, detailState) {
      if (!detailState || detailState.status === "loading") {
        return '<div class="empty">Loading findings...</div>';
      }

      if (detailState.status === "error") {
        return \`<div class="empty">\${escapeHtml(detailState.message)}</div>\`;
      }

      const trace = decisionTrace(detailState.detail);
      const findings = trace.findings || [];
      const evidence = trace.evidence || [];
      const proposals = trace.decision_proposals || [];
      const reasons = responseReasons(detailState.detail);
      const sections = [];

      if (reasons.length > 0) {
        sections.push(recordList("Decision reasons", reasons.map((reason) => ({
          title: reason,
          meta: []
        }))));
      }

      sections.push(recordList("Findings", findings.map((finding) => ({
        title: finding.message || finding.summary || finding.rule_id || "finding",
        badge: finding.enforcement_class || finding.rule_id || "",
        badgeClass: finding.enforcement_class === "hard_deny_floor" ? "deny" : "need_approval",
        meta: [
          finding.rule_id ? \`rule \${finding.rule_id}\` : "",
          finding.source_pass ? \`pass \${finding.source_pass}\` : "",
          finding.enforcement_class ? \`class \${finding.enforcement_class}\` : ""
        ].filter(Boolean)
      }))));

      sections.push(recordList("Decision proposals", proposals.map((proposal) => ({
        title: proposal.reason || proposal.rule_id || "proposal",
        badge: proposal.decision || "",
        badgeClass: proposal.decision || "unknown",
        meta: [
          proposal.rule_id ? \`rule \${proposal.rule_id}\` : "",
          proposal.source_pass ? \`pass \${proposal.source_pass}\` : ""
        ].filter(Boolean)
      }))));

      sections.push(recordList("Evidence", evidence.map((entry) => ({
        title: entry.summary || entry.rule_id || "evidence",
        badge: entry.rule_id || "",
        badgeClass: "unknown",
        meta: [
          entry.kind ? \`kind \${kindName(entry.kind)}\` : "",
          entry.source ? \`source \${sourceName(entry.source)}\` : ""
        ].filter(Boolean)
      }))));

      if (sections.every((section) => !section)) {
        return '<div class="empty">No findings or evidence recorded for this sequence.</div>';
      }

      return \`<div class="stack">\${sections.filter(Boolean).join("")}</div>\`;
    }

    function executionDetailGroupsHtml(item, detailState) {
      if (!detailState || detailState.status === "loading" || detailState.status === "error") {
        return executionHtml(item, detailState);
      }

      return executionGroupsFromExplain(detailState.detail.explain || {});
    }

    function executionGroupsFromExplain(explain) {
      const units = explain.execution_units || [];
      const derived = explain.derived_invocations || [];
      const flows = explain.execution_unit_flows || [];
      const nestedPayloads = explain.nested_payloads || [];
      const semantics = explain.execution_semantics || [];
      const groups = [
        executionRecordGroup("Execution Units", units.map(executionUnitRecord)),
        executionRecordGroup("Derived Invocations", derived.map(derivedInvocationRecord)),
        executionFlowGroup(flows),
        executionRecordGroup("Nested Payloads", nestedPayloads.map(nestedPayloadRecord)),
        executionRecordGroup("Execution Semantics", semantics.map(executionSemanticRecord))
      ].filter(Boolean);

      if (groups.length === 0) {
        return '<div class="empty">No execution semantics recorded for this sequence.</div>';
      }

      return \`<div class="execution-detail-groups">\${groups.join("")}</div>\`;
    }

    function executionRecordGroup(title, records) {
      const cleaned = (records || []).filter(Boolean);
      if (cleaned.length === 0) {
        return "";
      }

      return \`
        <section class="execution-detail-group">
          <div class="execution-group-header">
            <span class="execution-group-title">\${escapeHtml(title)}</span>
            <span class="count-pill">\${formatCount(cleaned.length)}</span>
          </div>
          <div class="execution-record-list">
            \${cleaned.map(recordHtml).join("")}
          </div>
        </section>
      \`;
    }

    function executionFlowGroup(flows) {
      if (!flows || flows.length === 0) {
        return "";
      }

      const records = flows.map((flow) => {
        const fromText = (flow.from && flow.from.raw_text) || (flow.from && flow.from.node_id) || "";
        const toText = (flow.to && flow.to.raw_text) || (flow.to && flow.to.node_id) || "";
        return \`
          <article class="record flow">
            <code>\${escapeHtml(fromText)}</code>
            <span class="flow-arrow">-></span>
            <code>\${escapeHtml(toText)}</code>
          </article>
        \`;
      });

      return \`
        <section class="execution-detail-group">
          <div class="execution-group-header">
            <span class="execution-group-title">Execution Flows</span>
            <span class="count-pill">\${formatCount(flows.length)}</span>
          </div>
          <div class="execution-record-list">
            \${records.join("")}
          </div>
        </section>
      \`;
    }

    function executionUnitRecord(unit) {
      return {
        title: unit.raw_text || unit.node_id,
        badge: unit.execution_kind || "",
        badgeClass: unit.execution_kind === "top_level" ? "allow" : "unknown",
        meta: [
          unit.shell_kind ? \`shell \${unit.shell_kind}\` : "",
          unit.depth != null ? \`depth \${unit.depth}\` : "",
          unit.root_sequence_no != null ? \`root #\${unit.root_sequence_no}\` : ""
        ].filter(Boolean)
      };
    }

    function derivedInvocationRecord(invocation) {
      return {
        title: invocation.raw_text || invocation.node_id,
        badge: invocation.command_name || "",
        badgeClass: "unknown",
        meta: [
          invocation.shell_kind ? \`shell \${invocation.shell_kind}\` : "",
          invocation.depth != null ? \`depth \${invocation.depth}\` : "",
          invocation.origin ? \`origin \${kindName(invocation.origin)}\` : ""
        ].filter(Boolean)
      };
    }

    function nestedPayloadRecord(payload) {
      return {
        title: payload.raw_text || payload.payload_text || payload.node_id || "payload",
        badge: payload.payload_kind || kindName(payload.kind),
        badgeClass: "need_approval",
        meta: [
          payload.source_node_id ? \`source \${payload.source_node_id}\` : "",
          payload.depth != null ? \`depth \${payload.depth}\` : ""
        ].filter(Boolean)
      };
    }

    function executionSemanticRecord(entry) {
      return {
        title: (entry.source && entry.source.raw_text) || entry.normalized_command_name || entry.node_id,
        badge: entry.normalized_command_name || "",
        badgeClass: semanticBadgeClass(entry),
        meta: semanticFlags(entry)
      };
    }

    function executionHtml(item, detailState) {
      if (!detailState || detailState.status === "loading") {
        return '<div class="empty">Loading execution detail...</div>';
      }

      if (detailState.status === "error") {
        return \`<div class="empty">\${escapeHtml(detailState.message)}</div>\`;
      }

      return executionGroupsFromExplain(detailState.detail.explain || {});
    }

    function rawHtml(item, detailState) {
      if (!detailState || detailState.status === "loading") {
        return '<div class="empty">Loading raw check detail...</div>';
      }

      if (detailState.status === "error") {
        return \`<div class="empty">\${escapeHtml(detailState.message)}</div>\`;
      }

      return \`<pre>\${escapeHtml(JSON.stringify(detailState.detail, null, 2))}</pre>\`;
    }

    function decisionTrace(detail) {
      return (((detail || {}).response || {}).decision_trace) || {};
    }

    function responseReasons(detail) {
      return ((((detail || {}).response || {}).reasons) || []).filter(Boolean);
    }

    function recordList(title, records) {
      if (!records || records.length === 0) {
        return "";
      }

      return \`
        <section class="stack">
          <div class="subsection-title"><span>\${escapeHtml(title)}</span><span>\${records.length}</span></div>
          \${records.map(recordHtml).join("")}
        </section>
      \`;
    }

    function recordHtml(record) {
      const meta = (record.meta || []).filter(Boolean);
      return \`
        <article class="record">
          <div class="record-title">
            <span>\${escapeHtml(record.title || "")}</span>
            \${record.badge ? \`<span class="badge \${record.badgeClass || "unknown"}">\${escapeHtml(record.badge)}</span>\` : ""}
          </div>
          \${meta.length ? \`<div class="record-meta">\${meta.map((item) => \`<span>\${escapeHtml(item)}</span>\`).join("")}</div>\` : ""}
        </article>
      \`;
    }

    function semanticFlags(entry) {
      const flags = [
        ["executes payload", entry.executes_payload],
        ["remote command", entry.executes_remote_command],
        ["interactive escape", entry.opens_interactive_escape_surface],
        ["startup config", entry.loads_startup_config],
        ["project config", entry.loads_project_config],
        ["tool config", entry.loads_tool_config],
        ["process control", entry.controls_process],
        ["mutates shell", entry.mutates_current_shell],
        ["child command", entry.dispatches_child_command],
        ["in-process code", entry.loads_in_process_code],
        ["package logic", entry.executes_imported_package_logic]
      ];
      const enabled = flags.filter(([, value]) => value).map(([label]) => label);
      if (entry.form_id) {
        enabled.unshift(\`form \${entry.form_id}\`);
      }
      if (entry.payload_mode) {
        enabled.push(\`payload \${entry.payload_mode}\`);
      }
      return enabled;
    }

    function semanticBadgeClass(entry) {
      if (
        entry.executes_payload ||
        entry.executes_remote_command ||
        entry.opens_interactive_escape_surface ||
        entry.controls_process
      ) {
        return "need_approval";
      }
      return "unknown";
    }

    function kindName(kind) {
      if (!kind || typeof kind !== "object") {
        return String(kind || "");
      }
      return Object.keys(kind)[0] || "";
    }

    function sourceName(source) {
      if (!source || typeof source !== "object") {
        return String(source || "");
      }
      return source.node_id || source.raw_text || kindName(source) || JSON.stringify(source);
    }

    function detailStateFor(sequenceNo) {
      return detailCache[String(sequenceNo)] || null;
    }

    function ensureDetailLoaded(sequenceNo) {
      const key = String(sequenceNo);
      const current = detailCache[key];
      if (current && (current.status === "loading" || current.status === "loaded")) {
        return;
      }

      detailCache[key] = { status: "loading" };
      renderDetails();
      vscodeApi.postMessage({
        type: "loadDetail",
        sequenceNo
      });
    }

    function requestMoreTimeline() {
      if (loadingMore || filterText || !model.overview.has_more) {
        return;
      }

      loadingMore = true;
      timelineError = null;
      renderTimeline();
      vscodeApi.postMessage({
        type: "loadMoreTimeline",
        beforeSequence: model.overview.next_before_sequence || null,
        afterSequence: model.overview.next_after_sequence || null
      });
    }

    function maybeRequestMoreTimeline() {
      const container = document.getElementById("timeline");
      if (!container || loadingMore || filterText || !model.overview.has_more) {
        return;
      }
      const remaining = container.scrollHeight - container.scrollTop - container.clientHeight;
      if (remaining <= autoLoadThresholdPx) {
        requestMoreTimeline();
      }
    }

    function timelineStatusText() {
      if (timelineError) {
        return timelineError;
      }
      if (loadingMore) {
        return "Loading more...";
      }
      if (filterText) {
        return "";
      }
      return model.overview.has_more ? "Scroll for more" : "";
    }

    function mergeOverviewPage(overview) {
      const seen = new Set((model.overview.items || []).map((item) => item.sequence_no));
      for (const item of overview.items || []) {
        if (!seen.has(item.sequence_no)) {
          model.overview.items.push(item);
          seen.add(item.sequence_no);
        }
      }

      model.overview.has_more = Boolean(overview.has_more);
      model.overview.next_before_sequence = overview.next_before_sequence || null;
      model.overview.next_after_sequence = overview.next_after_sequence || null;
    }

    function setText(id, value) {
      const node = document.getElementById(id);
      if (node) {
        node.textContent = value == null ? "" : String(value);
      }
    }

    function filteredTimelineItems(items) {
      if (!filterText) {
        return items;
      }
      return items.filter((item) => {
        const haystack = [
          item.raw_text,
          decisionLabel(item.decision),
          padSequence(item.sequence_no),
          formatTime(item.observed_at_ms)
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(filterText);
      });
    }

    function formatCount(value) {
      const number = Number(value || 0);
      if (!Number.isFinite(number)) {
        return "0";
      }
      return number.toLocaleString();
    }

    function formatMetaValue(value) {
      if (typeof value === "number" && Number.isFinite(value)) {
        return String(value);
      }
      return String(value);
    }

    function countEntries(value) {
      if (Array.isArray(value)) {
        return value.length;
      }
      if (value && typeof value === "object") {
        return Object.keys(value).length;
      }
      return 0;
    }

    function padSequence(value) {
      const text = String(value == null ? "" : value);
      return text.padStart(3, "0");
    }

    function formatTime(value) {
      const number = Number(value || 0);
      if (!number) {
        return "";
      }
      try {
        const date = new Date(number);
        return [date.getHours(), date.getMinutes(), date.getSeconds()]
          .map((part) => String(part).padStart(2, "0"))
          .join(":");
      } catch {
        return "";
      }
    }

    function formatDateTime(value) {
      const number = Number(value || 0);
      if (!number) {
        return "unknown";
      }
      try {
        return new Date(number).toLocaleString();
      } catch {
        return String(value);
      }
    }

    function decisionLabel(decision) {
      if (decision === "allow") {
        return "ALLOW";
      }
      if (decision === "need_approval") {
        return "NEED";
      }
      if (decision === "deny") {
        return "DENY";
      }
      return "UNKNOWN";
    }

    function redactedShellValue(name, value) {
      if (isSensitiveName(name)) {
        return "[redacted]";
      }
      const rendered = shellValueText(value);
      if (isSensitiveName(rendered)) {
        return "[redacted]";
      }
      return rendered;
    }

    function shellValueText(value) {
      if (value == null) {
        return "";
      }
      if (typeof value === "string") {
        return value;
      }
      if (typeof value === "object") {
        if (typeof value.value === "string") {
          return value.value;
        }
        if (Array.isArray(value.values)) {
          return value.values.join(" ");
        }
        return JSON.stringify(value);
      }
      return String(value);
    }

    function isSensitiveName(value) {
      return /(token|secret|password|passwd|apikey|api_key|credential|private|auth|bearer)/i.test(
        String(value || "")
      );
    }

    function decisionClass(decision) {
      if (decision === "allow" || decision === "deny" || decision === "need_approval") {
        return decision;
      }
      return "unknown";
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }

    try {
      window.addEventListener("message", (event) => {
        const message = event.data || {};

        if (message.type === "detailLoaded" && message.detail) {
          detailCache[String(message.detail.sequence_no)] = {
            status: "loaded",
            detail: message.detail
          };
          if (activeItem && activeItem.sequence_no === message.detail.sequence_no) {
            renderDetails();
          }
          return;
        }

        if (message.type === "timelinePageLoaded" && message.overview) {
          loadingMore = false;
          mergeOverviewPage(message.overview);
          renderTimeline();
          if (!activeItem && (model.overview.items || []).length > 0) {
            activeItem = model.overview.items[0];
            ensureDetailLoaded(activeItem.sequence_no);
          }
          renderDetails();
          return;
        }

        if (message.type === "queryError") {
          if (message.operation === "loadDetail" && message.sequenceNo != null) {
            detailCache[String(message.sequenceNo)] = {
              status: "error",
              message: message.message || "detail query failed"
            };
            if (activeItem && activeItem.sequence_no === message.sequenceNo) {
              renderDetails();
            }
            return;
          }

          if (message.operation === "loadMoreTimeline") {
            loadingMore = false;
            timelineError = message.message || "timeline query failed";
            renderTimeline();
          }
        }
      });

      document.getElementById("timeline").addEventListener("scroll", maybeRequestMoreTimeline, {
        passive: true
      });
      document.getElementById("timeline-filter").addEventListener("input", (event) => {
        filterText = String(event.target.value || "").trim().toLowerCase();
        renderTimeline();
      });
      renderTimeline();
      renderDetails();
      if (activeItem) {
        ensureDetailLoaded(activeItem.sequence_no);
      }
    } catch (error) {
      const message = escapeHtml(error && error.stack ? error.stack : String(error));
      document.body.innerHTML = \`
        <div style="padding:24px;color:#f8f1d7;background:#12140f;font-family:monospace;">
          <h2 style="margin-top:0;">Caushell webview render failed</h2>
          <pre style="white-space:pre-wrap;">\${message}</pre>
        </div>
      \`;
    }
  </script>
</body>
</html>`;
}

function loadingHtml(webview, message) {
  const escaped = escapeHtml(message);
  return `<!DOCTYPE html><html><body><p>${escaped}</p></body></html>`;
}

function errorHtml(webview, error) {
  const message = escapeHtml(error.message || String(error));
  return `<!DOCTYPE html><html><body><h2>Caushell query failed</h2><pre>${message}</pre></body></html>`;
}

function sessionTooltip(session) {
  const lines = [
    ...(session.displayTitle && session.displayTitle !== session.session_id
      ? [`Title: ${session.displayTitle}`]
      : []),
    `Session: ${session.session_id}`,
    `Runtime: ${session.runtimeLabel}`,
    `Store: ${session.storeLabel}`,
    `Checks: ${session.check_count || 0}`,
    `Events: ${session.event_count || 0}`,
    `Latest decision: ${session.last_decision || "unknown"}`
  ];

  if (session.workspace_root) {
    lines.push(`Workspace: ${session.workspace_root}`);
  }
  if (session.last_command) {
    lines.push(`Latest command: ${session.last_command}`);
  }

  return lines.join("\n");
}

async function decorateSession(descriptor, session, titleResolver) {
  const workspaceRoot = normalizeWorkspaceRoot(session.workspace_root || "");
  const runtimeKind = runtimeKindForSession(session.runtime_name, descriptor.storeKind);
  const runtimeLabel = runtimeLabelFor(session.runtime_name, descriptor.storeKind);
  const storeIdentityGroup = storeIdentityGroupForRoot(descriptor.storeRoot, descriptor.storeKind);
  const title = titleResolver
    ? await titleResolver.resolve(descriptor, session)
    : fallbackSessionTitle(session.session_id);
  return {
    ...session,
    session_key: logicalSessionKey(
      storeIdentityGroup,
      runtimeKind,
      descriptor.storeKind,
      session.session_id
    ),
    storeRoot: descriptor.storeRoot,
    storeKind: descriptor.storeKind,
    storeIdentityGroup,
    storeLabel: descriptor.label,
    runtimeKind,
    runtimeLabel,
    displayTitle: title.displayTitle,
    titleSource: title.titleSource,
    workspace_root: workspaceRoot,
    workspaceLabel: workspaceScopeLabel(workspaceRoot)
  };
}

function fallbackSessionTitle(sessionId) {
  return {
    displayTitle: String(sessionId || "Unknown session"),
    titleSource: "session_id"
  };
}

function sessionPanelLabel(session) {
  return `Caushell ${truncateText(session.displayTitle || session.session_id, 72)}`;
}

function sessionSubtitle(session) {
  const parts = [
    session.storeLabel,
    session.runtimeLabel,
    `${session.check_count || 0} checks`,
    `latest ${session.last_decision || "unknown"}`
  ];

  if (session.displayTitle && session.displayTitle !== session.session_id) {
    parts.push(`session ${session.session_id}`);
  }

  return parts.join(" · ");
}

function compareSessionsDesc(left, right) {
  if ((left.last_observed_at_ms || 0) !== (right.last_observed_at_ms || 0)) {
    return (right.last_observed_at_ms || 0) - (left.last_observed_at_ms || 0);
  }
  if (left.storeKind !== right.storeKind) {
    return String(left.storeKind).localeCompare(String(right.storeKind));
  }
  return String(right.session_id).localeCompare(String(left.session_id));
}

function storeDescriptor(storeRoot) {
  return {
    storeRoot,
    storeKind: storeKindForRoot(storeRoot),
    label: storeLabelForRoot(storeRoot)
  };
}

function logicalSessionKey(storeIdentityGroup, runtimeKind, fallbackStoreKind, sessionId) {
  const runtime = runtimeKind || fallbackStoreKind || "store";
  return `${storeIdentityGroup || runtime}:${runtime}:${sessionId || "unknown-session"}`;
}

function storeIdentityGroupForRoot(storeRoot, storeKind) {
  if (storeRoot.includes(`${path.sep}lab-logs${path.sep}`)) {
    return `lab:${storeKind || "store"}`;
  }
  if (storeKind === "codex" || storeKind === "claude") {
    return storeKind;
  }
  return `store:${storeRoot}`;
}

function storeKindForRoot(storeRoot) {
  if (storeRoot.includes(`${path.sep}codex${path.sep}`)) {
    return "codex";
  }
  if (storeRoot.includes(`${path.sep}claude${path.sep}`)) {
    return "claude";
  }
  return "store";
}

function storeLabelForRoot(storeRoot) {
  const storeKind = storeKindForRoot(storeRoot);
  if (storeKind === "codex") {
    return "Codex";
  }
  if (storeKind === "claude") {
    return "Claude";
  }
  return "Store";
}

function runtimeLabelFor(runtimeName, fallbackStoreKind) {
  if (runtimeName === "codex" || runtimeName === "openai_codex") {
    return "Codex";
  }
  if (runtimeName === "claude" || runtimeName === "claude_code") {
    return "Claude";
  }
  if (runtimeName) {
    return runtimeName;
  }
  if (fallbackStoreKind === "codex") {
    return "Codex";
  }
  if (fallbackStoreKind === "claude") {
    return "Claude";
  }
  return "Unknown";
}

function runtimeGroupLabel(runtimeKind, fallbackLabel) {
  if (runtimeKind === "codex") {
    return "Codex";
  }
  if (runtimeKind === "claude") {
    return "Claude Code";
  }
  return fallbackLabel || "Unknown";
}

function runtimeGroupOrder(runtimeKind) {
  if (runtimeKind === "codex") {
    return 0;
  }
  if (runtimeKind === "claude") {
    return 1;
  }
  return 2;
}

function defaultWorkspaceRoot() {
  return normalizeWorkspaceRoot(workspaceRoots()[0] || "");
}

function workspaceRoots() {
  return (vscode.workspace.workspaceFolders || [])
    .map((folder) => normalizeWorkspaceRoot(folder.uri.fsPath))
    .filter(Boolean);
}

function workspaceScopeLabel(workspaceRoot) {
  if (!workspaceRoot) {
    return "Unknown workspace";
  }
  return path.basename(workspaceRoot) || workspaceRoot;
}

function compactPathLabel(targetPath) {
  if (!targetPath) {
    return "";
  }
  const home = normalizeWorkspaceRoot(os.homedir());
  if (home && (pathEquals(targetPath, home) || targetPath.startsWith(`${home}${path.sep}`))) {
    return `~${targetPath.slice(home.length) || ""}`;
  }
  return targetPath;
}

function sessionCountLabel(count) {
  return `${count} ${count === 1 ? "session" : "sessions"}`;
}

function expandHome(value) {
  if (value === "~") {
    return os.homedir();
  }
  if (value.startsWith("~/")) {
    return path.join(os.homedir(), value.slice(2));
  }
  return value;
}

function fileExists(targetPath) {
  try {
    return fs.existsSync(targetPath);
  } catch {
    return false;
  }
}

function requireExistingConfiguredStoreRoot(storeRoot) {
  if (fileExists(storeRoot)) {
    return storeRoot;
  }

  throw new Error(`configured caushell.storeRoot does not exist: ${storeRoot}`);
}

function canonicalStoreRoots() {
  const configuredStateHome = envOption("XDG_STATE_HOME");
  const stateHome = configuredStateHome
    ? expandHome(configuredStateHome)
    : path.join(os.homedir(), ".local", "state");
  const stateRoot = path.join(stateHome, "caushell");
  const roots = [];
  const seen = new Set();

  for (const subdir of CANONICAL_STORE_SUBDIRS) {
    const storeRoot = path.join(stateRoot, ...subdir.split("/"));
    if (fileExists(storeRoot)) {
      pushUnique(roots, seen, storeRoot);
    }
  }

  for (const subdir of CANONICAL_STORE_GLOB_DIRS) {
    const parent = path.join(stateRoot, ...subdir.split("/"));
    for (const storeRoot of childStoreRoots(parent)) {
      pushUnique(roots, seen, storeRoot);
    }
  }

  return roots;
}

function childStoreRoots(parent) {
  if (!fileExists(parent)) {
    return [];
  }

  let entries = [];
  try {
    entries = fs.readdirSync(parent, { withFileTypes: true });
  } catch {
    return [];
  }

  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(parent, entry.name))
    .filter((storeRoot) => fileExists(path.join(storeRoot, "caushell.sqlite3")));
}

function runtimeKindForSession(runtimeName, fallbackStoreKind) {
  if (runtimeName === "codex" || runtimeName === "openai_codex") {
    return "codex";
  }
  if (runtimeName === "claude" || runtimeName === "claude_code") {
    return "claude";
  }
  if (fallbackStoreKind === "codex" || fallbackStoreKind === "claude") {
    return fallbackStoreKind;
  }
  return "";
}

function sessionCacheKey(descriptor, session) {
  return `${descriptor.storeKind}:${descriptor.storeRoot}:${session.session_id}`;
}

function findSessionFile(rootPath, fileNameSuffix, maxDepth) {
  if (!fileExists(rootPath)) {
    return null;
  }

  const stack = [{ directory: rootPath, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) {
      continue;
    }

    let entries = [];
    try {
      entries = fs.readdirSync(current.directory, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const entryPath = path.join(current.directory, entry.name);
      if (entry.isFile() && entry.name.endsWith(fileNameSuffix)) {
        return entryPath;
      }
      if (entry.isDirectory() && current.depth < maxDepth) {
        stack.push({ directory: entryPath, depth: current.depth + 1 });
      }
    }
  }

  return null;
}

async function firstJsonlValue(filePath, extract) {
  const stream = fs.createReadStream(filePath, { encoding: "utf8" });
  const reader = readline.createInterface({
    input: stream,
    crlfDelay: Infinity
  });

  try {
    for await (const line of reader) {
      if (!line) {
        continue;
      }

      let record = null;
      try {
        record = JSON.parse(line);
      } catch {
        continue;
      }

      const value = extract(record);
      if (value) {
        return value;
      }
    }
  } finally {
    reader.close();
    stream.destroy();
  }

  return "";
}

function derivePromptTitle(message) {
  if (typeof message !== "string") {
    return "";
  }

  const normalizedMessage = String(message).replace(/\\n/g, "\n");
  const lines = normalizedMessage
    .split(/\r?\n/)
    .map((line) => collapseWhitespace(line))
    .filter(Boolean);

  if (lines.length === 0) {
    return "";
  }

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const inlineTask = line.match(/^task:\s*(.+)$/i);
    if (inlineTask && inlineTask[1]) {
      return normalizeSessionTitle(inlineTask[1]);
    }

    if (/^task:\s*$/i.test(line) && lines[index + 1]) {
      return normalizeSessionTitle(lines[index + 1]);
    }
  }

  const candidate =
    lines.find(
      (line) =>
        !/^you are codex\b/i.test(line) &&
        !/^return only\b/i.test(line) &&
        !/^no markdown\b/i.test(line)
    ) || lines[0];

  return normalizeSessionTitle(candidate);
}

function normalizeSessionTitle(value) {
  const collapsed = collapseWhitespace(
    String(value || "")
      .replace(/[`*_#>]+/g, " ")
      .replace(/\s+/g, " ")
  );

  if (!collapsed) {
    return "";
  }

  return truncateText(collapsed, 96);
}

function collapseWhitespace(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function truncateText(value, maxLength) {
  if (value.length <= maxLength) {
    return value;
  }
  if (maxLength <= 3) {
    return value.slice(0, maxLength);
  }
  return `${value.slice(0, maxLength - 3).trimEnd()}...`;
}

function pathEquals(left, right) {
  return normalizePath(left) === normalizePath(right);
}

function normalizePath(value) {
  return String(value || "").replace(/[\\/]+$/, "");
}

function normalizeWorkspaceRoot(value) {
  return normalizePath(value || "");
}

function envOption(name) {
  const value = process.env[name];
  if (!value) {
    return "";
  }
  return value.trim();
}

function findExecutableOnPath(executable) {
  const pathValue = envOption("PATH");
  if (!pathValue) {
    return null;
  }

  const executableNames = process.platform === "win32"
    ? windowsExecutableNames(executable)
    : [executable];

  for (const directory of pathValue.split(path.delimiter).filter(Boolean)) {
    for (const name of executableNames) {
      const candidate = path.join(directory, name);
      if (fileExists(candidate)) {
        return candidate;
      }
    }
  }

  return null;
}

function windowsExecutableNames(executable) {
  const suffixes = envOption("PATHEXT")
    .split(";")
    .map((suffix) => suffix.trim())
    .filter(Boolean);
  const names = [executable];

  for (const suffix of suffixes) {
    if (executable.toLowerCase().endsWith(suffix.toLowerCase())) {
      continue;
    }
    names.push(`${executable}${suffix}`);
  }

  return names;
}

function cliCandidates(extensionPath, executable) {
  const candidates = [];
  const seen = new Set();
  const workspaceFolders = vscode.workspace.workspaceFolders || [];

  for (const folder of workspaceFolders) {
    pushUnique(
      candidates,
      seen,
      path.join(folder.uri.fsPath, "target", "debug", executable)
    );
    pushUnique(
      candidates,
      seen,
      path.join(folder.uri.fsPath, "Caushell", "target", "debug", executable)
    );
  }

  pushUnique(
    candidates,
    seen,
    path.resolve(extensionPath, "..", "..", "target", "debug", executable)
  );
  pushUnique(
    candidates,
    seen,
    path.resolve(extensionPath, "..", "..", "..", "target", "debug", executable)
  );

  return candidates;
}

function pushUnique(items, seen, value) {
  if (seen.has(value)) {
    return;
  }
  seen.add(value);
  items.push(value);
}

function nonceValue() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 32; i += 1) {
    result += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return result;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = {
  activate,
  deactivate
};

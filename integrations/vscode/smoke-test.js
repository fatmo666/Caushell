"use strict";

const assert = require("assert");
const events = require("events");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Module = require("module");

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "caushell-vscode-smoke-"));
const stateHome = path.join(tempRoot, "state");
const homeRoot = path.join(tempRoot, "home");
const runtimeDir = path.join(tempRoot, "runtime");
const configPath = path.join(homeRoot, ".config", "caushell", "config.yaml");
process.env.XDG_RUNTIME_DIR = runtimeDir;
const codexStore = path.join(stateHome, "caushell", "codex", "sessions");
const codexFingerprintStore = path.join(
  stateHome,
  "caushell",
  "codex",
  "sessions",
  "v2",
  "runtime-fingerprint"
);
const claudeStore = path.join(stateHome, "caushell", "claude", "sessions");
fs.mkdirSync(codexStore, { recursive: true });
fs.mkdirSync(codexFingerprintStore, { recursive: true });
fs.mkdirSync(claudeStore, { recursive: true });
fs.writeFileSync(path.join(codexFingerprintStore, "caushell.sqlite3"), "");

process.env.XDG_STATE_HOME = stateHome;
process.env.HOME = homeRoot;

const claudeSessionDir = path.join(homeRoot, ".claude", "projects", "workspace-app");
const codexSessionDir = path.join(homeRoot, ".codex", "sessions", "2026", "06", "15");
fs.mkdirSync(claudeSessionDir, { recursive: true });
fs.mkdirSync(codexSessionDir, { recursive: true });

fs.writeFileSync(
  path.join(claudeSessionDir, "claude-current.jsonl"),
  `${JSON.stringify({
    type: "ai-title",
    aiTitle: "Claude fixes the session routing bug",
    sessionId: "claude-current"
  })}\n`
);

fs.writeFileSync(
  path.join(codexSessionDir, "rollout-2026-06-15T00-00-00-codex-current.jsonl"),
  `${JSON.stringify({
    type: "event_msg",
    payload: {
      type: "user_message",
      message: "Use Bash to run pwd and reply with the directory only."
    }
  })}\n`
);

fs.writeFileSync(
  path.join(codexSessionDir, "rollout-2026-06-15T00-00-00-codex-other.jsonl"),
  `${JSON.stringify({
    type: "event_msg",
    payload: {
      type: "user_message",
      message: "Task:\\nAudit the other workspace session history and summarize key shell checks."
    }
  })}\n`
);

const workspaceRoot = "/workspace/app";
const otherWorkspaceRoot = "/workspace/other";
const fakeSocketPath = path.join(runtimeDir, "caushell", "codex", "runtime", "workspace", "caushell.sock");
const fakeRuntimePid = 987654321;
const fakeRuntimeCmdline = Buffer.from(
  `caushell\0serve-unix\0--socket\0${fakeSocketPath}\0--store\0${codexFingerprintStore}\0`,
  "utf8"
);
const originalProcessKill = process.kill;
const originalReadFileSync = fs.readFileSync;

process.kill = function patchedProcessKill(pid, signal) {
  if (pid === fakeRuntimePid && signal === 0) {
    return true;
  }
  return originalProcessKill.call(process, pid, signal);
};

fs.readFileSync = function patchedReadFileSync(filePath, ...args) {
  if (path.normalize(String(filePath)) === path.join("/proc", String(fakeRuntimePid), "cmdline")) {
    return Buffer.from(fakeRuntimeCmdline);
  }
  return originalReadFileSync.call(fs, filePath, ...args);
};

const activeRuntimeRoot = path.join(
  runtimeDir,
  "caushell",
  "codex",
  "runtime",
  "workspace"
);
const activeSessionRoot = path.join(activeRuntimeRoot, "active-sessions", "codex-current");
fs.mkdirSync(activeSessionRoot, { recursive: true });
fs.writeFileSync(
  path.join(activeRuntimeRoot, "daemon.json"),
  `${JSON.stringify(
    {
      pid: fakeRuntimePid,
      instance_id: "runtime-instance",
      status: "ready",
      started_at_ms: Date.now(),
      socket_path: fakeSocketPath,
      store_root: codexFingerprintStore,
      runtime_path: "caushell",
      runtime_fingerprint: "runtime",
      workspace_hash: "workspace"
    },
    null,
    2
  )}\n`
);
fs.writeFileSync(
  path.join(activeSessionRoot, "active-session.json"),
  `${JSON.stringify(
    {
      record_type: "active_session",
      runtime_name: "codex",
      session_id: "codex-current",
      workspace_root: workspaceRoot,
      workspace_hash: "workspace",
      daemon_pid: fakeRuntimePid,
      daemon_instance_id: "runtime-instance",
      socket_path: fakeSocketPath,
      store_root: codexFingerprintStore,
      runtime_fingerprint: "runtime",
      started_at: new Date().toISOString(),
      heartbeat_at: new Date().toISOString(),
      heartbeat_at_ms: Date.now(),
      last_event_name: "PreToolUse",
      plugin_version: "0.0.1"
    },
    null,
    2
  )}\n`
);

const fixtures = new Map([
  [
    codexStore,
    {
      current_workspace: [
        {
          session_id: "codex-current",
          first_observed_at_ms: 100,
          last_observed_at_ms: 300,
          last_event_index: 3,
          event_count: 3,
          check_count: 3,
          last_sequence_no: 3,
          last_command: "pwd",
          last_decision: "allow",
          workspace_root: workspaceRoot,
          runtime_name: "codex"
        }
      ],
      all: [
        {
          session_id: "codex-current",
          first_observed_at_ms: 100,
          last_observed_at_ms: 300,
          last_event_index: 3,
          event_count: 3,
          check_count: 3,
          last_sequence_no: 3,
          last_command: "pwd",
          last_decision: "allow",
          workspace_root: workspaceRoot,
          runtime_name: "codex"
        },
        {
          session_id: "codex-other",
          first_observed_at_ms: 50,
          last_observed_at_ms: 250,
          last_event_index: 2,
          event_count: 2,
          check_count: 2,
          last_sequence_no: 2,
          last_command: "ls",
          last_decision: "need_approval",
          workspace_root: otherWorkspaceRoot,
          runtime_name: "codex"
        }
      ]
    }
  ],
  [
    codexFingerprintStore,
    {
      current_workspace: [
        {
          session_id: "codex-current",
          first_observed_at_ms: 100,
          last_observed_at_ms: 350,
          last_event_index: 5,
          event_count: 5,
          check_count: 5,
          last_sequence_no: 5,
          last_command: "pwd from v2",
          last_decision: "allow",
          workspace_root: workspaceRoot,
          runtime_name: "codex"
        }
      ],
      all: [
        {
          session_id: "codex-current",
          first_observed_at_ms: 100,
          last_observed_at_ms: 350,
          last_event_index: 5,
          event_count: 5,
          check_count: 5,
          last_sequence_no: 5,
          last_command: "pwd from v2",
          last_decision: "allow",
          workspace_root: workspaceRoot,
          runtime_name: "codex"
        }
      ]
    }
  ],
  [
    claudeStore,
    {
      current_workspace: [
        {
          session_id: "claude-current",
          first_observed_at_ms: 200,
          last_observed_at_ms: 400,
          last_event_index: 4,
          event_count: 4,
          check_count: 4,
          last_sequence_no: 4,
          last_command: "echo hi",
          last_decision: "allow",
          workspace_root: workspaceRoot,
          runtime_name: "claude_code"
        }
      ],
      all: [
        {
          session_id: "claude-current",
          first_observed_at_ms: 200,
          last_observed_at_ms: 400,
          last_event_index: 4,
          event_count: 4,
          check_count: 4,
          last_sequence_no: 4,
          last_command: "echo hi",
          last_decision: "allow",
          workspace_root: workspaceRoot,
          runtime_name: "claude_code"
        }
      ]
    }
  ]
]);

const providers = new Map();
let lastPanel = null;
let lastShownDocument = null;
const commands = new Map();
const cliInvocations = [];

const vscodeMock = {
  EventEmitter: class {
    constructor() {
      this.emitter = new events.EventEmitter();
      this.event = (listener) => {
        this.emitter.on("change", listener);
        return { dispose() {} };
      };
    }
    fire(value) {
      this.emitter.emit("change", value);
    }
    dispose() {}
  },
  ThemeIcon: class {
    constructor(id) {
      this.id = id;
    }
  },
  TreeItem: class {
    constructor(label, collapsibleState) {
      this.label = label;
      this.collapsibleState = collapsibleState;
    }
  },
  TreeItemCollapsibleState: {
    None: 0,
    Collapsed: 1,
    Expanded: 2
  },
  ViewColumn: {
    One: 1
  },
  ConfigurationTarget: {
    Workspace: 1
  },
  Uri: {
    file(fsPath) {
      return { fsPath };
    }
  },
  window: {
    registerTreeDataProvider(id, candidate) {
      providers.set(id, candidate);
      return { dispose() {} };
    },
    showInputBox() {
      return Promise.resolve(undefined);
    },
    showQuickPick(items) {
      return Promise.resolve(items[0]);
    },
    showWarningMessage() {},
    showInformationMessage() {},
    showTextDocument(document) {
      lastShownDocument = document;
      return Promise.resolve();
    },
    onDidChangeActiveTextEditor() {
      return { dispose() {} };
    },
    createWebviewPanel(viewType, title) {
      lastPanel = {
        viewType,
        title,
        webview: {
          html: "",
          onDidReceiveMessage() {
            return { dispose() {} };
          },
          postMessage() {
            return Promise.resolve(true);
          }
        }
      };
      return lastPanel;
    }
  },
  commands: {
    registerCommand(name, handler) {
      commands.set(name, handler);
      return { dispose() {} };
    },
    executeCommand() {
      return Promise.resolve();
    }
  },
  workspace: {
    workspaceFolders: [
      { uri: { fsPath: workspaceRoot } },
      { uri: { fsPath: "/workspace/second" } }
    ],
    getConfiguration() {
      return {
        get(name, fallback) {
          if (name === "storeRoot" || name === "cliPath") {
            return "";
          }
          return fallback;
        },
        update() {
          return Promise.resolve();
        }
      };
    },
    onDidChangeWorkspaceFolders() {
      return { dispose() {} };
    },
    onDidChangeConfiguration() {
      return { dispose() {} };
    },
    openTextDocument(uri) {
      return Promise.resolve({ uri });
    }
  }
};

const childProcessMock = {
  spawn(_command, args) {
    const emitter = new events.EventEmitter();
    emitter.stdout = new events.EventEmitter();
    emitter.stderr = new events.EventEmitter();
    if (args[0] === "config") {
      cliInvocations.push([...args]);
      setImmediate(() => {
        if (args[1] === "path") {
          emitter.stdout.emit("data", Buffer.from(`${configPath}\n`, "utf8"));
        } else if (args[1] === "init") {
          fs.mkdirSync(path.dirname(configPath), { recursive: true });
          fs.writeFileSync(configPath, "version: 1\n");
        }
        emitter.emit("close", 0);
      });
      return emitter;
    }
    const storeRoot = args[2];
    let input = "";
    emitter.stdin = {
      end(value) {
        input += value;
        setImmediate(() => {
          const payload = JSON.parse(input.trim());
          let response = null;
          if (payload.query === "session_overview") {
            const rawText = storeRoot === codexFingerprintStore ? "pwd from v2" : "pwd";
            response = JSON.stringify({
              query: "session_overview",
              session_id: payload.session_id,
              items: [
                {
                  sequence_no: 3,
                  event_index: 3,
                  observed_at_ms: 300,
                  raw_text: rawText,
                  decision: "allow",
                  finding_count: 0,
                  evidence_count: 0,
                  has_derived_invocations: false,
                  has_nested_payloads: false,
                  has_execution_payload_sink: false,
                  has_startup_config_load: false,
                  has_interactive_escape: false
                }
              ],
              has_more: false
            });
          } else {
            const scope = payload.scope || "all";
            const sessions = (fixtures.get(storeRoot) || {})[scope] || [];
            response = JSON.stringify({
              query: "session_list",
              sessions,
              has_more: false
            });
          }
          emitter.stdout.emit("data", Buffer.from(`${response}\n`, "utf8"));
          emitter.emit("close", 0);
        });
      }
    };
    return emitter;
  }
};

const originalLoad = Module._load;
Module._load = function patched(request, parent, isMain) {
  if (request === "vscode") {
    return vscodeMock;
  }
  if (request === "child_process") {
    return childProcessMock;
  }
  return originalLoad(request, parent, isMain);
};

async function main() {
  const extension = require("./extension.js");
  extension.activate({ extensionPath: __dirname, subscriptions: [] });

  const expectedViewIds = [
    "caushell.currentRunningSessions",
    "caushell.otherRunningSessions",
    "caushell.currentHistorySessions",
    "caushell.otherHistorySessions"
  ];
  for (const viewId of expectedViewIds) {
    assert(providers.has(viewId), `${viewId} tree provider should be registered`);
  }
  assert(!providers.has("caushell.sessions"), "legacy single session tree should not be registered");
  assert(!commands.has("caushell.openDashboard"));
  assert(!commands.has("caushell.switchSessionView"));
  assert(!commands.has("caushell.switchWorkspaceScope"));
  assert(commands.has("caushell.openConfig"));
  assert(commands.has("caushell.setFailureAction"));

  await commands.get("caushell.openConfig")();
  assert(fs.existsSync(configPath), "open config should initialize a missing config file");
  assert.strictEqual(lastShownDocument.uri.fsPath, configPath);
  fs.writeFileSync(configPath, "version: [\n");
  lastShownDocument = null;
  await commands.get("caushell.openConfig")();
  assert.strictEqual(
    lastShownDocument.uri.fsPath,
    configPath,
    "invalid YAML must remain openable for repair"
  );
  assert.strictEqual(fs.readFileSync(configPath, "utf8"), "version: [\n");
  await commands.get("caushell.setFailureAction")();
  assert(
    cliInvocations.some(
      (args) => args.join(" ") === "config set failure_action allow"
    ),
    "failure action picker should update the shared config"
  );

  assert(!providers.has("caushell.runtimeHealth"));

  const currentRunningProvider = providers.get("caushell.currentRunningSessions");
  const currentRunningItems = await currentRunningProvider.getChildren();
  assert(!currentRunningItems.some((item) => item.label === "Current Workspace"));
  assert(!currentRunningItems.some((item) => item.label === "Codex"));
  assert(!currentRunningItems.some((item) => item.label === "Claude Code"));
  assert(!currentRunningItems.some((item) => item.label === "Caushell Runtime"));
  assert(currentRunningItems.some((item) => item.label === "Codex (1)"));
  const runningCodexGroup = currentRunningItems.find((item) => item.label === "Codex (1)");
  const runningCodexSessions = await currentRunningProvider.getChildren(runningCodexGroup);
  const runningCodexSession = runningCodexSessions.find(
    (item) => item.label === "Use Bash to run pwd and reply with the directory only."
  );
  assert(runningCodexSession, "active-session record should drive the running Codex session");

  const otherRunningItems = await providers.get("caushell.otherRunningSessions").getChildren();
  assert(otherRunningItems.some((item) => String(item.label).includes("No running sessions")));

  const historicalProvider = providers.get("caushell.currentHistorySessions");
  const historicalGroups = await historicalProvider.getChildren();
  assert(!historicalGroups.some((item) => item.label === "Codex (1)"));
  assert(historicalGroups.some((item) => item.label === "Claude Code (1)"));

  const codexSession = runningCodexSession;
  assert.strictEqual(codexSession.collapsibleState, vscodeMock.TreeItemCollapsibleState.None);
  assert(String(codexSession.description).includes("ALLOW"));
  assert(String(codexSession.description).includes("5 checks"));
  assert.strictEqual(codexSession.session.storeRoot, codexFingerprintStore);
  assert(String(codexSession.tooltip).includes("Title: Use Bash to run pwd and reply with the directory only."));
  assert(String(codexSession.tooltip).includes("Session: codex-current"));

  const otherHistoryChildren = await providers.get("caushell.otherHistorySessions").getChildren();
  assert.strictEqual(otherHistoryChildren.length, 1);
  assert.strictEqual(otherHistoryChildren[0].label, "other");
  assert.strictEqual(otherHistoryChildren[0].description, "1 session");
  assert.strictEqual(
    otherHistoryChildren[0].collapsibleState,
    vscodeMock.TreeItemCollapsibleState.Collapsed
  );
  const otherHistoryRuntimeGroups = await providers
    .get("caushell.otherHistorySessions")
    .getChildren(otherHistoryChildren[0]);
  assert.strictEqual(otherHistoryRuntimeGroups.length, 1);
  assert.strictEqual(otherHistoryRuntimeGroups[0].label, "Codex (1)");
  assert.strictEqual(
    otherHistoryRuntimeGroups[0].collapsibleState,
    vscodeMock.TreeItemCollapsibleState.Collapsed
  );
  const otherHistorySessions = await providers
    .get("caushell.otherHistorySessions")
    .getChildren(otherHistoryRuntimeGroups[0]);
  assert.strictEqual(otherHistorySessions.length, 1);
  assert(String(otherHistorySessions[0].label).startsWith("Audit the other workspace session history"));
  assert.strictEqual(otherHistorySessions[0].description, "NEED · 2 checks");

  await commands.get("caushell.openSessionTimeline")(codexSession);
  assert(lastPanel, "session timeline panel should be created");
  assert.strictEqual(lastPanel.viewType, "caushellSessionTimeline");
  assert(String(lastPanel.webview.html).includes("Caushell Session"));
  assert(String(lastPanel.webview.html).includes("CAUSHELL"));
  assert(!String(lastPanel.webview.html).includes("session-tabbar"));
  assert(!String(lastPanel.webview.html).includes("tab-title"));
  assert(String(lastPanel.webview.html).includes("Terminal Feed"));
  assert(String(lastPanel.webview.html).includes("Command Inspection"));
  assert(String(lastPanel.webview.html).includes("pane-header"));
  assert(String(lastPanel.webview.html).includes("inspection-hero"));
  assert(String(lastPanel.webview.html).includes("summary-grid"));
  assert(String(lastPanel.webview.html).includes("Shell Bindings"));
  assert(String(lastPanel.webview.html).includes("binding-groups"));
  assert(!String(lastPanel.webview.html).includes("context-grid"));
  assert(String(lastPanel.webview.html).includes("detail-tabs"));
  assert(String(lastPanel.webview.html).includes("EXECUTION"));
  assert(String(lastPanel.webview.html).includes("Execution Inventory"));
  assert(String(lastPanel.webview.html).includes("Execution Signals"));
  assert(String(lastPanel.webview.html).includes("execution-primary-command"));
  assert(String(lastPanel.webview.html).includes("execution-detail-groups"));
  assert(String(lastPanel.webview.html).includes("timeline-filter"));
  assert(String(lastPanel.webview.html).includes("Filter commands..."));
  assert(String(lastPanel.webview.html).includes("maybeRequestMoreTimeline"));
  assert(!String(lastPanel.webview.html).includes('id="load-more"'));
  assert(String(lastPanel.webview.html).includes('"raw_text":"pwd from v2"'));
  assert(!String(lastPanel.webview.html).includes('data-tab="summary"'));

  console.log("caushell-vscode smoke test passed");
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => {
    Module._load = originalLoad;
    process.kill = originalProcessKill;
    fs.readFileSync = originalReadFileSync;
  });

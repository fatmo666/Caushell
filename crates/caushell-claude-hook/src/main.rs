use std::env;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use caushell::{CliError, check_unix_socket, ping_unix_socket};
use caushell_config::{
    ConfigFileError, ConfigPathError, FailureAction, load_config_file_or_default,
    resolve_config_path,
};
use caushell_runtime_security::{
    ensure_private_directory, ensure_private_directory_tree, harden_private_tree,
    open_private_append, open_private_read_write, private_directory_is_usable,
    process_identity_matches, process_start_marker, read_private_file_optional,
    read_private_to_string_optional, remove_private_file_if_exists,
    remove_private_unix_socket_if_exists, wait_for_process_start_marker, write_private_file,
    write_private_file_atomic,
};
use caushell_types::{
    CheckResponse, Decision, RuntimeCheckRequest, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_TERMINATE_TIMEOUT: Duration = Duration::from_millis(500);
const ACTIVE_SESSION_STALE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);
const DEFAULT_CLAUDE_STORE_SUBDIR: &str = "claude/sessions";
const DEFAULT_STORE_LAYOUT_VERSION: &str = "v2";

#[derive(Debug)]
enum HookError {
    Io(io::Error),
    Json(serde_json::Error),
    Cli(CliError),
    UnsupportedEvent(String),
    UnsupportedTool(String),
    MissingCommandField,
    RuntimeMissing(PathBuf),
    ConfigPath(ConfigPathError),
    ConfigFile(ConfigFileError),
    DaemonUnavailable,
    BadArgs(String),
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "caushell-claude-hook I/O failure: {error}"),
            Self::Json(error) => write!(f, "caushell-claude-hook JSON failure: {error}"),
            Self::Cli(error) => write!(f, "caushell runtime transport failure: {error}"),
            Self::UnsupportedEvent(event) => write!(f, "unsupported hook event {event}"),
            Self::UnsupportedTool(tool) => write!(f, "unsupported Claude tool {tool}"),
            Self::MissingCommandField => write!(f, "Claude Bash tool payload is missing command"),
            Self::RuntimeMissing(path) => {
                write!(f, "caushell runtime is not executable: {}", path.display())
            }
            Self::ConfigPath(error) => write!(f, "failed to resolve Caushell config: {error}"),
            Self::ConfigFile(error) => write!(f, "failed to load Caushell config: {error}"),
            Self::DaemonUnavailable => write!(f, "caushell runtime daemon is unavailable"),
            Self::BadArgs(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for HookError {}

impl From<io::Error> for HookError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for HookError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<CliError> for HookError {
    fn from(error: CliError) -> Self {
        Self::Cli(error)
    }
}

impl From<ConfigPathError> for HookError {
    fn from(error: ConfigPathError) -> Self {
        Self::ConfigPath(error)
    }
}

impl From<ConfigFileError> for HookError {
    fn from(error: ConfigFileError) -> Self {
        Self::ConfigFile(error)
    }
}

#[derive(Debug, Deserialize)]
struct ClaudeHookRequest {
    session_id: String,
    cwd: String,
    hook_event_name: String,
    tool_name: String,
    tool_input: ClaudeToolInput,
}

#[derive(Debug, Deserialize)]
struct ClaudeToolInput {
    command: Option<String>,
}

fn extract_session_id(stdin_text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(stdin_text).ok()?;
    value
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn session_id_from_payload(stdin_text: &str) -> String {
    extract_session_id(stdin_text).unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, Serialize)]
struct ClaudeHookResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: PreToolUseHookOutput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreToolUseHookOutput {
    hook_event_name: String,
    permission_decision: String,
    permission_decision_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveSessionRecord {
    record_type: String,
    runtime_name: String,
    session_id: String,
    workspace_root: String,
    workspace_hash: String,
    daemon_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_instance_id: Option<String>,
    socket_path: String,
    store_root: String,
    runtime_fingerprint: String,
    started_at: String,
    heartbeat_at: String,
    heartbeat_at_ms: u64,
    last_event_name: String,
    plugin_version: String,
}

#[derive(Debug, Clone)]
struct HookConfig {
    runtime_path: PathBuf,
    runtime_fingerprint: String,
    config_path: PathBuf,
    failure_action: FailureAction,
    config_load_error: Option<String>,
    store_root: PathBuf,
    runtime_security_root: PathBuf,
    socket_root: PathBuf,
    workspace_root: PathBuf,
}

#[derive(Debug, Clone)]
struct RuntimePaths {
    workspace_hash: String,
    workspace_runtime_dir: PathBuf,
    socket_path: PathBuf,
    pid_path: PathBuf,
    daemon_lock_path: PathBuf,
    daemon_metadata_path: PathBuf,
    daemon_run_lock_path: PathBuf,
    plugin_log_path: PathBuf,
    daemon_log_path: PathBuf,
    active_sessions_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DaemonStatus {
    Starting,
    Ready,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonMetadata {
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_start_marker: Option<u64>,
    instance_id: String,
    status: DaemonStatus,
    started_at_ms: u64,
    socket_path: String,
    store_root: String,
    runtime_path: String,
    runtime_fingerprint: String,
    config_path: String,
    #[serde(default)]
    failure_action: FailureAction,
    workspace_hash: String,
}

struct ExclusiveFileLock {
    file: File,
}

#[derive(Debug, Clone)]
struct HookContext {
    event_name: String,
    session_id: String,
    started_at: Instant,
    config: HookConfig,
    paths: RuntimePaths,
}

impl HookContext {
    fn new(event_name: String, session_id: String) -> Result<Self, HookError> {
        let mut config = HookConfig::from_env()?;
        let paths = RuntimePaths::new(&config);
        ensure_private_directory(&config.runtime_security_root)?;
        ensure_private_directory_tree(&config.runtime_security_root, &paths.workspace_runtime_dir)?;
        harden_private_tree(&paths.workspace_runtime_dir)?;
        ensure_private_directory(&config.store_root)?;

        reconcile_failure_action(&mut config, &paths)?;

        Ok(Self {
            event_name,
            session_id,
            started_at: Instant::now(),
            config,
            paths,
        })
    }

    fn log(&self, level: &str, message: &str, fields: &[(&str, String)]) -> Result<(), HookError> {
        let mut file = open_private_append(&self.paths.plugin_log_path)?;

        write!(
            file,
            "timestamp={} level={} event={} workspace={} session_id={} latency_ms={} msg={}",
            now_utc_string(),
            level,
            self.event_name,
            self.paths.workspace_hash,
            self.session_id,
            self.started_at.elapsed().as_millis(),
            message,
        )?;

        for (key, value) in fields {
            write!(file, " {key}={}", sanitize_log_value(value))?;
        }

        writeln!(file)?;
        Ok(())
    }
}

impl HookConfig {
    fn from_env() -> Result<Self, HookError> {
        let plugin_root = env_path("CLAUDE_PLUGIN_ROOT")
            .or_else(|| current_exe_parent_n(2))
            .unwrap_or_else(|| PathBuf::from("."));
        let repo_root = env_path("CAUSHELL_REPO_ROOT")
            .unwrap_or_else(|| plugin_root.join("../..").lexical_normalize());
        let home = env_path("HOME");
        let state_root = env_path("XDG_STATE_HOME")
            .unwrap_or_else(|| {
                home.clone()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".local/state")
            })
            .join("caushell");
        let runtime_root = preferred_runtime_root();

        let runtime_path = option_path("CLAUDE_PLUGIN_OPTION_RUNTIME_PATH")
            .or_else(|| env_path("CAUSHELL_CLAUDE_RUNTIME_PATH"))
            .or_else(|| find_executable_on_path("caushell"))
            .unwrap_or_else(|| repo_root.join("target/debug/caushell"));
        let runtime_fingerprint = runtime_fingerprint(&runtime_path)?;
        let config_path = resolve_config_path()?;
        let (failure_action, config_load_error) = match load_config_file_or_default(&config_path) {
            Ok(loaded) => (loaded.effective.failure_action, None),
            Err(error) => (FailureAction::Allow, Some(error.to_string())),
        };
        let store_root = option_path("CLAUDE_PLUGIN_OPTION_STORE_ROOT")
            .or_else(|| env_path("CAUSHELL_CLAUDE_STORE_ROOT"))
            .unwrap_or_else(|| {
                state_root
                    .join(DEFAULT_CLAUDE_STORE_SUBDIR)
                    .join(DEFAULT_STORE_LAYOUT_VERSION)
                    .join(&runtime_fingerprint)
            });
        let configured_socket_root = option_path("CLAUDE_PLUGIN_OPTION_SOCKET_ROOT")
            .or_else(|| env_path("CAUSHELL_CLAUDE_SOCKET_ROOT"));
        let (runtime_security_root, socket_root) = match configured_socket_root {
            Some(socket_root) => (socket_root.clone(), socket_root),
            None => (
                runtime_root.clone(),
                runtime_root.join("claude").join(&runtime_fingerprint),
            ),
        };
        let workspace_root = env_path("CLAUDE_PROJECT_DIR")
            .or_else(|| env::current_dir().ok())
            .or_else(|| home.clone())
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(Self {
            runtime_path,
            runtime_fingerprint,
            config_path,
            failure_action,
            config_load_error,
            store_root,
            runtime_security_root,
            socket_root,
            workspace_root,
        })
    }
}

fn preferred_runtime_root() -> PathBuf {
    runtime_root_for(env_path("XDG_RUNTIME_DIR").as_deref())
}

fn runtime_root_for(xdg_runtime_dir: Option<&Path>) -> PathBuf {
    let fallback = PathBuf::from(format!("/tmp/caushell-{}", effective_uid()));
    match xdg_runtime_dir {
        Some(path) if runtime_dir_usable(path) => path.join("caushell"),
        _ => fallback,
    }
}

fn runtime_dir_usable(path: &Path) -> bool {
    private_directory_is_usable(path)
}

impl RuntimePaths {
    fn new(config: &HookConfig) -> Self {
        let workspace_hash = workspace_hash(&config.workspace_root);
        let workspace_runtime_dir = config.socket_root.join(&workspace_hash);

        Self {
            workspace_hash,
            socket_path: workspace_runtime_dir.join("caushell.sock"),
            pid_path: workspace_runtime_dir.join("caushell.pid"),
            daemon_lock_path: workspace_runtime_dir.join("daemon.lock"),
            daemon_metadata_path: workspace_runtime_dir.join("daemon.json"),
            daemon_run_lock_path: workspace_runtime_dir.join("daemon.run.lock"),
            plugin_log_path: workspace_runtime_dir.join("plugin.log"),
            daemon_log_path: workspace_runtime_dir.join("daemon.log"),
            active_sessions_dir: workspace_runtime_dir.join("active-sessions"),
            workspace_runtime_dir,
        }
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), HookError> {
    let mut args = env::args().skip(1);
    let Some(event_name) = args.next() else {
        return Err(HookError::BadArgs(
            "usage: caushell-claude-hook <SessionStart|PreToolUse|PostToolUse|PostToolUseFailure|SessionEnd|Status>".to_string(),
        ));
    };

    match event_name.as_str() {
        "SessionStart" => {
            let mut stdin_text = String::new();
            io::stdin().read_to_string(&mut stdin_text)?;
            if let Ok(context) = HookContext::new(event_name, session_id_from_payload(&stdin_text))
            {
                let _ = run_session_start(&context);
            }
            Ok(())
        }
        "PreToolUse" => {
            let mut stdin_text = String::new();
            io::stdin().read_to_string(&mut stdin_text)?;
            run_pretooluse(event_name, &stdin_text, &mut io::stdout())
        }
        "PostToolUse" => run_observational_event(
            event_name,
            "PostToolUse observed (no-op in v1)",
            "observational",
        ),
        "PostToolUseFailure" => run_observational_event(
            event_name,
            "PostToolUseFailure observed (no-op in v1)",
            "observational",
        ),
        "SessionEnd" => run_session_end(event_name),
        "Status" => run_status(),
        other => Err(HookError::UnsupportedEvent(other.to_string())),
    }
}

fn run_session_start(context: &HookContext) -> Result<(), HookError> {
    ensure_daemon(context)?;
    remove_legacy_session_start_record(context)?;
    prune_stale_active_sessions(context)?;
    let runtime_version = runtime_version(context)?;
    let compatibility_status = version_compatibility_status(&runtime_version);

    if compatibility_status != "compatible" {
        context.log(
            "error",
            "runtime version incompatible",
            &[
                ("error_code", "version_mismatch".to_string()),
                ("plugin_version", PLUGIN_VERSION.to_string()),
                ("runtime_version", runtime_version),
            ],
        )?;
        return Err(HookError::DaemonUnavailable);
    }

    write_active_session_record(context)?;

    context.log(
        "info",
        "session start ready",
        &[
            ("daemon_action", "ready".to_string()),
            ("runtime_version", runtime_version),
            ("compatibility_status", compatibility_status),
            ("socket_path", path_string(&context.paths.socket_path)),
        ],
    )?;
    Ok(())
}

fn run_pretooluse<W: Write>(
    event_name: String,
    stdin_text: &str,
    writer: &mut W,
) -> Result<(), HookError> {
    let hook_request: ClaudeHookRequest = match serde_json::from_str(stdin_text) {
        Ok(hook_request) => hook_request,
        Err(error) => {
            let reason = format!("failed to parse Claude PreToolUse hook payload: {error}");
            emit_pretooluse_protocol_error_response(
                writer,
                &event_name,
                &reason,
                failure_action_or_default(),
            )?;
            return Ok(());
        }
    };
    let context = match HookContext::new(event_name, hook_request.session_id.clone()) {
        Ok(context) => context,
        Err(error) => {
            emit_pre_context_fallback_response(
                writer,
                &hook_request.hook_event_name,
                &error.to_string(),
                failure_action_or_default(),
            )?;
            return Ok(());
        }
    };

    if let Err(error) = ensure_daemon(&context) {
        let reason = format!("caushell runtime daemon is unavailable: {error}");
        context.log(
            "error",
            "daemon unavailable during pretooluse",
            &[("error_code", "daemon_unavailable".to_string())],
        )?;
        emit_fallback_response(&context, writer, &reason)?;
        return Ok(());
    }
    write_active_session_record(&context)?;

    let runtime_request = match build_runtime_request(&hook_request, &context.config.workspace_root)
    {
        Ok(runtime_request) => runtime_request,
        Err(error) => {
            context.log(
                "error",
                "invalid pretooluse payload",
                &[
                    ("error_code", "invalid_pretooluse_payload".to_string()),
                    ("reason", error.to_string()),
                ],
            )?;
            emit_pretooluse_protocol_error_response(
                writer,
                "PreToolUse",
                &error.to_string(),
                context.config.failure_action,
            )?;
            return Ok(());
        }
    };
    let response = match check_unix_socket(&context.paths.socket_path, &runtime_request) {
        Ok(response) => response,
        Err(error) => {
            let reason = format!("caushell runtime failed while handling PreToolUse: {error}");
            context.log(
                "error",
                "runtime failed during pretooluse",
                &[
                    ("error_code", "runtime_failed".to_string()),
                    ("socket_path", path_string(&context.paths.socket_path)),
                ],
            )?;
            emit_fallback_response(&context, writer, &reason)?;
            return Ok(());
        }
    };

    let decision_class =
        emit_pretooluse_response(writer, &hook_request.hook_event_name, &response)?;
    context.log(
        "info",
        "pretooluse runtime completed",
        &[
            ("decision_class", decision_class),
            ("socket_path", path_string(&context.paths.socket_path)),
        ],
    )?;
    Ok(())
}

fn run_observational_event(
    event_name: String,
    message: &str,
    decision_class: &str,
) -> Result<(), HookError> {
    if let Ok(context) = HookContext::new(event_name, "unknown".to_string()) {
        let _ = context.log(
            "info",
            message,
            &[("decision_class", decision_class.to_string())],
        );
    }
    Ok(())
}

fn run_session_end(event_name: String) -> Result<(), HookError> {
    let mut stdin_text = String::new();
    io::stdin().read_to_string(&mut stdin_text)?;
    let session_id = session_id_from_payload(&stdin_text);
    if let Ok(context) = HookContext::new(event_name, session_id) {
        let _ = remove_active_session_record(&context);
        let _ = context.log(
            "info",
            "session end",
            &[("decision_class", "lifecycle".to_string())],
        );
    }
    Ok(())
}

fn run_status() -> Result<(), HookError> {
    let context = HookContext::new("Status".to_string(), "unknown".to_string())?;
    let daemon_metadata = read_daemon_metadata(&context.paths.daemon_metadata_path)?;
    let (runtime_status, runtime_version, runtime_instance_id) =
        match ping_unix_socket(&context.paths.socket_path) {
            Ok(response) => (
                "up".to_string(),
                response.runtime_version,
                response
                    .instance_id
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
            Err(_) => (
                "down".to_string(),
                "unavailable".to_string(),
                "unknown".to_string(),
            ),
        };
    let daemon_pid = read_pid(&context.paths.pid_path)?
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let daemon_lock_exists = context.paths.daemon_lock_path.exists().to_string();
    let daemon_run_lock_exists = context.paths.daemon_run_lock_path.exists().to_string();
    let daemon_metadata_exists = context.paths.daemon_metadata_path.exists().to_string();
    let last_status = last_log_line(&context.paths.plugin_log_path)?;
    let last_failure = last_error_log_line(&context.paths.plugin_log_path)?;

    println!("plugin_name=caushell-claude");
    println!("plugin_version={PLUGIN_VERSION}");
    println!("runtime_status={runtime_status}");
    println!("runtime_version={runtime_version}");
    println!("runtime_instance_id={runtime_instance_id}");
    println!("runtime_path={}", path_string(&context.config.runtime_path));
    println!("runtime_fingerprint={}", context.config.runtime_fingerprint);
    println!("config_path={}", path_string(&context.config.config_path));
    println!("store_root={}", path_string(&context.config.store_root));
    println!(
        "workspace_root={}",
        path_string(&context.config.workspace_root)
    );
    println!("workspace_hash={}", context.paths.workspace_hash);
    println!("socket_path={}", path_string(&context.paths.socket_path));
    println!("pid_path={}", path_string(&context.paths.pid_path));
    println!("daemon_pid={daemon_pid}");
    println!(
        "daemon_lock_path={}",
        path_string(&context.paths.daemon_lock_path)
    );
    println!(
        "daemon_metadata_path={}",
        path_string(&context.paths.daemon_metadata_path)
    );
    println!(
        "daemon_run_lock_path={}",
        path_string(&context.paths.daemon_run_lock_path)
    );
    println!(
        "daemon_metadata_instance_id={}",
        daemon_metadata
            .as_ref()
            .map(|metadata| metadata.instance_id.as_str())
            .unwrap_or("unknown")
    );
    println!(
        "daemon_metadata_status={}",
        daemon_metadata
            .as_ref()
            .map(|metadata| format!("{:?}", metadata.status).to_lowercase())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "daemon_metadata_runtime_fingerprint={}",
        daemon_metadata
            .as_ref()
            .map(|metadata| metadata.runtime_fingerprint.as_str())
            .unwrap_or("unknown")
    );
    println!("daemon_lock_exists={daemon_lock_exists}");
    println!("daemon_metadata_exists={daemon_metadata_exists}");
    println!("daemon_run_lock_exists={daemon_run_lock_exists}");
    println!(
        "active_sessions_dir={}",
        path_string(&context.paths.active_sessions_dir)
    );
    println!(
        "plugin_log_path={}",
        path_string(&context.paths.plugin_log_path)
    );
    println!(
        "daemon_log_path={}",
        path_string(&context.paths.daemon_log_path)
    );
    println!("failure_action={}", context.config.failure_action.as_str());
    println!(
        "config_load_error={}",
        context.config.config_load_error.as_deref().unwrap_or("")
    );
    println!("last_status={last_status}");
    println!("last_failure={last_failure}");
    Ok(())
}

fn build_runtime_request(
    hook_request: &ClaudeHookRequest,
    workspace_root: &Path,
) -> Result<RuntimeCheckRequest, HookError> {
    if hook_request.hook_event_name != "PreToolUse" {
        return Err(HookError::UnsupportedEvent(
            hook_request.hook_event_name.clone(),
        ));
    }

    if hook_request.tool_name != "Bash" {
        return Err(HookError::UnsupportedTool(hook_request.tool_name.clone()));
    }

    let command = hook_request
        .tool_input
        .command
        .clone()
        .ok_or(HookError::MissingCommandField)?;

    Ok(RuntimeCheckRequest {
        session_id: SessionId::new(hook_request.session_id.clone()),
        command,
        shell_state_before: caushell_types::ShellStateSnapshot::new(hook_request.cwd.clone()),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "claude_code".to_string(),
            tool_name: Some(hook_request.tool_name.clone()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::cwd_persistent(),
        },
        home: resolve_os_home_dir().or_else(|| env_option("HOME")),
        workspace_root: Some(path_string(workspace_root)),
    })
}

fn emit_pretooluse_response<W: Write>(
    writer: &mut W,
    hook_event_name: &str,
    response: &CheckResponse,
) -> Result<String, HookError> {
    match response.decision {
        Decision::Allow => Ok("allow".to_string()),
        Decision::NeedApproval => {
            write_claude_response(
                writer,
                hook_event_name,
                "ask",
                &user_visible_reason(&joined_reasons(
                    &response.reasons,
                    "shell query policy requires explicit approval",
                )),
            )?;
            Ok("ask".to_string())
        }
        Decision::Deny => {
            write_claude_response(
                writer,
                hook_event_name,
                "deny",
                &user_visible_reason(&joined_reasons(
                    &response.reasons,
                    "shell query policy denied the command",
                )),
            )?;
            Ok("deny".to_string())
        }
    }
}

fn emit_fallback_response<W: Write>(
    context: &HookContext,
    writer: &mut W,
    reason: &str,
) -> Result<(), HookError> {
    let action = context.config.failure_action;
    context.log(
        "warn",
        "applying configured runtime failure action",
        &[
            ("fallback_action", action.as_str().to_string()),
            ("decision_class", format!("fallback_{}", action.as_str())),
            ("error_code", "runtime_error".to_string()),
            ("reason", reason.to_string()),
        ],
    )?;
    emit_pre_context_fallback_response(writer, "PreToolUse", reason, action)?;

    Ok(())
}

fn emit_pre_context_fallback_response<W: Write>(
    writer: &mut W,
    hook_event_name: &str,
    reason: &str,
    action: FailureAction,
) -> Result<(), HookError> {
    match action {
        FailureAction::Allow => Ok(()),
        FailureAction::NeedApproval => {
            write_claude_response(writer, hook_event_name, "ask", &user_visible_reason(reason))
        }
        FailureAction::Deny => write_claude_response(
            writer,
            hook_event_name,
            "deny",
            &user_visible_reason(reason),
        ),
    }
}

fn emit_pretooluse_protocol_error_response<W: Write>(
    writer: &mut W,
    hook_event_name: &str,
    reason: &str,
    action: FailureAction,
) -> Result<(), HookError> {
    emit_pre_context_fallback_response(writer, hook_event_name, reason, action)
}

fn write_claude_response<W: Write>(
    writer: &mut W,
    hook_event_name: &str,
    decision: &str,
    reason: &str,
) -> Result<(), HookError> {
    let response = ClaudeHookResponse {
        hook_specific_output: PreToolUseHookOutput {
            hook_event_name: hook_event_name.to_string(),
            permission_decision: decision.to_string(),
            permission_decision_reason: reason.to_string(),
        },
    };

    serde_json::to_writer(&mut *writer, &response)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn user_visible_reason(reason: &str) -> String {
    const PREFIX: &str = "[Caushell] ";
    if reason.starts_with(PREFIX) {
        reason.to_string()
    } else {
        format!("{PREFIX}{reason}")
    }
}

fn ensure_daemon(context: &HookContext) -> Result<(), HookError> {
    if let Some(metadata) = current_daemon_metadata(context)? {
        if daemon_metadata_matches_config(context, &metadata) {
            if let Some(response) = healthy_runtime_response(context, Some(&metadata.instance_id)) {
                context.log(
                    "info",
                    "reusing healthy daemon",
                    &[
                        ("daemon_action", "reuse".to_string()),
                        ("socket_path", path_string(&context.paths.socket_path)),
                        (
                            "daemon_instance_id",
                            response
                                .instance_id
                                .unwrap_or_else(|| "unknown".to_string()),
                        ),
                    ],
                )?;
                return Ok(());
            }
        }
    }

    let _lock = acquire_exclusive_lock(&context.paths.daemon_lock_path)?;
    if let Some(metadata) = current_daemon_metadata(context)? {
        if daemon_metadata_matches_config(context, &metadata) {
            if let Some(response) = healthy_runtime_response(context, Some(&metadata.instance_id)) {
                context.log(
                    "info",
                    "reusing healthy daemon after lifecycle lock",
                    &[
                        ("daemon_action", "reuse_after_lock".to_string()),
                        ("socket_path", path_string(&context.paths.socket_path)),
                        (
                            "daemon_instance_id",
                            response
                                .instance_id
                                .unwrap_or_else(|| "unknown".to_string()),
                        ),
                    ],
                )?;
                return Ok(());
            }
        }

        if daemon_process_matches(&metadata) {
            if daemon_metadata_matches_config(context, &metadata) {
                if metadata.status == DaemonStatus::Starting
                    && daemon_starting_within_timeout(&metadata)?
                {
                    if wait_for_daemon_ready(
                        context,
                        Some(&metadata.instance_id),
                        daemon_deadline_ms(&metadata),
                    )?
                    .is_some()
                    {
                        return Ok(());
                    }
                }

                if wait_for_daemon_ready(
                    context,
                    Some(&metadata.instance_id),
                    current_time_ms()?.saturating_add(250),
                )?
                .is_some()
                {
                    return Ok(());
                }
            }

            terminate_daemon_process(context, &metadata)?;
        }

        clear_daemon_metadata(context)?;
    }

    remove_stale_socket_path(&context.paths.socket_path)?;
    let metadata = start_daemon(context)?;
    let deadline_ms = daemon_deadline_ms(&metadata);
    if wait_for_daemon_ready(context, Some(&metadata.instance_id), deadline_ms)?.is_some() {
        return Ok(());
    }

    let _ = terminate_daemon_process(context, &metadata);
    clear_daemon_metadata(context)?;
    remove_stale_socket_path(&context.paths.socket_path)?;
    Err(HookError::DaemonUnavailable)
}

fn current_daemon_metadata(context: &HookContext) -> Result<Option<DaemonMetadata>, HookError> {
    if let Some(metadata) = read_daemon_metadata(&context.paths.daemon_metadata_path)? {
        return Ok(Some(metadata));
    }

    let Some(pid) = read_pid(&context.paths.pid_path)? else {
        return Ok(None);
    };

    Ok(Some(DaemonMetadata {
        pid,
        process_start_marker: process_start_marker(pid),
        instance_id: format!("legacy-pid-{pid}"),
        status: DaemonStatus::Ready,
        started_at_ms: 0,
        socket_path: path_string(&context.paths.socket_path),
        store_root: String::new(),
        runtime_path: String::new(),
        runtime_fingerprint: String::new(),
        config_path: String::new(),
        failure_action: FailureAction::Allow,
        workspace_hash: context.paths.workspace_hash.clone(),
    }))
}

fn healthy_runtime_response(
    context: &HookContext,
    expected_instance_id: Option<&str>,
) -> Option<caushell_types::RuntimePingResponse> {
    let response = ping_unix_socket(&context.paths.socket_path).ok()?;
    if let Some(expected_instance_id) = expected_instance_id {
        if response.instance_id.as_deref() != Some(expected_instance_id) {
            return None;
        }
    }
    Some(response)
}

fn daemon_metadata_matches_config(context: &HookContext, metadata: &DaemonMetadata) -> bool {
    metadata.socket_path == path_string(&context.paths.socket_path)
        && metadata.store_root == path_string(&context.config.store_root)
        && metadata.runtime_path == path_string(&context.config.runtime_path)
        && metadata.runtime_fingerprint == context.config.runtime_fingerprint
        && metadata.config_path == path_string(&context.config.config_path)
        && metadata.workspace_hash == context.paths.workspace_hash
}

fn start_daemon(context: &HookContext) -> Result<DaemonMetadata, HookError> {
    if !is_executable(&context.config.runtime_path) {
        context.log(
            "error",
            "runtime not executable",
            &[
                ("error_code", "runtime_missing".to_string()),
                ("runtime_path", path_string(&context.config.runtime_path)),
            ],
        )?;
        return Err(HookError::RuntimeMissing(
            context.config.runtime_path.clone(),
        ));
    }

    remove_stale_socket_path(&context.paths.socket_path)?;

    context.log(
        "info",
        "starting daemon",
        &[
            ("daemon_action", "spawn".to_string()),
            ("runtime_path", path_string(&context.config.runtime_path)),
            (
                "runtime_fingerprint",
                context.config.runtime_fingerprint.clone(),
            ),
            ("socket_path", path_string(&context.paths.socket_path)),
            ("store_root", path_string(&context.config.store_root)),
            ("config_path", path_string(&context.config.config_path)),
        ],
    )?;

    let daemon_log = open_private_append(&context.paths.daemon_log_path)?;
    let daemon_log_err = daemon_log.try_clone()?;

    let daemon_instance_id = daemon_instance_id(context);
    let mut command = Command::new(&context.config.runtime_path);
    command
        .arg("serve-unix")
        .arg("--socket")
        .arg(&context.paths.socket_path)
        .arg("--store")
        .arg(&context.config.store_root)
        .env("CAUSHELL_DAEMON_INSTANCE_ID", &daemon_instance_id)
        .env(
            "CAUSHELL_DAEMON_RUN_LOCK_PATH",
            &context.paths.daemon_run_lock_path,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(daemon_log))
        .stderr(Stdio::from(daemon_log_err));

    command.arg("--config").arg(&context.config.config_path);

    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }

    let child = command.spawn()?;
    let metadata = DaemonMetadata {
        pid: child.id(),
        process_start_marker: wait_for_process_start_marker(child.id(), Duration::from_millis(250)),
        instance_id: daemon_instance_id.clone(),
        status: DaemonStatus::Starting,
        started_at_ms: current_time_ms()?,
        socket_path: path_string(&context.paths.socket_path),
        store_root: path_string(&context.config.store_root),
        runtime_path: path_string(&context.config.runtime_path),
        runtime_fingerprint: context.config.runtime_fingerprint.clone(),
        config_path: path_string(&context.config.config_path),
        failure_action: context.config.failure_action,
        workspace_hash: context.paths.workspace_hash.clone(),
    };
    write_private_file(&context.paths.pid_path, format!("{}\n", child.id()))?;
    write_daemon_metadata(&context.paths.daemon_metadata_path, &metadata)?;
    context.log(
        "info",
        "daemon spawned",
        &[
            ("daemon_action", "spawned".to_string()),
            ("daemon_pid", child.id().to_string()),
            ("daemon_instance_id", daemon_instance_id),
            (
                "daemon_run_lock_path",
                path_string(&context.paths.daemon_run_lock_path),
            ),
        ],
    )?;
    Ok(metadata)
}

fn reconcile_failure_action(
    config: &mut HookConfig,
    paths: &RuntimePaths,
) -> Result<(), HookError> {
    let Some(mut metadata) = read_daemon_metadata(&paths.daemon_metadata_path)? else {
        return Ok(());
    };
    if metadata.config_path != path_string(&config.config_path)
        || metadata.workspace_hash != paths.workspace_hash
    {
        return Ok(());
    }

    if config.config_load_error.is_some() {
        config.failure_action = metadata.failure_action;
    } else if metadata.failure_action != config.failure_action {
        metadata.failure_action = config.failure_action;
        write_daemon_metadata(&paths.daemon_metadata_path, &metadata)?;
    }
    Ok(())
}

fn wait_for_daemon_ready(
    context: &HookContext,
    expected_instance_id: Option<&str>,
    deadline_ms: u64,
) -> Result<Option<caushell_types::RuntimePingResponse>, HookError> {
    while current_time_ms()? <= deadline_ms {
        if let Some(response) = healthy_runtime_response(context, expected_instance_id) {
            let daemon_instance_id = response
                .instance_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            if let Some(instance_id) = expected_instance_id {
                if let Some(mut metadata) =
                    read_daemon_metadata(&context.paths.daemon_metadata_path)?
                {
                    if metadata.instance_id == instance_id {
                        metadata.status = DaemonStatus::Ready;
                        write_daemon_metadata(&context.paths.daemon_metadata_path, &metadata)?;
                    }
                }
            }
            context.log(
                "info",
                "daemon ready",
                &[
                    ("daemon_action", "ready".to_string()),
                    ("socket_path", path_string(&context.paths.socket_path)),
                    ("daemon_instance_id", daemon_instance_id),
                ],
            )?;
            return Ok(Some(response));
        }

        if let Some(pid) = read_pid(&context.paths.pid_path)? {
            if !process_alive(pid) {
                break;
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    context.log(
        "error",
        "daemon failed readiness check",
        &[
            ("daemon_action", "ready".to_string()),
            ("error_code", "daemon_not_ready".to_string()),
            ("socket_path", path_string(&context.paths.socket_path)),
        ],
    )?;
    Ok(None)
}

fn daemon_deadline_ms(metadata: &DaemonMetadata) -> u64 {
    metadata
        .started_at_ms
        .saturating_add(DAEMON_STARTUP_TIMEOUT.as_millis() as u64)
}

fn daemon_starting_within_timeout(metadata: &DaemonMetadata) -> Result<bool, HookError> {
    Ok(current_time_ms()?.saturating_sub(metadata.started_at_ms)
        <= DAEMON_STARTUP_TIMEOUT.as_millis() as u64)
}

fn daemon_instance_id(context: &HookContext) -> String {
    format!(
        "{}-{}-{}",
        context.paths.workspace_hash,
        std::process::id(),
        current_time_ms().unwrap_or_default()
    )
}

fn read_daemon_metadata(path: &Path) -> Result<Option<DaemonMetadata>, HookError> {
    let Some(contents) = read_private_file_optional(path)? else {
        return Ok(None);
    };
    match serde_json::from_slice(&contents) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(_) => Ok(None),
    }
}

fn write_daemon_metadata(path: &Path, metadata: &DaemonMetadata) -> Result<(), HookError> {
    let payload = serde_json::to_vec_pretty(metadata)?;
    write_private_file_atomic(path, payload)?;
    Ok(())
}

fn write_active_session_record(context: &HookContext) -> Result<(), HookError> {
    if !has_real_session_id(&context.session_id) {
        return Ok(());
    }

    remove_legacy_session_start_record(context)?;
    prune_stale_active_sessions(context)?;
    let path = active_session_record_path(context);
    if let Some(parent) = path.parent() {
        ensure_private_directory_tree(&context.config.runtime_security_root, parent)?;
    }

    let now_ms = current_time_ms()?;
    let now = now_utc_string();
    let existing_started_at = read_active_session_record(&path)?
        .map(|record| record.started_at)
        .unwrap_or_else(|| now.clone());
    let daemon_metadata = read_daemon_metadata(&context.paths.daemon_metadata_path)?;
    let record = ActiveSessionRecord {
        record_type: "active_session".to_string(),
        runtime_name: "claude_code".to_string(),
        session_id: context.session_id.clone(),
        workspace_root: path_string(&context.config.workspace_root),
        workspace_hash: context.paths.workspace_hash.clone(),
        daemon_pid: read_pid(&context.paths.pid_path)?,
        daemon_instance_id: daemon_metadata.map(|metadata| metadata.instance_id),
        socket_path: path_string(&context.paths.socket_path),
        store_root: path_string(&context.config.store_root),
        runtime_fingerprint: context.config.runtime_fingerprint.clone(),
        started_at: existing_started_at,
        heartbeat_at: now,
        heartbeat_at_ms: now_ms,
        last_event_name: context.event_name.clone(),
        plugin_version: PLUGIN_VERSION.to_string(),
    };
    let payload = serde_json::to_vec_pretty(&record)?;
    write_private_file(&path, [payload, b"\n".to_vec()].concat())?;
    Ok(())
}

fn remove_active_session_record(context: &HookContext) -> Result<(), HookError> {
    if !has_real_session_id(&context.session_id) {
        prune_stale_active_sessions(context)?;
        return Ok(());
    }

    let path = active_session_record_path(context);
    remove_if_exists(&path)?;
    if let Some(parent) = path.parent() {
        remove_dir_if_empty(parent)?;
    }
    prune_stale_active_sessions(context)?;
    Ok(())
}

fn remove_legacy_session_start_record(context: &HookContext) -> Result<(), HookError> {
    remove_if_exists(
        &context
            .paths
            .workspace_runtime_dir
            .join("session-start.json"),
    )
}

fn prune_stale_active_sessions(context: &HookContext) -> Result<(), HookError> {
    let now_ms = current_time_ms()?;
    let stale_after_ms = ACTIVE_SESSION_STALE_TIMEOUT.as_millis() as u64;
    let Ok(entries) = fs::read_dir(&context.paths.active_sessions_dir) else {
        return Ok(());
    };

    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let record_path = dir.join("active-session.json");
        let stale = match read_active_session_record(&record_path)? {
            Some(record) => now_ms.saturating_sub(record.heartbeat_at_ms) > stale_after_ms,
            None => true,
        };
        if stale {
            remove_if_exists(&record_path)?;
            remove_dir_if_empty(&dir)?;
        }
    }
    Ok(())
}

fn read_active_session_record(path: &Path) -> Result<Option<ActiveSessionRecord>, HookError> {
    let Some(contents) = read_private_file_optional(path)? else {
        return Ok(None);
    };
    match serde_json::from_slice(&contents) {
        Ok(record) => Ok(Some(record)),
        Err(_) => Ok(None),
    }
}

fn active_session_record_path(context: &HookContext) -> PathBuf {
    context
        .paths
        .active_sessions_dir
        .join(session_id_hash(&context.session_id))
        .join("active-session.json")
}

fn session_id_hash(session_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn has_real_session_id(session_id: &str) -> bool {
    let trimmed = session_id.trim();
    !trimmed.is_empty() && trimmed != "unknown"
}

fn remove_dir_if_empty(path: &Path) -> Result<(), HookError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => Err(HookError::Io(error)),
    }
}

fn clear_daemon_metadata(context: &HookContext) -> Result<(), HookError> {
    let metadata_path = context.paths.daemon_metadata_path.clone();
    let pid_path = context.paths.pid_path.clone();
    let had_metadata = metadata_path.exists();
    let had_pid = pid_path.exists();
    remove_if_exists(&metadata_path)?;
    remove_if_exists(&pid_path)?;

    if had_metadata || had_pid {
        context.log(
            "info",
            "cleared daemon metadata",
            &[
                ("daemon_action", "clear_metadata".to_string()),
                ("daemon_metadata_path", path_string(&metadata_path)),
                ("pid_path", path_string(&pid_path)),
            ],
        )?;
    }

    Ok(())
}

fn daemon_process_matches(metadata: &DaemonMetadata) -> bool {
    let Some(expected_start_marker) = metadata.process_start_marker else {
        return false;
    };
    process_identity_matches(
        metadata.pid,
        expected_start_marker,
        Path::new(&metadata.runtime_path),
    )
}

fn terminate_daemon_process(
    context: &HookContext,
    metadata: &DaemonMetadata,
) -> Result<(), HookError> {
    if !daemon_process_matches(metadata) {
        return Ok(());
    }

    context.log(
        "warn",
        "terminating stale daemon",
        &[
            ("daemon_action", "terminate".to_string()),
            ("daemon_pid", metadata.pid.to_string()),
            ("daemon_instance_id", metadata.instance_id.clone()),
        ],
    )?;

    send_signal(metadata.pid, libc::SIGTERM)?;
    if wait_for_process_exit(metadata.pid, DAEMON_TERMINATE_TIMEOUT) {
        return Ok(());
    }

    send_signal(metadata.pid, libc::SIGKILL)?;
    if wait_for_process_exit(metadata.pid, DAEMON_TERMINATE_TIMEOUT) {
        return Ok(());
    }

    Err(HookError::DaemonUnavailable)
}

fn acquire_exclusive_lock(path: &Path) -> Result<ExclusiveFileLock, HookError> {
    let file = open_private_read_write(path)?;
    flock_exclusive(&file, false)?;
    Ok(ExclusiveFileLock { file })
}

fn runtime_version(context: &HookContext) -> Result<String, HookError> {
    Ok(ping_unix_socket(&context.paths.socket_path)?.runtime_version)
}

fn remove_stale_socket_path(path: &Path) -> Result<(), HookError> {
    remove_private_unix_socket_if_exists(path).map_err(HookError::Io)
}

fn joined_reasons(reasons: &[String], fallback: &str) -> String {
    if reasons.is_empty() {
        fallback.to_string()
    } else {
        reasons.join("; ")
    }
}

fn version_compatibility_status(runtime_version: &str) -> String {
    let plugin_mm = major_minor(PLUGIN_VERSION);
    let runtime_mm = major_minor(runtime_version);
    if plugin_mm == runtime_mm {
        "compatible".to_string()
    } else {
        "incompatible".to_string()
    }
}

fn major_minor(version: &str) -> String {
    version.split('.').take(2).collect::<Vec<_>>().join(".")
}

fn workspace_hash(workspace_root: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path_string(workspace_root).as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now_utc_string() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let d = doy - (153 * mp + 2).div_euclid(5) + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

fn sanitize_log_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_whitespace() { '_' } else { ch })
        .collect()
}

fn current_time_ms() -> Result<u64, HookError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| HookError::Io(io::Error::other(error)))?
        .as_millis() as u64)
}

fn runtime_fingerprint(path: &Path) -> Result<String, HookError> {
    let metadata = fs::metadata(path).map_err(|_| HookError::RuntimeMissing(path.to_path_buf()))?;
    if !metadata.is_file() {
        return Err(HookError::RuntimeMissing(path.to_path_buf()));
    }

    let canonical_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(path_string(&canonical_path).as_bytes());
    hasher.update(metadata.len().to_le_bytes());

    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|timestamp| timestamp.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    hasher.update(modified_nanos.to_le_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        hasher.update(metadata.dev().to_le_bytes());
        hasher.update(metadata.ino().to_le_bytes());
        hasher.update(metadata.mode().to_le_bytes());
        hasher.update(metadata.ctime().to_le_bytes());
        hasher.update(metadata.ctime_nsec().to_le_bytes());
    }

    let digest = hasher.finalize();
    Ok(digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn env_option(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn failure_action_or_default() -> FailureAction {
    resolve_config_path()
        .ok()
        .and_then(|path| load_config_file_or_default(path).ok())
        .map(|loaded| loaded.effective.failure_action)
        .unwrap_or_default()
}

fn env_path(name: &str) -> Option<PathBuf> {
    env_option(name).map(PathBuf::from)
}

fn option_path(name: &str) -> Option<PathBuf> {
    env_path(name)
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    for dir in env::split_paths(&paths) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn read_pid(path: &Path) -> Result<Option<u32>, HookError> {
    Ok(read_private_to_string_optional(path)?.and_then(|text| text.trim().parse::<u32>().ok()))
}

fn last_log_line(path: &Path) -> Result<String, HookError> {
    Ok(read_private_to_string_optional(path)?
        .and_then(|text| text.lines().last().map(str::to_string))
        .unwrap_or_default())
}

fn last_error_log_line(path: &Path) -> Result<String, HookError> {
    Ok(read_private_to_string_optional(path)?
        .map(|text| {
            text.lines()
                .rev()
                .find(|line| line.contains(" level=error "))
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default())
}

fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if result == 0 {
            return true;
        }
        matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM))
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn send_signal(pid: u32, signal: i32) -> Result<(), HookError> {
    let result = unsafe { libc::kill(pid as i32, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ESRCH)) {
        return Ok(());
    }
    Err(HookError::Io(error))
}

fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    !process_alive(pid)
}

fn remove_if_exists(path: &Path) -> Result<(), HookError> {
    remove_private_file_if_exists(path).map_err(HookError::Io)
}

#[cfg(unix)]
fn flock_exclusive(file: &File, nonblocking: bool) -> Result<(), HookError> {
    let mut operation = libc::LOCK_EX;
    if nonblocking {
        operation |= libc::LOCK_NB;
    }
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result == 0 {
        return Ok(());
    }
    Err(HookError::Io(io::Error::last_os_error()))
}

#[cfg(not(unix))]
fn flock_exclusive(_file: &File, _nonblocking: bool) -> Result<(), HookError> {
    Ok(())
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }

    #[cfg(not(unix))]
    {
        0
    }
}

fn current_exe_parent_n(n: usize) -> Option<PathBuf> {
    let mut path = env::current_exe().ok()?;
    for _ in 0..n {
        path = path.parent()?.to_path_buf();
    }
    Some(path)
}

trait LexicalNormalize {
    fn lexical_normalize(self) -> PathBuf;
}

impl LexicalNormalize for PathBuf {
    fn lexical_normalize(self) -> PathBuf {
        let mut result = PathBuf::new();
        for component in self.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    result.pop();
                }
                other => result.push(other.as_os_str()),
            }
        }
        result
    }
}

#[cfg(unix)]
fn resolve_os_home_dir() -> Option<String> {
    let uid = unsafe { libc::geteuid() };
    let suggested_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let buf_len = if suggested_len > 0 {
        suggested_len as usize
    } else {
        16 * 1024
    };

    let mut passwd = MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0_u8; buf_len];
    let mut result = ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            passwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };

    if status != 0 || result.is_null() {
        return None;
    }

    let passwd = unsafe { passwd.assume_init() };
    if passwd.pw_dir.is_null() {
        return None;
    }

    let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
    home.to_str().ok().map(str::to_owned)
}

#[cfg(not(unix))]
fn resolve_os_home_dir() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::{
        ClaudeHookRequest, ClaudeToolInput, DaemonMetadata, DaemonStatus, build_runtime_request,
        civil_from_days, daemon_process_matches, emit_pre_context_fallback_response,
        emit_pretooluse_protocol_error_response, major_minor, runtime_root_for,
        session_id_from_payload, user_visible_reason, version_compatibility_status, workspace_hash,
    };
    use caushell_config::FailureAction;
    use std::path::Path;

    #[test]
    fn utc_date_conversion_handles_unix_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn compatibility_uses_major_minor() {
        assert_eq!(version_compatibility_status("0.0.9"), "compatible");
        assert_eq!(version_compatibility_status("0.1.0"), "incompatible");
    }

    #[test]
    fn major_minor_uses_first_two_segments() {
        assert_eq!(major_minor("1.2.3"), "1.2");
    }

    #[test]
    fn workspace_hash_matches_existing_shell_shape() {
        assert_eq!(workspace_hash(Path::new("/lab/workspace")).len(), 16);
    }

    #[test]
    fn user_visible_reason_adds_caushell_prefix_once() {
        assert_eq!(
            user_visible_reason("manual review required"),
            "[Caushell] manual review required"
        );
        assert_eq!(
            user_visible_reason("[Caushell] manual review required"),
            "[Caushell] manual review required"
        );
    }

    #[test]
    fn session_id_from_payload_uses_real_session_id() {
        assert_eq!(
            session_id_from_payload(r#"{"session_id":"sess-123"}"#),
            "sess-123"
        );
        assert_eq!(session_id_from_payload("{}"), "unknown");
        assert_eq!(session_id_from_payload(r#"{"session_id":""}"#), "unknown");
    }

    #[test]
    fn runtime_request_uses_resolved_hook_workspace_root() {
        let hook_request = ClaudeHookRequest {
            session_id: "sess-workspace".to_string(),
            cwd: "/lab/workspace/subdir".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: ClaudeToolInput {
                command: Some("bash ../shared/build.sh".to_string()),
            },
        };

        let request = build_runtime_request(&hook_request, Path::new("/lab/workspace"))
            .expect("runtime request should be built from valid bash hook payload");

        assert_eq!(request.workspace_root.as_deref(), Some("/lab/workspace"));
        assert_eq!(request.shell_state_before.cwd(), "/lab/workspace/subdir");
    }

    #[test]
    fn claude_integration_uses_stable_identity_and_entrypoint() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("crate should live under <repo>/crates");

        let marketplace_path = repo_root.join(".claude-plugin/marketplace.json");
        let marketplace: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&marketplace_path).unwrap_or_else(|error| {
                panic!("failed to read {}: {error}", marketplace_path.display())
            }),
        )
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", marketplace_path.display()));
        let published_plugin = marketplace["plugins"]
            .as_array()
            .and_then(|plugins| plugins.first())
            .expect("Claude marketplace should publish one integration");
        assert_eq!(published_plugin["name"], "caushell-claude");
        assert_eq!(published_plugin["source"], "./integrations/claude-code");

        let plugin_manifest_path =
            repo_root.join("integrations/claude-code/.claude-plugin/plugin.json");
        let plugin_manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&plugin_manifest_path).unwrap_or_else(|error| {
                panic!("failed to read {}: {error}", plugin_manifest_path.display())
            }),
        )
        .unwrap_or_else(|error| {
            panic!(
                "failed to parse {}: {error}",
                plugin_manifest_path.display()
            )
        });
        assert_eq!(plugin_manifest["name"], "caushell-claude");

        let hooks_path = repo_root.join("integrations/claude-code/hooks/hooks.json");
        let hooks_manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&hooks_path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", hooks_path.display())),
        )
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", hooks_path.display()));
        let hooks = hooks_manifest["hooks"]
            .as_object()
            .expect("Claude integration should define hooks");

        for event_name in [
            "SessionStart",
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "SessionEnd",
        ] {
            let handler = hooks[event_name]
                .as_array()
                .and_then(|groups| groups.first())
                .and_then(|group| group["hooks"].as_array())
                .and_then(|handlers| handlers.first())
                .unwrap_or_else(|| panic!("{event_name} must define a command hook"));
            assert_eq!(
                handler["command"],
                "${CLAUDE_PLUGIN_ROOT}/bin/caushell-claude-hook"
            );
            assert_eq!(handler["args"], serde_json::json!([event_name]));
        }
    }

    #[test]
    fn pre_context_fallback_allows_by_default_for_claude() {
        let mut output = Vec::new();
        emit_pre_context_fallback_response(
            &mut output,
            "PreToolUse",
            "caushell runtime is not executable: /nonexistent/caushell",
            FailureAction::Allow,
        )
        .expect("fallback response should write");

        assert!(output.is_empty());
    }

    #[test]
    fn pre_context_fallback_requests_approval_when_configured_for_claude() {
        let mut output = Vec::new();
        emit_pre_context_fallback_response(
            &mut output,
            "PreToolUse",
            "caushell runtime is not executable: /nonexistent/caushell",
            FailureAction::NeedApproval,
        )
        .expect("fallback response should write");

        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("fallback response should be JSON");
        let hook_output = value
            .get("hookSpecificOutput")
            .expect("hookSpecificOutput should be present");

        assert_eq!(hook_output["hookEventName"], "PreToolUse");
        assert_eq!(hook_output["permissionDecision"], "ask");
        assert_eq!(
            hook_output["permissionDecisionReason"],
            "[Caushell] caushell runtime is not executable: /nonexistent/caushell"
        );
    }

    #[test]
    fn pre_context_fallback_denies_when_configured_for_claude() {
        let mut output = Vec::new();
        emit_pre_context_fallback_response(
            &mut output,
            "PreToolUse",
            "caushell runtime is not executable: /nonexistent/caushell",
            FailureAction::Deny,
        )
        .expect("fallback response should write");

        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("fallback response should be JSON");
        let hook_output = value
            .get("hookSpecificOutput")
            .expect("hookSpecificOutput should be present");

        assert_eq!(hook_output["hookEventName"], "PreToolUse");
        assert_eq!(hook_output["permissionDecision"], "deny");
    }

    #[test]
    fn pretooluse_protocol_error_respects_deny_action() {
        let mut output = Vec::new();
        emit_pretooluse_protocol_error_response(
            &mut output,
            "PreToolUse",
            "Claude Bash tool payload is missing command",
            FailureAction::Deny,
        )
        .expect("protocol error response should write");

        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("protocol error response should be JSON");
        let hook_output = value
            .get("hookSpecificOutput")
            .expect("hookSpecificOutput should be present");

        assert_eq!(hook_output["hookEventName"], "PreToolUse");
        assert_eq!(hook_output["permissionDecision"], "deny");
    }

    #[test]
    fn invalid_xdg_runtime_dir_falls_back_to_tmp() {
        let runtime_root = runtime_root_for(Some(std::path::Path::new(
            "/definitely/missing/caushell-runtime-dir",
        )));
        assert_eq!(
            runtime_root,
            std::path::PathBuf::from(format!("/tmp/caushell-{}", super::effective_uid()))
        );
    }

    #[test]
    fn daemon_process_match_rejects_metadata_without_start_marker() {
        let metadata = DaemonMetadata {
            pid: std::process::id(),
            process_start_marker: None,
            instance_id: "missing-identity".to_string(),
            status: DaemonStatus::Ready,
            started_at_ms: 0,
            socket_path: "/tmp/caushell.sock".to_string(),
            store_root: "/tmp/store".to_string(),
            runtime_path: std::env::current_exe()
                .expect("test executable should be known")
                .to_string_lossy()
                .into_owned(),
            runtime_fingerprint: "fingerprint".to_string(),
            config_path: "/tmp/config.yaml".to_string(),
            failure_action: FailureAction::Allow,
            workspace_hash: "workspace".to_string(),
        };

        assert!(!daemon_process_matches(&metadata));
    }
}

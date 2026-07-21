use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use caushell::{CliError, ping_unix_socket};
use caushell_config::{
    ConfigFileError, ConfigPathError, FailureAction, load_config_file_or_default,
    resolve_config_path,
};
use caushell_runtime_security::{
    ensure_private_directory, ensure_private_directory_tree, harden_private_tree,
    open_private_append, open_private_read_write, private_directory_is_usable,
    process_identity_matches, read_private_file_optional, read_private_to_string_optional,
    remove_private_file_if_exists, remove_private_unix_socket_if_exists,
    wait_for_process_start_marker, write_private_file, write_private_file_atomic,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
const DAEMON_STARTUP_BASE_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_STARTUP_EXTENDED_TIMEOUT: Duration = Duration::from_secs(30);
const DAEMON_STARTUP_PROGRESS_STALE_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_TERMINATE_TIMEOUT: Duration = Duration::from_millis(500);
const ACTIVE_SESSION_STALE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);
const DEFAULT_CODEX_STORE_SUBDIR: &str = "codex/sessions";
const DEFAULT_STORE_LAYOUT_VERSION: &str = "v2";

#[derive(Debug)]
enum HookError {
    Io(io::Error),
    Cli(CliError),
    UnsupportedEvent(String),
    RuntimeMissing(PathBuf),
    AdapterMissing(PathBuf),
    ConfigPath(ConfigPathError),
    ConfigFile(ConfigFileError),
    DaemonUnavailable(String),
    BadArgs(String),
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "caushell-codex-hook I/O failure: {error}"),
            Self::Cli(error) => write!(f, "caushell-codex-hook transport failure: {error}"),
            Self::UnsupportedEvent(event) => write!(f, "unsupported hook event {event}"),
            Self::RuntimeMissing(path) => {
                write!(f, "caushell runtime is not executable: {}", path.display())
            }
            Self::AdapterMissing(path) => {
                write!(
                    f,
                    "caushell Codex adapter is not executable: {}",
                    path.display()
                )
            }
            Self::ConfigPath(error) => write!(f, "failed to resolve Caushell config: {error}"),
            Self::ConfigFile(error) => write!(f, "failed to load Caushell config: {error}"),
            Self::DaemonUnavailable(message) => {
                write!(f, "caushell runtime daemon is unavailable: {message}")
            }
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
    adapter_path: PathBuf,
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
    daemon_startup_progress_path: PathBuf,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    startup_progress_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonStartupProgress {
    instance_id: String,
    pid: u32,
    phase: String,
    updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
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
        let plugin_root = env_path("PLUGIN_ROOT")
            .or_else(|| env_path("CLAUDE_PLUGIN_ROOT"))
            .or_else(|| current_exe_parent_n(2))
            .unwrap_or_else(|| PathBuf::from("."));
        let repo_root =
            env_path("CAUSHELL_REPO_ROOT").unwrap_or_else(|| normalize_join(&plugin_root, "../.."));
        let home = env_path("HOME");
        let state_root = env_path("XDG_STATE_HOME")
            .unwrap_or_else(|| {
                home.clone()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".local/state")
            })
            .join("caushell");
        let runtime_root = preferred_runtime_root();

        let runtime_path = option_path("CODEX_PLUGIN_OPTION_RUNTIME_PATH")
            .or_else(|| env_path("CAUSHELL_CODEX_RUNTIME_PATH"))
            .or_else(|| current_exe_sibling("caushell"))
            .or_else(|| find_executable_on_path("caushell"))
            .unwrap_or_else(|| repo_root.join("target/debug/caushell"));
        let runtime_fingerprint = runtime_fingerprint(&runtime_path)?;
        let adapter_path = option_path("CODEX_PLUGIN_OPTION_ADAPTER_PATH")
            .or_else(|| env_path("CAUSHELL_CODEX_ADAPTER_PATH"))
            .or_else(|| current_exe_sibling("caushell-adapter-codex"))
            .or_else(|| find_executable_on_path("caushell-adapter-codex"))
            .unwrap_or_else(|| repo_root.join("target/debug/caushell-adapter-codex"));
        let config_path = resolve_config_path()?;
        let (failure_action, config_load_error) = match load_config_file_or_default(&config_path) {
            Ok(loaded) => (loaded.effective.failure_action, None),
            Err(error) => (FailureAction::Allow, Some(error.to_string())),
        };
        let store_root = option_path("CODEX_PLUGIN_OPTION_STORE_ROOT")
            .or_else(|| env_path("CAUSHELL_CODEX_STORE_ROOT"))
            .unwrap_or_else(|| {
                state_root
                    .join(DEFAULT_CODEX_STORE_SUBDIR)
                    .join(DEFAULT_STORE_LAYOUT_VERSION)
                    .join(&runtime_fingerprint)
            });
        let configured_socket_root = option_path("CODEX_PLUGIN_OPTION_SOCKET_ROOT")
            .or_else(|| env_path("CAUSHELL_CODEX_SOCKET_ROOT"));
        let (runtime_security_root, socket_root) = match configured_socket_root {
            Some(socket_root) => (socket_root.clone(), socket_root),
            None => (
                runtime_root.clone(),
                runtime_root.join("codex").join(&runtime_fingerprint),
            ),
        };
        let workspace_root = env_path("CODEX_PROJECT_DIR")
            .or_else(|| env::current_dir().ok())
            .or_else(|| home.clone())
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(Self {
            runtime_path,
            runtime_fingerprint,
            adapter_path,
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
            daemon_startup_progress_path: workspace_runtime_dir.join("daemon.startup.json"),
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
            "usage: caushell-codex-hook <SessionStart|PreToolUse|PermissionRequest|PostToolUse|SessionEnd|Status>".to_string(),
        ));
    };

    match event_name.as_str() {
        "SessionStart" => {
            let stdin_text = io::read_to_string(io::stdin()).unwrap_or_default();
            if let Ok(context) = HookContext::new(event_name, session_id_from_payload(&stdin_text))
            {
                let _ = run_session_start(&context);
            }
            Ok(())
        }
        "PreToolUse" => run_adapter_event(event_name, "pretooluse"),
        "PermissionRequest" => run_adapter_event(event_name, "permission-request"),
        "PostToolUse" => run_observational_event(
            event_name,
            "PostToolUse observed (no-op in v1)",
            "observational",
        ),
        "SessionEnd" => run_session_end(event_name),
        "Status" => run_status(),
        other => Err(HookError::UnsupportedEvent(other.to_string())),
    }
}

fn run_session_start(context: &HookContext) -> Result<(), HookError> {
    ensure_adapter_present(context)?;
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
        return Err(HookError::DaemonUnavailable(
            "runtime version incompatible".to_string(),
        ));
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

fn run_adapter_event(event_name: String, adapter_subcommand: &str) -> Result<(), HookError> {
    let stdin_text = io::read_to_string(io::stdin())?;
    let session_id = session_id_from_payload(&stdin_text);
    let context = match HookContext::new(event_name.clone(), session_id) {
        Ok(context) => context,
        Err(error) => {
            emit_pre_context_fallback_response(
                &mut io::stdout(),
                &event_name,
                &error.to_string(),
                failure_action_or_default(),
            )?;
            return Ok(());
        }
    };

    if let Err(error) = ensure_adapter_present(&context) {
        let reason = format!("caushell runtime adapter is unavailable: {error}");
        context.log(
            "error",
            "adapter unavailable during hook handling",
            &[("error_code", "adapter_unavailable".to_string())],
        )?;
        emit_fallback_response(&context, &mut io::stdout(), &event_name, &reason)?;
        return Ok(());
    }

    if let Err(error) = ensure_daemon(&context) {
        let reason = format!("caushell runtime daemon is unavailable: {error}");
        context.log(
            "error",
            "daemon unavailable during hook handling",
            &[("error_code", "daemon_unavailable".to_string())],
        )?;
        emit_fallback_response(&context, &mut io::stdout(), &event_name, &reason)?;
        return Ok(());
    }
    write_active_session_record(&context)?;

    let output = match run_adapter_process(&context, adapter_subcommand, &stdin_text) {
        Ok(output) => output,
        Err(error) => {
            let reason =
                format!("caushell-adapter-codex failed while handling {event_name}: {error}");
            context.log(
                "error",
                "adapter failed during hook handling",
                &[
                    ("error_code", "adapter_failed".to_string()),
                    ("socket_path", path_string(&context.paths.socket_path)),
                    ("adapter_error", error.to_string()),
                ],
            )?;
            emit_fallback_response(&context, &mut io::stdout(), &event_name, &reason)?;
            return Ok(());
        }
    };

    if !output.status.success() {
        let reason = format!("caushell-adapter-codex failed while handling {event_name}");
        let adapter_stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        context.log(
            "error",
            "adapter failed during hook handling",
            &[
                ("error_code", "adapter_failed".to_string()),
                ("socket_path", path_string(&context.paths.socket_path)),
                (
                    "adapter_exit_code",
                    output.status.code().unwrap_or(-1).to_string(),
                ),
                ("adapter_stderr", adapter_stderr),
            ],
        )?;
        emit_fallback_response(&context, &mut io::stdout(), &event_name, &reason)?;
        return Ok(());
    }

    let decision_class = match validate_adapter_output(&event_name, &output.stdout) {
        Ok(decision_class) => decision_class,
        Err(error) => {
            let reason = format!("caushell-adapter-codex emitted invalid hook response: {error}");
            context.log(
                "error",
                "adapter emitted invalid hook response",
                &[
                    ("error_code", "adapter_invalid_response".to_string()),
                    ("socket_path", path_string(&context.paths.socket_path)),
                    ("reason", error),
                ],
            )?;
            emit_fallback_response(&context, &mut io::stdout(), &event_name, &reason)?;
            return Ok(());
        }
    };

    if !output.stdout.is_empty() {
        io::stdout().write_all(&output.stdout)?;
    }

    context.log(
        "info",
        "hook adapter completed",
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
    let stdin_text = io::read_to_string(io::stdin()).unwrap_or_default();
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
    let (runtime_status, runtime_version, daemon_instance_id) =
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
    let recorded_daemon_instance_id = read_daemon_metadata(&context.paths.daemon_metadata_path)?
        .map(|metadata| metadata.instance_id)
        .unwrap_or_else(|| "unknown".to_string());
    let daemon_metadata_status = read_daemon_metadata(&context.paths.daemon_metadata_path)?
        .map(|metadata| format!("{:?}", metadata.status).to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());
    let daemon_pid = read_pid(&context.paths.pid_path)?
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let daemon_lock_exists = context.paths.daemon_lock_path.exists().to_string();
    let daemon_run_lock_exists = context.paths.daemon_run_lock_path.exists().to_string();
    let daemon_metadata_exists = context.paths.daemon_metadata_path.exists().to_string();
    let last_status = last_log_line(&context.paths.plugin_log_path)?;
    let last_failure = last_error_log_line(&context.paths.plugin_log_path)?;

    println!("plugin_name=caushell-codex");
    println!("plugin_version={PLUGIN_VERSION}");
    println!("runtime_status={runtime_status}");
    println!("runtime_version={runtime_version}");
    println!("runtime_instance_id={daemon_instance_id}");
    println!("runtime_path={}", path_string(&context.config.runtime_path));
    println!("runtime_fingerprint={}", context.config.runtime_fingerprint);
    println!("adapter_path={}", path_string(&context.config.adapter_path));
    println!("config_path={}", path_string(&context.config.config_path));
    println!("store_root={}", path_string(&context.config.store_root));
    println!(
        "workspace_root={}",
        path_string(&context.config.workspace_root)
    );
    println!("workspace_hash={}", context.paths.workspace_hash);
    println!("socket_path={}", path_string(&context.paths.socket_path));
    println!("pid_path={}", path_string(&context.paths.pid_path));
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
    println!("daemon_pid={daemon_pid}");
    println!("daemon_metadata_instance_id={recorded_daemon_instance_id}");
    println!("daemon_metadata_status={daemon_metadata_status}");
    println!(
        "daemon_metadata_runtime_fingerprint={}",
        read_daemon_metadata(&context.paths.daemon_metadata_path)?
            .map(|metadata| metadata.runtime_fingerprint)
            .unwrap_or_else(|| "unknown".to_string())
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

fn ensure_adapter_present(context: &HookContext) -> Result<(), HookError> {
    if is_executable(&context.config.adapter_path) {
        return Ok(());
    };

    Err(HookError::AdapterMissing(
        context.config.adapter_path.clone(),
    ))
}

fn emit_fallback_response(
    context: &HookContext,
    writer: &mut impl Write,
    event_name: &str,
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
    emit_pre_context_fallback_response(writer, event_name, reason, action)?;

    Ok(())
}

fn emit_pre_context_fallback_response(
    writer: &mut impl Write,
    event_name: &str,
    reason: &str,
    action: FailureAction,
) -> Result<(), HookError> {
    match action {
        FailureAction::Allow | FailureAction::NeedApproval => Ok(()),
        FailureAction::Deny => {
            write_deny_response(writer, event_name, &user_visible_reason(reason))
        }
    }
}

fn write_deny_response(
    writer: &mut impl Write,
    event_name: &str,
    reason: &str,
) -> Result<(), HookError> {
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });

    serde_json::to_writer(&mut *writer, &response)
        .map_err(|error| HookError::Io(io::Error::other(error)))?;
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

fn run_adapter_process(
    context: &HookContext,
    subcommand: &str,
    stdin_text: &str,
) -> Result<std::process::Output, HookError> {
    let mut command = Command::new(&context.config.adapter_path);
    command
        .arg(subcommand)
        .arg("--socket")
        .arg(&context.paths.socket_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(stdin_text.as_bytes())?;
    }
    child.wait_with_output().map_err(HookError::Io)
}

fn validate_adapter_output(event_name: &str, output: &[u8]) -> Result<String, String> {
    if output.is_empty() {
        return Ok("allow".to_string());
    }

    let value = serde_json::from_slice::<serde_json::Value>(output)
        .map_err(|error| format!("stdout is not JSON: {error}"))?;
    let hook_output = value
        .get("hookSpecificOutput")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "stdout missing object hookSpecificOutput".to_string())?;
    let hook_event_name = hook_output
        .get("hookEventName")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "stdout missing hookSpecificOutput.hookEventName".to_string())?;
    if hook_event_name != event_name {
        return Err(format!(
            "stdout hookEventName {hook_event_name} did not match {event_name}"
        ));
    }

    let decision = hook_output
        .get("permissionDecision")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "stdout missing hookSpecificOutput.permissionDecision".to_string())?;
    match decision {
        "allow" => Ok("allow".to_string()),
        "deny" => {
            if hook_output
                .get("permissionDecisionReason")
                .and_then(serde_json::Value::as_str)
                .is_none()
            {
                return Err(
                    "stdout missing hookSpecificOutput.permissionDecisionReason".to_string()
                );
            }
            Ok("deny".to_string())
        }
        other => Err(format!("stdout has unsupported permissionDecision {other}")),
    }
}

fn extract_session_id(stdin_text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(stdin_text).ok()?;
    value
        .get("session_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn session_id_from_payload(stdin_text: &str) -> String {
    extract_session_id(stdin_text).unwrap_or_else(|| "unknown".to_string())
}

fn ensure_daemon(context: &HookContext) -> Result<(), HookError> {
    if let Some(metadata) = read_daemon_metadata(&context.paths.daemon_metadata_path)? {
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
    if let Some(metadata) = read_daemon_metadata(&context.paths.daemon_metadata_path)? {
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
                        daemon_base_deadline_ms(&metadata),
                        Some(&metadata),
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
                    None,
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

    remove_stale_socket(&context.paths.socket_path)?;
    remove_if_exists(&context.paths.daemon_startup_progress_path)?;
    let metadata = start_daemon(context)?;
    let deadline_ms = daemon_base_deadline_ms(&metadata);
    if wait_for_daemon_ready(
        context,
        Some(&metadata.instance_id),
        deadline_ms,
        Some(&metadata),
    )?
    .is_some()
    {
        return Ok(());
    }

    let timeout_message = daemon_startup_timeout_message(context, &metadata)?;
    let _ = terminate_daemon_process(context, &metadata);
    clear_daemon_metadata(context)?;
    remove_if_exists(&context.paths.daemon_startup_progress_path)?;
    remove_stale_socket(&context.paths.socket_path)?;
    Err(HookError::DaemonUnavailable(timeout_message))
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

fn start_daemon(context: &HookContext) -> Result<DaemonMetadata, HookError> {
    if !is_executable(&context.config.runtime_path) {
        return Err(HookError::RuntimeMissing(
            context.config.runtime_path.clone(),
        ));
    }

    let daemon_log = open_private_append(&context.paths.daemon_log_path)?;
    let daemon_log_err = daemon_log.try_clone()?;
    let instance_id = daemon_instance_id(context);

    let mut command = Command::new(&context.config.runtime_path);
    command
        .arg("serve-unix")
        .arg("--socket")
        .arg(&context.paths.socket_path)
        .arg("--store")
        .arg(&context.config.store_root)
        .env("CAUSHELL_DAEMON_INSTANCE_ID", &instance_id)
        .env(
            "CAUSHELL_DAEMON_STARTUP_PROGRESS_PATH",
            &context.paths.daemon_startup_progress_path,
        )
        .env(
            "CAUSHELL_DAEMON_RUN_LOCK_PATH",
            &context.paths.daemon_run_lock_path,
        )
        .stdout(Stdio::from(daemon_log))
        .stderr(Stdio::from(daemon_log_err));

    append_config_arg(&mut command, &context.config.config_path);

    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let child = command.spawn()?;
    let started_at_ms = current_time_ms()?;
    let metadata = DaemonMetadata {
        pid: child.id(),
        process_start_marker: wait_for_process_start_marker(child.id(), Duration::from_millis(250)),
        instance_id: instance_id.clone(),
        status: DaemonStatus::Starting,
        started_at_ms,
        socket_path: path_string(&context.paths.socket_path),
        store_root: path_string(&context.config.store_root),
        runtime_path: path_string(&context.config.runtime_path),
        runtime_fingerprint: context.config.runtime_fingerprint.clone(),
        config_path: path_string(&context.config.config_path),
        failure_action: context.config.failure_action,
        workspace_hash: context.paths.workspace_hash.clone(),
        startup_progress_path: path_string(&context.paths.daemon_startup_progress_path),
    };
    write_pid(&context.paths.pid_path, child.id())?;
    write_daemon_metadata(&context.paths.daemon_metadata_path, &metadata)?;
    context.log(
        "info",
        "starting daemon",
        &[
            ("daemon_action", "spawn".to_string()),
            ("daemon_pid", child.id().to_string()),
            ("daemon_instance_id", instance_id),
            ("runtime_path", path_string(&context.config.runtime_path)),
            (
                "runtime_fingerprint",
                context.config.runtime_fingerprint.clone(),
            ),
            ("socket_path", path_string(&context.paths.socket_path)),
            ("store_root", path_string(&context.config.store_root)),
            ("config_path", path_string(&context.config.config_path)),
            (
                "daemon_run_lock_path",
                path_string(&context.paths.daemon_run_lock_path),
            ),
        ],
    )?;
    Ok(metadata)
}

fn append_config_arg(command: &mut Command, config_path: &Path) {
    command.arg("--config").arg(config_path);
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
    startup_metadata: Option<&DaemonMetadata>,
) -> Result<Option<caushell_types::RuntimePingResponse>, HookError> {
    let mut last_progress_key: Option<(String, Option<String>)> = None;
    loop {
        let now_ms = current_time_ms()?;
        if startup_metadata.is_none() && now_ms > deadline_ms {
            break;
        }
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
        if let Some(metadata) = startup_metadata {
            let mut effective_deadline_ms = deadline_ms;
            if let Some(progress) = matching_startup_progress(context, metadata)? {
                let progress_is_fresh = startup_progress_is_fresh(&progress, now_ms);
                let progress_key = (progress.phase.clone(), progress.detail.clone());
                if last_progress_key.as_ref() != Some(&progress_key) {
                    context.log(
                        "info",
                        "daemon startup progress",
                        &[
                            ("daemon_action", "startup_progress".to_string()),
                            ("daemon_pid", metadata.pid.to_string()),
                            ("daemon_instance_id", metadata.instance_id.clone()),
                            ("startup_phase", progress.phase),
                            ("updated_at_ms", progress.updated_at_ms.to_string()),
                        ],
                    )?;
                    last_progress_key = Some(progress_key);
                }
                if progress_is_fresh && daemon_process_matches(metadata) {
                    effective_deadline_ms =
                        effective_deadline_ms.max(daemon_extended_deadline_ms(metadata));
                }
            }
            if now_ms > effective_deadline_ms {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Ok(None)
}

fn daemon_base_deadline_ms(metadata: &DaemonMetadata) -> u64 {
    metadata
        .started_at_ms
        .saturating_add(DAEMON_STARTUP_BASE_TIMEOUT.as_millis() as u64)
}

fn daemon_extended_deadline_ms(metadata: &DaemonMetadata) -> u64 {
    metadata
        .started_at_ms
        .saturating_add(DAEMON_STARTUP_EXTENDED_TIMEOUT.as_millis() as u64)
}

fn daemon_starting_within_timeout(metadata: &DaemonMetadata) -> Result<bool, HookError> {
    Ok(current_time_ms()?.saturating_sub(metadata.started_at_ms)
        <= DAEMON_STARTUP_EXTENDED_TIMEOUT.as_millis() as u64)
}

fn matching_startup_progress(
    context: &HookContext,
    metadata: &DaemonMetadata,
) -> Result<Option<DaemonStartupProgress>, HookError> {
    let Some(contents) = read_private_file_optional(&context.paths.daemon_startup_progress_path)?
    else {
        return Ok(None);
    };
    let progress: DaemonStartupProgress = match serde_json::from_slice(&contents) {
        Ok(progress) => progress,
        Err(_) => return Ok(None),
    };
    if progress.instance_id != metadata.instance_id {
        return Ok(None);
    }
    if !startup_progress_matches_metadata(&progress, metadata) {
        return Ok(None);
    }
    Ok(Some(progress))
}

fn startup_progress_matches_metadata(
    progress: &DaemonStartupProgress,
    metadata: &DaemonMetadata,
) -> bool {
    progress.instance_id == metadata.instance_id
        && progress.pid == metadata.pid
        && progress.updated_at_ms >= metadata.started_at_ms
}

fn startup_progress_is_fresh(progress: &DaemonStartupProgress, now_ms: u64) -> bool {
    progress
        .updated_at_ms
        .saturating_add(DAEMON_STARTUP_PROGRESS_STALE_TIMEOUT.as_millis() as u64)
        >= now_ms
}

fn daemon_startup_timeout_message(
    context: &HookContext,
    metadata: &DaemonMetadata,
) -> Result<String, HookError> {
    let mut message = format!(
        "daemon instance {} did not become ready before timeout",
        metadata.instance_id
    );
    if let Some(progress) = matching_startup_progress(context, metadata)? {
        let age_ms = current_time_ms()?.saturating_sub(progress.updated_at_ms);
        message.push_str(&format!(
            "; last_startup_phase={} progress_age_ms={age_ms}",
            progress.phase
        ));
        if let Some(detail) = progress.detail.filter(|detail| !detail.is_empty()) {
            message.push_str(&format!(" detail={}", sanitize_log_value(&detail)));
        }
    } else {
        message.push_str("; no matching startup progress was observed");
    }
    let daemon_log_last_line = last_log_line(&context.paths.daemon_log_path)?;
    if !daemon_log_last_line.is_empty() {
        message.push_str(&format!(
            "; daemon_log_last_line={}",
            sanitize_log_value(&daemon_log_last_line)
        ));
    }
    Ok(message)
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
    let payload = serde_json::to_vec_pretty(metadata)
        .map_err(|error| HookError::Io(io::Error::other(error)))?;
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
        runtime_name: "codex".to_string(),
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
    let payload = serde_json::to_vec_pretty(&record)
        .map_err(|error| HookError::Io(io::Error::other(error)))?;
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
    hex_encode(&digest[..8])
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

fn daemon_metadata_matches_config(context: &HookContext, metadata: &DaemonMetadata) -> bool {
    metadata.socket_path == path_string(&context.paths.socket_path)
        && metadata.store_root == path_string(&context.config.store_root)
        && metadata.runtime_path == path_string(&context.config.runtime_path)
        && metadata.runtime_fingerprint == context.config.runtime_fingerprint
        && metadata.config_path == path_string(&context.config.config_path)
        && metadata.workspace_hash == context.paths.workspace_hash
        && (metadata.startup_progress_path.is_empty()
            || metadata.startup_progress_path
                == path_string(&context.paths.daemon_startup_progress_path))
}

fn clear_daemon_metadata(context: &HookContext) -> Result<(), HookError> {
    let metadata_path = context.paths.daemon_metadata_path.clone();
    let pid_path = context.paths.pid_path.clone();
    let startup_progress_path = context.paths.daemon_startup_progress_path.clone();
    let had_metadata = metadata_path.exists();
    let had_pid = pid_path.exists();
    let had_startup_progress = startup_progress_path.exists();
    remove_if_exists(&context.paths.daemon_metadata_path)?;
    remove_if_exists(&context.paths.pid_path)?;
    remove_if_exists(&context.paths.daemon_startup_progress_path)?;

    if had_metadata || had_pid || had_startup_progress {
        context.log(
            "info",
            "cleared daemon metadata",
            &[
                ("daemon_action", "clear_metadata".to_string()),
                ("daemon_metadata_path", path_string(&metadata_path)),
                ("pid_path", path_string(&pid_path)),
                ("startup_progress_path", path_string(&startup_progress_path)),
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

    Err(HookError::DaemonUnavailable(format!(
        "failed to terminate stale daemon pid {}",
        metadata.pid
    )))
}

fn acquire_exclusive_lock(path: &Path) -> Result<ExclusiveFileLock, HookError> {
    let file = open_private_read_write(path)?;
    flock_exclusive(&file, false)?;
    Ok(ExclusiveFileLock { file })
}

fn remove_stale_socket(path: &Path) -> Result<(), HookError> {
    remove_private_unix_socket_if_exists(path).map_err(HookError::Io)
}

fn runtime_version(context: &HookContext) -> Result<String, HookError> {
    Ok(ping_unix_socket(&context.paths.socket_path)?.runtime_version)
}

fn version_compatibility_status(runtime_version: &str) -> String {
    if runtime_version.is_empty() {
        "unknown".to_string()
    } else {
        "compatible".to_string()
    }
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
    Ok(hex_encode(&digest[..16]))
}

fn process_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as i32, 0) };
    if result == 0 {
        return true;
    }
    matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM))
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

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(PathBuf::from)
}

fn failure_action_or_default() -> FailureAction {
    resolve_config_path()
        .ok()
        .and_then(|path| load_config_file_or_default(path).ok())
        .map(|loaded| loaded.effective.failure_action)
        .unwrap_or_default()
}

fn option_path(name: &str) -> Option<PathBuf> {
    env_path(name).filter(|path| !path.as_os_str().is_empty())
}

fn current_exe_parent_n(levels: usize) -> Option<PathBuf> {
    let mut path = env::current_exe().ok()?;
    for _ in 0..levels {
        path = path.parent()?.to_path_buf();
    }
    Some(path)
}

fn current_exe_sibling(name: &str) -> Option<PathBuf> {
    let path = env::current_exe().ok()?.parent()?.join(name);
    is_executable(&path).then_some(path)
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for entry in env::split_paths(&path_var) {
        let candidate = entry.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        fs::metadata(path)
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn workspace_hash(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest[..8])
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '0',
    }
}

fn now_utc_string() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    chrono_like_rfc3339(now)
}

fn chrono_like_rfc3339(duration: std::time::Duration) -> String {
    format!("{}Z", seconds_to_iso8601(duration.as_secs()))
}

fn seconds_to_iso8601(seconds: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = seconds / SECS_PER_DAY;
    let secs_of_day = seconds % SECS_PER_DAY;
    let (year, month, day) = civil_from_days(days as i64);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
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

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn normalize_join(base: &Path, suffix: &str) -> PathBuf {
    let joined = base.join(suffix);
    fs::canonicalize(&joined).unwrap_or(joined)
}

fn sanitize_log_value(value: &str) -> String {
    value.replace('\n', "\\n").replace('\r', "\\r")
}

fn read_pid(path: &Path) -> Result<Option<u32>, HookError> {
    let Some(contents) = read_private_to_string_optional(path)? else {
        return Ok(None);
    };
    Ok(contents.trim().parse::<u32>().ok())
}

fn write_pid(path: &Path, pid: u32) -> Result<(), HookError> {
    write_private_file(path, pid.to_string()).map_err(HookError::Io)
}

fn last_log_line(path: &Path) -> Result<String, HookError> {
    let Some(contents) = read_private_to_string_optional(path)? else {
        return Ok(String::new());
    };
    Ok(contents.lines().last().unwrap_or_default().to_string())
}

fn last_error_log_line(path: &Path) -> Result<String, HookError> {
    let Some(contents) = read_private_to_string_optional(path)? else {
        return Ok(String::new());
    };
    Ok(contents
        .lines()
        .rev()
        .find(|line| line.contains(" level=error "))
        .unwrap_or_default()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        DAEMON_STARTUP_PROGRESS_STALE_TIMEOUT, DaemonMetadata, DaemonStartupProgress, DaemonStatus,
        HookConfig, RuntimePaths, append_config_arg, civil_from_days, daemon_process_matches,
        emit_pre_context_fallback_response, is_executable, read_daemon_metadata,
        reconcile_failure_action, runtime_root_for, seconds_to_iso8601, session_id_from_payload,
        startup_progress_is_fresh, startup_progress_matches_metadata, user_visible_reason,
        validate_adapter_output, write_daemon_metadata,
    };
    use caushell_config::FailureAction;
    use std::{path::Path, process::Command};

    #[test]
    fn utc_date_conversion_handles_unix_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn iso8601_renders_unix_epoch() {
        assert_eq!(seconds_to_iso8601(0), "1970-01-01T00:00:00");
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
    fn pre_context_fallback_allows_by_default_for_codex() {
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
    fn pre_context_fallback_denies_when_configured_for_codex() {
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
        assert_eq!(
            hook_output["permissionDecisionReason"],
            "[Caushell] caushell runtime is not executable: /nonexistent/caushell"
        );
    }

    #[test]
    fn adapter_output_validation_accepts_empty_allow() {
        assert_eq!(
            validate_adapter_output("PreToolUse", b"").expect("empty output should allow"),
            "allow"
        );
    }

    #[test]
    fn adapter_output_validation_rejects_non_json_stdout() {
        let error = validate_adapter_output("PreToolUse", b"not-json")
            .expect_err("non-json stdout should be rejected");

        assert!(error.contains("stdout is not JSON"));
    }

    #[test]
    fn adapter_output_validation_rejects_wrong_event() {
        let error = validate_adapter_output(
            "PreToolUse",
            br#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","permissionDecision":"deny","permissionDecisionReason":"[Caushell] denied"}}"#,
        )
        .expect_err("wrong event stdout should be rejected");

        assert!(error.contains("did not match"));
    }

    #[test]
    fn missing_config_path_is_forwarded_for_future_hot_reload() {
        let missing = std::env::temp_dir().join(format!(
            "caushell-codex-missing-config-{}",
            std::process::id()
        ));
        let mut command = Command::new("caushell");

        append_config_arg(&mut command, &missing);

        let args = command
            .get_args()
            .map(|arg| arg.to_os_string())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            ["--config".into(), missing.as_os_str().to_os_string()]
        );
    }

    #[test]
    fn failure_action_reconciliation_keeps_the_last_valid_value() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("caushell-config-reconcile-{unique}"));
        caushell_runtime_security::ensure_private_directory(&root)
            .expect("runtime root should be private");

        let mut config = HookConfig {
            runtime_path: root.join("caushell"),
            runtime_fingerprint: "runtime".to_string(),
            adapter_path: root.join("adapter"),
            config_path: root.join("config.yaml"),
            failure_action: FailureAction::Deny,
            config_load_error: None,
            store_root: root.join("store"),
            runtime_security_root: root.clone(),
            socket_root: root.clone(),
            workspace_root: root.join("workspace"),
        };
        let paths = RuntimePaths::new(&config);
        caushell_runtime_security::ensure_private_directory_tree(
            &root,
            &paths.workspace_runtime_dir,
        )
        .expect("workspace runtime directory should be private");
        let metadata = DaemonMetadata {
            pid: 1,
            process_start_marker: None,
            instance_id: "instance".to_string(),
            status: DaemonStatus::Ready,
            started_at_ms: 1,
            socket_path: paths.socket_path.to_string_lossy().into_owned(),
            store_root: config.store_root.to_string_lossy().into_owned(),
            runtime_path: config.runtime_path.to_string_lossy().into_owned(),
            runtime_fingerprint: config.runtime_fingerprint.clone(),
            config_path: config.config_path.to_string_lossy().into_owned(),
            failure_action: FailureAction::Allow,
            workspace_hash: paths.workspace_hash.clone(),
            startup_progress_path: String::new(),
        };
        write_daemon_metadata(&paths.daemon_metadata_path, &metadata)
            .expect("metadata should be written");

        reconcile_failure_action(&mut config, &paths)
            .expect("valid config action should be persisted");
        assert_eq!(
            read_daemon_metadata(&paths.daemon_metadata_path)
                .expect("metadata should be readable")
                .expect("metadata should exist")
                .failure_action,
            FailureAction::Deny
        );

        config.failure_action = FailureAction::Allow;
        config.config_load_error = Some("invalid YAML".to_string());
        reconcile_failure_action(&mut config, &paths)
            .expect("invalid edit should use the last valid action");
        assert_eq!(config.failure_action, FailureAction::Deny);

        std::fs::remove_dir_all(root).expect("temporary runtime root should be removed");
    }

    #[cfg(unix)]
    #[test]
    fn executable_check_rejects_non_executable_files() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let path =
            std::env::temp_dir().join(format!("caushell-codex-nonexec-{}", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("temp file should be created");
        writeln!(file, "#!/usr/bin/env bash").expect("temp file should be written");
        let mut permissions = std::fs::metadata(&path)
            .expect("temp file metadata should exist")
            .permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&path, permissions).expect("permissions should be updated");

        assert!(!is_executable(&path));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn plugin_hook_configs_only_use_hooks_top_level_key() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("crate should live under <repo>/crates");

        for relative_path in [
            "integrations/codex/hooks/hooks.json",
            "integrations/claude-code/hooks/hooks.json",
        ] {
            let path = repo_root.join(relative_path);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            let value: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
            let object = value
                .as_object()
                .unwrap_or_else(|| panic!("{} must be a JSON object", path.display()));

            assert_eq!(
                object.len(),
                1,
                "{} must only define the host hook schema keys",
                path.display()
            );
            assert!(
                object
                    .get("hooks")
                    .is_some_and(serde_json::Value::is_object),
                "{} must define an object-valued hooks key",
                path.display()
            );
        }
    }

    #[test]
    fn codex_plugin_hooks_use_single_stable_entrypoint() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .expect("crate should live under <repo>/crates");
        let path = repo_root.join("integrations/codex/hooks/hooks.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let value: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

        let hooks = value
            .get("hooks")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("{} must define hooks", path.display()));
        let expected_events = [
            "SessionStart",
            "PreToolUse",
            "PermissionRequest",
            "PostToolUse",
            "SessionEnd",
        ];

        for event_name in expected_events {
            let command = hooks
                .get(event_name)
                .and_then(serde_json::Value::as_array)
                .and_then(|groups| groups.first())
                .and_then(|group| group.get("hooks"))
                .and_then(serde_json::Value::as_array)
                .and_then(|handlers| handlers.first())
                .and_then(|handler| handler.get("command"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("{event_name} must define a command hook"));

            assert_eq!(
                command,
                format!("${{PLUGIN_ROOT}}/bin/caushell-codex-hook {event_name}")
            );
        }
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
    fn startup_progress_only_matches_same_daemon_instance_and_pid() {
        let metadata = DaemonMetadata {
            pid: 123,
            process_start_marker: Some(456),
            instance_id: "workspace-123-1000".to_string(),
            status: DaemonStatus::Starting,
            started_at_ms: 1_000,
            socket_path: "/tmp/caushell.sock".to_string(),
            store_root: "/tmp/store".to_string(),
            runtime_path: "/tmp/caushell".to_string(),
            runtime_fingerprint: "fingerprint".to_string(),
            config_path: "/tmp/config.yaml".to_string(),
            failure_action: FailureAction::Allow,
            workspace_hash: "workspace".to_string(),
            startup_progress_path: "/tmp/progress.json".to_string(),
        };
        let progress = DaemonStartupProgress {
            instance_id: metadata.instance_id.clone(),
            pid: metadata.pid,
            phase: "create_runtime".to_string(),
            updated_at_ms: 1_001,
            detail: None,
        };

        assert!(startup_progress_matches_metadata(&progress, &metadata));

        let mut wrong_pid = progress.clone();
        wrong_pid.pid += 1;
        assert!(!startup_progress_matches_metadata(&wrong_pid, &metadata));

        let mut wrong_instance = progress.clone();
        wrong_instance.instance_id = "other".to_string();
        assert!(!startup_progress_matches_metadata(
            &wrong_instance,
            &metadata
        ));

        let mut stale_from_previous_start = progress;
        stale_from_previous_start.updated_at_ms = metadata.started_at_ms - 1;
        assert!(!startup_progress_matches_metadata(
            &stale_from_previous_start,
            &metadata
        ));
    }

    #[test]
    fn startup_progress_freshness_has_bounded_extension_window() {
        let progress = DaemonStartupProgress {
            instance_id: "instance".to_string(),
            pid: 123,
            phase: "create_runtime".to_string(),
            updated_at_ms: 10_000,
            detail: None,
        };
        let stale_after_ms = DAEMON_STARTUP_PROGRESS_STALE_TIMEOUT.as_millis() as u64;

        assert!(startup_progress_is_fresh(
            &progress,
            progress.updated_at_ms + stale_after_ms
        ));
        assert!(!startup_progress_is_fresh(
            &progress,
            progress.updated_at_ms + stale_after_ms + 1
        ));
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
            startup_progress_path: "/tmp/progress.json".to_string(),
        };

        assert!(!daemon_process_matches(&metadata));
    }
}

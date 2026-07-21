use std::env;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::process::{self, ExitCode};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use caushell::{
    CliError, SessionRepairAction, SessionRepairKeep, create_runtime, ping_unix_socket,
    repair_session_log, serve_query_stdio, serve_stdio, serve_unix_socket,
};
use caushell_config::{
    RawAction, RawConfigFile, initialize_config_file, load_config_file_or_default,
    resolve_config_path, write_config_file,
};
use caushell_runtime_security::{require_private_directory, write_private_file};
use caushell_types::SessionId;
use serde::Serialize;

const CAUSHELL_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CliError> {
    run_with_args(env::args().skip(1))
}

fn run_with_args(mut args: impl Iterator<Item = String>) -> Result<(), CliError> {
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "config" => run_config_command(args),
        "serve-stdio" => {
            let options = parse_serve_options(args)?;
            let config_path = runtime_config_path(options.config_path)?;
            let mut runtime =
                create_runtime(Some(config_path.as_path()), options.store_root.as_deref())?;
            let stdin = io::stdin();
            let mut stdout = io::stdout();

            serve_stdio(&mut runtime, BufReader::new(stdin.lock()), &mut stdout)
        }
        "serve-unix" => {
            let options = parse_serve_options(args)?;
            let socket_path = options.socket_path.ok_or_else(|| {
                CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--socket is required for caushell serve-unix",
                ))
            })?;
            let startup_progress = DaemonStartupProgressWriter::from_env();
            if let Some(progress) = &startup_progress {
                progress.write("serve_unix_begin", Some(&socket_path.display().to_string()));
            }
            let heartbeat = startup_progress
                .as_ref()
                .map(|progress| progress.spawn_heartbeat("create_runtime"));
            let config_path = runtime_config_path(options.config_path)?;
            let runtime_result =
                create_runtime(Some(config_path.as_path()), options.store_root.as_deref());
            drop(heartbeat);
            let mut runtime = match runtime_result {
                Ok(runtime) => {
                    if let Some(progress) = &startup_progress {
                        progress.write("create_runtime_complete", None);
                    }
                    runtime
                }
                Err(error) => {
                    if let Some(progress) = &startup_progress {
                        let detail = error.to_string();
                        progress.write("create_runtime_error", Some(&detail));
                    }
                    return Err(error);
                }
            };
            if let Some(progress) = &startup_progress {
                progress.write(
                    "socket_bind_begin",
                    Some(&socket_path.display().to_string()),
                );
            }

            serve_unix_socket(&mut runtime, &socket_path)
        }
        "query-stdio" => {
            let options = parse_query_options(args)?;
            let store_root = options.store_root.ok_or_else(|| {
                CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--store is required for caushell query-stdio",
                ))
            })?;
            let stdin = io::stdin();
            let mut stdout = io::stdout();

            serve_query_stdio(&store_root, BufReader::new(stdin.lock()), &mut stdout)
        }
        "ping-unix" => {
            let options = parse_serve_options(args)?;
            let socket_path = options.socket_path.ok_or_else(|| {
                CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--socket is required for caushell ping-unix",
                ))
            })?;

            let response = ping_unix_socket(&socket_path)?;
            serde_json::to_writer_pretty(io::stdout().lock(), &response)
                .map_err(CliError::InvalidResponse)?;
            println!();
            Ok(())
        }
        "repair-session-log" => {
            let options = parse_repair_options(args)?;
            let store_root = options.store_root.ok_or_else(|| {
                CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--store is required for caushell repair-session-log",
                ))
            })?;
            let session_id = options.session_id.ok_or_else(|| {
                CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--session-id is required for caushell repair-session-log",
                ))
            })?;

            let action = match (
                options.truncate_after_event_index,
                options.dedupe_event_index,
            ) {
                (Some(event_index), None) => {
                    SessionRepairAction::TruncateAfterEventIndex(event_index)
                }
                (None, Some(event_index)) => {
                    let keep = options.keep.ok_or_else(|| {
                        CliError::Io(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--keep <first|last> is required with --dedupe-event-index",
                        ))
                    })?;
                    SessionRepairAction::DedupeEventIndex { event_index, keep }
                }
                (Some(_), Some(_)) => {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "choose exactly one repair action: --truncate-after-event-index or --dedupe-event-index",
                    )));
                }
                (None, None) => {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "one repair action is required: --truncate-after-event-index or --dedupe-event-index",
                    )));
                }
            };

            let result = repair_session_log(&store_root, &SessionId::new(session_id), action)?;
            serde_json::to_writer_pretty(io::stdout().lock(), &result)
                .map_err(CliError::InvalidResponse)?;
            println!();
            Ok(())
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "--version" | "-V" => {
            if let Some(arg) = args.next() {
                return Err(invalid_cli_input(format!(
                    "unexpected caushell version argument: {arg}"
                )));
            }
            println!("caushell {CAUSHELL_VERSION}");
            Ok(())
        }
        other => Err(invalid_cli_input(format!("unknown command: {other}"))),
    }
}

#[derive(Serialize)]
struct ConfigShowOutput<'a> {
    path: &'a std::path::Path,
    exists: bool,
    config: &'a RawConfigFile,
}

fn run_config_command(mut args: impl Iterator<Item = String>) -> Result<(), CliError> {
    let Some(command) = args.next() else {
        print_config_usage();
        return Ok(());
    };
    let path = resolve_config_path()?;

    match command.as_str() {
        "path" => {
            reject_extra_config_args(args)?;
            println!("{}", path.display());
            Ok(())
        }
        "init" => {
            reject_extra_config_args(args)?;
            initialize_config_file(&path)?;
            println!("initialized {}", path.display());
            Ok(())
        }
        "validate" => {
            reject_extra_config_args(args)?;
            let loaded = load_config_file_or_default(&path)?;
            if loaded.exists {
                println!("valid {}", path.display());
            } else {
                println!(
                    "valid built-in defaults ({} does not exist)",
                    path.display()
                );
            }
            Ok(())
        }
        "show" => {
            reject_extra_config_args(args)?;
            let loaded = load_config_file_or_default(&path)?;
            serde_json::to_writer_pretty(
                io::stdout().lock(),
                &ConfigShowOutput {
                    path: &loaded.path,
                    exists: loaded.exists,
                    config: &loaded.raw,
                },
            )
            .map_err(CliError::InvalidResponse)?;
            println!();
            Ok(())
        }
        "get" => {
            let Some(field) = args.next() else {
                return Err(invalid_cli_input("caushell config get requires a field"));
            };
            reject_extra_config_args(args)?;
            let loaded = load_config_file_or_default(&path)?;
            match field.as_str() {
                "failure_action" => {
                    println!("{}", loaded.effective.failure_action.as_str());
                    Ok(())
                }
                other => Err(invalid_cli_input(format!(
                    "unsupported config field {other:?}; supported field: failure_action"
                ))),
            }
        }
        "set" => {
            let Some(field) = args.next() else {
                return Err(invalid_cli_input(
                    "caushell config set requires a field and value",
                ));
            };
            let Some(value) = args.next() else {
                return Err(invalid_cli_input(format!(
                    "caushell config set {field} requires a value"
                )));
            };
            reject_extra_config_args(args)?;

            let mut loaded = load_config_file_or_default(&path)?;
            match field.as_str() {
                "failure_action" => loaded.raw.failure_action = parse_raw_action(&value)?,
                other => {
                    return Err(invalid_cli_input(format!(
                        "unsupported config field {other:?}; supported field: failure_action"
                    )));
                }
            }
            write_config_file(&path, &loaded.raw)?;
            println!("updated {field} in {}", path.display());
            Ok(())
        }
        "--help" | "-h" | "help" => {
            reject_extra_config_args(args)?;
            print_config_usage();
            Ok(())
        }
        other => Err(invalid_cli_input(format!(
            "unknown caushell config command: {other}"
        ))),
    }
}

fn parse_raw_action(value: &str) -> Result<RawAction, CliError> {
    match value {
        "allow" => Ok(RawAction::Allow),
        "need_approval" => Ok(RawAction::NeedApproval),
        "deny" => Ok(RawAction::Deny),
        other => Err(invalid_cli_input(format!(
            "invalid action {other:?}; expected allow, need_approval, or deny"
        ))),
    }
}

fn reject_extra_config_args(mut args: impl Iterator<Item = String>) -> Result<(), CliError> {
    if let Some(arg) = args.next() {
        return Err(invalid_cli_input(format!(
            "unexpected caushell config argument: {arg}"
        )));
    }
    Ok(())
}

fn invalid_cli_input(message: impl Into<String>) -> CliError {
    CliError::InvalidArguments(message.into())
}

struct ServeOptions {
    config_path: Option<PathBuf>,
    socket_path: Option<PathBuf>,
    store_root: Option<PathBuf>,
}

struct QueryOptions {
    store_root: Option<PathBuf>,
}

struct RepairOptions {
    store_root: Option<PathBuf>,
    session_id: Option<String>,
    truncate_after_event_index: Option<u64>,
    dedupe_event_index: Option<u64>,
    keep: Option<SessionRepairKeep>,
}

fn parse_serve_options(mut args: impl Iterator<Item = String>) -> Result<ServeOptions, CliError> {
    let mut config_path = None;
    let mut socket_path = None;
    let mut store_root = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let Some(path) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--config requires a following path",
                    )));
                };

                config_path = Some(PathBuf::from(path));
            }
            "--socket" => {
                let Some(path) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--socket requires a following path",
                    )));
                };

                socket_path = Some(PathBuf::from(path));
            }
            "--store" => {
                let Some(path) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--store requires a following path",
                    )));
                };

                store_root = Some(PathBuf::from(path));
            }
            other => {
                return Err(CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected caushell argument: {other}"),
                )));
            }
        }
    }

    Ok(ServeOptions {
        config_path,
        socket_path,
        store_root,
    })
}

fn runtime_config_path(explicit: Option<PathBuf>) -> Result<PathBuf, CliError> {
    explicit.map_or_else(|| resolve_config_path().map_err(CliError::from), Ok)
}

fn parse_query_options(mut args: impl Iterator<Item = String>) -> Result<QueryOptions, CliError> {
    let mut store_root = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--store" => {
                let Some(path) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--store requires a following path",
                    )));
                };

                store_root = Some(PathBuf::from(path));
            }
            other => {
                return Err(CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected caushell query argument: {other}"),
                )));
            }
        }
    }

    Ok(QueryOptions { store_root })
}

fn parse_repair_options(mut args: impl Iterator<Item = String>) -> Result<RepairOptions, CliError> {
    let mut store_root = None;
    let mut session_id = None;
    let mut truncate_after_event_index = None;
    let mut dedupe_event_index = None;
    let mut keep = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--store" => {
                let Some(path) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--store requires a following path",
                    )));
                };
                store_root = Some(PathBuf::from(path));
            }
            "--session-id" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--session-id requires a following value",
                    )));
                };
                session_id = Some(value);
            }
            "--truncate-after-event-index" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--truncate-after-event-index requires a following integer",
                    )));
                };
                truncate_after_event_index =
                    Some(parse_u64_arg("--truncate-after-event-index", &value)?);
            }
            "--dedupe-event-index" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--dedupe-event-index requires a following integer",
                    )));
                };
                dedupe_event_index = Some(parse_u64_arg("--dedupe-event-index", &value)?);
            }
            "--keep" => {
                let Some(value) = args.next() else {
                    return Err(CliError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--keep requires first or last",
                    )));
                };
                keep = Some(parse_keep_arg(&value)?);
            }
            other => {
                return Err(CliError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected caushell repair argument: {other}"),
                )));
            }
        }
    }

    Ok(RepairOptions {
        store_root,
        session_id,
        truncate_after_event_index,
        dedupe_event_index,
        keep,
    })
}

fn parse_u64_arg(name: &str, value: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|error| {
        CliError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} expects an unsigned integer: {error}"),
        ))
    })
}

fn parse_keep_arg(value: &str) -> Result<SessionRepairKeep, CliError> {
    match value {
        "first" => Ok(SessionRepairKeep::First),
        "last" => Ok(SessionRepairKeep::Last),
        other => Err(CliError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("--keep must be first or last, got {other}"),
        ))),
    }
}

#[derive(Clone)]
struct DaemonStartupProgressWriter {
    path: PathBuf,
    instance_id: String,
    pid: u32,
}

#[derive(Serialize)]
struct DaemonStartupProgressRecord<'a> {
    instance_id: &'a str,
    pid: u32,
    phase: &'a str,
    updated_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

struct DaemonStartupProgressHeartbeat {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DaemonStartupProgressWriter {
    fn from_env() -> Option<Self> {
        let path = env::var_os("CAUSHELL_DAEMON_STARTUP_PROGRESS_PATH").map(PathBuf::from)?;
        let instance_id = env::var("CAUSHELL_DAEMON_INSTANCE_ID")
            .ok()
            .filter(|value| !value.is_empty())?;
        Some(Self {
            path,
            instance_id,
            pid: process::id(),
        })
    }

    fn write(&self, phase: &str, detail: Option<&str>) {
        let Some(updated_at_ms) = current_time_ms() else {
            return;
        };
        let record = DaemonStartupProgressRecord {
            instance_id: &self.instance_id,
            pid: self.pid,
            phase,
            updated_at_ms,
            detail,
        };
        if let Some(parent) = self.path.parent() {
            if require_private_directory(parent).is_err() {
                return;
            }
        }
        let Ok(payload) = serde_json::to_vec(&record) else {
            return;
        };
        let _ = write_private_file(&self.path, payload);
    }

    fn spawn_heartbeat(&self, phase: &'static str) -> DaemonStartupProgressHeartbeat {
        let writer = self.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        writer.write(phase, None);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(250));
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                writer.write(phase, None);
            }
        });
        DaemonStartupProgressHeartbeat {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for DaemonStartupProgressHeartbeat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.handle.take();
    }
}

fn current_time_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
}

fn print_usage() {
    eprintln!(
        "usage:\n  caushell --version\n  caushell config <path|init|validate|show|set>\n  caushell serve-stdio [--config <path>] [--store <path>]\n  caushell serve-unix --socket <path> [--config <path>] [--store <path>]\n  caushell ping-unix --socket <path>\n  caushell query-stdio --store <path>\n  caushell repair-session-log --store <path> --session-id <id> (--truncate-after-event-index <n> | --dedupe-event-index <n> --keep <first|last>)\n\nserve commands read JSONL RuntimeTransportRequest messages and write JSON RuntimeTransportResponse messages\nping-unix probes a running Unix socket runtime and prints JSON health metadata\nquery-stdio reads JSONL QueryRequest messages and writes JSON QueryResponse messages\nrepair-session-log rewrites a corrupted session log and rebuilds its materialized snapshot/query state"
    );
}

fn print_config_usage() {
    eprintln!(
        "usage:\n  caushell config path\n  caushell config init\n  caushell config validate\n  caushell config show\n  caushell config get failure_action\n  caushell config set failure_action <allow|need_approval|deny>"
    );
}

#[cfg(test)]
mod tests {
    use super::{CAUSHELL_VERSION, run_with_args};

    #[test]
    fn unknown_top_level_command_is_an_error() {
        let error = run_with_args(["does-not-exist".to_owned()].into_iter())
            .expect_err("unknown commands must fail");

        assert!(
            error
                .to_string()
                .contains("unknown command: does-not-exist")
        );
    }

    #[test]
    fn version_rejects_extra_arguments() {
        let error = run_with_args(["--version".to_owned(), "extra".to_owned()].into_iter())
            .expect_err("version must reject extra arguments");

        assert!(
            error
                .to_string()
                .contains("unexpected caushell version argument: extra")
        );
    }

    #[test]
    fn agent_plugin_versions_match_runtime_version() {
        for (name, manifest) in [
            (
                "Codex",
                include_str!("../../../integrations/codex/.codex-plugin/plugin.json"),
            ),
            (
                "Claude Code",
                include_str!("../../../integrations/claude-code/.claude-plugin/plugin.json"),
            ),
        ] {
            let manifest: serde_json::Value =
                serde_json::from_str(manifest).expect("plugin manifest must be valid JSON");
            assert_eq!(
                manifest.get("version").and_then(serde_json::Value::as_str),
                Some(CAUSHELL_VERSION),
                "{name} plugin version must match the Caushell runtime version"
            );
        }
    }

    #[test]
    fn claude_plugin_exposes_only_live_integration_options() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../integrations/claude-code/.claude-plugin/plugin.json"
        ))
        .expect("Claude Code plugin manifest must be valid JSON");
        let options = manifest
            .get("userConfig")
            .and_then(serde_json::Value::as_object)
            .expect("Claude Code plugin must declare userConfig");
        let mut option_names = options.keys().map(String::as_str).collect::<Vec<_>>();
        option_names.sort_unstable();

        assert_eq!(
            option_names,
            ["hook_path", "runtime_path", "socket_root", "store_root"]
        );
    }
}

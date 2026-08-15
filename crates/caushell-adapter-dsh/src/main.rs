use std::env;
use std::ffi::CStr;
use std::io::{self, BufRead, Write};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::ptr;

use caushell::{CliRuntime, create_runtime};
use caushell_config::resolve_config_path;
use caushell_types::{
    CheckResponse, Decision, RuntimeCheckRequest, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};
use serde::{Deserialize, Serialize};

const RUNTIME_NAME: &str = "deepseek_harness";
const TOOL_NAME: &str = "bash";
const PROTOCOL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DshCheckRequest {
    schema_version: u32,
    request_id: String,
    session_id: String,
    cwd: String,
    command: String,
    workspace_root: String,
}

#[derive(Debug, Serialize)]
struct DshCheckResponse {
    schema_version: u32,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<DshDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum DshDecision {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug)]
struct AdapterOptions {
    config_path: Option<PathBuf>,
    store_root: PathBuf,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("caushell-adapter-dsh: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let options = parse_options(env::args().skip(1))?;
    let config_path = match options.config_path {
        Some(path) => Some(path),
        None => Some(resolve_config_path().map_err(|error| error.to_string())?),
    };
    let mut runtime = create_runtime(config_path.as_deref(), Some(&options.store_root))
        .map_err(|error| error.to_string())?;

    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for (line_no, line) in stdin.lock().lines().enumerate() {
        let line =
            line.map_err(|error| format!("failed to read request line {}: {error}", line_no + 1))?;
        if line.trim().is_empty() {
            continue;
        }

        let request: DshCheckRequest = serde_json::from_str(&line)
            .map_err(|error| format!("invalid DSH request on line {}: {error}", line_no + 1))?;
        let response = check_request(&mut runtime, request)?;
        serde_json::to_writer(&mut stdout, &response)
            .map_err(|error| format!("failed to serialize DSH response: {error}"))?;
        stdout
            .write_all(b"\n")
            .map_err(|error| format!("failed to write DSH response: {error}"))?;
        stdout
            .flush()
            .map_err(|error| format!("failed to flush DSH response: {error}"))?;
    }

    Ok(())
}

fn parse_options(mut args: impl Iterator<Item = String>) -> Result<AdapterOptions, String> {
    let mut config_path = None;
    let mut store_root = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--config requires a following path".to_string())?;
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err("--config requires an absolute path".to_string());
                }
                config_path = Some(path);
            }
            "--store" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--store requires a following path".to_string())?;
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err("--store requires an absolute path".to_string());
                }
                store_root = Some(path);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    let store_root = store_root.ok_or_else(|| "--store is required".to_string())?;
    Ok(AdapterOptions {
        config_path,
        store_root,
    })
}

fn check_request(
    runtime: &mut CliRuntime,
    request: DshCheckRequest,
) -> Result<DshCheckResponse, String> {
    let request_id = request.request_id.clone();
    if let Err(error) = validate_request(&request) {
        return Ok(error_response(request_id, error));
    }
    let runtime_request = build_runtime_request(request);

    match runtime.handle_runtime_request(runtime_request) {
        Ok(response) => Ok(map_response(request_id, &response)),
        Err(error) => Ok(error_response(
            request_id,
            format!("runtime check failed: {error}"),
        )),
    }
}

fn validate_request(request: &DshCheckRequest) -> Result<(), String> {
    if request.schema_version != PROTOCOL_SCHEMA_VERSION {
        return Err(format!(
            "unsupported DSH adapter schema_version {}; expected {PROTOCOL_SCHEMA_VERSION}",
            request.schema_version
        ));
    }
    if request.request_id.is_empty() {
        return Err("request_id must be non-empty".to_string());
    }
    if request.session_id.is_empty() {
        return Err("session_id must be non-empty".to_string());
    }
    if request.command.trim().is_empty() {
        return Err("command must be non-empty".to_string());
    }
    if !Path::new(&request.cwd).is_absolute() {
        return Err("cwd must be an absolute path".to_string());
    }
    if !Path::new(&request.workspace_root).is_absolute() {
        return Err("workspace_root must be an absolute path".to_string());
    }
    Ok(())
}

fn build_runtime_request(request: DshCheckRequest) -> RuntimeCheckRequest {
    let DshCheckRequest {
        schema_version: _,
        request_id: _,
        session_id,
        cwd,
        command,
        workspace_root,
    } = request;

    RuntimeCheckRequest {
        session_id: SessionId::new(session_id),
        command,
        shell_state_before: ShellStateSnapshot::new(cwd),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: RUNTIME_NAME.to_string(),
            tool_name: Some(TOOL_NAME.to_string()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
        home: resolve_os_home_dir().or_else(|| env::var("HOME").ok()),
        workspace_root: Some(workspace_root),
    }
}

fn error_response(request_id: String, error: impl Into<String>) -> DshCheckResponse {
    DshCheckResponse {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        request_id,
        decision: None,
        reason: None,
        error: Some(error.into()),
    }
}

fn map_response(request_id: String, response: &CheckResponse) -> DshCheckResponse {
    let reason = if response.reasons.is_empty() {
        None
    } else {
        Some(response.reasons.join("; "))
    };

    let decision = match response.decision {
        Decision::Allow => DshDecision::Allow,
        Decision::NeedApproval => DshDecision::Ask,
        Decision::Deny => DshDecision::Deny,
    };

    DshCheckResponse {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        request_id,
        decision: Some(decision),
        reason,
        error: None,
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
    unsafe { CStr::from_ptr(passwd.pw_dir) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

#[cfg(not(unix))]
fn resolve_os_home_dir() -> Option<String> {
    None
}

fn print_usage() {
    eprintln!(
        "usage: caushell-adapter-dsh --store <path> [--config <path>]\n\nReads newline-delimited ordinary DSH Bash checks from stdin and writes one decision JSON object per line."
    );
}

#[cfg(test)]
mod tests {
    use super::{
        DshCheckRequest, DshDecision, PROTOCOL_SCHEMA_VERSION, build_runtime_request, map_response,
        validate_request,
    };
    use caushell_types::{
        CheckResponse, Decision, DecisionTrace, ShellKind, ShellRuntimeCapabilities,
    };

    #[test]
    fn maps_allow_without_reason() {
        let response = map_response(
            "call-1".to_string(),
            &CheckResponse {
                decision: Decision::Allow,
                reasons: vec![],
                decision_trace: DecisionTrace::default(),
            },
        );
        assert!(matches!(response.decision, Some(DshDecision::Allow)));
        assert_eq!(response.schema_version, PROTOCOL_SCHEMA_VERSION);
        assert_eq!(response.reason, None);
    }

    #[test]
    fn maps_need_approval_and_joins_reasons() {
        let response = map_response(
            "call-2".to_string(),
            &CheckResponse {
                decision: Decision::NeedApproval,
                reasons: vec!["a".to_string(), "b".to_string()],
                decision_trace: DecisionTrace::default(),
            },
        );
        assert!(matches!(response.decision, Some(DshDecision::Ask)));
        assert_eq!(response.schema_version, PROTOCOL_SCHEMA_VERSION);
        assert_eq!(response.reason.as_deref(), Some("a; b"));
    }

    #[test]
    fn maps_deny() {
        let response = map_response(
            "call-3".to_string(),
            &CheckResponse {
                decision: Decision::Deny,
                reasons: vec!["blocked".to_string()],
                decision_trace: DecisionTrace::default(),
            },
        );
        assert!(matches!(response.decision, Some(DshDecision::Deny)));
        assert_eq!(response.request_id, "call-3");
    }

    #[test]
    fn builds_request_only_bash_context_with_explicit_workspace_root() {
        let request = build_runtime_request(DshCheckRequest {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            request_id: "call-4".to_string(),
            session_id: "session-4".to_string(),
            cwd: "/workspace/project".to_string(),
            command: "printf hello".to_string(),
            workspace_root: "/workspace".to_string(),
        });

        assert_eq!(request.session_id.0, "session-4");
        assert_eq!(request.command, "printf hello");
        assert_eq!(request.shell_state_before.cwd(), "/workspace/project");
        assert_eq!(request.shell_kind, ShellKind::Bash);
        assert_eq!(request.runtime.runtime_name, "deepseek_harness");
        assert_eq!(request.runtime.tool_name, Some("bash".to_string()));
        assert_eq!(
            request.runtime.shell_runtime_capabilities,
            ShellRuntimeCapabilities::request_only()
        );
        assert_eq!(request.workspace_root, Some("/workspace".to_string()));
    }

    #[test]
    fn rejects_unknown_protocol_version_and_relative_paths() {
        let mut request = DshCheckRequest {
            schema_version: PROTOCOL_SCHEMA_VERSION + 1,
            request_id: "call-5".to_string(),
            session_id: "session-5".to_string(),
            cwd: "/workspace/project".to_string(),
            command: "printf hello".to_string(),
            workspace_root: "/workspace".to_string(),
        };
        assert!(
            validate_request(&request)
                .unwrap_err()
                .contains("schema_version")
        );

        request.schema_version = PROTOCOL_SCHEMA_VERSION;
        request.cwd = "relative".to_string();
        assert_eq!(
            validate_request(&request).unwrap_err(),
            "cwd must be an absolute path"
        );
    }
}

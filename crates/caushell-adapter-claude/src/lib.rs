use std::env;
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;
use std::time::Instant;

use caushell::{CliError, check_unix_socket};
use caushell_types::{
    CheckResponse, Decision, RuntimeCheckRequest, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities,
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum AdapterError {
    Io(io::Error),
    Cli(CliError),
    InvalidHookPayload(serde_json::Error),
    UnsupportedHookEvent(String),
    UnsupportedTool(String),
    MissingCommandField,
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "caushell-adapter-claude I/O failure: {error}"),
            Self::Cli(error) => write!(f, "caushell-adapter-claude transport failure: {error}"),
            Self::InvalidHookPayload(error) => {
                write!(f, "failed to parse Claude hook JSON payload: {error}")
            }
            Self::UnsupportedHookEvent(event_name) => {
                write!(f, "unsupported Claude hook event {event_name}")
            }
            Self::UnsupportedTool(tool_name) => {
                write!(f, "unsupported Claude tool {tool_name} for bash adapter")
            }
            Self::MissingCommandField => {
                write!(f, "Claude Bash tool payload is missing tool_input.command")
            }
        }
    }
}

impl std::error::Error for AdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Cli(error) => Some(error),
            Self::InvalidHookPayload(error) => Some(error),
            Self::UnsupportedHookEvent(_)
            | Self::UnsupportedTool(_)
            | Self::MissingCommandField => None,
        }
    }
}

impl From<io::Error> for AdapterError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CliError> for AdapterError {
    fn from(error: CliError) -> Self {
        Self::Cli(error)
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreToolUseDecision {
    Allow,
    Ask { reason: String },
    Deny { reason: String },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ClaudeHookResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: PreToolUseHookOutput,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PreToolUseHookOutput {
    hook_event_name: String,
    permission_decision: String,
    permission_decision_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaudeHostContext {
    home: Option<String>,
    workspace_root: Option<String>,
}

impl ClaudeHostContext {
    fn from_environment() -> Self {
        Self::from_sources(
            resolve_os_home_dir(),
            env::var("HOME").ok(),
            env::var("CLAUDE_PROJECT_DIR").ok(),
        )
    }

    fn from_sources(
        os_home: Option<String>,
        env_home: Option<String>,
        workspace_root: Option<String>,
    ) -> Self {
        Self {
            home: os_home.or(env_home),
            workspace_root,
        }
    }
}

pub fn run_pretooluse<R: Read, W: Write>(
    socket_path: &Path,
    reader: R,
    writer: &mut W,
) -> Result<(), AdapterError> {
    let timing_enabled = timing_enabled();
    let total_start = Instant::now();

    let parse_start = Instant::now();
    let hook_request: ClaudeHookRequest =
        serde_json::from_reader(reader).map_err(AdapterError::InvalidHookPayload)?;
    let parse_json_ms = elapsed_ms(parse_start);

    let host_context_start = Instant::now();
    let host_context = ClaudeHostContext::from_environment();
    let host_context_ms = elapsed_ms(host_context_start);

    let build_start = Instant::now();
    let runtime_request = build_runtime_request(
        &hook_request,
        host_context.home,
        host_context.workspace_root,
    )?;
    let build_request_ms = elapsed_ms(build_start);

    let socket_start = Instant::now();
    let response = check_unix_socket(socket_path, &runtime_request)?;
    let socket_roundtrip_ms = elapsed_ms(socket_start);

    let emit_start = Instant::now();
    write_pretooluse_decision(
        writer,
        &hook_request.hook_event_name,
        map_check_response_to_decision(&response),
    )?;
    let write_response_ms = elapsed_ms(emit_start);

    if timing_enabled {
        eprintln!(
            "caushell-timing component=adapter event={} session_id={} parse_json_ms={:.3} host_context_ms={:.3} build_request_ms={:.3} socket_roundtrip_ms={:.3} write_response_ms={:.3} total_ms={:.3}",
            hook_request.hook_event_name,
            hook_request.session_id,
            parse_json_ms,
            host_context_ms,
            build_request_ms,
            socket_roundtrip_ms,
            write_response_ms,
            elapsed_ms(total_start),
        );
    }

    Ok(())
}

fn build_runtime_request(
    hook_request: &ClaudeHookRequest,
    home: Option<String>,
    workspace_root: Option<String>,
) -> Result<RuntimeCheckRequest, AdapterError> {
    if hook_request.hook_event_name != "PreToolUse" {
        return Err(AdapterError::UnsupportedHookEvent(
            hook_request.hook_event_name.clone(),
        ));
    }

    if hook_request.tool_name != "Bash" {
        return Err(AdapterError::UnsupportedTool(
            hook_request.tool_name.clone(),
        ));
    }

    let command = hook_request
        .tool_input
        .command
        .clone()
        .ok_or(AdapterError::MissingCommandField)?;

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
        home,
        workspace_root,
    })
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

fn map_check_response_to_decision(response: &CheckResponse) -> PreToolUseDecision {
    match response.decision {
        Decision::Allow => PreToolUseDecision::Allow,
        Decision::NeedApproval => PreToolUseDecision::Ask {
            reason: user_visible_reason(&joined_reasons(
                &response.reasons,
                "shell query policy requires explicit approval",
            )),
        },
        Decision::Deny => PreToolUseDecision::Deny {
            reason: user_visible_reason(&joined_reasons(
                &response.reasons,
                "shell query policy denied the command",
            )),
        },
    }
}

fn joined_reasons(reasons: &[String], fallback: &str) -> String {
    if reasons.is_empty() {
        fallback.to_string()
    } else {
        reasons.join("; ")
    }
}

fn user_visible_reason(reason: &str) -> String {
    const PREFIX: &str = "[Caushell] ";
    if reason.starts_with(PREFIX) {
        reason.to_string()
    } else {
        format!("{PREFIX}{reason}")
    }
}

fn timing_enabled() -> bool {
    matches!(
        env::var("CAUSHELL_TIMING").ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn write_pretooluse_decision<W: Write>(
    writer: &mut W,
    hook_event_name: &str,
    decision: PreToolUseDecision,
) -> Result<(), AdapterError> {
    let Some(response) = build_hook_response(hook_event_name, decision) else {
        return Ok(());
    };

    serde_json::to_writer(&mut *writer, &response).map_err(AdapterError::InvalidHookPayload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn build_hook_response(
    hook_event_name: &str,
    decision: PreToolUseDecision,
) -> Option<ClaudeHookResponse> {
    match decision {
        PreToolUseDecision::Allow => None,
        PreToolUseDecision::Ask { reason } => Some(ClaudeHookResponse {
            hook_specific_output: PreToolUseHookOutput {
                hook_event_name: hook_event_name.to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: reason,
            },
        }),
        PreToolUseDecision::Deny { reason } => Some(ClaudeHookResponse {
            hook_specific_output: PreToolUseHookOutput {
                hook_event_name: hook_event_name.to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: reason,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClaudeHostContext, build_hook_response, build_runtime_request,
        map_check_response_to_decision, run_pretooluse,
    };
    use caushell_types::{CheckResponse, Decision, RuntimeTransportResponse};
    use serde_json::json;
    use std::fs;
    use std::io::{BufRead, BufReader, Cursor, Write};
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_hook_payload(command: &str) -> String {
        json!({
            "session_id": "sess-1",
            "cwd": "/tmp/project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": command,
                "description": "run bash command"
            }
        })
        .to_string()
    }

    #[test]
    fn host_context_prefers_os_home_over_home_env() {
        let context = ClaudeHostContext::from_sources(
            Some("/real/home".to_string()),
            Some("/env/home".to_string()),
            Some("/tmp/project".to_string()),
        );

        assert_eq!(
            context,
            ClaudeHostContext {
                home: Some("/real/home".to_string()),
                workspace_root: Some("/tmp/project".to_string()),
            }
        );
    }

    #[test]
    fn host_context_falls_back_to_home_env_when_os_home_is_missing() {
        let context = ClaudeHostContext::from_sources(
            None,
            Some("/env/home".to_string()),
            Some("/tmp/project".to_string()),
        );

        assert_eq!(
            context,
            ClaudeHostContext {
                home: Some("/env/home".to_string()),
                workspace_root: Some("/tmp/project".to_string()),
            }
        );
    }

    #[test]
    fn host_context_keeps_home_empty_when_no_source_is_available() {
        let context = ClaudeHostContext::from_sources(None, None, Some("/tmp/project".to_string()));

        assert_eq!(
            context,
            ClaudeHostContext {
                home: None,
                workspace_root: Some("/tmp/project".to_string()),
            }
        );
    }

    #[cfg(unix)]
    fn temp_socket_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("expected wall clock after unix epoch")
            .as_nanos();

        let root = std::env::temp_dir().join(format!("caushell-adapter-claude-{name}-{unique}"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&root)
            .expect("expected private adapter socket directory");
        root.join("runtime.sock")
    }

    #[test]
    fn build_runtime_request_maps_claude_bash_payload() {
        let payload = serde_json::from_str::<super::ClaudeHookRequest>(&sample_hook_payload("pwd"))
            .expect("expected sample hook payload to deserialize");

        let request = build_runtime_request(
            &payload,
            Some("/home/alice".to_string()),
            Some("/workspace/project".to_string()),
        )
        .expect("expected bash payload to map into runtime request");

        assert_eq!(request.session_id.0, "sess-1");
        assert_eq!(request.command, "pwd");
        assert_eq!(request.shell_state_before.cwd(), "/tmp/project");
        assert_eq!(request.runtime.runtime_name, "claude_code");
        assert_eq!(request.runtime.tool_name, Some("Bash".to_string()));
        assert_eq!(request.home, Some("/home/alice".to_string()));
        assert_eq!(
            request.workspace_root,
            Some("/workspace/project".to_string())
        );
    }

    #[test]
    fn need_approval_maps_to_ask_permission_response() {
        let response = build_hook_response(
            "PreToolUse",
            map_check_response_to_decision(&CheckResponse {
                decision: Decision::NeedApproval,
                reasons: vec!["manual review required".to_string()],
                decision_trace: Default::default(),
            }),
        )
        .expect("expected need approval to produce hook response");

        let value =
            serde_json::to_value(response).expect("expected hook response to serialize to json");

        assert_eq!(
            value,
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": "[Caushell] manual review required"
                }
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_pretooluse_reads_socket_response_and_emits_claude_hook_json() {
        let socket_path = temp_socket_path("pretooluse");
        let listener = UnixListener::bind(&socket_path).expect("expected unix listener to bind");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .expect("expected private test socket mode");

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .expect("expected unix listener to accept one connection");
            let mut request_line = String::new();
            BufReader::new(
                stream
                    .try_clone()
                    .expect("expected unix stream clone for reader"),
            )
            .read_line(&mut request_line)
            .expect("expected request line to be readable");

            let request: caushell_types::RuntimeTransportRequest =
                serde_json::from_str(request_line.trim())
                    .expect("expected adapter request to deserialize");

            let caushell_types::RuntimeTransportRequest::Check(request) = request else {
                panic!("expected check transport request");
            };

            assert_eq!(request.command, "unknown-tool --help");
            assert_eq!(request.runtime.tool_name, Some("Bash".to_string()));

            serde_json::to_writer(
                &mut stream,
                &RuntimeTransportResponse::Check(CheckResponse {
                    decision: Decision::NeedApproval,
                    reasons: vec!["manual review required".to_string()],
                    decision_trace: Default::default(),
                }),
            )
            .expect("expected test response to serialize");
            stream
                .write_all(b"\n")
                .expect("expected test response newline");
        });

        let mut output = Vec::new();

        run_pretooluse(
            &socket_path,
            Cursor::new(sample_hook_payload("unknown-tool --help")),
            &mut output,
        )
        .expect("expected pretooluse adapter to succeed");

        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("expected hook output to deserialize");

        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "ask");
        assert_eq!(
            value["hookSpecificOutput"]["permissionDecisionReason"],
            "[Caushell] manual review required"
        );

        handle
            .join()
            .expect("expected unix listener thread to join");
        fs::remove_dir_all(socket_path.parent().unwrap())
            .expect("expected test socket directory to be removed");
    }
}

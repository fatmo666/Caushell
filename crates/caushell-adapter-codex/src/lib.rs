use std::env;
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;

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
            Self::Io(error) => write!(f, "caushell-adapter-codex I/O failure: {error}"),
            Self::Cli(error) => write!(f, "caushell-adapter-codex transport failure: {error}"),
            Self::InvalidHookPayload(error) => {
                write!(f, "failed to parse Codex hook JSON payload: {error}")
            }
            Self::UnsupportedHookEvent(event_name) => {
                write!(f, "unsupported Codex hook event {event_name}")
            }
            Self::UnsupportedTool(tool_name) => {
                write!(f, "unsupported Codex tool {tool_name} for bash adapter")
            }
            Self::MissingCommandField => {
                write!(f, "Codex Bash tool payload is missing tool_input.command")
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
struct CodexHookRequest {
    session_id: String,
    cwd: String,
    hook_event_name: String,
    tool_name: String,
    tool_input: CodexToolInput,
}

#[derive(Debug, Deserialize)]
struct CodexToolInput {
    command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HookDecision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct HookResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput {
    hook_event_name: String,
    permission_decision: String,
    permission_decision_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodexHostContext {
    home: Option<String>,
    workspace_root: Option<String>,
}

impl CodexHostContext {
    fn from_environment() -> Self {
        Self::from_sources(
            resolve_os_home_dir(),
            env::var("HOME").ok(),
            env::var("CODEX_PROJECT_DIR")
                .ok()
                .or_else(|| env::var("PWD").ok()),
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
    let hook_request: CodexHookRequest =
        serde_json::from_reader(reader).map_err(AdapterError::InvalidHookPayload)?;
    let host_context = CodexHostContext::from_environment();
    let runtime_request = build_runtime_request(
        &hook_request,
        host_context.home,
        host_context.workspace_root,
        "PreToolUse",
    )?;
    let response = check_unix_socket(socket_path, &runtime_request)?;

    write_hook_decision(
        writer,
        &hook_request.hook_event_name,
        map_pretooluse_response_to_decision(&response),
    )
}

pub fn run_permission_request<R: Read, W: Write>(
    socket_path: &Path,
    reader: R,
    writer: &mut W,
) -> Result<(), AdapterError> {
    let hook_request: CodexHookRequest =
        serde_json::from_reader(reader).map_err(AdapterError::InvalidHookPayload)?;
    let host_context = CodexHostContext::from_environment();
    let runtime_request = build_runtime_request(
        &hook_request,
        host_context.home,
        host_context.workspace_root,
        "PermissionRequest",
    )?;
    let response = check_unix_socket(socket_path, &runtime_request)?;

    write_hook_decision(
        writer,
        &hook_request.hook_event_name,
        map_permission_request_response_to_decision(&response),
    )
}

fn build_runtime_request(
    hook_request: &CodexHookRequest,
    home: Option<String>,
    workspace_root: Option<String>,
    expected_event_name: &str,
) -> Result<RuntimeCheckRequest, AdapterError> {
    if hook_request.hook_event_name != expected_event_name {
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
            runtime_name: "codex".to_string(),
            tool_name: Some(hook_request.tool_name.clone()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
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

fn map_pretooluse_response_to_decision(response: &CheckResponse) -> HookDecision {
    match response.decision {
        Decision::Allow => HookDecision::Allow,
        Decision::NeedApproval => HookDecision::Allow,
        Decision::Deny => HookDecision::Deny {
            reason: user_visible_reason(&joined_reasons(
                &response.reasons,
                "shell query policy denied the command",
            )),
        },
    }
}

fn map_permission_request_response_to_decision(response: &CheckResponse) -> HookDecision {
    match response.decision {
        Decision::Allow => HookDecision::Allow,
        Decision::NeedApproval => HookDecision::Allow,
        Decision::Deny => HookDecision::Deny {
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

fn write_hook_decision<W: Write>(
    writer: &mut W,
    hook_event_name: &str,
    decision: HookDecision,
) -> Result<(), AdapterError> {
    let Some(response) = build_hook_response(hook_event_name, decision) else {
        return Ok(());
    };

    serde_json::to_writer(&mut *writer, &response).map_err(AdapterError::InvalidHookPayload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn build_hook_response(hook_event_name: &str, decision: HookDecision) -> Option<HookResponse> {
    match decision {
        HookDecision::Allow => None,
        HookDecision::Deny { reason } => Some(HookResponse {
            hook_specific_output: HookSpecificOutput {
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
        CodexHostContext, build_hook_response, build_runtime_request,
        map_permission_request_response_to_decision, map_pretooluse_response_to_decision,
    };
    use caushell_types::{CheckResponse, Decision};
    use serde_json::json;

    fn sample_hook_payload(event: &str, command: &str) -> String {
        json!({
            "session_id": "sess-1",
            "cwd": "/tmp/project",
            "hook_event_name": event,
            "tool_name": "Bash",
            "tool_input": {
                "command": command
            }
        })
        .to_string()
    }

    #[test]
    fn host_context_prefers_os_home_over_home_env() {
        let context = CodexHostContext::from_sources(
            Some("/real/home".to_string()),
            Some("/env/home".to_string()),
            Some("/tmp/project".to_string()),
        );

        assert_eq!(
            context,
            CodexHostContext {
                home: Some("/real/home".to_string()),
                workspace_root: Some("/tmp/project".to_string()),
            }
        );
    }

    #[test]
    fn build_runtime_request_maps_codex_bash_payload() {
        let payload = serde_json::from_str::<super::CodexHookRequest>(&sample_hook_payload(
            "PreToolUse",
            "pwd",
        ))
        .expect("expected sample hook payload to deserialize");

        let request = build_runtime_request(
            &payload,
            Some("/home/alice".to_string()),
            Some("/workspace/project".to_string()),
            "PreToolUse",
        )
        .expect("expected bash payload to map into runtime request");

        assert_eq!(request.session_id.0, "sess-1");
        assert_eq!(request.command, "pwd");
        assert_eq!(request.shell_state_before.cwd(), "/tmp/project");
        assert_eq!(request.runtime.runtime_name, "codex");
        assert_eq!(request.runtime.tool_name, Some("Bash".to_string()));
        assert_eq!(request.home, Some("/home/alice".to_string()));
        assert_eq!(
            request.workspace_root,
            Some("/workspace/project".to_string())
        );
    }

    #[test]
    fn pretooluse_need_approval_falls_through() {
        let response = build_hook_response(
            "PreToolUse",
            map_pretooluse_response_to_decision(&CheckResponse {
                decision: Decision::NeedApproval,
                reasons: vec!["manual review required".to_string()],
                decision_trace: Default::default(),
            }),
        );

        assert!(response.is_none());
    }

    #[test]
    fn permission_request_need_approval_falls_through() {
        let response = build_hook_response(
            "PermissionRequest",
            map_permission_request_response_to_decision(&CheckResponse {
                decision: Decision::NeedApproval,
                reasons: vec!["manual review required".to_string()],
                decision_trace: Default::default(),
            }),
        );

        assert!(response.is_none());
    }
}

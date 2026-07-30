#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn posttooluse_drains_large_payload_before_exiting() {
    let root = unique_temp_dir("caushell-claude-posttooluse");
    fs::create_dir_all(&root).expect("test root must be created");
    let home = root.join("home");
    let state = root.join("state");
    let runtime = root.join("runtime");
    let socket_root = root.join("socket");
    let store = root.join("store");
    let workspace = root.join("workspace");
    for path in [&home, &state, &runtime, &socket_root, &store, &workspace] {
        fs::create_dir_all(path).expect("test directory must be created");
    }
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))
        .expect("runtime directory must be private");

    let session_id = "claude-posttooluse-regression";
    let payload = serde_json::json!({
        "session_id": session_id,
        "cwd": workspace,
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf ok"},
        "tool_response": {"output": "x".repeat(4 * 1024 * 1024)}
    })
    .to_string();
    let runtime_binary = std::env::current_exe().expect("test executable path must be available");

    let mut child = Command::new(env!("CARGO_BIN_EXE_caushell-claude-hook"))
        .arg("PostToolUse")
        .env("HOME", &home)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("CAUSHELL_CONFIG_PATH", root.join("config.yaml"))
        .env("CLAUDE_PLUGIN_OPTION_RUNTIME_PATH", &runtime_binary)
        .env("CLAUDE_PLUGIN_OPTION_SOCKET_ROOT", &socket_root)
        .env("CLAUDE_PLUGIN_OPTION_STORE_ROOT", &store)
        .env("CLAUDE_PROJECT_DIR", &workspace)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PostToolUse hook must start");

    let mut stdin = child.stdin.take().expect("hook stdin must be piped");
    stdin
        .write_all(payload.as_bytes())
        .expect("hook must consume the complete PostToolUse payload");
    drop(stdin);

    let output = child
        .wait_with_output()
        .expect("PostToolUse hook must terminate");
    assert!(
        output.status.success(),
        "hook failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = find_file(&socket_root, "plugin.log").expect("hook log must be created");
    let log = fs::read_to_string(log_path).expect("hook log must be readable");
    assert!(log.lines().any(|line| {
        line.split_whitespace()
            .any(|field| field == "event=PostToolUse")
            && line
                .split_whitespace()
                .any(|field| field == format!("session_id={session_id}"))
    }));
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.file_name().and_then(|value| value.to_str()) == Some(name) {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        }
    }
    None
}

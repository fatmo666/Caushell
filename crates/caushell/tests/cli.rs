use std::process::Command;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn version_reports_the_release_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .arg("--version")
        .output()
        .expect("caushell must start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output must be UTF-8"),
        format!("caushell {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn unknown_command_returns_failure() {
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .arg("does-not-exist")
        .output()
        .expect("caushell must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("error output must be UTF-8"),
        "invalid caushell arguments: unknown command: does-not-exist\n"
    );
}

#[test]
fn doctor_help_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .args(["doctor", "--help"])
        .output()
        .expect("caushell doctor help must start");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("help output must be UTF-8");
    assert!(stderr.contains("caushell doctor codex [--smoke]"));
    assert!(stderr.contains("caushell doctor claude [--smoke]"));
}

#[test]
fn doctor_requires_known_agent() {
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .args(["doctor", "does-not-exist"])
        .output()
        .expect("caushell doctor must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("error output must be UTF-8"),
        "invalid caushell arguments: unknown doctor target \"does-not-exist\"; expected codex or claude\n"
    );
}

#[cfg(unix)]
#[test]
fn doctor_codex_smoke_verifies_fresh_hook_log_events() {
    let temp_dir = unique_temp_dir("caushell-doctor-codex-smoke");
    fs::create_dir_all(&temp_dir).expect("temp dir must be created");
    let log_path = temp_dir.join("plugin.log");
    let adapter_path = temp_dir.join("caushell-adapter-codex");
    let hook_path = temp_dir.join("caushell-codex-hook");
    let codex_path = temp_dir.join("codex");

    write_executable(&adapter_path, "#!/bin/sh\nexit 0\n");
    write_executable(
        &hook_path,
        &format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             Status)\n\
             printf '%s\\n' 'plugin_name=caushell-codex'\n\
             printf '%s\\n' 'plugin_version={version}'\n\
             printf '%s\\n' 'runtime_status=up'\n\
             printf '%s\\n' 'runtime_path={runtime_path}'\n\
             printf '%s\\n' 'adapter_path={adapter_path}'\n\
             printf '%s\\n' 'config_load_error='\n\
             printf '%s\\n' 'plugin_log_path={log_path}'\n\
             printf '%s\\n' 'last_failure='\n\
             ;;\n\
             PreToolUse)\n\
             cat >/dev/null\n\
             printf '%s\\n' 'timestamp=fake level=info event=PreToolUse msg=fake decision_class=allow' >> {log_path_quoted}\n\
             ;;\n\
             PostToolUse)\n\
             cat >/dev/null\n\
             printf '%s\\n' 'timestamp=fake level=info event=PostToolUse msg=fake decision_class=observational' >> {log_path_quoted}\n\
             ;;\n\
             esac\n",
            version = env!("CARGO_PKG_VERSION"),
            runtime_path = env!("CARGO_BIN_EXE_caushell"),
            adapter_path = adapter_path.display(),
            log_path = log_path.display(),
            log_path_quoted = shell_quote(&log_path.display().to_string()),
        ),
    );
    write_executable(
        &codex_path,
        &format!(
            "#!/bin/sh\n\
             if [ \"$1\" = plugin ] && [ \"$2\" = list ] && [ \"$3\" = --json ]; then\n\
             printf '%s\\n' '{plugin_json}'\n\
             exit 0\n\
             fi\n\
             exit 1\n",
            plugin_json = serde_json::json!({
                "installed": [
                    {
                        "pluginId": "caushell-codex@caushell",
                        "name": "caushell-codex",
                        "marketplaceName": "caushell",
                        "version": env!("CARGO_PKG_VERSION"),
                        "installed": true,
                        "enabled": true
                    }
                ],
                "available": []
            }),
        ),
    );

    let path = format!(
        "{}:{}",
        temp_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .args(["doctor", "codex", "--smoke"])
        .env("PATH", path)
        .output()
        .expect("caushell doctor must start");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("doctor output must be UTF-8");
    assert!(stdout.contains("[ok] Codex plugin enabled: caushell-codex@caushell"));
    assert!(stdout.contains("[ok] direct PreToolUse hook completed"));
    assert!(stdout.contains("[ok] PreToolUse allowed harmless smoke command"));
    assert!(stdout.contains("[ok] hook log contains event=PreToolUse"));
    assert!(stdout.contains("[ok] hook log contains event=PostToolUse"));
    assert!(stdout.contains("Result: OK"));
}

#[cfg(unix)]
fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

#[cfg(unix)]
fn write_executable(path: &std::path::Path, content: &str) {
    fs::write(path, content).expect("script must be written");
    let mut permissions = fs::metadata(path)
        .expect("script metadata must be available")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("script must be executable");
}

#[cfg(unix)]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

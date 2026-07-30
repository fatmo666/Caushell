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
fn build_info_reports_embedded_release_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .arg("build-info")
        .output()
        .expect("caushell build-info must start");

    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("build-info must emit JSON");
    assert_eq!(value["name"], "caushell");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        value["commit"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        value["release"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        value["target"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[test]
fn update_help_succeeds_without_network_access() {
    for command in ["update", "--update"] {
        let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
            .args([command, "--help"])
            .output()
            .expect("caushell update help must start");

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("help output must be UTF-8");
        assert!(stderr.contains("caushell update [--check]"));
    }
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
             printf '%s\\n' \"timestamp=fake level=info event=PostToolUse session_id=caushell-doctor-$PPID msg=fake decision_class=observational\" >> {log_path_quoted}\n\
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

#[cfg(all(
    unix,
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
#[test]
fn update_verifies_and_replaces_the_complete_runtime_bundle() {
    let temp_dir = unique_temp_dir("caushell-update");
    let dist_dir = temp_dir.join("dist");
    let install_dir = temp_dir.join("install");
    let target = release_target_for_test();
    let package_name = format!("caushell-{target}");
    let package_bin = dist_dir.join(&package_name).join("bin");
    fs::create_dir_all(&package_bin).expect("package bin directory must be created");
    fs::create_dir_all(&install_dir).expect("install directory must be created");

    let build_info = serde_json::json!({
        "name": "caushell",
        "version": env!("CARGO_PKG_VERSION"),
        "commit": "candidate-update-build",
        "release": "v0.0.1-test",
        "target": target
    });
    for binary in release_binaries_for_test() {
        let content = if binary == "caushell" {
            format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = build-info ]; then\n  printf '%s\\n' '{build_info}'\n  exit 0\nfi\nprintf '%s\\n' candidate-runtime\n",
            )
        } else {
            "#!/bin/sh\nprintf '%s\\n' candidate-runtime\n".to_string()
        };
        write_executable(&package_bin.join(binary), &content);
        write_executable(
            &install_dir.join(binary),
            "#!/bin/sh\nprintf '%s\\n' old-runtime\n",
        );
    }

    let asset = format!("{package_name}.tar.gz");
    let archive = dist_dir.join(&asset);
    let tar_output = Command::new("tar")
        .arg("-C")
        .arg(&dist_dir)
        .args(["-czf"])
        .arg(&archive)
        .arg(&package_name)
        .output()
        .expect("tar must start");
    assert!(
        tar_output.status.success(),
        "tar failed: {}",
        String::from_utf8_lossy(&tar_output.stderr)
    );
    let checksum = sha256_for_test(&archive);
    fs::write(
        dist_dir.join(format!("{asset}.sha256")),
        format!("{checksum}  {asset}\n"),
    )
    .expect("checksum file must be written");

    let check_output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .args(["update", "--check", "--runtime-only"])
        .env(
            "CAUSHELL_UPDATE_BASE_URL",
            format!("file://{}", dist_dir.display()),
        )
        .env("CAUSHELL_UPDATE_INSTALL_DIR", &install_dir)
        .output()
        .expect("caushell update --check must start");
    assert!(
        check_output.status.success(),
        "update check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&check_output.stdout),
        String::from_utf8_lossy(&check_output.stderr)
    );
    assert!(
        !install_dir.join(".caushell-update.lock").exists(),
        "check-only update must not leave a persistent lock file"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .args(["update", "--runtime-only"])
        .env(
            "CAUSHELL_UPDATE_BASE_URL",
            format!("file://{}", dist_dir.display()),
        )
        .env("CAUSHELL_UPDATE_INSTALL_DIR", &install_dir)
        .output()
        .expect("caushell update must start");

    assert!(
        output.status.success(),
        "update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("update output must be UTF-8");
    assert!(stdout.contains("[ok] release checksum verified"));
    assert!(stdout.contains("[ok] runtime binaries updated"));
    assert!(stdout.contains("available=v0.0.1-test/candida"));

    for binary in release_binaries_for_test() {
        let contents = fs::read_to_string(install_dir.join(binary))
            .expect("updated binary fixture must be readable");
        assert!(
            contents.contains("candidate-runtime"),
            "{binary} was not updated"
        );
    }

    fs::remove_dir_all(temp_dir).expect("update test directory must be removed");
}

#[cfg(all(
    unix,
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
#[test]
fn update_refreshes_an_installed_codex_plugin_when_runtime_is_current() {
    let temp_dir = unique_temp_dir("caushell-update-plugin");
    let dist_dir = temp_dir.join("dist");
    let install_dir = temp_dir.join("install");
    fs::create_dir_all(&install_dir).expect("install directory must be created");

    let current_output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .arg("build-info")
        .output()
        .expect("current build-info must start");
    let current_info: serde_json::Value =
        serde_json::from_slice(&current_output.stdout).expect("current build-info must be JSON");
    let commit = current_info["commit"]
        .as_str()
        .expect("current build must have a commit");
    assert_ne!(commit, "unknown", "test requires a known current commit");
    let candidate_info = serde_json::json!({
        "name": "caushell",
        "version": env!("CARGO_PKG_VERSION"),
        "commit": commit,
        "release": "v0.0.1-current",
        "target": "unknown"
    });

    create_release_fixture(&temp_dir, &candidate_info, "candidate-runtime");
    for binary in release_binaries_for_test() {
        let content = if binary == "caushell" {
            "#!/bin/sh\nif [ \"${1:-}\" = doctor ]; then exit 0; fi\nprintf '%s\\n' old-runtime\n"
        } else {
            "#!/bin/sh\nprintf '%s\\n' old-runtime\n"
        };
        write_executable(&install_dir.join(binary), content);
    }

    let command_log = temp_dir.join("codex-commands.log");
    let codex_path = temp_dir.join("codex");
    write_executable(
        &codex_path,
        &format!(
            "#!/bin/sh\n\
             if [ \"$1\" = plugin ] && [ \"$2\" = list ] && [ \"$3\" = --json ]; then\n\
             printf '%s\\n' '{plugin_json}'\n\
             exit 0\n\
             fi\n\
             printf '%s\\n' \"$*\" >> {log_path}\n\
             exit 0\n",
            plugin_json = serde_json::json!({
                "installed": [{
                    "pluginId": "caushell-codex@caushell",
                    "installed": true,
                    "enabled": true
                }],
                "available": []
            }),
            log_path = shell_quote(&command_log.display().to_string()),
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .arg("update")
        .env(
            "CAUSHELL_UPDATE_BASE_URL",
            format!("file://{}", dist_dir.display()),
        )
        .env("CAUSHELL_UPDATE_INSTALL_DIR", &install_dir)
        .env("PATH", format!("{}:/usr/bin:/bin", temp_dir.display()))
        .output()
        .expect("caushell update must start");

    assert!(
        output.status.success(),
        "update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("update output must be UTF-8");
    assert!(stdout.contains("runtime binaries are already up to date"));
    assert!(stdout.contains("Codex doctor passed"));

    let commands = fs::read_to_string(command_log).expect("Codex command log must exist");
    assert!(commands.contains("plugin marketplace add fatmo666/Caushell"));
    assert!(commands.contains("plugin marketplace upgrade caushell"));
    assert!(commands.contains("plugin add caushell-codex@caushell"));
    assert!(!commands.contains("plugin remove"));

    fs::remove_dir_all(temp_dir).expect("update test directory must be removed");
}

#[cfg(all(
    unix,
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
fn create_release_fixture(
    temp_dir: &std::path::Path,
    build_info: &serde_json::Value,
    marker: &str,
) -> std::path::PathBuf {
    let dist_dir = temp_dir.join("dist");
    let target = release_target_for_test();
    let package_name = format!("caushell-{target}");
    let package_bin = dist_dir.join(&package_name).join("bin");
    fs::create_dir_all(&package_bin).expect("package bin directory must be created");

    for binary in release_binaries_for_test() {
        let content = if binary == "caushell" {
            format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = build-info ]; then\n  printf '%s\\n' '{build_info}'\n  exit 0\nfi\nprintf '%s\\n' {marker}\n"
            )
        } else {
            format!("#!/bin/sh\nprintf '%s\\n' {marker}\n")
        };
        write_executable(&package_bin.join(binary), &content);
    }

    let asset = format!("{package_name}.tar.gz");
    let archive = dist_dir.join(&asset);
    let tar_output = Command::new("tar")
        .arg("-C")
        .arg(&dist_dir)
        .args(["-czf"])
        .arg(&archive)
        .arg(&package_name)
        .output()
        .expect("tar must start");
    assert!(
        tar_output.status.success(),
        "tar failed: {}",
        String::from_utf8_lossy(&tar_output.stderr)
    );
    let checksum = sha256_for_test(&archive);
    fs::write(
        dist_dir.join(format!("{asset}.sha256")),
        format!("{checksum}  {asset}\n"),
    )
    .expect("checksum file must be written");
    dist_dir
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn release_target_for_test() -> &'static str {
    "x86_64-unknown-linux-musl"
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn release_target_for_test() -> &'static str {
    "x86_64-apple-darwin"
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn release_target_for_test() -> &'static str {
    "aarch64-apple-darwin"
}

#[cfg(unix)]
fn release_binaries_for_test() -> [&'static str; 5] {
    [
        "caushell",
        "caushell-adapter-codex",
        "caushell-codex-hook",
        "caushell-adapter-claude",
        "caushell-claude-hook",
    ]
}

#[cfg(unix)]
fn sha256_for_test(path: &std::path::Path) -> String {
    let output = if Command::new("sha256sum")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        Command::new("sha256sum")
            .arg(path)
            .output()
            .expect("sha256sum must start")
    } else {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
            .expect("shasum must start")
    };
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("checksum output must be UTF-8")
        .split_whitespace()
        .next()
        .expect("checksum output must contain a digest")
        .to_string()
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

//! Static effect checks only. No pip, package code, network, or task executes.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("pip-native-paths"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/u".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn explicit_output_cache_and_log_facts_survive_independent_unknown_effects() {
    for command in [
        "pip --cache-dir /outside/cache --log /outside/pip.log download package -d /workspace/dist --no-deps",
        "pip3 wheel package --cache-dir=/outside/cache --log /outside/pip.log --wheel-dir /workspace/dist",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        for path in ["/outside/cache", "/outside/pip.log", "/workspace/dist"] {
            assert!(
                response
                    .decision_trace
                    .path_targets
                    .iter()
                    .any(|f| f.lexical.concrete_path() == Some(path)),
                "missing {path}: {response:#?}"
            );
        }
        assert!(
            response
                .decision_trace
                .path_targets
                .iter()
                .any(|f| f.operation == PathTargetOperation::Write
                    && f.lexical.concrete_path().is_none()),
            "unknown native configuration must remain separate: {response:#?}"
        );
    }
}

#[test]
fn native_configuration_unknowns_remain_ask_and_do_not_weaken_deny() {
    for command in [
        "pip --disable-pip-version-check list",
        "pip --isolated --disable-pip-version-check show package",
        "pip config list",
        "pip config --user set global.timeout 10",
        "PIP_CONFIG_FILE=/workspace/settings.ini pip config set global.timeout 10",
        "pip --no-cache-dir download package --dest /workspace/dist --no-deps",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
    for command in [
        "pip --cache-dir /workspace/cache download package --unknown; rm -rf /",
        "pip --disable-pip-version-check list; rm -rf /",
        "pip config set global.log /workspace/log; rm -rf /",
    ] {
        assert_eq!(check(command).decision, Decision::Deny, "{command}");
    }
    assert_eq!(check("pip --version").decision, Decision::Allow);
}

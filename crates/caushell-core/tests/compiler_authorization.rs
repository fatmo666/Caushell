//! Static policy checks: no submitted program or compiler command is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
        .with_environment_observation("ENV", ShellEnvironmentValue::Absent);
    shell.observability.variables = ShellStateKnowledge::Complete;
    shell.observability.aliases = ShellStateKnowledge::Complete;
    shell.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("compiler-authority"),
        sequence_no: CommandSequenceNo(sequence),
        command: command.into(),
        shell_state_before: shell,
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(command: &str, expected: Decision) {
    let r = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
}

#[test]
fn compiler_diagnostics_use_existing_output_authority() {
    for output in ["./build/program", "/tmp/program", "/private/tmp/program"] {
        expect(
            &format!("gcc -Wall -Wextra -pedantic source.c -o {output}"),
            Decision::Allow,
        );
    }
    expect(
        "gcc -Wall source.c -o /outside/program",
        Decision::NeedApproval,
    );
}

#[test]
fn a_pure_version_query_has_no_output_fact_or_ambient_grant() {
    let r = ShellQueryCore::new().check(request("gcc --version | head -1", 1));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.reasons);
    assert!(
        !r.decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation.is_mutation())
    );
    for command in [
        "gcc --version --unknown-mode",
        "gcc --version @options",
        "gcc --version -fplugin=/outside/plugin.so",
        "gcc --version; touch /outside/result",
    ] {
        expect(command, Decision::NeedApproval);
    }
    expect("gcc --version; rm -rf /", Decision::Deny);
}

#[test]
fn compiler_unknown_options_and_code_loads_remain_approval() {
    for command in [
        "gcc -Wall --unknown-mode source.c -o build/program",
        "gcc -Wall -Wl,-Map=/outside/map source.c -o build/program",
        "gcc -Wall -fplugin=/outside/plugin.so source.c -o build/program",
        "gcc @options -o build/program",
    ] {
        expect(command, Decision::NeedApproval);
    }
    expect(
        "gcc -Wall source.c -o build/program; rm -rf /",
        Decision::Deny,
    );
}

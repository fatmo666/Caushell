//! Native CLI admission fixtures only; never compile or run COBOL/C code.
use caushell_core::ShellQueryCore;
use caushell_types::*;

const CONTROLS: &[&str] = &[
    "COB_CC",
    "COB_CFLAGS",
    "COB_LDFLAGS",
    "COB_DEBUG_FLAGS",
    "COB_LIBS",
    "COB_LDADD",
    "COB_LIB_PATHS",
    "COB_CONFIG_DIR",
    "COBCPY",
    "TMPDIR",
    "TMP",
    "TEMP",
];

fn check(
    command: &str,
    observe: bool,
    override_value: Option<(&str, ShellEnvironmentValue)>,
) -> CheckResponse {
    let mut shell =
        ShellStateSnapshot::new("/workspace").with_variable_knowledge(ShellStateKnowledge::Unknown);
    if observe {
        for name in CONTROLS {
            let value = override_value
                .as_ref()
                .filter(|(key, _)| key == name)
                .map(|(_, v)| v.clone())
                .unwrap_or(ShellEnvironmentValue::Absent);
            shell = shell.with_environment_observation(*name, value);
        }
    }
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("cobc-native"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: shell,
        home: Some("/home/tester".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn information_queries_do_not_compile_or_write_even_with_unknown_toolchain_environment() {
    for command in [
        "cobc --version",
        "cobc -V",
        "cobc --help",
        "cobc -h",
        "cobc -o /outside/ignored --help",
    ] {
        let r = check(command, false, None);
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .all(|p| p.operation != PathTargetOperation::Write)
        );
    }
}

#[test]
fn bounded_explicit_compilation_uses_existing_read_and_write_policy() {
    for command in [
        "cobc -x -o binary source.cbl",
        "cobc -x -free source.cbl -o /tmp/native-output",
        "cobc --free -g -O2 -Wall -x -obinary one.cbl two.cbl",
        "cobc -x -ofirst -o final source.cbl",
        "cobc -x -outline -o final source.cbl",
    ] {
        let r = check(command, true, None);
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .any(|p| p.operation == PathTargetOperation::Write)
        );
    }
    let r = check("cobc -x -o /outside/binary source.cbl", true, None);
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
}

#[test]
fn native_controls_unknown_outputs_and_unsafe_command_string_operands_remain_ask() {
    let command = "cobc -x -o binary source.cbl";
    assert_eq!(check(command, false, None).decision, Decision::NeedApproval);
    for key in CONTROLS {
        let r = check(
            command,
            true,
            Some((
                key,
                ShellEnvironmentValue::Present {
                    value: "native-override".into(),
                },
            )),
        );
        assert_eq!(r.decision, Decision::NeedApproval, "{key}: {:?}", r.reasons);
    }
    for command in [
        "cobc -x source.cbl",
        "cobc -o module source.cbl",
        "cobc -xj -o binary source.cbl",
        "cobc -x -o binary --save-temps source.cbl",
        "cobc -x -o binary -Q '-Wl,unknown' source.cbl",
        "cobc -x -o --version source.cbl",
        "cobc -x -o 'binary;touch /outside/marker' source.cbl",
        "cobc -x -o binary 'source name.cbl'",
        "cobc -x -o \"$UNKNOWN\" source.cbl",
        "cobc -x -o binary",
        "cobc -x -jV -o binary source.cbl",
        "cobc -xFjV -o binary source.cbl",
        "cobc -Oh -o binary source.cbl",
        "cobc -x -o--help source.cbl",
        "COB_CC='$(not_shell)' cobc -x -o binary source.cbl",
    ] {
        let r = check(command, true, None);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
    }
}

#[test]
fn independent_deletion_asks_and_denies_are_not_downgraded() {
    let r = check("cobc --version; rm /workspace/old", false, None);
    assert_eq!(r.decision, Decision::NeedApproval);
    for command in [
        "cobc -x -o binary source.cbl; rm -rf /",
        "cobc --unsupported; rm -rf /",
        "cobc -xj source.cbl; rm -rf /",
        "cobc -x -o \"$(rm -rf /)\" source.cbl",
    ] {
        let r = check(command, false, None);
        assert_eq!(r.decision, Decision::Deny, "{command}: {:?}", r.reasons);
    }
}

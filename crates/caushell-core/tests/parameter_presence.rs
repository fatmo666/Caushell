//! Static Graph/guard checks. These command strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) {
    for capabilities in [
        ShellRuntimeCapabilities::persistent_shell(),
        ShellRuntimeCapabilities::request_only(),
    ] {
        let response = ShellQueryCore::new().check(CheckRequest {
            session_id: SessionId::new("parameter-presence"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.into(),
            shell_kind: ShellKind::Bash,
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            home: Some("/home/alice".into()),
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "static-test".into(),
                tool_name: None,
                shell_runtime_capabilities: capabilities,
            },
        });
        assert_eq!(response.decision, expected, "{command}: {response:#?}");
        if command == "bash -c \"${CODE:-printf SAFE}\""
            || command == "bash -c \"${CODE-printf SAFE}\""
        {
            assert!(
                !response
                    .decision_trace
                    .derived_invocations
                    .iter()
                    .any(|child| child.raw_text == "printf SAFE"),
                "{response:#?}"
            );
        }
    }
}

#[test]
fn unknown_paths_code_and_positional_operators_require_approval() {
    for command in [
        "touch -- \"${OUT:-./safe.txt}\"",
        "touch -- \"${OUT-./safe.txt}\"",
        "bash -c \"${CODE:-printf SAFE}\"",
        "bash -c \"${CODE-printf SAFE}\"",
        "target=${OUT//x/y}; touch -- \"${target}.bak\"",
        "find ${1:-.} -mindepth 1 -maxdepth 1 -type d",
        "find . -type f -iname '*'\"${1:-}\"'*' -exec ${2:-file} {} \\;",
        "target=${OUT+./safe}; touch -- \"${target}suffix\"",
        "target=${OUT:+./safe}; touch -- \"${target}suffix\"",
        "if flag; then OUT=./safe; fi; touch -- \"${OUT:-./fallback}\"",
        "unset OUT; export OUT; prefix=${OUT+./safe}; touch -- \"$prefix/etc/out\"",
        "export OUT; prefix=${OUT+./safe}; touch -- \"$prefix/etc/out\"",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn proved_absent_empty_and_local_values_keep_their_real_meaning() {
    for command in [
        "unset OUT; touch -- \"${OUT:-./safe.txt}\"",
        "OUT=; touch -- \"${OUT:-./safe.txt}\"",
        "OUT=./local; touch -- \"${OUT:-/opt/out}\"",
        "unset CODE; bash -c \"${CODE:-printf SAFE}\"",
        "set --; find ${1:-.} -mindepth 1 -maxdepth 1 -type d",
        "OUT=./x; target=${OUT//x/y}; touch -- \"${target}.bak\"",
        "unset OUT; target=${OUT//x/y}; touch -- \"${target}.bak\"",
        "OUT=; target=${OUT+./safe}; touch -- \"${target}suffix\"",
        "OUT=; target=${OUT:+/opt/out}; touch -- \"${target}suffix\"",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn known_external_values_and_proved_root_defaults_do_not_gain_exemptions() {
    for command in [
        "OUT=/opt/out; touch -- \"${OUT:-./safe.txt}\"",
        "CODE='touch /opt/out'; bash -c \"${CODE:-printf SAFE}\"",
        "set -- -delete; find ${1:-.} -mindepth 1 -maxdepth 1 -type d",
        "OUT=x; target=${OUT:+/opt/out}; touch -- \"$target\"",
    ] {
        check(command, Decision::NeedApproval);
    }
    check("unset OUT; rm -rf -- \"${OUT:-/}\"", Decision::Deny);
    check("OUT=/; rm -rf -- \"${OUT:-/tmp/safe}\"", Decision::Deny);
}

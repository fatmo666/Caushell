//! Static checks only; sample programs and file operations are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("env-reset"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

#[test]
fn reset_marker_exposes_real_child_effects() {
    for command in [
        "env - touch /opt/out",
        "env -- - touch /opt/out",
        "env -i - touch /opt/out",
        "env - rm /opt/out",
        "env - /bin/sh",
        "env - `cat ~/cronenv` /bin/sh",
        "env - $(cat vars.txt) /bin/sh",
        "env - \"$unknown\" /bin/sh",
        "env -C /opt - touch out",
        "env -S '- /bin/sh'",
        "env - X=$unknown printf ok",
        "env - X=$(cat vars.txt) printf ok",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
    for (command, name) in [
        ("env - touch /opt/out", "touch"),
        ("env - rm /opt/out", "rm"),
    ] {
        let r = check(command);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == name)
        );
        assert!(
            !r.decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("-"))
        );
    }
}

#[test]
fn local_and_empty_environment_forms_remain_allowed() {
    for command in [
        "env - touch ./out",
        "env -- - touch ./out",
        "env -",
        "env - X=value",
        "env - printf -- -",
        "env - printf -- --help",
        "env -i touch ./out",
        "PROGRAM=touch; env - \"$PROGRAM\" ./out",
        "env - X=\"$unknown\" printf ok",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

#[test]
fn reset_erases_inherited_facts_and_applies_assignments_afterward() {
    for command in [
        "DEST=./local; export DEST; env - sh -c 'touch \"$DEST\"'",
        "DEST=./local; export DEST; env -- - sh -c 'touch \"$DEST\"'",
        "env - DEST=/opt/out sh -c 'touch \"$DEST\"'",
        "PROGRAM=touch; env - \"$PROGRAM\" /opt/out",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
    }
    for command in [
        "DEST=/opt/out; export DEST; env - DEST=./local sh -c 'touch \"$DEST\"'",
        "env - DEST=./local sh -c 'touch \"$DEST\"'",
        "DEST=./local; export DEST; env - printf ok; touch \"$DEST\"",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

#[test]
fn marker_is_not_consumed_twice_or_after_assignments() {
    for command in ["env - - /bin/sh", "env X=value - /bin/sh"] {
        let r = check(command);
        assert!(
            r.decision_trace
                .derived_invocations
                .iter()
                .any(|d| d.command_name.as_deref() == Some("-")),
            "{command}: {r:#?}"
        );
        assert!(
            !r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "sh"),
            "{command}: {r:#?}"
        );
    }
}

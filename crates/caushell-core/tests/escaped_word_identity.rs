//! Static checks only; no command under test is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn check(command: &str, expected: Decision) {
    let r = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("escaped-word"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    });
    assert_eq!(r.decision, expected, "{command:?}: {:?}", r.reasons);
}
#[test]
fn unknown_escaped_program_names_keep_the_existing_approval_policy() {
    for s in [
        r"\ egrep abc",
        "' egrep' abc",
        "\\\tegrep abc",
        r"env \ egrep abc",
        r"printf x | \ egrep abc",
        r"command \ egrep abc",
        r"env bash -c '\ egrep abc'",
        r"\ 'egrep' abc",
    ] {
        check(s, Decision::NeedApproval);
    }
}
#[test]
fn ordinary_escapes_and_literal_data_keep_their_meaning() {
    for s in [
        r"\egrep abc",
        r"printf '%s' \ hello",
        "printf '%s' '\\ egrep'",
        "cat <<'EOF'\n\\ egrep abc\nEOF\n",
    ] {
        check(s, Decision::Allow);
    }
}
#[test]
fn unknown_prefixes_cannot_erase_later_deny_or_nested_execution() {
    for s in [
        r"\ exit 0; rm -rf /",
        r"\ egrep abc; rm -rf /",
        "cat <<EOF\n$(\\ egrep abc)\nEOF\n; rm -rf /",
    ] {
        check(s, Decision::Deny);
    }
    check("cat <<EOF\n$(\\ egrep abc)\nEOF\n", Decision::NeedApproval);
    check("bash <<'EOF'\n\\ egrep abc\nEOF\n", Decision::NeedApproval);
    check("bash <<EOF\n\\ egrep abc\nEOF\n", Decision::NeedApproval);
    check(
        "bash <<-EOF\n\t\\ egrep abc\n\tEOF\n",
        Decision::NeedApproval,
    );
}

use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, ResolvedPathRole, RuleId, RuntimeMetadata, SessionId,
    SessionMutation, SessionStateEffect, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(session: &str, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new(session),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "terminal-escape-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

#[test]
fn separate_terminal_escape_preserves_optional_read_operand() {
    let mut core = ShellQueryCore::new();
    let command = r"nl -ba fixture-first \";
    let output = core.check_with_outcome(request("optional-read", command));
    assert_eq!(output.response.decision, Decision::Allow, "{output:#?}");
    let SessionStateEffect::Committed { committed_mutations, .. } = output.state_effect else {
        panic!("a complete allowed check should preserve its read effects");
    };
    let mut reads: Vec<_> = committed_mutations
        .iter()
        .filter_map(|mutation| match mutation {
            SessionMutation::AddPathFact {
                resolution, role: ResolvedPathRole::Read, ..
            } => resolution.concrete_path(),
            _ => None,
        })
        .collect();
    reads.sort_unstable();
    assert_eq!(reads, [r"/tmp/project/\", "/tmp/project/fixture-first"]);
    assert!(
        output.response.decision_trace.execution_units.iter().any(|unit| unit.raw_text == command)
    );

    let mut update = request("optional-write", r"touch -- caushell-fixture-output \");
    update.shell_state_before = ShellStateSnapshot::new("/tmp");
    update.workspace_root = Some("/tmp".into());
    for (id, spelling) in [
        ("write-discard", "touch -- caushell-fixture-output"),
        ("write-keep", r"touch -- caushell-fixture-output \\"),
    ] {
        let mut alternative = update.clone();
        alternative.session_id = SessionId::new(id);
        alternative.command = spelling.into();
        assert_eq!(core.check(alternative).decision, Decision::Allow);
    }
    assert_eq!(core.check(update).decision, Decision::NeedApproval);
}

#[test]
fn terminal_escape_needs_matching_request_effects() {
    let mut core = ShellQueryCore::new();
    let command = r"set label=\[$(hostname -s)\]\#\";
    let output = core.check(request("terminal-data", command));
    assert_eq!(output.decision, Decision::Allow, "{output:#?}");
    assert!(
        output.decision_trace.execution_units.iter().any(|unit| unit.raw_text == command)
    );

    for (session, command) in [
        ("terminal-state", r"set -- fixture\"),
        ("terminal-read", r"cat fixture\"),
        ("terminal-redirect", r"printf '%s' fixture > \"),
        ("terminal-unclosed", r"printf '%s' 'fixture\"),
    ] {
        let output = core.check(request(session, command));
        assert_eq!(output.decision, Decision::NeedApproval, "{output:#?}");
        assert!(
            output.decision_trace.decision_proposals.iter()
                .any(|proposal| proposal.rule_id == RuleId::CommandParseFailure)
        );
    }
}

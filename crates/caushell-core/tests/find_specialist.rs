//! Static checks and Graph assertions only; no sample actions execute.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("find-specialist"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(command: &str, decision: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, decision, "{command}: {result:#?}");
}

#[test]
fn shell_expanded_home_paths_reach_existing_child_mutation_guard() {
    for command in [
        r"find . -exec cp {} ~/cache/ \;",
        "find . -exec cp -t ~/cache -- {} +",
        r"find . -exec mv {} ~/cache/ \;",
        r"find . -exec chmod 644 ~/cache/file \;",
        r"find . -exec cp {} ~/cache/{}.copy \;",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
    }
    let mut core = ShellQueryCore::new();
    let result = core.check(request(r"find . -exec cp {} ~/cache/ \;"));
    assert!(
        result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
    );
    // NeedApproval requests are observed, not committed. Inspect the staged
    // Graph used by the guard, not the allowed-command history.
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(r"find . -exec cp {} ~/cache/ \;"));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    assert!(staged.graph().nodes().any(|node|
        matches!(&node.kind, NodeKind::PathFact { normalized_command_name: Some(name), resolution, .. }
            if name == "cp" && resolution.concrete_path() == Some("/home/alice/cache"))));
}

#[test]
fn dispatched_executable_spelling_is_expanded_without_changing_unknown_command_policy() {
    let result = ShellQueryCore::new().check(request(r"find . -exec ~/script.sh {} \;"));
    // This checks argv conversion, not a new risk rule for unprofiled programs.
    assert!(
        result
            .decision_trace
            .derived_invocations
            .iter()
            .any(|unit| unit.command_name.as_deref() == Some("/home/alice/script.sh"))
    );
}

#[test]
fn literal_tilde_and_materialized_data_are_not_expanded_a_second_time() {
    for command in [
        r"find . -exec cp {} ./cache/ \;",
        r"find . -exec cp {} '~/cache/' \;",
        r"find . -exec cp {} \~/cache/ \;",
        r#"target='~/cache/'; find . -exec cp {} "$target" \;"#,
        r#"target='$HOME/cache/'; find . -exec cp {} "$target" \;"#,
    ] {
        expect(command, Decision::Allow);
    }
    for home in [None, Some("/home/space dir/$literal".into())] {
        let mut input = request(r"find . -exec cp {} ~/cache/ \;");
        input.home = home;
        let result = ShellQueryCore::new().check(input);
        assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    }
    for command in [
        r"find . -exec cp {} ~unknown-user/cache/ \;",
        r"find . -exec cp {} ~+/cache/ \;",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn bracing_unknown_scalar_never_removes_argv_control_uncertainty() {
    for command in [
        "find ${DIRECTORY} -type f -print",
        "find $DIRECTORY -type f -print",
        "find ${DIRECTORY} -type f -print | wc -l",
        "find ${DIRECTORY} -exec printf '%s' {} +",
    ] {
        expect(command, Decision::NeedApproval);
    }
    for command in [
        "DIRECTORY=.; find ${DIRECTORY} -type f -print",
        "find '${DIRECTORY}' -type f -print",
        r"find \${DIRECTORY} -type f -print",
    ] {
        expect(command, Decision::Allow);
    }
    let mut core = ShellQueryCore::new();
    let result = core.check(request(
        "find ${DIRECTORY:-$(touch /opt/shared/marker)} -type f -print",
    ));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    assert!(
        result
            .decision_trace
            .execution_semantics
            .iter()
            .any(|unit| unit.normalized_command_name == "touch")
    );
}

#[test]
fn cpio_copy_pass_keeps_fixed_external_destination_even_with_unknown_stdin() {
    for flags in [
        "-pdm",
        "-dump",
        "-pvd",
        "-pdv0",
        "-pamvd0",
        "-pvdmB",
        "--pass-through --make-directories --preserve-modification-time",
    ] {
        let command = format!("find . -print | cpio {flags} /opt/shared/cache");
        let result = ShellQueryCore::new().check(request(&command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|unit| unit.normalized_command_name == "cpio"
                    && unit.form_id == "pass_through_archive")
        );
    }
    for command in [
        "find . -print | cpio -pdm cache",
        "find . -print0 | cpio -pd0 cache",
        "find . -print | cpio -pdm -- '-cache'",
        "find data/ -name 'filepattern-*2009*' | cpio -ov --format=ustar > 2009.tar",
    ] {
        expect(command, Decision::Allow);
    }
    for command in [
        "find . -print | cpio -pdm $destination",
        "find . -print | cpio -pdm",
        "find . -print | cpio -pi /opt/shared/cache",
        "find . -print | cpio -p --unsupported /opt/shared/cache",
        "find . -print | cpio -pam cache",
        "find . -print | cpio --pass-through --reset-access-time cache",
        "find . -print | cpio -p cache extra-destination",
        "find . -print | cpio -o --format",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

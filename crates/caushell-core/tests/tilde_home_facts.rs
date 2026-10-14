//! Static checks only: no file mutations, shell execution or host-home lookup.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, home: Option<&str>) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("tilde-home"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: home.map(str::to_owned),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(command: &str, home: Option<&str>, decision: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(request(command, home));
    assert_eq!(response.decision, decision, "{command}: {response:#?}");
    response
}

#[test]
fn mixed_quote_source_paths_no_longer_create_unresolved_copy_semantics() {
    for command in [
        r#"cp ~/Library/"Application Support/Google/Chrome/Default/Login Data" "/tmp/T1555.003_Login Data""#,
        "cp ~/'$literal*' output",
        "cp ~/Library/'Login Data' output",
        "cp ~/input output",
    ] {
        let response = expect(command, Some("/home/a b$literal*"), Decision::Allow);
        assert!(
            !response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError)
        );
    }
}

#[test]
fn destination_paths_use_visible_home_overrides() {
    for command in [
        "HOME=/workspace; cp input ~/\"file name\"",
        "HOME=/workspace; cp input ~/output/*",
        "HOME=/workspace; touch ~/\"file name\"",
    ] {
        expect(command, Some("/outside"), Decision::Allow);
    }
    for command in [
        "HOME=/outside; cp input ~/\"file name\"",
        "HOME=/outside; cp input ~/output/*",
        "HOME=''; cp input ~/output",
        "HOME=\"$UNKNOWN\"; cp input ~/output",
        "HOME=/outside; touch ~/\"file name\"",
    ] {
        expect(command, Some("/workspace"), Decision::NeedApproval);
    }
}

#[test]
fn prefix_assignments_do_not_retroactively_change_parent_argv() {
    expect(
        "HOME=/outside cp input ~/output",
        Some("/workspace"),
        Decision::Allow,
    );
    expect(
        "HOME=/workspace cp input ~/output",
        Some("/outside"),
        Decision::NeedApproval,
    );
}

#[test]
fn unset_home_uses_account_home_not_previous_value() {
    expect(
        "HOME=/outside; unset HOME; cp input ~/output",
        Some("/workspace"),
        Decision::Allow,
    );
    expect(
        "HOME=/workspace; unset HOME; cp input ~/output",
        Some("/outside"),
        Decision::NeedApproval,
    );
    expect(
        "unset HOME; cp input ~/output",
        None,
        Decision::NeedApproval,
    );
}

#[test]
fn opaque_snapshot_home_is_not_replaced_by_request_default() {
    let mut r = request("cp input ~/output", Some("/workspace"));
    r.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "HOME",
            ShellValueSnapshot::opaque_dynamic("unknown"),
            true,
        ));
    let response = ShellQueryCore::new().check(r);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn initial_home_default_preserves_the_request_contract_but_not_explicit_absence() {
    expect(
        "cp input \"$HOME/output\"",
        Some("/workspace"),
        Decision::Allow,
    );
    expect(
        "find $HOME -iname '*.ogg' -size +20M",
        Some("/workspace"),
        Decision::Allow,
    );
    let mut absent = request("cp input \"${HOME:-/outside}/output\"", Some("/workspace"));
    absent.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
    assert_eq!(
        ShellQueryCore::new().check(absent).decision,
        Decision::NeedApproval
    );
    let mut r = request("cp input \"$HOME/output\"", Some("/outside"));
    r.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "HOME",
            ShellValueSnapshot::exact_scalar("/workspace"),
            true,
        ));
    assert_eq!(ShellQueryCore::new().check(r).decision, Decision::Allow);
}

#[test]
fn quoted_and_transported_tildes_remain_local_data() {
    for command in [
        "cp input '~/output'",
        r#"cp input "~/output""#,
        r"cp input \~/output",
        "d='~/output'; cp input \"$d\"",
        "cp input ''~/output",
        "empty=''; cp input \"$empty\"~/output",
        "cp input -t~/output",
    ] {
        expect(command, Some("/outside"), Decision::Allow);
    }
    expect(
        "cp input ~/output",
        Some("/outside"),
        Decision::NeedApproval,
    );
}

#[test]
fn child_shell_home_respects_export_and_explicit_child_environment() {
    // HOME's default is initially exported. Explicitly unexport it to test
    // that an actual parent-local override cannot leak into a child shell.
    expect(
        "export -n HOME; HOME=/outside; bash -c 'touch ~/output'",
        Some("/workspace"),
        Decision::Allow,
    );
    expect(
        "HOME=/outside; export HOME; bash -c 'touch ~/output'",
        Some("/workspace"),
        Decision::NeedApproval,
    );
    expect(
        "HOME=/outside bash -c 'touch ~/output'",
        Some("/workspace"),
        Decision::NeedApproval,
    );
    expect(
        "env HOME=/outside bash -c 'touch ~/output'",
        Some("/workspace"),
        Decision::NeedApproval,
    );
}

#[test]
fn graph_paths_keep_complete_literal_expanded_bytes() {
    use caushell_graph::{NodeKind, SessionGraph, SessionRead};
    use caushell_passes::{
        ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_profile::ProfileRegistry;
    use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
    for (command, home, expected) in [
        (
            "cp input ~/'file $literal*'",
            "/workspace/a b$HOME*'\"",
            "/workspace/a b$HOME*'\"/file $literal*",
        ),
        (
            "HOME=/workspace; cp input ~/\"file name\"",
            "/outside",
            "/workspace/file name",
        ),
        ("cp input ''~/output", "/outside", "/workspace/~/output"),
    ] {
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
        let mut ctx = RunnerContext::new(request(command, Some(home)));
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
        assert!(staged.graph().nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution: PathResolution::Concrete { path }, .. } if path==expected)), "{command}: missing {expected}");
    }
}

#[test]
fn repeated_home_expansions_share_the_source_value_not_the_full_operand() {
    use caushell_graph::NodeKind;
    let mut core = ShellQueryCore::new();
    let command =
        "cp ~/Library/\"Login Data\" /tmp/one\ncp ~/Library/\"Login Data For Account\" /tmp/two";
    let response = core.check(request(command, Some("/home/alice")));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    let graph = core.session_graph(&SessionId::new("tilde-home")).unwrap();
    assert!(graph.nodes().any(|n| matches!(&n.kind,NodeKind::ProvenanceArtifact { artifact:ProvenanceArtifact::InheritedEnvValue { name,state:ProvenanceVariableValueState::ExactScalar { value },.. },.. } if name=="HOME" && value=="/home/alice")));
    for suffix in ["Login Data", "Login Data For Account"] {
        let expected = format!("/home/alice/Library/{suffix}");
        assert!(graph.nodes().any(|n| matches!(&n.kind,NodeKind::ProvenanceArtifact { artifact:ProvenanceArtifact::MaterializedValue { state:ProvenanceMaterializedValueState::ExactScalar { value },.. },.. } if value==&expected)));
    }
    let mut r = request("cat \"$PREFIX/first\" \"$PREFIX/second\"", None);
    r.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "PREFIX",
            ShellValueSnapshot::exact_scalar("/opt/data"),
            true,
        ));
    assert_eq!(ShellQueryCore::new().check(r).decision, Decision::Allow);
}

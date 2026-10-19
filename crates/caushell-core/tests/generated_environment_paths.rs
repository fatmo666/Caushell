//! Static inputs only: no filter or filesystem mutation is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let mut core = ShellQueryCore::new();
    let response = core.check(CheckRequest {
        session_id: SessionId::new("generated-environment"),
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
    });
    assert_eq!(response.decision, expected, "{command}: {response:#?}");
    response
}

#[test]
fn generated_names_cover_default_explicit_and_encoded_output_filters() {
    for command in [
        "zcat biglogfile.gz | split -l500000 --filter='gzip > $FILE.gz'",
        "cat afile | split -l 2 --filter='bzip2 > \"$FILE.bz2\"'",
        "zcat doc.gz | split -l 1000 --filter='gzip > $FILE.gz'",
        "split -l 100 input.txt ./cache/part_ --filter='gzip > \"$FILE.gz\"'",
        "split -l 100 input.txt ./cache/part_ --filter='gzip > ${FILE}.gz'",
        "split input.txt --filter='cat > \"$FILE\".gz'",
        "split --additional-suffix=.part input.txt cache/p_ --filter='cat > \"$FILE\"'",
        "split -d --numeric-suffixes=2 input.txt cache/p_ --filter='cat > \"$FILE\"'",
        "split -x --hex-suffixes=2 input.txt cache/p_ --filter='cat > \"$FILE\"'",
        "split input.txt --filter='cat >/dev/null'",
        "split input.txt --filter='cat >./cache/fixed'",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn outside_unknown_and_escaping_prefixes_require_approval() {
    for command in [
        "split input.txt /opt/backup/part_ --filter='cat > \"$FILE\"'",
        "split input.txt ../part_ --filter='cat > \"$FILE\"'",
        "split input.txt \"$unknown\" --filter='cat > \"$FILE\"'",
        "split --additional-suffix=../escape input.txt --filter='cat > \"$FILE\"'",
        "split --additional-suffix=\"$unknown\" input.txt --filter='cat > \"$FILE\"'",
        "split input.txt --filter='cd /opt; cat > \"$FILE\"'",
        "split input.txt --filter='cat > \"$FILE/../../outside\"'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn known_external_names_are_bounded_targets_not_unresolved_variables() {
    let response = check(
        "split input.txt /opt/backup/part_ --filter='cat > \"$FILE\"'",
        Decision::NeedApproval,
    );
    assert!(
        response
            .decision_trace
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation)
    );
    assert!(
        !response
            .reasons
            .iter()
            .any(|reason| reason.contains("cannot be resolved")),
        "{response:#?}"
    );
}

#[test]
fn generated_environment_overrides_the_callers_value_without_leaking_back() {
    check(
        "FILE=/opt/out; export FILE; split input.txt --filter='cat > \"$FILE\"'",
        Decision::Allow,
    );
    check(
        "FILE=./local; export FILE; split input.txt /opt/out_ --filter='cat > \"$FILE\"'",
        Decision::NeedApproval,
    );
    check(
        "FILE=/opt/out; export FILE; split input.txt --filter='cat > \"$FILE\"'; cat >\"$FILE\"",
        Decision::NeedApproval,
    );
}

#[test]
fn reassignments_and_nested_environment_boundaries_do_not_reuse_stale_domains() {
    for command in [
        "split input.txt --filter='FILE=/opt/out; cat > \"$FILE\"'",
        "split input.txt --filter='FILE=$unknown; cat > \"$FILE\"'",
        "split input.txt --filter='unset FILE; cat > \"$FILE\"'",
        "split input.txt --filter='env -i sh -c '\"'\"'cat >\"$FILE\"'\"'\"''",
        "split input.txt --filter='env FILE=/opt/out sh -c '\"'\"'cat >\"$FILE\"'\"'\"''",
        "split input.txt --filter='export -n FILE; sh -c '\"'\"'cat >\"$FILE\"'\"'\"''",
    ] {
        check(command, Decision::NeedApproval);
    }
    for command in [
        "split input.txt --filter='FILE=./fixed; cat > \"$FILE\"'",
        "split input.txt --filter='sh -c '\"'\"'cat >\"$FILE\"'\"'\"''",
        "split input.txt --filter='env sh -c '\"'\"'cat >\"$FILE\"'\"'\"''",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn quoted_literal_spelling_is_not_reinterpreted_as_shell_expansion() {
    for command in [
        "split input.txt './cache/part * ' --filter='cat > \"$FILE\"'",
        "split --additional-suffix='* space' input.txt --filter='cat > \"$FILE\"'",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "split input.txt './cache/part * ' --filter='cat > $FILE'",
        "split --additional-suffix='* space' input.txt --filter='cat > $FILE'",
        "split input.txt --filter='IFS=/; cat > $FILE'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn opening_frames_and_file_operands_share_the_same_domain() {
    for command in [
        "split input.txt --filter='(cat) > \"$FILE.gz\"'",
        "split input.txt --filter='{ cat; } > \"$FILE.gz\"'",
        "split input.txt --filter='tee \"$FILE\"'",
    ] {
        check(command, Decision::Allow);
    }
    check(
        "split input.txt /opt/out_ --filter='tee \"$FILE\"'",
        Decision::NeedApproval,
    );
}

#[test]
fn graph_retains_directory_bounds_not_a_fabricated_chunk_filename() {
    use caushell_graph::{NodeKind, SessionGraph, SessionRead};
    use caushell_passes::{
        ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass,
        ProjectTopLevelCommandsPass, ResolveInvocationPass,
    };
    use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        caushell_profile::ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(CheckRequest {
        session_id: SessionId::new("generated-graph"),
        sequence_no: CommandSequenceNo::new(1),
        command: "split input.txt cache/p_ --filter='cat > \"$FILE.gz\"'".into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: None,
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    });
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    assert!(staged.graph().nodes().any(|node| matches!(&node.kind,
        NodeKind::PathFact { role: ResolvedPathRole::Write,
            resolution: PathResolution::BoundedPathSet { roots, may_escape: false }, .. }
            if roots == &["/workspace/cache".to_string()])));
    assert!(!staged.graph().nodes().any(|node| matches!(&node.kind,
        NodeKind::PathFact { resolution: PathResolution::Concrete { path }, .. }
            if path.contains("p_aa"))));
}

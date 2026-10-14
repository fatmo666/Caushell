//! Static native-path binding and guard checks; no shell sample is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ExtractPipelineFlowPass, ParseCommandPass,
    ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::{BoundValue, ProfileRegistry};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("dos2unix-bounded"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str, decision: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, decision, "{command}: {r:#?}");
    r
}
fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&base, &summary), &mut ctx);
    // Confirm the child still carries the original symbolic domain; this
    // repair must not fabricate an actual filename to obtain a known binding.
    for record in ctx.execution_unit_resolve_records() {
        if let caushell_profile::ResolveInvocationArtifactResult::Resolved(r) = &record.result
            && r.bound.command_name.as_str() == "dos2unix"
        {
            assert!(!r.bound.operation_semantics_unresolved, "{r:#?}");
            assert!(
                r.bound
                    .bound_parameters
                    .iter()
                    .filter(|p| p.name.as_str() == "input_files")
                    .flat_map(|p| &p.values)
                    .any(|v| matches!(
                        v,
                        BoundValue::ImplicitInput {
                            domain: Some(RuntimeArgumentDomain::PathSet { .. }),
                            ..
                        }
                    )),
                "{r:#?}"
            );
        }
    }
    StagedSession::new(&base, ctx.request(), &summary, ctx.pending_mutations())
        .graph()
        .nodes()
        .cloned()
        .collect()
}
fn bounded(nodes: &[GraphNode], role: ResolvedPathRole, root: &str) -> bool {
    nodes.iter().any(|n| matches!(&n.kind,NodeKind::PathFact {role:actual,resolution:PathResolution::BoundedPathSet {roots,may_escape:false},..}
        if *actual==role && roots==&[root]))
}

#[test]
fn native_find_children_and_nul_batches_keep_workspace_mutation_semantics() {
    for c in [
        "find . -type f -exec dos2unix {} \\;",
        "find . -type f -exec dos2unix {} {} \\;",
        "find . -name '*' -type f -exec dos2unix {} \\;",
        "find . -type f -exec dos2unix {} +",
        "find . -type f -print0 | xargs -0 dos2unix",
        "find . -type f -print0 | xargs -0 -n1 -P4 dos2unix",
        "find . -type f -print0 | xargs -0 -I '{}' dos2unix '{}'",
        "find . -type f -exec dos2unix -k {} \\;",
        "find . -type f -exec dos2unix -- {} \\;",
    ] {
        let r = check(c, Decision::Allow);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "dos2unix"
                    && s.form_id == "convert_in_place"
                    && !s.operation_semantics_unresolved)
        );
        assert!(
            !r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError)
        );
    }
}

#[test]
fn external_and_mixed_roots_still_require_the_existing_modification_guard() {
    for c in [
        "find /opt/shared -type f -exec dos2unix {} \\;",
        "find . /opt/shared -type f -exec dos2unix {} \\;",
        "find /opt/shared -type f -exec dos2unix {} +",
        "find /opt/shared -type f -print0 | xargs -0 dos2unix",
        "find /opt/shared -type f -exec dos2unix -- {} \\;",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{r:#?}"
        );
        assert!(
            !r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{r:#?}"
        );
    }
}

#[test]
fn uncertain_splitting_control_words_and_late_modes_are_not_reclassified_as_files() {
    for c in [
        "find . -name *.txt | xargs dos2unix",
        "find . -type f -print | xargs dos2unix",
        "dos2unix \"$FILE\"",
        "dos2unix $FILE",
        "dos2unix ./file --help",
        "dos2unix ./file -n ./source /opt/shared/out",
        "find . -type f -exec dos2unix {} --help \\;",
        "find . -type f -exec dos2unix {} -n {} /opt/shared/out \\;",
        "find . -type f -exec dos2unix -n {} {} +",
        "dos2unix -n ./source ./out orphan",
    ] {
        check(c, Decision::NeedApproval);
    }
}

#[test]
fn inspection_and_stdout_modes_do_not_inherit_file_write_effects() {
    for c in [
        "find /opt/shared -type f -exec dos2unix -i {} \\;",
        "find /opt/shared -type f -print0 | xargs -0 dos2unix -i",
        "find /opt/shared -type f -exec dos2unix -O {} \\;",
        "find /opt/shared -type f -print0 | xargs -0 dos2unix -O",
    ] {
        check(c, Decision::Allow);
    }
    check(
        "find /opt/shared -type f -exec dos2unix -O {} \\; > /opt/shared/out",
        Decision::NeedApproval,
    );
    check(
        "find . -type f -exec dos2unix {} \\;; rm -rf /",
        Decision::Deny,
    );
}

#[test]
fn staged_graph_retains_bounded_read_and_write_roles_without_filename_invention() {
    for (c, root) in [
        ("find . -type f -exec dos2unix {} \\;", "/workspace/project"),
        (
            "find /opt/shared -type f -exec dos2unix {} \\;",
            "/opt/shared",
        ),
        (
            "find . -type f -print0 | xargs -0 dos2unix",
            "/workspace/project",
        ),
    ] {
        let nodes = graph(c);
        assert!(
            bounded(&nodes, ResolvedPathRole::Read, root),
            "{c}: {nodes:#?}"
        );
        assert!(
            bounded(&nodes, ResolvedPathRole::Write, root),
            "{c}: {nodes:#?}"
        );
    }
}

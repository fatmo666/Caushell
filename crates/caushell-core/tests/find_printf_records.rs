//! Static check requests only; no sample command is executed.
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
        session_id: SessionId::new("find-printf-records"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command))
}

fn expect(commands: &[&str], decision: Decision) {
    for command in commands {
        let response = check(command);
        assert_eq!(response.decision, decision, "{command}: {response:#?}");
    }
}

#[test]
fn complete_nul_path_formats_preserve_directory_scope() {
    expect(
        &[
            r#"find olddir -type d -print0 | xargs -0 mkdir -p"#,
            r#"find olddir -type d -printf "%p\0" | xargs -0 mkdir -p"#,
            r#"find olddir -type d -printf "newdir/%P\0" | xargs -0 mkdir -p"#,
            r#"find -printf "%p\0" | xargs -0 mkdir -p"#,
            r#"FMT='%p\0'; find olddir -printf "$FMT" | xargs -0 mkdir -p"#,
            r#"find olddir -name script.sh -printf "%p\0" -printf "newdir/%P\0" | xargs -0L2 cp -n"#,
            r#"find olddir -name script.sh -printf "%p\000newdir/%P\0" | xargs -0L2 cp -n"#,
            r#"find /opt/input -type d -printf "newdir/%P\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "percent%%/%P\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "newdir/%P\0" | tee | xargs -0 mkdir -p"#,
            r#"find olddir -printf "newdir/%P\0" -o -printf "other/%P\0" | xargs -0 mkdir -p"#,
        ],
        Decision::Allow,
    );
}

#[test]
fn external_or_parent_traversing_targets_and_unknown_cwd_remain_guarded() {
    expect(
        &[
            r#"find /opt/input -printf "%p\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "/opt/shared/%P\0" | xargs -0 mkdir -p"#,
            r#"find ../external -printf "%p\0" | xargs -0 mkdir -p"#,
            r#"find ../../external -printf "newdir/%p\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "newdir/../../external/%P\0" | xargs -0 mkdir -p"#,
            r#"cd /opt/shared; find olddir -printf "%p\0" | xargs -0 mkdir -p"#,
            r#"cd "$UNKNOWN"; find olddir -printf "%p\0" | xargs -0 mkdir -p"#,
            r#"find -L olddir -printf "%p\0" | xargs -0 mkdir -p"#,
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn format_data_is_not_implicitly_safe_path_records() {
    expect(
        &[
            r#"find olddir -printf "$FORMAT" | xargs -0 mkdir -p"#,
            r#"find "$ROOT" -printf "%p\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\n" | xargs mkdir -p"#,
            r#"find olddir -printf "%p" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%P\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%f\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%.2p\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf ".%p\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p/../../external\0" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0trailing" | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" | xargs -n1 mkdir -p"#,
            r#"find olddir -printf "-control/%P\0" | xargs -0 mkdir -p"#,
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn mixed_output_actions_and_pipeline_overrides_cannot_claim_a_pure_stream() {
    expect(
        &[
            r#"find olddir -printf "%p\0" -print | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" -print0 | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" -ls | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" -fprintf /dev/stdout '%f\0' | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" -exec printf '%s\0' /opt/shared \; | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" 2>&1 | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" |& xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p\0" | xargs -0 mkdir -p <list"#,
            r#"find olddir -printf "%p\0" | sed 's/old/new/' | xargs -0 mkdir -p"#,
            r#"find olddir -printf "%p" -o -printf '\0' | xargs -0 mkdir -p"#,
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn path_record_proofs_do_not_erase_independent_effects() {
    expect(
        &[r#"find /opt/shared -delete -printf "newdir/%P\0" | xargs -0 mkdir -p"#],
        Decision::NeedApproval,
    );
    expect(
        &[r#"find . -printf "%p\0" | xargs -0 -n1 rm -rf /"#],
        Decision::Deny,
    );
}

#[test]
fn graph_retains_a_bounded_write_not_a_fabricated_concrete_filename() {
    let command = r#"find /opt/input -type d -printf "newdir/%P\0" | xargs -0 mkdir -p"#;
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
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let writes = staged
        .graph()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                normalized_command_name,
                role: ResolvedPathRole::Write,
                resolution,
                ..
            } if normalized_command_name.as_deref() == Some("mkdir") => Some(resolution),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!writes.is_empty());
    assert!(writes.iter().all(|resolution| matches!(resolution,
        PathResolution::BoundedPathSet { roots, may_escape: false }
            if !roots.is_empty() && roots.iter().all(|root| root.trim_end_matches('/') == "/bench/workspace/newdir")
    )), "{writes:#?}");
}

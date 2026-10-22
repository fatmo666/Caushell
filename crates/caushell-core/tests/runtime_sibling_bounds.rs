//! Static analysis only: none of the checked commands is executed.
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
        session_id: SessionId::new("runtime-sibling-bounds"),
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

fn expect(commands: &[&str], expected: Decision) {
    for command in commands {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(response.decision, expected, "{command}: {response:#?}");
    }
}

#[test]
fn find_and_xargs_filename_affixes_keep_sibling_outputs_inside_the_directory_bound() {
    expect(
        &[
            "find . -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find ./ -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find ./audio -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find /bench/workspace/ -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find -name '*.flac' -exec ffmpeg -i {} -acodec libmp3lame -ab 128k {}.mp3 \\;",
            "find . -print0 | xargs -0 -I {} ffmpeg -i {} {}.mp4",
            "find . -print0 | xargs -0 -I {} -n1 -P4 ffmpeg -i {} {}.mp4",
            "find /tmp/input -type f -exec ffmpeg -i {} {}.mp3 \\;",
        ],
        Decision::Allow,
    );
}

#[test]
fn external_unknown_escaping_and_changed_cwd_domains_remain_guarded() {
    expect(
        &[
            "find /opt/input -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find . /opt/input -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find \"$ROOT\" -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find ../outside -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find . -type f -exec ffmpeg -i {} /opt/output/{}.mp3 \\;",
            "find -L . -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find . -print0 | xargs -0 -I {} ffmpeg -i {} ../{}.mp3",
            "find . -print0 | xargs -0 -I {} ffmpeg -i {} {}.mp3/../../outside",
            "cat file-list | xargs -0 -I {} ffmpeg -i {} {}.mp3",
            "cd /opt; find . -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "cd \"$UNKNOWN\"; find . -type f -exec ffmpeg -i {} {}.mp3 \\;",
            "find . -delete -exec ffmpeg -i {} {}.mp3 \\;",
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn inclusive_roots_are_not_silently_reclassified_as_directory_bounds() {
    expect(
        &[
            "find . -type f -exec ffmpeg -i input {} \\;",
            "find /bench/workspace -type f -exec ffmpeg -i input {} \\;",
            "find . -print0 | xargs -0 -I {} ffmpeg -i input {}",
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn graph_keeps_both_explicit_and_sibling_writes_as_path_sets_not_guessed_files() {
    let command = "find . -type f -exec ffmpeg -i {} {}.mp3 \\;";
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
    let writes: Vec<_> = staged
        .graph()
        .nodes()
        .filter_map(|node| match &node.kind {
            NodeKind::PathFact {
                normalized_command_name,
                role: ResolvedPathRole::Write,
                resolution,
                ..
            } if normalized_command_name.as_deref() == Some("ffmpeg") => Some(resolution),
            _ => None,
        })
        .collect();
    assert!(writes.len() >= 2, "{writes:#?}");
    assert!(
        writes.iter().all(|resolution| matches!(resolution,
        PathResolution::BoundedPathSet { roots, may_escape: false }
            if roots == &["/bench/workspace".to_string()])),
        "{writes:#?}"
    );
}

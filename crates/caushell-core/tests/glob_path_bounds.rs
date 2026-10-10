//! Static checks only: no command below is executed and no directory is read.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathResolution, ResolvedPathRole, RuntimeMetadata,
    SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("glob-path-bounds"),
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

fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&base, &summary), &mut ctx);
    StagedSession::new(&base, ctx.request(), &summary, ctx.pending_mutations())
        .graph()
        .nodes()
        .cloned()
        .collect()
}

#[test]
fn stable_local_globs_work_across_existing_mutation_profiles() {
    for command in [
        "chmod +x ./*.sh",
        "chmod 644 img/* js/* html/*",
        "chown owner:group ./assets/*",
        "chgrp group ./assets/*",
        "touch -d '30 August 2013' ./*.php",
        "rmdir ed*",
        "rmdir -v ./dir*",
        "mv file*.txt destination",
        "cp input.txt out*.txt",
        "gzip dir/*.txt",
        "bzip2 dir/*",
        "compress file*",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn graph_retains_a_bounded_set_instead_of_a_concrete_expansion() {
    let nodes = graph("chmod +x ./tools/*.sh");
    assert!(nodes.iter().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::MetadataMutation, resolution: PathResolution::BoundedPathSet {roots, may_escape: false}, ..} if roots == &["/tmp/project/"] )));
    assert!(!nodes.iter().any(|n| matches!(&n.kind, NodeKind::PathFact {resolution: PathResolution::Concrete {path}, ..} if path.contains('*'))));
    let nodes = graph("gzip dir/*.txt");
    assert!(nodes.iter().any(|n| matches!(&n.kind, NodeKind::PathFact {role: ResolvedPathRole::Write, resolution: PathResolution::BoundedPathSet {roots, may_escape: false}, ..} if roots == &["/tmp/project"] )));
}

#[test]
fn unsafe_controls_parent_expansion_and_unknown_cwd_keep_approval() {
    for command in [
        "chmod +x *.sh",
        "chmod +x *",
        "rmdir *",
        "chmod +x ./.*",
        "chmod +x ./[.][.]",
        "chmod +x dir/*/../*.sh",
        "chmod +x ../*.sh",
        "chmod +x /opt/shared/*.sh",
        "chmod +x /tmp/project/*.sh",
        "chmod +x ~/cache/*.sh",
        "chmod +x ./$dir/*.sh",
        "chmod +x ./{..,cache}/*",
        "cd /opt/shared; chmod +x ./*.sh",
        "cd \"$where\"; chmod +x ./*.sh",
        "gzip -d --force dir/* /etc",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn quoted_patterns_literal_brackets_and_known_runtime_bytes_stay_literal() {
    for command in [
        "chmod +x '*.sh'",
        "chmod +x '.*'",
        "rm []",
        "find . -inum 31246 -exec rm [] ';'",
        "target='./*.sh'; chmod +x \"$target\"",
        "target='/opt/shared/*.sh'; chmod +x \"$target\"",
    ] {
        expect(
            command,
            if command.contains("/opt/shared") {
                Decision::NeedApproval
            } else {
                Decision::Allow
            },
        );
    }
    assert!(graph("target='./*.sh'; chmod +x \"$target\"").iter().any(|n| matches!(&n.kind, NodeKind::PathFact {resolution: PathResolution::Concrete {path}, ..} if path == "/tmp/project/*.sh")));
}

#[test]
fn shell_redirection_patterns_are_data_not_cli_controls() {
    for command in ["echo data > *.txt", "echo data >> ./logs/*.txt", "> *.txt"] {
        expect(command, Decision::Allow);
    }
    for command in [
        "echo data > ../*.txt",
        "echo data > /opt/shared/*.txt",
        "echo data > .*",
        "echo data > \"$target\"",
        "cd \"$where\"; echo data > *.txt",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn parent_removal_is_not_certified_by_the_leaf_glob_bound() {
    for command in [
        "rmdir -p dir*",
        "rmdir --parents ./dir*",
        "rmdir -pv ./dir*",
        "rmdir -vp ./dir*",
        "rmdir --paren ./dir*",
    ] {
        expect(command, Decision::NeedApproval);
    }
    expect("rmdir -p ./dir/leaf", Decision::Allow);
    let nodes = graph("rmdir -p ./dir*");
    assert!(nodes.iter().any(|n| matches!(
        &n.kind,
        NodeKind::PathFact {
            role: ResolvedPathRole::Target,
            resolution: PathResolution::BoundedPathSet { roots, may_escape: false },
            ..
        } if roots == &["/tmp/project/"]
    )));
}

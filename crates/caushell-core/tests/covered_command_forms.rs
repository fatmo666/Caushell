//! Guard and Graph regression only; all command strings are static test data.
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
        session_id: SessionId::new("covered-command-forms"),
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
fn expect(command: &str, expected: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, expected, "{command}: {result:#?}");
}
fn paths(command: &str) -> Vec<(ResolvedPathRole, PathResolution)> {
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
    staged
        .graph()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => Some((*role, resolution.clone())),
            _ => None,
        })
        .collect()
}
#[test]
fn ffmpeg_local_media_and_stdio_are_allowed() {
    for cmd in [
        "ffmpeg -i input.mp4 output.mp4",
        "ffmpeg -i input.mp4 -f flv -",
        "ffmpeg -i a -i b -c:v libx264 first.mp4 second.mp4",
        "cat input | ffmpeg -f image2pipe -framerate 30 -vcodec mjpeg -i - -vcodec libx264 -profile:v baseline -level 3.0 -movflags +faststart -crf 19 -pix_fmt yuv420p -r 30 out.mp4",
    ] {
        expect(cmd, Decision::Allow);
    }
}
#[test]
fn ffmpeg_preserves_external_writes_and_opaque_control_surfaces() {
    for cmd in [
        "ffmpeg -i input /opt/shared/out",
        "ffmpeg -i a first.mp4 /opt/shared/second.mp4",
        "ffmpeg -i in -vf 'movie=/opt/shared/file' out.mp4",
        "ffmpeg -i in -f hls out.m3u8",
        "ffmpeg -f image2pipe -i - -f hls out.m3u8",
        "ffmpeg -i in https://collector.example/out",
        "ffmpeg -i in file:/opt/shared/out",
        "ffmpeg -i in -pass 1 out.mp4",
        "ffmpeg -i in -progress /opt/shared/log out",
        "ffmpeg -i in frame%03d.png",
        "ffmpeg -i in --unknown out",
        "ffmpeg -i in \"$target\"",
        "ffmpeg -f lavfi -i anullsrc -af ladspa=file=/opt/lib.so out.wav",
    ] {
        expect(cmd, Decision::NeedApproval);
    }
}
#[test]
fn ffmpeg_graph_keeps_all_explicit_paths_and_sibling_output_families() {
    let p = paths("ffmpeg -i a.mp4 -i b.mp4 first.mp4 /opt/shared/second.mp4");
    for (role, path) in [
        (ResolvedPathRole::Read, "/tmp/project/a.mp4"),
        (ResolvedPathRole::Read, "/tmp/project/b.mp4"),
        (ResolvedPathRole::Write, "/tmp/project/first.mp4"),
        (ResolvedPathRole::Write, "/opt/shared/second.mp4"),
    ] {
        assert!(
            p.iter()
                .any(|(r, v)| *r == role && v.concrete_path() == Some(path)),
            "{role:?} {path}: {p:#?}"
        );
    }
    assert!(
        p.iter().any(|(r, v)| *r == ResolvedPathRole::Write
            && matches!(v, PathResolution::BoundedPathSet { .. })),
        "{p:#?}"
    );
    let stdio = paths("ffmpeg -i - -f flv -");
    assert!(
        !stdio
            .iter()
            .any(|(_, p)| p.concrete_path() == Some("/tmp/project/-")),
        "{stdio:#?}"
    );
    let generated = paths("ffmpeg -f lavfi -i anullsrc -af ladspa=file=/opt/lib.so local.wav");
    assert!(
        !generated
            .iter()
            .any(|(_, p)| p.concrete_path() == Some("/tmp/project/anullsrc")),
        "{generated:#?}"
    );
    let help = paths("ffmpeg -h -i input.mp4");
    assert!(
        !help
            .iter()
            .any(|(_, p)| p.concrete_path() == Some("/tmp/project/input.mp4")),
        "{help:#?}"
    );
    expect("ffmpeg -i \"$source\" out", Decision::Allow);
    assert!(
        paths("ffmpeg -i \"$source\" out")
            .iter()
            .any(|(r, p)| *r == ResolvedPathRole::Read && p.concrete_path().is_none())
    );
}

#[test]
fn ffmpeg_nested_output_keeps_existing_runtime_path_domain() {
    let local = r"find ./media/ -type f -exec ffmpeg -i {} {}.mp3 \;";
    let p = paths(local);
    assert!(p.iter().any(|(r,v)| *r==ResolvedPathRole::Write && matches!(v,PathResolution::BoundedPathSet {roots,may_escape:false} if roots.contains(&"/tmp/project/media".into()))),"{p:#?}");
    expect(local, Decision::Allow);
    expect(
        r"find /opt/shared -type f -exec ffmpeg -i {} {}.mp3 \;",
        Decision::NeedApproval,
    );
}
#[test]
fn ip_queries_are_allowed_but_mutations_and_ambiguous_operations_are_not() {
    for cmd in [
        "ip addr show en0",
        "ip -br -4 address",
        "ip -j route",
        "ip neighbour show",
        "ip tcp_metrics show",
        "ip link show",
        "ip -n lab addr show dev eth0",
        "ip route get 192.0.2.1",
    ] {
        expect(cmd, Decision::Allow);
    }
    for cmd in [
        "ip route flush table main",
        "ip addr add 192.0.2.1/24 dev eth0",
        "ip link set eth0 down",
        "ip link s eth0 down",
        "ip route \"$operation\"",
        "ip \"$object\"",
        "ip route show >/opt/shared/log",
        "ip -batch commands",
        "ip netns delete lab",
        "ip netns exec lab rm /opt/shared/file",
        "ip --unknown addr",
    ] {
        expect(cmd, Decision::NeedApproval);
    }
}
#[test]
fn php_lint_is_read_only_without_clearing_execution_or_config_risks() {
    for cmd in [
        "php -l a.php",
        "php --syntax-check /opt/shared/a.php",
        "php -n -l a.php b.php",
        "printf CODE | php -l",
        "php -i | more",
        "php -m",
        r"find . -name '*.php' -exec php -l {} \;",
        "find . -name '*.php' -print0 | xargs -0 -n1 php -l",
    ] {
        expect(cmd, Decision::Allow);
    }
    for cmd in [
        "php -r 'system(\"/bin/sh\");'",
        "php script.php",
        "php -f script.php",
        "php script.php -l",
        "php -l -r 'echo 1;'",
        "php -d extension=/opt/lib.so -l a.php",
        "php -c /opt/php.ini -i",
        "php -l a.php >/opt/shared/log",
        "php --unknown",
    ] {
        expect(cmd, Decision::NeedApproval);
    }
    assert!(paths("php -l /opt/shared/a.php").iter().any(
        |(r, p)| *r == ResolvedPathRole::Read && p.concrete_path() == Some("/opt/shared/a.php")
    ));
}

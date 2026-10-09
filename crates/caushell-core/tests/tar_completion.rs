//! Static guard checks; no shell sample is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("tar-completion"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "tar-static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(command: &str, decision: Decision) {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, decision, "{command}: {r:#?}");
}

#[test]
fn ordinary_archive_updates_and_metadata_options_are_allowed() {
    for command in [
        "tar -rf images.tar input.png",
        "tar rvf images.tar input.png",
        "tar uf a.tar input",
        "find . -iname '*.png' -exec tar -rf images.tar {} \\;",
        "find . -type f -name '*.java' | xargs tar rvf myfile.tar",
        "find data -print0 | tar --null -T - --create -f archive.tar",
        "tar cf archive.tar --files-from=- --no-recursion",
        "tar -I pbzip2 -cf OUTPUT.tar.bz2 /DIR_TO_ZIP/",
        "tar -C my_dir -zcvf my_dir.tar.gz .[^.]* ..?* *",
        "tar --mtime='2023-01-01' --owner=0 --group=0 -zcf archive.tgz /etc",
        "tar -N '2014-02-01 18:00:00' -jcvf archive.tar.bz2 files",
        "tar -cf backup.tar -X /etc/exclude.txt /etc",
        "tar -cf - input",
        "tar -cf - input > local.tar",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn real_outside_or_unknown_archive_writes_keep_existing_approval() {
    for command in [
        "tar -rf /opt/shared/images.tar input",
        "tar rvf /opt/shared/images.tar input",
        "tar --update --file=/opt/shared/images.tar input",
        "tar -Af /opt/shared/a.tar local.tar",
        "tar --delete -f /opt/shared/a.tar member",
        "tar -rf \"$archive\" input",
        "tar uf \"$archive\" input",
        "tar -cf - input > /opt/shared/a.tar",
        "tar -c input",
        "tar c input",
        "tar cv --files-from=-",
        "tar -xf -",
        "tar xf -",
        "tar x",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn member_deletion_is_an_archive_write_not_host_file_deletion() {
    let mut core = ShellQueryCore::new();
    let r = core.check(request("tar --delete -f local.tar /etc/passwd"));
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
    let graph = core
        .session_graph(&SessionId::new("tar-completion"))
        .unwrap();
    assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/local.tar"))));
    assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write | ResolvedPathRole::Target, resolution, .. } if resolution.concrete_path() == Some("/etc/passwd"))));
}

#[test]
fn callbacks_and_source_removal_keep_independent_risk_checks() {
    for command in [
        "tar -rf local.tar input --checkpoint-action='exec=rm /opt/shared/file'",
        "tar rvf local.tar input --checkpoint-action='exec=rm /opt/shared/file'",
        "tar -cf local.tar /opt/shared/input --remove-files",
        "tar -cf local.tar -T - --remove-files",
        "tar -cf local.tar -C /opt/shared input --remove-files",
        "tar -I 'sh -c \"rm /opt/shared/file\"' -cf local.tar input",
        "tar -xf archive.tar --to-command='sh'",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn stdout_extraction_has_no_fabricated_member_write() {
    for command in [
        "tar -xOf a.tar",
        "tar xOf a.tar",
        "tar xvf a.tar --to-stdout",
        "tar -xOf -",
        "tar xO",
        "tar -xO",
        "tar -tf -",
    ] {
        expect(command, Decision::Allow);
    }
    expect(
        "tar -xOf a.tar > /opt/shared/output",
        Decision::NeedApproval,
    );
}

#[test]
fn files_and_stream_markers_enter_the_graph_with_correct_roles() {
    for command in [
        "tar -cf local.tar -T list.txt",
        "tar cf local.tar -T list.txt",
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(core.check(request(command)).decision, Decision::Allow);
        let graph = core
            .session_graph(&SessionId::new("tar-completion"))
            .unwrap();
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/list.txt"))));
    }
    for command in ["tar -cf - input", "tar -cf local.tar -T -", "tar tf -"] {
        let mut core = ShellQueryCore::new();
        assert_eq!(core.check(request(command)).decision, Decision::Allow);
        let graph = core
            .session_graph(&SessionId::new("tar-completion"))
            .unwrap();
        assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { resolution, .. } if resolution.concrete_path() == Some("/tmp/project/-"))), "{command}");
    }
}

#[test]
fn member_directory_does_not_rebase_the_archive_destination() {
    let mut core = ShellQueryCore::new();
    let r = core.check(request("tar -C /opt/shared -cf local.tar input"));
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
    let graph = core
        .session_graph(&SessionId::new("tar-completion"))
        .unwrap();
    assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution, .. } if resolution.concrete_path() == Some("/tmp/project/local.tar"))));
    assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Write, resolution, .. } if resolution.concrete_path() == Some("/opt/shared/local.tar"))));
}

#[test]
fn old_style_archive_opens_keep_descriptor_stream_semantics() {
    for (command, role, alias, descriptor) in [
        (
            "tar cf /dev/stdout input",
            ResolvedPathRole::Write,
            "/dev/stdout",
            "1",
        ),
        (
            "tar tf /dev/stdin",
            ResolvedPathRole::Read,
            "/dev/stdin",
            "0",
        ),
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        let graph = core
            .session_graph(&SessionId::new("tar-completion"))
            .unwrap();
        assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: r, resolution, .. } if *r == role && resolution.concrete_path() == Some(alias))), "{command}");
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::DescriptorStream { descriptor: fd, unresolved: false, .. } } if fd == descriptor)), "{command}");
    }
    expect(
        "tar cf /dev/stdout input > /opt/shared/archive.tar",
        Decision::NeedApproval,
    );
}

#[test]
fn unsupported_or_incomplete_arities_are_not_silently_accepted() {
    for command in [
        "tar -cf a.tar -T",
        "tar -I -cf a.tar input",
        "tar cIf gzip a.tar input",
        "tar -cf a.tar --unknown-control input",
        "tar -cf a.tar",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

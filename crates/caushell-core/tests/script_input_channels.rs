use caushell_core::ShellQueryCore;
use caushell_graph::{EdgeKind, NodeKind};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("script-input-channels"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
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

#[test]
fn known_shell_streams_use_payload_semantics_for_every_shell_profile() {
    for command in [
        "printf 'echo safe\\n' | source /dev/stdin",
        "printf 'echo safe\\n' | sh /dev/stdin",
        "bash /dev/fd/3 3<<< 'echo safe'",
        "zsh /proc/self/fd/3 3<<< 'echo safe'",
        "source /dev/null",
        "sh /dev/null",
        "bash /dev/null",
        "source /dev/fd/3 3<&-",
        "sh /dev/fd/3 3<&-",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn stream_graph_edges_keep_script_source_identity_without_a_fake_device_file() {
    for command in [
        "source /dev/stdin <<< 'echo safe'",
        "sh /dev/fd/3 3<<< 'echo safe'",
        "zsh /proc/self/fd/3 3<<< 'echo safe'",
    ] {
        let mut core = ShellQueryCore::new();
        let r = core.check(request(command));
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        let graph = core
            .session_graph(&SessionId::new("script-input-channels"))
            .unwrap();
        assert!(!graph.nodes().any(|node| matches!(&node.kind,
            NodeKind::PathFact { resolution, purpose: Some(ResolvedPathPurpose::ScriptSource), .. }
            if resolution.concrete_path().is_some_and(|p| p.starts_with("/dev/") || p.starts_with("/proc/")))));
        assert!(
            graph.nodes().any(|node| matches!(
                &node.kind,
                NodeKind::ProvenanceArtifact {
                    artifact: ProvenanceArtifact::InlineShellContent { .. }
                }
            ) && graph.incoming_edges(&node.id).any(|edge| edge.kind
                == EdgeKind::Consumes
                && matches!(&edge.semantics, Some(ProvenanceEdgeSemantics::Consume {
                    consume_kind: ProvenanceConsumeKind::ScriptSource, slot_name: Some(slot), ..
                }) if slot == "script_path"))),
            "{command}"
        );
    }
}

#[test]
fn descriptors_pointing_to_real_files_keep_the_real_path_and_policy() {
    for command in [
        "source /dev/stdin <./config.sh",
        "sh /dev/fd/3 3<./config.sh",
    ] {
        let mut core = ShellQueryCore::new();
        let r = core.check(request(command));
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        let graph = core
            .session_graph(&SessionId::new("script-input-channels"))
            .unwrap();
        assert!(graph.nodes().any(|node| matches!(&node.kind,
            NodeKind::PathFact { resolution, purpose: Some(ResolvedPathPurpose::ScriptSource), .. }
            if resolution.concrete_path() == Some("/bench/workspace/config.sh"))));
    }
    for command in [
        "source /dev/stdin </opt/config.sh",
        "sh /dev/fd/3 3</opt/config.sh",
        "bash -c 'source /dev/fd/3' 3</opt/config.sh",
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            r.reasons
                .iter()
                .any(|reason| reason.contains("/opt/config.sh")),
            "{:?}",
            r.reasons
        );
        assert!(
            !r.reasons
                .iter()
                .any(|reason| reason.starts_with("script source path /dev/"))
        );
    }
}

#[test]
fn streams_do_not_inherit_file_execution_exemptions_or_hide_known_effects() {
    for command in [
        "source /dev/stdin",
        "sh /dev/stdin",
        "source /dev/fd/9",
        "source /proc/1234/fd/0",
        "source /dev/urandom",
        "ksh /dev/stdin <<< 'echo safe'",
        "python /dev/stdin <<< 'print(1)'",
        "source /dev/stdin <<< 'touch /opt/out'",
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
    }
    for command in [
        "printf 'rm -rf /\\n' | source /dev/stdin",
        "bash /dev/fd/3 3<<< 'rm -rf /'",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Deny, "{command}: {:?}", r.reasons);
        assert!(
            r.decision_trace
                .derived_invocations
                .iter()
                .any(|c| c.command_name.as_deref() == Some("rm"))
        );
    }
}

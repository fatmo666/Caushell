use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, ProvenanceArtifact, ResolvedPathRole, RuleId,
    RuntimeMetadata, SessionId, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("frequency-profile-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.to_string(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project".to_string()),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".to_string(),
            tool_name: Some("Bash".to_string()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".to_string()),
        workspace_root: Some("/tmp/project".to_string()),
    }
}

#[test]
fn pdftotext_graph_preserves_exact_explicit_and_implicit_writes() {
    for (command, target) in [
        ("pdftotext a.pdf out.txt", "/tmp/project/out.txt"),
        ("pdftotext a.pdf", "/tmp/project/a.txt"),
        ("pdftotext a.PDF", "/tmp/project/a.txt"),
        ("pdftotext a.Pdf", "/tmp/project/a.Pdf.txt"),
        ("pdftotext -htmlmeta a.pdf", "/tmp/project/a.html"),
        ("pdftotext -bbox a.PDF", "/tmp/project/a.html"),
        ("pdftotext -bbox-layout a", "/tmp/project/a.html"),
        ("pdftotext -tsv a.pdf", "/tmp/project/a.txt"),
        ("pdftotext - stdin.txt", "/tmp/project/stdin.txt"),
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        let writes: Vec<_> = core
            .session_graph(&SessionId::new("frequency-profile-test"))
            .unwrap()
            .nodes()
            .filter_map(|n| match &n.kind {
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write,
                    resolution,
                    ..
                } => resolution.concrete_path(),
                _ => None,
            })
            .collect();
        assert_eq!(writes, vec![target], "{command}");
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.decision_trace.findings
        );
    }
}

#[test]
fn pdftotext_outside_and_unknown_writes_require_approval_but_reads_do_not() {
    for command in [
        "pdftotext /etc/input.pdf",
        "pdftotext a.pdf /etc/out.txt",
        "pdftotext - /etc/out.txt",
        "pdftotext a.pdf \"$OUTPUT\"",
        "pdftotext \"$INPUT\"",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {:?}",
            response.decision_trace.findings
        );
    }
    for command in [
        "pdftotext /etc/input.pdf -",
        "pdftotext - -",
        "pdftotext -h",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.decision_trace.findings
        );
        assert!(
            !core
                .session_graph(&SessionId::new("frequency-profile-test"))
                .unwrap()
                .nodes()
                .any(|n| matches!(
                    n.kind,
                    NodeKind::PathFact {
                        role: ResolvedPathRole::Write,
                        ..
                    }
                )),
            "{command}"
        );
    }
}

#[test]
fn bc_file_reads_and_nl2bash_pipeline_keep_data_not_command_semantics() {
    for command in [
        "bc /etc/expression.bc",
        "seq -s '*' 1 500 | bc",
        "echo '2+2' | bc",
        "bc -l math.bc",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.decision_trace.findings
        );
        let graph = core
            .session_graph(&SessionId::new("frequency-profile-test"))
            .unwrap();
        assert!(
            !graph.nodes().any(|n| matches!(
                n.kind,
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write,
                    ..
                }
            )),
            "{command}"
        );
        if command == "bc /etc/expression.bc" {
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { role: ResolvedPathRole::Read, resolution, .. } if resolution.concrete_path() == Some("/etc/expression.bc"))));
        }
    }
}

#[test]
fn pdftotext_protocol_inputs_do_not_drop_explicit_or_implicit_writes() {
    for command in [
        "pdftotext fd://0 /etc/out.txt",
        "pdftotext fd://4 /etc/out.txt",
        "pdftotext https://example.test/a.pdf /etc/out.txt",
        "pdftotext fd://4",
        "pdftotext https://example.test/a.pdf",
        "pdftotext file:///etc/a.PDF",
        "pdftotext -htmlmeta https://example.test/a.pdf",
        "pdftotext -bbox file:///etc/a.PDF",
        "pdftotext -bbox-layout fd://4",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(response.decision, Decision::NeedApproval, "{command}");
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {:?}",
            response.decision_trace.findings
        );
    }
    for (command, target) in [
        ("pdftotext fd://4 -", None),
        ("pdftotext fd://0 -", None),
        ("pdftotext fd://4 out.txt", Some("/tmp/project/out.txt")),
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(response.decision, Decision::Allow, "{command}");
        let graph = core
            .session_graph(&SessionId::new("frequency-profile-test"))
            .unwrap();
        let writes: Vec<_> = graph
            .nodes()
            .filter_map(|n| match &n.kind {
                NodeKind::PathFact {
                    role: ResolvedPathRole::Write,
                    resolution,
                    ..
                } => resolution.concrete_path(),
                _ => None,
            })
            .collect();
        assert_eq!(writes, target.into_iter().collect::<Vec<_>>(), "{command}");
        assert!(
            !graph.nodes().any(|n| matches!(
                n.kind,
                NodeKind::PathFact {
                    role: ResolvedPathRole::Read,
                    ..
                }
            )),
            "{command}"
        );
    }
}

#[test]
fn getent_keeps_nl2bash_queries_read_only_without_fake_operand_paths() {
    for command in [
        "getent passwd | cut -d: -f1",
        "getent group | cut -d: -f1 | sort | cat -n",
        "getent -s files passwd 1000",
        "getent --service=dns hosts example.test",
    ] {
        let mut core = ShellQueryCore::new();
        let response = core.check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.decision_trace.findings
        );
        let graph = core
            .session_graph(&SessionId::new("frequency-profile-test"))
            .unwrap();
        assert!(!graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact { normalized_command_name: Some(name), slot_name, .. } if name == "getent" && ["database", "lookup_keys", "host_keys", "service_overrides"].contains(&slot_name.as_str()))));
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|fact| fact.normalized_command_name == "getent"
                    && fact.loads_tool_config
                    && fact.loads_in_process_code)
        );
        assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {resolution, ..} if resolution.concrete_path() == Some("/etc/nsswitch.conf"))), "{command}");
        if command.contains("hosts") {
            assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::ProvenanceArtifact {artifact: ProvenanceArtifact::NetworkEndpoint {endpoint, ..}} if endpoint == "example.test")), "{command}");
        }
    }
}

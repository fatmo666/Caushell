//! Classify command text and inspect evidence only; no package manager executes.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PolicyConfig, ProvenanceArtifact, RuleAction,
    RuleId, RulePolicyEntry, RuntimeMetadata, SessionId, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("package-locator-contract"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn assert_source(command: &str, expected: Decision, source: &str) {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(
        response.decision, expected,
        "{command}: {:?}",
        response.decision_trace.findings
    );
    assert!(
        response
            .decision_trace
            .findings
            .iter()
            .any(
                |finding| finding.rule_id == RuleId::ImportedPackageExecution
                    && finding.message.contains(source)
            ),
        "{command}: {:?}",
        response.decision_trace.findings
    );
}

#[test]
fn definition_filename_changes_do_not_change_the_decision() {
    for name in [
        "input",
        "environment.yml",
        "requirements.txt",
        "custom.spec",
    ] {
        assert_source(
            &format!("pip install -r {name}"),
            Decision::Allow,
            "requirement_file",
        );
        assert_source(
            &format!("conda env create -p env -f {name}"),
            Decision::Allow,
            "requirement_file",
        );
    }
}

#[test]
fn definition_classification_does_not_approve_an_unknown_or_outside_environment() {
    for command in [
        "conda env create -n dev -f input",
        "conda env create -p /opt/env -f environment.yml",
    ] {
        assert_source(command, Decision::NeedApproval, "requirement_file");
        let response = ShellQueryCore::new().check(request(command));
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation)
        );
    }
}

#[test]
fn remote_definitions_and_unknown_values_still_require_approval() {
    for command in [
        "pip install -r https://example.test/input",
        "conda env create -p env -f https://example.test/input",
    ] {
        assert_source(command, Decision::NeedApproval, "direct_url");
    }
    for command in [
        "pip install -r \"$FILE\"",
        "pip install -r \"https://example.test/$FILE\"",
        "pip install -r s3://bucket/input",
        "conda env create -p env -f \"$FILE\"",
    ] {
        assert_source(command, Decision::NeedApproval, "unknown_dynamic");
    }
}

#[test]
fn semantic_role_not_filename_selects_the_package_source_class() {
    assert_source("pip install requests.txt", Decision::Allow, "registry_ref");
    assert_source(
        "pip install -r requests.txt",
        Decision::Allow,
        "requirement_file",
    );
    assert_source("pip install -e requests.txt", Decision::Allow, "local_path");
}

#[test]
fn known_argv_value_is_not_reexpanded_as_shell_source() {
    let mut req = request("pip install -r \"$FILE\"");
    req.shell_state_before =
        req.shell_state_before
            .with_exact_scalar_variable("FILE", "input$LITERAL", true);
    let mut core = ShellQueryCore::new();
    let response = core.check(req.clone());
    assert_eq!(
        response.decision,
        Decision::Allow,
        "{:?}",
        response.decision_trace.findings
    );
    assert!(core.session_graph(&req.session_id).unwrap().nodes().any(|node|
        matches!(&node.kind, NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::ImportedPackage { source_path: Some(path), .. } } if path == "/tmp/project/input$LITERAL")));
}

#[test]
fn package_rule_configuration_still_controls_definition_sources() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::ImportedPackageExecution,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    for command in [
        "pip install -r input",
        "conda env create -p env -f environment.yml",
    ] {
        assert_eq!(
            ShellQueryCore::with_policy(policy.clone())
                .check(request(command))
                .decision,
            Decision::Deny
        );
    }
}

//! Classify command text and inspect evidence only; no package manager executes.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::{
    CheckRequest, CheckResponse, CommandSequenceNo, Decision, EvidenceKind,
    ImportedPackageExecutionSinkEvidence, PackageLocatorKind, PolicyConfig, ProvenanceArtifact,
    RuleAction, RuleId, RulePolicyEntry, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
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

fn package_sinks(response: &CheckResponse) -> Vec<&ImportedPackageExecutionSinkEvidence> {
    response
        .decision_trace
        .evidence
        .iter()
        .filter_map(|evidence| match &evidence.kind {
            EvidenceKind::ImportedPackageExecution(imported) => Some(&imported.sink),
            _ => None,
        })
        .collect()
}

#[test]
fn mixed_package_sources_are_order_independent_across_managers() {
    let url = "https://packages.example.test/other.pkg";
    for prefix in ["pip install", "npm install", "conda install -p env"] {
        for args in [format!("numpy {url}"), format!("{url} numpy")] {
            let command = format!("{prefix} {args}");
            let response = ShellQueryCore::new().check(request(&command));
            assert_eq!(
                response.decision,
                Decision::NeedApproval,
                "{command}: {response:?}"
            );
            let sinks = package_sinks(&response);
            assert_eq!(sinks.len(), 2, "{command}: {sinks:?}");
            assert!(
                sinks
                    .iter()
                    .any(|s| s.locator == "numpy"
                        && s.locator_kind == PackageLocatorKind::RegistryRef)
            );
            assert!(
                sinks
                    .iter()
                    .any(|s| s.locator == url && s.locator_kind == PackageLocatorKind::DirectUrl)
            );
        }
    }
}

#[test]
fn sources_in_other_parameter_slots_cannot_be_masked_by_a_registry_package() {
    for command in [
        "pip install numpy -r https://packages.example.test/input",
        "pip install -r https://packages.example.test/input numpy",
        "conda install -p env numpy -c https://packages.example.test",
        "conda install -p env -c https://packages.example.test numpy",
        "conda install -p env numpy -f https://packages.example.test/input",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:?}"
        );
        let sinks = package_sinks(&response);
        assert_eq!(sinks.len(), 2, "{command}: {sinks:?}");
        assert!(
            sinks
                .iter()
                .any(|s| s.locator_kind == PackageLocatorKind::DirectUrl)
        );
        assert!(
            sinks
                .iter()
                .any(|s| s.locator_kind == PackageLocatorKind::RegistryRef)
        );
    }
}

#[test]
fn all_six_source_kinds_keep_evidence_without_stopping_at_the_first_approval() {
    let response = ShellQueryCore::new().check(request(
        "pip install numpy ./dist/pkg.whl -r input https://packages.example.test/pkg.whl git+https://packages.example.test/repo.git \"$PKG\"",
    ));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:?}");
    let sinks = package_sinks(&response);
    assert_eq!(sinks.len(), 6, "{sinks:?}");
    for kind in [
        PackageLocatorKind::RegistryRef,
        PackageLocatorKind::LocalPath,
        PackageLocatorKind::RequirementFile,
        PackageLocatorKind::DirectUrl,
        PackageLocatorKind::VcsUrl,
        PackageLocatorKind::UnknownDynamic,
    ] {
        assert_eq!(
            sinks.iter().filter(|s| s.locator_kind == kind).count(),
            1,
            "{kind:?}: {sinks:?}"
        );
    }
    assert_eq!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .filter(|p| p.rule_id == RuleId::ImportedPackageExecution
                && p.decision == Decision::NeedApproval)
            .count(),
        3
    );
}

#[test]
fn repeated_sources_are_deduplicated_only_within_the_same_invocation_and_kind() {
    let response = ShellQueryCore::new().check(request(
        "pip install https://packages.example.test/pkg https://packages.example.test/pkg -r https://packages.example.test/pkg",
    ));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert_eq!(package_sinks(&response).len(), 1, "{response:?}");
    assert_eq!(
        response
            .decision_trace
            .findings
            .iter()
            .filter(|f| f.rule_id == RuleId::ImportedPackageExecution)
            .count(),
        1
    );

    let response = ShellQueryCore::new().check(request("pip install input -r input -e input"));
    assert_eq!(response.decision, Decision::Allow);
    let sinks = package_sinks(&response);
    assert_eq!(sinks.len(), 3, "{sinks:?}");
    for kind in [
        PackageLocatorKind::RegistryRef,
        PackageLocatorKind::LocalPath,
        PackageLocatorKind::RequirementFile,
    ] {
        assert!(
            sinks
                .iter()
                .any(|s| s.locator == "input" && s.locator_kind == kind)
        );
    }

    let response = ShellQueryCore::new().check(request(
        "pip install https://packages.example.test/pkg; pip install https://packages.example.test/pkg",
    ));
    assert_eq!(response.decision, Decision::NeedApproval);
    let sinks = package_sinks(&response);
    assert_eq!(sinks.len(), 2, "{sinks:?}");
    assert_ne!(sinks[0].node_id, sinks[1].node_id);
}

#[test]
fn explicit_package_policy_applies_to_every_source_and_keeps_all_evidence() {
    for (action, decision) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::ImportedPackageExecution,
            RulePolicyEntry::new(action),
        );
        let response = ShellQueryCore::with_policy(policy).check(request(
            "pip install numpy https://packages.example.test/pkg git+https://packages.example.test/repo.git",
        ));
        assert_eq!(response.decision, decision, "{action:?}: {response:?}");
        assert_eq!(
            package_sinks(&response).len(),
            3,
            "{action:?}: {response:?}"
        );
    }
}

#[test]
fn nested_package_calls_check_all_child_sources_and_preserve_child_identity() {
    for command in [
        "env pip install numpy https://packages.example.test/pkg",
        "bash -c 'pip install numpy https://packages.example.test/pkg'",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:?}"
        );
        let sinks = package_sinks(&response);
        assert_eq!(sinks.len(), 2, "{command}: {sinks:?}");
        assert!(
            sinks.iter().all(|s| s.depth == 1
                && s.command == "pip install numpy https://packages.example.test/pkg")
        );
        assert_eq!(sinks[0].node_id, sinks[1].node_id);
    }
}

#[test]
fn download_preview_and_query_do_not_trigger_package_execution_even_under_deny() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::ImportedPackageExecution,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    for command in [
        "conda install -p env --download-only numpy https://packages.example.test/pkg",
        "conda create -p env --dry-run numpy https://packages.example.test/pkg",
        "conda search -c https://packages.example.test numpy",
        "printf 'numpy https://packages.example.test/pkg'",
    ] {
        let response = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:?}"
        );
        assert!(
            package_sinks(&response).is_empty(),
            "{command}: {response:?}"
        );
        assert!(
            !response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ImportedPackageExecution)
        );
    }
}

#[test]
fn earlier_session_package_sources_are_not_rechecked_for_later_calls() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::ImportedPackageExecution,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    let mut core = ShellQueryCore::with_policy(policy);
    let first = core.check(request("pip install https://packages.example.test/pkg"));
    assert_eq!(first.decision, Decision::Allow);
    assert_eq!(package_sinks(&first).len(), 1);
    let mut second_request = request("pip install numpy");
    second_request.sequence_no = CommandSequenceNo::new(2);
    let second = core.check(second_request);
    assert_eq!(second.decision, Decision::Allow);
    let sinks = package_sinks(&second);
    assert_eq!(sinks.len(), 1, "{second:?}");
    assert_eq!(sinks[0].locator, "numpy");
    assert_eq!(sinks[0].sequence_no, CommandSequenceNo::new(2));
}

#[test]
fn package_approval_does_not_override_a_stronger_neighboring_denial() {
    let response = ShellQueryCore::new().check(request(
        "pip install numpy https://packages.example.test/pkg; rm -rf /",
    ));
    assert_eq!(response.decision, Decision::Deny, "{response:?}");
    assert_eq!(package_sinks(&response).len(), 2);
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::ImportedPackageExecution
                && p.decision == Decision::NeedApproval)
    );
}

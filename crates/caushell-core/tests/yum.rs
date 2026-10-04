//! Container-only static decision and staged Graph checks. No Yum command runs.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, DecisionAssemblyPass, ExtractExecutionSemanticsPass,
    ExtractImportedPackageProvenancePass, ExtractPathFactsPass, ExtractPipelineFlowPass,
    ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("yum-static-scope"),
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
fn check(command: &str, expected: Decision) -> CheckResponse {
    check_request(request(command), expected)
}
fn check_request(req: CheckRequest, expected: Decision) -> CheckResponse {
    let mut core = ShellQueryCore::new();
    let response = core.check(req.clone());
    assert_eq!(
        response.decision, expected,
        "{}: {:?}",
        req.command, response.decision_trace
    );
    assert!(
        !response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::NoProfile),
        "{}",
        req.command
    );
    if expected != Decision::Allow {
        assert!(
            !core
                .session_graph(&req.session_id)
                .unwrap()
                .nodes()
                .any(|n| matches!(
                    n.kind,
                    NodeKind::PathFact {
                        role: ResolvedPathRole::Write | ResolvedPathRole::Target,
                        ..
                    }
                ))
        );
    }
    response
}
fn proposed(response: &CheckResponse, rule: RuleId) -> bool {
    response
        .decision_trace
        .decision_proposals
        .iter()
        .any(|p| p.rule_id == rule)
}
fn facts(
    req: CheckRequest,
) -> (
    Vec<(ResolvedPathRole, PathResolution)>,
    Vec<ProvenanceArtifact>,
) {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_session_transform_pass(ExtractImportedPackageProvenancePass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(req);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let mut paths = vec![];
    let mut packages = vec![];
    for node in staged.graph().nodes() {
        match &node.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => paths.push((*role, resolution.clone())),
            NodeKind::ProvenanceArtifact {
                artifact: a @ ProvenanceArtifact::ImportedPackage { .. },
            } => packages.push(a.clone()),
            _ => {}
        }
    }
    (paths, packages)
}
fn has_write(paths: &[(ResolvedPathRole, PathResolution)], expected: &str) -> bool {
    paths.iter().any(|(role, path)| {
        *role == ResolvedPathRole::Write && path.concrete_path() == Some(expected)
    })
}

#[test]
fn system_transactions_require_workspace_approval_not_root_delete_denial() {
    for c in [
        "yum install curl",
        "yum update",
        "yum upgrade",
        "yum reinstall curl",
        "yum distro-sync",
        "yum remove curl",
        "yum erase curl",
        "yum autoremove",
        "yum localinstall package.rpm",
        "yum -C --assumeno install curl",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(proposed(&r, RuleId::OutsideWorkspaceMutation), "{c}");
        assert!(
            !r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.decision == Decision::Deny)
        );
        let (paths, _) = facts(request(c));
        assert!(has_write(&paths, "/"), "{c}: {paths:?}");
        assert!(
            !paths.iter().any(
                |(role, p)| *role == ResolvedPathRole::Target && p.concrete_path() == Some("/")
            ),
            "{c}"
        );
    }
}

#[test]
fn workspace_installation_roots_and_last_overrides_use_existing_path_guard() {
    for c in [
        "yum --installroot /tmp/project/rootfs install curl",
        "yum install --installroot=/tmp/project/rootfs -y curl",
        "yum --installroot /opt/old install --installroot /tmp/project/rootfs curl",
        "yum --installroot=/tmp/project/rootfs update",
        "yum remove --installroot=/tmp/project/rootfs curl",
        "yum --installroot=/tmp/project/rootfs autoremove",
    ] {
        let r = check(c, Decision::Allow);
        assert!(!proposed(&r, RuleId::OutsideWorkspaceMutation));
        let (paths, _) = facts(request(c));
        assert!(has_write(&paths, "/tmp/project/rootfs"), "{c}: {paths:?}");
        assert!(!has_write(&paths, "/opt/old"));
    }
}

#[test]
fn remote_and_ambiguous_sources_remain_independent_of_a_workspace_root() {
    for (c, kind) in [
        (
            "yum --installroot=/tmp/project/rootfs install https://example.test/pkg.rpm",
            PackageLocatorKind::DirectUrl,
        ),
        (
            "yum --installroot=/tmp/project/rootfs install curl https://example.test/pkg",
            PackageLocatorKind::DirectUrl,
        ),
        (
            "yum --installroot=/tmp/project/rootfs install package.rpm",
            PackageLocatorKind::UnknownDynamic,
        ),
        (
            "yum --installroot=/tmp/project/rootfs install ./package.rpm",
            PackageLocatorKind::UnknownDynamic,
        ),
        (
            "yum --installroot=/tmp/project/rootfs install /usr/bin/cc",
            PackageLocatorKind::UnknownDynamic,
        ),
        (
            "yum --installroot=/tmp/project/rootfs install \"$PACKAGE\"",
            PackageLocatorKind::UnknownDynamic,
        ),
        (
            "yum --installroot=/tmp/project/rootfs localinstall s3://bucket/pkg.rpm",
            PackageLocatorKind::UnknownDynamic,
        ),
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(proposed(&r, RuleId::ImportedPackageExecution), "{c}");
        assert!(!proposed(&r, RuleId::OutsideWorkspaceMutation), "{c}");
        assert!(r.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::ImportedPackageExecution(evidence) if evidence.sink.locator_kind == kind)), "{c}");
    }
}

#[test]
fn localinstall_role_not_extension_records_actual_local_provenance() {
    for operand in [
        "extensionless",
        "custom.txt",
        "./package.rpm",
        "/opt/package.rpm",
    ] {
        let c = format!("yum --installroot=/tmp/project/rootfs localinstall {operand}");
        check(&c, Decision::Allow);
        let (_, packages) = facts(request(&c));
        assert!(
            packages.iter().any(|p| matches!(
                p,
                ProvenanceArtifact::ImportedPackage {
                    manager: PackageManagerKind::Yum,
                    locator_kind: PackageLocatorKind::LocalPath,
                    source_path: Some(_),
                    ..
                }
            )),
            "{c}: {packages:?}"
        );
    }
}

#[test]
fn default_queries_keep_an_unknown_incidental_write_but_no_transaction() {
    for c in [
        "yum list installed",
        "yum info curl",
        "yum search ssh",
        "yum provides /usr/bin/cc",
        "yum check-update",
        "yum history list",
        "yum history info 1",
        "yum group list",
        "yum groups info core",
        "yum makecache fast",
        "yum --noplugins -C list",
    ] {
        let r = check(c, Decision::Allow);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| !s.executes_imported_package_logic),
            "{c}"
        );
        let (paths, packages) = facts(request(c));
        assert!(
            paths
                .iter()
                .any(|(role, path)| *role == ResolvedPathRole::Write
                    && path.concrete_path().is_none()),
            "{c}: {paths:?}"
        );
        assert!(packages.is_empty(), "{c}");
        assert!(!has_write(&paths, "/"));
    }
}

#[test]
fn explicit_download_output_is_not_exempt_even_on_a_query() {
    for c in [
        "yum list --downloaddir=/etc/output",
        "yum makecache --downloaddir=/etc/output",
        "yum install --downloadonly --downloaddir=/etc/output curl",
    ] {
        assert!(
            proposed(
                &check(c, Decision::NeedApproval),
                RuleId::OutsideWorkspaceMutation
            ),
            "{c}"
        );
        let (paths, _) = facts(request(c));
        assert!(has_write(&paths, "/etc/output"), "{c}: {paths:?}");
    }
    for c in [
        "yum list --downloaddir=out",
        "yum install --downloadonly --downloaddir=out curl",
        "yum --downloaddir=/etc/old install --downloadonly --downloaddir=out curl",
    ] {
        check(c, Decision::Allow);
        let (paths, _) = facts(request(c));
        assert!(has_write(&paths, "/tmp/project/out"), "{c}: {paths:?}");
        assert!(!has_write(&paths, "/etc/old"));
    }
    check("yum list --downloaddir \"$OUTPUT\"", Decision::NeedApproval);
}

#[test]
fn downloads_do_not_become_execution_from_source_nodes_alone() {
    for c in [
        "yum install --downloadonly curl",
        "yum install --downloadonly https://example.test/pkg.rpm",
        "yum install --downloadonly \"$PACKAGE\"",
        "yum update --downloadonly",
    ] {
        let r = check(c, Decision::Allow);
        assert!(!proposed(&r, RuleId::ImportedPackageExecution));
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .all(|s| !s.executes_imported_package_logic),
            "{c}"
        );
        let (paths, _) = facts(request(c));
        assert!(!has_write(&paths, "/"), "{c}");
    }
}

#[test]
fn unknown_relative_outside_and_lexically_escaping_roots_do_not_fall_back() {
    for c in [
        "yum --installroot \"$ROOT\" install curl",
        "yum --installroot rootfs install curl",
        "yum --installroot '' install curl",
        "yum --installroot /tmp/project-other install curl",
        "yum --installroot /tmp/project/../../etc install curl",
        "yum --installroot /tmp/project/rootfs install curl --installroot /opt/root",
        "yum --installroot /tmp/project/rootfs install curl --installroot \"$ROOT\"",
    ] {
        assert!(
            proposed(
                &check(c, Decision::NeedApproval),
                RuleId::OutsideWorkspaceMutation
            ),
            "{c}"
        );
    }
}

#[test]
fn explicit_config_plugins_and_non_bash_languages_use_resolve_gap_approval() {
    for c in [
        "yum shell",
        "yum shell script",
        "yum load-transaction saved",
        "yum history redo 1",
        "yum groups install core",
        "yum clean plugins",
        "yum --setopt=installroot=/tmp/project/rootfs install curl",
        "yum --setopt=cachedir=/etc/output list",
        "yum --installroot=/tmp/project/rootfs --config=config install curl",
        "yum -cconfig list",
        "yum --enableplugin custom list",
        "yum --noplugins --setopt=plugins=1 list",
        "yum --future list",
        "yum -qZ list",
        "yum -Zq list",
        "yum install --future curl",
        "yum install --installroot",
    ] {
        let r = check(c, Decision::NeedApproval);
        assert!(
            r.decision_trace.execution_semantics.iter().any(|s| {
                s.normalized_command_name == "yum" && s.operation_semantics_unresolved
            }),
            "{c}"
        );
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id.family() == RuleFamily::ResolveGap),
            "{c}: {:?}",
            r.decision_trace
        );
    }
}

#[test]
fn unknown_cache_deletion_is_not_an_incidental_write_or_root_deletion() {
    for c in [
        "yum clean all",
        "yum clean metadata",
        "yum --installroot=/tmp/project/rootfs clean packages",
    ] {
        assert!(
            proposed(
                &check(c, Decision::NeedApproval),
                RuleId::OutsideWorkspaceMutation
            ),
            "{c}"
        );
        let (paths, _) = facts(request(c));
        assert!(
            paths
                .iter()
                .any(|(role, path)| *role == ResolvedPathRole::Target
                    && path.concrete_path().is_none()),
            "{c}: {paths:?}"
        );
        assert!(
            !paths.iter().any(
                |(role, p)| *role == ResolvedPathRole::Target && p.concrete_path() == Some("/")
            )
        );
    }
}

#[test]
fn help_has_no_tool_mutation_but_shell_redirections_still_count() {
    for c in [
        "yum --version",
        "yum install curl --help --downloaddir=/etc/output",
    ] {
        check(c, Decision::Allow);
        assert!(facts(request(c)).0.is_empty(), "{c}");
    }
    assert!(proposed(
        &check("yum --help > /etc/output", Decision::NeedApproval),
        RuleId::OutsideWorkspaceMutation
    ));
}

#[test]
fn nested_dispatch_keeps_sources_targets_and_stronger_decisions() {
    for c in [
        "env yum install curl",
        "bash -c 'yum install curl'",
        "bash -c 'yum --installroot=/tmp/project/rootfs install https://example.test/pkg.rpm'",
    ] {
        check(c, Decision::NeedApproval);
    }
    check(
        "bash -c 'yum --installroot=/tmp/project/rootfs install curl'",
        Decision::Allow,
    );
    check("yum list; rm -rf /", Decision::Deny);
}

#[test]
fn option_terminator_does_not_turn_package_data_into_download_mode() {
    let r = check(
        "yum --installroot=/tmp/project/rootfs install -- --downloadonly",
        Decision::NeedApproval,
    );
    assert!(proposed(&r, RuleId::ImportedPackageExecution));
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.executes_imported_package_logic)
    );
}

#[test]
fn supplied_runtime_values_are_not_reexpanded_as_shell_text() {
    let mut req = request("yum --installroot \"$ROOT\" localinstall \"$FILE\"");
    req.shell_state_before = req
        .shell_state_before
        .with_exact_scalar_variable("ROOT", "/tmp/project/root$LITERAL", true)
        .with_exact_scalar_variable("FILE", "./input$LITERAL", true);
    check_request(req.clone(), Decision::Allow);
    let (paths, packages) = facts(req);
    assert!(has_write(&paths, "/tmp/project/root$LITERAL"));
    assert!(packages.iter().any(|p| matches!(p,
        ProvenanceArtifact::ImportedPackage { locator_kind: PackageLocatorKind::LocalPath,
            source_path: Some(path), .. } if path == "/tmp/project/input$LITERAL")));
}

#[test]
fn source_policy_can_deny_a_package_without_changing_destination_policy() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::ImportedPackageExecution,
        RulePolicyEntry {
            action: RuleAction::Deny,
            trust_sets: vec![],
        },
    );
    let r = ShellQueryCore::with_policy(policy).check(request(
        "yum --installroot=/tmp/project/rootfs install https://example.test/pkg.rpm",
    ));
    assert_eq!(r.decision, Decision::Deny, "{:?}", r.decision_trace);
    assert!(proposed(&r, RuleId::ImportedPackageExecution));
    assert!(!proposed(&r, RuleId::OutsideWorkspaceMutation));
}

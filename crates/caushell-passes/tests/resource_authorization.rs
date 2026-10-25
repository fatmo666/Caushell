use caushell_graph::SessionGraph;
use caushell_passes::*;
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::*;
use caushell_types::*;
use std::time::Duration;

#[test]
fn arbitrary_tool_names_follow_typed_effects_and_consumer_scoped_resources() {
    let registry = ManagedResourceRegistry::default();
    let owner = ResourceOwner {
        session_id: SessionId::new("declaration-test"),
        runtime_name: "host".into(),
        executor_instance_id: "executor".into(),
        namespace_id: "network".into(),
    };
    let instance = registry
        .register(
            ManagedResource {
                resource_id: "result-service".into(),
                instance_id: "generation-a".into(),
                owner: owner.clone(),
                endpoints: vec!["http://127.0.0.1:18891/results".into()],
            },
            Duration::from_secs(60),
        )
        .unwrap();
    let _grant = registry
        .grant(
            ResourcePermission {
                grant_id: "publish".into(),
                resource: instance.instance().clone(),
                owner: owner.clone(),
                domain: StateOperationDomain::RemoteResource,
                operation: StateOperationKind::Mutate,
            },
            Duration::from_secs(60),
        )
        .unwrap();
    let _route = registry
        .bind_route(
            ResourceRoute {
                route_id: "result-name".into(),
                resource: instance.instance().clone(),
                owner: owner.clone(),
                endpoint: "http://reports.internal:18891/results".into(),
                target: "http://127.0.0.1:18891/results".into(),
            },
            Duration::from_secs(60),
        )
        .unwrap();
    for name in ["arbitrary-client", "renamed-client"] {
        let profile = load_command_profile_from_str(&format!(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: {name}}}
forms:
  - id: submit
    parameters:
      - {{name: destination, semantic: {{kind: endpoint, endpoint_kind: url, usage: upload_target}}, binding: {{kind: remaining_positionals}}, cardinality: required_many}}
    effects:
      - {{kind: network_endpoint, target: {{kind: slot, name: destination}}}}
      - {{kind: state_operation, state_operation: {{domain: remote_resource, operation: mutate, resource: {{kind: endpoint, usage: upload_target}}}}, target: {{kind: none}}}}
"#)).unwrap();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![profile]).unwrap(),
        ));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractEndpointProvenancePass);
        runner.register_session_analysis_pass(StateOperationGuardPass);
        runner.register_session_analysis_pass(NetworkUploadGuardPass);
        runner.register_session_analysis_pass(ResolvePolicyPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        for (tail, expected) in [
            ("http://127.0.0.1:18891/results", Decision::Allow),
            ("http://reports.internal:18891/results", Decision::Allow),
            (
                "http://unknown.internal:18891/results",
                Decision::NeedApproval,
            ),
            (
                "http://127.0.0.1:18891/results http://127.0.0.1:18891/admin",
                Decision::NeedApproval,
            ),
        ] {
            let request = CheckRequest {
                session_id: owner.session_id.clone(),
                sequence_no: CommandSequenceNo(1),
                command: format!("{name} {tail}"),
                shell_state_before: ShellStateSnapshot::new("/tmp"),
                shell_kind: ShellKind::Bash,
                runtime: RuntimeMetadata {
                    runtime_name: owner.runtime_name.clone(),
                    tool_name: None,
                    shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
                },
                home: None,
                workspace_root: Some("/tmp".into()),
            };
            let binding = ExecutionFrameBinding::for_request(&request, &owner.executor_instance_id);
            let _admission = registry
                .admit_check(binding.clone(), owner.clone(), Duration::from_secs(60))
                .unwrap();
            let snapshot = registry.snapshot(&binding).unwrap();
            let mut ctx = RunnerContext::new(request);
            ctx.set_resource_authority(snapshot);
            let graph = SessionGraph::new();
            let summary = SessionSummary::new();
            runner.run(SessionView::new(&graph, &summary), &mut ctx);
            assert_eq!(
                ctx.final_decision,
                Some(expected),
                "{name} {tail}: {:?}",
                ctx.decision_proposals
            );
            assert!(ctx.evidence.iter().any(|e| matches!(&e.kind, EvidenceKind::ResourceAuthorization(p) if p.targets.len() == tail.split_whitespace().count())));
        }
    }
}

#[test]
fn namespace_transfer_requires_a_declared_local_dispatch_contract() {
    for (namespace, remote, expected) in [
        ("", false, Decision::NeedApproval),
        ("resource_namespace: same_executor", false, Decision::Allow),
        (
            "resource_namespace: same_executor",
            true,
            Decision::NeedApproval,
        ),
    ] {
        let registry = ManagedResourceRegistry::default();
        let owner = ResourceOwner {
            session_id: SessionId::new("namespace-test"),
            runtime_name: "host".into(),
            executor_instance_id: "executor".into(),
            namespace_id: "network".into(),
        };
        let instance = registry
            .register(
                ManagedResource {
                    resource_id: "service".into(),
                    instance_id: "instance".into(),
                    owner: owner.clone(),
                    endpoints: vec!["http://127.0.0.1:18891/results".into()],
                },
                Duration::from_secs(60),
            )
            .unwrap();
        let _grant = registry
            .grant(
                ResourcePermission {
                    grant_id: "submit".into(),
                    resource: instance.instance().clone(),
                    owner: owner.clone(),
                    domain: StateOperationDomain::RemoteResource,
                    operation: StateOperationKind::Mutate,
                },
                Duration::from_secs(60),
            )
            .unwrap();
        let client = load_command_profile_from_str(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary-client}
forms:
  - id: submit
    parameters:
      - {name: destination, semantic: {kind: endpoint, endpoint_kind: url, usage: upload_target}, binding: {kind: next_positional}, cardinality: required_one}
    effects:
      - {kind: network_endpoint, target: {kind: slot, name: destination}}
      - {kind: state_operation, state_operation: {domain: remote_resource, operation: mutate, resource: {kind: endpoint, usage: upload_target}}, target: {kind: none}}
"#).unwrap();
        let remote_effect = if remote {
            "      - {kind: execute_remote_command, target: {kind: none}}"
        } else {
            ""
        };
        let wrapper = load_command_profile_from_str(&format!(r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: arbitrary-launcher}}
option_scope: leading_options
forms:
  - id: launch
    parameters:
      - {{name: child, semantic: {{kind: command_ref, dispatch: wrapper_command}}, binding: {{kind: next_positional}}, cardinality: required_one}}
      - {{name: args, semantic: {{kind: plain_value}}, binding: {{kind: remaining_args}}, cardinality: optional_many}}
    effects:
      - kind: dispatch_command
        {namespace}
        target: {{kind: dispatch, command: child, argv: [args]}}
{remote_effect}
"#)).unwrap();
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::from_profiles(vec![client, wrapper]).unwrap(),
        ));
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
        runner.register_session_transform_pass(ExtractEndpointProvenancePass);
        runner.register_session_analysis_pass(StateOperationGuardPass);
        runner.register_session_analysis_pass(ResolvePolicyPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        let request = CheckRequest {
            session_id: owner.session_id.clone(),
            sequence_no: CommandSequenceNo(1),
            command: "arbitrary-launcher arbitrary-client http://127.0.0.1:18891/results".into(),
            shell_state_before: ShellStateSnapshot::new("/tmp"),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: owner.runtime_name.clone(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
            home: None,
            workspace_root: Some("/tmp".into()),
        };
        let binding = ExecutionFrameBinding::for_request(&request, &owner.executor_instance_id);
        let _admission = registry
            .admit_check(binding.clone(), owner, Duration::from_secs(60))
            .unwrap();
        let mut ctx = RunnerContext::new(request);
        ctx.set_resource_authority(registry.snapshot(&binding).unwrap());
        runner.run(
            SessionView::new(&SessionGraph::new(), &SessionSummary::new()),
            &mut ctx,
        );
        assert_eq!(
            ctx.final_decision,
            Some(expected),
            "{namespace} remote={remote}: {:?}",
            ctx.evidence
        );
        let proof = ctx
            .evidence
            .iter()
            .find_map(|e| match &e.kind {
                EvidenceKind::ResourceAuthorization(proof) => Some(proof),
                _ => None,
            })
            .expect("child resource proof");
        assert_eq!(proof.authorized, expected == Decision::Allow);
        if expected == Decision::NeedApproval {
            assert!(
                proof.gap.as_deref().unwrap().contains("namespace"),
                "{proof:?}"
            );
        }
    }
}

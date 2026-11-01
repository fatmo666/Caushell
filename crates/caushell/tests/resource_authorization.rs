use caushell_runner::{
    ManagedResource, ManagedResourceRegistry, ResourceOwner, ResourcePermission,
};
use caushell_types::*;
use std::{
    fs,
    io::Cursor,
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn owner() -> ResourceOwner {
    ResourceOwner {
        session_id: SessionId::new("resource-runtime"),
        runtime_name: "managed-test-host".into(),
        executor_instance_id: "executor-instance".into(),
        namespace_id: "test-network".into(),
    }
}
fn request(command: &str, root: &std::path::Path) -> RuntimeCheckRequest {
    RuntimeCheckRequest {
        intent: CheckIntent::JudgeOnly,
        session_id: owner().session_id,
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new(root.to_str().unwrap())
            .with_variable_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete)
            .with_function_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: owner().runtime_name,
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: None,
        workspace_root: Some(root.to_str().unwrap().into()),
    }
}
fn check(
    runtime: &mut caushell::CliRuntime,
    registry: &ManagedResourceRegistry,
    command: &str,
    root: &std::path::Path,
) -> CheckResponse {
    let mut request = request(command, root);
    let RuntimeTransportResponse::ExecutionFramePlan(plan) = runtime
        .handle_runtime_transport_request(RuntimeTransportRequest::ExecutionFramePlan(
            ExecutionFramePlanRequest {
                request: request.clone(),
                executor_instance_id: owner().executor_instance_id,
            },
        ))
        .unwrap()
    else {
        panic!("execution frame plan")
    };
    request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        integer_variables: Default::default(),
        native_variants: Default::default(),
        binding: plan.binding.clone(),
        variables: Vec::new(),
        environment: plan
            .requirements
            .environment_names
            .into_iter()
            .map(|name| ShellEnvironmentSnapshot {
                name,
                value: ShellEnvironmentValue::Absent,
            })
            .collect(),
        pathname: None,
    });
    let _admission = registry
        .admit_check(plan.binding, owner(), Duration::from_secs(60))
        .unwrap();
    let input = serde_json::to_string(&RuntimeTransportRequest::Check(request)).unwrap() + "\n";
    let mut output = Vec::new();
    caushell::serve_stdio(runtime, Cursor::new(input), &mut output).unwrap();
    match serde_json::from_slice::<RuntimeTransportResponse>(&output).unwrap() {
        RuntimeTransportResponse::Check(result) => {
            assert!(result.check_receipt.is_none());
            result.response
        }
        _ => panic!("check response"),
    }
}

#[test]
fn runtime_transport_persistence_and_owned_service_lifetimes_keep_authority_separate() {
    let root = std::env::temp_dir().join(format!(
        "caushell-resource-runtime-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::write(root.join("defaults.yaml"), "{}\n").unwrap();
    fs::write(root.join("sentinel"), "unchanged").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/results", listener.local_addr().unwrap());
    let command = format!("curl -q --noproxy '*' --data SAFE --url {endpoint}");
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = registry
        .register(
            ManagedResource {
                resource_id: "result-service".into(),
                instance_id: "service-instance".into(),
                owner: owner(),
                endpoints: vec![endpoint.clone()],
            },
            Duration::from_secs(600),
        )
        .unwrap();
    let open = || {
        caushell::create_runtime(Some(&root.join("defaults.yaml")), Some(&root.join("store")))
            .unwrap()
    };
    let grant;
    {
        let mut runtime = open();
        runtime.set_resource_authority(registry.clone());
        assert_eq!(
            check(&mut runtime, &registry, &command, &root).decision,
            Decision::NeedApproval
        );
        grant = registry
            .grant(
                ResourcePermission {
                    grant_id: "publish-results".into(),
                    resource: registration.instance().clone(),
                    owner: owner(),
                    domain: StateOperationDomain::RemoteResource,
                    operation: StateOperationKind::Mutate,
                },
                Duration::from_secs(600),
            )
            .unwrap();
        let result = check(&mut runtime, &registry, &command, &root);
        assert_eq!(result.decision, Decision::Allow, "{result:#?}");
        assert!(result.decision_trace.evidence.iter().any(|e| matches!(&e.kind, EvidenceKind::ResourceAuthorization(proof) if proof.authorized && proof.targets[0].grant_id.as_deref() == Some("publish-results"))));
    }
    {
        let mut runtime = open();
        assert_eq!(
            check(&mut runtime, &registry, &command, &root).decision,
            Decision::NeedApproval
        );
        runtime.set_resource_authority(registry.clone());
        assert_eq!(
            check(&mut runtime, &registry, &command, &root).decision,
            Decision::Allow
        );
        let script = check(
            &mut runtime,
            &registry,
            &format!("{command}; python3 -c 'pass'"),
            &root,
        );
        assert_eq!(script.decision, Decision::NeedApproval);
        assert!(
            script
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::NonShellScriptExecution)
        );
        assert_eq!(
            check(
                &mut runtime,
                &registry,
                &format!("{command}; rm -rf /"),
                &root
            )
            .decision,
            Decision::Deny
        );
        drop(grant);
        assert_eq!(
            check(&mut runtime, &registry, &command, &root).decision,
            Decision::NeedApproval
        );
        drop(registration);
        assert_eq!(
            check(&mut runtime, &registry, &command, &root).decision,
            Decision::NeedApproval
        );
    }
    assert_eq!(
        fs::read_to_string(root.join("sentinel")).unwrap(),
        "unchanged"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(listener);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tool_transport_cannot_register_resources_or_mint_grants() {
    for kind in ["bind_resource_route", "unbind_resource_route"] {
        assert!(
            serde_json::from_value::<RuntimeTransportRequest>(
                serde_json::json!({"kind":kind,"payload":{"route_id":"self-asserted"}})
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<RuntimeTransportRequest>(
            serde_json::json!({"kind":"register_resource","payload":{"resource_id":"x"}})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<RuntimeTransportRequest>(
            serde_json::json!({"kind":"grant_resource","payload":{"authorized":true}})
        )
        .is_err()
    );
    let root = std::env::temp_dir();
    let mut value = serde_json::to_value(RuntimeTransportRequest::Check(request(
        "curl -q --data SAFE --url http://127.0.0.1:18891/result",
        &root,
    )))
    .unwrap();
    value["payload"]["resource_authority"] =
        serde_json::json!({"authorized":true,"grants":["all"]});
    let input = serde_json::to_string(&value).unwrap() + "\n";
    let mut runtime = caushell::create_runtime(None, None).unwrap();
    let mut output = Vec::new();
    caushell::serve_stdio(&mut runtime, Cursor::new(input), &mut output).unwrap();
    let RuntimeTransportResponse::Check(result) = serde_json::from_slice(&output).unwrap() else {
        panic!()
    };
    assert_eq!(result.decision, Decision::NeedApproval);
}

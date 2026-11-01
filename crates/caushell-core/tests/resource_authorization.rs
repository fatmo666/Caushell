use caushell_core::ShellQueryCore;
use caushell_runner::{
    ManagedResource, ManagedResourceRegistry, ResourceAuthority, ResourceAuthoritySnapshot,
    ResourceGrant, ResourceOwner, ResourcePermission,
};
use caushell_types::*;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const ENDPOINT: &str = "http://127.0.0.1:18891/result";

struct TestCore {
    core: ShellQueryCore,
    registry: ManagedResourceRegistry,
}
impl TestCore {
    fn new(registry: &ManagedResourceRegistry) -> Self {
        Self {
            core: ShellQueryCore::new(),
            registry: registry.clone(),
        }
    }
    fn check(&mut self, request: CheckRequest) -> CheckResponse {
        let admission = request
            .shell_state_before
            .execution_frame
            .as_ref()
            .and_then(|frame| {
                self.registry
                    .admit_check(frame.binding.clone(), owner(), Duration::from_secs(60))
                    .ok()
            });
        let response = self.core.check(request);
        drop(admission);
        response
    }
}
impl std::ops::Deref for TestCore {
    type Target = ShellQueryCore;
    fn deref(&self) -> &ShellQueryCore {
        &self.core
    }
}
impl std::ops::DerefMut for TestCore {
    fn deref_mut(&mut self) -> &mut ShellQueryCore {
        &mut self.core
    }
}

fn owner() -> ResourceOwner {
    ResourceOwner {
        session_id: SessionId::new("resource-test"),
        runtime_name: "owned-host".into(),
        executor_instance_id: "executor-a".into(),
        namespace_id: "namespace-a".into(),
    }
}
fn request(sequence: u64, command: &str) -> CheckRequest {
    let mut request = CheckRequest {
        session_id: owner().session_id,
        sequence_no: CommandSequenceNo(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp")
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
        workspace_root: Some("/tmp".into()),
    };
    request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        integer_variables: Default::default(),
        native_variants: Default::default(),
        binding: ExecutionFrameBinding::for_request(&request, owner().executor_instance_id),
        variables: Vec::new(),
        environment: [
            "http_proxy",
            "HTTP_PROXY",
            "https_proxy",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ]
        .into_iter()
        .map(|name| ShellEnvironmentSnapshot {
            name: name.into(),
            value: ShellEnvironmentValue::Absent,
        })
        .collect(),
        pathname: None,
    });
    request
}
fn command(endpoint: &str) -> String {
    format!("curl -q --noproxy '*' --data SAFE --url {endpoint}")
}
fn register(
    registry: &ManagedResourceRegistry,
    id: &str,
    endpoint: &str,
) -> caushell_runner::ResourceRegistration {
    registry
        .register(
            ManagedResource {
                resource_id: id.into(),
                instance_id: "instance-a".into(),
                owner: owner(),
                endpoints: vec![endpoint.into()],
            },
            Duration::from_secs(600),
        )
        .unwrap()
}
fn permission(
    registration: &caushell_runner::ResourceRegistration,
    id: &str,
) -> ResourcePermission {
    ResourcePermission {
        grant_id: id.into(),
        resource: registration.instance().clone(),
        owner: owner(),
        domain: StateOperationDomain::RemoteResource,
        operation: StateOperationKind::Mutate,
    }
}
fn proof(response: &CheckResponse) -> &ResourceAuthorizationEvidence {
    response
        .decision_trace
        .evidence
        .iter()
        .find_map(|e| {
            if let EvidenceKind::ResourceAuthorization(p) = &e.kind {
                Some(p)
            } else {
                None
            }
        })
        .expect("resource proof")
}

#[test]
fn facts_do_not_authorize_and_grants_require_an_exact_live_instance() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry.clone());
    assert_eq!(
        core.check(request(1, &command(ENDPOINT))).decision,
        Decision::NeedApproval
    );
    let registration = register(&registry, "results", ENDPOINT);
    let known = core.check(request(2, &command(ENDPOINT)));
    assert_eq!(known.decision, Decision::NeedApproval);
    assert_eq!(
        proof(&known).targets[0].resource_id.as_deref(),
        Some("results")
    );
    assert!(proof(&known).targets[0].grant_id.is_none());
    let grant = registry
        .grant(
            permission(&registration, "upload-results"),
            Duration::from_secs(60),
        )
        .unwrap();
    let result = core.check(request(3, &command(ENDPOINT)));
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    assert!(proof(&result).authorized);
    assert_eq!(
        proof(&result).targets[0].resource_id.as_deref(),
        Some("results")
    );
    assert_eq!(
        proof(&result).targets[0].grant_id.as_deref(),
        Some("upload-results")
    );
    assert_eq!(
        core.check(request(4, &format!("curl -q -X DELETE --url {ENDPOINT}")))
            .decision,
        Decision::Allow
    );
    drop(grant);
    assert_eq!(
        core.check(request(5, &command(ENDPOINT))).decision,
        Decision::NeedApproval
    );
}

#[test]
fn exact_scope_does_not_trust_loopback_paths_names_or_dynamic_targets() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "results", ENDPOINT);
    let _grant = registry
        .grant(permission(&registration, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry);
    for (i, endpoint) in [
        "http://127.0.0.1:18891/admin",
        "http://127.0.0.1:18892/result",
        "http://localhost:18891/result",
        "http://127.0.0.1:18891/result/../admin",
        "http://127.0.0.1:18891/res%75lt",
        "\"$UNKNOWN_ENDPOINT\"",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            core.check(request(i as u64 + 1, &command(endpoint)))
                .decision,
            Decision::NeedApproval,
            "{endpoint}"
        );
    }
}

#[test]
fn host_bound_names_require_permission_and_do_not_override_other_policies() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "tls-reports", "https://127.0.0.1:18891/result");
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry.clone());
    let command = command("https://reports.internal:18891/result");
    assert_eq!(
        core.check(request(1, &command)).decision,
        Decision::NeedApproval
    );
    let route = registry
        .bind_route(
            caushell_runner::ResourceRoute {
                route_id: "reports-name".into(),
                resource: registration.instance().clone(),
                owner: owner(),
                endpoint: "https://reports.internal:18891/result".into(),
                target: "https://127.0.0.1:18891/result".into(),
            },
            Duration::from_secs(60),
        )
        .unwrap();
    let bound = core.check(request(2, &command));
    assert_eq!(bound.decision, Decision::NeedApproval);
    assert_eq!(
        proof(&bound).targets[0].route_id.as_deref(),
        Some("reports-name")
    );
    assert!(proof(&bound).targets[0].grant_id.is_none());
    let _grant = registry
        .grant(permission(&registration, "upload"), Duration::from_secs(60))
        .unwrap();
    let allowed = core.check(request(3, &command));
    assert_eq!(allowed.decision, Decision::Allow, "{allowed:#?}");
    assert_eq!(
        proof(&allowed).targets[0].resolved_endpoint.as_deref(),
        Some("https://127.0.0.1:18891/result")
    );
    for (sequence, extra, expected) in [
        (4, " --insecure", Decision::NeedApproval),
        (5, "; python3 -c 'pass'", Decision::NeedApproval),
        (6, "; perl -e 'print 1'", Decision::NeedApproval),
        (7, "; rm -rf /", Decision::Deny),
        (8, " --location", Decision::NeedApproval),
        (
            9,
            " --resolve reports.internal:18891:127.0.0.2",
            Decision::NeedApproval,
        ),
    ] {
        assert_eq!(
            core.check(request(sequence, &format!("{command}{extra}")))
                .decision,
            expected,
            "{extra}"
        );
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::StateMutation,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    core.replace_policy(policy);
    assert_eq!(core.check(request(10, &command)).decision, Decision::Deny);
    core.replace_policy(PolicyConfig::default());
    drop(route);
    assert_eq!(
        core.check(request(11, &command)).decision,
        Decision::NeedApproval
    );
}

#[test]
fn a_host_bound_localhost_name_does_not_make_a_nonlocal_service_local() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "nonlocal", "http://192.0.2.10:18891/result");
    let _grant = registry
        .grant(permission(&registration, "upload"), Duration::from_secs(60))
        .unwrap();
    let _route = registry
        .bind_route(
            caushell_runner::ResourceRoute {
                route_id: "named-route".into(),
                resource: registration.instance().clone(),
                owner: owner(),
                endpoint: "http://localhost:18891/result".into(),
                target: "http://192.0.2.10:18891/result".into(),
            },
            Duration::from_secs(60),
        )
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry);
    let response = core.check(request(1, &command("http://localhost:18891/result")));
    assert_eq!(response.decision, Decision::NeedApproval);
    assert!(proof(&response).authorized);
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::NetworkUpload)
    );
}

#[test]
fn all_targets_and_all_execution_units_need_their_own_authorization() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let a = register(&registry, "first", ENDPOINT);
    let b = register(&registry, "second", "http://127.0.0.1:18892/result");
    let _ga = registry
        .grant(permission(&a, "grant-first"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry.clone());
    let multi = format!("{} --url http://127.0.0.1:18892/result", command(ENDPOINT));
    let denied = core.check(request(1, &multi));
    assert_eq!(denied.decision, Decision::NeedApproval);
    assert!(!proof(&denied).authorized);
    let _gb = registry
        .grant(permission(&b, "grant-second"), Duration::from_secs(60))
        .unwrap();
    assert_eq!(core.check(request(2, &multi)).decision, Decision::Allow);
    let mixed = format!(
        "{}; {}",
        command(ENDPOINT),
        command("http://127.0.0.1:18893/admin")
    );
    assert_eq!(
        core.check(request(3, &mixed)).decision,
        Decision::NeedApproval
    );
}

#[test]
fn wrappers_functions_and_history_use_declarations_not_command_spelling() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "results", ENDPOINT);
    let _grant = registry
        .grant(permission(&registration, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry);
    assert_eq!(
        core.check(request(
            1,
            &format!("dest={ENDPOINT}; send_result() {{ curl -q --data SAFE --url \"$dest\"; }}")
        ))
        .decision,
        Decision::Allow
    );
    let mut invoke = request(2, "send_result");
    invoke.shell_state_before.observability = ShellStateObservability::default();
    let result = core.check(invoke);
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    assert!(proof(&result).node_id.starts_with("derived-function:"));
    let result = core.check(request(
        3,
        &format!("env bash -c \"curl -q --data SAFE --url {ENDPOINT}\""),
    ));
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
}

#[test]
fn retirement_port_reuse_and_grant_handle_reuse_do_not_transfer_permissions() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let first = register(&registry, "results", ENDPOINT);
    let first_ref = first.instance().clone();
    let old_grant = registry
        .grant(permission(&first, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry.clone());
    assert_eq!(
        core.check(request(1, &command(ENDPOINT))).decision,
        Decision::Allow
    );
    drop(first);
    let second = register(&registry, "results", ENDPOINT);
    assert_ne!(first_ref.generation, second.instance().generation);
    assert_eq!(
        core.check(request(2, &command(ENDPOINT))).decision,
        Decision::NeedApproval
    );
    let _new_grant = registry
        .grant(permission(&second, "grant"), Duration::from_secs(60))
        .unwrap();
    drop(old_grant);
    assert_eq!(
        core.check(request(3, &command(ENDPOINT))).decision,
        Decision::Allow
    );
}

#[test]
fn session_executor_policy_and_operation_boundaries_remain_independent() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "results", ENDPOINT);
    let mut foreign = permission(&registration, "foreign");
    foreign.owner.namespace_id = "other".into();
    assert!(registry.grant(foreign, Duration::from_secs(60)).is_err());
    let mut control = permission(&registration, "control");
    control.operation = StateOperationKind::Control;
    let _control = registry.grant(control, Duration::from_secs(60)).unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry.clone());
    assert_eq!(
        core.check(request(1, &command(ENDPOINT))).decision,
        Decision::NeedApproval
    );
    let _mutate = registry
        .grant(permission(&registration, "mutate"), Duration::from_secs(60))
        .unwrap();
    let mut foreign = request(2, &command(ENDPOINT));
    foreign.session_id = SessionId::new("other");
    foreign
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .binding = ExecutionFrameBinding::for_request(&foreign, "executor-a");
    assert_eq!(core.check(foreign).decision, Decision::NeedApproval);
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::StateMutation,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    core.replace_policy(policy);
    assert_eq!(
        core.check(request(2, &command(ENDPOINT))).decision,
        Decision::Deny
    );
}

#[test]
fn route_and_environment_changes_are_not_covered_by_a_destination_grant() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "results", ENDPOINT);
    let _grant = registry
        .grant(permission(&registration, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry);
    for (i, extra) in [
        "-L",
        "--proxy http://127.0.0.1:18899",
        "--connect-to 127.0.0.1:18891:127.0.0.1:18899",
        "--resolve 127.0.0.1:18891:127.0.0.2",
        "--request-target /admin",
        "-H 'Host: admin'",
        "--unix-socket /tmp/other.socket",
        "--url-query action=delete",
    ]
    .into_iter()
    .enumerate()
    {
        let result = core.check(request(
            i as u64 + 1,
            &format!("{} {extra}", command(ENDPOINT)),
        ));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{extra}: {result:#?}"
        );
    }
    let result = core.check(request(
        9,
        &format!("http_proxy=http://127.0.0.1:18899 {}", command(ENDPOINT)),
    ));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    let mut unknown = request(10, &command(ENDPOINT));
    unknown
        .shell_state_before
        .execution_frame
        .as_mut()
        .unwrap()
        .environment
        .clear();
    assert_eq!(core.check(unknown).decision, Decision::NeedApproval);
    assert_eq!(
        core.check(request(11, &command(ENDPOINT))).decision,
        Decision::Allow
    );
}

#[test]
fn resource_grants_never_lower_script_approval_or_existing_denies() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "results", ENDPOINT);
    let _grant = registry
        .grant(permission(&registration, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry);
    let script = core.check(request(
        1,
        &format!("{}; python3 -c 'pass'", command(ENDPOINT)),
    ));
    assert_eq!(script.decision, Decision::NeedApproval);
    assert!(
        script
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::NonShellScriptExecution)
    );
    assert_eq!(
        core.check(request(2, &format!("{}; rm -rf /", command(ENDPOINT))))
            .decision,
        Decision::Deny
    );
    assert_eq!(
        core.check(request(
            3,
            &format!(
                "{}; python3 -c 'import shutil; shutil.rmtree(\"/\")'",
                command(ENDPOINT)
            )
        ))
        .decision,
        Decision::Deny
    );
}

struct RevokeDuringCheck {
    registry: ManagedResourceRegistry,
    grant: Mutex<Option<ResourceGrant>>,
}
impl ResourceAuthority for RevokeDuringCheck {
    fn snapshot(
        &self,
        binding: &ExecutionFrameBinding,
    ) -> Result<ResourceAuthoritySnapshot, String> {
        self.registry.snapshot(binding)
    }
    fn is_current(&self, snapshot: &ResourceAuthoritySnapshot) -> bool {
        drop(self.grant.lock().unwrap().take());
        self.registry.is_current(snapshot)
    }
}

#[test]
fn revocation_during_analysis_invalidates_a_positive_proof() {
    let registry = ManagedResourceRegistry::default();
    let registration = register(&registry, "results", ENDPOINT);
    let grant = registry
        .grant(permission(&registration, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(Arc::new(RevokeDuringCheck {
        registry,
        grant: Mutex::new(Some(grant)),
    }));
    let result = core.check(request(1, &command(ENDPOINT)));
    assert_eq!(result.decision, Decision::NeedApproval);
    assert!(!proof(&result).authorized);
    assert!(
        proof(&result)
            .gap
            .as_deref()
            .unwrap()
            .contains("expired during analysis")
    );
}

#[test]
fn restoring_analysis_history_does_not_restore_resource_authority() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "results", ENDPOINT);
    let _grant = registry
        .grant(permission(&registration, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = TestCore::new(&registry);
    core.set_resource_authority(registry);
    assert_eq!(
        core.check(request(1, &command(ENDPOINT))).decision,
        Decision::Allow
    );
    let snapshot = core.session_snapshot(&owner().session_id, 0).unwrap();
    let mut restored = ShellQueryCore::new();
    restored.insert_session_state(
        snapshot.session_id.clone(),
        caushell_core::SessionState::from_snapshot(snapshot).unwrap(),
    );
    assert_eq!(
        restored.check(request(2, &command(ENDPOINT))).decision,
        Decision::NeedApproval
    );
}

#[test]
fn self_reported_executor_ids_cannot_replace_host_frame_admission() {
    let registry = Arc::new(ManagedResourceRegistry::default());
    let registration = register(&registry, "results", ENDPOINT);
    let _grant = registry
        .grant(permission(&registration, "grant"), Duration::from_secs(60))
        .unwrap();
    let mut core = ShellQueryCore::new();
    core.set_resource_authority(registry.clone());
    let proposed = request(1, &command(ENDPOINT));
    assert_eq!(core.check(proposed).decision, Decision::NeedApproval);
    let admitted = request(2, &command(ENDPOINT));
    let _admission = registry
        .admit_check(
            admitted
                .shell_state_before
                .execution_frame
                .as_ref()
                .unwrap()
                .binding
                .clone(),
            owner(),
            Duration::from_secs(60),
        )
        .unwrap();
    let different_command = request(2, &command("http://127.0.0.1:18891/admin"));
    assert!(
        registry
            .snapshot(
                &different_command
                    .shell_state_before
                    .execution_frame
                    .as_ref()
                    .unwrap()
                    .binding
            )
            .is_err()
    );
    assert_eq!(core.check(admitted).decision, Decision::Allow);
}

use caushell_runner::*;
use caushell_types::*;
use std::time::Duration;

fn owner() -> ResourceOwner {
    ResourceOwner {
        session_id: SessionId::new("owner"),
        runtime_name: "host".into(),
        executor_instance_id: "executor".into(),
        namespace_id: "network-1".into(),
    }
}
fn resource() -> ManagedResource {
    ManagedResource {
        resource_id: "results".into(),
        instance_id: "server-instance".into(),
        owner: owner(),
        endpoints: vec!["http://127.0.0.1:18891/result".into()],
    }
}
fn binding() -> ExecutionFrameBinding {
    ExecutionFrameBinding {
        protocol: 1,
        executor_instance_id: "executor".into(),
        session_id: owner().session_id,
        sequence_no: CommandSequenceNo(1),
        runtime_name: "host".into(),
        shell_kind: ShellKind::Bash,
        cwd: "/tmp".into(),
        command_sha256: "a".repeat(64),
    }
}
fn operation() -> StateOperation {
    StateOperation {
        domain: StateOperationDomain::RemoteResource,
        operation: StateOperationKind::Mutate,
        resource: Some(StateResourceSelector::Endpoint {
            usage: ProvenanceEndpointUsage::UploadTarget,
        }),
    }
}
fn permission(registration: &ResourceRegistration) -> ResourcePermission {
    ResourcePermission {
        grant_id: "grant".into(),
        resource: registration.instance().clone(),
        owner: owner(),
        domain: StateOperationDomain::RemoteResource,
        operation: StateOperationKind::Mutate,
    }
}

#[test]
fn resource_identity_is_separate_from_permission_and_expires() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry
        .admit_check(binding(), owner(), Duration::from_secs(60))
        .unwrap();
    let registration = registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    let instance = snapshot.resolve(&resource().endpoints[0]).unwrap();
    assert!(snapshot.permission(&instance, operation()).is_none());
    let _grant = registry
        .grant(permission(&registration), Duration::from_millis(100))
        .unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    assert!(snapshot.permission(&instance, operation()).is_some());
    std::thread::sleep(Duration::from_millis(150));
    assert!(!registry.is_current(&snapshot));
    let fresh = registry.snapshot(&binding()).unwrap();
    assert!(fresh.resolve(&resource().endpoints[0]).is_some());
    assert!(fresh.permission(&instance, operation()).is_none());
}

#[test]
fn resource_expiration_and_retirement_prevent_new_grants() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry
        .admit_check(binding(), owner(), Duration::from_secs(60))
        .unwrap();
    let registration = registry
        .register(resource(), Duration::from_millis(100))
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        registry
            .grant(permission(&registration), Duration::from_secs(60))
            .is_err()
    );
    assert!(
        registry
            .snapshot(&binding())
            .unwrap()
            .resolve(&resource().endpoints[0])
            .is_none()
    );
    drop(registration);
    let next = registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    assert!(next.instance().generation > 1);
}

#[test]
fn namespace_changes_and_ambiguous_registrations_require_retirement() {
    let registry = ManagedResourceRegistry::default();
    let first = registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    let mut conflicting = resource();
    conflicting.resource_id = "another".into();
    assert!(
        registry
            .register(conflicting.clone(), Duration::from_secs(60))
            .is_err()
    );
    conflicting.owner.namespace_id = "network-2".into();
    assert!(
        registry
            .register(conflicting.clone(), Duration::from_secs(60))
            .is_err()
    );
    drop(first);
    assert!(
        registry
            .register(conflicting, Duration::from_secs(60))
            .is_ok()
    );
}

#[test]
fn launch_snapshot_is_bound_to_the_registry_and_exact_request() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry
        .admit_check(binding(), owner(), Duration::from_secs(60))
        .unwrap();
    let _registration = registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    assert_eq!(
        registry
            .with_current_snapshot(&snapshot, &binding(), || 7)
            .unwrap(),
        7
    );
    let mut other = binding();
    other.sequence_no = CommandSequenceNo(2);
    assert!(
        registry
            .with_current_snapshot(&snapshot, &other, || panic!("must not launch"))
            .is_err()
    );
    let another_registry = ManagedResourceRegistry::default();
    let _other = another_registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    assert!(!another_registry.is_current(&snapshot));
    assert!(
        another_registry
            .with_current_snapshot(&snapshot, &binding(), || panic!("must not launch"))
            .is_err()
    );
    drop(_registration);
    assert!(
        registry
            .with_current_snapshot(&snapshot, &binding(), || panic!("must not launch"))
            .is_err()
    );
}

#[test]
fn resource_lease_serializes_retirement_with_launch() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry
        .admit_check(binding(), owner(), Duration::from_secs(60))
        .unwrap();
    let registration = registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (end_tx, end_rx) = std::sync::mpsc::channel();
    let worker = registry
        .with_current_snapshot(&snapshot, &binding(), || {
            let thread = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                drop(registration);
                end_tx.send(()).unwrap();
            });
            started_rx.recv().unwrap();
            assert!(end_rx.try_recv().is_err());
            thread
        })
        .unwrap();
    worker.join().unwrap();
    end_rx.recv().unwrap();
    assert!(!registry.is_current(&snapshot));
}

#[test]
fn invalid_locators_lifetimes_and_opaque_permissions_are_rejected() {
    let registry = ManagedResourceRegistry::default();
    assert!(registry.register(resource(), Duration::ZERO).is_err());
    assert!(
        registry
            .register(resource(), Duration::from_secs(3601))
            .is_err()
    );
    for endpoint in [
        "http://localhost/result",
        "http://127.0.0.1/{result,admin}",
        "http://127.0.0.1/a%2fresult",
        "http://127.0.0.1/a/../result",
    ] {
        let mut fact = resource();
        fact.endpoints = vec![endpoint.into()];
        assert!(registry.register(fact, Duration::from_secs(60)).is_err());
    }
    let registration = registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    let mut permission = permission(&registration);
    permission.operation = StateOperationKind::Opaque;
    assert!(registry.grant(permission, Duration::from_secs(60)).is_err());
}

#[test]
fn host_admission_expires_and_does_not_follow_self_reported_frame_changes() {
    let registry = ManagedResourceRegistry::default();
    let _registration = registry
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    assert!(registry.snapshot(&binding()).is_err());
    let admission = registry
        .admit_check(binding(), owner(), Duration::from_millis(100))
        .unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    let mut changed = binding();
    changed.command_sha256 = "b".repeat(64);
    assert!(registry.snapshot(&changed).is_err());
    std::thread::sleep(Duration::from_millis(150));
    assert!(!registry.is_current(&snapshot));
    assert!(registry.snapshot(&binding()).is_err());
    drop(admission);
    let admission = registry
        .admit_check(binding(), owner(), Duration::from_secs(60))
        .unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    drop(admission);
    assert!(!registry.is_current(&snapshot));
}

#[test]
fn instance_references_do_not_transfer_between_authorities_after_restart() {
    let first = ManagedResourceRegistry::default();
    let first_resource = first.register(resource(), Duration::from_secs(60)).unwrap();
    let second = ManagedResourceRegistry::default();
    let second_resource = second
        .register(resource(), Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        first_resource.instance().generation,
        second_resource.instance().generation
    );
    assert_ne!(first_resource.instance(), second_resource.instance());
    assert!(
        second
            .grant(permission(&first_resource), Duration::from_secs(60))
            .is_err()
    );
}

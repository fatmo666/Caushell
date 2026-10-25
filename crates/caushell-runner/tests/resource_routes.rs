use caushell_runner::*;
use caushell_types::*;
use std::time::Duration;

const TTL: Duration = Duration::from_secs(60);

fn owner() -> ResourceOwner {
    ResourceOwner {
        session_id: SessionId::new("route-owner"),
        runtime_name: "host".into(),
        executor_instance_id: "executor".into(),
        namespace_id: "network-a".into(),
    }
}
fn binding() -> ExecutionFrameBinding {
    ExecutionFrameBinding {
        protocol: 1,
        session_id: owner().session_id,
        runtime_name: "host".into(),
        executor_instance_id: "executor".into(),
        sequence_no: CommandSequenceNo(1),
        shell_kind: ShellKind::Bash,
        cwd: "/tmp".into(),
        command_sha256: "a".repeat(64),
    }
}
fn fact() -> ManagedResource {
    ManagedResource {
        resource_id: "reports".into(),
        instance_id: "service-a".into(),
        owner: owner(),
        endpoints: vec!["https://127.0.0.1:18891/".into()],
    }
}
fn route(registration: &ResourceRegistration) -> ResourceRoute {
    ResourceRoute {
        route_id: "reports-name".into(),
        resource: registration.instance().clone(),
        owner: owner(),
        endpoint: "https://reports.internal:18891/".into(),
        target: "https://127.0.0.1:18891/".into(),
    }
}
fn permission(registration: &ResourceRegistration) -> ResourcePermission {
    ResourcePermission {
        grant_id: "publish".into(),
        resource: registration.instance().clone(),
        owner: owner(),
        domain: StateOperationDomain::RemoteResource,
        operation: StateOperationKind::Mutate,
    }
}
fn operation() -> StateOperation {
    StateOperation {
        domain: StateOperationDomain::RemoteResource,
        operation: StateOperationKind::Mutate,
        resource: Some(StateResourceSelector::RequestEndpoints),
    }
}
fn register(registry: &ManagedResourceRegistry) -> ResourceRegistration {
    registry
        .register_scoped(fact(), ResourceLocatorScope::HttpOrigin, TTL)
        .unwrap()
}

#[test]
fn names_need_a_live_owned_route_and_separate_operation_grant() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry.admit_check(binding(), owner(), TTL).unwrap();
    let resource = register(&registry);
    let endpoint = "https://reports.internal:18891/report";
    assert!(
        registry
            .snapshot(&binding())
            .unwrap()
            .resolve(endpoint)
            .is_none()
    );
    let _route = registry.bind_route(route(&resource), TTL).unwrap();
    let resolved = registry
        .snapshot(&binding())
        .unwrap()
        .resolve_target(endpoint)
        .unwrap();
    assert_eq!(resolved.endpoint, "https://127.0.0.1:18891/report");
    assert_eq!(resolved.route_id.as_deref(), Some("reports-name"));
    assert!(
        registry
            .snapshot(&binding())
            .unwrap()
            .permission(&resolved.instance, operation())
            .is_none()
    );
    let grant = registry.grant(permission(&resource), TTL).unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    assert_eq!(
        snapshot
            .permission(&resolved.instance, operation())
            .as_deref(),
        Some("publish")
    );
    for unknown in [
        "https://localhost:18891/report",
        "http://reports.internal:18891/report",
        "https://reports.internal:18892/report",
        "https://reports.internal.evil:18891/report",
        "https://reports.internal:18891/report?next=x",
        "https://reports.internal:18891/a/../report",
    ] {
        assert!(snapshot.resolve(unknown).is_none(), "{unknown}");
    }
    drop(grant);
    assert!(!registry.is_current(&snapshot));
    let snapshot = registry.snapshot(&binding()).unwrap();
    assert!(snapshot.resolve(endpoint).is_some());
    assert!(
        snapshot
            .permission(&resolved.instance, operation())
            .is_none()
    );
}

#[test]
fn exact_routes_do_not_widen_paths_or_infer_localhost() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry.admit_check(binding(), owner(), TTL).unwrap();
    let mut exact = fact();
    exact.endpoints = vec!["https://127.0.0.1:18891/report".into()];
    let resource = registry.register(exact, TTL).unwrap();
    let mut named = route(&resource);
    named.endpoint = "https://localhost:18891/report".into();
    named.target = "https://127.0.0.1:18891/report".into();
    let _route = registry.bind_route(named, TTL).unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    assert!(snapshot.resolve("https://localhost:18891/report").is_some());
    assert!(snapshot.resolve("https://localhost:18891/admin").is_none());
    assert!(
        snapshot
            .resolve("https://localhost:18891/report/next")
            .is_none()
    );
    assert!(
        snapshot
            .resolve("https://other.internal:18891/report")
            .is_none()
    );
}

#[test]
fn invalid_or_ambiguous_routes_are_rejected() {
    let registry = ManagedResourceRegistry::default();
    let resource = register(&registry);
    for (endpoint, target) in [
        (
            "https://reports.internal:18891/",
            "https://127.0.0.2:18891/",
        ),
        ("http://reports.internal:18891/", "https://127.0.0.1:18891/"),
        (
            "https://reports.internal:18892/",
            "https://127.0.0.1:18891/",
        ),
        (
            "https://reports.internal:18891/admin",
            "https://127.0.0.1:18891/",
        ),
        (
            "https://reports.internal:18891/admin",
            "https://127.0.0.1:18891/admin",
        ),
        ("https://127.0.0.1:18891/", "https://127.0.0.1:18891/"),
        (
            "https://reports.internal:18891/",
            "https://other.internal:18891/",
        ),
    ] {
        let mut r = route(&resource);
        r.endpoint = endpoint.into();
        r.target = target.into();
        assert!(
            registry.bind_route(r, TTL).is_err(),
            "{endpoint} => {target}"
        );
    }
    let mut wrong_owner = route(&resource);
    wrong_owner.owner.namespace_id = "network-b".into();
    assert!(registry.bind_route(wrong_owner, TTL).is_err());
    let _route = registry.bind_route(route(&resource), TTL).unwrap();
    let mut conflict = route(&resource);
    conflict.route_id = "another-route".into();
    assert!(registry.bind_route(conflict, TTL).is_err());
    assert!(
        registry
            .bind_route(route(&resource), Duration::ZERO)
            .is_err()
    );
}

#[test]
fn one_name_origin_cannot_select_different_addresses_by_request_path() {
    let registry = ManagedResourceRegistry::default();
    let mut first = fact();
    first.endpoints = vec!["https://127.0.0.1:18891/a".into()];
    let first = registry.register(first, TTL).unwrap();
    let mut a = route(&first);
    a.endpoint.push('a');
    a.target.push('a');
    let _a = registry.bind_route(a, TTL).unwrap();
    let mut second = fact();
    second.resource_id = "other".into();
    second.endpoints = vec!["https://127.0.0.2:18891/b".into()];
    let second = registry.register(second, TTL).unwrap();
    let mut b = route(&second);
    b.route_id = "other-name".into();
    b.endpoint.push('b');
    b.target = "https://127.0.0.2:18891/b".into();
    assert!(registry.bind_route(b, TTL).is_err());
}

#[test]
fn route_expiry_and_revocation_invalidate_snapshots_without_revoking_numeric_grants() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry.admit_check(binding(), owner(), TTL).unwrap();
    let resource = register(&registry);
    let _grant = registry.grant(permission(&resource), TTL).unwrap();
    let route = registry
        .bind_route(route(&resource), Duration::from_millis(100))
        .unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    assert!(
        snapshot
            .resolve("https://reports.internal:18891/report")
            .is_some()
    );
    std::thread::sleep(Duration::from_millis(150));
    assert!(!registry.is_current(&snapshot));
    let fresh = registry.snapshot(&binding()).unwrap();
    assert!(
        fresh
            .resolve("https://reports.internal:18891/report")
            .is_none()
    );
    let numeric = fresh.resolve("https://127.0.0.1:18891/report").unwrap();
    assert!(fresh.permission(&numeric, operation()).is_some());
    drop(route);
}

#[test]
fn retirement_and_reuse_do_not_transfer_routes_or_grants() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry.admit_check(binding(), owner(), TTL).unwrap();
    let first = register(&registry);
    let stale = registry.bind_route(route(&first), TTL).unwrap();
    let _grant = registry.grant(permission(&first), TTL).unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    drop(first);
    assert!(!registry.is_current(&snapshot));
    let second = register(&registry);
    assert!(
        registry
            .snapshot(&binding())
            .unwrap()
            .resolve("https://reports.internal:18891/report")
            .is_none()
    );
    let current_route = registry.bind_route(route(&second), TTL).unwrap();
    assert_ne!(stale.revision(), current_route.revision());
    drop(stale);
    let fresh = registry.snapshot(&binding()).unwrap();
    let resolved = fresh
        .resolve("https://reports.internal:18891/report")
        .unwrap();
    assert!(fresh.permission(&resolved, operation()).is_none());
    drop(current_route);
    assert!(
        registry
            .snapshot(&binding())
            .unwrap()
            .resolve("https://reports.internal:18891/report")
            .is_none()
    );
}

#[test]
fn routes_do_not_cross_sessions_namespaces_or_registry_restarts() {
    let registry = ManagedResourceRegistry::default();
    let resource = register(&registry);
    let _route = registry.bind_route(route(&resource), TTL).unwrap();
    let other_registry = ManagedResourceRegistry::default();
    let _other = register(&other_registry);
    assert!(other_registry.bind_route(route(&resource), TTL).is_err());
    for changed_owner in [
        ResourceOwner {
            namespace_id: "network-b".into(),
            ..owner()
        },
        ResourceOwner {
            session_id: SessionId::new("another-session"),
            ..owner()
        },
        ResourceOwner {
            executor_instance_id: "another-executor".into(),
            ..owner()
        },
    ] {
        let mut frame = binding();
        frame.session_id = changed_owner.session_id.clone();
        frame.executor_instance_id = changed_owner.executor_instance_id.clone();
        let _admission = registry
            .admit_check(frame.clone(), changed_owner, TTL)
            .unwrap();
        assert!(
            registry
                .snapshot(&frame)
                .unwrap()
                .resolve("https://reports.internal:18891/report")
                .is_none()
        );
    }
}

#[test]
fn launch_lease_serializes_route_removal() {
    let registry = ManagedResourceRegistry::default();
    let _admission = registry.admit_check(binding(), owner(), TTL).unwrap();
    let resource = register(&registry);
    let route = registry.bind_route(route(&resource), TTL).unwrap();
    let snapshot = registry.snapshot(&binding()).unwrap();
    let (start_tx, start_rx) = std::sync::mpsc::channel();
    let (end_tx, end_rx) = std::sync::mpsc::channel();
    let worker = registry
        .with_current_snapshot(&snapshot, &binding(), || {
            let worker = std::thread::spawn(move || {
                start_tx.send(()).unwrap();
                drop(route);
                end_tx.send(()).unwrap();
            });
            start_rx.recv().unwrap();
            assert!(end_rx.try_recv().is_err());
            worker
        })
        .unwrap();
    worker.join().unwrap();
    end_rx.recv().unwrap();
    assert!(!registry.is_current(&snapshot));
}

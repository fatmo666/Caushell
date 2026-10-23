use caushell_types::{RuntimePingResponse, ShellEnvironmentValue as V, ShellStateSnapshot};
use serde_json::json;

#[test]
fn named_environment_observations_roundtrip_without_global_completeness() {
    let snapshot = ShellStateSnapshot::new("/work")
        .with_environment_observation("MODE", V::Present { value: "".into() })
        .with_environment_observation("FLAGS", V::Absent)
        .with_environment_observation("PATH", V::Unknown);
    let value = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(
        value,
        json!({"cwd":"/work", "environment":[
            {"name":"MODE","value":{"status":"present","value":""}},
            {"name":"FLAGS","value":{"status":"absent"}},
            {"name":"PATH","value":{"status":"unknown"}}
        ]})
    );
    assert_eq!(
        serde_json::from_value::<ShellStateSnapshot>(value).unwrap(),
        snapshot
    );
}

#[test]
fn old_snapshots_remain_unknown_not_empty_environment() {
    let snapshot: ShellStateSnapshot = serde_json::from_value(json!({"cwd":"/work"})).unwrap();
    assert!(snapshot.environment.is_empty());
    assert_eq!(
        serde_json::to_value(snapshot).unwrap(),
        json!({"cwd":"/work"})
    );
}

#[test]
fn presence_requires_a_value_and_does_not_accept_absence_with_bytes() {
    for value in [
        json!({"status":"present"}),
        json!({"status":"absent","value":""}),
        json!({"status":"unknown","value":"data"}),
    ] {
        assert!(serde_json::from_value::<V>(value).is_err());
    }
}

#[test]
fn named_environment_protocol_is_explicit_and_missing_on_older_servers() {
    assert_eq!(
        RuntimePingResponse::ok("test").environment_observation_protocol,
        Some(1)
    );
    let old: RuntimePingResponse =
        serde_json::from_value(json!({"status":"ok","runtime_version":"old"})).unwrap();
    assert_eq!(old.environment_observation_protocol, None);
}

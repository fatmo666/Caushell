use caushell_types::{RuntimePingResponse, ShellStateSnapshot};
use serde_json::json;

#[test]
fn pathname_snapshot_is_explicit_complete_and_backward_compatible() {
    let absent = json!({"status":"absent"});
    let mut state = json!({"cwd":"/work", "pathname": {
        "noglob":false,"nullglob":false,"failglob":false,"dotglob":false,"nocaseglob":false,
        "globstar":false,"extglob":false,"globskipdots":true,"globignore":absent,
        "lc_all":{"status":"present","value":"C"}, "lc_collate":absent, "lc_ctype":absent, "lang":absent
    }});
    let decoded: ShellStateSnapshot = serde_json::from_value(state.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), state);
    state["pathname"].as_object_mut().unwrap().remove("noglob");
    assert!(serde_json::from_value::<ShellStateSnapshot>(state).is_err());
    let old: ShellStateSnapshot = serde_json::from_value(json!({"cwd":"/work"})).unwrap();
    assert!(old.pathname.is_none());
    assert_eq!(serde_json::to_value(old).unwrap(), json!({"cwd":"/work"}));
    assert_eq!(
        RuntimePingResponse::ok("test").pathname_observation_protocol,
        Some(1)
    );
    let old: RuntimePingResponse =
        serde_json::from_value(json!({"status":"ok","runtime_version":"old"})).unwrap();
    assert_eq!(old.pathname_observation_protocol, None);
}

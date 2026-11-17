//! Exact original requests, adapted only to the direct Core API sequence contract.
//! This is a selected regression check, not a new full RQ1 score.
use caushell_core::ShellQueryCore;
use caushell_types::*;
#[test]
fn original_top_three_cohorts_and_all_baseline_denies_keep_their_boundaries() {
    let rows: serde_json::Value = serde_json::from_str(include_str!("fixtures/top3_original_requests.json")).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 468);
    let mut core = ShellQueryCore::new();
    let mut counts = std::collections::BTreeMap::new();
    for row in rows.as_array().unwrap() {
        let mut p = row["request"]["payload"].clone();
        p.as_object_mut().unwrap().remove("intent");
        p["sequence_no"] = serde_json::json!(1);
        let request: CheckRequest = serde_json::from_value(p).unwrap();
        let result = core.check(request);
        let predicted = serde_json::to_value(result.decision).unwrap();
        eprintln!("original {}: {} -> {}", row["id"], row["predicted"], predicted);
        assert_eq!(predicted, row["predicted"], "{}: {:?}", row["id"], result.reasons);
        *counts.entry(predicted.as_str().unwrap().to_owned()).or_insert(0usize) += 1;
    }
    assert_eq!(counts.get("deny"), Some(&9));
    assert_eq!(counts.get("need_approval"), Some(&459));
}

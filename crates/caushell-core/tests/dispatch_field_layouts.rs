//! Exercise the normal check path. The analyzed shell commands never run.
use caushell_core::ShellQueryCore;
use caushell_types::{CheckRequest, CheckResponse, Decision};

fn fixture_requests() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!("fixtures/dispatch_field_layout_requests.json")).unwrap()
}

fn request(payload: &serde_json::Value) -> CheckRequest {
    let mut payload = payload.clone();
    payload.as_object_mut().unwrap().remove("intent");
    payload["sequence_no"] = 1.into();
    serde_json::from_value(payload).unwrap()
}

fn controls(command: &str) -> CheckResponse {
    let mut request = request(&fixture_requests()[0]["request"]["payload"]);
    request.command = command.to_owned();
    ShellQueryCore::new().check(request)
}

#[test]
fn original_requests_check_all_layouts_and_keep_the_distinct_child_effects() {
    for row in fixture_requests() {
        let result = ShellQueryCore::new().check(request(&row["request"]["payload"]));
        let grep_forms: Vec<_> = result
            .decision_trace
            .execution_semantics
            .iter()
            .filter(|s| s.normalized_command_name == "grep")
            .map(|s| s.form_id.as_str())
            .collect();
        eprintln!(
            "{} {:?} {:?}: {:?}",
            row["id"], result.decision, grep_forms, result.reasons
        );
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(grep_forms.len(), 3);
        assert!(grep_forms.contains(&"positional_pattern_filename_records"));
        assert!(grep_forms.contains(&"positional_pattern_search_stdin"));
    }
}

#[test]
fn layout_uncertainty_cannot_move_region_boundaries_or_skip_effects() {
    for command in [
        r"find ./fixtures -exec grep $(printf ';') -l {} \;",
        r"find ./fixtures -exec grep X {} $(printf X) + -print",
        r"find ./fixtures -name $(printf X) -print",
        r"find ./fixtures -exec $(printf x) echo hi \;",
        r"find ./fixtures -exec echo $(printf abc) \;",
        r"find ./fixtures -exec echo $(printf '*') \;",
        r"find ./fixtures -exec grep $(printf 'a') $(printf 'b') $(printf 'c') -l {} \;",
        r"find ./fixtures -exec touch $(printf '\15') /outside/marker \;",
        r"find ./fixtures -exec touch $(printf '\15') ./marker \;",
    ] {
        let result = controls(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

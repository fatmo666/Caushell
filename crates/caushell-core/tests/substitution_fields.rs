//! Static checks only; no sample shell actions or substitutions are executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn check(text: &str) -> CheckResponse { check_shell(text, ShellKind::Bash) }
fn check_shell(text: &str, shell: ShellKind) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("substitution-fields"), sequence_no: CommandSequenceNo(1),
        command: text.into(), shell_kind: shell,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/benchmark-user".into()), workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata { runtime_name: "static-test".into(), tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only() },
    })
}
fn materialized(r: &CheckResponse) -> Vec<String> {
    r.decision_trace.evidence.iter().filter_map(|e| match &e.kind {
        EvidenceKind::ShellArgumentFields(p) => p.materialized_command.clone(),
        _ => None,
    }).collect()
}
#[test]
fn unknown_ifs_does_not_claim_an_exact_unquoted_argv() {
    for text in [r"printf %s $(printf 'a b')", r"touch $(printf /opt/shared/output)"] {
        let r=check(text);
        assert!(materialized(&r).is_empty(), "{text}: {:?}",materialized(&r));
        assert!(r.decision_trace.derived_invocations.iter().any(|v| matches!(v.origin,
            DerivedInvocationOrigin::CommandSubstitutionBody { .. })));
    }
}
#[test]
fn known_ifs_preserves_carriage_return_empty_fields_and_disabled_splitting() {
    for (text, expected) in [
        (r"IFS=$' \t\n'; printf %s $(printf '\15')", "printf %s '\r'"),
        (r"IFS=; printf %s $(printf 'a b')", "printf %s 'a b'"),
        (r"IFS=,; printf %s $(printf ',one,,two,')", "printf %s '' 'one' '' 'two'"),
    ] {
        let r=check(text);let got=materialized(&r);
        assert!(got.iter().any(|s|s==expected), "{text}: expected {expected:?}, got {got:?}");
    }
}
#[test]
fn produced_bytes_are_not_expanded_as_source_a_second_time() {
    for (text, expected) in [
        (r#"target=/opt/shared/output; touch "$(printf '$target')""#, "touch '$target'"),
        (r#"printf %s pre"$(printf 'a b')"post"#, "printf %s 'prea bpost'"),
    ] {
        let r=check(text);
        // The same complete fields now bind the original owning invocation.
        assert_eq!(r.decision,Decision::Allow,"{text}: {:?}",r.reasons);
        assert!(!r.decision_trace.path_targets.iter().any(|f|
            matches!(&f.resolution, SemanticResolution::Resolved {value} if value.concrete_path()==Some("/opt/shared/output"))));
        assert!(materialized(&r).iter().any(|s|s==expected), "{text}: {:?}",materialized(&r));
    }
    let r=check(r#"touch "$(printf '$(touch /opt/shared/output)')""#);
    assert!(materialized(&r).iter().any(|s|s=="touch '$(touch /opt/shared/output)'"));
    assert!(!r.decision_trace.execution_units.iter().any(|u|u.raw_text=="touch /opt/shared/output"));
}
#[test]
fn reconstruction_retains_prefix_assignments_and_outer_redirections() {
    for text in [r#"FLAG=value printf %s "$(printf data)""#,
                 r#"printf %s "$(printf data)" > /opt/shared/output"#] {
        let r=check(text);let got=materialized(&r);
        assert!(got.iter().any(|s| if text.starts_with("FLAG=") {s.starts_with("FLAG=value ")}
            else {s.ends_with(" > /opt/shared/output")}), "{text}: {got:?}");
        if text.contains("/opt/shared") {assert_ne!(r.decision,Decision::Allow);}
    }
}
#[test]
fn glob_unknown_producers_and_mixed_unquoted_words_are_not_invented() {
    for text in [r"unset IFS; printf %s $(printf '*')", r"unset IFS; touch pre$(printf x)",
        r#"touch "$(printf safe; cat /unknown)""#,r#"touch "$(printf safe > /opt/shared/output)""#] {
        let r=check(text);assert!(materialized(&r).is_empty(),"{text}: {:?}",materialized(&r));
    }
}
#[test]
fn ifs_injected_command_boundaries_do_not_split_literal_characters() {
    let r=check("IFS=f; printf${IFS}X");
    assert_eq!(r.decision,Decision::Allow,"{:?}",r.reasons);
    assert!(r.decision_trace.execution_semantics.iter().any(|s|s.normalized_command_name=="printf"));
}
#[test]
fn unknown_ifs_keeps_possible_hazards_without_positive_argv_proofs() {
    for text in ["rm${IFS}-rf${IFS}/etc", "IFS=$'\\r'; rm${IFS}-rf${IFS}/etc",
                 "IFS=$'\\v'; rm${IFS}-rf${IFS}/etc", "IFS=$'\\f'; rm${IFS}-rf${IFS}/etc"] {
        assert_eq!(check(text).decision, Decision::Deny, "{text}");
    }
    // Native dialects without exact Bash field proof still retain hazards.
    assert_eq!(check_shell("rm${IFS}-rf${IFS}/etc", ShellKind::Sh).decision, Decision::Deny);
    assert_ne!(check_shell("printf${IFS}safe", ShellKind::Sh).decision, Decision::Allow);
    let r = check("printf${IFS}safe");
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    for text in ["IFS=$'\\r'; printf %s $(printf 'a b')",
                 "IFS=,; printf %s $(printf ',a,,')\"\""] {
        assert!(materialized(&check(text)).is_empty(), "{text}");
    }
}
#[test]
fn original_argv_cohort_is_measured_without_changing_context() {
    let rows: serde_json::Value=serde_json::from_str(include_str!("fixtures/substitution_field_requests.json")).unwrap();
    assert_eq!(rows.as_array().unwrap().len(),163);
    let mut core = ShellQueryCore::new();
    let mut sessions = std::collections::BTreeSet::new();
    for row in rows.as_array().unwrap() {
        let mut p=row["request"]["payload"].clone();p.as_object_mut().unwrap().remove("intent");
        p["sequence_no"]=serde_json::json!(1);
        assert!(sessions.insert(p["session_id"].as_str().unwrap().to_owned()));
        let r=core.check(serde_json::from_value(p).unwrap());
        eprintln!("measured {}: {:?} {:?}",row["id"].as_str().unwrap(),r.decision,r.reasons);
        assert_ne!(r.decision,Decision::Allow,"unexpected widening for {}",row["id"]);
    }
}

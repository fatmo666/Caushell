//! Static checks only. Expansion evidence must reach the owning invocation.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn request(text: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("substitution-authority"),
        sequence_no: CommandSequenceNo(1),
        command: text.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}
fn check(text: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(text))
}
#[test]
fn exact_fields_close_only_the_owning_argv_gap() {
    for (expanded, literal) in [
        (r#"touch "$(printf safe)""#, "touch safe"),
        (
            r#"target=/opt/shared/output; touch "$(printf '$target')""#,
            "touch '$target'",
        ),
        (r#"touch pre"$(printf data)"post"#, "touch predatapost"),
        (
            r#"FLAG=value touch "$(printf safe)""#,
            "FLAG=value touch safe",
        ),
        (r#"IFS=' '; touch $(printf 'one two')"#, "touch one two"),
        (r#"touch "$(printf '*')""#, "touch '*'"),
        (r#"touch $(printf '') safe"#, "touch safe"),
        (r#"sed "$(printf 's/a/b/')""#, "sed 's/a/b/'"),
        (r#"env touch "$(printf safe)""#, "env touch safe"),
        (r#"env "$(printf touch)" safe"#, "env touch safe"),
        (r#"command touch "$(printf safe)""#, "command touch safe"),
    ] {
        let baseline = check(literal);
        assert_eq!(
            baseline.decision,
            Decision::Allow,
            "literal {literal}: {:?}",
            baseline.reasons
        );
        let result = check(expanded);
        assert_eq!(
            result.decision, baseline.decision,
            "{expanded}: {:?}",
            result.reasons
        );
        assert!(
            !result
                .reasons
                .iter()
                .any(|r| r.contains("argument region ownership is unresolved")),
            "{:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .evidence
                .iter()
                .any(|e| matches!(e.kind, EvidenceKind::ShellArgumentFields(_)))
        );
    }
}
#[test]
fn exact_fields_reenter_native_option_selection() {
    assert_eq!(
        check(r#"rm "$(printf %s -rf)" "$(printf /)""#).decision,
        Decision::Deny
    );
    assert_eq!(
        check(r#"IFS=' '; rm $(printf '%s' '-rf /')"#).decision,
        Decision::Deny
    );
    // A produced -- is a native delimiter, and shell metacharacters stay data.
    let result = check(r#"touch "$(printf %s --)" "$(printf '%s' '-rf;$(uname)')""#);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    assert!(
        !result
            .decision_trace
            .execution_units
            .iter()
            .any(|u| u.raw_text == "uname")
    );
}
#[test]
fn uncertain_fields_do_not_acquire_positive_authority() {
    for text in [
        r"touch $(printf safe)",
        r"unset IFS; touch $(printf '*')",
        r#"touch "$(printf safe; cat /unknown)""#,
        r#"touch "$(printf safe)" "$unknown""#,
        r#"touch pre$(printf safe)"#,
        r#"IFS=$'\r'; touch $(printf 'a b')"#,
        r#"sh -c 'touch "$(printf safe)"'"#,
    ] {
        assert_ne!(check(text).decision, Decision::Allow, "{text}");
    }
}
#[test]
fn producer_effects_remain_independent_of_output_fields() {
    assert_eq!(
        check(r#"touch "$(printf safe; rm -rf /)""#).decision,
        Decision::Deny
    );
    assert_eq!(
        check(r#"bash -c "$(printf 'rm -rf /')""#).decision,
        Decision::Deny
    );
    for text in [
        r#"touch "$(printf safe > /opt/shared/output)""#,
        r#"printf %s "$(printf data)" > /opt/shared/output"#,
        r#"sed "$(printf 's/a/b/e')""#,
        r#"sed "$(printf 'w /etc/passwd')""#,
        r#"sed -e "$(printf 's/a/b/')" -e 'e rm -rf /'"#,
    ] {
        assert_ne!(check(text).decision, Decision::Allow, "{text}");
    }
}
#[test]
fn configuration_and_directory_state_are_not_waived() {
    for text in [
        r#"curl "$(printf http://127.0.0.1)""#,
        r#"tar -cf "$(printf archive.tar)" file"#,
        r#"cd /opt/shared; touch "$(printf safe)""#,
        r#"touch "$(printf /opt/shared/output)""#,
        r#"value=/opt/shared/output; env value=safe touch "$(printf %s "$value")""#,
        r#"bash --rcfile /unknown -ic "$(printf 'touch safe')""#,
    ] {
        assert_ne!(check(text).decision, Decision::Allow, "{text}");
    }
}
#[test]
fn complete_fields_preserve_upload_effects_with_configuration_disabled() {
    // -q is supplied first, so missing curlrc evidence cannot mask this guard.
    for (expanded, literal) in [
        (
            r#"curl -q --data "$(printf SAFE)" https://example.test/"#,
            "curl -q --data SAFE https://example.test/",
        ),
        (
            r#"curl "$(printf %s -q)" --data SAFE https://example.test/"#,
            "curl -q --data SAFE https://example.test/",
        ),
    ] {
        let baseline = check(literal);
        let result = check(expanded);
        assert_eq!(baseline.decision, Decision::NeedApproval);
        assert_eq!(result.decision, baseline.decision, "{:?}", result.reasons);
        for response in [&baseline, &result] {
            assert!(
                response
                    .decision_trace
                    .findings
                    .iter()
                    .any(|finding| { finding.rule_id == RuleId::NetworkUpload }),
                "{expanded}: {response:?}"
            );
        }
    }
}
#[test]
fn expanded_scopes_use_the_same_authority_boundary() {
    for text in [
        r#"bash -c 'touch "$(printf safe)"'"#,
        r#"f() { touch "$(printf safe)"; }; f"#,
        r#"(touch "$(printf safe)")"#,
        r#"bash -c "$(printf 'touch safe')""#,
    ] {
        let result = check(text);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{text}: {:?}",
            result.reasons
        );
    }
}
#[test]
fn producer_lookup_is_not_replaced_with_a_builtin_assumption() {
    for text in [
        r#"printf() { cat /unknown; }; touch "$(printf safe)""#,
        r#"touch "$(/usr/bin/printf safe)""#,
        r#"alias printf='printf /opt/shared/output'; touch "$(printf safe)""#,
    ] {
        assert_ne!(check(text).decision, Decision::Allow, "{text}");
    }
}
#[test]
fn incomplete_depth_and_opaque_siblings_keep_their_own_approval() {
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 0;
    let result = ShellQueryCore::try_with_policy(policy)
        .unwrap()
        .check(request(r#"touch "$(printf safe)""#));
    assert_ne!(result.decision, Decision::Allow);
    assert!(
        !result
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(e.kind, EvidenceKind::ShellArgumentFields(_)))
    );
    assert_ne!(
        check(r#"opaque-command; touch "$(printf safe)""#).decision,
        Decision::Allow
    );
}
#[test]
fn exact_literal_byte_paths_keep_the_same_namespace_decision() {
    let literal = check(r#"touch -- '-rf;$(rm -rf /)'"#);
    let expanded = check(r#"touch "$(printf %s --)" "$(printf '%s' '-rf;$(rm -rf /)')""#);
    assert_eq!(
        expanded.decision, literal.decision,
        "literal: {:?}; expanded: {:?}",
        literal.reasons, expanded.reasons
    );
    assert!(
        !expanded
            .decision_trace
            .execution_units
            .iter()
            .any(|u| u.raw_text == "rm -rf /")
    );
}
#[test]
fn original_wrong_cases_and_all_denies_are_measured_without_new_observations() {
    let rows: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/substitution_authority_original_requests.json"
    ))
    .unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 934);
    let mut core = ShellQueryCore::new();
    let mut sessions = std::collections::BTreeSet::new();
    for row in rows.as_array().unwrap() {
        let mut p = row["request"]["payload"].clone();
        p.as_object_mut().unwrap().remove("intent");
        p["sequence_no"] = serde_json::json!(1);
        assert!(sessions.insert(p["session_id"].as_str().unwrap().to_owned()));
        let result = core.check(serde_json::from_value(p).unwrap());
        eprintln!(
            "ORIGINAL {}",
            serde_json::json!({"id":row["id"],"before":row["predicted"],"after":result.decision,"ground_truth":row["ground_truth"],"reasons":result.reasons})
        );
        if row["predicted"] == "deny" {
            assert_eq!(result.decision, Decision::Deny, "{}", row["id"]);
        }
    }
}

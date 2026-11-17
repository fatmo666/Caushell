//! Static analysis requests only. None of the sample commands is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("multi-action-dispatch"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command))
}

#[test]
fn sibling_regions_and_nested_scopes_keep_individual_known_children() {
    for command in [
        r"find . -exec echo {} \; -exec true {} \;",
        r"find . -exec echo {} + -o -exec true {} +",
        r"find . \( -exec echo {} \; -o -exec true {} \; \)",
        r"env find . -exec echo {} \; -exec true {} \;",
        r"bash -c 'find . -exec echo {} \; -exec true {} \;'",
        r"f() { find . -exec echo {} \; -exec true {} \;; }; f",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        for name in ["echo", "true"] {
            assert!(
                result
                    .decision_trace
                    .execution_semantics
                    .iter()
                    .any(|s| { s.normalized_command_name == name }),
                "{command}: missing {name}"
            );
        }
        assert!(
            !result
                .reasons
                .iter()
                .any(|r| r.contains("singular dispatched command"))
        );
    }
}

#[test]
fn unknown_executables_and_malformed_regions_keep_their_approval() {
    for command in [
        r#"find . -exec echo {} \; -exec "$UNKNOWN" {} \; -exec true {} \;"#,
        r"find . -exec echo {} \; -exec unknown-program {} \;",
        r"find . -exec echo {} \; -exec python3 -m unknown_cli_module {} \;",
        r"find . -exec echo {} \; -exec true {}",
        r"find . -execdir",
        r"find . -exec echo {} \; -unsupported",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn destructive_siblings_and_conditional_children_keep_their_real_guards() {
    for command in [
        r"find . -exec echo {} \; -exec rm -rf / \;",
        r"find . -exec rm -rf / \; -exec echo {} \;",
        r"find . \( -exec true {} \; -o -exec rm -rf / \; \)",
        r"env find . -exec echo {} \; -exec rm -rf / \;",
    ] {
        assert_eq!(check(command).decision, Decision::Deny, "{command}");
    }
    for command in [
        r"find . -exec echo {} \; -exec touch /opt/shared/output \;",
        r"find /opt/shared -exec echo {} \; -exec chmod 777 {} \;",
        r#"cd "$UNKNOWN"; find . -exec echo {} \; -exec touch {} \;"#,
        r#"find "$UNKNOWN" -exec echo {} \; -exec touch {} \;"#,
        r"find -L . -exec echo {} \; -exec touch {} \;",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn actual_child_frontier_keeps_the_depth_limit() {
    for leaf in [
        r"find . -exec echo {} \; -exec true {} \;",
        r#"find . -exec echo {} \; -exec "$UNKNOWN" {} \;"#,
    ] {
        let mut policy = PolicyConfig::default();
        policy.semantic_expansion.max_nested_parse_depth = 0;
        let result = ShellQueryCore::try_with_policy(policy)
            .unwrap()
            .check(request(leaf));
        assert_eq!(result.decision, Decision::NeedApproval);
        assert!(
            result.decision_trace.evidence.iter().any(|e| matches!(
                &e.kind, EvidenceKind::ExecutionExpansionTruncated(t)
                    if t.depth == 0 && t.next_candidate_count == 2
            )),
            "{leaf}: {result:?}"
        );
        // The trace can retain declared pending candidates. Only admitted
        // execution semantics may claim analysis below this zero-depth gate.
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.source.depth == 0)
        );
    }
}

#[test]
fn original_regressions_and_preserved_bom_gain_use_original_requests() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/multi_action_dispatch_requests.json")).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 27);
    let mut failures = Vec::new();
    for row in rows.as_array().unwrap() {
        let mut payload = row["request"]["payload"].clone();
        payload.as_object_mut().unwrap().remove("intent");
        // JSONL judge_only requests are adapted to the internal Core API,
        // which requires an explicit first-command sequence number.
        payload["sequence_no"] = serde_json::json!(1);
        let result = ShellQueryCore::new().check(serde_json::from_value(payload).unwrap());
        eprintln!(
            "ORIGINAL {}",
            serde_json::json!({
                "id":row["id"],"before":row["predicted"],"after":result.decision,
                "ground_truth":row["ground_truth"],"reasons":result.reasons
            })
        );
        if result.decision != Decision::Allow {
            failures.push((row["id"].clone(), result.reasons));
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}

//! Static checks using inert names and the existing benchmark workspace.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("find-argument-fields"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        workspace_root: Some("/bench/workspace".into()),
        home: Some("/home/test".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn check_with_frame(command: &str, variables: &[(&str, &str)]) -> CheckResponse {
    let mut request = request(command);
    request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
        binding: ExecutionFrameBinding::for_request(&request, "find-test-executor"),
        variables: variables
            .iter()
            .map(|(name, value)| ShellEnvironmentSnapshot {
                name: (*name).into(),
                value: ShellEnvironmentValue::Present {
                    value: (*value).into(),
                },
            })
            .collect(),
        environment: Vec::new(),
        variable_values: Vec::new(),
        integer_variables: Default::default(),
        native_variants: Default::default(),
        pathname: None,
    });
    ShellQueryCore::new().check(request)
}

fn check(command: &str, pwd: Option<&str>, ifs: Option<&str>) -> CheckResponse {
    let variables: Vec<_> = [("PWD", pwd), ("IFS", ifs)]
        .into_iter()
        .filter_map(|(name, value)| Some((name, value?)))
        .collect();
    check_with_frame(command, &variables)
}

fn observed_records(result: &CheckResponse) -> Vec<Vec<u8>> {
    let mut inputs: Vec<_> = result
        .decision_trace
        .evidence
        .iter()
        .filter_map(|e| match &e.kind {
            EvidenceKind::StdoutRecords(evidence) if evidence.complete => Some(&evidence.records),
            _ => None,
        })
        .flatten()
        .map(|record| record.bytes.clone())
        .collect();
    inputs.sort();
    inputs.dedup();
    inputs
}

fn has_ownership_gap(result: &CheckResponse) -> bool {
    result
        .reasons
        .iter()
        .any(|reason| reason.contains("argument region ownership is unresolved"))
}

#[test]
fn quoted_pwd_suffix_uses_the_observed_value_independently_of_cwd() {
    let expanded = check(
        r#"find "$PWD"/workspace -maxdepth 0 -print0"#,
        Some("/bench"),
        None,
    );
    let literal = check("find /bench/workspace -maxdepth 0 -print0", None, None);
    assert_eq!(expanded.decision, Decision::Allow, "{:?}", expanded.reasons);
    assert_eq!(observed_records(&expanded), observed_records(&literal));
    assert_eq!(
        observed_records(&expanded),
        vec![b"/bench/workspace\0".to_vec()]
    );
}

#[test]
fn scalar_and_composite_pwd_follow_the_same_observed_splitter() {
    let with_ifs = check(
        "find $PWD -maxdepth 0 -print0",
        Some(".:/bench"),
        Some(":"),
    );
    let literal = check("find . /bench -maxdepth 0 -print0", None, None);
    assert_eq!(with_ifs.decision, Decision::Allow, "{:?}", with_ifs.reasons);
    assert_eq!(observed_records(&with_ifs), observed_records(&literal));
    assert_eq!(observed_records(&with_ifs).len(), 2);
    let composite = check(
        "find $PWD/workspace -maxdepth 0 -print0",
        Some(".:/bench"),
        Some(":"),
    );
    let expected = check("find . /bench/workspace -maxdepth 0 -print0", None, None);
    assert_eq!(observed_records(&composite), observed_records(&expected));
    assert_eq!(observed_records(&composite).len(), 2);
    let quoted = check(
        r#"find "$PWD" -maxdepth 0 -print0"#,
        Some(".:/bench"),
        Some(":"),
    );
    assert!(observed_records(&quoted).is_empty());
    assert!(!has_ownership_gap(&quoted));
}

#[test]
fn missing_values_or_unproved_globbing_do_not_certify_exact_find_argv() {
    let glob = check("find $PWD -maxdepth 0", Some("/bench/*"), Some(":"));
    assert_eq!(glob.decision, Decision::NeedApproval, "{:?}", glob.reasons);
    assert!(has_ownership_gap(&glob));
    assert_ne!(
        check(r#"find "$PWD" -maxdepth 0"#, None, None).decision,
        Decision::Allow
    );
    let legacy = check("find $HOME -maxdepth 0", None, None);
    assert_eq!(legacy.decision, Decision::Allow, "{:?}", legacy.reasons);
}

#[test]
fn a_known_substitution_with_an_unquoted_suffix_reenters_find_binding() {
    let raw = "find $(printf '%s' 'left:right')/child -maxdepth 0";
    let expanded = check(raw, None, Some(":"));
    assert_eq!(expanded.decision, Decision::Allow, "{:?}", expanded.reasons);
    assert!(expanded.decision_trace.evidence.iter().any(|e| {
        matches!(&e.kind, EvidenceKind::ShellArgumentFields(f) if f.fields == ["left", "right/child"])
    }));
    assert_ne!(check(raw, None, None).decision, Decision::Allow);
}

#[test]
fn bare_pwd_and_shadowed_producers_do_not_inherit_working_directory_bytes() {
    for raw in [
        "find $(pwd)/child -maxdepth 0",
        "find `pwd` -maxdepth 0",
        "printf() { cat /missing-field-source; }; find $(printf left)/child -maxdepth 0",
    ] {
        let result = check(raw, Some("/bench/workspace"), Some(" "));
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{raw}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn visible_directory_changes_invalidate_old_pwd_and_oldpwd_spellings() {
    for name in ["PWD", "OLDPWD"] {
        for prefix in ["cd /bench;", "change() { cd /bench; }; change;"] {
            let raw = format!(r#"{prefix} find "${name}" -maxdepth 0"#);
            let response = check_with_frame(&raw, &[(name, "/bench/workspace/stale")]);
            assert!(
                has_ownership_gap(&response),
                "{raw}: {:?}",
                response.reasons
            );
        }
    }
    let sub = check(
        r#"(cd .); find "$PWD"/workspace -maxdepth 0"#,
        Some("/bench"),
        None,
    );
    assert!(!has_ownership_gap(&sub), "{:?}", sub.reasons);
}

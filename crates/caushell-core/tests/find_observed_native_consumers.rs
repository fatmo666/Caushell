//! Static end-to-end tests. The harness provides one inert workspace file.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        command: command.into(),
        session_id: SessionId::new("find-observed-native-consumers"),
        sequence_no: CommandSequenceNo(1),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        workspace_root: Some("/bench/workspace".into()),
        home: Some("/home/test".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

fn complete_decode(result: &CheckResponse) -> bool {
    result
        .decision_trace
        .evidence
        .iter()
        .any(|e| matches!(&e.kind, EvidenceKind::NativeInputDecode(d) if d.complete))
}

#[test]
fn rename_uses_verified_stdin_without_inventing_file_operands() {
    for command in [
        r"find . -name 'not-in-the-fixture' | rename 's/old$/new/'",
        r"find . -name '.rq1-sentinel' | rename 's/old$/new/'",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            complete_decode(&result),
            "{command}: {:#?}",
            result.decision_trace.evidence
        );
    }
}

#[test]
fn changing_or_replaced_stdin_does_not_inherit_the_candidate() {
    for command in [
        r"find . -name '.rq1-sentinel' | rename 's/sentinel$/renamed/'",
        r"find . -name 'not-in-the-fixture' | rename 's/old$/new/' < unknown.list",
        r"find ./missing-producer -name 'not-in-the-fixture' | rename 's/old$/new/'",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            !complete_decode(&result),
            "{command}: {:#?}",
            result.decision_trace.evidence
        );
    }
}

#[test]
fn verified_empty_stdin_does_not_hide_perl_startup_controls() {
    for command in [
        r"find . -name 'not-in-the-fixture' | PERL5OPT=-MFixtureProbe rename 's/old$/new/'",
        r"find . -name 'not-in-the-fixture' | PERL5LIB=./fixture-modules file-rename 's/old$/new/'",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
        assert!(!complete_decode(&result));
        assert!(
            result.decision_trace.nested_payloads.iter().any(|payload| {
                matches!(&payload.origin, NestedPayloadOrigin::Parameter { slot_name }
                    if slot_name.starts_with("perl_"))
            }),
            "{command}: {:#?}",
            result.decision_trace.nested_payloads
        );
    }
}

#[test]
fn observed_metadata_targets_are_bound_and_still_audited() {
    let command = r"find . -type f -name '.rq1-sentinel' | cpio -oa";
    let result = check(command);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    assert!(
        result.decision_trace.path_targets.iter().any(|target| {
            target.operation == PathTargetOperation::Metadata
                && target.lexical.concrete_path() == Some("/bench/workspace/.rq1-sentinel")
        }),
        "{:#?}",
        result.decision_trace.path_targets
    );
    assert!(complete_decode(&result));
    assert_ne!(
        check(r"printf '%s\n' /opt/shared/file | cpio -oa").decision,
        Decision::Allow
    );
}

#[test]
fn general_metadata_mutation_cannot_borrow_source_metadata_preservation() {
    let result = check("find . -type f | xargs chown fixture-owner");
    assert_eq!(
        result.decision,
        Decision::NeedApproval,
        "{:?}",
        result.reasons
    );
    assert!(!complete_decode(&result));
}

#[test]
fn short_circuited_case_tests_can_certify_stdout_without_a_locale() {
    let skipped = check(r"find . -false -a -iname '*.txt' -print0 | xargs -r0 ls -l");
    assert!(
        skipped
            .decision_trace
            .evidence
            .iter()
            .any(|e| matches!(&e.kind,
                EvidenceKind::StdoutRecords(p) if p.complete && p.records.is_empty()
            )),
        "{:#?}",
        skipped.decision_trace.evidence
    );
    let reached = check(r"find . -type f -iname '*.txt' -print0 | cat");
    assert!(
        reached.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
            EvidenceKind::StdoutRecords(p) if !p.complete
                && p.gap.as_deref() == Some("native case folding locale is unobserved or unsupported")
        )),
        "{:#?}",
        reached.decision_trace.evidence
    );
}

//! Graph/guard checks only. Submitted command strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("parameter-removal"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    });
    assert_eq!(r.decision, expected, "{command}: {r:#?}");
    r
}

#[test]
fn exact_targets_work_uniformly_for_all_four_operators_and_consumers() {
    for command in [
        "f=./report.html; mv -- \"$f\" \"${f%.html}.txt\"",
        "f=./report.html; touch -- \"${f%%.*}.txt\"",
        "f=./src/report.html; cp -- \"$f\" \"${f##*/}\"",
        "f=./src/report.html; touch -- \"${f#./}\"",
        "f=./report.html; target=${f%.html}.txt; touch -- \"$target\"",
        "f=./report.html; ext=.html; touch -- \"${f%${ext}}.txt\"",
        "f=./report.html; sh -c 'touch -- \"${1%.html}.txt\"' _ \"$f\"",
        "f=./report.html; run() { touch -- \"${1%.html}.txt\"; }; run \"$f\"",
    ] {
        let r = check(command, Decision::Allow);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id.family() == RuleFamily::ResolveGap),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn exact_outside_and_destructive_results_keep_real_guards() {
    for command in [
        "f=/opt/report.html; touch -- \"${f%.html}.txt\"",
        "f=/opt/report.html; mv -- \"$f\" \"${f%.html}.txt\"",
        "f=x/opt/out; touch -- \"${f#x}\"",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {r:#?}"
        );
        assert!(
            !r.reasons.iter().any(|r| r.contains("cannot be resolved")),
            "{command}: {r:#?}"
        );
    }
    check("f=/.txt; rm -rf -- \"${f%.txt}\"", Decision::Deny);
    check("f=./a.txt; rm -- \"${f%.txt}\"", Decision::NeedApproval);
}

#[test]
fn abstract_filename_suffixes_work_in_loops_functions_and_native_child_shells() {
    for command in [
        "for f in ./*.html; do mv -- \"$f\" \"${f%.html}.txt\"; done",
        "find . -name '*.txt' -exec sh -c 'mv -- \"$0\" \"${0%.txt}.txt_bak\"' {} \\;",
        "find . -name '*.txt' -exec sh -c 'mv -- \"$1\" \"${1%.txt}.txt_bak\"' _ {} \\;",
        "find . -name '*.txt' -exec sh -c 'shift; touch -- \"${1%.txt}.bak\"' _ ignored {} \\;",
        "run() { touch -- \"${1%.html}.txt\"; }; for f in ./*.html; do run \"$f\"; done",
        "for f in /tmp/*.html; do touch -- \"${f%.html}.txt\"; done",
    ] {
        check(command, Decision::Allow);
    }
    check(
        "for f in /opt/*.html; do touch -- \"${f%.html}.txt\"; done",
        Decision::NeedApproval,
    );
}

#[test]
fn bounded_root_member_and_dot_dot_cases_never_gain_trust() {
    for command in [
        "for f in ./...html; do touch -- \"${f%.html}\"; done",
        "find . -name '*.html' -exec sh -c 'touch -- \"${1%.html}\"' _ {} \\;",
        "find /opt -name '*.txt' -exec sh -c 'touch -- \"${1%.txt}.bak\"' _ {} \\;",
        "for f in ./*.txt; do touch -- \"${f%/*}.bak\"; done",
    ] {
        check(command, Decision::NeedApproval);
    }
    // A native root can itself match the removed suffix; it must not be
    // treated as a descendant whose original root spelling is unchanged.
    check(
        "find /opt/report.html -exec sh -c 'touch -- \"${1%.html}.txt\"' _ {} \\;",
        Decision::NeedApproval,
    );
}

#[test]
fn unknown_patterns_and_argument_frames_are_not_assumed_empty_or_safe() {
    for command in [
        "touch -- \"${UNKNOWN%.txt}.bak\"",
        "f=./a.txt; touch -- \"${f%$UNKNOWN}.bak\"",
        "for f in ./*.txt; do touch -- \"${f%/}.bak\"; done",
        "find . -name '*.txt' -exec sh -c 'set -- /opt/new.txt; touch -- \"${1%.txt}.bak\"' _ {} \\;",
        "find . -name '*.txt' -exec sh -c 'shift; touch -- \"${1%.txt}.bak\"' _ {} /opt/new.txt \\;",
    ] {
        check(command, Decision::NeedApproval);
    }
    // A successful shift of the sole known-width item proves $1 absent.
    check(
        "sh -c 'shift; touch -- \"${1%.txt}.bak\"' _ ./a.txt",
        Decision::Allow,
    );
}

#[test]
fn expanded_bytes_are_data_not_a_new_round_of_shell_source() {
    let command = "f='./$(touch /opt/out)*.txt'; touch -- \"${f%.txt}.bak\"";
    let r = check(command, Decision::Allow);
    assert!(
        !r.decision_trace
            .derived_invocations
            .iter()
            .any(|d| d.raw_text.contains("/opt/out")),
        "{r:#?}"
    );
}

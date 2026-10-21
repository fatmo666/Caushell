//! Only parses/analyzes text; none of the sample commands is executed.
use caushell_core::{SessionState, ShellQueryCore};
use caushell_graph::SessionGraph;
use caushell_query::{StateCandidateQuery, StateCandidateResult};
use caushell_types::*;

fn request(n: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("capture:test"),
        sequence_no: CommandSequenceNo(n),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "capture-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/test".into()),
        workspace_root: Some("/bench/workspace".into()),
    }
}

fn candidates(
    core: &ShellQueryCore,
    kind: SafetyStateKind,
    name: &str,
    scope: SafetyScope,
    sequence: u64,
    start: usize,
) -> StateCandidateResult {
    let snapshot = core
        .session_snapshot(&SessionId::new("capture:test"), 0)
        .unwrap();
    let graph = SessionGraph::from_snapshot(snapshot.graph).unwrap();
    StateCandidateQuery {
        object: &SafetyObject {
            scope,
            kind,
            name: name.into(),
        },
        before_sequence: CommandSequenceNo(sequence),
        before_source_start: start,
        limits: &AnalysisBudgetPolicy::default(),
    }
    .execute(&graph)
}

fn variables(core: &ShellQueryCore, name: &str) -> Vec<SafetyStateValue> {
    candidates(
        core,
        SafetyStateKind::Variable,
        name,
        SafetyScope::Shell,
        99,
        0,
    )
    .candidates
    .into_iter()
    .map(|v| v.value)
    .collect()
}

fn scalar(value: &str) -> SafetyStateValue {
    SafetyStateValue::Variable {
        value: SessionVariableValue::exact_scalar(value),
        exported: false,
    }
}

#[test]
fn intermediate_and_repeated_assignment_values_survive_unset_and_snapshot_restore() {
    let mut core = ShellQueryCore::new();
    let command = "DEST=/outside DEST=/bench/workspace; DEST=/other; unset DEST";
    assert_eq!(core.check(request(1, command)).decision, Decision::Allow);
    let values = variables(&core, "DEST");
    for value in [
        scalar("/outside"),
        scalar("/bench/workspace"),
        scalar("/other"),
        SafetyStateValue::Absent,
    ] {
        assert!(values.contains(&value), "missing {value:?}: {values:?}");
    }
    let early = candidates(
        &core,
        SafetyStateKind::Variable,
        "DEST",
        SafetyScope::Shell,
        1,
        0,
    );
    assert!(
        early.candidates.is_empty(),
        "later writes may not leak before their source position"
    );
    let snapshot = core
        .session_snapshot(&SessionId::new("capture:test"), 0)
        .unwrap();
    let mut restored = ShellQueryCore::new();
    restored.insert_session_state(
        snapshot.session_id.clone(),
        SessionState::from_snapshot(snapshot).unwrap(),
    );
    assert_eq!(variables(&restored, "DEST"), values);
}

#[test]
fn approval_records_possible_values_once_but_rejection_and_judge_only_do_not() {
    for approve in [false, true] {
        let mut core = ShellQueryCore::new();
        let outcome = core
            .try_check_with_outcome(request(
                1,
                "DEST=/outside; DEST=/bench/outside/a; touch \"$DEST\"",
            ))
            .unwrap();
        assert_eq!(outcome.response.decision, Decision::NeedApproval);
        assert!(variables(&core, "DEST").is_empty());
        let receipt = outcome.check_receipt.unwrap();
        let approval = ApprovalRequest {
            check_id: receipt.check_id,
            state_revision: receipt.state_revision,
            approved: approve,
            authority: ApprovalAuthority::SimulatedUser,
        };
        core.authorize(&approval).unwrap();
        let values = variables(&core, "DEST");
        assert_eq!(values.contains(&scalar("/outside")), approve);
        core.authorize(&approval).unwrap();
        assert_eq!(variables(&core, "DEST"), values);
    }
    let mut core = ShellQueryCore::new();
    core.try_check_with_intent(request(1, "DEST=/outside"), CheckIntent::JudgeOnly)
        .unwrap();
    assert!(variables(&core, "DEST").is_empty());
    assert_eq!(
        core.check(request(2, "DEST=/outside; rm -rf /")).decision,
        Decision::Deny
    );
    assert!(variables(&core, "DEST").is_empty());
}

#[test]
fn called_function_retains_intermediate_global_writes_not_local_or_positional_values() {
    let mut core = ShellQueryCore::new();
    let response = core.check(request(1, "f() { GLOBAL=/outside; GLOBAL=/bench/workspace; local LOCAL=/outside; LOCAL=/bench/workspace; set -- /outside; }; f"));
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    let values = variables(&core, "GLOBAL");
    assert!(values.contains(&scalar("/outside")), "{values:?}");
    assert!(values.contains(&scalar("/bench/workspace")), "{values:?}");
    assert!(variables(&core, "LOCAL").is_empty());
    assert!(
        candidates(
            &core,
            SafetyStateKind::Positionals,
            "@",
            SafetyScope::Shell,
            99,
            0
        )
        .candidates
        .is_empty()
    );
}

#[test]
fn aliases_functions_and_positionals_do_not_disappear_on_replacement() {
    let mut core = ShellQueryCore::new();
    assert_eq!(core.check(request(1, "alias deploy='echo first'; alias deploy='echo second'; unalias deploy; f() { echo first; }; f() { echo second; }; unset -f f; set -- /outside; set -- /bench/workspace" )).decision, Decision::Allow);
    for (kind, name) in [
        (SafetyStateKind::Alias, "deploy"),
        (SafetyStateKind::Function, "f"),
    ] {
        let values: Vec<_> = candidates(&core, kind, name, SafetyScope::Shell, 99, 0)
            .candidates
            .into_iter()
            .map(|v| v.value)
            .collect();
        assert!(
            values.iter().any(
                |v| matches!(v, SafetyStateValue::Definition { body, .. } if body.contains("first"))
            ),
            "{kind:?}: {values:?}"
        );
        assert!(values.iter().any(|v| matches!(v, SafetyStateValue::Definition { body, .. } if body.contains("second"))), "{kind:?}: {values:?}");
        assert!(values.contains(&SafetyStateValue::Absent));
    }
    let positionals = candidates(
        &core,
        SafetyStateKind::Positionals,
        "@",
        SafetyScope::Shell,
        99,
        0,
    );
    for value in ["/outside", "/bench/workspace"] {
        assert!(positionals.candidates.iter().any(|c| c.value
            == SafetyStateValue::Positionals(vec![SessionVariableValue::exact_scalar(value)])));
    }
}

#[test]
fn isolated_invocation_and_unreachable_writes_do_not_pollute_the_persistent_shell() {
    let mut core = ShellQueryCore::new();
    let mut req = request(1, "DEST=/outside; DEST=/bench/workspace");
    req.runtime.shell_runtime_capabilities = ShellRuntimeCapabilities::request_only();
    assert_eq!(core.check(req).decision, Decision::Allow);
    assert!(variables(&core, "DEST").is_empty());
    assert_eq!(
        candidates(
            &core,
            SafetyStateKind::Variable,
            "DEST",
            SafetyScope::Invocation {
                sequence_no: CommandSequenceNo(1)
            },
            2,
            0
        )
        .candidates
        .len(),
        2
    );
    core.check(request(2, "exit; AFTER=/outside"));
    assert!(variables(&core, "AFTER").is_empty());
}

#[test]
fn candidate_padding_reaches_sticky_approval_instead_of_evicting_the_risky_value() {
    let mut policy = PolicyConfig::default();
    policy.analysis_budget.max_candidates_per_object = 3;
    let mut core = ShellQueryCore::with_policy(policy);
    let outcome = core
        .try_check_with_outcome(request(
            1,
            "DEST=/outside; DEST=safe1; DEST=safe2; DEST=safe3",
        ))
        .unwrap();
    assert_eq!(outcome.response.decision, Decision::NeedApproval);
    assert!(
        outcome
            .response
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::AnalysisIncomplete)
    );
    assert_eq!(
        core.check(request(2, "pwd")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn replacing_a_known_entry_value_keeps_it_and_scoped_prefixes_do_not_escape() {
    let mut core = ShellQueryCore::new();
    let mut req = request(
        1,
        "DEST=/bench/workspace; TEMP=/outside printf hello; (ISOLATED=/outside)",
    );
    req.shell_state_before = req
        .shell_state_before
        .with_exact_scalar_variable("DEST", "/outside", false)
        .with_variable_knowledge(ShellStateKnowledge::Complete);
    assert_eq!(core.check(req).decision, Decision::Allow);
    let values = variables(&core, "DEST");
    assert!(values.contains(&scalar("/outside")), "{values:?}");
    assert!(values.contains(&scalar("/bench/workspace")), "{values:?}");
    assert!(variables(&core, "TEMP").is_empty());
    assert!(variables(&core, "ISOLATED").is_empty());
}

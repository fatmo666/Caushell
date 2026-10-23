use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("read-source-state"),
        sequence_no: CommandSequenceNo(sequence),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete),
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn decision(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(command, 1))
}

#[test]
fn complete_nul_file_input_flows_only_to_the_success_branch() {
    for (path, expected) in [
        ("/workspace/a b", Decision::Allow),
        ("/outside/a b", Decision::NeedApproval),
    ] {
        let command = format!(
            "printf '%s\\0' '{path}' > argument.bin; IFS= read -r -d '' slot < argument.bin && touch -- \"$slot\""
        );
        let result = decision(&command);
        assert_eq!(result.decision, expected, "{command}: {result:#?}");
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .any(|t| t.lexical.concrete_path() == Some(path)),
            "{result:#?}"
        );
    }
}

#[test]
fn historical_bytes_and_function_local_reads_use_the_same_input_boundary() {
    for capabilities in [
        ShellRuntimeCapabilities::persistent_shell(),
        ShellRuntimeCapabilities::request_only(),
    ] {
        let mut core = ShellQueryCore::new();
        let mut first = request("printf '%s\\0' /workspace/file > argument.bin", 1);
        first.runtime.shell_runtime_capabilities = capabilities.clone();
        assert_eq!(core.check(first).decision, Decision::Allow);
        let mut next = request(
            "IFS= read -r -d '' slot < argument.bin && touch -- \"$slot\"",
            2,
        );
        next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        next.runtime.shell_runtime_capabilities = capabilities;
        let result = core.check(next);
        assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    }
    let result = decision(
        "f() { local slot=/workspace/old; IFS= read -r slot <<< /workspace/file && touch -- \"$slot\"; }; f",
    );
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
}

#[test]
fn source_success_propagates_state_through_and_chains_and_then_arms() {
    for suffix in [
        "source ./invocation.conf && touch -- \"$slot\"",
        "source ./invocation.conf && true && touch -- \"$slot\"",
        "if source ./invocation.conf; then touch -- \"$slot\"; fi",
    ] {
        for (path, expected) in [
            ("/workspace/file", Decision::Allow),
            ("/outside/file", Decision::NeedApproval),
        ] {
            let command = format!("printf '%s\\n' 'slot={path}' > invocation.conf; {suffix}");
            let result = decision(&command);
            assert_eq!(result.decision, expected, "{command}: {result:#?}");
            assert!(
                result
                    .decision_trace
                    .path_targets
                    .iter()
                    .any(|t| t.lexical.concrete_path() == Some(path)),
                "{result:#?}"
            );
        }
    }
}

#[test]
fn failed_reads_unknown_bytes_and_shared_streams_keep_the_gap() {
    for command in [
        "IFS= read -r -d '' slot < unknown.bin && touch -- \"$slot\"",
        "printf '%s' /workspace/file > argument.bin; IFS= read -r -d '' slot < argument.bin && touch -- \"$slot\"",
        "printf '%s\\0' /workspace/file > argument.bin; IFS= read -r -d '' slot < argument.bin; touch -- \"$slot\"",
        "{ IFS= read -r first; IFS= read -r slot && touch -- \"$slot\"; } <<< /workspace/file",
        "printf '%s\\0' /workspace/file > argument.bin; while IFS= read -r -d '' slot < argument.bin; do touch -- \"$slot\"; done",
    ] {
        let result = decision(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
    }
}

#[test]
fn source_joins_failure_paths_and_partial_bodies_do_not_become_exact() {
    for suffix in [
        "source ./invocation.conf || touch -- \"$slot\"",
        "source ./invocation.conf && true; touch -- \"$slot\"",
        "if test -f flag; then source ./invocation.conf; fi; touch -- \"$slot\"",
    ] {
        let command = format!(
            "slot=/outside/file; printf '%s\\n' 'slot=/workspace/file' > invocation.conf; {suffix}"
        );
        let result = decision(&command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
    }
    let result = decision("source ./unknown.conf && touch -- \"$slot\"");
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    for body in [
        "return 0; slot=/workspace/file",
        "eval unknown; slot=/workspace/file",
        "if unknown; then slot=/workspace/file; fi",
    ] {
        let command = format!(
            "slot=/outside/file; printf '%s\\n' '{body}' > invocation.conf; source ./invocation.conf && touch -- \"$slot\""
        );
        let result = decision(&command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
    }
}

#[test]
fn read_writes_follow_references_without_freezing_the_relation() {
    let result =
        decision("input=/workspace/file; IFS= read -r slot <<< \"$input\" && touch -- \"$slot\"");
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    assert!(
        result
            .decision_trace
            .path_targets
            .iter()
            .any(|t| t.lexical.concrete_path() == Some("/workspace/file")),
        "{result:#?}"
    );
    let result = decision("IFS= read -r slot <<< '$input' && touch -- \"$slot\"");
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    let result = decision("HOME=/outside; IFS= read -r slot <<< ~/file && touch -- \"$slot\"");
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    let result =
        decision("input=/outside/file; IFS= read -r slot <<< \"$input\" && touch -- \"$slot\"");
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    let result = decision(
        "target=/workspace/old; declare -n ref=target; IFS= read -r ref <<< /outside/new && touch -- \"$target\"",
    );
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    let result = decision("declare -i slot=0; IFS= read -r slot <<< 1+2 && touch -- \"$slot\"");
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
}

#[test]
fn unmodeled_destination_attributes_survive_between_actions() {
    for declaration in [
        "declare -i slot=0",
        "declare -u slot=old",
        "declare -l slot=old",
    ] {
        let mut core = ShellQueryCore::new();
        let outcome = core
            .try_check_with_outcome(request(declaration, 1))
            .unwrap();
        if let Some(receipt) = outcome.check_receipt {
            core.authorize(&ApprovalRequest {
                check_id: receipt.check_id,
                state_revision: receipt.state_revision,
                approved: true,
                authority: ApprovalAuthority::SimulatedUser,
            })
            .unwrap();
        }
        let mut next = request("IFS= read -r slot <<< 1+2 && touch -- \"$slot\"", 2);
        next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        let result = core.check(next);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{declaration}: {result:#?}"
        );
    }
}

#[test]
fn branch_local_facts_do_not_escape_through_persistence_or_erase_prior_gaps() {
    let mut scoped = ShellQueryCore::new();
    let result = scoped.check(request(
        "set -- caller; printf '%s\\n' 'set -- /outside/temporary; slot=/workspace/file' > invocation.conf; source ./invocation.conf temporary && true", 1));
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    let snapshot = scoped
        .session_snapshot(&SessionId::new("read-source-state"), 0)
        .unwrap();
    let graph = caushell_graph::SessionGraph::from_snapshot(snapshot.graph).unwrap();
    let candidates = caushell_query::StateCandidateQuery {
        object: &SafetyObject {
            scope: SafetyScope::Shell,
            kind: SafetyStateKind::Positionals,
            name: "@".into(),
        },
        before_sequence: CommandSequenceNo(99),
        before_source_start: 0,
        limits: &AnalysisBudgetPolicy::default(),
    }
    .execute(&graph);
    assert!(!candidates.candidates.iter().any(|v| matches!(&v.value,
        SafetyStateValue::Positionals(values) if values.iter().any(|value| matches!(value,
            SessionVariableValue::ExactScalar(value) if value == "/outside/temporary" || value == "temporary")))), "{candidates:?}");
    let mut core = ShellQueryCore::new();
    let result = core.check(request(
        "printf '%s\\n' 'slot=/workspace/file' > invocation.conf; source ./invocation.conf && true",
        1,
    ));
    assert_eq!(result.decision, Decision::Allow, "{result:#?}");
    let snapshot = core
        .session_snapshot(&SessionId::new("read-source-state"), 0)
        .unwrap();
    assert!(snapshot.summary.shell_state_uncertainty().is_some());
    let mut next = request("touch -- \"$slot\"", 2);
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let result = core.check(next);
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    let mut core = ShellQueryCore::new();
    let outcome = core
        .try_check_with_outcome(request("source ./unknown.conf", 1))
        .unwrap();
    assert_eq!(outcome.response.decision, Decision::NeedApproval);
    let receipt = outcome.check_receipt.unwrap();
    core.authorize(&ApprovalRequest {
        check_id: receipt.check_id,
        state_revision: receipt.state_revision,
        approved: true,
        authority: ApprovalAuthority::SimulatedUser,
    })
    .unwrap();
    let mut next = request(
        "printf '%s\\n' 'slot=/workspace/file' > invocation.conf; source ./invocation.conf && touch -- \"$slot\"",
        2,
    );
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    let result = core.check(next);
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
}

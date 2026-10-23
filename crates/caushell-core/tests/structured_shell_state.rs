use caushell_core::{SessionState, ShellQueryCore};
use caushell_profile::{EnvironmentValueRef, SessionBindings};
use caushell_query::{QuerySession, StateCandidateQuery, VariableBindingQuery};
use caushell_types::*;

fn values() -> Vec<StructuredShellValue> {
    vec![
        StructuredShellValue::IndexedArray {
            elements: Default::default(),
            complete: true,
        },
        StructuredShellValue::IndexedArray {
            elements: [(2, ShellScalarValue::exact("/outside"))].into(),
            complete: false,
        },
        StructuredShellValue::AssociativeArray {
            elements: [(
                "selected".into(),
                ShellScalarValue::exact("/workspace/safe"),
            )]
            .into(),
            complete: true,
        },
        StructuredShellValue::NameReference {
            target: ShellReferenceTarget::Variable {
                name: "target".into(),
            },
        },
        StructuredShellValue::Unknown {
            reason: "not observed".into(),
        },
    ]
}

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("structured-state"),
        sequence_no: CommandSequenceNo(2),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn summary_bindings_and_snapshot_import_keep_structured_values_and_export_scope() {
    for value in values() {
        let stored = SessionVariableValue::structured(value.clone());
        let mut summary = SessionSummary::new();
        summary.upsert_variable_binding(SessionVariableBinding::new(
            "paths",
            stored.clone(),
            false,
            CommandSequenceNo(1),
        ));
        let bindings = SessionBindings::from_session_summary(&summary);
        assert_eq!(bindings.get("paths").unwrap().value, &stored);
        assert_eq!(
            bindings.environment_value("paths"),
            EnvironmentValueRef::Absent
        );
        let mut snapshot = ShellStateSnapshot::new("/workspace")
            .with_variable_knowledge(ShellStateKnowledge::Complete);
        snapshot.variables.push(ShellVariableSnapshot::new(
            "paths",
            ShellValueSnapshot::structured(value),
            false,
        ));
        let imported = SessionBindings::from_summary_and_shell_state(&summary, &snapshot);
        assert_eq!(imported.get("paths").unwrap().value, &stored);
        assert_eq!(
            imported.environment_value("paths"),
            EnvironmentValueRef::Absent
        );
    }
}

#[test]
fn graph_candidates_and_live_summary_roundtrip_without_copying_reference_targets() {
    for value in values() {
        let stored = SessionVariableValue::structured(value);
        let mut state = SessionState::new();
        state
            .summary_mut()
            .upsert_variable_binding(SessionVariableBinding::new(
                "paths",
                stored.clone(),
                false,
                CommandSequenceNo(1),
            ));
        state.summary_mut().set_exact_scalar_variable(
            "target",
            "/workspace/new",
            false,
            CommandSequenceNo(2),
        );
        let object = SafetyObject {
            scope: SafetyScope::Frame {
                sequence_no: CommandSequenceNo(1),
                frame_id: "owner".into(),
            },
            kind: SafetyStateKind::Variable,
            name: "paths".into(),
        };
        state.graph_mut().add_node(caushell_graph::GraphNode::new(
            caushell_graph::NodeId::new("source"),
            caushell_graph::NodeKind::StateCandidate {
                fact: StateCandidateFact {
                    object: object.clone(),
                    value: SafetyStateValue::Variable {
                        value: stored.clone(),
                        exported: false,
                    },
                    sequence_no: CommandSequenceNo(1),
                    source_end: 4,
                },
            },
        ));
        let restored = SessionState::from_snapshot(SessionSnapshot::new(
            SessionId::new("structured-state"),
            4,
            state.summary().clone(),
            state.graph().to_snapshot(),
        ))
        .unwrap();
        let current = VariableBindingQuery::new("paths")
            .execute(QuerySession::new(restored.graph(), restored.summary()))
            .unwrap();
        assert_eq!(current.value(), &stored);
        assert!(!current.exported());
        assert_eq!(current.observed_at(), CommandSequenceNo(1));
        let result = StateCandidateQuery {
            object: &object,
            before_sequence: CommandSequenceNo(2),
            before_source_start: 0,
            limits: &AnalysisBudgetPolicy::default(),
        }
        .execute(restored.graph());
        assert_eq!(
            result.candidates[0].value,
            SafetyStateValue::Variable {
                value: stored,
                exported: false
            }
        );
        assert_eq!(result.candidates[0].witness.0, "source");
    }
}

#[test]
fn unsupported_structured_expansions_never_become_safe_scalar_paths_or_payloads() {
    for value in values() {
        for command in [
            "touch \"$paths\"",
            "curl -q -K \"$paths\" https://example.test",
            "sh -c \"$paths\"",
        ] {
            let mut state = SessionState::new();
            state
                .summary_mut()
                .upsert_variable_binding(SessionVariableBinding::new(
                    "paths",
                    SessionVariableValue::structured(value.clone()),
                    false,
                    CommandSequenceNo(1),
                ));
            let mut core = ShellQueryCore::new();
            core.insert_session_state(SessionId::new("structured-state"), state);
            let outcome = core
                .try_check_with_intent(request(command), CheckIntent::JudgeOnly)
                .unwrap();
            assert_eq!(
                outcome.response.decision,
                Decision::NeedApproval,
                "{value:?}: {command}: {:?}",
                outcome.response.reasons
            );
            let retained = core
                .session_snapshot(&SessionId::new("structured-state"), 0)
                .unwrap();
            assert_eq!(
                retained.summary.variable_binding("paths").unwrap().value,
                SessionVariableValue::structured(value.clone())
            );
        }
    }
}

#[test]
fn runtime_snapshot_reconciliation_preserves_structured_state() {
    for value in values() {
        let mut request = request("pwd");
        request.sequence_no = CommandSequenceNo(1);
        request.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
        request
            .shell_state_before
            .variables
            .push(ShellVariableSnapshot::new(
                "paths",
                ShellValueSnapshot::structured(value.clone()),
                false,
            ));
        let mut core = ShellQueryCore::new();
        assert_eq!(core.check(request).decision, Decision::Allow);
        let snapshot = core
            .session_snapshot(&SessionId::new("structured-state"), 0)
            .unwrap();
        assert_eq!(
            snapshot.summary.variable_binding("paths").unwrap().value,
            SessionVariableValue::structured(value)
        );
    }
}

//! A typed possible-state query, not an extra content/taint edge.
use caushell_graph::{GraphNode, GraphRead, NodeId, NodeKind};
use caushell_types::{
    AnalysisBudgetKind as B, AnalysisBudgetPolicy, CommandSequenceNo, ProvenanceArtifact,
    SafetyObject, SafetyStateValue, SessionVariableValue,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCandidate {
    pub value: SafetyStateValue,
    /// One witness suffices for a value; complete audit facts stay in the Graph.
    pub witness: NodeId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateCandidateResult {
    pub candidates: Vec<StateCandidate>,
    pub incomplete_budgets: BTreeSet<B>,
    pub unknown: bool,
}

impl StateCandidateResult {
    pub fn is_complete(&self) -> bool {
        self.incomplete_budgets.is_empty() && !self.unknown
    }
}

pub struct StateCandidateQuery<'a> {
    pub object: &'a SafetyObject,
    pub before_sequence: CommandSequenceNo,
    pub before_source_start: usize,
    pub limits: &'a AnalysisBudgetPolicy,
}

impl StateCandidateQuery<'_> {
    pub fn execute(&self, graph: &dyn GraphRead) -> StateCandidateResult {
        self.collect(graph, graph.state_candidate_nodes(self.object))
    }

    /// Reference path for index equivalence tests and isolated benchmarks.
    pub fn execute_scanning(&self, graph: &dyn GraphRead) -> StateCandidateResult {
        self.collect(
            graph,
            graph.nodes().filter(|node| {
                matches!(&node.kind,
            NodeKind::StateCandidate { fact } if &fact.object == self.object)
            }),
        )
    }

    fn collect<'a>(
        &self,
        graph: &dyn GraphRead,
        nodes: impl Iterator<Item = &'a GraphNode>,
    ) -> StateCandidateResult {
        let mut result = StateCandidateResult::default();
        result.incomplete_budgets.extend(graph.incomplete_budgets());
        if graph.state_history_bytes() >= self.limits.max_state_history_bytes {
            result.incomplete_budgets.insert(B::StateHistoryBytes);
        }
        let scope_bytes = match &self.object.scope {
            caushell_types::SafetyScope::Frame { frame_id, .. } => frame_id.len(),
            caushell_types::SafetyScope::Workspace { root } => root.len(),
            _ => 0,
        };
        if self.object.name.len().saturating_add(scope_bytes) > self.limits.max_state_value_bytes {
            result.incomplete_budgets.insert(B::StateValueBytes);
            return result;
        }
        if graph.state_object_count() >= self.limits.max_state_objects {
            result.incomplete_budgets.insert(B::StateObjects);
        }
        if self.limits.max_candidates_per_object == 0 {
            result.incomplete_budgets.insert(B::StateCandidates);
            return result;
        }
        for (visited, node) in nodes.enumerate() {
            if visited >= self.limits.max_history_nodes {
                result.incomplete_budgets.insert(B::Search);
                break;
            }
            let NodeKind::StateCandidate { fact } = &node.kind else {
                continue;
            };
            if &fact.object != self.object
                || !fact.precedes(self.before_sequence, self.before_source_start)
            {
                continue;
            }
            let value = self.resolve(graph, &fact.value, &mut result);
            let value = match (&self.object.kind, value) {
                (_, SafetyStateValue::Unknown) => SafetyStateValue::Unknown,
                (_, SafetyStateValue::Absent) => SafetyStateValue::Absent,
                (
                    caushell_types::SafetyStateKind::Variable,
                    value @ SafetyStateValue::Variable { .. },
                )
                | (
                    caushell_types::SafetyStateKind::Alias
                    | caushell_types::SafetyStateKind::Function,
                    value @ SafetyStateValue::Definition { .. },
                )
                | (caushell_types::SafetyStateKind::Cwd, value @ SafetyStateValue::Cwd(_))
                | (
                    caushell_types::SafetyStateKind::Positionals,
                    value @ SafetyStateValue::Positionals(_),
                )
                | (
                    caushell_types::SafetyStateKind::FileContent
                    | caushell_types::SafetyStateKind::PathBinding,
                    value @ SafetyStateValue::Reference { .. },
                ) => value,
                _ => SafetyStateValue::Unknown,
            };
            result.unknown |=
                matches!(value, SafetyStateValue::Unknown) || value.has_structured_unknown();
            if result
                .candidates
                .iter()
                .any(|candidate| candidate.value == value)
            {
                continue;
            }
            if result.candidates.len() >= self.limits.max_candidates_per_object {
                result.incomplete_budgets.insert(B::StateCandidates);
                break;
            }
            result.candidates.push(StateCandidate {
                value,
                witness: node.id.clone(),
            });
        }
        if result.candidates.len() >= self.limits.max_candidates_per_object {
            result.incomplete_budgets.insert(B::StateCandidates);
        }
        // Node IDs, not insertion order, determine which witness is retained.
        result.candidates.sort_by(|a, b| a.witness.cmp(&b.witness));
        result
    }

    fn resolve(
        &self,
        graph: &dyn GraphRead,
        value: &SafetyStateValue,
        result: &mut StateCandidateResult,
    ) -> SafetyStateValue {
        if value.retained_bytes() > self.limits.max_state_value_bytes {
            result.incomplete_budgets.insert(B::StateValueBytes);
            return SafetyStateValue::Unknown;
        }
        let SafetyStateValue::Reference { node_id } = value else {
            return value.clone();
        };
        let Some(node) = graph.get_node(&NodeId::new(node_id)) else {
            return SafetyStateValue::Unknown;
        };
        if matches!(
            self.object.kind,
            caushell_types::SafetyStateKind::FileContent
                | caushell_types::SafetyStateKind::PathBinding
        ) {
            // Resource provenance is not an inline variable or executable body.
            return value.clone();
        }
        let resolved = match &node.kind {
            NodeKind::FunctionBinding { body_repr, .. } => {
                if body_repr.len() > self.limits.max_state_value_bytes {
                    result.incomplete_budgets.insert(B::StateValueBytes);
                    return SafetyStateValue::Unknown;
                }
                SafetyStateValue::Definition {
                    body: body_repr.clone(),
                    uncertainty: None,
                }
            }
            NodeKind::AliasBinding { body, .. } => {
                if body.len() > self.limits.max_state_value_bytes {
                    result.incomplete_budgets.insert(B::StateValueBytes);
                    return SafetyStateValue::Unknown;
                }
                SafetyStateValue::Definition {
                    body: body.clone(),
                    uncertainty: None,
                }
            }
            NodeKind::DirectoryState { path, .. } => SafetyStateValue::Cwd(path.clone()),
            NodeKind::ProvenanceArtifact {
                artifact:
                    ProvenanceArtifact::VariableValue { state, .. }
                    | ProvenanceArtifact::InheritedEnvValue { state, .. },
            } => {
                let exported = match &node.kind {
                    NodeKind::ProvenanceArtifact {
                        artifact: ProvenanceArtifact::VariableValue { exported, .. },
                    } => *exported,
                    _ => true,
                };
                let value = SessionVariableValue::from(state);
                SafetyStateValue::Variable { value, exported }
            }
            NodeKind::ProvenanceArtifact { .. } => value.clone(),
            _ => SafetyStateValue::Unknown,
        };
        if resolved.retained_bytes() > self.limits.max_state_value_bytes {
            result.incomplete_budgets.insert(B::StateValueBytes);
            SafetyStateValue::Unknown
        } else {
            resolved
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_graph::{GraphNode, SessionGraph};
    use caushell_types::{SafetyScope, SafetyStateKind as K, StateCandidateFact};

    #[test]
    fn structured_references_keep_frame_source_and_unknown_members_after_restore() {
        use caushell_types::{
            ProvenanceVariableValueState, ShellScalarValue as S, StructuredShellValue as V,
        };
        let mut graph = SessionGraph::new();
        let mut key = object();
        key.scope = SafetyScope::Frame {
            sequence_no: CommandSequenceNo(1),
            frame_id: "function:first".into(),
        };
        let value = SessionVariableValue::structured(V::IndexedArray {
            elements: [
                (0, S::exact("/outside")),
                (
                    8,
                    S::Unknown {
                        reason: "not captured".into(),
                    },
                ),
            ]
            .into(),
            complete: false,
        });
        graph.add_node(GraphNode::new(
            NodeId::new("array-source"),
            NodeKind::ProvenanceArtifact {
                artifact: ProvenanceArtifact::VariableValue {
                    name: "DEST".into(),
                    state: ProvenanceVariableValueState::from(&value),
                    exported: false,
                    version: 1,
                },
            },
        ));
        add(
            &mut graph,
            "array-witness",
            key.clone(),
            SafetyStateValue::Reference {
                node_id: "array-source".into(),
            },
            1,
            10,
        );
        let graph = SessionGraph::from_snapshot(graph.to_snapshot()).unwrap();
        let limits = AnalysisBudgetPolicy::default();
        let query = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(1),
            before_source_start: 11,
            limits: &limits,
        };
        let result = query.execute(&graph);
        assert!(result.unknown && !result.is_complete());
        assert_eq!(
            result.candidates,
            vec![StateCandidate {
                value: SafetyStateValue::Variable {
                    value,
                    exported: false
                },
                witness: NodeId::new("array-witness")
            }]
        );
        assert_eq!(result, query.execute_scanning(&graph));
        assert!(
            StateCandidateQuery {
                before_source_start: 9,
                ..query
            }
            .execute(&graph)
            .candidates
            .is_empty()
        );
        key.scope = SafetyScope::Frame {
            sequence_no: CommandSequenceNo(1),
            frame_id: "function:second".into(),
        };
        assert!(
            StateCandidateQuery {
                object: &key,
                before_sequence: CommandSequenceNo(2),
                before_source_start: 0,
                limits: &limits
            }
            .execute(&graph)
            .candidates
            .is_empty()
        );
    }

    #[test]
    fn complete_empty_partial_and_reference_values_are_distinct_candidates() {
        use caushell_types::{ShellReferenceTarget, StructuredShellValue as V};
        let mut graph = SessionGraph::new();
        for (index, value) in [
            V::IndexedArray {
                elements: Default::default(),
                complete: true,
            },
            V::IndexedArray {
                elements: Default::default(),
                complete: false,
            },
            V::NameReference {
                target: ShellReferenceTarget::Variable {
                    name: "OTHER".into(),
                },
            },
        ]
        .into_iter()
        .enumerate()
        {
            add(
                &mut graph,
                &format!("state-{index}"),
                object(),
                SafetyStateValue::Variable {
                    value: SessionVariableValue::structured(value),
                    exported: false,
                },
                1,
                index,
            );
        }
        let key = object();
        let limits = AnalysisBudgetPolicy::default();
        let result = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(2),
            before_source_start: 0,
            limits: &limits,
        }
        .execute(&graph);
        assert_eq!(result.candidates.len(), 3);
        assert!(result.unknown);
        assert!(
            matches!(&result.candidates[2].value, SafetyStateValue::Variable { value: SessionVariableValue::Structured(V::NameReference { target: ShellReferenceTarget::Variable { name } }), .. } if name == "OTHER")
        );
        let limits = AnalysisBudgetPolicy {
            max_state_value_bytes: 16,
            ..limits
        };
        let result = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(2),
            before_source_start: 0,
            limits: &limits,
        }
        .execute(&graph);
        assert!(!result.is_complete());
        assert!(result.incomplete_budgets.contains(&B::StateValueBytes));
    }

    fn object() -> SafetyObject {
        SafetyObject {
            scope: SafetyScope::Shell,
            kind: K::Variable,
            name: "DEST".into(),
        }
    }
    fn value(text: &str) -> SafetyStateValue {
        SafetyStateValue::Variable {
            value: SessionVariableValue::exact_scalar(text),
            exported: false,
        }
    }
    fn add(
        graph: &mut SessionGraph,
        id: &str,
        object: SafetyObject,
        value: SafetyStateValue,
        sequence: u64,
        end: usize,
    ) {
        graph.add_node(GraphNode::new(
            NodeId::new(id),
            NodeKind::StateCandidate {
                fact: StateCandidateFact {
                    object,
                    value,
                    sequence_no: CommandSequenceNo(sequence),
                    source_end: end,
                },
            },
        ));
    }

    #[test]
    fn total_candidate_payload_limit_is_checked_even_for_an_unrecorded_object() {
        let mut graph = SessionGraph::new();
        add(&mut graph, "old", object(), value("/outside"), 1, 0);
        let mut limits = AnalysisBudgetPolicy::default();
        limits.max_state_history_bytes = graph.state_history_bytes();
        let mut key = object();
        key.name = "unrecorded".into();
        let query = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(2),
            before_source_start: 0,
            limits: &limits,
        };
        for graph in [
            &graph,
            &SessionGraph::from_snapshot(graph.to_snapshot()).unwrap(),
        ] {
            let result = query.execute(graph);
            assert!(result.candidates.is_empty());
            assert!(result.incomplete_budgets.contains(&B::StateHistoryBytes));
            assert!(!result.is_complete());
        }
    }

    #[test]
    fn indexed_and_scanned_queries_agree_before_and_after_snapshot_rebuild() {
        let mut graph = SessionGraph::new();
        add(&mut graph, "z", object(), value("/outside"), 1, 10);
        add(&mut graph, "a", object(), value("./safe"), 2, 20);
        add(&mut graph, "b", object(), value("./safe"), 2, 30);
        let key = object();
        let limits = AnalysisBudgetPolicy::default();
        let query = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(3),
            before_source_start: 0,
            limits: &limits,
        };
        let expected = query.execute_scanning(&graph);
        assert_eq!(query.execute(&graph), expected);
        assert_eq!(expected.candidates.len(), 2);
        assert!(expected.is_complete());
        let restored = SessionGraph::from_snapshot(graph.to_snapshot()).unwrap();
        assert_eq!(query.execute(&restored), expected);
        let bytes = graph.nodes().fold(0usize, |bytes, node| {
            bytes
                + match &node.kind {
                    NodeKind::StateCandidate { fact } => fact.retained_bytes(),
                    _ => 0,
                }
        });
        assert_eq!(graph.state_history_bytes(), bytes);
        assert_eq!(restored.state_history_bytes(), bytes);
        // A derived index replacement cannot retain the replaced object's entry.
        let mut other = object();
        other.name = "OTHER".into();
        add(&mut graph, "z", other, value("elsewhere"), 4, 0);
        let new_bytes = graph.nodes().fold(0usize, |bytes, node| {
            bytes
                + match &node.kind {
                    NodeKind::StateCandidate { fact } => fact.retained_bytes(),
                    _ => 0,
                }
        });
        assert_eq!(graph.state_history_bytes(), new_bytes);
        assert_eq!(query.execute(&graph), query.execute_scanning(&graph));
        assert_eq!(query.execute(&graph).candidates.len(), 1);
    }

    #[test]
    fn scope_kind_and_statement_order_do_not_leak_candidates() {
        let mut graph = SessionGraph::new();
        add(&mut graph, "old", object(), value("/outside"), 1, 0);
        add(&mut graph, "now", object(), value("./safe"), 2, 20);
        let mut frame = object();
        frame.scope = SafetyScope::Frame {
            sequence_no: CommandSequenceNo(2),
            frame_id: "child".into(),
        };
        add(&mut graph, "child", frame, value("/child"), 2, 0);
        let mut function = object();
        function.kind = K::Function;
        add(
            &mut graph,
            "function",
            function,
            SafetyStateValue::Definition {
                body: "printf hello".into(),
                uncertainty: None,
            },
            1,
            0,
        );
        let key = object();
        let limits = AnalysisBudgetPolicy::default();
        let mut query = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(2),
            before_source_start: 19,
            limits: &limits,
        };
        assert_eq!(query.execute(&graph).candidates.len(), 1);
        query.before_source_start = 20;
        assert_eq!(query.execute(&graph).candidates.len(), 2);
    }

    #[test]
    fn padding_never_evicts_old_values_into_an_apparently_complete_result() {
        let mut graph = SessionGraph::new();
        add(&mut graph, "000", object(), value("/outside"), 1, 0);
        for n in 1..12 {
            add(
                &mut graph,
                &format!("{n:03}"),
                object(),
                value(&format!("./safe{n}")),
                2,
                n,
            );
        }
        let key = object();
        let mut limits = AnalysisBudgetPolicy::default();
        limits.max_candidates_per_object = 4;
        let query = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(3),
            before_source_start: 0,
            limits: &limits,
        };
        let result = query.execute(&graph);
        assert!(!result.is_complete());
        assert!(result.incomplete_budgets.contains(&B::StateCandidates));
        assert!(
            result
                .candidates
                .iter()
                .any(|candidate| candidate.value == value("/outside"))
        );
        assert_eq!(result, query.execute_scanning(&graph));
    }

    #[test]
    fn oversize_missing_and_wrong_typed_references_never_look_safe() {
        for fact_value in [
            value(&"x".repeat(100)),
            SafetyStateValue::Reference {
                node_id: "missing".into(),
            },
            SafetyStateValue::Definition {
                body: "printf hello".into(),
                uncertainty: None,
            },
        ] {
            let mut graph = SessionGraph::new();
            add(&mut graph, "fact", object(), fact_value, 1, 0);
            let key = object();
            let mut limits = AnalysisBudgetPolicy::default();
            limits.max_state_value_bytes = 64;
            let query = StateCandidateQuery {
                object: &key,
                before_sequence: CommandSequenceNo(2),
                before_source_start: 0,
                limits: &limits,
            };
            assert!(!query.execute(&graph).is_complete());
        }
    }

    #[test]
    fn total_object_capacity_covers_unrecorded_names_and_survives_restore() {
        let mut graph = SessionGraph::new();
        for n in 0..4 {
            let mut key = object();
            key.name = format!("V{n}");
            add(&mut graph, &format!("fact{n}"), key, value("safe"), 1, 0);
        }
        let key = object();
        let mut limits = AnalysisBudgetPolicy::default();
        limits.max_state_objects = 4;
        let query = StateCandidateQuery {
            object: &key,
            before_sequence: CommandSequenceNo(2),
            before_source_start: 0,
            limits: &limits,
        };
        let result = query.execute(&graph);
        assert!(result.candidates.is_empty());
        assert!(result.incomplete_budgets.contains(&B::StateObjects));
        let restored = SessionGraph::from_snapshot(graph.to_snapshot()).unwrap();
        assert_eq!(query.execute(&restored), result);
    }
}

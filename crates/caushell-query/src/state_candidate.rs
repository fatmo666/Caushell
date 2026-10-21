//! A typed possible-state query, not an extra content/taint edge.
use caushell_graph::{GraphNode, GraphRead, NodeId, NodeKind};
use caushell_types::{
    AnalysisBudgetKind as B, AnalysisBudgetPolicy, CommandSequenceNo, ProvenanceArtifact,
    ProvenanceVariableValueState, SafetyObject, SafetyStateValue, SessionVariableValue,
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
            result.unknown |= matches!(value, SafetyStateValue::Unknown);
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
                let value = match state {
                    ProvenanceVariableValueState::ExactScalar { value } => {
                        SessionVariableValue::exact_scalar(value)
                    }
                    ProvenanceVariableValueState::RuntimeProduced { value, value_kind } => {
                        SessionVariableValue::runtime_produced(value, *value_kind)
                    }
                    ProvenanceVariableValueState::OpaqueDynamic { repr } => {
                        SessionVariableValue::opaque_dynamic(repr)
                    }
                    ProvenanceVariableValueState::RuntimeInput { source, capture } => {
                        SessionVariableValue::runtime_input(*source, capture.clone())
                    }
                };
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
        // A derived index replacement cannot retain the replaced object's entry.
        let mut other = object();
        other.name = "OTHER".into();
        add(&mut graph, "z", other, value("elsewhere"), 4, 0);
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

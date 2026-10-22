use caushell_graph::NodeKind;
use caushell_types::{CommandSequenceNo, PathTargetFact, SemanticResolution};

use crate::{PathScopeProof, PathScopeQuery, QuerySession};

pub struct PathTargetQuery {
    sequence: CommandSequenceNo,
}

impl PathTargetQuery {
    pub fn new(sequence: CommandSequenceNo) -> Self {
        Self { sequence }
    }

    pub fn execute<'a>(&self, session: QuerySession<'a>) -> Vec<&'a PathTargetFact> {
        session
            .graph()
            .nodes()
            .filter_map(|node| match &node.kind {
                NodeKind::PathTargetFact { fact } if fact.sequence_no == self.sequence => {
                    Some(fact)
                }
                _ => None,
            })
            .collect()
    }

    pub fn prove_scope(fact: &PathTargetFact, covered: impl FnMut(&str) -> bool) -> PathScopeProof {
        match &fact.resolution {
            SemanticResolution::Resolved { value } => PathScopeQuery::new(value).prove_all(covered),
            SemanticResolution::NotApplicable { .. } => PathScopeProof::Covered,
            SemanticResolution::Unresolved { .. } => PathScopeProof::Unproven,
        }
    }
}

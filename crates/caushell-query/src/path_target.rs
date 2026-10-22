use caushell_graph::NodeKind;
use caushell_types::{CommandSequenceNo, PathTargetFact, SemanticResolution};

use crate::{PathScopeProof, PathScopeQuery, QuerySession, path_is_within_root};

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

    pub fn prove_within(target: &PathTargetFact, root: &PathTargetFact) -> PathScopeProof {
        match (&target.resolution, &root.resolution) {
            (
                SemanticResolution::Resolved { value },
                SemanticResolution::Resolved { value: root },
            ) => {
                let Some(root) = root
                    .concrete_path()
                    .filter(|path| path.starts_with('/') && !path.contains('\0'))
                else {
                    return PathScopeProof::Unproven;
                };
                PathScopeQuery::new(value).prove_all(|path| path_is_within_root(path, root))
            }
            _ => PathScopeProof::Unproven,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_types::{
        PathResolution, PathTargetAccess, PathTargetOperation, SemanticGap, SemanticGapKind,
    };

    fn fact(resolution: SemanticResolution<PathResolution>) -> PathTargetFact {
        PathTargetFact {
            sequence_no: CommandSequenceNo::new(1),
            source_node_id: "source".into(),
            effect_key: "context".into(),
            slot_name: "cwd".into(),
            operation: PathTargetOperation::WorkingDirectory,
            access: PathTargetAccess::Follow,
            lexical: PathResolution::Concrete {
                path: "/lexical".into(),
            },
            spelling: Some("/lexical".into()),
            resolution,
            observations: Vec::new(),
            metadata_mutation: None,
            implicit_incidental_cache: false,
        }
    }

    fn resolved(path: &str) -> PathTargetFact {
        fact(SemanticResolution::Resolved {
            value: PathResolution::Concrete { path: path.into() },
        })
    }

    #[test]
    fn physical_target_relation_does_not_use_lexical_spelling() {
        let root = resolved("/work");
        assert_eq!(
            PathTargetQuery::prove_within(&resolved("/work/child"), &root),
            PathScopeProof::Covered
        );
        assert_eq!(
            PathTargetQuery::prove_within(&resolved("/work-other/child"), &root),
            PathScopeProof::Outside
        );
        assert_eq!(
            PathTargetQuery::prove_within(&resolved("/outside"), &root),
            PathScopeProof::Outside
        );
    }

    #[test]
    fn incomplete_or_non_path_context_never_proves_membership() {
        for resolution in [
            SemanticResolution::Unresolved {
                gap: SemanticGap {
                    kind: SemanticGapKind::UnknownTarget,
                    detail: "unknown".into(),
                },
            },
            SemanticResolution::NotApplicable {
                reason: "channel".into(),
            },
        ] {
            let uncertain = fact(resolution);
            assert_eq!(
                PathTargetQuery::prove_within(&uncertain, &resolved("/work")),
                PathScopeProof::Unproven
            );
            assert_eq!(
                PathTargetQuery::prove_within(&resolved("/work"), &uncertain),
                PathScopeProof::Unproven
            );
        }
        for root in ["relative", "/work\0suffix"] {
            assert_eq!(
                PathTargetQuery::prove_within(&resolved("/work"), &resolved(root)),
                PathScopeProof::Unproven
            );
        }
    }

    #[test]
    fn all_resolved_targets_must_be_inside_a_single_proven_root() {
        for (paths, expected) in [
            (vec!["/work/a", "/work/b"], PathScopeProof::Covered),
            (vec!["/work/a", "/outside/b"], PathScopeProof::Outside),
        ] {
            let bounded = fact(SemanticResolution::Resolved {
                value: PathResolution::BoundedPathSet {
                    roots: paths.into_iter().map(str::to_owned).collect(),
                    may_escape: false,
                },
            });
            assert_eq!(
                PathTargetQuery::prove_within(&bounded, &resolved("/work")),
                expected
            );
            assert_eq!(
                PathTargetQuery::prove_within(&resolved("/work"), &bounded),
                PathScopeProof::Unproven
            );
        }
    }
}

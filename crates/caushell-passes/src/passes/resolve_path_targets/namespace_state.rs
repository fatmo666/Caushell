//! Scope invariants for abstract namespace states. No command-name checks,
//! authorization policy, observed output creation, or execution-order guesses.
use caushell_types::{
    FilesystemEntry, FilesystemObservation, PathNamespaceEffect, PathNamespaceProof,
    PathResolution, SemanticResolution,
};

use super::Input;
use std::collections::{BTreeSet, VecDeque};

pub(super) type Baseline = (
    SemanticResolution<PathResolution>,
    Vec<FilesystemObservation>,
);

pub(super) fn overlaps(input: &Input, baseline: &Baseline, root: Option<&str>) -> bool {
    let Some(root) = root else { return true };
    // Families include descendants absent from the entry snapshot. Both
    // mutation of an ancestor and creation of a future child can affect them.
    let family_overlap = matches!(&baseline.0,
        SemanticResolution::Resolved { value: PathResolution::BoundedPathSet { roots, .. } }
        if roots.iter().any(|anchor|
            caushell_query::path_is_within_root(root, anchor)
            || caushell_query::path_is_within_root(anchor, root)));
    family_overlap
        || input
            .fact
            .spelling
            .as_deref()
            .is_some_and(|path| super::spelling_visits(path, root))
        || baseline
            .1
            .iter()
            .any(|o| caushell_query::path_is_within_root(&o.path, root))
        || input
            .fact
            .lexical
            .concrete_path()
            .is_some_and(|path| caushell_query::path_is_within_root(path, root))
}

/// Close producer preconditions under other namespace mutations. If a third
/// operation invalidates a producer's spelling, every proof depending on that
/// producer must also be rejected, even when the consumer uses another spelling.
pub(super) fn stable_producers(
    inputs: &[Input],
    baselines: &[Baseline],
    writes: &[(usize, Option<String>)],
    comparisons: &mut usize,
    closed_tree: bool,
) -> BTreeSet<usize> {
    let mut candidates: BTreeSet<_> = writes
        .iter()
        .filter_map(|(i, _)| {
            if !closed_tree
                && inputs[*i].namespace_effect != Some(PathNamespaceEffect::RegularFileWrite)
            {
                return None;
            }
            scope_preservation(&inputs[*i], &baselines[*i], &baselines[*i]).map(|_| *i)
        })
        .collect();
    let mut dependents = vec![Vec::new(); inputs.len()];
    let mut invalid = VecDeque::new();
    for &producer in &candidates {
        for (other, root) in writes {
            *comparisons += 1;
            if *comparisons > 65536 {
                return BTreeSet::new();
            }
            if *other == producer
                || !overlaps(&inputs[producer], &baselines[producer], root.as_deref())
            {
                continue;
            }
            if candidates.contains(other)
                && scope_preservation(&inputs[*other], &baselines[*other], &baselines[producer])
                    .is_some()
            {
                dependents[*other].push(producer);
            } else {
                invalid.push_back(producer);
            }
        }
    }
    while let Some(producer) = invalid.pop_front() {
        if candidates.remove(&producer) {
            invalid.extend(dependents[producer].iter().copied());
        }
    }
    candidates
}

/// A declared regular-file write can leave the old leaf, fail, or create a
/// new regular leaf. With observed stable directory ancestors and no links,
/// every outcome has the same path resolution. This holds for branches,
/// loops, and interleavings; it does not claim that a build succeeded.
pub(super) fn scope_preservation(
    writer: &Input,
    writer_state: &Baseline,
    consumer_state: &Baseline,
) -> Option<PathNamespaceProof> {
    if writer.namespace_effect == Some(PathNamespaceEffect::DirectoryTreeWrite) {
        let SemanticResolution::Resolved {
            value:
                PathResolution::BoundedPathSet {
                    roots,
                    may_escape: false,
                },
        } = &writer_state.0
        else {
            return None;
        };
        let consumer_roots = match &consumer_state.0 {
            SemanticResolution::Resolved {
                value: PathResolution::Concrete { path },
            } => vec![path],
            SemanticResolution::Resolved {
                value:
                    PathResolution::BoundedPathSet {
                        roots,
                        may_escape: false,
                    },
            } => roots.iter().collect(),
            _ => return None,
        };
        if roots.is_empty()
            || consumer_roots.is_empty()
            || writer_state.1.iter().any(|o| {
                !matches!(
                    o.entry,
                    FilesystemEntry::Directory | FilesystemEntry::File | FilesystemEntry::Missing
                )
            })
        {
            return None;
        }
        if consumer_roots.iter().all(|path| {
            roots
                .iter()
                .any(|root| caushell_query::path_is_within_root(path, root))
        }) {
            return Some(PathNamespaceProof {
                producer_node_id: writer.fact.source_node_id.clone(),
                producer_effect_key: writer.fact.effect_key.clone(),
                path: roots[0].clone(),
                effect: PathNamespaceEffect::DirectoryTreeWrite,
                additional_paths: roots.iter().skip(1).cloned().collect(),
            });
        }
        return None;
    }
    if writer.namespace_effect != Some(PathNamespaceEffect::RegularFileWrite) {
        return None;
    }
    let concrete = |resolution: &SemanticResolution<PathResolution>| match resolution {
        SemanticResolution::Resolved {
            value: PathResolution::Concrete { path },
        } => Some(path.clone()),
        _ => None,
    };
    let path = concrete(&writer_state.0)?;
    if concrete(&consumer_state.0)? != path {
        return None;
    }
    if !ordinary_leaf(&path, &writer_state.1) || !ordinary_leaf(&path, &consumer_state.1) {
        return None;
    }
    Some(PathNamespaceProof {
        producer_node_id: writer.fact.source_node_id.clone(),
        producer_effect_key: writer.fact.effect_key.clone(),
        path,
        effect: PathNamespaceEffect::RegularFileWrite,
        additional_paths: Vec::new(),
    })
}

fn ordinary_leaf(path: &str, observations: &[FilesystemObservation]) -> bool {
    observations.iter().any(|o| {
        o.path == path && matches!(o.entry, FilesystemEntry::File | FilesystemEntry::Missing)
    }) && observations.iter().all(|o| {
        if o.path == path {
            matches!(o.entry, FilesystemEntry::File | FilesystemEntry::Missing)
        } else {
            matches!(o.entry, FilesystemEntry::Directory)
        }
    })
}

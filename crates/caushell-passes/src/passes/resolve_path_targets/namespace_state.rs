//! Scope invariants for abstract namespace states. No command-name checks,
//! authorization policy, observed output creation, or execution-order guesses.
use caushell_types::{
    FilesystemEntry, FilesystemObservation, PathNamespaceEffect, PathNamespaceProof, PathResolution,
    PathTargetOperation, SemanticResolution,
};

use super::Input;
use std::collections::{BTreeSet, VecDeque};

pub(super) type Baseline = (
    SemanticResolution<PathResolution>,
    Vec<FilesystemObservation>,
);

pub(super) fn overlaps(
    input: &Input,
    baseline: &Baseline,
    writer: &Baseline,
    root: Option<&str>,
) -> bool {
    let Some(root) = root else { return true };
    if let SemanticResolution::Resolved {
        value: PathResolution::FileNamePrefix { directory, prefix },
    } = &baseline.0
    {
        // The scan observes unrelated siblings to validate the snapshot.
        // Only the parent, its ancestors, and matching subtrees affect the target.
        return prefix_depends_on(directory, prefix, root)
            || matches!(&input.fact.lexical,
                PathResolution::FileNamePrefix { directory, .. }
                if prefix_depends_on(directory, prefix, root))
            || baseline.1.iter().any(|observation| {
                matches!(observation.entry, FilesystemEntry::Symlink { .. })
                    && caushell_query::path_is_within_root(&observation.path, root)
            });
    }
    if let SemanticResolution::Resolved {
        value: PathResolution::FileNamePrefix { directory, prefix },
    } = &writer.0
        && let SemanticResolution::Resolved { value } = &baseline.0
        && let Some(path) = value.concrete_path()
        && let Some(lexical) = input.fact.lexical.concrete_path()
        && input.fact.spelling.as_ref().is_some_and(|spelling| {
            spelling.starts_with('/') && !spelling.split('/').any(|part| part == "..")
        })
    {
        return [path, lexical]
            .into_iter()
            .chain(baseline.1.iter().map(|observation| observation.path.as_str()))
            .any(|candidate| prefix_covers(directory, prefix, candidate));
    }
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

fn prefix_depends_on(directory: &str, prefix: &str, writer: &str) -> bool {
    caushell_query::path_is_within_root(directory, writer)
        || prefix_covers(directory, prefix, writer)
}

fn prefix_covers(directory: &str, prefix: &str, path: &str) -> bool {
    path.strip_prefix(directory.trim_end_matches('/'))
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|first| {
            !first.is_empty() && (!first.is_ascii() || !prefix.is_ascii()
                || first.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix)))
        })
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
    completes_before_writer: impl Fn(&Input, &Input) -> bool,
) -> BTreeSet<usize> {
    let mut candidates: BTreeSet<_> = writes
        .iter()
        .filter_map(|(i, _)| {
            if !closed_tree
                && (inputs[*i].namespace_effect != Some(PathNamespaceEffect::RegularFileWrite)
                    || !matches!(&baselines[*i].0, SemanticResolution::Resolved { value }
                        if value.concrete_path().is_some()))
            {
                return None;
            }
            scope_preservation(&inputs[*i], &baselines[*i], &inputs[*i], &baselines[*i]).map(|_| *i)
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
                || completes_before_writer(&inputs[producer], &inputs[*other])
                || !overlaps(&inputs[producer], &baselines[producer], &baselines[*other], root.as_deref())
            {
                continue;
            }
            if candidates.contains(other)
                && preserves_relocation_leaves(&inputs[producer], &inputs[*other], root.as_deref())
                && scope_preservation(&inputs[*other], &baselines[*other], &inputs[producer], &baselines[producer])
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

fn preserves_relocation_leaves(producer: &Input, sibling: &Input, root: Option<&str>) -> bool {
    let Some(scope) = producer.relocation_scope.as_ref() else {
        return true;
    };
    let leaves = [&scope.ordinary_source, &scope.ordinary_destination];
    if !leaves.into_iter().flatten().any(|leaf| {
        root.is_none_or(|root| caushell_query::path_is_within_root(leaf, root)
            || caushell_query::path_is_within_root(root, leaf))
    }) {
        return true;
    }
    // A directory creation or a relocation of unknown entry types could turn
    // an observed missing source into a directory, invalidating the leaf fact.
    match sibling.namespace_effect {
        Some(PathNamespaceEffect::RegularFileWrite | PathNamespaceEffect::EntryRemoval) => true,
        Some(PathNamespaceEffect::EntryRelocation) => sibling.relocation_scope.as_ref()
            .is_some_and(|scope| scope.ordinary_source.is_some()),
        _ => false,
    }
}

/// Close a typed namespace transformer over observed entry states. A removed
/// ordinary leaf, a regular-file write, or a directory creation may fail; no
/// proof asserts that it ran. Stable ancestors and the dependency fixed point
/// preserve pathname meaning across branches, loops, and interleavings.
pub(super) fn scope_preservation(
    writer: &Input,
    writer_state: &Baseline,
    consumer: &Input,
    consumer_state: &Baseline,
) -> Option<PathNamespaceProof> {
    if writer.namespace_effect == Some(PathNamespaceEffect::EntryRelocation)
        && let Some(scope) = &writer.relocation_scope
    {
        // Matching transfer pairs share the two stationary anchors.
        // A different invocation may enter a descendant that has moved.
        if scope.disjoint_destination.is_some() && consumer.relocation_scope.as_ref() != Some(scope) {
            return None;
        }
        let path = match &consumer_state.0 {
            SemanticResolution::Resolved {
                value: PathResolution::BoundedPathSet { roots, may_escape: false },
            } if !roots.is_empty()
                && roots.iter().all(|p| caushell_query::path_is_within_root(p, &scope.root)
                    || scope.disjoint_destination.as_ref()
                        .is_some_and(|dest| caushell_query::path_is_within_root(p, dest))) =>
            {
                &scope.root
            }
            SemanticResolution::Resolved {
                value: PathResolution::Concrete { path },
            } if scope.ordinary_source.as_ref() == Some(path)
                || scope.ordinary_destination.as_ref() == Some(path) => path,
            _ => return None,
        };
        // An ordinary source stays a regular leaf or becomes absent. Neither
        // this leaf invariant nor family containment preserves an inode.
        return Some(PathNamespaceProof {
            producer_node_id: writer.fact.source_node_id.clone(),
            producer_effect_key: writer.fact.effect_key.clone(),
            path: path.clone(),
            effect: PathNamespaceEffect::EntryRelocation,
            additional_paths: scope.disjoint_destination.iter().cloned().collect(),
            same_iteration_success: false,
        });
    }
    if writer.namespace_effect == Some(PathNamespaceEffect::EntryRemoval)
        || (writer.namespace_effect == Some(PathNamespaceEffect::EntryRelocation)
            && writer.fact.operation == PathTargetOperation::MoveSource)
    {
        let SemanticResolution::Resolved {
            value: PathResolution::Concrete { path },
        } = &writer_state.0
        else {
            return None;
        };
        // Preserve only the namespace meaning of this ordinary leaf. Moving
        // directories/links needs a separate relational transformer; observed
        // absence is not a promise that an opaque sibling cannot create one.
        if !ordinary_leaf(path, &writer_state.1)
            || !matches!(&consumer_state.0,
            SemanticResolution::Resolved {value:PathResolution::Concrete {path:consumer}} if consumer==path)
            || !ordinary_leaf(path, &consumer_state.1)
        {
            return None;
        }
        return Some(PathNamespaceProof {
            producer_node_id: writer.fact.source_node_id.clone(),
            producer_effect_key: writer.fact.effect_key.clone(),
            path: path.clone(),
            effect: PathNamespaceEffect::EntryRemoval,
            additional_paths: Vec::new(),
            same_iteration_success: false,
        });
    }
    if writer.namespace_effect == Some(PathNamespaceEffect::DirectoryCreate)
        && matches!(
            writer_state.0,
            SemanticResolution::Resolved {
                value: PathResolution::Concrete { .. }
            }
        )
    {
        let SemanticResolution::Resolved {
            value: PathResolution::Concrete { path },
        } = &writer_state.0
        else {
            return None;
        };
        if !matches!(&consumer_state.0, SemanticResolution::Resolved { value }
            if value.concrete_path().is_some()
                || matches!(value, PathResolution::BoundedPathSet { roots, may_escape: false } if !roots.is_empty()))
            || writer_state.1.is_empty()
            || writer_state.1.iter().any(|o| {
                !matches!(
                    o.entry,
                    FilesystemEntry::Directory | FilesystemEntry::Missing
                )
            })
        {
            return None;
        }
        // Missing -> directory, unchanged, or failure all preserve path
        // resolution. This invariant does not require execution-order guesses
        // or turn an observed Missing entry into an observed Directory.
        return Some(PathNamespaceProof {
            producer_node_id: writer.fact.source_node_id.clone(),
            producer_effect_key: writer.fact.effect_key.clone(),
            path: path.clone(),
            effect: PathNamespaceEffect::DirectoryCreate,
            additional_paths: Vec::new(),
            same_iteration_success: false,
        });
    }
    // In a closed, observed link-free tree, regular-file writes at bounded
    // execution directories cannot introduce symlinks or relocate ancestors.
    // Preserve that invariant across alternative cwd projections, retaining
    // the actual RegularFileWrite effect in the proof.
    if writer.namespace_effect == Some(PathNamespaceEffect::DirectoryTreeWrite)
        || (writer.namespace_effect == Some(PathNamespaceEffect::DirectoryCreate)
            && matches!(
                writer_state.0,
                SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet {
                        may_escape: false,
                        ..
                    }
                }
            ))
        || (writer.namespace_effect == Some(PathNamespaceEffect::RegularFileWrite)
            && matches!(
                writer_state.0,
                SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet {
                        may_escape: false,
                        ..
                    }
                }
            ))
    {
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
            || writer_state.1.is_empty()
            || writer_state.1.iter().any(|o| {
                !matches!(
                    o.entry,
                    FilesystemEntry::Directory | FilesystemEntry::File | FilesystemEntry::Missing
                )
            })
        {
            return None;
        }
        // Both relocation operands use the observations from their shared
        // closed tree, so a sibling directory creation can overlap those
        // observations without containing the consumer's own target. It can
        // only add ordinary directories. Preserve the family invariant while
        // keeping the stricter conditions for an exact ordinary source.
        let preserves_closed_relocation = writer.namespace_effect
            == Some(PathNamespaceEffect::DirectoryCreate)
            && consumer.relocation_scope.as_ref().is_some_and(|scope| {
                scope.ordinary_source.is_none()
                    && scope.disjoint_destination.is_none()
                    && roots.iter().all(|root| {
                        caushell_query::path_is_within_root(root, &scope.root)
                    })
            });
        if preserves_closed_relocation || consumer_roots.iter().all(|path| {
            roots
                .iter()
                .any(|root| caushell_query::path_is_within_root(path, root))
        }) {
            return Some(PathNamespaceProof {
                producer_node_id: writer.fact.source_node_id.clone(),
                producer_effect_key: writer.fact.effect_key.clone(),
                path: roots[0].clone(),
                effect: writer.namespace_effect.expect("typed output effect"),
                additional_paths: roots.iter().skip(1).cloned().collect(),
                same_iteration_success: false,
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
    if matches!(&consumer_state.0, SemanticResolution::Resolved {
        value: PathResolution::BoundedPathSet { roots, may_escape: false }
    } if !roots.is_empty() && roots.iter().any(|root| caushell_query::path_is_within_root(&path, root)))
        && ordinary_leaf(&path, &writer_state.1)
        && !consumer_state.1.is_empty()
        && consumer_state.1.iter().all(|o| {
            matches!(
                o.entry,
                FilesystemEntry::Directory | FilesystemEntry::File | FilesystemEntry::Missing
            )
        })
    {
        // A single regular leaf can change within a link-free family without
        // invalidating that family's namespace. It does not rewrite its root.
        return Some(PathNamespaceProof {
            producer_node_id: writer.fact.source_node_id.clone(),
            producer_effect_key: writer.fact.effect_key.clone(),
            path,
            effect: PathNamespaceEffect::RegularFileWrite,
            additional_paths: Vec::new(),
            same_iteration_success: false,
        });
    }
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
        same_iteration_success: false,
    })
}

pub(super) fn ordinary_leaf(path: &str, observations: &[FilesystemObservation]) -> bool {
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

#[cfg(test)]
mod tests {
    use super::prefix_covers;

    #[test]
    fn filename_family_accounts_for_case_and_compares_only_the_first_component() {
        assert!(prefix_covers("/work", "file.txt.", "/work/FILE.TXT.backup/content"));
        assert!(!prefix_covers("/work", "file.txt.", "/work/file.txt"));
        assert!(!prefix_covers("/work", "file.txt.", "/work/other/file.txt.backup"));
    }
}

//! Relational namespace closure for paired transfers between observed entries.
use super::{
    Input, directory_tree,
    namespace_state::{Baseline, ordinary_leaf},
};
use crate::path::namespace::{NamespaceResolver, unresolved};
use caushell_runner::{DirectoryReadBudget, FilesystemView};
use caushell_types::*;
use std::{collections::{BTreeMap, BTreeSet}, sync::Arc};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct RelocationScope {
    pub(super) root: String,
    pub(super) ordinary_source: Option<String>,
    pub(super) ordinary_destination: Option<String>,
    pub(super) disjoint_destination: Option<String>,
}

pub(super) fn resolve_backup(spelling: &str, resolver: &mut NamespaceResolver) -> Baseline {
    let (entry, mut observations) = resolver.resolve(spelling, PathTargetAccess::Entry);
    let (followed, followed_observations) = resolver.resolve(spelling, PathTargetAccess::Follow);
    observations.extend(followed_observations);
    let result = (|| {
        let SemanticResolution::Resolved { value: PathResolution::Concrete { path: entry } } = entry else {
            return entry;
        };
        let SemanticResolution::Resolved { value: PathResolution::Concrete { path: followed } } = followed else {
            return followed;
        };
        // GNU mv uses a directory (including a link to one) as the parent
        // of the placed entry. Otherwise it replaces the destination entry
        // itself. Appending a backup name never follows the backup leaf.
        let directory = if followed == "/" || observations.iter().any(|observation| {
            observation.path == followed && observation.entry == FilesystemEntry::Directory
        }) {
            followed
        } else {
            let (parent, _) = entry.rsplit_once('/').expect("resolved absolute path");
            if parent.is_empty() { "/".into() } else { parent.into() }
        };
        let (parent, parent_observations) = resolver.resolve(&directory, PathTargetAccess::Follow);
        observations.extend(parent_observations);
        match parent {
            SemanticResolution::Resolved { value: PathResolution::Concrete { path } }
                if path == "/" || observations.iter().any(|observation| {
                    observation.path == path && observation.entry == FilesystemEntry::Directory
                }) =>
            {
                SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots: vec![path], may_escape: false },
                }
            }
            SemanticResolution::Unresolved { .. } => parent,
            _ => unresolved(SemanticGapKind::UnknownTarget, "backup parent directory is unproved"),
        }
    })();
    (result, observations)
}

/// A backup and the paired move are effects of one native invocation. With
/// one observed ordinary source, this invocation cannot reparent its own
/// backup directory. Other execution units still depend on these writes.
pub(super) fn closed_backup_groups(
    inputs: &[Input],
    baselines: &[Baseline],
) -> BTreeSet<String> {
    let mut groups = BTreeMap::<&str, Vec<usize>>::new();
    for input in inputs {
        if input.namespace_effect == Some(PathNamespaceEffect::EntryReplacementBackup) {
            groups.entry(input.fact.source_node_id.as_str()).or_default();
        }
    }
    if groups.is_empty() {
        return BTreeSet::new();
    }
    for (index, input) in inputs.iter().enumerate() {
        if input.namespace_write && let Some(group) = groups.get_mut(input.fact.source_node_id.as_str()) {
            group.push(index);
        }
    }
    groups.into_iter().filter_map(|(node, indices)| {
        let [source, destination, backup] = indices[..] else {
            return None;
        };
        let source_fact = &inputs[source];
        let destination_fact = &inputs[destination];
        let backup_fact = &inputs[backup];
        if ![source_fact, destination_fact, backup_fact].iter().all(|input| input.pending_resolution)
            || source_fact.fact.operation != PathTargetOperation::MoveSource
            || destination_fact.fact.operation != PathTargetOperation::Write
            || source_fact.namespace_effect != Some(PathNamespaceEffect::EntryRelocation)
            || destination_fact.namespace_effect != Some(PathNamespaceEffect::EntryRelocation)
            || backup_fact.namespace_effect != Some(PathNamespaceEffect::EntryReplacementBackup)
            || destination_fact.fact.spelling != backup_fact.fact.spelling
            || !matches!(baselines[backup].0, SemanticResolution::Resolved { .. })
        {
            return None;
        }
        match &baselines[source].0 {
            SemanticResolution::Resolved { value: PathResolution::Concrete { path } }
                if source_fact.fact.lexical.concrete_path() == Some(path)
                    && ordinary_leaf(path, &baselines[source].1) => Some(node.to_owned()),
            _ => None,
        }
    }).collect()
}

pub(super) fn same_backup_operation(
    target: &Input,
    writer: &Input,
    groups: &BTreeSet<String>,
) -> bool {
    (target.namespace_effect == Some(PathNamespaceEffect::EntryReplacementBackup)
        || writer.namespace_effect == Some(PathNamespaceEffect::EntryReplacementBackup))
        && target.fact.source_node_id == writer.fact.source_node_id
        && groups.contains(target.fact.source_node_id.as_str())
}

pub(super) fn close_families(
    inputs: &mut [Input],
    baselines: &mut [Baseline],
    resolver: &mut NamespaceResolver,
    view: Arc<dyn FilesystemView>,
    budget: &mut DirectoryReadBudget,
    entry_directory: &str,
    foreground: impl Fn(&str) -> bool,
) -> Vec<DirectoryTreeEvidence> {
    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, input) in inputs.iter().enumerate() {
        if input.namespace_effect == Some(PathNamespaceEffect::EntryRelocation) {
            groups.entry(input.fact.source_node_id.clone()).or_default().push(index);
        }
    }
    let mut evidence = Vec::new();
    let mut comparisons = 0usize;
    for (node, indices) in groups {
        comparisons = comparisons.saturating_add(inputs.len());
        if comparisons > 65536 { break; }
        if indices.len() > 256
            || !indices.iter().any(|&i| inputs[i].fact.operation == PathTargetOperation::MoveSource)
            || !indices.iter().any(|&i| inputs[i].fact.operation == PathTargetOperation::Write)
            || inputs.iter().enumerate().any(|(i, input)| {
                input.fact.source_node_id == node && input.namespace_write
                    && input.pending_resolution && !indices.contains(&i)
            })
        {
            continue;
        }
        let mut anchors = Vec::new();
        let mut fixed_writes = Vec::new();
        let mut ordinary_source = None;
        let complete = indices.iter().all(|&i| {
            if !inputs[i].pending_resolution { return false; }
            match &baselines[i].0 {
                SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if !roots.is_empty() => {
                    anchors.extend(roots.iter().cloned());
                    true
                }
                SemanticResolution::Resolved {
                    value: PathResolution::Concrete { path },
                } if inputs[i].fact.operation == PathTargetOperation::Write
                    && inputs[i].fact.lexical.concrete_path() == Some(path.as_str())
                    && ordinary_fixed_write(path, &baselines[i].1) =>
                {
                    fixed_writes.push((i, path.clone()));
                    true
                }
                SemanticResolution::Resolved {
                    value: PathResolution::Concrete { path },
                } if indices.len() == 2
                    && inputs[i].fact.operation == PathTargetOperation::MoveSource
                    && inputs[i].fact.lexical.concrete_path() == Some(path.as_str()) =>
                {
                    if !ordinary_leaf(path, &baselines[i].1) {
                        return false;
                    }
                    ordinary_source = Some((path.clone(), i));
                    true
                }
                _ => false,
            }
        });
        if !complete || anchors.len() > 256 { continue; }
        if anchors.is_empty()
            && let (Some((source, _)), [(_, destination)]) =
                (&ordinary_source, fixed_writes.as_slice())
            && source != destination
            && foreground(&node)
        {
            let destination_index = fixed_writes[0].0;
            if ordinary_leaf(destination, &baselines[destination_index].1) {
                // Whether an ordinary leaf move succeeds, fails, or is
                // skipped, neither operand becomes a link or a directory.
                // The producer fixed point checks writes affecting either leaf.
                let scope = RelocationScope {
                    root: source.clone(),
                    ordinary_source: Some(source.clone()),
                    ordinary_destination: Some(destination.clone()),
                    disjoint_destination: None,
                };
                for &index in &indices {
                    inputs[index].relocation_scope = Some(scope.clone());
                }
            }
            continue;
        }
        let Some(root) = common_root(&anchors) else { continue };
        if let Some((source, source_index)) = &ordinary_source
            && anchors.as_slice() == [root.clone()]
            && fixed_writes.is_empty()
            && !caushell_query::path_is_within_root(source, &root)
            && !caushell_query::path_is_within_root(&root, source)
            && foreground(&node)
            && baselines[*source_index].1.iter().all(|o| view.entry(&o.path) == o.entry)
        {
            // An ordinary disjoint source and an already closed destination
            // family can be related without expanding either to their parent.
            let scope = RelocationScope {
                root,
                ordinary_source: Some(source.clone()),
                ordinary_destination: None,
                disjoint_destination: None,
            };
            for &index in &indices {
                inputs[index].relocation_scope = Some(scope.clone());
            }
            continue;
        }
        if let [source, destination] = indices.as_slice()
            && let [(fixed, path)] = fixed_writes.as_slice()
            && destination == fixed
            && anchors == [root.clone()]
            && inputs[*source].move_from_dot_search
            && root == entry_directory
            && !caushell_query::path_is_within_root(path, &root)
            && !caushell_query::path_is_within_root(&root, path)
            && inputs[*destination].fact.spelling.as_ref().is_some_and(|p| p.ends_with('/'))
            && baselines[*source].1.iter().any(|o| o.path == root && o.entry == FilesystemEntry::Directory)
            && baselines[*destination].1.iter().any(|o| o.path == *path && o.entry == FilesystemEntry::Directory)
        {
            let mut family = inputs[*destination].clone();
            family.fact.lexical = PathResolution::BoundedPathSet {
                roots: vec![root.clone(), path.clone()],
                may_escape: false,
            };
            let ((state, observations), proof) =
                directory_tree::resolve(&family, resolver, view.clone(), budget, entry_directory);
            let mut identities = BTreeSet::new();
            let closed = proof.complete
                && matches!(state, SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if roots == [root.clone(), path.clone()])
                && [root.as_str(), path.as_str()].into_iter()
                    .all(|anchor| proof.directories.iter().any(|dir| dir.path == anchor))
                && proof.directories.iter().all(|dir| dir.identity.as_ref()
                    .is_some_and(|id| identities.insert((id.device, id.inode))));
            evidence.push(proof);
            if closed {
                // Facts retain separate policy bounds. Both depend on the
                // complete two-root snapshot for mutation invalidation.
                baselines[*destination].0 = SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet {
                        roots: vec![path.clone()],
                        may_escape: false,
                    },
                };
                let scope = RelocationScope {
                    root,
                    ordinary_source: None,
                    ordinary_destination: None,
                    disjoint_destination: Some(path.clone()),
                };
                for &index in &indices {
                    inputs[index].relocation_scope = Some(scope.clone());
                    for observation in &observations {
                        if !baselines[index].1.contains(observation) {
                            baselines[index].1.push(observation.clone());
                        }
                    }
                }
            }
            continue;
        }
        // Fixed destinations must fit within the existing family. They do
        // not extend its root or replace the entry anchoring the proof.
        if fixed_writes.iter().any(|(_, path)| {
            path == &root || !caushell_query::path_is_within_root(path, &root)
        }) || ordinary_source.as_ref().is_some_and(|(path, _)| {
            path == &root || !caushell_query::path_is_within_root(path, &root)
        }) {
            continue;
        }
        let mut family = inputs[indices[0]].clone();
        family.fact.lexical = PathResolution::BoundedPathSet { roots: vec![root.clone()], may_escape: false };
        let ((state, observations), proof) =
            directory_tree::resolve(&family, resolver, view.clone(), budget, entry_directory);
        let closed = proof.complete && matches!(state,
            SemanticResolution::Resolved { value: PathResolution::BoundedPathSet { may_escape: false, .. } })
            && ((fixed_writes.is_empty() && ordinary_source.is_none())
                || proof.directories.iter().any(|dir| dir.path == root))
            && ordinary_source.as_ref().is_none_or(|(source, index)| {
                baselines[*index].1.iter()
                    .filter(|o| &o.path == source)
                    .all(|o| view.entry(&o.path) == o.entry)
            });
        evidence.push(proof);
        if !closed { continue; }
        // The landing path can denote a directory when the move runs. Use a
        // subtree bound for this write effect so later dependencies see all
        // potentially replaced children. Its original spelling stays exact.
        for (i, path) in fixed_writes {
            baselines[i].0 = SemanticResolution::Resolved {
                value: PathResolution::BoundedPathSet { roots: vec![path], may_escape: false },
            };
        }
        let scope = RelocationScope {
            root,
            ordinary_source: ordinary_source.map(|(path, _)| path),
            ordinary_destination: None,
            disjoint_destination: None,
        };
        for &i in &indices {
            inputs[i].relocation_scope = Some(scope.clone());
            for observation in &observations {
                if !baselines[i].1.contains(observation) {
                    baselines[i].1.push(observation.clone());
                }
            }
        }
    }
    evidence
}

fn ordinary_fixed_write(path: &str, observations: &[FilesystemObservation]) -> bool {
    observations.iter().any(|o| o.path == path)
        && observations.iter().all(|o| {
            o.source != FilesystemObservationSource::Unavailable
                && matches!(
                    o.entry,
                    FilesystemEntry::File | FilesystemEntry::Directory | FilesystemEntry::Missing
                )
        })
}

fn common_root(anchors: &[String]) -> Option<String> {
    if anchors.is_empty() || anchors.iter().any(|s| !s.starts_with('/') || s.contains('\0')) {
        return None;
    }
    let mut parts: Vec<_> = anchors[0].split('/').filter(|p| !p.is_empty()).collect();
    for anchor in &anchors[1..] {
        let other: Vec<_> = anchor.split('/').filter(|p| !p.is_empty()).collect();
        parts.truncate(parts.iter().zip(&other).take_while(|(a, b)| a == b).count());
    }
    Some(format!("/{}", parts.join("/")))
}

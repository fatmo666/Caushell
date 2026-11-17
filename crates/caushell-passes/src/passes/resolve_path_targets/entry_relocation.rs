//! Relational namespace closure for paired bounded entry transfers.
//! Containment only: no command names, policy roots, exact entries or outputs.
use super::{Input, directory_tree, namespace_state::Baseline};
use crate::path::namespace::NamespaceResolver;
use caushell_runner::{DirectoryReadBudget, FilesystemView};
use caushell_types::*;
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn close_families(
    inputs: &mut [Input],
    baselines: &mut [Baseline],
    resolver: &mut NamespaceResolver,
    view: Arc<dyn FilesystemView>,
    budget: &mut DirectoryReadBudget,
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
        let complete = indices.iter().all(|&i| {
            if !inputs[i].pending_resolution { return false; }
            match &baselines[i].0 {
                SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if !roots.is_empty() => {
                    anchors.extend(roots.iter().cloned());
                    true
                }
                _ => false,
            }
        });
        if !complete || anchors.len() > 256 { continue; }
        let Some(root) = common_root(&anchors) else { continue };
        let mut family = inputs[indices[0]].clone();
        family.fact.lexical = PathResolution::BoundedPathSet { roots: vec![root.clone()], may_escape: false };
        let ((state, observations), proof) = directory_tree::resolve(&family, resolver, view.clone(), budget);
        let closed = proof.complete && matches!(state,
            SemanticResolution::Resolved { value: PathResolution::BoundedPathSet { may_escape: false, .. } });
        evidence.push(proof);
        if !closed { continue; }
        for &i in &indices {
            inputs[i].relocation_scope = Some(root.clone());
            for observation in &observations {
                if !baselines[i].1.contains(observation) {
                    baselines[i].1.push(observation.clone());
                }
            }
        }
    }
    evidence
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

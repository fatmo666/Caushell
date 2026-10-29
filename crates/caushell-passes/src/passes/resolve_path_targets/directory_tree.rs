//! Close a declared link-free directory/file write family under its namespace.
//! Observations do not assert that any output exists or grant write permission.
use super::{Input, namespace_state::Baseline};
use crate::path::namespace::{NamespaceResolver, unresolved};
use caushell_runner::{DirectoryReadBudget, FilesystemView};
use caushell_types::*;
use std::{collections::BTreeSet, sync::Arc};

pub(super) fn resolve(
    input: &Input,
    resolver: &mut NamespaceResolver,
    view: Arc<dyn FilesystemView>,
    budget: &mut DirectoryReadBudget,
) -> (Baseline, DirectoryTreeEvidence) {
    let roots = match &input.fact.lexical {
        PathResolution::Concrete { path } => vec![path.clone()],
        PathResolution::BoundedPathSet {
            roots,
            may_escape: false,
        } => roots.clone(),
        _ => Vec::new(),
    };
    let mut evidence = DirectoryTreeEvidence {
        node_id: input.fact.source_node_id.clone(),
        roots: Vec::new(),
        directories: Vec::new(),
        complete: false,
        gap: None,
    };
    let mut observations = Vec::new();
    let result =
        (|| {
            if roots.is_empty() || roots.len() > 64 {
                return Err("directory write family has no bounded root".to_owned());
            }
            let mut queue = Vec::new();
            let mut seen = BTreeSet::new();
            let mut entries = 0;
            for spelling in roots {
                let (resolution, obs) = resolver.resolve(&spelling, PathTargetAccess::Follow);
                observations.extend(obs);
                let SemanticResolution::Resolved {
                    value: PathResolution::Concrete { path },
                } = resolution
                else {
                    return Err("directory family root namespace is unresolved".into());
                };
                evidence.roots.push(path.clone());
                queue.push((path, 0));
            }
            while let Some((path, depth)) = queue.pop() {
                if !seen.insert(path.clone()) {
                    continue;
                }
                let entry = view.entry(&path);
                observations.push(FilesystemObservation {
                    source: view.source(),
                    path: path.clone(),
                    entry: entry.clone(),
                });
                match entry {
                    FilesystemEntry::Missing => continue,
                    FilesystemEntry::Directory => {}
                    _ => return Err(
                        "directory write family contains a non-directory root or unresolved link"
                            .into(),
                    ),
                }
                let read = budget.read(view.as_ref(), &path, depth);
                evidence.directories.push(read.observation.clone());
                let Some(children) = read.complete_entries(&path, DirectoryReadLimits::default())
                else {
                    return Err(
                        "directory write family is incomplete or over its traversal budget".into(),
                    );
                };
                for child in children {
                    entries += 1;
                    if entries > MAX_DIRECTORY_ENTRIES {
                        return Err("directory write family entry budget exceeded".into());
                    }
                    let child_path =
                        format!("{}/{name}", path.trim_end_matches('/'), name = child.name);
                    let actual = view.entry(&child_path);
                    let expected = match child.kind {
                        DirectoryEntryKind::Directory => FilesystemEntry::Directory,
                        DirectoryEntryKind::File => FilesystemEntry::File,
                        _ => {
                            return Err(
                                "directory write family contains links or special entries".into()
                            );
                        }
                    };
                    if actual != expected {
                        return Err("directory write family changed during traversal".into());
                    }
                    observations.push(FilesystemObservation {
                        source: view.source(),
                        path: child_path.clone(),
                        entry: actual,
                    });
                    if child.kind == DirectoryEntryKind::Directory {
                        queue.push((child_path, depth + 1));
                    }
                }
            }
            // Recheck the complete snapshots, including directories which appeared
            // empty. A mixed snapshot cannot be used as a closed namespace proof.
            for o in &evidence.directories {
                if view.read_directory(&o.path, o.limits).observation != *o {
                    return Err("directory write family changed after traversal".into());
                }
            }
            for o in &observations {
                if view.entry(&o.path) != o.entry {
                    return Err("directory family ancestor changed during observation".into());
                }
            }
            Ok(())
        })();
    match result {
        Ok(()) => {
            evidence.complete = true;
            (
                (
                    SemanticResolution::Resolved {
                        value: PathResolution::BoundedPathSet {
                            roots: evidence.roots.clone(),
                            may_escape: false,
                        },
                    },
                    observations,
                ),
                evidence,
            )
        }
        Err(gap) => {
            evidence.gap = Some(gap.clone());
            (
                (
                    unresolved(SemanticGapKind::UnknownTarget, gap),
                    observations,
                ),
                evidence,
            )
        }
    }
}

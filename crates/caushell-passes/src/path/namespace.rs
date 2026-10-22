use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use caushell_runner::FilesystemView;
use caushell_types::{
    FilesystemEntry, FilesystemObservation, PathResolution, PathTargetAccess, SemanticGap,
    SemanticGapKind, SemanticResolution,
};

const MAX_LOOKUPS: usize = 4096;
const MAX_LINKS: usize = 40;
const MAX_PATH_BYTES: usize = 16384;
const MAX_STEPS: usize = 65536;

pub(crate) fn unresolved(
    kind: SemanticGapKind,
    detail: impl Into<String>,
) -> SemanticResolution<PathResolution> {
    SemanticResolution::Unresolved {
        gap: SemanticGap {
            kind,
            detail: detail.into(),
        },
    }
}

pub(crate) struct NamespaceResolver {
    view: Arc<dyn FilesystemView>,
    cache: BTreeMap<String, FilesystemEntry>,
    steps: usize,
}

impl NamespaceResolver {
    pub fn new(view: Arc<dyn FilesystemView>) -> Self {
        Self {
            view,
            cache: BTreeMap::new(),
            steps: 0,
        }
    }

    pub fn resolve(
        &mut self,
        spelling: &str,
        access: PathTargetAccess,
    ) -> (
        SemanticResolution<PathResolution>,
        Vec<FilesystemObservation>,
    ) {
        let mut observations = BTreeMap::new();
        let mut paths = Vec::new();
        for follow in match access {
            PathTargetAccess::Follow => &[true][..],
            PathTargetAccess::Entry => &[false][..],
            PathTargetAccess::Either => &[true, false][..],
        } {
            match self.walk(spelling, *follow, &mut observations) {
                Ok(path) => {
                    if !paths.contains(&path) {
                        paths.push(path);
                    }
                }
                Err(gap) => {
                    return (
                        SemanticResolution::Unresolved { gap },
                        observations
                            .into_iter()
                            .map(|(path, entry)| FilesystemObservation {
                                source: self.view.source(),
                                path,
                                entry,
                            })
                            .collect(),
                    );
                }
            }
        }
        let value = if paths.len() == 1 {
            PathResolution::Concrete {
                path: paths.remove(0),
            }
        } else {
            PathResolution::BoundedPathSet {
                roots: paths,
                may_escape: false,
            }
        };
        (
            SemanticResolution::Resolved { value },
            observations
                .into_iter()
                .map(|(path, entry)| FilesystemObservation {
                    source: self.view.source(),
                    path,
                    entry,
                })
                .collect(),
        )
    }

    fn walk(
        &mut self,
        spelling: &str,
        follow: bool,
        observations: &mut BTreeMap<String, FilesystemEntry>,
    ) -> Result<String, SemanticGap> {
        let gap = |kind, detail: String| SemanticGap { kind, detail };
        if !spelling.starts_with('/') || spelling.contains('\0') {
            return Err(gap(
                SemanticGapKind::UnknownTarget,
                "target spelling is not an absolute pathname".into(),
            ));
        }
        let mut pending: VecDeque<String> = spelling
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let mut parts: Vec<String> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut links = 0;
        let follow = follow || spelling.ends_with('/') || spelling.ends_with("/.");
        while let Some(component) = pending.pop_front() {
            let process_path = parts
                .first()
                .map_or(matches!(component.as_str(), "dev" | "proc"), |part| {
                    part == "dev" || part == "proc"
                });
            if process_path {
                let remaining = crate::path::normalize_shell_path(&format!(
                    "/{}/{}/{}",
                    parts.join("/"),
                    component,
                    pending.iter().cloned().collect::<Vec<_>>().join("/")
                ));
                if caushell_query::IoTargetQuery::descriptor_alias(&remaining).is_some() {
                    return Err(gap(SemanticGapKind::UnknownTarget, "descriptor pathname requires an execution I/O target, not a filesystem observation".into()));
                }
            }
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Err(gap(
                    SemanticGapKind::BudgetExceeded,
                    "namespace traversal budget exhausted".into(),
                ));
            }
            if spelling.len() + pending.iter().map(String::len).sum::<usize>() > MAX_PATH_BYTES {
                return Err(gap(
                    SemanticGapKind::BudgetExceeded,
                    "pathname expansion exceeded its byte budget".into(),
                ));
            }
            if component == "." {
                continue;
            }
            if component == ".." {
                parts.pop();
                continue;
            }
            let path = format!(
                "/{}{}{}",
                parts.join("/"),
                if parts.is_empty() { "" } else { "/" },
                component
            );
            if pending.is_empty() && !follow {
                parts.push(component);
                break;
            }
            let entry = if let Some(entry) = self.cache.get(&path) {
                entry.clone()
            } else {
                if self.cache.len() >= MAX_LOOKUPS {
                    return Err(gap(
                        SemanticGapKind::BudgetExceeded,
                        "filesystem lookup budget exhausted".into(),
                    ));
                }
                let entry = self.view.entry(&path);
                self.cache.insert(path.clone(), entry.clone());
                entry
            };
            observations.insert(path.clone(), entry.clone());
            match entry {
                FilesystemEntry::Unavailable { reason } => {
                    return Err(gap(
                        SemanticGapKind::FilesystemUnavailable,
                        format!("{path}: {reason}"),
                    ));
                }
                FilesystemEntry::Symlink { target } => {
                    links += 1;
                    if !seen.insert((path.clone(), pending.clone())) {
                        return Err(gap(
                            SemanticGapKind::LinkCycle,
                            format!("symbolic link cycle at {path}"),
                        ));
                    }
                    if links > MAX_LINKS {
                        return Err(gap(
                            SemanticGapKind::BudgetExceeded,
                            "symbolic link expansion budget exhausted".into(),
                        ));
                    }
                    if target.is_empty() || target.contains('\0') || target.len() > MAX_PATH_BYTES {
                        return Err(gap(
                            SemanticGapKind::UnknownTarget,
                            format!("invalid symbolic link target at {path}"),
                        ));
                    }
                    if target.starts_with('/') {
                        parts.clear();
                    }
                    for item in target.split('/').filter(|s| !s.is_empty()).rev() {
                        pending.push_front(item.into());
                    }
                }
                FilesystemEntry::File if !pending.is_empty() => {
                    return Err(gap(
                        SemanticGapKind::UnknownTarget,
                        format!("non-directory path component {path}"),
                    ));
                }
                FilesystemEntry::Directory | FilesystemEntry::File | FilesystemEntry::Missing => {
                    parts.push(component)
                }
            }
        }
        Ok(format!("/{}", parts.join("/")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct View(BTreeMap<String, FilesystemEntry>);
    impl FilesystemView for View {
        fn entry(&self, path: &str) -> FilesystemEntry {
            self.0
                .get(path)
                .cloned()
                .unwrap_or(FilesystemEntry::Directory)
        }
    }
    fn resolver(entries: &[(&str, FilesystemEntry)]) -> NamespaceResolver {
        NamespaceResolver::new(Arc::new(View(
            entries
                .iter()
                .map(|(path, entry)| ((*path).into(), entry.clone()))
                .collect(),
        )))
    }
    fn link(target: &str) -> FilesystemEntry {
        FilesystemEntry::Symlink {
            target: target.into(),
        }
    }
    fn path(result: &SemanticResolution<PathResolution>) -> Option<&str> {
        match result {
            SemanticResolution::Resolved { value } => value.concrete_path(),
            _ => None,
        }
    }

    #[test]
    fn access_mode_distinguishes_the_entry_from_opened_content() {
        let mut resolver = resolver(&[("/work/link", link("/outside/file"))]);
        assert_eq!(
            path(&resolver.resolve("/work/link", PathTargetAccess::Entry).0),
            Some("/work/link")
        );
        assert_eq!(
            path(&resolver.resolve("/work/link", PathTargetAccess::Follow).0),
            Some("/outside/file")
        );
        assert!(
            matches!(resolver.resolve("/work/link", PathTargetAccess::Either).0,
            SemanticResolution::Resolved { value: PathResolution::BoundedPathSet { roots, may_escape: false } } if roots.len() == 2)
        );
    }

    #[test]
    fn process_local_descriptors_do_not_use_the_observers_fd_table() {
        let mut resolver = resolver(&[("/work/door", link("/proc/self/fd"))]);
        for spelling in ["/dev/fd/9", "/proc/self/fd/9", "/work/door/9"] {
            let (result, observations) = resolver.resolve(spelling, PathTargetAccess::Follow);
            assert!(
                matches!(result, SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::UnknownTarget)
            );
            assert!(
                !observations
                    .iter()
                    .any(|entry| entry.path.starts_with("/proc/self")
                        || entry.path.starts_with("/dev/fd"))
            );
        }
    }

    #[test]
    fn parent_links_are_followed_even_for_namespace_entries() {
        let mut resolver = resolver(&[("/work/dir", link("/outside"))]);
        assert_eq!(
            path(&resolver.resolve("/work/dir/new", PathTargetAccess::Entry).0),
            Some("/outside/new")
        );
        assert_eq!(
            path(
                &resolver
                    .resolve("/work/dir/../new", PathTargetAccess::Follow)
                    .0
            ),
            Some("/new")
        );
    }

    #[test]
    fn relative_and_dangling_links_keep_their_parent_anchor() {
        let mut resolver = resolver(&[
            ("/work/link", link("../outside/new")),
            ("/outside/new", FilesystemEntry::Missing),
            ("/work/missing", FilesystemEntry::Missing),
            ("/work/door", link("/outside")),
        ]);
        let (resolved, evidence) = resolver.resolve("/work/link", PathTargetAccess::Follow);
        assert_eq!(path(&resolved), Some("/outside/new"));
        assert!(
            evidence.iter().any(
                |entry| entry.path == "/outside/new" && entry.entry == FilesystemEntry::Missing
            )
        );
        for access in [PathTargetAccess::Follow, PathTargetAccess::Entry] {
            let (resolved, evidence) = resolver.resolve("/work/missing/../door/new", access);
            assert_eq!(path(&resolved), Some("/outside/new"));
            assert!(evidence.iter().any(|entry| entry.path == "/work/door"));
        }
    }

    #[test]
    fn repeated_link_visits_are_not_necessarily_cycles() {
        let mut resolver = resolver(&[("/work/link", link("/work/dir"))]);
        assert_eq!(
            path(
                &resolver
                    .resolve("/work/link/../link/file", PathTargetAccess::Follow)
                    .0
            ),
            Some("/work/dir/file")
        );
    }

    #[test]
    fn unavailable_component_is_a_gap_not_a_path() {
        let mut resolver = resolver(&[(
            "/work",
            FilesystemEntry::Unavailable {
                reason: "denied".into(),
            },
        )]);
        assert!(
            matches!(resolver.resolve("/work/file", PathTargetAccess::Follow).0,
            SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::FilesystemUnavailable)
        );
    }

    #[test]
    fn lookup_budget_never_falls_back_to_lexical_success() {
        let mut resolver = resolver(&[]);
        for index in 0..MAX_LOOKUPS {
            resolver.resolve(&format!("/file{index}"), PathTargetAccess::Follow);
        }
        assert!(
            matches!(resolver.resolve("/overflow", PathTargetAccess::Follow).0,
            SemanticResolution::Unresolved { gap } if gap.kind == SemanticGapKind::BudgetExceeded)
        );
    }

    #[test]
    fn byte_budget_and_invalid_paths_are_explicit_gaps() {
        let mut resolver = resolver(&[]);
        for path in [
            "relative".to_string(),
            "/bad\0name".into(),
            format!("/{}", "x".repeat(MAX_PATH_BYTES + 1)),
        ] {
            assert!(matches!(
                resolver.resolve(&path, PathTargetAccess::Follow).0,
                SemanticResolution::Unresolved { .. }
            ));
        }
    }
}

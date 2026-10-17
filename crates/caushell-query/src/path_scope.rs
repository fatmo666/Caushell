//! Lexical POSIX path ranges. No policy, filesystem access or shell decoding.
use caushell_types::PathResolution;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathScopeProof {
    Covered,
    Outside,
    Unproven,
}

pub struct PathScopeQuery<'a> {
    resolution: &'a PathResolution,
}
impl<'a> PathScopeQuery<'a> {
    pub fn new(resolution: &'a PathResolution) -> Self {
        Self { resolution }
    }
    /// Every possible target must be covered, possibly by different roots.
    pub fn prove_all(&self, mut covered: impl FnMut(&str) -> bool) -> PathScopeProof {
        let valid = |path: &str| path.starts_with('/') && !path.contains('\0');
        if let Some(path) = self.resolution.concrete_path() {
            return if !valid(path) {
                PathScopeProof::Unproven
            } else if covered(path) {
                PathScopeProof::Covered
            } else {
                PathScopeProof::Outside
            };
        }
        match self.resolution {
            PathResolution::FileNamePrefix { directory, .. } if valid(directory) => {
                if covered(directory) {
                    PathScopeProof::Covered
                } else {
                    PathScopeProof::Outside
                }
            }
            PathResolution::BoundedPathSet {
                roots,
                may_escape: false,
            } if !roots.is_empty() && roots.iter().all(|r| valid(r)) => {
                if roots.iter().all(|r| covered(r)) {
                    PathScopeProof::Covered
                } else {
                    PathScopeProof::Outside
                }
            }
            _ => PathScopeProof::Unproven,
        }
    }
}

pub fn normalize_shell_path(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if let Some(last) = parts.last() {
                    if *last != ".." {
                        parts.pop();
                        continue;
                    }
                }
                if !is_absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    if is_absolute {
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

pub fn path_is_within_root(path: &str, root: &str) -> bool {
    let path = normalize_shell_path(path);
    let root = normalize_shell_path(root);
    if root == "/" {
        return path.starts_with('/');
    }
    path == root || path.strip_prefix(&root).is_some_and(|s| s.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_bounds_and_absolute_identity_are_required() {
        for (roots, escape, expected) in [
            (vec!["/work/a", "/tmp/b"], false, PathScopeProof::Covered),
            (vec!["/work/a", "/etc/b"], false, PathScopeProof::Outside),
            (vec!["/work/a"], true, PathScopeProof::Unproven),
            (vec![], false, PathScopeProof::Unproven),
            (vec!["relative"], false, PathScopeProof::Unproven),
        ] {
            let r = PathResolution::BoundedPathSet {
                roots: roots.into_iter().map(str::to_owned).collect(),
                may_escape: escape,
            };
            assert_eq!(
                PathScopeQuery::new(&r).prove_all(
                    |p| path_is_within_root(p, "/work") || path_is_within_root(p, "/tmp")
                ),
                expected
            );
        }
        assert!(!path_is_within_root("/tmp-evil/x", "/tmp"));
        assert!(!path_is_within_root("/work/../etc/x", "/work"));
    }
}

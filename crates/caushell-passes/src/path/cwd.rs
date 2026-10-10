//! Static path projection over execution-directory sets. No filesystem lookup.
use caushell_runner::{CwdPathContext, EffectiveCwd};
use caushell_types::PathResolution;

use super::normalize::normalize_shell_path;

pub(crate) fn effective_cwd_cases<'a>(
    cwd: Option<&'a EffectiveCwd>,
    fallback: &'a str,
) -> Vec<CwdPathContext<'a>> {
    cwd.map_or_else(
        || vec![CwdPathContext::Exact(fallback)],
        EffectiveCwd::cases,
    )
}

/// The collector resolves at a case's base first. A subtree base is only a
/// calculation anchor: widen relative results before exposing them as facts.
/// Unknown bytes never acquire a bound merely from the cwd.
pub(crate) fn project_path_at_cwd(
    resolution: PathResolution,
    cwd_dependent: bool,
    case: CwdPathContext<'_>,
) -> PathResolution {
    if !cwd_dependent {
        return resolution;
    }
    match case {
        CwdPathContext::Exact(_) => resolution,
        CwdPathContext::Unknown => PathResolution::UnsupportedDynamicText {
            text: "path depends on unresolved execution cwd".into(),
        },
        CwdPathContext::Subtree(root) => {
            let (paths, may_escape) = match &resolution {
                PathResolution::BoundedPathSet { roots, may_escape } => {
                    (roots.clone(), *may_escape)
                }
                other => match other.concrete_path() {
                    Some(path) => (vec![path.to_string()], false),
                    None => return resolution,
                },
            };
            let mut roots = Vec::new();
            let mut escape = may_escape || paths.is_empty();
            for path in paths {
                if !path.starts_with('/') || !root.starts_with('/') {
                    escape = true;
                    continue;
                }
                let bound = common_directory_bound(root, &path);
                if !roots.contains(&bound) {
                    roots.push(bound);
                }
            }
            PathResolution::BoundedPathSet {
                roots,
                may_escape: escape,
            }
        }
    }
}

fn common_directory_bound(left: &str, right: &str) -> String {
    let left = normalize_shell_path(left);
    let right = normalize_shell_path(right);
    let parts: Vec<_> = left
        .split('/')
        .filter(|p| !p.is_empty())
        .zip(right.split('/').filter(|p| !p.is_empty()))
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_not_fictitious_concrete_paths_or_subtrees_under_the_operand() {
        for (path, root) in [
            ("/workspace/out", "/workspace"),
            ("/workspace/sub/out", "/workspace"),
            ("/out", "/"),
            ("/workspace-peer/out", "/"),
        ] {
            assert_eq!(
                project_path_at_cwd(
                    PathResolution::Concrete { path: path.into() },
                    true,
                    CwdPathContext::Subtree("/workspace")
                ),
                PathResolution::BoundedPathSet {
                    roots: vec![root.into()],
                    may_escape: false,
                }
            );
        }
    }

    #[test]
    fn absolute_and_unresolved_targets_do_not_borrow_cwd_bounds() {
        let exact = PathResolution::Concrete {
            path: "/opt/out".into(),
        };
        assert_eq!(
            project_path_at_cwd(exact.clone(), false, CwdPathContext::Subtree("/workspace")),
            exact
        );
        let unknown = PathResolution::MissingBinding {
            variable_name: "TARGET".into(),
        };
        assert_eq!(
            project_path_at_cwd(unknown.clone(), true, CwdPathContext::Subtree("/workspace")),
            unknown
        );
        let escape = PathResolution::BoundedPathSet {
            roots: vec!["/workspace/sub".into()],
            may_escape: true,
        };
        assert!(matches!(
            project_path_at_cwd(escape, true, CwdPathContext::Subtree("/workspace")),
            PathResolution::BoundedPathSet {
                may_escape: true,
                ..
            }
        ));
    }
}

//! Bounds for path-valued runtime argv, not expansion or runtime observation.
use std::borrow::Cow;

use caushell_types::RuntimeArgumentDomain;

pub(crate) struct RuntimePathBounds<'a> {
    pub roots: Cow<'a, [String]>,
    pub may_escape: bool,
    pub root_membership: RootMembership,
}

/// Whether a possible argv path can denote the bounding root itself. This is
/// a proof about the domain, not an inference from a normalized trailing slash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootMembership {
    Inclusive,
    StrictDescendants,
}

/// Retain raw directory anchors for both ordinary path facts and subsequent
/// tool-declared suffix derivation. This query never invents a filename.
pub(crate) fn runtime_path_bounds(domain: &RuntimeArgumentDomain) -> Option<RuntimePathBounds<'_>> {
    match domain {
        RuntimeArgumentDomain::Unbounded | RuntimeArgumentDomain::TextTemplate { .. } => None,
        RuntimeArgumentDomain::GeneratedFileName { prefix, suffix } => {
            if prefix.len() + suffix.len() > 4096
                || prefix.contains('\0')
                || suffix.contains(['/', '\0'])
            {
                return None;
            }
            let parent = match prefix.rsplit_once('/') {
                Some(("", _)) => "/",
                Some((parent, _)) => parent,
                None => ".",
            };
            Some(RuntimePathBounds {
                roots: Cow::Owned(vec![directory_anchor(parent.into())]),
                may_escape: false,
                root_membership: RootMembership::StrictDescendants,
            })
        }
        RuntimeArgumentDomain::PathSet { roots, may_escape } => Some(RuntimePathBounds {
            roots: Cow::Borrowed(roots),
            may_escape: *may_escape,
            root_membership: RootMembership::Inclusive,
        }),
        RuntimeArgumentDomain::PathTemplate {
            roots,
            may_escape,
            prefix,
            suffix,
        } => {
            if roots.is_empty()
                || prefix.len() + suffix.len() > 4096
                || prefix.contains('\0')
                || suffix.contains('\0')
                // Appending '.' to the root spelling '.' can produce '..'.
                || matches!(suffix.split('/').next(), Some("." | ".."))
                || suffix.split('/').any(|component| component == "..")
            {
                return None;
            }
            let mut bounds = Vec::with_capacity(roots.len());
            for root in roots {
                if root.is_empty() || root.contains('\0') {
                    return None;
                }
                // String concatenation, NOT path join: `dest/` + `/opt/a`
                // is the relative `dest//opt/a`, not `/opt/a`.
                let stem = format!("{prefix}{root}");
                // A path binding is not a certificate that generated argv
                // bytes cannot become command options or mode controls.
                if stem.starts_with(['-', '+']) {
                    return None;
                }
                let bound = if suffix.is_empty() {
                    stem
                } else if suffix.starts_with('/')
                    || stem.ends_with('/')
                    || matches!(stem.rsplit('/').next(), Some("." | ".."))
                {
                    directory_anchor(stem)
                } else {
                    // The inclusive root may name a file too: `sub` plus
                    // `.bak` produces its sibling `sub.bak`. Widen to the
                    // parent, preserving that it is a directory-only anchor.
                    directory_anchor(match stem.rsplit_once('/') {
                        Some(("", _)) => "/".into(),
                        Some((parent, _)) => parent.into(),
                        None => ".".into(),
                    })
                };
                if !bounds.contains(&bound) {
                    bounds.push(bound);
                }
            }
            Some(RuntimePathBounds {
                roots: Cow::Owned(bounds),
                may_escape: *may_escape,
                // A fixed non-special final component makes every result a
                // descendant of its directory bound. Empty/`.` suffixes keep
                // the inclusive contract; no filename or root type is guessed.
                root_membership: if !matches!(suffix.rsplit('/').next(), Some("" | "." | "..")) {
                    RootMembership::StrictDescendants
                } else {
                    RootMembership::Inclusive
                },
            })
        }
    }
}

fn directory_anchor(mut spelling: String) -> String {
    if !spelling.ends_with('/') {
        spelling.push('/');
    }
    spelling
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::normalize::{join_shell_path, normalize_shell_path, path_is_within_root};

    fn template(roots: &[&str], prefix: &str, suffix: &str) -> RuntimeArgumentDomain {
        RuntimeArgumentDomain::PathTemplate {
            roots: roots.iter().map(|root| (*root).into()).collect(),
            may_escape: false,
            prefix: prefix.into(),
            suffix: suffix.into(),
        }
    }

    #[test]
    fn root_membership_is_semantic_not_a_trailing_slash_guess() {
        for root in [".", "./", "sub", "sub/", "/tmp/project/"] {
            let domain = RuntimeArgumentDomain::PathSet {
                roots: vec![root.into()],
                may_escape: false,
            };
            assert_eq!(
                runtime_path_bounds(&domain).unwrap().root_membership,
                RootMembership::Inclusive
            );
            for (suffix, membership) in [
                ("", RootMembership::Inclusive),
                ("/", RootMembership::Inclusive),
                ("/.", RootMembership::Inclusive),
                (".bak", RootMembership::StrictDescendants),
                ("/index", RootMembership::StrictDescendants),
                (".bak/child", RootMembership::StrictDescendants),
            ] {
                let domain = template(&[root], "", suffix);
                assert_eq!(
                    runtime_path_bounds(&domain).unwrap().root_membership,
                    membership,
                    "{domain:?}"
                );
            }
        }
    }

    #[test]
    fn generated_filename_bounds_cover_every_name_without_claiming_an_exact_path() {
        for (prefix, expected) in [
            ("x", "./"),
            ("", "./"),
            ("..", "./"),
            ("cache/p_", "cache/"),
            ("/opt/out_", "/opt/"),
            ("./cache/../p_", "./cache/../"),
            ("/opt/", "/opt/"),
        ] {
            let domain = RuntimeArgumentDomain::GeneratedFileName {
                prefix: prefix.into(),
                suffix: ".gz".into(),
            };
            assert_eq!(
                runtime_path_bounds(&domain).unwrap().roots.as_ref(),
                &[expected.to_string()]
            );
            let derived = domain.substitute_into("../{}", "{}");
            assert!(runtime_path_bounds(&derived).is_some());
        }
        for suffix in ["/../../out", "/child", "\0"] {
            let domain = RuntimeArgumentDomain::GeneratedFileName {
                prefix: "x".into(),
                suffix: suffix.into(),
            };
            assert!(runtime_path_bounds(&domain).is_none());
        }
    }

    #[test]
    fn affixes_preserve_raw_directory_anchors_and_widen_sibling_targets() {
        for (root, prefix, suffix, bound) in [
            (".", "", ".bak", "./"),
            ("sub", "", ".bak", "./"),
            ("/tmp/project", "", ".bak", "/tmp/"),
            ("/tmp/project/", "", ".bak", "/tmp/project/"),
            (".", "", "/index.html", "./"),
            ("sub", "", "/index.html", "sub/"),
            ("sub", "dest/", "", "dest/sub"),
            ("/opt/shared", "dest/", "", "dest//opt/shared"),
            (".", "/opt/copies/", ".bak", "/opt/copies/./"),
            (".", "PRE_", "", "PRE_."),
            ("sub", "", ".bak/index", "./"),
            (".", "", ".bak*", "./"),
        ] {
            let domain = template(&[root], prefix, suffix);
            let bounds = runtime_path_bounds(&domain).unwrap();
            assert_eq!(bounds.roots.as_ref(), &[bound.to_string()], "{domain:?}");
            assert!(!bounds.may_escape);
        }
    }

    #[test]
    fn unknown_escape_parent_suffix_and_control_boundaries_remain_unproven() {
        for domain in [
            RuntimeArgumentDomain::Unbounded,
            RuntimeArgumentDomain::Unbounded.substitute_into("/tmp/{}", "{}"),
            RuntimeArgumentDomain::Unbounded.substitute_into("./{}", "{}"),
            template(&[], "", ".bak"),
            template(&[""], "dest/", ""),
            template(&["."], "", "."),
            template(&["."], "", "./victim"),
            template(&["."], "", "/../../victim"),
            template(&["."], "-", ".bak"),
            template(&["."], "+", ".bak"),
            template(&["."], "", "\0"),
            template(&["."], &"x".repeat(4097), ""),
        ] {
            assert!(runtime_path_bounds(&domain).is_none(), "{domain:?}");
        }
        let mut domain = template(&["."], "", ".bak");
        if let RuntimeArgumentDomain::PathTemplate { may_escape, .. } = &mut domain {
            *may_escape = true;
        }
        assert!(runtime_path_bounds(&domain).unwrap().may_escape);
    }

    #[test]
    fn computed_bounds_cover_literal_concatenation_not_path_join() {
        // Synthetic argv bytes only; no directories or command execution.
        for root in [
            ".",
            "./",
            "sub",
            "sub/",
            "sub/..",
            "..",
            "../",
            "/opt/source",
            "/opt/source/",
            "/../../opt/source/",
        ] {
            for prefix in ["", "dest/", "./cache/", "../out/", "/opt/out/", "PRE_", "."] {
                for suffix in ["", ".bak", "l", "/index", "/./index", ".bak/child"] {
                    let domain = template(&[root], prefix, suffix);
                    let Some(bounds) = runtime_path_bounds(&domain) else {
                        continue;
                    };
                    for tail in ["", "/file", "/a/b", "/...", "/$value", "/file*"] {
                        let output = format!("{prefix}{root}{tail}{suffix}");
                        let path = if output.starts_with('/') {
                            normalize_shell_path(&output)
                        } else {
                            join_shell_path("/tmp/project", &output)
                        };
                        assert!(
                            bounds.roots.iter().any(|bound| {
                                let bound = if bound.starts_with('/') {
                                    normalize_shell_path(bound)
                                } else {
                                    join_shell_path("/tmp/project", bound)
                                };
                                path_is_within_root(&path, &bound)
                                    && (bounds.root_membership == RootMembership::Inclusive
                                        || (path != bound
                                            && path_is_within_root(
                                                &join_shell_path(&path, ".."),
                                                &bound,
                                            )))
                            }),
                            "{domain:?}: {output:?} is not bounded by {:?}",
                            bounds.roots
                        );
                    }
                }
            }
        }
    }
}

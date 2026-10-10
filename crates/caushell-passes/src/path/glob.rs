//! Lexical bounds for pure shell pathname generation, never glob expansion.
use caushell_profile::{ArgumentFieldCount, shell_word_structure};
use caushell_types::PathResolution;

use super::normalize::{join_shell_path, resolve_path_operand};

/// `option_like_fields_are_data` is true only for a shell redirection, not
/// because a command happens to bind a glob-looking token to a path slot.
pub(crate) fn resolve_glob_path_operand(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
    option_like_fields_are_data: bool,
) -> Option<PathResolution> {
    // Cheap common-word rejection before doing any structural work.
    // Limit work on unusually large words; unknown stays unknown.
    if text.len() > 4096 || !text.contains(['*', '?', '[']) {
        return None;
    }
    if quoted || !matches!(node_kind, "word" | "concatenation") {
        return None;
    }
    // This query proves pathname generation only. Do not inherit a prefix
    // across IFS splitting, substitutions, brace/vector expansion or extglob.
    // Escaped/mixed-quoted words keep the existing literal/unknown handling.
    if text.contains(['$', '`', '{', '}', '(', ')', '\\', '\'', '"', '\0']) {
        return None;
    }
    let (shape_text, tilde) = match text.strip_prefix("~/") {
        Some(rest) => (rest, true),
        None if text.starts_with('~') => return None,
        None => (text, false),
    };
    let shape = shell_word_structure(shape_text, false, node_kind);
    if let Some(literal) = shape.exact_value() {
        // `[]` and an unmatched `[` are literal names, not bracket globs.
        let path = if tilde {
            join_shell_path(home.filter(|p| p.starts_with('/'))?, literal)
        } else {
            resolve_path_operand(literal, false, "raw_string", cwd, home)?
        };
        return Some(PathResolution::Concrete { path });
    }
    if shape.fields != ArgumentFieldCount::ZeroOrMore
        || (!tilde
            && !option_like_fields_are_data
            && (shape.may_start_with("-") || shape.may_start_with("+")))
    {
        return None;
    }

    let mut depth = 0usize;
    let mut parents = 0usize;
    let mut pattern_seen = false;
    for component in shape_text.split('/') {
        let component_shape = shell_word_structure(component, false, "word");
        if component_shape.exact {
            match component {
                "" | "." => {}
                ".." if pattern_seen => return None,
                ".." if depth == 0 => parents += 1,
                ".." => depth -= 1,
                _ => depth += 1,
            }
        } else {
            if component_shape.fields != ArgumentFieldCount::ZeroOrMore {
                return None;
            }
            // `*`/`?` do not select . or .., even under Bash dotglob.
            // Explicit-dot/bracket patterns might; never silently normalize
            // those generated names back into the nominal search root.
            if component.starts_with(['.', '[']) && component_shape.may_equal("..") {
                return None;
            }
            pattern_seen = true;
        }
    }
    if !pattern_seen {
        return None;
    }
    // Case-insensitive pathname generation can change literal directory
    // components too. Relative patterns are bounded by their starting cwd
    // (or explicit parent), not an invented exact spelling of a subdirectory.
    // Absolute patterns therefore retain a / bound and cannot become a
    // workspace-contained proof without shell-option facts we do not have.
    let mut root = if tilde {
        home.filter(|p| p.starts_with('/'))?.to_string()
    } else if shape_text.starts_with('/') {
        "/".into()
    } else {
        cwd.to_string()
    };
    for _ in 0..parents {
        root = join_shell_path(&root, "..");
    }
    // Preserve a directory anchor spelling for downstream suffix derivation;
    // a filename glob does not mean the cwd itself is a sibling-file input.
    if !root.ends_with('/') {
        root.push('/');
    }
    Some(PathResolution::BoundedPathSet {
        roots: vec![root],
        may_escape: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(text: &str) -> Option<PathResolution> {
        resolve_glob_path_operand(
            text,
            false,
            "word",
            "/tmp/project",
            Some("/home/alice"),
            false,
        )
    }

    #[test]
    fn glob_scope_uses_a_directory_anchor_without_inventing_filenames() {
        for text in [
            "./*.sh",
            "img/*",
            "img/*/*.sh",
            "file*.gz",
            "ed*",
            "./[ab]*",
            "./**/*",
            "./..?*",
            "./.[^.]*",
        ] {
            assert_eq!(
                query(text),
                Some(PathResolution::BoundedPathSet {
                    roots: vec!["/tmp/project/".into()],
                    may_escape: false,
                }),
                "{text}"
            );
        }
    }

    #[test]
    fn external_and_parent_roots_remain_external() {
        for (text, root) in [
            ("../dir/*.sh", "/tmp/"),
            ("dir/../../*.sh", "/tmp/"),
            ("/opt/shared/*.sh", "/"),
            ("~/cache/*.sh", "/home/alice/"),
        ] {
            assert_eq!(
                query(text),
                Some(PathResolution::BoundedPathSet {
                    roots: vec![root.into()],
                    may_escape: false,
                }),
                "{text}"
            );
        }
        assert!(
            resolve_glob_path_operand("~/cache/*.sh", false, "word", "/tmp/project", None, false)
                .is_none()
        );
    }

    #[test]
    fn controls_dynamic_expansion_and_generated_parents_do_not_gain_a_path_proof() {
        for text in [
            "*",
            "*.sh",
            "[a-z]*",
            "./.*",
            "./.[.]*",
            "./[.][.]",
            "dir/*/../*.sh",
            "./$dir/*.sh",
            "./$(pwd)/*.sh",
            "./`pwd`/*.sh",
            "./{..,cache}/*",
            "./@(cache|..)/*",
            "~bob/*.sh",
            "./\\*.sh",
            "./\"cache\"/*",
        ] {
            assert!(query(text).is_none(), "{text}");
        }
        assert!(query(&format!("./{}*", "a".repeat(4096))).is_none());
    }

    #[test]
    fn bracket_literals_and_runtime_bytes_do_not_become_pattern_guesses() {
        for (text, path) in [
            ("[]", "/tmp/project/[]"),
            ("abc[", "/tmp/project/abc["),
            ("~/[]", "/home/alice/[]"),
        ] {
            assert_eq!(
                query(text),
                Some(PathResolution::Concrete { path: path.into() })
            );
        }
        for (quoted, node_kind) in [
            (true, "string"),
            (false, "command_substitution"),
            (false, "process_substitution"),
        ] {
            assert!(
                resolve_glob_path_operand("./*.sh", quoted, node_kind, "/tmp/project", None, false)
                    .is_none()
            );
        }
    }

    #[test]
    fn only_shell_redirections_can_ignore_option_like_filenames() {
        assert!(query("*.sh").is_none());
        assert_eq!(
            resolve_glob_path_operand("*.sh", false, "word", "/tmp/project", None, true),
            Some(PathResolution::BoundedPathSet {
                roots: vec!["/tmp/project/".into()],
                may_escape: false,
            })
        );
        assert!(
            resolve_glob_path_operand(".*", false, "word", "/tmp/project", None, true).is_none()
        );
    }
}

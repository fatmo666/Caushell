//! Repair the pinned grammar's misclassification of literal dollar bytes.
//! The stand-in is used only for tree construction. Every caller reads the
//! original source, and real expansions retain their original delimiters.
use tree_sitter::{Node, Parser, Tree};

use super::{heredoc_data, parse_escaped_blanks};
use crate::ParseError;

/// Recognizes the punctuation accepted after a literal dollar in shell words.
pub fn is_literal_dollar_follower(character: char) -> bool {
    matches!(character, '.' | '/' | ':' | ',' | '%' | '+' | '=' | '^')
}

struct Site {
    dollar: usize,
    backquote_opening: Option<usize>,
}

pub(super) fn recover(
    parser: &mut Parser,
    source: &[u8],
    tree: Tree,
    normalize_backquotes: bool,
) -> Result<Tree, ParseError> {
    if !tree.root_node().has_error() || source.len() > 65_536 || !source.contains(&b'$') {
        return Ok(tree);
    }
    let mut sites = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if !node.has_error() {
            continue;
        }
        if let Some(site) = punctuation_site(node, source) {
            sites.push(site);
        }
        if node.is_error() {
            closing_backquote_sites(node, source, &mut sites);
        }
        if sites.len() > 128 {
            return Ok(tree);
        }
        stack.extend(node.children(&mut node.walk()));
    }
    if sites.is_empty() {
        return Ok(tree);
    }
    let opaque = heredoc_data(tree.root_node(), source);
    let mut view = source.to_vec();
    for site in &sites {
        if opaque[site.dollar]
            || site
                .backquote_opening
                .is_some_and(|opening| opaque[opening])
        {
            return Ok(tree);
        }
        view[site.dollar] = b'_';
    }
    let repaired = parse_escaped_blanks(parser, &view)?;
    let root = repaired.root_node();
    if root.has_error() {
        return Ok(tree);
    }
    let opaque = heredoc_data(root, source);
    if sites.iter().all(|site| {
        !opaque[site.dollar]
            && match site.backquote_opening {
                Some(opening) => {
                    !opaque[opening]
                        && root
                            .descendant_for_byte_range(opening, site.dollar + 2)
                            .is_some_and(|node| {
                                node.kind() == "command_substitution"
                                    && node.start_byte() == opening
                                    && (normalize_backquotes || node.end_byte() == site.dollar + 2)
                            })
                }
                None => root
                    .descendant_for_byte_range(site.dollar, site.dollar + 2)
                    .is_some_and(|node| node.kind() == "word" && is_argument_word(node)),
            }
    }) {
        return Ok(repaired);
    }
    Ok(tree)
}

fn is_argument_word(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "concatenation" {
            node = parent;
            continue;
        }
        return parent.kind() == "command"
            && parent
                .children_by_field_name("argument", &mut parent.walk())
                .any(|arg| arg == node);
    }
    false
}

fn punctuation_site(node: Node<'_>, source: &[u8]) -> Option<Site> {
    let dollar = node.start_byte();
    if !isolated_dollar(source, dollar)
        || !source
            .get(dollar + 1)
            .is_some_and(|&b| is_literal_dollar_follower(char::from(b)))
    {
        return None;
    }
    let first = node.child(0)?;
    if first.kind() != "$" || first.start_byte() != dollar || first.end_byte() != dollar + 1 {
        return None;
    }
    // An ERROR inside an argument concatenation, or an expansion whose only
    // alleged name is a zero-width recovery node, owns this exact byte.
    let missing_name = node.kind() == "simple_expansion"
        && is_argument_word(node)
        && node.child_count() == 2
        && node.child(1).is_some_and(|name| name.is_missing());
    let broken_word = node.is_error()
        && (node.parent().is_some_and(|p| p.kind() == "concatenation") && is_argument_word(node)
            || node.end_byte() == dollar + 2
                && node.prev_named_sibling().is_some_and(|previous| {
                    previous.kind() == "command"
                        && previous.end_byte() == dollar
                        && previous
                            .children_by_field_name("argument", &mut previous.walk())
                            .last()
                            .is_some_and(|arg| arg.end_byte() == dollar)
                }));
    (missing_name || broken_word).then_some(Site {
        dollar,
        backquote_opening: None,
    })
}

fn closing_backquote_sites(node: Node<'_>, source: &[u8], sites: &mut Vec<Site>) {
    let mut opening = None;
    for child in node.children(&mut node.walk()) {
        let start = child.start_byte();
        match child.kind() {
            "`" if source.get(start..child.end_byte()) == Some(b"`") => opening = Some(start),
            "$`" if source.get(start..child.end_byte()) == Some(b"$`") => {
                if let Some(opening) = opening.take()
                    && isolated_dollar(source, start)
                    && crate::backtick::closing_backquote(source, opening, child.end_byte())
                        == Some(start + 1)
                {
                    sites.push(Site {
                        dollar: start,
                        backquote_opening: Some(opening),
                    });
                }
            }
            _ => {}
        }
    }
}

fn isolated_dollar(source: &[u8], offset: usize) -> bool {
    source.get(offset) == Some(&b'$')
        && offset
            .checked_sub(1)
            .is_none_or(|prev| !matches!(source[prev], b'$' | b'\\' | b'\n' | b'\r'))
}

#[cfg(test)]
mod tests {
    use caushell_types::ShellKind;

    use crate::{
        ParseStatus, decode_static_shell_argument, parse_command, parse_command_substitutions,
    };

    #[test]
    fn punctuation_after_a_bare_dollar_keeps_original_argument_bytes() {
        for argument in [
            "prefix$.",
            "$.",
            "prefix$/file",
            "prefix$:",
            "prefix$+",
            "prefix$=data",
        ] {
            let source = format!("printf '%s' {argument}");
            let artifact = parse_command(&source, ShellKind::Bash).unwrap();
            assert_eq!(
                artifact.status,
                ParseStatus::Complete,
                "{argument}: {:?}",
                artifact.diagnostics
            );
            let words = &artifact.commands[0].tokens;
            assert_eq!(words.len(), 2);
            let word = &words[1];
            assert_eq!(word.text, argument);
            assert_eq!(&source[word.span.start_byte..word.span.end_byte], argument);
            assert_eq!(
                decode_static_shell_argument(&word.text, word.quoted, &word.node_kind).as_deref(),
                Some(argument)
            );
        }
    }

    #[test]
    fn terminal_bare_dollar_keeps_the_original_backquote_body_and_span() {
        for source in [
            "printf '%s' `printf token$`",
            "printf '%s' \"`printf token$`\"",
            "printf '%s' `printf token$` `printf sibling`",
            "printf '%s' `printf token$`tail",
        ] {
            let artifact = parse_command(source, ShellKind::Bash).unwrap();
            assert_eq!(
                artifact.status,
                ParseStatus::Complete,
                "{source}: {:?}",
                artifact.diagnostics
            );
            let facts = parse_command_substitutions(source, ShellKind::Bash).unwrap();
            assert_eq!(
                facts.len(),
                if source.contains("sibling") { 2 } else { 1 },
                "{source}"
            );
            assert_eq!(facts[0].body_text, "printf token$");
            assert_eq!(
                &source[facts[0].span.start_byte..facts[0].span.end_byte],
                "`printf token$`"
            );
            assert_eq!(
                artifact.commands[0].tokens[1].command_substitutions[0],
                facts[0]
            );
        }
    }

    #[test]
    fn real_expansions_quotes_and_missing_boundaries_keep_their_roles() {
        let source = "printf '%s' prefix$.$(printf value)";
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{:?}",
            parsed.diagnostics
        );
        let word = &parsed.commands[0].tokens[1];
        assert_eq!(word.command_substitutions[0].body_text, "printf value");
        assert_eq!(
            decode_static_shell_argument(&word.text, word.quoted, &word.node_kind),
            None
        );

        for source in ["printf '%s' `printf token$", "printf '%s' prefix$. \"open"] {
            assert_eq!(
                parse_command(source, ShellKind::Bash).unwrap().status,
                ParseStatus::Partial
            );
        }
        for expansion in [
            "prefix$$",
            "prefix$?",
            "prefix$@",
            "prefix$-",
            "prefix$VAR",
            "prefix${VAR}",
        ] {
            assert_eq!(
                decode_static_shell_argument(expansion, false, "concatenation"),
                None
            );
        }
        let literal = "printf '%s' '`printf token$`'";
        assert!(
            parse_command_substitutions(literal, ShellKind::Bash)
                .unwrap()
                .is_empty()
        );
        let source = "printf '%s' `printf token$$`";
        let facts = parse_command_substitutions(source, ShellKind::Bash).unwrap();
        assert_eq!(facts[0].body_text, "printf token$$");
    }
}

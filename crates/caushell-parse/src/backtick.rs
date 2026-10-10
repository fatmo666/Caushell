//! Compatibility projection for the grammar's greedy backquote boundary.
//! Only AST-recognized substitution openings qualify. No raw-source shell
//! lexer, command-specific rule, subprocess, or filesystem query is used.
use tree_sitter::{Node, Parser, Tree};

use crate::{CommandSubstitutionFact, ParseError, ParsedCommandArtifact, SourceSpan};

pub(crate) struct BacktickTree {
    pub tree: Tree,
    pub source: Option<Vec<u8>>,
    pub facts: Vec<CommandSubstitutionFact>,
}

pub(crate) fn project(parser: &mut Parser, source: &str) -> Result<BacktickTree, ParseError> {
    let mut tree = parser
        .parse(source, None)
        .ok_or(ParseError::ParseCancelled)?;
    let mut projected = None;
    let mut facts = Vec::new();
    if !source.contains('`') {
        return Ok(BacktickTree {
            tree,
            source: projected,
            facts,
        });
    }
    // Each retry exposes the next sibling hidden by a greedy AST node. A
    // correctly bounded backquote, or an input without one, needs no retry.
    // Never turn a remaining, unanalyzed boundary into a successful parse.
    for round in 0..=32 {
        let bytes = projected.as_deref().unwrap_or(source.as_bytes());
        let mut ranges = Vec::new();
        collect_boundaries(tree.root_node(), bytes, &mut ranges);
        if ranges.is_empty() {
            return Ok(BacktickTree {
                tree,
                source: projected,
                facts,
            });
        }
        if round == 32 {
            return Err(ParseError::BacktickBoundaryLimit);
        }
        let bytes = projected.get_or_insert_with(|| source.as_bytes().to_vec());
        for (start, end) in ranges {
            facts.push(CommandSubstitutionFact {
                text: source[start..end].into(),
                body_text: decode_body(&source[start + 1..end - 1]),
                span: source_span(source.as_bytes(), start, end),
            });
            // A raw-string placeholder is one opaque shell word, including
            // multiline bodies. Inside a double-quoted string its quote bytes
            // are ordinary text. Every original byte/line coordinate survives.
            for byte in &mut bytes[start..end] {
                if *byte != b'\n' {
                    *byte = b'_';
                }
            }
            bytes[start] = b'\'';
            bytes[end - 1] = b'\'';
        }
        tree = parser
            .parse(bytes.as_slice(), None)
            .ok_or(ParseError::ParseCancelled)?;
    }
    unreachable!("bounded loop returns on completion or exhaustion")
}

fn collect_boundaries(node: Node<'_>, bytes: &[u8], ranges: &mut Vec<(usize, usize)>) {
    if node.kind() == "command_substitution" && bytes.get(node.start_byte()) == Some(&b'`') {
        let start = node.start_byte();
        let mut index = start + 1;
        while index < node.end_byte() {
            match bytes[index] {
                b'\\' => index += 2,
                b'`' => {
                    if index + 1 < node.end_byte() {
                        ranges.push((start, index + 1));
                    }
                    // The body belongs to its own nested analysis. In
                    // particular, escaped inner ticks are not siblings here.
                    return;
                }
                _ => index += 1,
            }
        }
        // An incomplete opening retains the original parse diagnostics.
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_boundaries(child, bytes, ranges);
    }
}

/// Bash removes one old-style substitution escape layer BEFORE parsing the
/// body, even when those bytes appear inside quotes in that body. Other
/// backslashes remain shell source; this is not general quote removal.
pub(crate) fn decode_body(body: &str) -> String {
    let mut output = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek().copied() {
                Some('$' | '`' | '\\') => output.push(chars.next().unwrap()),
                Some('\n') => {
                    chars.next();
                }
                _ => output.push(ch),
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn source_span(bytes: &[u8], start: usize, end: usize) -> SourceSpan {
    let point = |offset| {
        let prefix = &bytes[..offset];
        let row = prefix.iter().filter(|&&b| b == b'\n').count();
        let column = prefix
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(offset, |i| offset - i - 1);
        (row, column)
    };
    let (start_row, start_column) = point(start);
    let (end_row, end_column) = point(end);
    SourceSpan {
        start_byte: start,
        end_byte: end,
        start_row,
        start_column,
        end_row,
        end_column,
    }
}

/// Restore expansion facts, not placeholder values. Modern $(...) owns its
/// nested syntax; do not also attach an inner backquote as a sibling producer.
pub(crate) fn restore(artifact: &mut ParsedCommandArtifact, facts: &[CommandSubstitutionFact]) {
    if facts.is_empty() {
        return;
    }
    let restore_value = |span: &SourceSpan,
                         node_kind: &mut String,
                         quoted: &mut bool,
                         substitutions: &mut Vec<CommandSubstitutionFact>| {
        if facts.iter().any(|f| f.span == *span) {
            *node_kind = "command_substitution".into();
            *quoted = false;
        }
        let extra: Vec<_> = facts
            .iter()
            .filter(|fact| {
                span.start_byte <= fact.span.start_byte
                    && fact.span.end_byte <= span.end_byte
                    && !substitutions.iter().any(|outer| {
                        outer.span.start_byte <= fact.span.start_byte
                            && fact.span.end_byte <= outer.span.end_byte
                    })
            })
            .cloned()
            .collect();
        substitutions.extend(extra);
        substitutions.sort_by_key(|fact| fact.span.start_byte);
    };
    for command in &mut artifact.commands {
        for token in &mut command.tokens {
            restore_value(
                &token.span,
                &mut token.node_kind,
                &mut token.quoted,
                &mut token.command_substitutions,
            );
        }
    }
    for assignment in artifact
        .commands
        .iter_mut()
        .flat_map(|c| &mut c.prefix_assignments)
        .chain(
            artifact
                .assignment_commands
                .iter_mut()
                .flat_map(|c| &mut c.assignments),
        )
        .chain(
            artifact
                .declaration_commands
                .iter_mut()
                .flat_map(|c| &mut c.assignments),
        )
    {
        let value = &mut assignment.value;
        restore_value(
            &value.span,
            &mut value.node_kind,
            &mut value.quoted,
            &mut value.command_substitutions,
        );
    }
    for redirection in &mut artifact.redirections {
        for value in [&mut redirection.target, &mut redirection.content]
            .into_iter()
            .flatten()
        {
            if facts.iter().any(|f| f.span == value.span) {
                value.node_kind = "command_substitution".into();
                value.quoted = false;
            }
        }
    }
}

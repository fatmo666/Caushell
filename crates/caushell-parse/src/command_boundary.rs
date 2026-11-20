//! A simple command cannot contain an unquoted, unescaped newline between
//! argv words. The pinned Bash grammar can nevertheless accept those bytes as
//! whitespace when a later redirect competes with a nested pipeline parse.
//! Qualify boundaries from AST sibling gaps, never from command names or from
//! newlines inside words, quoted data, substitutions, or heredoc bodies.
use tree_sitter::{InputEdit, Node, Point, Tree};

pub(crate) fn separators(root: Node<'_>, source: &[u8]) -> Vec<usize> {
    fn visit(node: Node<'_>, source: &[u8], result: &mut Vec<usize>) {
        let mut boundary = None;
        if matches!(
            node.kind(),
            "command"
                | "declaration_command"
                | "unset_command"
                | "variable_assignments"
                | "file_redirect"
                | "redirected_statement"
        ) {
            let mut cursor = node.walk();
            let children: Vec<_> = node.children(&mut cursor).collect();
            for pair in children.windows(2) {
                let [left, right] = pair else { unreachable!() };
                if left.kind() == "comment"
                    || left.has_error()
                    || right.has_error()
                    || left.is_missing()
                    || right.is_missing()
                {
                    continue;
                }
                // A newline before a redirect destination is incomplete
                // syntax, not permission to invent a missing operand.
                if node.kind() == "file_redirect" && !(left.is_named() && right.is_named()) {
                    continue;
                }
                let start = left.end_byte();
                let end = right.start_byte();
                let Some(gap) = source.get(start..end) else {
                    continue;
                };
                let mut first_break = None;
                let mut index = 0;
                while index < gap.len() {
                    match gap[index] {
                        b' ' | b'\t' => index += 1,
                        b'\\' if gap.get(index + 1) == Some(&b'\n') => index += 2,
                        b'\n' => {
                            let absolute = start + index;
                            let backslashes = source[..absolute]
                                .iter()
                                .rev()
                                .take_while(|&&b| b == b'\\')
                                .count();
                            if backslashes % 2 == 0 {
                                first_break.get_or_insert(absolute);
                            }
                            index += 1;
                        }
                        // Do not interpret arbitrary source or comment text
                        // in an AST gap with a second shell lexer.
                        _ => {
                            first_break = None;
                            break;
                        }
                    }
                }
                // Beyond this separator the current node no longer owns the
                // words or their gaps. Reparse before classifying that source.
                if let Some(first) = first_break {
                    result.push(first);
                    boundary = Some(first);
                    break;
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if boundary.is_some_and(|at| child.end_byte() > at) {
                break;
            }
            visit(child, source, result);
        }
    }
    if !source.contains(&b'\n') {
        return Vec::new();
    }
    let mut result = Vec::new();
    visit(root, source, &mut result);
    result.sort_unstable();
    result.dedup();
    result
}

/// Parsing uses same-byte-length semicolon placeholders. Restore their line
/// coordinates with Tree-sitter's source-edit map before extracting any facts.
/// The syntax remains a statement separator and all text comes from the
/// original source; no projected source is executed or exposed as argv.
pub(crate) fn restore_points(tree: &mut Tree, original: &[u8], projected: Option<&[u8]>) {
    let Some(projected) = projected else { return };
    let mut point = Point::new(0, 0);
    for (index, &byte) in original.iter().enumerate() {
        if byte == b'\n' {
            if projected[index] == b';' {
                tree.edit(&InputEdit {
                    start_byte: index,
                    old_end_byte: index + 1,
                    new_end_byte: index + 1,
                    start_position: point,
                    old_end_position: Point::new(point.row, point.column + 1),
                    new_end_position: Point::new(point.row + 1, 0),
                });
            }
            point = Point::new(point.row + 1, 0);
        } else {
            point.column += 1;
        }
    }
}

//! Bounded syntax facts shared by source-position consumers. No reparse,
//! execution, outcome observation, command-name rule or permission inference.
use crate::{ShellStatusCondition, SourceSpan};
use tree_sitter::Node;

fn span(n: Node<'_>) -> SourceSpan {
    SourceSpan {
        start_byte: n.start_byte(),
        end_byte: n.end_byte(),
        start_row: n.start_position().row,
        start_column: n.start_position().column,
        end_row: n.end_position().row,
        end_column: n.end_position().column,
    }
}
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = n.walk();
    n.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}
fn frame(mut n: Node<'_>) -> Option<SourceSpan> {
    while let Some(p) = n.parent() {
        if p.kind() == "subshell" {
            return Some(span(p));
        }
        if p.kind() == "pipeline" {
            return Some(span(n));
        }
        n = p;
    }
    None
}
fn implied(
    n: Node<'_>,
    success: bool,
    source: &[u8],
    depth: usize,
    out: &mut Vec<(SourceSpan, bool)>,
) {
    if depth == 0 || out.len() >= 4096 {
        return;
    }
    let c = children(n);
    match n.kind() {
        "command" | "test_command" => out.push((span(n), success)),
        "redirected_statement" => {
            if let Some(n) = c.iter().find(|n| n.kind() == "command") {
                implied(*n, success, source, depth - 1, out);
            }
        }
        // Consumers must distinguish an invocation's status from the status
        // of a negated compound before using a condition through `!`.
        "negated_command" => {}
        "list" if c.len() == 2 => {
            let op = source
                .get(c[0].end_byte()..c[1].start_byte())
                .unwrap_or_default();
            let op = std::str::from_utf8(op).unwrap_or("").trim();
            if (op == "&&" && success) || (op == "||" && !success) {
                for n in c {
                    implied(n, success, source, depth - 1, out);
                }
            }
        }
        _ => {}
    }
}
pub(crate) fn collect(root: Node<'_>, source: &[u8]) -> Vec<ShellStatusCondition> {
    // Truncation loses optional precision only. Never turn unproved syntax
    // into a successful-status condition, especially on a repaired partial tree.
    if root.has_error() || source.len() > 65536 {
        return Vec::new();
    }
    fn visit(n: Node<'_>, source: &[u8], depth: usize, out: &mut Vec<ShellStatusCondition>) {
        if depth == 0
            || out.len() >= 4096
            || matches!(
                n.kind(),
                "command_substitution" | "process_substitution" | "function_definition"
            )
        {
            return;
        }
        let c = children(n);
        let mut add = |producer, success, region: SourceSpan| {
            let mut commands = Vec::new();
            implied(producer, success, source, 32, &mut commands);
            for (command_span, success) in commands {
                if out.len() >= 4096 {
                    break;
                }
                out.push(ShellStatusCondition {
                    command_span,
                    success,
                    guarded_region: region.clone(),
                    shell_scope_span: frame(n),
                });
            }
        };
        if n.kind() == "list" && c.len() == 2 {
            let op = source
                .get(c[0].end_byte()..c[1].start_byte())
                .unwrap_or_default();
            match std::str::from_utf8(op).unwrap_or("").trim() {
                "&&" => add(c[0], true, span(c[1])),
                "||" => add(c[0], false, span(c[1])),
                _ => {}
            }
        }
        if matches!(n.kind(), "if_statement" | "elif_clause") {
            let mut cursor = n.walk();
            let all: Vec<_> = n.children(&mut cursor).collect();
            if let Some(then) = all.iter().find(|n| n.kind() == "then") {
                if let Some(condition) = c.iter().rev().find(|n| n.end_byte() <= then.start_byte())
                {
                    let boundary = all.iter().find(|n| {
                        matches!(n.kind(), "elif_clause" | "else_clause" | "fi")
                            && n.start_byte() >= then.end_byte()
                    });
                    if let Some(end) = boundary {
                        let mut region = span(*then);
                        region.start_byte = then.end_byte();
                        region.start_row = then.end_position().row;
                        region.start_column = then.end_position().column;
                        region.end_byte = end.start_byte();
                        region.end_row = end.start_position().row;
                        region.end_column = end.start_position().column;
                        add(*condition, true, region);
                        if end.kind() != "fi" {
                            let mut tail = span(*end);
                            tail.end_byte = n.end_byte();
                            tail.end_row = n.end_position().row;
                            tail.end_column = n.end_position().column;
                            add(*condition, false, tail);
                        }
                    }
                }
            }
        }
        for child in c {
            visit(child, source, depth - 1, out);
        }
    }
    let mut result = Vec::new();
    visit(root, source, 256, &mut result);
    result
}

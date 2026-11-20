//! One grammar entry for commands AND disposable word queries. The pinned
//! grammar treats some backslash-quoted whitespace as extras, omitting valid
//! shell word bytes. Qualify only escaped bytes absent from terminal spans;
//! parse a same-width escaped-literal stand-in and extract all facts from the
//! caller's original source. No projected text becomes argv or is executed.
use tree_sitter::{Node, Parser, Tree};

use crate::ParseError;

mod bare_dollar;

fn escaped_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\x0b' | b'\x0c' | b'\r')
}

pub(crate) fn parse(parser: &mut Parser, source: &[u8]) -> Result<Tree, ParseError> {
    let tree = parse_escaped_blanks(parser, source)?;
    bare_dollar::recover(parser, source, tree, false)
}

/// Backquote extraction normalizes greedy substitution extents before reading
/// any facts. Only that entry may accept a tree that still needs this step.
pub(crate) fn parse_for_backquotes(parser: &mut Parser, source: &[u8]) -> Result<Tree, ParseError> {
    let tree = parse_escaped_blanks(parser, source)?;
    bare_dollar::recover(parser, source, tree, true)
}

pub use bare_dollar::is_literal_dollar_follower;

fn parse_escaped_blanks(parser: &mut Parser, source: &[u8]) -> Result<Tree, ParseError> {
    let mut tree = parser
        .parse(source, None)
        .ok_or(ParseError::ParseCancelled)?;
    if !source
        .windows(2)
        .any(|p| p[0] == b'\\' && escaped_blank(p[1]))
    {
        return Ok(tree);
    }
    let mut edits = vec![false; source.len()];
    for _ in 0..8 {
        let covered = terminal_coverage(tree.root_node(), source.len());
        let opaque = heredoc_data(tree.root_node(), source);
        let mut next = edits.clone();
        // A newly exposed heredoc can reveal that a formerly visible word was
        // deferred input. Undo such stand-ins before accepting the new tree.
        for (index, selected) in next.iter_mut().enumerate() {
            if opaque[index] {
                *selected = false;
            }
        }
        let mut index = 0;
        while index + 1 < source.len() {
            if source[index] == b'\\' {
                if escaped_blank(source[index + 1])
                    && !covered[index + 1]
                    && !opaque[index]
                    && !opaque[index + 1]
                {
                    next[index + 1] = true;
                }
                // Pairing preserves escape parity. In particular, a quoted
                // backslash followed by a separator is not an escaped blank.
                index += 2;
            } else {
                index += 1;
            }
        }
        if next == edits {
            return Ok(tree);
        }
        edits = next;
        let mut view = source.to_vec();
        for (index, selected) in edits.iter().enumerate() {
            if *selected {
                view[index] = b'_';
            }
        }
        tree = parser
            .parse(&view, None)
            .ok_or(ParseError::ParseCancelled)?;
    }
    Err(ParseError::WordBoundaryLimit)
}

fn terminal_coverage(root: Node<'_>, length: usize) -> Vec<bool> {
    let mut covered = vec![false; length];
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.child_count() == 0 {
            if let Some(range) = covered.get_mut(node.start_byte()..node.end_byte()) {
                range.fill(true);
            }
        } else {
            stack.extend((0..node.child_count()).filter_map(|i| node.child(i as u32)));
        }
    }
    covered
}

/// Here-doc data is not ordinary shell argv, including when the scanner emits
/// body words as siblings of an empty heredoc_body. Only an AST-owned command
/// substitution under an expandable delimiter reopens an actual shell scope.
fn heredoc_data(root: Node<'_>, source: &[u8]) -> Vec<bool> {
    let bodies = heredoc_bodies(root, source);
    let bodies: std::collections::BTreeMap<_, _> =
        bodies.into_iter().map(|b| (b.node_start, b)).collect();
    let mut ranges = Vec::new();
    let mut stack = vec![(root, None, 0usize)];
    while let Some((node, context, depth)) = stack.pop() {
        let mut context = context;
        if context == Some(false) && node.kind() == "command_substitution" {
            ranges.push((node.start_byte(), node.end_byte(), depth, false));
            context = None;
        }
        let body = bodies.get(&node.start_byte());
        if let Some(body) = body {
            ranges.push((body.marker.start, body.marker.end, depth + 1, true));
            if let Some(end) = &body.end {
                ranges.push((end.start, end.end, depth + 1, true));
            }
            ranges.push((body.content.start, body.content.end, depth, true));
        }
        for child in (0..node.child_count())
            .rev()
            .filter_map(|i| node.child(i as u32))
        {
            let child_context = match body {
                Some(body)
                    if body.content.start <= child.start_byte()
                        && child.end_byte() <= body.content.end =>
                {
                    Some(body.quoted)
                }
                _ => context,
            };
            stack.push((child, child_context, depth + 1));
        }
    }
    let mut events = Vec::with_capacity(ranges.len() * 2);
    for (id, &(start, end, depth, opaque)) in ranges.iter().enumerate() {
        if start < end {
            events.push((start, true, depth, id, opaque));
            events.push((end, false, depth, id, opaque));
        }
    }
    events.sort_unstable();
    let mut mask = vec![false; source.len()];
    let mut active = std::collections::BTreeSet::new();
    let mut cursor = 0;
    for (position, add, depth, id, opaque) in events {
        if active.last().is_some_and(|&(_, _, opaque)| opaque) {
            mask[cursor..position].fill(true);
        }
        cursor = position;
        if add {
            active.insert((depth, id, opaque));
        } else {
            active.remove(&(depth, id, opaque));
        }
    }
    mask
}

/// Canonical deferred-input ranges, shared by parsing-view protection and fact
/// extraction. A previous delimiter ending after this header belongs to the
/// same deferred here-doc queue; nested substitutions have separate queues.
pub(crate) struct HeredocBody {
    pub node_start: usize,
    pub marker: std::ops::Range<usize>,
    pub end: Option<std::ops::Range<usize>>,
    pub content: std::ops::Range<usize>,
    pub quoted: bool,
}

pub(crate) fn heredoc_bodies(root: Node<'_>, source: &[u8]) -> Vec<HeredocBody> {
    // A header newline inside a quoted word or a child substitution cannot
    // start this owner's deferred input. Classify breaks by lexical scope,
    // rather than trusting terminal coverage (body words can swallow '\n').
    let mut scopes = Vec::new();
    let mut pending = Vec::new();
    let mut comment_ends = std::collections::BTreeSet::new();
    let mut stack = vec![(root, 0usize, 0usize)];
    while let Some((node, parent_scope, depth)) = stack.pop() {
        let shell = matches!(node.kind(), "command_substitution" | "process_substitution");
        let scope = if shell { node.id() } else { parent_scope };
        if shell {
            scopes.push((node.start_byte(), node.end_byte(), depth, Some(scope)));
        }
        if matches!(
            node.kind(),
            "string"
                | "raw_string"
                | "ansi_c_string"
                | "translated_string"
                | "heredoc_start"
                | "heredoc_body"
                | "heredoc_content"
        ) {
            scopes.push((node.start_byte(), node.end_byte(), depth, None));
        }
        if node.kind() == "comment" {
            comment_ends.insert(node.end_byte());
        }
        if node.kind() == "heredoc_redirect"
            || (node.is_error()
                && (0..node.child_count())
                    .filter_map(|i| node.child(i as u32))
                    .any(|n| n.kind() == "heredoc_start"))
        {
            pending.push((node, scope));
        }
        for child in (0..node.child_count())
            .rev()
            .filter_map(|i| node.child(i as u32))
        {
            stack.push((child, scope, depth + 1));
        }
    }
    let mut events = Vec::new();
    for (id, &(start, end, depth, scope)) in scopes.iter().enumerate() {
        if start < end {
            events.push((start, true, depth, id, scope));
            events.push((end, false, depth, id, scope));
        }
    }
    events.sort_unstable();
    let mut events = events.into_iter().peekable();
    let mut active = std::collections::BTreeSet::new();
    let mut breaks: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    let mut slashes = 0;
    for (index, &byte) in source.iter().enumerate() {
        while events.peek().is_some_and(|e| e.0 <= index) {
            let (_, add, depth, id, scope) = events.next().unwrap();
            if add {
                active.insert((depth, id, scope));
            } else {
                active.remove(&(depth, id, scope));
            }
        }
        if byte == b'\n' && (slashes % 2 == 0 || comment_ends.contains(&index)) {
            if let Some(scope) = active.last().map_or(Some(0), |&(_, _, scope)| scope) {
                breaks.entry(scope).or_default().push(index);
            }
        }
        slashes = if byte == b'\\' { slashes + 1 } else { 0 };
    }
    pending.sort_by_key(|(node, _)| node.start_byte());
    let mut bodies = Vec::new();
    let mut ends: std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>> =
        Default::default();
    for (node, scope) in pending {
        let children: Vec<_> = (0..node.child_count())
            .filter_map(|i| node.child(i as u32))
            .collect();
        let Some(start) = children.iter().find(|n| n.kind() == "heredoc_start") else {
            continue;
        };
        let end = children
            .iter()
            .find(|n| n.kind() == "heredoc_end" && !n.is_missing())
            .map(|n| {
                let raw = n.start_byte()..n.end_byte();
                let bytes = &source[raw.clone()];
                let leading = bytes.iter().take_while(|&&b| b == b'\n').count();
                let trailing = bytes.iter().rev().take_while(|&&b| b == b'\n').count();
                // The scanner sometimes includes surrounding linefeeds in
                // heredoc_end. They belong to body/statement boundaries, not
                // to the marker. Preserve every leading body linefeed.
                if leading + trailing < bytes.len()
                    && !bytes[leading..bytes.len() - trailing].contains(&b'\n')
                {
                    raw.start + leading..raw.end - trailing
                } else {
                    raw
                }
            });
        let mut last = end.as_ref().map_or(source.len(), |r| r.start);
        if end.is_some() && children.iter().any(|n| n.kind() == "<<-") {
            let line = source[..last]
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |i| i + 1);
            if source[line..last].iter().all(|&b| b == b'\t') {
                last = line;
            }
        }
        let Some(lines) = breaks.get(&scope) else {
            continue;
        };
        let Some(&line) = lines.get(lines.partition_point(|&index| index < start.end_byte()))
        else {
            continue;
        };
        if line >= last {
            continue;
        }
        let mut begin = line + 1;
        let previous = ends.entry(scope).or_default();
        if let Some(&prior) = previous.range(..=last).next_back() {
            if prior > node.start_byte() && source.get(prior) == Some(&b'\n') {
                begin = begin.max(prior + 1);
            }
        }
        if let Some(end) = &end {
            previous.insert(end.end);
        }
        if begin > last {
            continue;
        }
        bodies.push(HeredocBody {
            node_start: node.start_byte(),
            marker: start.start_byte()..start.end_byte(),
            end,
            content: begin..last,
            quoted: crate::parser::heredoc_start_is_quoted(*start, source),
        });
    }
    bodies
}

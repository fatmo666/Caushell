//! AST-qualified grammar compatibility, never shell evaluation. Project only
//! syntax that the pinned grammar cannot express; facts retain original bytes.
use tree_sitter::{Node, Parser, Tree};

use crate::ParseError;

pub(crate) fn project(
    parser: &mut Parser,
    mut tree: Tree,
    source: &[u8],
    mut projected: Option<Vec<u8>>,
) -> Result<(Tree, Option<Vec<u8>>), ParseError> {
    // The grammar's multiline command merge can report Complete. Check its
    // AST-qualified boundaries independently of the error flag. Both retries
    // and separator edits are bounded; residual gaps become Partial below.
    let mut boundary_budget = 256;
    let mut arithmetic_budget = 256;
    for _ in 0..8 {
        let bytes = projected.as_deref().unwrap_or(source);
        let mut edits: Vec<_> = crate::command_boundary::separators(tree.root_node(), bytes)
            .into_iter()
            .take(boundary_budget)
            .map(|index| (index, b';'))
            .collect();
        boundary_budget -= edits.len();
        if tree.root_node().has_error() {
            collect(tree.root_node(), bytes, &mut edits, &mut arithmetic_budget);
        }
        if edits.is_empty() {
            break;
        }
        let bytes = projected.get_or_insert_with(|| source.to_vec());
        for (index, replacement) in edits {
            bytes[index] = replacement;
        }
        tree = parser
            .parse(bytes.as_slice(), None)
            .ok_or(ParseError::ParseCancelled)?;
    }
    // Remaining grammar errors OR unprojected boundaries remain Partial in
    // normal artifact creation, retaining known effects and Deny evidence.
    Ok((tree, projected))
}

fn collect(node: Node<'_>, bytes: &[u8], edits: &mut Vec<(usize, u8)>, budget: &mut usize) {
    if !node.has_error() {
        return;
    }
    if node.kind() == "c_style_for_statement" {
        for field in ["initializer", "condition", "update"] {
            let mut cursor = node.walk();
            for expression in node.children_by_field_name(field, &mut cursor) {
                if expression.has_error()
                    && let Some(tokens) = arithmetic_projection(
                        expression.start_byte(),
                        expression.end_byte(),
                        bytes,
                        budget,
                    )
                {
                    edits.extend(tokens);
                }
            }
        }
    }
    if node.kind() == "expansion"
        && bytes.get(node.start_byte()..node.start_byte() + 2) == Some(b"${")
    {
        // The grammar accepts a bare arithmetic variable as a substring offset,
        // but not its equivalent $name spelling. Its missing close brace sits
        // immediately before that $. Remove ONLY the arithmetic variable's $
        // for parsing. Do not mask $(...), ${...}, quotes, or arbitrary payloads.
        if let Some(close) = (0..node.child_count())
            .filter_map(|i| node.child(i as u32))
            .find(|child| child.is_missing() && child.kind() == "}")
        {
            let mut index = close.start_byte();
            while bytes.get(index).is_some_and(|b| matches!(b, b' ' | b'\t')) {
                index += 1;
            }
            let has_slice_colon = (0..node.child_count())
                .filter_map(|i| node.child(i as u32))
                .any(|child| child.kind() == ":" && child.end_byte() <= index);
            if has_slice_colon
                && bytes.get(index) == Some(&b'$')
                && bytes
                    .get(index + 1)
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            {
                edits.push((index, b' '));
            }
        }
    }
    if node.is_error() {
        // A missing optional separator in `for name do ...` appears as the
        // direct ERROR child sequence for / variable_name, followed by do.
        // The do token may be owned by an outer recovered do_group. Replacing
        // the separating horizontal whitespace with ; preserves coordinates.
        let children: Vec<_> = (0..node.child_count())
            .filter_map(|i| node.child(i as u32))
            .collect();
        // With a ternary inside a function the grammar can recover the entire
        // function as ERROR. Only its own `for` and `((` tokens admit header
        // recovery; word/string/heredoc contents cannot introduce such tokens.
        for pair in children.windows(2) {
            if pair[0].kind() == "for"
                && pair[1].kind() == "(("
                && let Some(tokens) = recovered_for_header(pair[1].end_byte(), bytes, budget)
            {
                edits.extend(tokens);
            }
        }
        for pair in children.windows(2) {
            let [keyword, variable] = pair else {
                unreachable!()
            };
            if keyword.kind() != "for" || variable.kind() != "variable_name" {
                continue;
            }
            let mut do_start = variable.end_byte();
            while bytes
                .get(do_start)
                .is_some_and(|b| matches!(b, b' ' | b'\t'))
            {
                do_start += 1;
            }
            if do_start > variable.end_byte()
                && bytes.get(do_start..do_start + 2) == Some(b"do")
                && bytes
                    .get(do_start + 2)
                    .is_none_or(|b| matches!(b, b' ' | b'\t' | b'\n' | b';'))
            {
                edits.push((do_start - 1, b';'));
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect(child, bytes, edits, budget);
    }
}

/// The pinned C-style-for grammar lacks ternaries, although its independent
/// shell-arithmetic grammar recognizes them. Validate the whole original field
/// there before projecting only its ternary punctuation to same-width binary
/// operators. Facts and later arithmetic analysis still use original bytes;
/// strings, substitutions, branch payloads and source coordinates are retained.
fn arithmetic_projection(
    start: usize,
    end: usize,
    bytes: &[u8],
    budget: &mut usize,
) -> Option<Vec<(usize, u8)>> {
    *budget = budget.checked_sub(1)?;
    let original = bytes.get(start..end)?;
    if original.len() > 8192 {
        return None;
    }
    let mut source = b"(( ".to_vec();
    source.extend_from_slice(original);
    source.extend_from_slice(b" ))");
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(&source, None)?;
    let root = tree.root_node();
    if root.has_error()
        || root.named_child_count() != 1
        || root.named_child(0)?.kind() != "compound_statement"
    {
        return None;
    }
    let mut pending = vec![root];
    let mut edits = Vec::new();
    let mut node_budget = 512usize;
    while let Some(node) = pending.pop() {
        node_budget = node_budget.checked_sub(1)?;
        if node.kind() == "ternary_expression" {
            for i in 0..node.child_count() {
                let token = node.child(i as u32)?;
                if matches!(token.kind(), "?" | ":") {
                    let index = token.start_byte().checked_sub(3)?;
                    if index >= original.len() {
                        return None;
                    }
                    edits.push((start + index, b'+'));
                }
            }
        }
        // A nested substitution has its own shell grammar and control flow.
        // Only punctuation owned by this arithmetic field is projected here.
        if node.kind() != "command_substitution" {
            pending
                .extend((0..node.named_child_count()).filter_map(|i| node.named_child(i as u32)));
        }
    }
    Some(edits)
}

fn recovered_for_header(
    start: usize,
    bytes: &[u8],
    budget: &mut usize,
) -> Option<Vec<(usize, u8)>> {
    // Delimiter candidates are validated by the independent arithmetic grammar.
    // A semicolon or close pair inside a string/substitution cannot truncate a
    // complete arithmetic field. No submitted text is evaluated or removed.
    let end = start.saturating_add(8192).min(bytes.len());
    let mut field_start = start;
    let mut edits = Vec::new();
    for field in 0..3 {
        let delimiter = if field < 2 {
            b";".as_slice()
        } else {
            b"))".as_slice()
        };
        let mut selected = None;
        for at in field_start..end {
            if bytes.get(at..at + delimiter.len()) != Some(delimiter) {
                continue;
            }
            if let Some(tokens) = arithmetic_projection(field_start, at, bytes, budget) {
                selected = Some((at + delimiter.len(), tokens));
                break;
            }
            if *budget == 0 {
                return None;
            }
        }
        let (next, tokens) = selected?;
        field_start = next;
        edits.extend(tokens);
    }
    (!edits.is_empty()).then_some(edits)
}

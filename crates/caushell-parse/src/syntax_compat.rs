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
    // Ordinary complete inputs pay only this root flag check. A fixed retry
    // budget also keeps adversarial malformed input from driving reparsing.
    for _ in 0..8 {
        if !tree.root_node().has_error() {
            break;
        }
        let bytes = projected.as_deref().unwrap_or(source);
        let mut edits = Vec::new();
        collect(tree.root_node(), bytes, &mut edits);
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
    // Any remaining grammar error remains Partial in normal artifact creation.
    Ok((tree, projected))
}

fn collect(node: Node<'_>, bytes: &[u8], edits: &mut Vec<(usize, u8)>) {
    if !node.has_error() {
        return;
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
        collect(child, bytes, edits);
    }
}

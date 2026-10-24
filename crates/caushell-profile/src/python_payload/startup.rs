use super::*;

/// Startup programs which do nothing when each listed import is absent.
/// Import absence must be independently proved with the initial importers.
pub fn python_startup_missing_imports(source: &str) -> Result<Vec<String>> {
    if source.len() > SOURCE_LIMIT || !python_source_encoding_supported(source) {
        return Err("unsupported Python startup source".into());
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|_| "Python parser unavailable")?;
    let tree = parser
        .parse(source, None)
        .ok_or("Python startup parse failed")?;
    let root = tree.root_node();
    if root.has_error() {
        return Err("invalid Python startup source".into());
    }
    fn noop(source: &str, node: Node<'_>) -> bool {
        match node.kind() {
            "comment" | "pass_statement" => true,
            "expression_statement" => {
                let children = named(node);
                children.len() == 1
                    && children[0].kind() == "string"
                    && decode_string(&source[children[0].byte_range()]).is_ok()
            }
            _ => false,
        }
    }
    let mut missing = Vec::new();
    for statement in named(root) {
        if noop(source, statement) {
            continue;
        }
        if statement.kind() != "try_statement" {
            return Err("unmodeled Python startup action".into());
        }
        let children = named(statement);
        let body = field(statement, "body")?;
        let actions = named(body)
            .into_iter()
            .filter(|n| n.kind() != "comment")
            .collect::<Vec<_>>();
        let [action] = actions.as_slice() else {
            return Err("unsupported Python startup try body".into());
        };
        if action.kind() != "import_statement" {
            return Err("unsupported Python startup import".into());
        }
        let imported = named(*action);
        let [module] = imported.as_slice() else {
            return Err("unsupported Python startup import list".into());
        };
        let name = &source[module.byte_range()];
        if module.kind() != "dotted_name" || !crate::shell_identifier(name) {
            return Err("unsupported Python startup import name".into());
        }
        let mut handlers = 0;
        for clause in children.into_iter().filter(|n| n.id() != body.id()) {
            match clause.kind() {
                "except_clause" => {
                    handlers += 1;
                    let items = named(clause);
                    if items.len() != 2
                        || !matches!(
                            &source[items[0].byte_range()],
                            "ImportError" | "ModuleNotFoundError"
                        )
                        || items[0].kind() != "identifier"
                        || items[1].kind() != "block"
                        || !named(items[1]).into_iter().all(|n| noop(source, n))
                    {
                        return Err("unmodeled Python startup exception handler".into());
                    }
                }
                "else_clause" => {}
                _ => return Err("unsupported Python startup try clause".into()),
            }
        }
        if handlers != 1 || missing.len() >= 32 {
            return Err("Python startup handler budget/shape exceeded".into());
        }
        missing.push(name.into());
    }
    Ok(missing)
}

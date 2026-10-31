//! The Bash grammar can attach a trailing simple-command redirect to an
//! entire &&/|| list, and then put that list on the left of a pipeline.
//! Recover execution topology using an AST-qualified, redirect-elided parse.
//! Original argv, redirects, substitutions and source bytes remain authoritative.
use super::*;

struct Site {
    span: SourceSpan,
    owner: Option<SourceSpan>,
    redirects: Vec<SourceSpan>,
}

fn tail_command(mut node: Node<'_>) -> Option<SourceSpan> {
    for _ in 0..128 {
        match node.kind() {
            "command" | "test_command" => return Some(span_for(node)),
            "list" => {
                node = named_children_of_kind(node, None)
                    .into_iter()
                    .rfind(|n| n.kind() != "comment")?
            }
            // Explicit groups and deferred function bodies are not the last
            // simple command of the enclosing list.
            _ => return None,
        }
    }
    None
}

pub(super) fn restore(artifact: &mut ParsedCommandArtifact, root: Node<'_>, source: &[u8]) {
    let mut sites = Vec::new();
    walk(root, &mut |node| {
        if node.kind() == "redirected_statement"
            && node
                .child_by_field_name("body")
                .is_some_and(|body| body.kind() == "list")
        {
            sites.push(Site {
                span: span_for(node),
                owner: node.child_by_field_name("body").and_then(tail_command),
                redirects: named_children_of_kind(node, None)
                    .into_iter()
                    .filter(|n| {
                        matches!(
                            n.kind(),
                            "file_redirect" | "heredoc_redirect" | "herestring_redirect"
                        )
                    })
                    .map(span_for)
                    .collect(),
            });
        }
    });
    if sites.is_empty() {
        return;
    }
    // No partial reparse may erase known effects. Failure retains all original
    // facts and marks the whole analysis incomplete, independent of policy.
    if !try_restore(artifact, &sites, source) {
        artifact.status = ParseStatus::Partial;
        artifact.diagnostics.push(ParseDiagnostic {
            kind: DiagnosticKind::ErrorNode,
            node_kind: "unresolved_redirect_list_precedence".into(),
            text: "redirect/list execution topology could not be proved".into(),
            span: sites[0].span.clone(),
        });
    }
}

fn try_restore(artifact: &mut ParsedCommandArtifact, sites: &[Site], source: &[u8]) -> bool {
    if source.len() > 65_536 || sites.len() > 128 || artifact.status != ParseStatus::Complete {
        return false;
    }
    let mut projected = source.to_vec();
    let mut owners = Vec::new();
    for (index, redirect) in artifact.redirections.iter().enumerate() {
        let Some(site) = sites.iter().find(|site| {
            site.redirects.iter().any(|span| {
                span.start_byte == redirect.span.start_byte
                    && redirect.span.end_byte <= span.end_byte
            })
        }) else {
            continue;
        };
        if redirect.kind != RedirectionKind::File {
            return false;
        }
        let Some(owner) = artifact
            .commands
            .iter()
            .position(|c| Some(&c.span) == site.owner.as_ref())
        else {
            return false;
        };
        owners.push((index, owner));
        for byte in &mut projected[redirect.span.start_byte..redirect.span.end_byte] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    if owners.is_empty() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&projected) else {
        return false;
    };
    let mut parser = Parser::new();
    let Ok(language) = language_for(artifact.shell_kind) else {
        return false;
    };
    if parser.set_language(&language).is_err() {
        return false;
    }
    let Ok(tree) = parse_with_descriptor_ownership(&mut parser, text, &[]) else {
        return false;
    };
    let root = tree.tree.root_node();
    if root.has_error() {
        return false;
    }
    let commands = extract_commands(root, &projected);
    // A topology projection must be bijective and preserve every original argv
    // word. Redirect operands, including substitutions, are never new argv.
    if commands.len() != artifact.commands.len() {
        return false;
    }
    let mut repaired = artifact.clone();
    for command in &mut repaired.commands {
        let Some(topology) = commands.iter().find(|candidate| {
            candidate.span.start_byte == command.span.start_byte
                && candidate.command_name == command.command_name
                && candidate.tokens == command.tokens
                && candidate.prefix_assignments == command.prefix_assignments
        }) else {
            return false;
        };
        command.in_pipeline = topology.in_pipeline;
        command.pipeline_position = topology.pipeline_position;
        command.pipeline_span = topology.pipeline_span.clone();
        command.terminator = topology.terminator;
        command.guarded = topology.guarded;
        command.conditional_execution = topology.conditional_execution;
        command.shell_scope_span = topology.shell_scope_span.clone();
        command.subshell_span = topology.subshell_span.clone();
        command.control_flow_span = topology.control_flow_span.clone();
        command.top_level_span = topology.top_level_span.clone();
    }
    // Other shell-state producers must see the same corrected execution scope.
    macro_rules! scopes {
        ($field:ident, $extract:ident) => {{
            let projected = $extract(root, &projected);
            if projected.len() != repaired.$field.len() {
                return false;
            }
            for fact in &mut repaired.$field {
                let Some(other) = projected
                    .iter()
                    .find(|p| p.span.start_byte == fact.span.start_byte)
                else {
                    return false;
                };
                fact.top_level_span = other.top_level_span.clone();
                fact.shell_scope_span = other.shell_scope_span.clone();
                fact.conditional_execution = other.conditional_execution;
                fact.unconditional_current_shell = other.unconditional_current_shell;
            }
        }};
    }
    scopes!(assignment_commands, extract_assignment_commands);
    scopes!(declaration_commands, extract_declaration_commands);
    scopes!(unset_commands, extract_unset_commands);
    repaired.status_conditions = crate::status_conditions::collect(root, &projected);
    let evaluations = extract_shell_evaluations(root, &projected, artifact.shell_kind);
    for site in &mut repaired.shell_evaluations {
        if let Some(other) = evaluations
            .iter()
            .find(|p| p.input.span.start_byte == site.input.span.start_byte)
        {
            site.top_level_span = other.top_level_span.clone();
            site.shell_scope_span = other.shell_scope_span.clone();
            site.conditional_execution = other.conditional_execution;
        } else if let Some((_, owner)) = owners.iter().find(|(index, _)| {
            let span = &artifact.redirections[*index].span;
            span.start_byte <= site.input.span.start_byte
                && site.input.span.end_byte <= span.end_byte
        }) {
            let command = &repaired.commands[*owner];
            site.top_level_span = command.top_level_span.clone();
            site.shell_scope_span = command.shell_scope_span.clone();
            site.conditional_execution = command.conditional_execution;
        } else {
            return false;
        }
    }
    for (index, owner) in owners {
        let command = &repaired.commands[owner];
        let redirect = &mut repaired.redirections[index];
        redirect.parent_command_name = command.command_name.clone();
        redirect.parent_command_span = Some(command.span.clone());
        redirect.shell_scope_span = command.shell_scope_span.clone();
        redirect.conditional_execution = command.conditional_execution;
        redirect.top_level_span = command.top_level_span.clone();
        redirect.opening_statement = None;
    }
    *artifact = repaired;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_list_precedence_preserves_words_owners_and_success_conditions() {
        for redirect in ["2>&1", "> result", "2>err", ">out 2>&1"] {
            for connector in ["&&", "||"] {
                let source =
                    format!("cd /elsewhere {connector} ./tool 'a|b' {redirect} | cat; printf end");
                let parsed = parse_command(&source, ShellKind::Bash).unwrap();
                assert_eq!(
                    parsed.status,
                    ParseStatus::Complete,
                    "{source}: {:?}",
                    parsed.diagnostics
                );
                assert_eq!(parsed.commands.len(), 4);
                let [cd, tool, cat, after] = parsed.commands.as_slice() else {
                    unreachable!()
                };
                assert!(!cd.in_pipeline, "{source}");
                assert!(tool.in_pipeline && cat.in_pipeline);
                assert_eq!(tool.top_level_span, cat.top_level_span);
                assert_ne!(cd.top_level_span, tool.top_level_span);
                assert!(!after.in_pipeline);
                assert_eq!(tool.tokens[0].text, "a|b");
                for redir in &parsed.redirections {
                    assert_eq!(redir.parent_command_span.as_ref(), Some(&tool.span));
                    assert_eq!(redir.shell_scope_span, tool.shell_scope_span);
                    assert_eq!(
                        &source[redir.span.start_byte..redir.span.end_byte],
                        redir.text
                    );
                }
                assert!(
                    parsed
                        .status_conditions
                        .iter()
                        .any(|c| c.command_span == cd.span && c.success == (connector == "&&"))
                );
            }
        }
    }

    #[test]
    fn explicit_groups_and_quoted_syntax_keep_their_original_owners() {
        for source in [
            "{ cd /elsewhere && ./tool; } 2>&1 | cat",
            "(cd /elsewhere && ./tool) 2>&1 | cat",
            "printf '%s' 'cd /elsewhere && ./tool 2>&1 | cat'",
        ] {
            let parsed = parse_command(source, ShellKind::Bash).unwrap();
            assert_eq!(
                parsed.status,
                ParseStatus::Complete,
                "{source}: {:?}",
                parsed.diagnostics
            );
            assert!(
                parsed
                    .redirections
                    .iter()
                    .all(|r| r.parent_command_span.is_none())
            );
        }
    }

    #[test]
    fn unsupported_reassociation_keeps_original_facts_and_partial_status() {
        let source = "true && value=x >out | cat";
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial);
        assert!(
            parsed
                .commands
                .iter()
                .any(|c| c.command_name.as_deref() == Some("true"))
        );
        assert!(!parsed.redirections.is_empty());
    }
}

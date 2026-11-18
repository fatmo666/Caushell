//! The Bash grammar can attach a trailing simple-command redirect to an
//! entire &&/|| list or pipeline, instead of its final stage.
//! Recover execution topology using an AST-qualified, redirect-elided parse.
//! Original argv, redirects, substitutions and source bytes remain authoritative.
use super::*;

struct Site {
    span: SourceSpan,
    owner: Option<(SourceSpan, bool)>,
    redirects: Vec<SourceSpan>,
}

fn tail_command(mut node: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..128 {
        match node.kind() {
            "command" | "test_command" | "subshell" | "compound_statement" => {
                return Some(node);
            }
            "list" | "pipeline" => {
                node = named_children_of_kind(node, None)
                    .into_iter()
                    .rfind(|n| n.kind() != "comment")?
            }
            // Deferred functions and other unsupported statements do not
            // acquire the authority of an enclosing execution scope.
            _ => return None,
        }
    }
    None
}

/// A grammar-owned redirect of a list or pipeline applies to its rightmost
/// command. Follow only the list/pipeline chain; a compound shell scope
/// never transfers its redirect operands into an inner command's argv.
pub(super) fn trailing_redirect_scope(command: Node<'_>) -> Option<Node<'_>> {
    let mut body = command.parent()?;
    for _ in 0..128 {
        if !matches!(body.kind(), "list" | "pipeline") {
            return None;
        }
        let parent = body.parent()?;
        if parent.kind() == "redirected_statement" {
            return (parent.child_by_field_name("body") == Some(body)
                && tail_command(body) == Some(command))
            .then_some(parent);
        }
        body = parent;
    }
    None
}

pub(super) fn restore(
    artifact: &mut ParsedCommandArtifact,
    root: Node<'_>,
    source: &[u8],
    heredocs: &[heredoc_pipeline::Projection],
) {
    let mut sites = Vec::new();
    walk(root, &mut |node| {
        if node.kind() == "redirected_statement"
            && node
                .child_by_field_name("body")
                .is_some_and(|body| matches!(body.kind(), "list" | "pipeline"))
        {
            sites.push(Site {
                span: span_for(node),
                owner: node
                    .child_by_field_name("body")
                    .and_then(tail_command)
                    .map(|owner| {
                        let span = if owner.kind() == "command" {
                            simple_command_span(owner, &simple_command_words(owner, source))
                        } else {
                            span_for(owner)
                        };
                        (span, matches!(owner.kind(), "command" | "test_command"))
                    }),
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
    if !try_restore(artifact, &sites, source, heredocs) {
        artifact.status = ParseStatus::Partial;
        artifact.diagnostics.push(ParseDiagnostic {
            kind: DiagnosticKind::ErrorNode,
            node_kind: "unresolved_redirect_list_precedence".into(),
            text: "redirect/list execution topology could not be proved".into(),
            span: sites[0].span.clone(),
        });
    }
}

fn try_restore(
    artifact: &mut ParsedCommandArtifact,
    sites: &[Site],
    source: &[u8],
    heredocs: &[heredoc_pipeline::Projection],
) -> bool {
    if source.len() > 65_536 || sites.len() > 128 || artifact.status != ParseStatus::Complete {
        return false;
    }
    let mut projected = source.to_vec();
    let mut owners = Vec::new();
    for (index, redirect) in artifact.redirections.iter().enumerate() {
        let Some(site) = sites.iter().find(|site| {
            site.redirects.iter().any(|span| {
                span.start_byte == redirect.span.start_byte
                    && (redirect.span.end_byte <= span.end_byte
                        || heredocs.iter().any(|h| h.fact.span == redirect.span))
            })
        }) else {
            continue;
        };
        if !matches!(
            redirect.kind,
            RedirectionKind::File | RedirectionKind::HereDoc | RedirectionKind::HereString
        ) {
            return false;
        }
        let Some((span, simple)) = site.owner.as_ref() else {
            return false;
        };
        if *simple && !artifact.commands.iter().any(|c| &c.span == span) {
            return false;
        }
        owners.push((index, span.clone(), *simple));
        // The grammar-qualified carrier includes its body and delimiter.
        // Mask that whole span in the topology-only view, preserving line
        // positions. The original payload/substitution facts stay intact.
        let ranges = heredocs
            .iter()
            .find(|h| h.fact.span == redirect.span)
            .map(|h| h.ranges.clone())
            .unwrap_or_else(|| vec![redirect.span.start_byte..redirect.span.end_byte]);
        for range in ranges {
            for byte in &mut projected[range] {
                if !matches!(*byte, b'\n' | b'\r') {
                    *byte = b' ';
                }
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
    let mut owner_facts = Vec::new();
    for (index, span, simple) in owners {
        let fact = if simple {
            repaired.commands.iter().find(|c| c.span == span).cloned()
        } else {
            let mut fact = None;
            walk(root, &mut |node| {
                if matches!(node.kind(), "subshell" | "compound_statement")
                    && span_for(node) == span
                {
                    fact = Some(opening_statement_for_owner(node, source));
                }
            });
            fact
        };
        let Some(fact) = fact else { return false };
        owner_facts.push((index, fact, simple));
    }
    let evaluations = extract_shell_evaluations(root, &projected, artifact.shell_kind);
    for site in &mut repaired.shell_evaluations {
        if let Some(other) = evaluations
            .iter()
            .find(|p| p.input.span.start_byte == site.input.span.start_byte)
        {
            site.top_level_span = other.top_level_span.clone();
            site.shell_scope_span = other.shell_scope_span.clone();
            site.conditional_execution = other.conditional_execution;
        } else if let Some((_, command, _)) = owner_facts.iter().find(|(index, _, _)| {
            let span = &artifact.redirections[*index].span;
            span.start_byte <= site.input.span.start_byte
                && site.input.span.end_byte <= span.end_byte
        }) {
            site.top_level_span = command.top_level_span.clone();
            site.shell_scope_span = command.shell_scope_span.clone();
            site.conditional_execution = command.conditional_execution;
        } else {
            return false;
        }
    }
    for (index, command, simple) in owner_facts {
        let redirect = &mut repaired.redirections[index];
        redirect.parent_command_name = command.command_name.clone();
        redirect.parent_command_span = simple.then(|| command.span.clone());
        redirect.shell_scope_span = command.shell_scope_span.clone();
        redirect.conditional_execution = command.conditional_execution;
        redirect.top_level_span = command.top_level_span.clone();
        redirect.opening_statement = (!simple).then_some(command);
    }
    *artifact = repaired;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_redirect_operands_and_argv_share_the_same_pipeline_owner() {
        let source = "printf input | cat > 'output file' -- 'input file'";
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{:?}",
            parsed.diagnostics
        );
        let [producer, consumer] = parsed.commands.as_slice() else {
            panic!("expected two pipeline stages");
        };
        assert_eq!(producer.tokens.len(), 1);
        assert_eq!(producer.pipeline_span, consumer.pipeline_span);
        assert_eq!(consumer.text, "cat > 'output file' -- 'input file'");
        assert_eq!(consumer.tokens.len(), 2);
        assert_eq!(consumer.tokens[0].kind, CommandTokenKind::DashDash);
        assert_eq!(consumer.tokens[1].text, "input file");
        let [redirect] = parsed.redirections.as_slice() else {
            panic!("expected a single redirect");
        };
        assert_eq!(redirect.target.as_ref().unwrap().text, "output file");
        assert_eq!(redirect.parent_command_span.as_ref(), Some(&consumer.span));
        assert!(redirect.span.end_byte <= consumer.tokens[0].span.start_byte);
    }

    #[test]
    fn trailing_redirect_preserves_second_stage_substitutions_and_redirect_order() {
        let source = "printf input | cat >out $(printf item) 2>err other";
        let parsed = parse_command(source, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{:?}",
            parsed.diagnostics
        );
        let consumer = &parsed.commands[1];
        assert_eq!(consumer.tokens.len(), 2);
        assert_eq!(
            consumer.tokens[0].command_substitutions[0].body_text,
            "printf item"
        );
        assert_eq!(consumer.tokens[1].text, "other");
        assert_eq!(parsed.redirections.len(), 2);
        for (redirect, target) in parsed.redirections.iter().zip(["out", "err"]) {
            assert_eq!(redirect.target.as_ref().unwrap().text, target);
            assert_eq!(redirect.parent_command_span.as_ref(), Some(&consumer.span));
        }
    }

    #[test]
    fn trailing_pipeline_redirects_belong_to_the_last_stage_without_reordering() {
        for source in [
            "printf x | cat 2>&1 >/dev/null | cat",
            "printf x | cat >/dev/null 2>&1 | cat",
            "printf x | cat >out",
            "printf x | (cat; printf y) 2>err | cat",
        ] {
            let parsed = parse_command(source, ShellKind::Bash).unwrap();
            assert_eq!(
                parsed.status,
                ParseStatus::Complete,
                "{source}: {:?}",
                parsed.diagnostics
            );
            for redir in &parsed.redirections {
                if source.contains("(cat;") {
                    let opening = redir.opening_statement.as_ref().unwrap();
                    assert_eq!(
                        &source[opening.span.start_byte..opening.span.end_byte],
                        "(cat; printf y)"
                    );
                } else {
                    assert_eq!(redir.parent_command_name.as_deref(), Some("cat"));
                    assert_eq!(
                        redir.parent_command_span.as_ref(),
                        Some(&parsed.commands[1].span)
                    );
                    assert!(redir.opening_statement.is_none());
                }
            }
            assert!(
                parsed
                    .redirections
                    .windows(2)
                    .all(|w| w[0].span.start_byte < w[1].span.start_byte)
            );
        }
    }
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
    fn heredoc_and_here_string_payloads_keep_original_bytes_and_conditional_owner() {
        for connector in ["&&", "||"] {
            for carrier in [
                "<<'EOF'\nrm -rf /\nEOF",
                "<<EOF\n$(printf x)\nEOF",
                "<<< 'literal > text'",
            ] {
                let source = format!("true {connector} cat {carrier}");
                let parsed = parse_command(&source, ShellKind::Bash).unwrap();
                assert_eq!(
                    parsed.status,
                    ParseStatus::Complete,
                    "{source}: {:?}",
                    parsed.diagnostics
                );
                assert_eq!(parsed.commands.len(), 2);
                let owner = &parsed.commands[1];
                assert_eq!(owner.command_name.as_deref(), Some("cat"));
                assert!(owner.conditional_execution);
                for redir in &parsed.redirections {
                    assert_eq!(redir.parent_command_span.as_ref(), Some(&owner.span));
                    assert_eq!(
                        &source[redir.span.start_byte..redir.span.end_byte],
                        redir.text
                    );
                    assert!(redir.conditional_execution);
                    assert!(redir.content.is_some());
                }
            }
        }
        let malformed =
            parse_command("true && cat <<'EOF'\nunterminated", ShellKind::Bash).unwrap();
        assert_eq!(malformed.status, ParseStatus::Partial);
    }

    #[test]
    fn redirected_tail_group_uses_its_opening_scope_not_the_inner_last_command() {
        for group in ["(cd /elsewhere; printf x)", "{ cd /elsewhere; printf x; }"] {
            let source = format!("true && {group} > result | cat");
            let parsed = parse_command(&source, ShellKind::Bash).unwrap();
            assert_eq!(
                parsed.status,
                ParseStatus::Complete,
                "{source}: {:?}",
                parsed.diagnostics
            );
            let redirect = &parsed.redirections[0];
            assert!(redirect.parent_command_span.is_none());
            let opening = redirect.opening_statement.as_ref().unwrap();
            assert!(opening.command_name.is_none());
            assert!(opening.guarded);
            // The outer && decides whether the pipeline starts; inside the
            // pipeline's own shell, opening this stage is unconditional.
            assert!(!opening.conditional_execution);
            assert!(opening.in_pipeline);
            assert_eq!(
                &source[opening.span.start_byte..opening.span.end_byte],
                group
            );
        }
    }

    #[test]
    fn redirect_after_a_conditional_pipeline_belongs_only_to_its_tail() {
        for source in [
            "cd /tmp && printf x | sort | cat >out",
            "true && printf x | cat <<'EOF'\nhello\nEOF",
        ] {
            let parsed = parse_command(source, ShellKind::Bash).unwrap();
            assert_eq!(
                parsed.status,
                ParseStatus::Complete,
                "{:?}",
                parsed.diagnostics
            );
            assert!(
                parsed
                    .redirections
                    .iter()
                    .all(|r| r.parent_command_name.as_deref() == Some("cat"))
            );
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

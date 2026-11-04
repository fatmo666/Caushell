//! Correct only AST-owned heredoc headers whose pipeline separator was parsed
//! as an erroneous redirect operand. Original bodies never become shell argv.
use super::*;

pub(super) struct Projection {
    pub fact: RedirectionFact,
    pub ranges: Vec<std::ops::Range<usize>>,
    evaluations: Vec<crate::ShellEvaluationSite>,
}

pub(super) fn project(root: Node<'_>, source: &[u8]) -> Option<(Vec<u8>, Vec<Projection>)> {
    if !root.has_error() || source.len() > 65_536 {
        return None;
    }
    let diagnostics = collect_diagnostics(root, source);
    if diagnostics.is_empty()
        || diagnostics
            .iter()
            .any(|d| d.node_kind != "ERROR" || d.text != "|")
    {
        return None;
    }
    let evaluations = extract_shell_evaluations(root, source, ShellKind::Bash);
    let mut projections = Vec::new();
    walk(root, &mut |node| {
        if node.kind() != "heredoc_redirect" || !node.has_error() {
            return;
        }
        let children = all_children(node);
        let Some(start) = children.iter().find(|n| n.kind() == "heredoc_start") else {
            return;
        };
        let Some(body) = children.iter().find(|n| n.kind() == "heredoc_body") else {
            return;
        };
        if !children
            .iter()
            .any(|n| n.kind() == "heredoc_end" && !n.is_missing())
        {
            return;
        }
        // A filename stand-in must not introduce expansion of the delimiter.
        // Complex native delimiters stay conservative rather than being guessed.
        let marker = source_text(*start, source);
        let marker = if marker.starts_with('\'') {
            let Some(value) = marker.strip_prefix('\'').and_then(|m| m.strip_suffix('\'')) else {
                return;
            };
            value
        } else if marker.starts_with('"') {
            let Some(value) = marker.strip_prefix('"').and_then(|m| m.strip_suffix('"')) else {
                return;
            };
            value
        } else {
            marker.as_str()
        };
        if marker.is_empty()
            || !marker
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return;
        }
        let fact = parse_heredoc(node, source);
        if !matches!(fact.operator.as_deref(), Some("<<" | "<<-")) {
            return;
        }
        let ranges = vec![
            node.start_byte()..start.end_byte(),
            body.start_byte()..node.end_byte(),
        ];
        if !diagnostics
            .iter()
            .any(|d| start.end_byte() <= d.span.start_byte && d.span.end_byte <= body.start_byte())
        {
            return;
        }
        let body_evaluations = if fact.heredoc_start.as_ref().is_some_and(|s| s.quoted) {
            Vec::new()
        } else {
            evaluations
                .iter()
                .filter(|e| {
                    body.start_byte() <= e.input.span.start_byte
                        && e.input.span.end_byte <= body.end_byte()
                })
                .cloned()
                .collect()
        };
        projections.push(Projection {
            fact,
            ranges,
            evaluations: body_evaluations,
        });
    });
    if projections.is_empty() || projections.len() > 16 {
        return None;
    }
    if !diagnostics.iter().all(|d| {
        projections
            .iter()
            .any(|p| p.ranges[0].end <= d.span.start_byte && d.span.end_byte <= p.ranges[1].start)
    }) {
        return None;
    }
    let mut projected = source.to_vec();
    for p in &projections {
        let operator = p.fact.span.start_byte;
        if source.get(operator..operator + 2) != Some(b"<<") {
            return None;
        }
        projected[operator + 1] = b' ';
        if p.fact.operator.as_deref() == Some("<<-") {
            projected[operator + 2] = b' ';
        }
        for byte in &mut projected[p.ranges[1].clone()] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    Some((projected, projections))
}

pub(super) fn restore(artifact: &mut ParsedCommandArtifact, projections: &[Projection]) {
    for p in projections {
        let Some(redir) = artifact.redirections.iter_mut().find(|r| {
            r.kind == RedirectionKind::File && r.span.start_byte == p.fact.span.start_byte
        }) else {
            artifact.status = ParseStatus::Partial;
            artifact.diagnostics.push(ParseDiagnostic {
                kind: DiagnosticKind::ErrorNode,
                node_kind: "unrestored_heredoc_header".into(),
                text: "heredoc ownership could not be restored".into(),
                span: p.fact.span.clone(),
            });
            continue;
        };
        let mut original = p.fact.clone();
        original.file_descriptor = redir.file_descriptor.clone().or(original.file_descriptor);
        original.parent_command_name = redir.parent_command_name.clone();
        original.parent_command_span = redir.parent_command_span.clone();
        original.top_level_span = redir.top_level_span.clone();
        original.shell_scope_span = redir.shell_scope_span.clone();
        original.conditional_execution = redir.conditional_execution;
        original.opening_statement = redir.opening_statement.clone();
        *redir = original;
    }
}

pub(super) fn restore_evaluations(
    artifact: &mut ParsedCommandArtifact,
    projections: &[Projection],
) {
    for p in projections {
        // Lexical top-level/pipeline carriers must include their deferred
        // heredoc bytes. Otherwise projecting a child unit would manufacture
        // an unterminated header and drop its authoritative stdin carrier.
        if let Some(old) = artifact
            .redirections
            .iter()
            .find(|r| r.kind == RedirectionKind::HereDoc && r.span == p.fact.span)
            .map(|r| r.top_level_span.clone())
        {
            let expanded = source_span_for_offsets(
                &artifact.raw_command,
                old.start_byte,
                old.end_byte.max(p.fact.span.end_byte),
            );
            for c in &mut artifact.commands {
                if c.top_level_span == old {
                    c.top_level_span = expanded.clone();
                }
                if c.pipeline_span.as_ref() == Some(&old) {
                    c.pipeline_span = Some(expanded.clone());
                }
            }
            for r in &mut artifact.redirections {
                if r.top_level_span == old {
                    r.top_level_span = expanded.clone();
                }
                if let Some(c) = &mut r.opening_statement {
                    if c.top_level_span == old {
                        c.top_level_span = expanded.clone();
                    }
                    if c.pipeline_span.as_ref() == Some(&old) {
                        c.pipeline_span = Some(expanded.clone());
                    }
                }
            }
            for e in &mut artifact.shell_evaluations {
                if e.top_level_span == old {
                    e.top_level_span = expanded.clone();
                }
            }
            for e in &mut artifact.status_conditions {
                if e.guarded_region == old {
                    e.guarded_region = expanded.clone();
                }
            }
        }
        let Some(redir) = artifact
            .redirections
            .iter()
            .find(|r| r.kind == RedirectionKind::HereDoc && r.span == p.fact.span)
        else {
            continue;
        };
        for original in &p.evaluations {
            let mut site = original.clone();
            site.top_level_span = redir.top_level_span.clone();
            site.shell_scope_span = redir.shell_scope_span.clone();
            site.conditional_execution = redir.conditional_execution;
            artifact.shell_evaluations.push(site);
        }
    }
}

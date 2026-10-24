use super::*;

/// A single quoted substitution is one argv field. Its source AST remains
/// available for child analysis and provenance; output bytes are never parsed.
pub(in crate::passes::resolve_invocation) fn materialize_outputs(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    max_depth: u8,
    ctx: &mut RunnerContext,
) {
    let outcome = output_field(registry, session, request, entry, context, max_depth);
    if let Some((command, proof)) = outcome {
        entry.result = resolve_invocation_artifact_with_bindings(
            registry,
            &command,
            runtime_context_for_parsed_command(
                &entry.parsed_scope,
                entry.command_ref.command_index,
                &command,
            ),
            &entry.bindings,
        );
        ctx.add_evidence(Evidence {
            rule_id: caushell_types::RuleId::NestedPayloadExpansion,
            summary: "Python stdout materialized as argv data".into(),
            kind: EvidenceKind::PythonStdoutField(proof),
        });
    }
}

fn output_field(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    max_depth: u8,
) -> Option<(
    caushell_parse::CommandFact,
    caushell_types::PythonStdoutFieldEvidence,
)> {
    if entry.depth.saturating_add(2) > max_depth
        || entry.inherited_scope.static_input_cwd_unproven
        || entry.bindings.shell_state_uncertainty().is_some()
    {
        return None;
    }
    let original = entry
        .parsed_scope
        .commands
        .get(entry.command_ref.command_index)?;
    if original
        .tokens
        .iter()
        .map(|t| t.command_substitutions.len())
        .sum::<usize>()
        != 1
        || original
            .prefix_assignments
            .iter()
            .any(|a| !a.value.command_substitutions.is_empty())
        || entry
            .parsed_scope
            .redirections
            .iter()
            .filter(|r| {
                crate::support::redirection_parent_command_index(&entry.parsed_scope, r)
                    == Some(entry.command_ref.command_index)
            })
            .any(|r| {
                r.target
                    .iter()
                    .chain(r.content.iter())
                    .any(|v| !v.command_substitutions.is_empty())
            })
    {
        return None;
    }
    let (index, token) = original
        .tokens
        .iter()
        .enumerate()
        .find(|(_, t)| !t.command_substitutions.is_empty())?;
    let substitution = &token.command_substitutions[0];
    if !token.quoted || token.text != substitution.text || token.runtime_data {
        return None;
    }
    let body = caushell_parse::parse_command(&substitution.body_text, entry.shell_kind).ok()?;
    if body.status != caushell_parse::ParseStatus::Complete
        || body.commands.len() != 1
        || !body.redirections.is_empty()
        || !body.assignment_commands.is_empty()
        || !body.declaration_commands.is_empty()
        || !body.function_definitions.is_empty()
    {
        return None;
    }
    let command = &body.commands[0];
    if command.text.trim() != substitution.body_text.trim()
        || command.in_pipeline
        || command.guarded
        || command.control_flow_span.is_some()
        || command.terminator == Some(caushell_parse::StatementTerminator::Background)
        || command
            .tokens
            .iter()
            .any(|t| !t.command_substitutions.is_empty())
        || command
            .prefix_assignments
            .iter()
            .any(|a| !a.value.command_substitutions.is_empty())
    {
        return None;
    }
    let name = command.command_name.as_deref()?;
    if entry.bindings.function_binding(name).is_some()
        || entry.bindings.profile_has_alias_shadow(name)
        || entry.bindings.alias_bindings().any(|a| a.name == name)
    {
        return None;
    }
    // Argument substitutions precede the outer command's temporary
    // environment assignments. Only assignments on the producer apply.
    let mut frame = entry.bindings.clone();
    frame.enter_child_shell_environment();
    let frame = crate::support::command_environment_bindings(
        &frame,
        &body,
        &ParsedCommandRef::new(0, command.span.clone()),
    );
    let ResolveInvocationArtifactResult::Resolved(resolved) =
        resolve_invocation_artifact_with_bindings(
            registry,
            command,
            InvocationRuntimeContext::new(),
            &frame,
        )
    else {
        return None;
    };
    if !caushell_profile::python_isolated_startup(&resolved)
        || resolved.bound.operation_semantics_unresolved
        || !resolved.bound.residuals.is_empty()
    {
        return None;
    }
    if !caushell_profile::collect_recursive_payload_candidates(&resolved.bound)
        .iter()
        .any(|p| p.language == PayloadLanguage::Python && p.source == PayloadSource::InlineString)
    {
        return None;
    }
    let observations = source_scope_observations(
        registry,
        request,
        &entry.parsed_scope,
        program_command_index(entry),
        program_scope_bindings(entry),
    );
    let cwds = crate::passes::source_scope_execution_cwds(
        &entry.parsed_scope,
        request,
        &context.entry_cwd,
        &observations,
    )
    .1;
    let caushell_runner::EffectiveCwd::Known(cwd) = cwds.get(program_command_index(entry))? else {
        return None;
    };
    let mut inputs = Inputs {
        registry,
        session,
        request,
        entry,
        context,
        cwd: cwd.clone(),
        bindings: frame,
    };
    let mut argv = vec!["-c".into()];
    argv.extend(decoded_task_arguments(&resolved.bound, "script_args")?);
    let report = caushell_profile::analyze_python(
        &one_argument(&resolved.bound, "payload").ok()?,
        &argv,
        &mut inputs,
    );
    if report.gap.is_some()
        || !report.stdout_complete
        || !report.stdout.is_ascii()
        || report.stdout.contains(&0)
        || report
            .effects
            .iter()
            .any(|e| !matches!(e, PythonEffect::ReadFile(_)))
    {
        return None;
    }
    let value = String::from_utf8(report.stdout.clone())
        .ok()?
        .trim_end_matches('\n')
        .to_owned();
    let mut projected = original.clone();
    let field = &mut projected.tokens[index];
    field.text = value.clone();
    field.runtime_data = true;
    field.node_kind = "python_stdout".into();
    field.command_substitutions.clear();
    field.kind = if value == "--" {
        caushell_parse::CommandTokenKind::DashDash
    } else if value.starts_with('-') && value.len() > 1 {
        caushell_parse::CommandTokenKind::Flag
    } else {
        caushell_parse::CommandTokenKind::Arg
    };
    Some((
        projected,
        caushell_types::PythonStdoutFieldEvidence {
            node_id: entry.source_node_id.0.clone(),
            argument_index: index,
            expression: substitution.text.clone(),
            stdout: report.stdout,
            value,
            inputs: report
                .inputs
                .into_iter()
                .map(|i| match i {
                    PythonInput::Environment { name, value } => {
                        PythonPayloadInputEvidence::Environment { name, value }
                    }
                    PythonInput::File { path, bytes } => {
                        PythonPayloadInputEvidence::File { path, bytes }
                    }
                })
                .collect(),
        },
    ))
}

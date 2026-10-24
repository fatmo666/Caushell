use super::*;

/// Quoted producer output remains data within the original scalar argv word.
pub(in crate::passes::resolve_invocation) fn materialize_outputs(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &mut ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    max_depth: u8,
    ancestor_records: &[ExecutionUnitResolveRecord],
    ctx: &mut RunnerContext,
) {
    let outcome = output_fields(
        registry,
        session,
        request,
        entry,
        context,
        max_depth,
        ancestor_records,
        ctx,
    );
    if let Some((command, proofs)) = outcome {
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
        for proof in proofs {
            ctx.add_evidence(Evidence {
                rule_id: caushell_types::RuleId::NestedPayloadExpansion,
                summary: "Python stdout materialized as argv data".into(),
                kind: EvidenceKind::PythonStdoutField(proof),
            });
        }
    }
}

fn output_fields(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    max_depth: u8,
    ancestor_records: &[ExecutionUnitResolveRecord],
    ctx: &mut RunnerContext,
) -> Option<(
    caushell_parse::CommandFact,
    Vec<caushell_types::PythonStdoutFieldEvidence>,
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
    let count = original
        .tokens
        .iter()
        .map(|t| t.command_substitutions.len())
        .sum::<usize>();
    if !(1..=8).contains(&count)
        || original.text.len() > 65_536
        || !caushell_parse::parse_process_substitutions(&original.text, entry.shell_kind)
            .ok()?
            .is_empty()
        || caushell_parse::parse_command_substitutions(&original.text, entry.shell_kind)
            .ok()?
            .len()
            != count
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
    let mut projected = original.clone();
    let mut proofs = Vec::new();
    let mut output_bytes = 0usize;
    for (index, token) in original.tokens.iter().enumerate() {
        if token.command_substitutions.is_empty() {
            continue;
        }
        if token.runtime_data {
            return None;
        }
        let parts = if entry.shell_kind == caushell_types::ShellKind::Bash {
            caushell_parse::scalar_argument_parts(&token.text, token.quoted, &token.node_kind)?
        } else if token.quoted
            && token.command_substitutions.len() == 1
            && token.text == token.command_substitutions[0].text
        {
            vec![caushell_parse::ScalarArgumentPart::CommandSubstitution(
                token.text.clone(),
            )]
        } else {
            return None;
        };
        let mut substitutions = token.command_substitutions.iter();
        let mut value = String::new();
        let start = proofs.len();
        for part in parts {
            match part {
                caushell_parse::ScalarArgumentPart::Literal(text) => value.push_str(&text),
                caushell_parse::ScalarArgumentPart::Parameter(text) => {
                    value.push_str(
                        &caushell_profile::exact_scalar_shell_parameter_reference_value(
                            &text,
                            &entry.bindings,
                        )?,
                    );
                }
                caushell_parse::ScalarArgumentPart::CommandSubstitution(text) => {
                    let substitution = substitutions.next()?;
                    if substitution.text != text {
                        return None;
                    }
                    let report = producer_output(
                        registry,
                        session,
                        request,
                        entry,
                        context,
                        substitution,
                        ancestor_records,
                        ctx,
                    )?;
                    value.push_str(
                        std::str::from_utf8(&report.stdout)
                            .ok()?
                            .trim_end_matches('\n'),
                    );
                    proofs.push(caushell_types::PythonStdoutFieldEvidence {
                        node_id: entry.source_node_id.0.clone(),
                        argument_index: index,
                        expression: substitution.text.clone(),
                        stdout: report.stdout,
                        value: String::new(),
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
                    });
                }
            }
            if value.len() > 262_144 {
                return None;
            }
        }
        if substitutions.next().is_some() || value.contains('\0') {
            return None;
        }
        output_bytes = output_bytes.checked_add(value.len())?;
        if output_bytes > 1_048_576 {
            return None;
        }
        for proof in &mut proofs[start..] {
            proof.value = value.clone();
        }
        let field = &mut projected.tokens[index];
        field.text = value.clone();
        field.runtime_data = true;
        field.quoted = true;
        field.node_kind = "python_stdout".into();
        field.command_substitutions.clear();
        field.kind = if value == "--" {
            caushell_parse::CommandTokenKind::DashDash
        } else if value.starts_with('-') && value.len() > 1 {
            caushell_parse::CommandTokenKind::Flag
        } else {
            caushell_parse::CommandTokenKind::Arg
        };
    }
    Some((projected, proofs))
}

fn producer_output(
    registry: &ProfileRegistry,
    session: SessionView<'_>,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    substitution: &caushell_parse::CommandSubstitutionFact,
    ancestor_records: &[ExecutionUnitResolveRecord],
    ctx: &mut RunnerContext,
) -> Option<caushell_profile::PythonAnalysis> {
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
    if resolved.bound.operation_semantics_unresolved || !resolved.bound.residuals.is_empty() {
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
    if !caushell_profile::python_isolated_startup(&resolved)
        || ctx.filesystem_view().python_runtime_contract().is_some()
    {
        startup::prove(
            registry,
            request,
            entry,
            context,
            &resolved,
            &inputs.bindings,
            &inputs.cwd,
            "-c",
            &report.imports,
            Some(&command.text),
            ancestor_records,
            ctx,
        )
        .ok()?;
    }
    Some(report)
}

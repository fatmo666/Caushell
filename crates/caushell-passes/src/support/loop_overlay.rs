//! Abstract members of shell word-list iteration; no filesystem enumeration.
use caushell_parse::ForLoopFact;
use caushell_profile::{
    ProjectedArg, ProjectedArgKind, ProjectedInvocation, SessionBindings, SessionValue,
    ValueMaterialization, materialize_projected_invocation,
};
use caushell_types::{PathResolution, RuntimeArgumentDomain};

/// A proof about every possible member, independent of the path-domain
/// approximation below. PathSet roots are anchors, not exact scalar values.
pub(super) fn integer_iteration(
    iteration: &ForLoopFact,
    bindings: &SessionBindings,
    shell_kind: caushell_types::ShellKind,
) -> bool {
    if bindings.runtime_variable_target_is_unresolved(&iteration.variable) {
        return false;
    }
    let Some(items) = &iteration.items else {
        return false;
    };
    if items.is_empty() || items.len() > 256 {
        return false;
    }
    let materialized =
        materialize_projected_invocation(&iteration_projection(items, shell_kind), bindings);
    !materialized.shell_expansion_unresolved
        && !materialized.invocation.args.is_empty()
        && materialized.invocation.args.len() <= 256
        && materialized.invocation.args.iter().all(|arg| {
            caushell_profile::argument_structure(arg)
                .exact_value()
                .is_some_and(super::variable_facts::integer_text)
        })
}

pub(super) fn numeric_iteration(
    iteration: &ForLoopFact,
    bindings: &SessionBindings,
    registry: Option<&caushell_profile::ProfileRegistry>,
    shell_kind: caushell_types::ShellKind,
) -> bool {
    const MAX_ITEMS: usize = 256;
    if bindings.runtime_variable_target_is_unresolved(&iteration.variable) {
        return false;
    }
    let Some(items) = &iteration.items else {
        return bindings.positional_parameters_are_complete()
            && !bindings.positional_parameters().is_empty()
            && bindings.positional_parameters().len() <= MAX_ITEMS
            && bindings
                .positional_parameters()
                .iter()
                .all(|value| match value {
                    SessionValue::ExactScalar(value)
                    | SessionValue::RuntimeProduced { value, .. } => {
                        super::variable_facts::arithmetic_text(value)
                    }
                    _ => false,
                });
    };
    if items.is_empty() || items.len() > MAX_ITEMS {
        return false;
    }
    let projection = iteration_projection(items, shell_kind);
    let materialized = materialize_projected_invocation(&projection, bindings);
    if !materialized.shell_expansion_unresolved
        && !materialized.invocation.args.is_empty()
        && materialized.invocation.args.len() <= MAX_ITEMS
        && materialized.invocation.args.iter().all(|arg| {
            caushell_profile::argument_structure(arg)
                .exact_value()
                .is_some_and(super::variable_facts::arithmetic_text)
        })
    {
        return true;
    }
    // Reuse registered stdout/assignment contracts. This proves an output
    // alphabet, never a producer's value, iteration count, or successful exit.
    items.iter().all(|item| {
        let value = caushell_parse::AssignmentValueFact {
            text: item.text.clone(),
            quoted: item.quoted,
            node_kind: item.node_kind.clone(),
            span: item.span.clone(),
            command_substitutions: item.command_substitutions.clone(),
        };
        super::variable_facts::assignment(&value, bindings, registry, shell_kind).scalar_shape
            == Some(caushell_profile::StdoutScalarShape::ArithmeticText)
    })
}

fn iteration_projection(
    items: &[caushell_parse::CommandToken],
    shell_kind: caushell_types::ShellKind,
) -> ProjectedInvocation {
    ProjectedInvocation {
        shell_kind,
        option_prefixes: Default::default(),
        command_name: None,
        stdin_payload_available: false,
        interactive_session: false,
        args: items
            .iter()
            .map(|item| ProjectedArg {
                word_context: Default::default(),
                text: item.text.clone(),
                quoted: item.quoted,
                node_kind: item.node_kind.clone(),
                span: item.span.clone(),
                kind: ProjectedArgKind::Positional,
                implicit_input_source: item.implicit_input_source,
                runtime_argument_domain: item.runtime_argument_domain.clone(),
                runtime_data: item.runtime_data,
                substitution_shape: None,
                native_region_field: None,
                lexical_field_prefix: None,
            })
            .collect(),
    }
}

pub(super) fn iteration_domain(
    iteration: &ForLoopFact,
    bindings: &SessionBindings,
    shell_kind: caushell_types::ShellKind,
) -> Option<(RuntimeArgumentDomain, bool)> {
    const MAX_ITEMS: usize = 256;
    if bindings.runtime_variable_target_is_unresolved(&iteration.variable) {
        return None;
    }
    let mut roots = Vec::new();
    // A for loop without "in" expands the same argv vector as quoted $@.
    // In particular, an unknown batch length does not erase its item domain.
    let positional_words;
    let items = match &iteration.items {
        Some(items) => items.as_slice(),
        None => {
            if !matches!(shell_kind, caushell_types::ShellKind::Bash | caushell_types::ShellKind::Sh)
                || bindings.positional_parameters().len() > MAX_ITEMS
            {
                return None;
            }
            positional_words = [caushell_parse::CommandToken {
                text: "$@".into(),
                quoted: true,
                node_kind: "string".into(),
                span: iteration.span.clone(),
                kind: caushell_parse::CommandTokenKind::Arg,
                implicit_input_source: None,
                runtime_argument_domain: None,
                runtime_data: false,
                command_substitutions: Vec::new(),
            }];
            &positional_words
        }
    };
    if items.len() > MAX_ITEMS {
        return None;
    }
    let projection = iteration_projection(items, shell_kind);
    let materialized = materialize_projected_invocation(&projection, bindings);
    if materialized.shell_expansion_unresolved {
        return None;
    }
    if materialized.invocation.args.len() > MAX_ITEMS {
        return None;
    }
    let mut complete_literal_members = items.iter().all(|item| {
        caushell_parse::decode_static_shell_argument(&item.text, item.quoted, &item.node_kind)
            .is_some()
    });
    for (arg, resolution) in materialized
        .invocation
        .args
        .iter()
        .zip(&materialized.arg_resolutions)
    {
        if let Some(domain) = &arg.runtime_argument_domain {
            complete_literal_members = false;
            // Keep nested domains without collapsing a template or choosing a
            // representative member. Mixed abstract lists stay conservative.
            if materialized.invocation.args.len() == 1 {
                return Some((domain.clone(), false));
            }
            let RuntimeArgumentDomain::PathSet {
                roots: candidates,
                may_escape: false,
                ..
            } = domain
            else {
                return None;
            };
            roots.extend(candidates.iter().cloned());
        } else if matches!(
            resolution,
            ValueMaterialization::ResolvedExactScalar { .. }
                | ValueMaterialization::ResolvedShellWord { .. }
        ) {
            roots.push(arg.text.clone());
        } else if let Some(value) = caushell_profile::argument_structure(arg).exact_value() {
            roots.push(value.to_string());
        } else {
            complete_literal_members = false;
            // Reuse the pathname-generation proof, then retain its RAW producer
            // spelling. Normalizing ./ away would break argv prefix/affix proofs.
            let Some(PathResolution::BoundedPathSet {
                may_escape: false, ..
            }) = crate::path::iteration_glob_bounds(
                &arg.text,
                arg.quoted,
                &arg.node_kind,
                ".",
                bindings.tilde_home(),
                false,
            )
            else {
                return None;
            };
            let first_pattern = arg.text.find(['*', '?', '['])?;
            let slash = arg.text[..first_pattern].rfind('/')?;
            let mut anchor = arg.text[..=slash].to_string();
            if let Some(rest) = anchor.strip_prefix("~/") {
                anchor = format!("{}/{rest}", bindings.tilde_home()?.trim_end_matches('/'));
            }
            roots.push(anchor);
        }
        if roots.len() > MAX_ITEMS {
            return None;
        }
    }
    path_domain(roots).map(|domain| (domain, complete_literal_members))
}

fn path_domain(mut roots: Vec<String>) -> Option<RuntimeArgumentDomain> {
    if roots.is_empty()
        || roots
            .iter()
            .any(|v| v.is_empty() || v.len() > 4096 || v.contains('\0'))
    {
        return None;
    }
    roots.sort();
    roots.dedup();
    Some(RuntimeArgumentDomain::PathSet {
        roots,
        may_escape: false,
        basename_suffix: None,
        no_adjacent_slashes: false,
        dot_relative_components: false,
        execdir_leaf: false,
    })
}

/// In later iterations the entry IFS must still apply. An assignment,
/// arithmetic expansion, indirect dispatch, or opaque same-shell command
/// anywhere in the body can invalidate it on the back edge.
pub(super) fn preserves_literal_iteration_state(
    iteration: &ForLoopFact,
    parsed: &caushell_parse::ParsedCommandArtifact,
    bindings: &SessionBindings,
    registry: Option<&caushell_profile::ProfileRegistry>,
) -> bool {
    use caushell_profile::{EffectKind, ProfileSourceKind, VariablePresence};

    let Some(registry) = registry else {
        return false;
    };
    let in_body = |span: &caushell_parse::SourceSpan| {
        span.start_byte >= iteration.body_span.start_byte
            && span.end_byte <= iteration.body_span.end_byte
    };
    if iteration.top_level_span != iteration.span
        || iteration.conditional_execution
        // Existing scalar attributes may change assignment semantics. An
        // absent receiver is a fresh, ordinary shell variable.
        || bindings.variable_presence(&iteration.variable) != VariablePresence::Absent
        || bindings.shell_state_uncertainty().is_some()
        || parsed.for_loops.iter().any(|item| in_body(&item.span))
        || parsed.declaration_commands.iter().any(|item| in_body(&item.span))
        || parsed.assignment_commands.iter().any(|item| in_body(&item.span))
        || parsed.unset_commands.iter().any(|item| in_body(&item.span))
        || parsed.function_definitions.iter().any(|item| in_body(&item.span))
        || parsed.shell_evaluations.iter().any(|item| {
            in_body(&item.input.span)
                && !matches!(&item.kind, caushell_parse::ShellEvaluationKind::ParameterReference { name }
                    if name == &iteration.variable)
        })
        || parsed.redirections.iter().any(|item| in_body(&item.span))
    {
        return false;
    }
    parsed
        .commands
        .iter()
        .filter(|command| in_body(&command.span))
        .all(|command| {
            let Some(name) = command.command_name.as_deref() else {
                return false;
            };
            if !command.prefix_assignments.is_empty()
                || bindings.retained_function_binding(name).is_some()
                || bindings.profile_has_alias_shadow(name)
            {
                return false;
            }
            registry.lookup(name).profile.is_some_and(|profile| {
                profile.trust.source == ProfileSourceKind::BuiltIn
                    && profile.subcommands.is_none()
                    && profile.dispatch_overrides.is_empty()
                    && profile.native_variable_writes.is_none()
                    && profile
                        .forms
                        .iter()
                        .flat_map(|f| &f.effects)
                        .chain(profile.modifiers.iter().flat_map(|m| &m.effects))
                        .chain(&profile.selection_failure_effects)
                        .all(|effect| {
                            matches!(
                                effect.kind,
                                EffectKind::ReadPath
                                    | EffectKind::TargetPath
                                    | EffectKind::ConsumeStdin
                                    | EffectKind::TransformData
                            )
                        })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_types::ShellKind;

    #[test]
    fn numeric_loop_proofs_follow_generic_contracts_not_path_anchors_or_names() {
        let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_counter}\nopaque_on_unresolved: true\nforms:\n  - id: run\n    stdout_scalar: arithmetic_text\n    stream_contract: {stdin_mode: ignored, stdout_mode: data, stderr_mode: opaque}\n";
        let registry =
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
                .unwrap();
        let parsed = caushell_parse::parse_command(
            "for member in $(arbitrary_counter); do echo $((member)); done",
            ShellKind::Bash,
        )
        .unwrap();
        assert!(numeric_iteration(
            &parsed.for_loops[0],
            &SessionBindings::new(),
            Some(&registry),
            ShellKind::Bash
        ));
        let registry = ProfileRegistry::from_profiles(vec![
            load_command_profile_from_str(
                &source.replace("    stdout_scalar: arithmetic_text\n", ""),
            )
            .unwrap(),
        ])
        .unwrap();
        assert!(!numeric_iteration(
            &parsed.for_loops[0],
            &SessionBindings::new(),
            Some(&registry),
            ShellKind::Bash
        ));

        let parsed = caushell_parse::parse_command(
            "for member in \"$anchor\"; do echo $((member)); done",
            ShellKind::Bash,
        )
        .unwrap();
        let mut bindings = SessionBindings::new();
        bindings.insert_argument_domain(
            "anchor",
            RuntimeArgumentDomain::PathSet {
                roots: vec!["123".into()],
                may_escape: false,
                basename_suffix: None,
                no_adjacent_slashes: false,
                dot_relative_components: false,
                execdir_leaf: false,
            },
        );
        assert!(
            !numeric_iteration(&parsed.for_loops[0], &bindings, None, ShellKind::Bash),
            "a numeric-looking directory anchor says nothing about its descendants' arithmetic syntax"
        );
    }
}

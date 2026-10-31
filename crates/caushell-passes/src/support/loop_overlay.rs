//! Abstract members of shell word-list iteration; no filesystem enumeration.
use caushell_parse::ForLoopFact;
use caushell_profile::{
    ProjectedArg, ProjectedArgKind, ProjectedInvocation, SessionBindings, SessionValue,
    ValueMaterialization, materialize_projected_invocation,
};
use caushell_types::{PathResolution, RuntimeArgumentDomain};

/// A proof about every possible member, independent of the path-domain
/// approximation below. PathSet roots are anchors, not exact scalar values.
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
                lexical_field_prefix: None,
            })
            .collect(),
    }
}

pub(super) fn iteration_domain(
    iteration: &ForLoopFact,
    bindings: &SessionBindings,
    shell_kind: caushell_types::ShellKind,
) -> Option<RuntimeArgumentDomain> {
    const MAX_ITEMS: usize = 256;
    if bindings.runtime_variable_target_is_unresolved(&iteration.variable) {
        return None;
    }
    let mut roots = Vec::new();
    let Some(items) = &iteration.items else {
        if !bindings.positional_parameters_are_complete()
            || bindings.positional_parameters().len() > MAX_ITEMS
        {
            return None;
        }
        for value in bindings.positional_parameters() {
            let SessionValue::ExactScalar(value) = value else {
                return None;
            };
            roots.push(value.clone());
        }
        return path_domain(roots);
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
    for (arg, resolution) in materialized
        .invocation
        .args
        .iter()
        .zip(&materialized.arg_resolutions)
    {
        if let Some(domain) = &arg.runtime_argument_domain {
            // Keep nested domains without collapsing a template or choosing a
            // representative member. Mixed abstract lists stay conservative.
            if materialized.invocation.args.len() == 1 {
                return Some(domain.clone());
            }
            let RuntimeArgumentDomain::PathSet {
                roots: candidates,
                may_escape: false,
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
    path_domain(roots)
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
            },
        );
        assert!(
            !numeric_iteration(&parsed.for_loops[0], &bindings, None, ShellKind::Bash),
            "a numeric-looking directory anchor says nothing about its descendants' arithmetic syntax"
        );
    }
}

//! Abstract members of shell word-list iteration; no filesystem enumeration.
use caushell_parse::ForLoopFact;
use caushell_profile::{
    ProjectedArg, ProjectedArgKind, ProjectedInvocation, SessionBindings, SessionValue,
    ValueMaterialization, materialize_projected_invocation,
};
use caushell_types::{PathResolution, RuntimeArgumentDomain};

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
    let projection = ProjectedInvocation {
        shell_kind,
        option_prefixes: Default::default(),
        command_name: None,
        stdin_payload_available: false,
        interactive_session: false,
        args: items
            .iter()
            .map(|item| ProjectedArg {
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
    };
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

//! Frame-local proofs, replayed with writes and inherited by ordinary scope clones.
use caushell_parse::{AssignmentValueFact, DeclarationCommandFact, DeclarationCommandKind};
use caushell_profile::{
    ProfileRegistry, SessionBindings, ShellArrayKind, ShellVariableFacts, StdoutScalarShape,
    materialize_shell_assignment_value,
};
use caushell_types::ShellKind;

pub(super) fn invalidate_all(
    bindings: &mut SessionBindings,
    touched: &mut std::collections::BTreeSet<String>,
) {
    touched.extend(
        bindings
            .variable_fact_entries()
            .map(|(name, _)| name.to_owned()),
    );
    bindings.forget_all_variable_facts();
}

pub(super) fn arithmetic_text(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_ascii_digit() || c.is_ascii_whitespace() || matches!(c, '+' | '-'))
}

pub(super) fn assignment(
    value: &AssignmentValueFact,
    bindings: &SessionBindings,
    registry: Option<&ProfileRegistry>,
    shell: ShellKind,
) -> ShellVariableFacts {
    let mut result = ShellVariableFacts::default();
    if value.text.len() > 8192 {
        return result;
    }
    let numeric =
        materialize_shell_assignment_value(&value.text, value.quoted, &value.node_kind, bindings)
            .is_some_and(|v| arithmetic_text(&v))
            || value.node_kind == "arithmetic_expansion"
            || (!matches!(value.node_kind.as_str(), "raw_string" | "ansi_c_string")
                && parameter_numeric(&value.text, bindings));
    if numeric {
        result.scalar_shape = Some(StdoutScalarShape::ArithmeticText);
    } else if !matches!(value.node_kind.as_str(), "raw_string" | "ansi_c_string")
        && !value.command_substitutions.is_empty()
        && value.command_substitutions.len() <= 16
        && let Some(registry) = registry
    {
        let mut rendered = value.text.clone();
        for substitution in &value.command_substitutions {
            if !super::substitution_shape::arithmetic_stdout(
                registry,
                shell,
                &substitution.body_text,
                bindings,
            ) {
                return result;
            }
            rendered = rendered.replacen(&substitution.text, "0", 1);
        }
        if materialize_shell_assignment_value(&rendered, value.quoted, &value.node_kind, bindings)
            .is_some_and(|v| arithmetic_text(&v))
        {
            result.scalar_shape = Some(StdoutScalarShape::ArithmeticText);
        }
    }
    result
}

fn parameter_numeric(text: &str, bindings: &SessionBindings) -> bool {
    if matches!(
        text,
        "$#" | "${#}" | "$?" | "${?}" | "$$" | "${$}" | "$!" | "${!}"
    ) {
        return true;
    }
    if let Some(name) = text.strip_prefix("${#").and_then(|s| s.strip_suffix('}')) {
        return super::scalar_identifier(name)
            || name
                .strip_suffix("[@]")
                .or_else(|| name.strip_suffix("[*]"))
                .is_some_and(super::scalar_identifier);
    }
    let name = text
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
        .or_else(|| text.strip_prefix('$'));
    name.is_some_and(|name| {
        super::scalar_identifier(name)
            && bindings.variable_facts(name).scalar_shape == Some(StdoutScalarShape::ArithmeticText)
    })
}

pub(super) fn declaration_arrays(
    declaration: &DeclarationCommandFact,
    bindings: &SessionBindings,
) -> Vec<(String, ShellVariableFacts)> {
    if !matches!(
        declaration.kind,
        DeclarationCommandKind::Declare
            | DeclarationCommandKind::Typeset
            | DeclarationCommandKind::Local
    ) {
        return Vec::new();
    }
    if declaration.conditional_execution
        || declaration_has_shadow(declaration, bindings)
        || super::declaration_uses_nameref(declaration)
    {
        return Vec::new();
    }
    if declaration.kind == DeclarationCommandKind::Local && !bindings.in_function_scope()
        || declaration
            .options
            .iter()
            .any(|o| !o.starts_with('-') || o[1..].chars().any(|c| !"aAgxr".contains(c)))
    {
        return Vec::new();
    }
    let kind = if declaration
        .options
        .iter()
        .any(|o| o.starts_with('-') && o[1..].contains('A'))
    {
        ShellArrayKind::Associative
    } else if declaration
        .options
        .iter()
        .any(|o| o.starts_with('-') && o[1..].contains('a'))
    {
        ShellArrayKind::Indexed
    } else {
        return Vec::new();
    };
    declaration
        .names
        .iter()
        .chain(declaration.assignments.iter().map(|a| &a.name))
        .filter(|name| super::scalar_identifier(name))
        .filter(|name| {
            (bindings.in_function_scope()
                && !declaration
                    .options
                    .iter()
                    .any(|o| o.starts_with('-') && o[1..].contains('g')))
                || bindings
                    .variable_facts(name)
                    .array_kind
                    .is_none_or(|old| old == kind)
        })
        .map(|name| {
            let element_shape = declaration
                .assignments
                .iter()
                .find(|a| a.name == *name)
                .filter(|a| {
                    a.operator == caushell_parse::AssignmentOperator::Assign
                        && a.value.node_kind == "array"
                })
                .and_then(|a| caushell_parse::static_array_entry_values(&a.value.text))
                .filter(|values| values.iter().all(|v| arithmetic_text(v)))
                .map(|_| StdoutScalarShape::ArithmeticText);
            (
                name.clone(),
                ShellVariableFacts {
                    array_kind: Some(kind),
                    element_shape,
                    ..Default::default()
                },
            )
        })
        .collect()
}

pub(super) fn declaration_name(declaration: &DeclarationCommandFact) -> &'static str {
    match declaration.kind {
        DeclarationCommandKind::Declare => "declare",
        DeclarationCommandKind::Typeset => "typeset",
        DeclarationCommandKind::Local => "local",
        DeclarationCommandKind::Readonly => "readonly",
        DeclarationCommandKind::Export => "export",
    }
}

pub(super) fn declaration_prints_only(declaration: &DeclarationCommandFact) -> bool {
    declaration.kind != DeclarationCommandKind::Export
        && declaration
            .options
            .iter()
            .any(|o| o.starts_with('-') && o[1..].chars().any(|c| matches!(c, 'p' | 'f' | 'F')))
}

pub(super) fn declaration_has_shadow(
    declaration: &DeclarationCommandFact,
    bindings: &SessionBindings,
) -> bool {
    let name = declaration_name(declaration);
    bindings.function_binding(name).is_some() || bindings.profile_has_alias_shadow(name)
}

pub(super) fn invalidate_evaluation(
    site: &caushell_parse::ShellEvaluationSite,
    bindings: &mut SessionBindings,
) {
    use caushell_parse::{ArithmeticReference as R, ShellEvaluationKind as K};
    if let K::ArrayElementAssignment { name, .. } = &site.kind {
        let mut facts = bindings.variable_facts(name);
        facts.scalar_shape = None;
        facts.element_shape = None;
        bindings.mark_unresolved_runtime_variable_target(name);
        bindings.set_variable_facts(name, facts);
        return;
    }
    if !bindings.has_variable_facts() {
        return;
    }
    if !matches!(
        site.kind,
        K::Arithmetic | K::ArithmeticBuiltin | K::UnresolvedArithmetic
    ) {
        return;
    }
    fn writes(refs: &[R], bindings: &mut SessionBindings) {
        for reference in refs {
            match reference {
                R::Assignment { name, value, .. } => {
                    bindings.forget_variable_facts(name);
                    writes(value, bindings);
                }
                R::Optional(items) => writes(items, bindings),
                R::ExpandedWord {
                    text,
                    quoted,
                    node_kind,
                } => {
                    if !parameter_numeric(text, bindings)
                        && !materialize_shell_assignment_value(text, *quoted, node_kind, bindings)
                            .is_some_and(|value| arithmetic_text(&value))
                    {
                        bindings.forget_all_variable_facts();
                    }
                }
                R::ArithmeticExpansion(_) | R::Unsupported(_) => {
                    bindings.forget_all_variable_facts()
                }
                R::Variable(name)
                    if bindings.variable_facts(name).scalar_shape
                        != Some(StdoutScalarShape::ArithmeticText)
                        && !bindings.get(name).is_some_and(|b| match b.value {
                            caushell_profile::SessionValue::ExactScalar(v)
                            | caushell_profile::SessionValue::RuntimeProduced {
                                value: v, ..
                            } => arithmetic_text(v),
                            _ => false,
                        }) =>
                {
                    bindings.forget_all_variable_facts();
                }
                R::Array { .. } => bindings.forget_all_variable_facts(),
                _ => {}
            }
        }
    }
    match caushell_parse::parse_arithmetic_references(&site.input.text) {
        Some(refs) => writes(&refs, bindings),
        None => bindings.forget_all_variable_facts(),
    }
}

pub(super) fn invalidate_command(
    command: &caushell_parse::CommandFact,
    parsed: &caushell_parse::ParsedCommandArtifact,
    target: usize,
    registry: Option<&ProfileRegistry>,
    bindings: &mut SessionBindings,
) {
    if !bindings.has_variable_facts() || !super::runtime_write_visible(command, parsed, target) {
        return;
    }
    let Some(registry) = registry else {
        bindings.forget_all_variable_facts();
        return;
    };
    let Some(name) = command
        .command_name
        .as_deref()
        .and_then(|n| caushell_profile::materialize_command_name(n, bindings))
    else {
        bindings.forget_all_variable_facts();
        return;
    };
    if bindings.function_binding(&name).is_some() {
        return;
    }
    if bindings.profile_has_alias_shadow(&name) {
        bindings.forget_all_variable_facts();
        return;
    }
    let lookup = registry.lookup(&name);
    let Some(profile) = lookup.profile else {
        bindings.forget_all_variable_facts();
        return;
    };
    if !profile
        .forms
        .iter()
        .flat_map(|f| &f.effects)
        .chain(profile.modifiers.iter().flat_map(|m| &m.effects))
        .any(|e| {
            matches!(
                e.kind,
                caushell_profile::EffectKind::ExecutePayload
                    | caushell_profile::EffectKind::SourceScriptIntoCurrentShell
                    | caushell_profile::EffectKind::DispatchCommand
            )
        })
    {
        return;
    }
    let result = caushell_profile::resolve_invocation_artifact_with_bindings(
        registry,
        command,
        caushell_profile::InvocationRuntimeContext::default().with_shell_kind(parsed.shell_kind),
        bindings,
    );
    if let caushell_profile::ResolveInvocationArtifactResult::Resolved(r) = result {
        if r.bound.effects.iter().any(|e| {
            matches!(
                e.kind,
                caushell_profile::EffectKind::ExecutePayload
                    | caushell_profile::EffectKind::SourceScriptIntoCurrentShell
                    | caushell_profile::EffectKind::DispatchCommand
            )
        }) {
            bindings.forget_all_variable_facts();
        }
    } else {
        bindings.forget_all_variable_facts();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_assignment_uses_the_registered_contract_not_a_tool_name() {
        let built_in = ProfileRegistry::built_in().unwrap();
        let mut profile = built_in.lookup("printf").profile.unwrap().clone();
        profile.identity.canonical_name = caushell_profile::CommandName::new("counter");
        profile.identity.aliases.clear();
        let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
        let parsed =
            caushell_parse::parse_command("value=$(counter '%d' 12)", ShellKind::Bash).unwrap();
        let value = &parsed.assignment_commands[0].assignments[0].value;
        let bindings = SessionBindings::new();
        assert_eq!(
            assignment(value, &bindings, Some(&registry), ShellKind::Bash).scalar_shape,
            Some(StdoutScalarShape::ArithmeticText)
        );
        assert!(bindings.get("value").is_none());
    }
}

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

pub(super) fn integer_text(text: &str) -> bool {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn pure_native_effects(bound: &caushell_profile::BoundInvocation) -> bool {
    !bound.operation_semantics_unresolved
        && bound.effects.iter().all(|effect| {
            matches!(
                effect.kind,
                caushell_profile::EffectKind::ReadPath
                    | caushell_profile::EffectKind::TargetPath
                    | caushell_profile::EffectKind::TransformData
                    | caushell_profile::EffectKind::ConsumeStdin
                    | caushell_profile::EffectKind::ConsumeAuxiliaryValue
                    | caushell_profile::EffectKind::ConsumeAuxiliaryEnvironment
            )
        })
}

/// Substitution bodies are not top-level CommandFacts. Inspect their declared
/// effects before retaining an entry executable contract after them. A bounded
/// single producer is sufficient; other programs remain unknown, never run.
pub(super) fn invalidate_native_substitutions(
    parsed: &caushell_parse::ParsedCommandArtifact,
    target: usize,
    registry: Option<&ProfileRegistry>,
    bindings: &mut SessionBindings,
) {
    if !bindings.has_native_variants() {
        return;
    }
    let substitutions: Vec<_> = parsed
        .commands
        .iter()
        .flat_map(|c| {
            c.tokens
                .iter()
                .flat_map(|t| &t.command_substitutions)
                .chain(
                    c.prefix_assignments
                        .iter()
                        .flat_map(|a| &a.value.command_substitutions),
                )
        })
        .chain(parsed.assignment_commands.iter().flat_map(|c| {
            c.assignments
                .iter()
                .flat_map(|a| &a.value.command_substitutions)
        }))
        .chain(parsed.declaration_commands.iter().flat_map(|c| {
            c.assignments
                .iter()
                .flat_map(|a| &a.value.command_substitutions)
        }))
        .chain(
            parsed
                .shell_evaluations
                .iter()
                .flat_map(|site| &site.input.command_substitutions),
        )
        .chain(parsed.for_loops.iter().flat_map(|l| {
            l.items
                .iter()
                .flatten()
                .flat_map(|t| &t.command_substitutions)
        }))
        .filter(|s| s.span.end_byte <= target)
        .collect();
    let preserves = substitutions.len() <= 128 && substitutions.iter().all(|s| {
        let Some(registry) = registry else { return false; };
        if s.body_text.len() > 8192 { return false; }
        let Ok(body) = caushell_parse::parse_command(&s.body_text, parsed.shell_kind) else { return false; };
        let Some(command) = super::substitution_shape::plain_single_producer(&body) else { return false; };
        if command.tokens.iter().any(|t| !t.command_substitutions.is_empty()) { return false; }
        let Some(name) = command.command_name.as_deref() else { return false; };
        if bindings.function_binding(name).is_some() || bindings.profile_has_alias_shadow(name) { return false; }
        matches!(caushell_profile::resolve_invocation_artifact_with_bindings(registry, command,
            caushell_profile::InvocationRuntimeContext::default().with_shell_kind(parsed.shell_kind), bindings),
            caushell_profile::ResolveInvocationArtifactResult::Resolved(r) if pure_native_effects(&r.bound))
    });
    if !preserves {
        bindings.forget_native_variants();
    }
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
    result.basename_text = shell == ShellKind::Bash
        && value.quoted
        && value.node_kind == "string"
        && !bindings.runtime_variable_target_is_unresolved("PWD")
        && matches!(caushell_profile::exact_shell_parameter_reference(&value.text),
            Some(caushell_profile::ShellParameterReference::PatternRemoval {
                parameter: caushell_profile::ShellParameterName::Variable(name),
                kind: caushell_profile::ShellPatternRemovalKind::LongestPrefix,
                pattern,
            }) if name == "PWD" && pattern == "*/");
    result.integer_scalar = materialize_shell_assignment_value(&value.text, value.quoted, &value.node_kind, bindings)
        .is_some_and(|v| integer_text(&v)) || value.node_kind == "arithmetic_expansion"
        || (!matches!(value.node_kind.as_str(), "raw_string" | "ansi_c_string")
            && caushell_profile::exact_shell_parameter_reference(&value.text).is_some_and(|r| {
                matches!(r, caushell_profile::ShellParameterReference::Variable(name) if bindings.variable_facts(&name).integer_scalar)
            }));
    let numeric =
        materialize_shell_assignment_value(&value.text, value.quoted, &value.node_kind, bindings)
            .is_some_and(|v| arithmetic_text(&v))
            || value.node_kind == "arithmetic_expansion"
            || (!matches!(value.node_kind.as_str(), "raw_string" | "ansi_c_string")
                && parameter_numeric(&value.text, bindings));
    if numeric {
        result.scalar_shape = Some(StdoutScalarShape::ArithmeticText);
    } else if let Some(registry) = registry
        && !matches!(value.node_kind.as_str(), "raw_string" | "ansi_c_string")
        && let [capture] = value.command_substitutions.as_slice()
        && value.text == capture.text
        && let Some(shape) = super::substitution_shape::encoded_stdout_shape(
            registry,
            shell,
            &capture.body_text,
            bindings,
        )
    {
        result.scalar_shape = Some(shape);
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
                .rfind(|a| a.name == *name)
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
        facts.integer_scalar = false;
        facts.basename_text = false;
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
    // Earlier commands in child/substitution scopes can also change executable
    // files. This proof is about resolution, not caller-shell variable writes.
    if matches!(
        command.command_name.as_deref(),
        Some("cd" | "pushd" | "popd" | "export" | "eval" | "source" | "." | "alias" | "unalias")
    ) || !command.prefix_assignments.is_empty()
        || parsed
            .redirections
            .iter()
            .any(|r| r.parent_command_span.as_ref() == Some(&command.span))
    {
        bindings.forget_native_variants();
    }
    if bindings.has_native_variants() {
        let preserves = registry.is_some_and(|registry| {
            let result = caushell_profile::resolve_invocation_artifact_with_bindings(
                registry,
                command,
                caushell_profile::InvocationRuntimeContext::default()
                    .with_shell_kind(parsed.shell_kind),
                bindings,
            );
            matches!(result, caushell_profile::ResolveInvocationArtifactResult::Resolved(r)
                if pure_native_effects(&r.bound))
        });
        if !preserves {
            bindings.forget_native_variants();
        }
    }
    if !bindings.has_variable_facts() || !super::runtime_write_visible(command, parsed, target) {
        return;
    }
    // A parsed simple Bash string test is syntax. Its opening bracket is
    // never an executable glob, and the comparison does not write variables.
    if parsed.shell_kind == ShellKind::Bash
        && command.command_name.as_deref() == Some("[[")
        && !command.command_name_runtime_data
        && command.prefix_assignments.is_empty()
        && let [left, operator, right, close] = command.tokens.as_slice()
        && matches!(operator.text.as_str(), "==" | "!=" | "=")
        && operator.node_kind == operator.text
        && close.node_kind == "]]"
        && [left, right].iter().all(|token| {
            token.command_substitutions.is_empty()
                && !token.text.contains(['[', '`'])
                && !token.text.contains("$(")
        })
    {
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

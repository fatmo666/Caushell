//! Positive stdout shape proofs supplied by selected Profiles. No executable
//! names, cwd substitution, shell execution, or filesystem observation.
use std::collections::BTreeMap;

use caushell_parse::{CommandFact, ParseStatus, ParsedCommandArtifact, SourceSpan, parse_command};
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    StdoutScalarShape, resolve_invocation_artifact_with_bindings,
};
use caushell_types::{SessionAliasBinding, ShellKind};

/// The entire captured stream must satisfy the declaration. A recognized
/// producer among other commands/branches is not proof of the stream's shape.
pub(crate) fn substitution_shapes(
    registry: &ProfileRegistry,
    command: &CommandFact,
    shell_kind: ShellKind,
    bindings: &SessionBindings,
    aliases: &BTreeMap<String, SessionAliasBinding>,
    remaining_depth: u8,
) -> Vec<(SourceSpan, StdoutScalarShape)> {
    if remaining_depth == 0 || !matches!(shell_kind, ShellKind::Bash | ShellKind::Sh) {
        return Vec::new();
    }
    command
        .tokens
        .iter()
        .filter_map(|token| {
            // Quoting prevents field splitting and pathname expansion. Mixed
            // words, multiple substitutions and unquoted output retain their
            // ordinary unknown/lexical bounds.
            if !token.quoted
                || token.node_kind != "string"
                || token.command_substitutions.len() != 1
            {
                return None;
            }
            let substitution = &token.command_substitutions[0];
            let suffix = token.text.strip_prefix(&substitution.text)?;
            let suffix = caushell_parse::decode_static_shell_argument(suffix, true, "string")?;
            // The producer can fail with empty output: a suffix like -delete
            // would then be a control word. Empty or slash-prefixed literal
            // suffixes preserve the empty-or-absolute-path guarantee.
            if !suffix.is_empty() && !suffix.starts_with('/') {
                return None;
            }
            let parsed = parse_command(&substitution.body_text, shell_kind).ok()?;
            let producer = plain_single_producer(&parsed)?;
            let name = producer.command_name.as_deref()?;
            let executable = if producer.command_name_runtime_data {
                name.to_string()
            } else {
                caushell_profile::materialize_command_name(name, bindings)?
            };
            // A function/alias can replace the registered executable. Do not
            // borrow the executable's contract for a shadowing definition, even
            // if that definition would itself be statically analyzable.
            if aliases.contains_key(name) || bindings.function_binding(&executable).is_some() {
                return None;
            }
            let ResolveInvocationArtifactResult::Resolved(resolved) =
                resolve_invocation_artifact_with_bindings(
                    registry,
                    producer,
                    InvocationRuntimeContext::default(),
                    bindings,
                )
            else {
                return None;
            };
            Some((token.span.clone(), resolved.proven_stdout_scalar()?))
        })
        .collect()
}

fn plain_single_producer(parsed: &ParsedCommandArtifact) -> Option<&CommandFact> {
    if parsed.status != ParseStatus::Complete
        || !parsed.diagnostics.is_empty()
        || parsed.commands.len() != 1
        || !parsed.redirections.is_empty()
        || !parsed.declaration_commands.is_empty()
        || !parsed.assignment_commands.is_empty()
        || !parsed.unset_commands.is_empty()
        || !parsed.function_definitions.is_empty()
    {
        return None;
    }
    let command = &parsed.commands[0];
    if command.in_pipeline
        || command.guarded
        || command.conditional_execution
        || command.terminator.is_some()
        || !command.prefix_assignments.is_empty()
        || command.text.trim() != parsed.raw_command.trim()
    {
        return None;
    }
    Some(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_profile::load_command_profile_from_str;
    const SOURCE: &str = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_absolute_producer}\noption_scope: all_arguments\nopaque_on_unresolved: true\nforms:\n  - id: path\n    stdout_scalar: absolute_path\n    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n";

    #[test]
    fn declarations_work_for_arbitrary_producer_names() {
        let registry =
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(SOURCE).unwrap()])
                .unwrap();
        for (text, expected) in [
            ("consumer \"$(arbitrary_absolute_producer)\"", 1),
            ("consumer \"`arbitrary_absolute_producer`\"", 1),
            ("consumer \"$(arbitrary_absolute_producer)/child\"", 1),
            ("consumer $(arbitrary_absolute_producer)", 0),
            ("consumer \"$(arbitrary_absolute_producer)-delete\"", 0),
            ("consumer \"$(arbitrary_absolute_producer)/$unknown\"", 0),
            ("consumer \"$(arbitrary_absolute_producer; other)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer & )\"", 0),
            ("consumer \"$(arbitrary_absolute_producer --unknown)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer 2>&1)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer >out)\"", 0),
            ("consumer \"$(arbitrary_absolute_producer | other)\"", 0),
        ] {
            let parsed = parse_command(text, ShellKind::Bash).unwrap();
            assert_eq!(
                substitution_shapes(
                    &registry,
                    &parsed.commands[0],
                    ShellKind::Bash,
                    &SessionBindings::new(),
                    &BTreeMap::new(),
                    8
                )
                .len(),
                expected,
                "{text}: {parsed:#?}"
            );
        }
        let parsed = parse_command(
            "consumer \"$(arbitrary_absolute_producer)\"",
            ShellKind::Bash,
        )
        .unwrap();
        let aliases = BTreeMap::from([(
            "arbitrary_absolute_producer".into(),
            SessionAliasBinding::new(
                "arbitrary_absolute_producer",
                "other",
                caushell_types::CommandSequenceNo::new(1),
            ),
        )]);
        assert!(
            substitution_shapes(
                &registry,
                &parsed.commands[0],
                ShellKind::Bash,
                &SessionBindings::new(),
                &aliases,
                8
            )
            .is_empty()
        );
        assert!(
            substitution_shapes(
                &registry,
                &parsed.commands[0],
                ShellKind::Bash,
                &SessionBindings::new(),
                &BTreeMap::new(),
                0
            )
            .is_empty()
        );
    }
}

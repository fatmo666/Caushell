//! Positive record-domain proofs. No tool names, filesystem enumeration or
//! captured command output: the producer's selected Profile supplies semantics.
use caushell_parse::{ParsedCommandArtifact, RedirectionKind};
use caushell_profile::{
    BoundArgumentMaterialization, BoundValue, ResolvedInvocationArtifact, SemanticValueRef,
    SemanticValueResolution, StdoutRecordProjection, StreamRecordSeparator,
};
use caushell_types::RuntimeArgumentDomain;

use super::{
    EffectiveStdinSource, collect_pipeline_groups, effective_stdin_source,
    redirection_parent_command_index, redirection_targets_stdin_payload,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathRecords {
    pub domain: RuntimeArgumentDomain,
    pub separator: StreamRecordSeparator,
}

/// Resolve only the effective, immediately connected upstream chain. A byte
/// transform is NOT a path-preserving transform. Forwarding requires an
/// explicit contract and cannot cross an input override or mixed stderr.
pub(crate) fn stdin_path_records(
    parsed: &ParsedCommandArtifact,
    consumer: usize,
    _cwd: &str,
    home: Option<&str>,
    max_hops: usize,
    mut resolve: impl FnMut(usize) -> Option<ResolvedInvocationArtifact>,
) -> Option<PathRecords> {
    if max_hops == 0 || effective_stdin_source(parsed, consumer) != EffectiveStdinSource::Inherited
    {
        return None;
    }
    let group = collect_pipeline_groups(parsed)
        .into_iter()
        .find(|g| g.commands.iter().any(|c| c.command_index == consumer))?;
    let mut position = group
        .commands
        .iter()
        .position(|c| c.command_index == consumer)?;
    for _ in 0..max_hops {
        let upstream_position = position.checked_sub(1)?;
        let upstream = &group.commands[upstream_position];
        let downstream = &group.commands[position];
        // `|&` includes stderr after explicit redirects have been applied.
        let between = parsed
            .raw_command
            .get(upstream.command.span.end_byte..downstream.command.span.start_byte)?;
        if between.contains("|&") || !stdout_route_is_plain(parsed, upstream.command_index) {
            return None;
        }
        let resolved = resolve(upstream.command_index)?;
        let records = resolved.proven_stdout_records()?;
        match &records.projection {
            StdoutRecordProjection::Paths {
                roots_slot,
                default_root,
                separator,
                escape_modifiers,
            } => {
                let mut roots = Vec::new();
                for parameter in resolved
                    .bound
                    .bound_parameters
                    .iter()
                    .filter(|p| p.name == *roots_slot)
                {
                    // An explicitly provided but inapplicable root is not
                    // evidence that the tool falls back to its default root.
                    let mut count = 0;
                    for value in parameter.semantic_values() {
                        count += 1;
                        let (decoded, tilde_expanded) = match value {
                            SemanticValueRef::Projected { value, .. } => {
                                let SemanticValueResolution::Known(text) = &value.resolution else {
                                    return None;
                                };
                                (text.clone(), false)
                            }
                            SemanticValueRef::Original(value) => {
                                let BoundValue::Argument {
                                    text,
                                    quoted,
                                    node_kind,
                                    materialization,
                                    ..
                                } = value
                                else {
                                    return None;
                                };
                                let data = !matches!(
                                    materialization,
                                    BoundArgumentMaterialization::Literal
                                );
                                let decoded = if data {
                                    text.clone()
                                } else {
                                    caushell_parse::decode_static_shell_argument(
                                        text, *quoted, node_kind,
                                    )?
                                };
                                let tilde = !data
                                    && !quoted
                                    && (decoded == "~" || decoded.starts_with("~/"));
                                (decoded, tilde)
                            }
                        };
                        // Keep relative argv roots relative: it is the consumer's
                        // cwd that interprets the paths emitted by the producer.
                        // Tilde expansion belongs to the producer's shell only.
                        let root = if tilde_expanded {
                            crate::path::expand_home_path_spelling(&decoded, home)?
                        } else {
                            decoded.clone()
                        };
                        if decoded.is_empty() {
                            return None;
                        }
                        if !roots.contains(&root) {
                            roots.push(root);
                        }
                    }
                    if count == 0 && !parameter.values.is_empty() {
                        return None;
                    }
                }
                if roots.is_empty() {
                    let root = default_root.as_ref()?;
                    roots.push(root.clone());
                }
                return Some(PathRecords {
                    domain: RuntimeArgumentDomain::PathSet {
                        roots,
                        may_escape: escape_modifiers
                            .iter()
                            .any(|m| resolved.bound.applied_modifiers.contains(m)),
                    },
                    separator: *separator,
                });
            }
            StdoutRecordProjection::Stdin => {
                if effective_stdin_source(parsed, upstream.command_index)
                    != EffectiveStdinSource::Inherited
                {
                    return None;
                }
                position = upstream_position;
            }
        }
    }
    None
}

fn stdout_route_is_plain(parsed: &ParsedCommandArtifact, index: usize) -> bool {
    parsed
        .redirections
        .iter()
        .filter(|r| redirection_parent_command_index(parsed, r) == Some(index))
        .all(|r| {
            redirection_targets_stdin_payload(r)
                || (r.file_descriptor.as_deref() == Some("2")
                    && r.kind == RedirectionKind::File
                    && !r
                        .target
                        .as_ref()
                        .is_some_and(|t| t.node_kind == "process_substitution")
                    && matches!(r.operator.as_deref(), Some(">" | ">>" | ">|")))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_parse::parse_command;
    use caushell_profile::{
        InvocationRuntimeContext, ProfileRegistry, ResolveInvocationArtifactResult,
        SessionBindings, load_command_profile_from_str, resolve_invocation_artifact_with_bindings,
    };
    use caushell_types::ShellKind;

    fn registry() -> ProfileRegistry {
        let producer = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_paths}\nforms:\n  - id: paths\n    parameters:\n      - name: roots\n        semantic: {kind: path, role: read}\n        binding: {kind: remaining_positionals}\n        cardinality: optional_many\n    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n    stdout_records:\n      projection: {kind: paths, roots_slot: roots, default_root: '.', separator: nul}\n";
        let forward = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_forward}\nforms:\n  - id: forward\n    stream_contract: {stdin_mode: data_required, stdout_mode: data, stderr_mode: opaque}\n    stdout_records: {projection: {kind: stdin}}\n";
        ProfileRegistry::from_profiles(vec![
            load_command_profile_from_str(producer).unwrap(),
            load_command_profile_from_str(forward).unwrap(),
        ])
        .unwrap()
    }

    fn proof(command: &str, max_hops: usize) -> Option<PathRecords> {
        let registry = registry();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        stdin_path_records(
            &parsed,
            parsed.commands.len() - 1,
            "/tmp/project",
            Some("/home/alice"),
            max_hops,
            |i| match resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[i],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            ) {
                ResolveInvocationArtifactResult::Resolved(r) => Some(r),
                _ => None,
            },
        )
    }

    #[test]
    fn arbitrary_producer_and_forwarder_preserve_domain_without_known_bytes() {
        for command in [
            "arbitrary_paths ./src /opt/shared | consumer",
            "arbitrary_paths ./src /opt/shared | arbitrary_forward | consumer",
        ] {
            assert_eq!(
                proof(command, 8),
                Some(PathRecords {
                    separator: StreamRecordSeparator::Nul,
                    domain: RuntimeArgumentDomain::PathSet {
                        roots: vec!["./src".into(), "/opt/shared".into()],
                        may_escape: false
                    }
                })
            );
        }
        assert_eq!(
            proof("arbitrary_paths | consumer", 8).unwrap().domain,
            RuntimeArgumentDomain::PathSet {
                roots: vec![".".into()],
                may_escape: false
            }
        );
    }

    #[test]
    fn overrides_mixing_undeclared_transforms_and_budget_exhaustion_have_no_proof() {
        for command in [
            "arbitrary_paths | consumer <list",
            "arbitrary_paths | arbitrary_forward <list | consumer",
            "arbitrary_paths 2>&1 | consumer",
            "arbitrary_paths |& consumer",
            "arbitrary_paths >output | consumer",
            "arbitrary_paths | undeclared | consumer",
            "arbitrary_paths \"$root\" | consumer",
        ] {
            assert_eq!(proof(command, 8), None, "{command}");
        }
        assert_eq!(
            proof("arbitrary_paths | arbitrary_forward | consumer", 1),
            None
        );
        assert_eq!(proof("arbitrary_paths | consumer", 0), None);
    }

    #[test]
    fn path_roots_use_semantic_projection_not_raw_option_spelling() {
        let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: projected_paths}\nforms:\n  - id: paths\n    parameters:\n      - name: roots\n        semantic: {kind: path, role: read}\n        binding: {kind: remaining_positionals}\n        cardinality: optional_many\n        value_projection: {kind: key_value, separator: '=', key: root}\n    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n    stdout_records:\n      projection: {kind: paths, roots_slot: roots, default_root: '.', separator: nul}\n";
        let registry =
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
                .unwrap();
        for (command, expected) in [
            (
                "projected_paths root=/opt/shared | consumer",
                Some(vec!["/opt/shared".into()]),
            ),
            ("projected_paths other=/opt/shared | consumer", None),
        ] {
            let parsed = parse_command(command, ShellKind::Bash).unwrap();
            let result = stdin_path_records(&parsed, 1, "/tmp/project", None, 8, |i| {
                match resolve_invocation_artifact_with_bindings(
                    &registry,
                    &parsed.commands[i],
                    InvocationRuntimeContext::new(),
                    &SessionBindings::new(),
                ) {
                    ResolveInvocationArtifactResult::Resolved(r) => Some(r),
                    _ => None,
                }
            });
            assert_eq!(
                result.map(|r| match r.domain {
                    RuntimeArgumentDomain::PathSet { roots, .. } => roots,
                    _ => panic!(),
                }),
                expected,
                "{command}"
            );
        }
    }
}

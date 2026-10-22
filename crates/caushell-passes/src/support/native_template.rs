//! Data-origin links for native template replacements, shared by provenance passes.
use caushell_graph::EdgeKind;
use caushell_profile::BoundValue;
use caushell_runner::{PendingMutation, RunnerContext, SessionView};
use caushell_types::{
    ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics, RuntimeInputSource,
};

/// Native wrappers preserve argv source spans; new shell bodies do not.
/// Only origins owned by this parent and actually forwarded as argv survive.
pub(crate) fn forwarded_native_argument_inputs(
    inherited: &caushell_runner::ExecutionUnitInheritedScope,
    parent: &caushell_graph::NodeId,
    child: &caushell_graph::NodeId,
    command: &caushell_parse::CommandFact,
) -> Vec<caushell_runner::NativeArgumentInput> {
    inherited
        .native_argument_inputs
        .iter()
        .filter(|input| input.consumer_node_id == *parent)
        .filter(|input| {
            command.tokens.iter().any(|token| {
                input.origin.data_ranges.iter().any(|range| {
                    token.span.start_byte < range.end && range.start < token.span.end_byte
                })
            })
        })
        .map(|input| caushell_runner::NativeArgumentInput {
            consumer_node_id: child.clone(),
            origin: input.origin.clone(),
            projections: input
                .projections
                .iter()
                .filter(|projection| {
                    command.tokens.iter().any(|token| {
                        token.span == projection.argument_span
                            && token.runtime_data
                            && token.implicit_input_source.is_none()
                            && token.text == projection.value
                    })
                })
                .cloned()
                .collect(),
        })
        .collect()
}

/// Replacement occurs in decoded native argv, not in the parent shell spelling.
pub(crate) fn replace_native_argument(
    value: &str,
    marker: &str,
    replacement: &str,
) -> (String, Vec<std::ops::Range<usize>>) {
    let mut output = String::new();
    let mut ranges = Vec::new();
    let mut offset = 0;
    for (start, _) in value.match_indices(marker) {
        output.push_str(&value[offset..start]);
        let data_start = output.len();
        output.push_str(replacement);
        ranges.push(data_start..output.len());
        offset = start + marker.len();
    }
    output.push_str(&value[offset..]);
    (output, ranges)
}

pub(crate) fn native_shell_payload_projection<'a>(
    projections: &'a [caushell_runner::NativeArgumentProjection],
    span: &caushell_parse::SourceSpan,
    payload: &str,
    shell_kind: caushell_types::ShellKind,
) -> Option<&'a caushell_runner::NativeArgumentProjection> {
    let projection = projections.iter().find(|projection| {
        projection.argument_span == *span
            && projection.value == payload
            && projection
                .data_ranges
                .iter()
                .all(|range| range.start <= range.end && payload.get(range.clone()).is_some())
    })?;
    let parsed = caushell_parse::parse_command(payload, shell_kind).ok()?;
    if parsed.status != caushell_parse::ParseStatus::Complete {
        return None;
    }
    // Direct words retain their source slots. Assignments, substitutions,
    // function definitions and shell syntax need a separate scope mapping.
    projection
        .data_ranges
        .iter()
        .all(|range| {
            range.is_empty()
                || (!parsed.function_definitions.iter().any(|definition| {
                    definition.span.start_byte < range.end && range.start < definition.span.end_byte
                }) && parsed.commands.iter().any(|command| {
                    command.tokens.iter().any(|token| {
                        token.span.start_byte <= range.start
                            && range.end <= token.span.end_byte
                            && token.command_substitutions.is_empty()
                            && caushell_parse::parse_process_substitutions(&token.text, shell_kind)
                                .is_ok_and(|substitutions| substitutions.is_empty())
                    })
                }))
        })
        .then_some(projection)
}

/// Reify compiler-owned data holes before ordinary shell-frame replay. A job
/// may run `set` or `shift`; that cannot alter replacements already performed
/// by the native tool. User-written positional references never enter here.
pub(crate) fn bind_symbolic_template_inputs(
    parsed: &mut caushell_parse::ParsedCommandArtifact,
    arguments: &[caushell_profile::ProjectedArg],
    origin: &caushell_runner::NativeTemplateInput,
) -> bool {
    if parsed.raw_command != origin.source_text {
        return false;
    }
    let mut owned = 0;
    for command in &mut parsed.commands {
        for token in &mut command.tokens {
            if !origin.origin.data_ranges.iter().any(|range| {
                range.start == token.span.start_byte && range.end == token.span.end_byte
            }) {
                continue;
            }
            let batch = token.text == "$@";
            let position = if batch {
                Some(1)
            } else {
                token
                    .text
                    .strip_prefix("${")
                    .and_then(|text| text.strip_suffix('}'))
                    .and_then(|text| text.parse::<usize>().ok())
            };
            let Some(argument) = position
                .filter(|position| *position > 0)
                .and_then(|position| arguments.get(position))
            else {
                return false;
            };
            let Some(source) = argument.implicit_input_source else {
                return false;
            };
            if !token.quoted
                || token.node_kind != "string"
                || batch != (argument.node_kind == "runtime_argument_list")
            {
                return false;
            }
            token.text.clear();
            token.implicit_input_source = Some(source);
            token.runtime_argument_domain = argument.runtime_argument_domain.clone();
            token.runtime_data = false;
            token.node_kind = argument.node_kind.clone();
            owned += 1;
        }
    }
    owned == origin.origin.data_ranges.len()
}

/// Connect replacements to actual parameter slots, not a blanket dispatcher
/// control edge. Native decoding must not erase known bytes' data origins.
pub(crate) fn collect_native_template_input_mutations(
    session: SessionView<'_>,
    ctx: &RunnerContext,
) -> Vec<PendingMutation> {
    use caushell_graph::{NodeKind, SessionRead};
    use caushell_runner::StagedSession;
    if !ctx.execution_unit_resolve_records().iter().any(|r| {
        r.inherited_scope.native_template_input.is_some()
            || r.inherited_scope
                .native_argument_inputs
                .iter()
                .any(|input| input.consumer_node_id == r.source_node_id)
    }) {
        return Vec::new();
    }
    let staged = StagedSession::new(
        session.graph(),
        ctx.request(),
        session.summary(),
        ctx.pending_mutations(),
    );
    let graph = staged.graph();
    let mut mutations = Vec::new();
    for record in ctx.execution_unit_resolve_records() {
        let template = record
            .inherited_scope
            .native_template_input
            .as_ref()
            .filter(|input| {
                record.parsed_scope.raw_command == input.source_text
                    || (record.origin_kind == caushell_runner::ExecutionUnitOriginKind::Dispatch
                        && record.parent_execution_node_id != input.origin.producer_node_id)
            });
        let origins = template
            .map(|input| input.origin.as_ref())
            .into_iter()
            .chain(
                record
                    .inherited_scope
                    .native_argument_inputs
                    .iter()
                    .filter(|input| input.consumer_node_id == record.source_node_id)
                    .map(|input| input.origin.as_ref()),
            );
        let Some(bound) = crate::support::bound_invocation(&record.result) else {
            continue;
        };
        for origin in origins {
            for parameter in &bound.bound_parameters {
                if !parameter.values.iter().any(|value| {
                    let span = match value {
                        BoundValue::Argument { span, .. } => Some(span),
                        BoundValue::ImplicitInput {
                            origin: Some(input),
                            ..
                        } => Some(&input.span),
                        _ => None,
                    };
                    span.is_some_and(|span| {
                        origin
                            .data_ranges
                            .iter()
                            .any(|range| span.start_byte < range.end && range.start < span.end_byte)
                    })
                }) {
                    continue;
                }
                // Copy only actual replacement inputs. Returned child stdout is
                // not the source of jobs that were already generated from a list.
                for edge in graph.outgoing_edges(&origin.producer_node_id) {
                    if edge.kind != EdgeKind::Consumes {
                        continue;
                    }
                    let Some(ProvenanceEdgeSemantics::Consume {
                        slot_name,
                        consume_kind,
                        ..
                    }) = &edge.semantics
                    else {
                        continue;
                    };
                    let stream = matches!(
                        consume_kind,
                        ProvenanceConsumeKind::StdinExplicit
                            | ProvenanceConsumeKind::StdinImplicit
                            | ProvenanceConsumeKind::PipelineInput
                    );
                    let Some(node) = graph.get_node(&edge.to) else {
                        continue;
                    };
                    let NodeKind::ProvenanceArtifact { artifact } = &node.kind else {
                        continue;
                    };
                    let runtime_stdin = matches!(
                        artifact,
                        ProvenanceArtifact::RuntimeInput {
                            source: RuntimeInputSource::StdinData
                                | RuntimeInputSource::StdinPayload,
                            ..
                        }
                    );
                    if !(slot_name
                        .as_ref()
                        .is_some_and(|slot| origin.input_slots.contains(slot))
                        || (origin.stdin && (stream || runtime_stdin)))
                    {
                        continue;
                    }
                    mutations.push(PendingMutation::AddProvenanceArtifact {
                        source_node_id: record.source_node_id.clone(),
                        node_id: edge.to.clone(),
                        artifact: artifact.clone(),
                        relation: EdgeKind::Consumes,
                        semantics: ProvenanceEdgeSemantics::Consume {
                            consume_kind: if bound.is_auxiliary_input_slot(parameter.name.as_str())
                            {
                                ProvenanceConsumeKind::AuxiliaryInput
                            } else {
                                ProvenanceConsumeKind::RuntimeInput
                            },
                            slot_name: Some(parameter.name.as_str().into()),
                            normalized_command_name: None,
                            domain_label: None,
                        },
                    });
                }
            }
        }
    }
    mutations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span() -> caushell_parse::SourceSpan {
        caushell_parse::SourceSpan {
            start_byte: 20,
            end_byte: 40,
            start_row: 0,
            start_column: 20,
            end_row: 0,
            end_column: 40,
        }
    }

    #[test]
    fn native_replacements_use_decoded_byte_offsets() {
        let (value, ranges) = replace_native_argument("echo 前@后 @", "@", "字");
        assert_eq!(value, "echo 前字后 字");
        assert_eq!(ranges, vec![8..11, 15..18]);
        assert_eq!(
            replace_native_argument("echo @suffix", "@", ""),
            ("echo suffix".into(), vec![5..5])
        );
    }

    #[test]
    fn shell_projection_requires_exact_value_span_and_valid_boundaries() {
        let make = |value: &str, range| caushell_runner::NativeArgumentProjection {
            argument_span: span(),
            value: value.into(),
            data_ranges: vec![range],
        };
        let good = [make("echo 字", 5..8)];
        assert!(
            native_shell_payload_projection(
                &good,
                &span(),
                "echo 字",
                caushell_types::ShellKind::Sh
            )
            .is_some()
        );
        for projections in [
            vec![make("echo 字", 6..8)],
            vec![make("echo 字", 5..20)],
            vec![make("echo old", 5..8)],
        ] {
            assert!(
                native_shell_payload_projection(
                    &projections,
                    &span(),
                    "echo 字",
                    caushell_types::ShellKind::Sh
                )
                .is_none()
            );
        }
        let mut different_span = span();
        different_span.start_byte += 1;
        assert!(
            native_shell_payload_projection(
                &good,
                &different_span,
                "echo 字",
                caushell_types::ShellKind::Sh
            )
            .is_none()
        );
    }

    #[test]
    fn shell_projection_does_not_claim_variable_or_substitution_lineage() {
        for (value, range) in [
            ("DATA=one; echo $DATA", 5..8),
            ("echo $(echo one)", 12..15),
            ("echo <(echo one)", 12..15),
            ("for x in one; do echo $x; done", 9..12),
            ("f(){ echo one; }; f", 10..13),
        ] {
            let projections = [caushell_runner::NativeArgumentProjection {
                argument_span: span(),
                value: value.into(),
                data_ranges: vec![range],
            }];
            assert!(
                native_shell_payload_projection(
                    &projections,
                    &span(),
                    value,
                    caushell_types::ShellKind::Sh
                )
                .is_none(),
                "{value}"
            );
        }
    }
}

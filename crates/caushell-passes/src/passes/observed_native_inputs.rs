use std::collections::{BTreeMap, BTreeSet};

use caushell_graph::NodeId;
use caushell_profile::{
    BoundValue, ImplicitInputSource, PayloadFormat, ProfileRegistry, ProfileSourceKind,
    ResolveInvocationArtifactResult, ResolvedInvocationArtifact, SessionBindings,
};
use caushell_runner::{ExecutionUnitOriginKind, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    Decision, Evidence, EvidenceKind, NativeInputDecodeEvidence, RuleId, StdoutRecordsEvidence,
};

use super::{ComputeEffectiveCwdPass, ExtractPipelineFlowPass, ObserveStdoutRecordsPass};
use crate::support::{graph_backed_execution_resolve_records, stdin_observed_records};

pub(super) struct ObservedInput {
    pub scope: caushell_parse::ParsedCommandArtifact,
    pub bindings: SessionBindings,
    pub records: StdoutRecordsEvidence,
    pub direct_stdin: Option<String>,
    pub empty_nul_path_snapshot: bool,
}

#[derive(Default)]
pub(super) struct ObservedInputs {
    pub inputs: BTreeMap<NodeId, ObservedInput>,
    pub decoded: BTreeMap<NodeId, NativeInputDecodeEvidence>,
    pub effect_proofs: Vec<caushell_types::NativeInputEffectEvidence>,
}

/// A later effect audit may discharge only this consumer's byte-gap proposal.
/// Equal diagnostic text from a different consumer must retain its own floor.
pub(super) fn gap_source(node: &str) -> String { format!("resolve_native_inputs:{node}") }

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConsumerMode {
    Dispatch,
    Direct,
}

fn consumer_mode(
    registry: &ProfileRegistry,
    resolved: &ResolvedInvocationArtifact,
) -> Option<ConsumerMode> {
    let bound = &resolved.bound;
    if resolved.normalized_command_name == "xargs" && bound.form_id.as_str() == "dispatch_from_stdin" {
        return Some(ConsumerMode::Dispatch);
    }
    if resolved.proven_stream_contract().is_none()
        || registry
            .lookup(&resolved.normalized_command_name)
            .profile?
            .trust
            .source
            != ProfileSourceKind::BuiltIn
    {
        return None;
    }
    let reads_name_list = bound.payload_projections.iter().any(|projection| {
        matches!(
            projection.format,
            PayloadFormat::RenameArguments | PayloadFormat::RenamePerlArguments
        )
    }) && bound.bound_parameters.iter().any(|p| {
        p.payload_generated
            && p.values.iter().any(|value| {
                matches!(value, BoundValue::ImplicitInput { source: ImplicitInputSource::StdinData, .. })
            })
    });
    (reads_name_list || bound.effects.iter().any(|effect| effect.path_list.is_some()))
        .then_some(ConsumerMode::Direct)
}

fn direct_stdin(output: &StdoutRecordsEvidence) -> Option<String> {
    let records = output.complete_records()?;
    // Reordering blocks can change what a native consumer decodes as a
    // single path. Use exact byte order for the direct projection API.
    if output.order != caushell_types::StreamRecordOrder::Exact {
        return None;
    }
    String::from_utf8(records.iter().flat_map(|record| record.bytes.iter().copied()).collect()).ok()
}

// A limited producer observation may refine argv only when the original
// dispatch's effects are already closed and read-only.
fn has_closed_read_only_dispatch(
    ctx: &RunnerContext,
    registry: &caushell_profile::ProfileRegistry,
    consumer: &NodeId,
) -> bool {
    let records = ctx.execution_unit_resolve_records();
    let mut children = records.iter().filter(|record| {
        &record.parent_execution_node_id == consumer && &record.source_node_id != consumer
    }).peekable();
    children.peek().is_some() && children.all(|child| {
        let ResolveInvocationArtifactResult::Resolved(resolved) = &child.result else {
            return false;
        };
        child.origin_kind == ExecutionUnitOriginKind::StaticXargs
            && !resolved.bound.operation_semantics_unresolved
            && resolved.bound.residuals.is_empty()
            && resolved.bound.effects.iter().all(super::symbolic_native_inputs::read_effect)
            && !records.iter().any(|record| record.parent_execution_node_id == child.source_node_id)
            && registry.lookup(&resolved.normalized_command_name).profile.is_some_and(|profile| {
                profile.trust.source == caushell_profile::ProfileSourceKind::BuiltIn
                    && caushell_profile::native_effect_contract_is_closed_in_domain(
                        profile,
                        caushell_types::NativeArgvEffectEnvelope::ContentRead,
                        child.bindings.command_lookup_domain(),
                    )
            })
    })
}

// The native line output has one argv-safe path per record when its exact
// spelling contains no xargs separators, quoting, or option prefix.
fn has_plain_path_lines(output: &StdoutRecordsEvidence) -> bool {
    output.producer_contract_sha256.is_some()
        && output.records.iter().all(|record| {
            let path = &record.path_spelling;
            (path.starts_with("./") || path.starts_with('/'))
                && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
                && record.bytes.strip_suffix(b"\n") == Some(path.as_bytes())
        })
}

pub(super) fn prepare(
    session: SessionView<'_>,
    ctx: &RunnerContext,
    registry: &caushell_profile::ProfileRegistry,
) -> ObservedInputs {
    let mut result = ObservedInputs::default();
    if !ctx.execution_unit_resolve_records().iter().any(|r| matches!(&r.result,
        ResolveInvocationArtifactResult::Resolved(r) if r.bound.stdout_records.as_ref().is_some_and(|c| c.native.is_some()))) {
        return result;
    }
    let mut provisional = ctx.clone();
    ComputeEffectiveCwdPass.run(session, &mut provisional);
    ExtractPipelineFlowPass.run(session, &mut provisional);
    let consumers: BTreeMap<_, _> = provisional
        .execution_unit_resolve_records()
        .iter()
        .filter_map(|record| {
            let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
                return None;
            };
            Some((record.source_node_id.0.clone(), consumer_mode(registry, resolved)?))
        })
        .collect();
    if consumers.is_empty() {
        return result;
    }
    let mut deferred: BTreeSet<_> = consumers.keys().cloned().collect();
    // Only a candidate projection may defer unresolved descendants. Acceptance
    // later checks every final child effect and the unchanged producer evidence.
    loop {
        let before = deferred.len();
        for record in provisional.execution_unit_resolve_records() {
            if deferred.contains(&record.parent_execution_node_id.0) {
                deferred.insert(record.source_node_id.0.clone());
            }
        }
        if deferred.len() == before {
            break;
        }
    }
    let limits = super::observe_stdout_records::observe_outputs(
        &mut provisional,
        &deferred,
        &BTreeSet::new(),
        super::observe_stdout_records::ObservationPhase::Candidate,
    );
    let records = graph_backed_execution_resolve_records(&provisional);
    for &consumer in records
        .iter()
        .filter(|r| consumers.contains_key(&r.source_node_id().0))
    {
        if consumer.static_input_cwd_unproven() {
            continue;
        }
        let in_frame = |index| {
            records.iter().copied().find(|r| {
                r.command_index() == index
                    && r.parsed_scope() == consumer.parsed_scope()
                    && r.variable_frame() == consumer.variable_frame()
            })
        };
        let Some((mut output, forwarded)) = stdin_observed_records(
            consumer.parsed_scope(),
            consumer.command_index(),
            64,
            |i| match in_frame(i)?.result() {
                ResolveInvocationArtifactResult::Resolved(r) => Some(r.clone()),
                _ => None,
            },
            |i| {
                provisional.evidence.iter().find_map(|e| match &e.kind {
                    EvidenceKind::StdoutRecords(r)
                        if r.node_id == in_frame(i)?.source_node_id().0 =>
                    {
                        Some(r.clone())
                    }
                    _ => None,
                })
            },
        ) else {
            continue;
        };
        let metadata_limited = limits.metadata_limited.contains(&output.producer_node_id);
        let limited_observation_gap = if !output.missing_starting_point_observations.is_empty() {
            Some("missing producer starting points do not close consumer effects")
        } else if metadata_limited {
            Some("producer metadata tests do not close consumer effects")
        } else {
            None
        };
        let mode = consumers[&consumer.source_node_id().0];
        if mode == ConsumerMode::Direct {
            // Limited observations are insufficient to reduce a direct
            // consumer's side effects. Keep its original projection.
            if limited_observation_gap.is_none()
                && let Some(direct_stdin) = direct_stdin(&output)
            {
                result.inputs.insert(
                    consumer.source_node_id().clone(),
                    ObservedInput {
                        scope: consumer.parsed_scope().clone(),
                        bindings: consumer.bindings().clone(),
                        records: output,
                        direct_stdin: Some(direct_stdin),
                        empty_nul_path_snapshot: false,
                    },
                );
            }
            continue;
        }
        // A filesystem snapshot can narrow the observed argv without proving
        // dispatch effects. An empty snapshot can omit children. A line
        // stream can also lose filename boundaries when later input is split.
        let limited_dispatch_gap = limited_observation_gap.or_else(|| {
            if limits.output_unreachable.contains(&output.producer_node_id) {
                return None;
            }
            if output.records.is_empty() {
                return Some("empty producer snapshot does not close consumer effects");
            }
            let plain_path_dispatch = || {
                ctx.request().shell_state_before.execution_frame.is_some()
                    && forwarded.is_empty()
                    && matches!(consumer.result(), ResolveInvocationArtifactResult::Resolved(resolved)
                        if super::resolve_invocation::xargs_accepts_plain_path_lines(resolved))
                    && has_plain_path_lines(&output)
            };
            if output.encoding == Some(caushell_types::StreamRecordEncoding::Lines) && !plain_path_dispatch() {
                return Some("line-delimited path observations do not close consumer effects");
            }
            None
        });
        let mut empty_nul_path_snapshot = false;
        if output.complete
            && let Some(gap) = limited_dispatch_gap
            && !has_closed_read_only_dispatch(ctx, registry, consumer.source_node_id())
        {
            // A missing start still leaves the direct NUL path contract.
            // Retain the input gap and let the separate effect audit check
            // the static child, including any bounded metadata targets.
            empty_nul_path_snapshot = !metadata_limited
                && output.records.is_empty()
                && output.encoding == Some(caushell_types::StreamRecordEncoding::Nul)
                && output.producer_contract_sha256.is_some()
                && output.forwarded_by.is_empty();
            output.complete = false;
            output.records.clear();
            output.gap = Some(gap.into());
        }
        if !output.complete
            && let Some(proof) = super::symbolic_native_inputs::prove(
                ctx,
                registry,
                &consumer.source_node_id().0,
                &output.producer_node_id,
                output
                    .gap
                    .as_deref()
                    .unwrap_or("concrete input is unavailable"),
            )
        {
            result.effect_proofs.push(proof);
            continue;
        }
        result.inputs.insert(
            consumer.source_node_id().clone(),
            ObservedInput {
                scope: consumer.parsed_scope().clone(),
                bindings: consumer.bindings().clone(),
                records: output,
                direct_stdin: None,
                empty_nul_path_snapshot,
            },
        );
    }
    result
}

#[cfg(test)]
#[test]
fn candidate_refinement_keeps_the_consumer_frame() {
    use caushell_runner::{DirectoryRead, FilesystemView, PassRunner};
    use caushell_types::*;
    struct Files;
    impl FilesystemView for Files {
        fn entry(&self, path: &str) -> FilesystemEntry {
            if ["/", "/work", "/work/input"].contains(&path) {
                FilesystemEntry::Directory
            } else if path == "/work/input/a" {
                FilesystemEntry::File
            } else {
                FilesystemEntry::Missing
            }
        }
        fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
            let id = FileContentIdentity {
                device: 1,
                inode: 1,
                size: 0,
                modified_seconds: 0,
                modified_nanos: 0,
                changed_seconds: 0,
                changed_nanos: 0,
            };
            DirectoryRead::complete(
                self.source(),
                path,
                limits,
                id.clone(),
                vec![DirectoryEntry {
                    name: "a".into(),
                    kind: DirectoryEntryKind::File,
                    identity: id,
                }],
            )
        }
    }
    let mut profiles = caushell_profile::ProfileRegistry::built_in()
        .unwrap()
        .profiles()
        .to_vec();
    for (text, from, to) in [
        (
            include_str!("../../../caushell-profile/profiles/find.yaml"),
            "canonical_name: find",
            "canonical_name: fixture_walk",
        ),
        (
            include_str!("../../../caushell-profile/profiles/cp.yaml"),
            "canonical_name: cp",
            "canonical_name: fixture_copy",
        ),
    ] {
        profiles.push(
            caushell_profile::load_command_profile_from_str(&text.replace(from, to)).unwrap(),
        );
    }
    let registry = caushell_profile::ProfileRegistry::from_profiles(profiles).unwrap();
    for command in [
        "find input -name a | xargs -n1 cp source",
        "fixture_walk input -name a | xargs -n1 fixture_copy source",
    ] {
        let mut ctx = RunnerContext::new(CheckRequest {
            session_id: SessionId::new("s"),
            sequence_no: CommandSequenceNo(1),
            command: command.into(),
            shell_kind: ShellKind::Bash,
            shell_state_before: ShellStateSnapshot::new("/work"),
            home: None,
            workspace_root: Some("/work".into()),
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
            },
        });
        ctx.set_filesystem_view(std::sync::Arc::new(Files));
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(crate::ParseCommandPass);
        runner.register_session_transform_pass(crate::ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(crate::ResolveInvocationPass::new(registry.clone()));
        let graph = caushell_graph::SessionGraph::new();
        let summary = SessionSummary::default();
        let session = SessionView::new(&graph, &summary);
        runner.run(session, &mut ctx);
        let inputs = prepare(session, &ctx, &registry);
        assert!(!inputs.inputs.is_empty(), "no candidate: {ctx:#?}");
        assert!(
            ctx.evidence
                .iter()
                .any(|e| matches!(&e.kind, EvidenceKind::NativeInputDecode(d) if d.complete)),
            "candidate exists but no complete decoding: {ctx:#?}"
        );
    }
}

pub(super) fn accept(
    session: SessionView<'_>,
    ctx: &mut RunnerContext,
    input: &mut ObservedInputs,
) -> bool {
    if input.decoded.is_empty()
        || input.decoded.len() != input.inputs.len()
        || input.decoded.values().any(|d| !d.complete)
    {
        return false;
    }
    ComputeEffectiveCwdPass.run(session, ctx);
    ExtractPipelineFlowPass.run(session, ctx);
    for expected in input.inputs.values().map(|i| &i.records) {
        ctx.add_evidence(Evidence {
            rule_id: RuleId::SelectionError,
            summary: "candidate native input pending full effect and namespace revalidation".into(),
            kind: EvidenceKind::StdoutRecords(expected.clone()),
        });
    }
    ObserveStdoutRecordsPass.run(session, ctx);
    let mut accepted = true;
    for (node, decoded) in &mut input.decoded {
        let expected = input.inputs.get(node).map(|i| &i.records);
        let current = expected.and_then(|expected| {
            ctx.evidence.iter().find_map(|e| match &e.kind {
                EvidenceKind::StdoutRecords(p) if p.node_id == expected.node_id => Some(p),
                _ => None,
            })
        });
        if expected.is_none() || current != expected {
            accepted = false;
            decoded.complete = false;
            decoded.rejected_candidate_encoding = expected
                .filter(|output| output.complete && !output.records.is_empty())
                .and_then(|output| output.encoding);
            decoded.gap = Some(format!(
                "producer input revalidation failed: {}",
                current
                    .and_then(|p| p.gap.as_deref())
                    .unwrap_or("observation identity or content changed")
            ));
        }
    }
    accepted
}

pub(super) fn reject(
    ctx: &mut RunnerContext,
    input: &ObservedInputs,
    registry: &caushell_profile::ProfileRegistry,
) {
    for (node, proof) in &input.inputs {
        if proof.direct_stdin.is_some() {
            // A speculative direct refinement never replaces the ordinary
            // static projection when the final action does not revalidate.
            if let Some(decoded) = input.decoded.get(node).cloned() {
                ctx.add_evidence(Evidence {
                    rule_id: RuleId::SelectionError,
                    summary: "direct native input refinement rejected".into(),
                    kind: EvidenceKind::NativeInputDecode(decoded),
                });
            }
            continue;
        }
        if let Some(proof) = super::symbolic_native_inputs::prove(
            ctx,
            registry,
            &node.0,
            &proof.records.producer_node_id,
            "producer effects or observations changed during input refinement",
        ) {
            emit_proof(ctx, proof);
            continue;
        }
        let mut decoded =
            input
                .decoded
                .get(node)
                .cloned()
                .unwrap_or_else(|| NativeInputDecodeEvidence {
                    node_id: node.0.clone(),
                    producer_node_id: proof.records.node_id.clone(),
                    complete: false,
                    alternative_groups: 0,
                    gap: Some("consumer frame does not match the observed input".into()),
                    rejected_candidate_encoding: None,
                    empty_nul_path_snapshot: false,
                });
        decoded.complete = false;
        decoded.gap.get_or_insert_with(|| {
            "producer effects or observations changed during input refinement".into()
        });
        ctx.propose_decision(
            gap_source(&decoded.node_id),
            RuleId::SelectionError,
            Decision::NeedApproval,
            decoded.gap.as_deref().unwrap(),
        );
        ctx.add_evidence(Evidence {
            rule_id: RuleId::SelectionError,
            summary: "native input remains incomplete".into(),
            kind: EvidenceKind::NativeInputDecode(decoded),
        });
    }
}

pub(super) fn emit_proof(
    ctx: &mut RunnerContext,
    proof: caushell_types::NativeInputEffectEvidence,
) {
    ctx.add_evidence(Evidence {
        rule_id: RuleId::SelectionError,
        summary: "symbolic native input has closed typed child effects; concrete records remain unproved".into(),
        kind: EvidenceKind::NativeInputEffect(proof),
    });
}

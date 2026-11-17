use std::collections::{BTreeMap, BTreeSet};

use caushell_graph::NodeId;
use caushell_profile::{ResolveInvocationArtifactResult, SessionBindings};
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

// Producer failure can establish the bytes of a stream in this namespace.
// It cannot erase a consumer's potential writes, execution, or unproved
// controls by making its native invocation disappear or select a no-op form.
fn can_refine_from_missing_starting_points(
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
                    && super::symbolic_native_inputs::reader_profile(profile)
            })
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
    let consumers = provisional.execution_unit_resolve_records().iter().filter(|r| matches!(&r.result,
        ResolveInvocationArtifactResult::Resolved(r) if r.normalized_command_name.as_str() == "xargs" && r.bound.form_id.as_str() == "dispatch_from_stdin"))
        .map(|r| r.source_node_id.0.clone()).collect::<BTreeSet<_>>();
    if consumers.is_empty() {
        return result;
    }
    let mut deferred = consumers.clone();
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
    super::observe_stdout_records::observe_outputs(&mut provisional, &deferred, &BTreeSet::new(), super::observe_stdout_records::ObservationPhase::Candidate);
    let records = graph_backed_execution_resolve_records(&provisional);
    for &consumer in records
        .iter()
        .filter(|r| consumers.contains(&r.source_node_id().0))
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
        let Some((mut output, _)) = stdin_observed_records(
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
        if output.complete
            && !output.missing_starting_point_observations.is_empty()
            && !can_refine_from_missing_starting_points(ctx, registry, consumer.source_node_id())
        {
            output.complete = false;
            output.records.clear();
            output.gap = Some("missing producer starting points do not close consumer effects".into());
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

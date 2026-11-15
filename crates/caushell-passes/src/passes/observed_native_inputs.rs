use std::collections::{BTreeMap, BTreeSet};

use caushell_graph::NodeId;
use caushell_profile::{ResolveInvocationArtifactResult, SessionBindings};
use caushell_runner::{RunnerContext, SessionTransformPass, SessionView};
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
    super::observe_stdout_records::observe_outputs(&mut provisional, &deferred, &BTreeSet::new());
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
        let Some((output, _)) = stdin_observed_records(
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
    input: &ObservedInputs,
) -> bool {
    if input.decoded.is_empty()
        || input.decoded.len() != input.inputs.len()
        || input.decoded.values().any(|d| !d.complete)
    {
        return false;
    }
    ComputeEffectiveCwdPass.run(session, ctx);
    ExtractPipelineFlowPass.run(session, ctx);
    ObserveStdoutRecordsPass.run(session, ctx);
    input.decoded.iter().all(|(node, _)| {
        input.inputs.get(node).is_some_and(|input| {
            ctx.evidence
                .iter()
                .any(|e| matches!(&e.kind, EvidenceKind::StdoutRecords(p) if p == &input.records))
        })
    })
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
                });
        decoded.complete = false;
        decoded.gap.get_or_insert_with(|| {
            "producer effects or observations changed during input refinement".into()
        });
        ctx.propose_decision(
            "resolve_native_inputs",
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
        summary: "symbolic native input has closed read/data-only child effects; concrete records remain unproved".into(),
        kind: EvidenceKind::NativeInputEffect(proof),
    });
}

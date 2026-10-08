use caushell_graph::{EdgeKind, NodeId};
use caushell_profile::PathRole;
use caushell_query::IoTarget;
use caushell_runner::{PendingMutation, RunnerContext};
use caushell_types::{
    InlineShellContentCarrier, ProvenanceArtifact, ProvenanceConsumeKind, ProvenanceEdgeSemantics,
    ProvenanceProduceKind,
};

use super::ExecutionResolveRecordRef;

pub(crate) fn stream_provenance_mutations(
    ctx: &RunnerContext,
    record: Option<ExecutionResolveRecordRef<'_>>,
    source: &NodeId,
    target: &IoTarget,
    role: PathRole,
    slot: &str,
    command_name: Option<&str>,
) -> Vec<PendingMutation> {
    let (node_id, artifact) = match target {
        IoTarget::InheritedDescriptor { descriptor } => record
            .and_then(|record| crate::passes::inherited_pipeline_artifact(ctx, record, descriptor))
            .or_else(|| {
                crate::passes::inherited_process_substitution_artifact(ctx, source, descriptor)
            })
            .unwrap_or_else(|| descriptor_artifact(ctx, source, descriptor, false)),
        IoTarget::UnknownDescriptor { descriptor } => {
            descriptor_artifact(ctx, source, descriptor, true)
        }
        IoTarget::ProcessSubstitution { redirection_index } => {
            let Some(artifact) = crate::passes::redirection_process_substitution_artifact(
                ctx,
                source,
                *redirection_index,
            ) else {
                return Vec::new();
            };
            artifact
        }
        IoTarget::InlineContent { redirection_index } => {
            // A content write must not re-assert the original heredoc bytes as
            // its output. Only reads retain that known inline content.
            if role == PathRole::Write {
                return stream_provenance_mutations(
                    ctx,
                    record,
                    source,
                    &IoTarget::UnknownDescriptor {
                        descriptor: format!("inline-{redirection_index}"),
                    },
                    role,
                    slot,
                    command_name,
                );
            }
            let Some(redirection) = record
                .and_then(|record| record.parsed_scope().redirections.get(*redirection_index))
            else {
                return Vec::new();
            };
            let Some(content) = &redirection.content else {
                return Vec::new();
            };
            (
                NodeId::new(format!(
                    "artifact:inline-shell-content:{}:{redirection_index}",
                    source.0
                )),
                ProvenanceArtifact::InlineShellContent {
                    carrier: if redirection.kind == caushell_parse::RedirectionKind::HereDoc {
                        InlineShellContentCarrier::HereDoc
                    } else {
                        InlineShellContentCarrier::HereString
                    },
                    text: content.text.clone(),
                    quoted: content.quoted,
                    node_kind: content.node_kind.clone(),
                    version: ctx.request().sequence_no.0,
                },
            )
        }
        IoTarget::Path { .. } | IoTarget::Closed | IoTarget::Discard => return Vec::new(),
    };
    let (relation, semantics) = match role {
        PathRole::Read => (
            EdgeKind::Consumes,
            ProvenanceEdgeSemantics::Consume {
                consume_kind: ProvenanceConsumeKind::PathRead,
                slot_name: Some(slot.into()),
                normalized_command_name: command_name.map(str::to_string),
                domain_label: None,
            },
        ),
        PathRole::Write => (
            EdgeKind::Produces,
            ProvenanceEdgeSemantics::Produce {
                produce_kind: ProvenanceProduceKind::StreamWrite,
                slot_name: Some(slot.into()),
                normalized_command_name: command_name.map(str::to_string),
                domain_label: None,
            },
        ),
        _ => return Vec::new(),
    };
    vec![PendingMutation::AddProvenanceArtifact {
        source_node_id: source.clone(),
        node_id,
        artifact,
        relation,
        semantics,
    }]
}

fn descriptor_artifact(
    ctx: &RunnerContext,
    source: &NodeId,
    descriptor: &str,
    unresolved: bool,
) -> (NodeId, ProvenanceArtifact) {
    let scope = source.0.clone();
    (
        NodeId::new(format!(
            "artifact:descriptor-stream:{scope}:{descriptor}:{unresolved}"
        )),
        ProvenanceArtifact::DescriptorStream {
            scope,
            descriptor: descriptor.into(),
            unresolved,
            version: ctx.request().sequence_no.0,
        },
    )
}

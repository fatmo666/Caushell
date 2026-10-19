use caushell_graph::EdgeKind;
use caushell_runner::{PendingMutation, RunnerContext, SessionAnalysisPass, SessionView};
use caushell_types::{
    Evidence, EvidenceKind, ProvenanceDomainLabel, ProvenanceEdgeSemantics, RuleId, StreamGrowth,
    UnboundedFileWriteEvidence,
};

pub struct UnboundedFileWriteGuardPass;

impl SessionAnalysisPass for UnboundedFileWriteGuardPass {
    fn name(&self) -> &'static str {
        "unbounded_file_write_guard"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        let seeds: Vec<_> = ctx
            .pending_mutations()
            .iter()
            .filter_map(|m| match m {
                PendingMutation::AddProvenanceArtifact {
                    source_node_id,
                    node_id,
                    relation: EdgeKind::Produces,
                    semantics:
                        ProvenanceEdgeSemantics::Produce {
                            domain_label:
                                Some(ProvenanceDomainLabel::StreamOutput {
                                    growth: Some(StreamGrowth::Continuous { records }),
                                    ..
                                }),
                            ..
                        },
                    ..
                } => Some((source_node_id.clone(), node_id.clone(), *records)),
                _ => None,
            })
            .collect();
        if seeds.is_empty() {
            return;
        }
        let result = caushell_query::StreamGrowthQuery::default().execute(
            staged.graph(),
            ctx.request().sequence_no,
            seeds.clone(),
        );
        let action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::UnboundedFileWrite);
        let mut evidence: Vec<_> = result
            .writes
            .into_iter()
            .map(|write| UnboundedFileWriteEvidence {
                producer_node_id: write.producer.0,
                writer_node_id: Some(write.writer.0),
                path: Some(write.path),
                traversal_truncated: false,
            })
            .collect();
        if result.truncated {
            evidence.push(UnboundedFileWriteEvidence {
                producer_node_id: seeds[0].0.0.clone(),
                writer_node_id: None,
                path: None,
                traversal_truncated: true,
            });
        }
        for item in evidence {
            let reason = item.path.as_ref().map_or_else(
                || "continuous-output traversal exceeded its static budget".into(),
                |path| {
                    format!("continuous output can reach file {path} without a proven finite bound")
                },
            );
            ctx.add_evidence(Evidence {
                rule_id: RuleId::UnboundedFileWrite,
                summary: reason.clone(),
                kind: EvidenceKind::UnboundedFileWrite(item),
            });
            ctx.add_finding(RuleId::UnboundedFileWrite, reason.clone());
            if let Some(decision) = crate::support::decision_for_rule_action(action) {
                ctx.propose_decision(self.name(), RuleId::UnboundedFileWrite, decision, reason);
            }
        }
    }
}

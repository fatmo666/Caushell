//! Join admitted destructive effects to their already-resolved target facts.
use super::host_target_catalog::{HostTargetOperand, block_device_path_for_operand};
use super::resolved_sink::{
    ResolvedHostRiskSemanticClass, ResolvedHostRiskSink, admitted_host_risk_effects,
};
use super::semantic_rules::{CommandSinkReasonBuckets, collect_sink_reasons};
use crate::support::{is_file_write_redirection_operator, redirection_parent_command_index};
use caushell_parse::{RedirectionFact, RedirectionKind};
use caushell_profile::{
    CatastrophicSemanticClass, HostRiskSemanticClass, ResolveInvocationArtifactResult,
    SessionBindings,
};
use caushell_query::{PathTargetQuery, QuerySession};
use caushell_runner::RunnerContext;
use caushell_types::{PathTargetOperation, SemanticGapKind, SemanticResolution};
use std::collections::BTreeMap;

fn destructive_redirect(redirect: &RedirectionFact) -> bool {
    redirect.kind == RedirectionKind::File
        && redirect
            .operator
            .as_deref()
            .is_some_and(is_file_write_redirection_operator)
}

enum Contract<'a> {
    Redirect,
    Invocation {
        class: ResolvedHostRiskSemanticClass,
        name: &'a str,
    },
}

pub(crate) fn collect_resolved_device_target_reason_buckets(
    ctx: &RunnerContext,
    session: QuerySession<'_>,
) -> CommandSinkReasonBuckets {
    let mut contracts = BTreeMap::new();
    for record in ctx.execution_unit_resolve_records() {
        let parsed = &record.parsed_scope;
        for (index, redirect) in parsed.redirections.iter().enumerate() {
            if redirection_parent_command_index(parsed, redirect)
                == Some(record.command_ref.command_index)
                && destructive_redirect(redirect)
            {
                contracts.insert(
                    (record.source_node_id.0.clone(), format!("redirect:{index}")),
                    Contract::Redirect,
                );
            }
        }
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            continue;
        };
        for (index, _, class) in admitted_host_risk_effects(resolved) {
            if matches!(
                class,
                ResolvedHostRiskSemanticClass::Catastrophic(
                    CatastrophicSemanticClass::RawWriteTarget
                        | CatastrophicSemanticClass::FormatTarget
                        | CatastrophicSemanticClass::FilesystemSignatureWipeTarget
                        | CatastrophicSemanticClass::PartitionTableMutationTarget
                ) | ResolvedHostRiskSemanticClass::HostRisk(
                    HostRiskSemanticClass::PartitionLayoutMutationTarget
                        | HostRiskSemanticClass::PartitionTableSessionTarget
                        | HostRiskSemanticClass::PartitionTableStateMutationTarget
                )
            ) {
                contracts.insert(
                    (record.source_node_id.0.clone(), format!("effect:{index}")),
                    Contract::Invocation {
                        class,
                        name: &resolved.normalized_command_name,
                    },
                );
            }
        }
    }
    for scope in ctx.shell_redirection_scopes() {
        for unit in &scope.units {
            for &index in &unit.redirection_indexes {
                if scope
                    .parsed
                    .redirections
                    .get(index)
                    .is_some_and(destructive_redirect)
                {
                    contracts.insert(
                        (
                            unit.source_node_id.0.clone(),
                            format!("syntax-redirect:{index}"),
                        ),
                        Contract::Redirect,
                    );
                }
            }
        }
    }
    let mut buckets = CommandSinkReasonBuckets::default();
    let empty_bindings = SessionBindings::new();
    for fact in PathTargetQuery::new(ctx.request().sequence_no).execute(session) {
        if fact.operation != PathTargetOperation::Write {
            continue;
        }
        let Some(contract) = contracts.get(&(fact.source_node_id.clone(), fact.effect_key.clone()))
        else {
            continue;
        };
        let (value, lexical_only) = match &fact.resolution {
            SemanticResolution::Resolved { value } => (value, false),
            // Namespace uncertainty blocks grants. It does not erase the same
            // conservative conventional-device risk used for literal operands.
            // The lexical value has already passed shell/descriptor materialization;
            // never substitute unresolved operation text or guess a target.
            SemanticResolution::Unresolved { gap }
                if gap.kind == SemanticGapKind::NamespaceMutation =>
            {
                (&fact.lexical, true)
            }
            _ => continue,
        };
        let Some(path) = value.concrete_path() else {
            continue;
        };
        let Some(target) =
            block_device_path_for_operand(HostTargetOperand::literal_argv_data(path), None, None)
        else {
            continue;
        };
        let mut reasons = match contract {
            Contract::Redirect => CommandSinkReasonBuckets {
                floor_reasons: vec![format!(
                    "resolved destructive storage target {target} via shell redirection"
                )],
                ..Default::default()
            },
            Contract::Invocation { class, name } => collect_sink_reasons(
                ResolvedHostRiskSink {
                    semantic_class: *class,
                    target_operands: vec![HostTargetOperand::literal_argv_data(path)],
                    runtime_targets: Vec::new(),
                    normalized_command_name: name,
                },
                None,
                None,
                &empty_bindings,
            ),
        };
        if lexical_only {
            for reason in reasons
                .floor_reasons
                .iter_mut()
                .chain(reasons.partition_layout_mutation_reasons.iter_mut())
                .chain(reasons.partition_table_session_reasons.iter_mut())
                .chain(reasons.partition_table_state_mutation_reasons.iter_mut())
                .chain(reasons.partition_table_mutation_reasons.iter_mut())
            {
                reason.push_str(
                    " (conventional device namespace; canonical target remains unproved)",
                );
            }
        }
        buckets.extend(reasons);
    }
    buckets
}

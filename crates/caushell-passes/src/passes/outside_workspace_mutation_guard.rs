use std::collections::BTreeSet;

use caushell_profile::{ArgumentBindingSource, EffectKind, ResolveInvocationArtifactResult};
use caushell_runner::{
    EffectiveCwd, ExecutionUnitOriginKind, PathExemption, PathExemptionBasis, PathExemptionPolicy,
    PathOperation, RunnerContext, SessionAnalysisPass, SessionView,
};
use caushell_types::{
    DerivedPathRule, DerivedPathUnresolvedReason, MutationExemptionOperation,
    PathMetadataMutationKind, PathResolution, PathTargetAccess, PathTargetFact,
    PathTargetOperation, RuleId, SemanticGapKind, SemanticResolution,
};

use crate::path::namespace::NamespaceResolver;
use crate::support::{
    bound_invocation, decision_for_rule_action, is_file_write_redirection_operator,
};

pub struct OutsideWorkspaceMutationGuardPass;

impl SessionAnalysisPass for OutsideWorkspaceMutationGuardPass {
    fn name(&self) -> &'static str {
        "outside_workspace_mutation_guard"
    }

    fn run(&self, _session: SessionView<'_>, staged: SessionView<'_>, ctx: &mut RunnerContext) {
        let facts = caushell_query::PathTargetQuery::new(ctx.request().sequence_no)
            .execute(caushell_query::QuerySession::from_session(&staged));
        let declared = ctx.execution_unit_resolve_records().iter().any(|record| {
            bound_invocation(&record.result).is_some_and(|bound| {
                bound.effects.iter().any(|effect| {
                    super::resolve_path_targets::path_mutation_kind(effect.kind).is_some()
                        && !matches!(effect.target, caushell_profile::EffectTarget::None)
                })
            })
        }) || ctx.parsed_command().is_some_and(|parsed| {
            parsed.redirections.iter().any(|redirect| {
                redirect
                    .operator
                    .as_deref()
                    .is_some_and(|op| is_file_write_redirection_operator(op) || op == "<>")
            })
        });
        let mut reasons = BTreeSet::new();
        let missing_effect = ctx.execution_unit_resolve_records().iter().any(|record| {
            bound_invocation(&record.result).is_some_and(|bound| {
                bound.effects.iter().enumerate().any(|(index, effect)| {
                    super::resolve_path_targets::path_mutation_kind(effect.kind).is_some()
                        && !(effect.kind == EffectKind::MetadataMutation
                            && matches!(effect.target, caushell_profile::EffectTarget::None))
                        && !facts.iter().any(|fact| {
                            fact.source_node_id == record.source_node_id.0
                                && fact.effect_key == format!("effect:{index}")
                        })
                })
            })
        });
        if missing_effect || (declared && (facts.is_empty() || ctx.target_path_policy().is_none()))
        {
            reasons.insert("declared filesystem effects have no target-scope proof".to_string());
        }
        if let Some(policy) = ctx.target_path_policy() {
            for fact in facts
                .into_iter()
                .filter(|fact| fact.operation.is_mutation())
            {
                if fact.implicit_incidental_cache && fact.lexical.concrete_path().is_none() {
                    continue;
                }
                let resolution = match &fact.resolution {
                    SemanticResolution::NotApplicable { .. } => continue,
                    SemanticResolution::Unresolved { gap } => {
                        if gap.kind == SemanticGapKind::UnknownTarget
                            && ordinary_unzip_member_in_workspace(&fact, ctx, policy)
                        {
                            continue;
                        }
                        reasons.insert(format!(
                            "{} target for slot {} is unresolved ({:?}): {}",
                            mutation_name(fact.operation),
                            fact.slot_name,
                            gap.kind,
                            gap.detail
                        ));
                        continue;
                    }
                    SemanticResolution::Resolved { value } => value,
                };
                let operation = match fact.operation {
                    PathTargetOperation::Write => EffectKind::WritePath,
                    PathTargetOperation::Delete => EffectKind::DeletePath,
                    PathTargetOperation::MoveSource => EffectKind::MovePath,
                    PathTargetOperation::Metadata => EffectKind::MetadataMutation,
                    _ => continue,
                };
                let operation_scope = match exemption_operation_for_target(
                    operation,
                    fact.metadata_mutation.as_ref(),
                ) {
                    Some(MutationExemptionOperation::Write) => PathOperation::Write,
                    Some(MutationExemptionOperation::OrdinaryMetadata) => {
                        PathOperation::OrdinaryMetadata
                    }
                    Some(MutationExemptionOperation::PermissionMetadata) => {
                        PathOperation::PermissionMetadata
                    }
                    None => PathOperation::UnspecifiedMutation,
                };
                if !policy
                    .check_target(fact, operation_scope, RuleId::OutsideWorkspaceMutation)
                    .is_exempt()
                {
                    reasons.insert(format!(
                        "{} target for slot {} is outside the granted path scope or unproven: {:?}",
                        mutation_name(fact.operation),
                        fact.slot_name,
                        resolution
                    ));
                }
            }
        }
        let action = ctx
            .policy()
            .rule_policy
            .action_for(RuleId::OutsideWorkspaceMutation);
        for reason in reasons {
            ctx.add_finding(RuleId::OutsideWorkspaceMutation, reason.clone());
            if let Some(decision) = decision_for_rule_action(action) {
                ctx.propose_decision(
                    self.name(),
                    RuleId::OutsideWorkspaceMutation,
                    decision,
                    reason,
                );
            }
        }
    }
}

/// Decide the policy for default-directory extraction while retaining the
/// unresolved member paths for other rules and later commands.
fn ordinary_unzip_member_in_workspace(
    fact: &PathTargetFact,
    ctx: &RunnerContext,
    policy: &PathExemptionPolicy,
) -> bool {
    if fact.operation != PathTargetOperation::Write
        || !matches!(
            &fact.lexical,
            PathResolution::DerivedUnresolved {
                rule: DerivedPathRule::ArchiveMembers,
                reason: DerivedPathUnresolvedReason::UnknownArchiveMembers,
                ..
            }
        )
    {
        return false;
    }
    let Some(record) = ctx.execution_unit_resolve_records().iter().find(|record| {
        record.source_node_id.0 == fact.source_node_id
            && record.origin_kind == ExecutionUnitOriginKind::TopLevel
    }) else {
        return false;
    };
    let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
        return false;
    };
    let bound = &resolved.bound;
    if resolved.normalized_command_name != "unzip"
        || bound.command_name.as_str() != "unzip"
        || bound.form_id.as_str() != "extract_archive"
        || bound.operation_semantics_unresolved
        || !bound.residuals.is_empty()
        || bound
            .applied_modifiers
            .iter()
            .any(|id| id.as_str() == "output_directory")
        || bound.owned_option_flags.iter().any(|flag| {
            matches!(
                flag,
                ArgumentBindingSource::FollowingFlag { flag_name, .. } if flag_name.as_str() == "-:"
            )
        })
        || bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ExecutePayload)
    {
        return false;
    }
    let Some(cwd) = ctx
        .execution_cwd_for_node(&record.source_node_id)
        .and_then(EffectiveCwd::as_known)
    else {
        return false;
    };
    let (resolution, _) =
        NamespaceResolver::new(ctx.filesystem_view()).resolve(cwd, PathTargetAccess::Follow);
    matches!(
        resolution,
        SemanticResolution::Resolved { value }
            if policy.check(&value, PathOperation::Write, RuleId::OutsideWorkspaceMutation)
                == (PathExemption::Exempt { basis: PathExemptionBasis::Workspace })
    )
}

fn mutation_name(kind: caushell_types::PathTargetOperation) -> &'static str {
    match kind {
        caushell_types::PathTargetOperation::Write => "write",
        caushell_types::PathTargetOperation::Delete => "delete",
        caushell_types::PathTargetOperation::MoveSource => "move source",
        caushell_types::PathTargetOperation::Metadata => "metadata mutation",
        _ => unreachable!("mutation facts only"),
    }
}

fn exemption_operation_for_target(
    operation: EffectKind,
    mutation: Option<&caushell_types::PathMetadataMutation>,
) -> Option<MutationExemptionOperation> {
    if operation == EffectKind::WritePath {
        return Some(MutationExemptionOperation::Write);
    }
    let mutation = mutation?;
    if mutation.mutation_kinds.is_empty()
        || mutation
            .mutation_kinds
            .iter()
            .any(|kind| *kind == PathMetadataMutationKind::Generic)
    {
        return None;
    }
    if mutation
        .mutation_kinds
        .contains(&PathMetadataMutationKind::ChangeMode)
        && !mutation
            .raw_operand
            .as_deref()
            .is_some_and(ordinary_permission_mode)
    {
        Some(MutationExemptionOperation::PermissionMetadata)
    } else {
        Some(MutationExemptionOperation::OrdinaryMetadata)
    }
}

fn ordinary_permission_mode(mode: &str) -> bool {
    let numeric = mode.strip_prefix(['+', '-']).unwrap_or(mode);
    if !numeric.is_empty() && numeric.bytes().all(|b| matches!(b, b'0'..=b'7')) {
        return u32::from_str_radix(numeric, 8)
            .is_ok_and(|bits| bits <= 0o7777 && bits & 0o6000 == 0);
    }
    mode.split(',').all(|clause| {
        let bytes = clause.as_bytes();
        let mut index = 0;
        while index < bytes.len() && matches!(bytes[index], b'u' | b'g' | b'o' | b'a') {
            index += 1;
        }
        let mut saw_operation = false;
        while index < bytes.len() {
            let action = bytes[index];
            if !matches!(action, b'+' | b'-' | b'=') {
                return false;
            }
            saw_operation = true;
            index += 1;
            while index < bytes.len() && !matches!(bytes[index], b'+' | b'-' | b'=') {
                if !matches!(
                    bytes[index],
                    b'r' | b'w' | b'x' | b'X' | b's' | b't' | b'u' | b'g' | b'o'
                ) || (bytes[index] == b's' && action != b'-')
                {
                    return false;
                }
                index += 1;
            }
        }
        saw_operation
    })
}

#[cfg(test)]
mod exemption_tests {
    use super::*;
    use caushell_runner::PathExemptionPolicy;
    use caushell_types::{
        CommandSequenceNo, PathResolution, PathTargetAccess, PathTargetFact, PathTargetOperation,
        PolicyConfig, SemanticGap, SemanticGapKind, SemanticResolution,
    };

    #[test]
    fn permission_modes_preserve_special_and_unknown_boundaries() {
        for mode in [
            "600", "0755", "1755", "u+rw,g-w", "+x", "u-s", "a=rw", "u=g",
        ] {
            assert!(ordinary_permission_mode(mode), "{mode}");
        }
        for mode in [
            "4755", "2755", "6755", "u+s", "a=rwxs", "u+s,g-s", "$MODE", "garbage", "999", "",
            "600,",
        ] {
            assert!(!ordinary_permission_mode(mode), "{mode}");
        }
    }

    #[test]
    fn exemption_requires_every_known_bound_and_no_escape() {
        let policy = PathExemptionPolicy::new(Some("/workspace"), None, &PolicyConfig::default());
        let exempt = |resolution| {
            let fact = PathTargetFact {
                sequence_no: CommandSequenceNo::new(1),
                source_node_id: "command:1".into(),
                effect_key: "effect:0".into(),
                slot_name: "output".into(),
                operation: PathTargetOperation::Write,
                access: PathTargetAccess::Either,
                lexical: PathResolution::Concrete {
                    path: "/workspace/output".into(),
                },
                spelling: Some("/workspace/output".into()),
                resolution,
                observations: Vec::new(),
                namespace_proofs: Vec::new(),
                metadata_mutation: None,
                implicit_incidental_cache: false,
            };
            policy
                .check_target(
                    &fact,
                    PathOperation::Write,
                    RuleId::OutsideWorkspaceMutation,
                )
                .is_exempt()
        };
        let scope = |roots: &[&str], may_escape| PathResolution::BoundedPathSet {
            roots: roots.iter().map(|s| (*s).into()).collect(),
            may_escape,
        };
        assert!(exempt(SemanticResolution::Resolved {
            value: scope(&["/tmp/a", "/private/tmp/b", "/workspace/c"], false)
        }));
        for resolution in [
            scope(&[], false),
            scope(&["/tmp/a"], true),
            scope(&["/tmp/a", "/etc/b"], false),
            PathResolution::UnsupportedDynamicText {
                text: "/tmp/$UNKNOWN".into(),
            },
        ] {
            assert!(!exempt(SemanticResolution::Resolved { value: resolution }));
        }
        assert!(!exempt(SemanticResolution::Unresolved {
            gap: SemanticGap {
                kind: SemanticGapKind::FilesystemUnavailable,
                detail: "no view".into()
            }
        }));
        assert!(!exempt(SemanticResolution::NotApplicable {
            reason: "channel".into()
        }));
    }
}

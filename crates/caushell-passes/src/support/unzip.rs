use caushell_profile::{
    ArgumentBindingSource, BoundInvocation, EffectKind, ResolveInvocationArtifactResult,
};
use caushell_runner::{ExecutionUnitOriginKind, ExecutionUnitResolveRecord};
use caushell_types::{
    DerivedPathRule, DerivedPathUnresolvedReason, PathResolution, PathTargetFact,
    PathTargetOperation,
};

pub(crate) fn ordinary_extraction(record: &ExecutionUnitResolveRecord) -> Option<&BoundInvocation> {
    let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
        return None;
    };
    let bound = &resolved.bound;
    (record.origin_kind == ExecutionUnitOriginKind::TopLevel
        && resolved.normalized_command_name == "unzip"
        && bound.command_name.as_str() == "unzip"
        && bound.form_id.as_str() == "extract_archive"
        && !bound.operation_semantics_unresolved
        && bound.residuals.is_empty()
        && !bound.owned_option_flags.iter().any(|flag| {
            matches!(
                flag,
                ArgumentBindingSource::FollowingFlag { flag_name, .. } if flag_name.as_str() == "-:"
            )
        })
        && !bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ExecutePayload))
    .then_some(bound)
}

pub(crate) fn has_explicit_directory(bound: &BoundInvocation) -> bool {
    bound
        .applied_modifiers
        .iter()
        .any(|id| id.as_str() == "output_directory")
}

pub(crate) fn directory_write(fact: &PathTargetFact) -> bool {
    fact.operation == PathTargetOperation::Write && fact.slot_name == "extraction_directory"
}

pub(crate) fn unknown_member_write(fact: &PathTargetFact) -> bool {
    fact.operation == PathTargetOperation::Write
        && matches!(
            &fact.lexical,
            PathResolution::DerivedUnresolved {
                rule: DerivedPathRule::ArchiveMembers,
                reason: DerivedPathUnresolvedReason::UnknownArchiveMembers,
                ..
            }
        )
}

use super::*;

pub(super) fn readonly_scope(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    parsed: &caushell_parse::ParsedCommandArtifact,
    index: usize,
    bindings: &SessionBindings,
    substitution: Option<&str>,
) -> Result<(), String> {
    if !parsed.redirections.is_empty() {
        return Err("Python startup namespace has pending redirection effects".into());
    }
    let substitutions =
        caushell_parse::parse_command_substitutions(&parsed.raw_command, parsed.shell_kind)
            .map_err(|_| "Python startup shell scope is incomplete")?;
    if !substitutions.is_empty()
        && !(substitutions.len() == 1
            && substitution.is_some_and(|s| s.trim() == substitutions[0].body_text.trim()))
    {
        return Err("Python startup namespace has unproved sibling substitutions".into());
    }
    if !caushell_parse::parse_process_substitutions(&parsed.raw_command, parsed.shell_kind)
        .is_ok_and(|v| v.is_empty())
    {
        return Err("Python startup namespace has process substitutions".into());
    }
    let observations = source_scope_observations(
        registry,
        request,
        parsed,
        parsed.commands.len().saturating_sub(1),
        bindings,
    );
    if observations.len() != parsed.commands.len() {
        return Err("Python startup source scope budget exceeded".into());
    }
    for (i, (result, _)) in observations.iter().enumerate() {
        if i == index {
            continue;
        }
        let ResolveInvocationArtifactResult::Resolved(r) = result else {
            return Err("Python startup namespace has unknown preceding effects".into());
        };
        if r.bound.operation_semantics_unresolved
            || !r.bound.residuals.is_empty()
            || r.bound.effects.iter().any(|e| {
                !matches!(
                    e.kind,
                    EffectKind::ReadPath
                        | EffectKind::TargetPath
                        | EffectKind::ConsumeStdin
                        | EffectKind::TransformData
                        | EffectKind::ConsumeAuxiliaryValue
                        | EffectKind::ConsumeAuxiliaryEnvironment
                        | EffectKind::NetworkEndpoint
                        | EffectKind::SetCurrentWorkingDirectory
                        | EffectKind::SetExecutionWorkingDirectory
                )
            })
        {
            return Err("Python startup namespace may be modified within this action".into());
        }
    }
    Ok(())
}

pub(super) fn ancestors_stable(
    entry: &ExpandedFrontierEntry,
    request: &CheckRequest,
    records: &[ExecutionUnitResolveRecord],
) -> Result<(), String> {
    if entry.depth == 0 {
        return Ok(());
    }
    let mut parent = entry.parent_execution_node_id.clone();
    let mut before_parent = entry.origin_kind == ExecutionUnitOriginKind::CommandSubstitutionBody;
    for _ in 0..32 {
        if parent == caushell_runner::request_anchor_node_id(request) {
            return Ok(());
        }
        let record = records
            .iter()
            .find(|r| r.source_node_id == parent)
            .ok_or("Python startup ancestor namespace is unobserved")?;
        if !before_parent {
            let ResolveInvocationArtifactResult::Resolved(r) = &record.result else {
                return Err("Python startup ancestor effects are unknown".into());
            };
            if r.bound.operation_semantics_unresolved
                || !r.bound.residuals.is_empty()
                || r.bound.effects.iter().any(|e| {
                    !matches!(
                        e.kind,
                        EffectKind::ReadPath
                            | EffectKind::TargetPath
                            | EffectKind::DispatchCommand
                            | EffectKind::ConsumeStdin
                            | EffectKind::TransformData
                            | EffectKind::ConsumeAuxiliaryValue
                            | EffectKind::ConsumeAuxiliaryEnvironment
                            | EffectKind::SetExecutionWorkingDirectory
                    )
                })
            {
                return Err("Python startup ancestor may modify its namespace".into());
            }
        }
        if record.depth == 0 && record.parent_execution_node_id == record.source_node_id {
            return Ok(());
        }
        before_parent = false;
        parent = record.parent_execution_node_id.clone();
    }
    Err("Python startup ancestor budget exceeded".into())
}

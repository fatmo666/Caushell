use caushell_profile::{
    BoundInvocation, BoundValue, CatastrophicSemanticClass, EffectTarget, HostRiskSemanticClass,
    ResolvedInvocationArtifact, SemanticValueRef, SemanticValueResolution,
};

use super::host_target_catalog::HostTargetOperand;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedHostRiskSemanticClass {
    Catastrophic(CatastrophicSemanticClass),
    HostRisk(HostRiskSemanticClass),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedHostRiskSink<'a> {
    pub semantic_class: ResolvedHostRiskSemanticClass,
    pub target_operands: Vec<HostTargetOperand<'a>>,
    pub runtime_targets: Vec<ResolvedRuntimeHostTarget>,
    pub normalized_command_name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedRuntimeHostTarget {
    pub source: caushell_profile::ImplicitInputSource,
    pub domain: Option<caushell_types::RuntimeArgumentDomain>,
}

pub(crate) fn each_resolved_host_risk_sink<'a, F>(
    resolved: &'a ResolvedInvocationArtifact,
    mut visit: F,
) where
    F: FnMut(ResolvedHostRiskSink<'a>),
{
    let mut emitted: Vec<(ResolvedHostRiskSemanticClass, &'a str)> = Vec::new();

    for effect in &resolved.bound.effects {
        let Some(slot_name) = slot_name_from_effect_target(&effect.target) else {
            continue;
        };
        let Some(semantic_class) = effect_semantic_class(effect) else {
            continue;
        };
        if !required_modifiers_satisfied(resolved, effect) {
            continue;
        }
        let target_operands = bound_argument_operands_for_slot(&resolved.bound, slot_name);
        let runtime_targets = bound_runtime_targets_for_slot(&resolved.bound, slot_name);
        if target_operands.is_empty() && runtime_targets.is_empty() {
            continue;
        }
        if emitted.iter().any(|(seen_class, seen_slot_name)| {
            *seen_class == semantic_class && *seen_slot_name == slot_name
        }) {
            continue;
        }

        emitted.push((semantic_class.clone(), slot_name));
        visit(ResolvedHostRiskSink {
            semantic_class,
            target_operands,
            runtime_targets,
            normalized_command_name: resolved.normalized_command_name.as_str(),
        });
    }
}

/// Configured targets have already-decoded, statically resolved path semantics.
/// Relative targets cannot be certified when cwd is unknown. No host lookup is
/// performed and an unresolved target never becomes a hard-deny proof.
pub(crate) fn each_configured_host_risk_sink(
    record: crate::support::ExecutionResolveRecordRef<'_>,
    cwd: Option<&str>,
    home: Option<&str>,
    mut visit: impl FnMut(ResolvedHostRiskSink<'_>),
) {
    let caushell_profile::ResolveInvocationArtifactResult::Resolved(resolved) = record.result()
    else {
        return;
    };
    for effect in &resolved.bound.effects {
        let EffectTarget::ConfiguredPath(target) = &effect.target else {
            continue;
        };
        let Some(semantic_class) = effect_semantic_class(effect) else {
            continue;
        };
        if !required_modifiers_satisfied(resolved, effect) {
            continue;
        }
        let Some(path) = crate::path::resolve_configured_path(
            &resolved.bound,
            target,
            cwd.unwrap_or("/"),
            home,
            Some(record),
        ) else {
            continue;
        };
        if cwd.is_none() && path.cwd_dependent {
            continue;
        }
        let Some(path) = path.resolution.concrete_path() else {
            continue;
        };
        visit(ResolvedHostRiskSink {
            semantic_class,
            target_operands: vec![HostTargetOperand::literal_argv_data(path)],
            runtime_targets: Vec::new(),
            normalized_command_name: resolved.normalized_command_name.as_str(),
        });
    }
}

fn bound_runtime_targets_for_slot(
    bound: &BoundInvocation,
    slot_name: &str,
) -> Vec<ResolvedRuntimeHostTarget> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot_name)
        .flat_map(|parameter| parameter.semantic_values())
        .filter_map(|value| match value {
            SemanticValueRef::Original(BoundValue::ImplicitInput { source, domain, .. }) => {
                Some(ResolvedRuntimeHostTarget {
                    source: source.clone(),
                    domain: domain.clone(),
                })
            }
            SemanticValueRef::Projected {
                source: BoundValue::ImplicitInput { source, .. },
                ..
            } => Some(ResolvedRuntimeHostTarget {
                source: source.clone(),
                // Bounds on a whole operand do not bound a substring.
                domain: None,
            }),
            _ => None,
        })
        .collect()
}

fn slot_name_from_effect_target(target: &EffectTarget) -> Option<&str> {
    match target {
        EffectTarget::Slot(slot_name) => Some(slot_name.as_str()),
        _ => None,
    }
}

fn required_modifiers_satisfied(
    resolved: &ResolvedInvocationArtifact,
    effect: &caushell_profile::Effect,
) -> bool {
    effect_required_modifiers(effect)
        .iter()
        .all(|required_modifier| {
            resolved
                .bound
                .applied_modifiers
                .iter()
                .any(|modifier| modifier == required_modifier)
        })
}

fn effect_semantic_class(
    effect: &caushell_profile::Effect,
) -> Option<ResolvedHostRiskSemanticClass> {
    effect
        .catastrophic
        .semantic_class
        .map(ResolvedHostRiskSemanticClass::Catastrophic)
        .or_else(|| {
            effect
                .host_risk
                .semantic_class
                .map(ResolvedHostRiskSemanticClass::HostRisk)
        })
}

fn effect_required_modifiers(effect: &caushell_profile::Effect) -> &[caushell_profile::ModifierId] {
    if effect.catastrophic.semantic_class.is_some() {
        &effect.catastrophic.required_modifiers
    } else {
        &effect.host_risk.required_modifiers
    }
}

pub(crate) fn bound_argument_operands_for_slot<'a>(
    bound: &'a BoundInvocation,
    slot_name: &str,
) -> Vec<HostTargetOperand<'a>> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot_name)
        .flat_map(|parameter| parameter.semantic_values())
        .filter_map(|value| match value {
            SemanticValueRef::Original(BoundValue::Argument {
                text,
                quoted,
                node_kind,
                ..
            }) => Some(HostTargetOperand {
                text: text.as_str(),
                quoted: *quoted,
                node_kind: node_kind.as_str(),
                literal_argv_data: false,
            }),
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(text) => {
                    Some(HostTargetOperand::literal_argv_data(text))
                }
                SemanticValueResolution::Unknown(_) => None,
            },
            SemanticValueRef::Original(BoundValue::ImplicitInput { .. }) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{bound_argument_operands_for_slot, bound_runtime_targets_for_slot};
    use caushell_profile::{
        ArgumentBindingSource, BoundInvocation, BoundParameter, BoundValue, CommandName, FormId,
        ImplicitInputSource, SemanticType, SlotName,
    };

    #[test]
    fn target_projection_keeps_runtime_source_distinct_from_literal_arguments() {
        let literal = BoundValue::argument(
            "/dev/sda",
            false,
            caushell_parse::SourceSpan {
                start_byte: 0,
                end_byte: 8,
                start_row: 0,
                start_column: 0,
                end_row: 0,
                end_column: 8,
            },
            ArgumentBindingSource::RemainingArg,
        );
        let runtime = BoundValue::ImplicitInput {
            source: ImplicitInputSource::StdinData,
            origin: None,
            domain: Some(caushell_types::RuntimeArgumentDomain::Unbounded),
        };
        let bound = BoundInvocation::new(CommandName::new("dd"), FormId::new("write"))
            .with_bound_parameter(
                BoundParameter::new(SlotName::new("target"), SemanticType::PlainValue)
                    .with_value(literal)
                    .with_value(runtime),
            );

        let operands = bound_argument_operands_for_slot(&bound, "target");
        assert_eq!(operands.len(), 1);
        assert_eq!(operands[0].text, "/dev/sda");

        let runtime_targets = bound_runtime_targets_for_slot(&bound, "target");
        assert_eq!(runtime_targets.len(), 1);
        assert_eq!(runtime_targets[0].source, ImplicitInputSource::StdinData);
        assert_eq!(
            runtime_targets[0].domain,
            Some(caushell_types::RuntimeArgumentDomain::Unbounded)
        );
    }
}

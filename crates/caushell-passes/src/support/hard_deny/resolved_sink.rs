use caushell_profile::{
    BoundInvocation, BoundValue, CatastrophicSemanticClass, EffectTarget, HostRiskSemanticClass,
    ResolvedInvocationArtifact,
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
    pub normalized_command_name: &'a str,
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
        if target_operands.is_empty() {
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
            normalized_command_name: resolved.normalized_command_name.as_str(),
        });
    }
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

fn bound_argument_operands_for_slot<'a>(
    bound: &'a BoundInvocation,
    slot_name: &str,
) -> Vec<HostTargetOperand<'a>> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot_name)
        .flat_map(|parameter| parameter.values.iter())
        .filter_map(|value| match value {
            BoundValue::Argument {
                text,
                quoted,
                node_kind,
                ..
            } => Some(HostTargetOperand {
                text: text.as_str(),
                quoted: *quoted,
                node_kind: node_kind.as_str(),
            }),
            BoundValue::ImplicitInput { .. } => None,
        })
        .collect()
}

//! Generic shell-variable destinations declared by runtime-input effects.
//! These are variable names, never shell code, paths, or guessed process IDs.
use crate::{
    BoundInvocation, EffectKind, EffectTarget, SemanticValueRef, SemanticValueResolution,
    ValueProjection, project_value,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeVariableWrites {
    pub names: Vec<String>,
    pub unresolved: bool,
}

pub fn runtime_variable_writes(bound: &BoundInvocation) -> RuntimeVariableWrites {
    let mut writes = RuntimeVariableWrites::default();
    for effect in &bound.effects {
        if effect.kind != EffectKind::BindVariableFromRuntimeInput {
            continue;
        }
        if let EffectTarget::VariableName(name) = &effect.target {
            if is_scalar_variable_name(name) {
                if !writes.names.contains(name) {
                    writes.names.push(name.clone());
                }
            } else {
                writes.unresolved = true;
            }
            continue;
        }
        let EffectTarget::Slot(slot) = &effect.target else {
            writes.unresolved = true;
            continue;
        };
        let Some(parameter) = bound.bound_parameters.iter().find(|p| p.name == *slot) else {
            writes.unresolved = true;
            continue;
        };
        let mut any = false;
        for value in parameter.semantic_values() {
            any = true;
            let resolution = match value {
                SemanticValueRef::Original(source) => {
                    project_value(&ValueProjection::Identity, source)
                }
                SemanticValueRef::Projected { value, .. } => Some(value.resolution.clone()),
            };
            if let Some(SemanticValueResolution::Known(name)) = resolution
                && is_scalar_variable_name(&name)
            {
                if !writes.names.contains(&name) {
                    writes.names.push(name);
                }
            } else {
                writes.unresolved = true;
            }
        }
        writes.unresolved |= !any;
    }
    writes
}

pub(crate) fn is_scalar_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|c| c == b'_' || c.is_ascii_alphabetic())
        && bytes.all(|c| c == b'_' || c.is_ascii_alphanumeric())
}

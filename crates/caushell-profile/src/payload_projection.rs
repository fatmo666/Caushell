//! Opt-in data-protocol projections. No command names, execution or disk reads.
use crate::{
    BoundInvocation, BoundParameter, BoundValue, ImplicitInputSource, PathPurpose, PathRole,
    PathSemantic, PayloadFormat, PayloadInputSource, ProjectedSemanticValue,
    ProjectionUnknownReason, SemanticType, SemanticValueResolution, SlotName, ValueProjection,
    project_value,
};

/// `complete_stdin` must describe the complete effective stdin stream, not a
/// known prefix/fragment. None keeps unknown writes/deletions for existing guards.
pub fn refresh_payload_projections(bound: &mut BoundInvocation, complete_stdin: Option<&str>) {
    if bound.payload_projections.is_empty() {
        return;
    }
    bound.bound_parameters.retain(|p| !p.payload_generated);
    let mut generated = Vec::new();
    for projection in &bound.payload_projections {
        let (source, resolution) = match &projection.source {
            PayloadInputSource::Slot(slot) => {
                let parameter = bound.bound_parameters.iter().find(|p| p.name == *slot);
                let values = parameter.map(|p| p.values.as_slice()).unwrap_or(&[]);
                let source = values.first().cloned().unwrap_or_else(missing_input);
                let resolution = if values.len() != 1 {
                    Err(ProjectionUnknownReason::InvalidPayload)
                } else if matches!(&source, BoundValue::Argument { text, .. } if text.len() > projection.max_bytes)
                {
                    Err(ProjectionUnknownReason::PayloadBudgetExceeded)
                } else {
                    match project_value(&ValueProjection::Identity, &source) {
                        Some(SemanticValueResolution::Known(text)) => Ok(text),
                        Some(SemanticValueResolution::Unknown(reason)) => Err(reason),
                        None => Err(ProjectionUnknownReason::PayloadUnavailable),
                    }
                };
                (source, resolution)
            }
            PayloadInputSource::Stdin => {
                if let Some(text) = complete_stdin {
                    let resolution = if text.len() > projection.max_bytes {
                        Err(ProjectionUnknownReason::PayloadBudgetExceeded)
                    } else {
                        Ok(text.to_string())
                    };
                    // Preserve the real stdin origin, not fabricated argv spans.
                    // Its source stream is already represented by Graph evidence.
                    (missing_input(), resolution)
                } else {
                    (
                        missing_input(),
                        Err(ProjectionUnknownReason::PayloadUnavailable),
                    )
                }
            }
        };
        let targets = resolution.and_then(|text| match projection.format {
            PayloadFormat::CodexApplyPatch => {
                crate::patch_payload::decode(&text, projection.max_bytes, projection.max_operations)
            }
        });
        let (reads, writes, deletes) = match targets {
            Ok(targets) => (
                targets
                    .reads
                    .into_iter()
                    .map(SemanticValueResolution::Known)
                    .collect(),
                targets
                    .writes
                    .into_iter()
                    .map(SemanticValueResolution::Known)
                    .collect(),
                targets
                    .deletes
                    .into_iter()
                    .map(SemanticValueResolution::Known)
                    .collect(),
            ),
            Err(reason) => {
                let unknown = vec![SemanticValueResolution::Unknown(reason)];
                (unknown.clone(), unknown.clone(), unknown)
            }
        };
        for (name, role, values) in [
            (&projection.reads, PathRole::Read, reads),
            (&projection.writes, PathRole::Write, writes),
            (&projection.deletes, PathRole::Target, deletes),
        ] {
            generated.push(target_parameter(name, role, &source, values));
        }
    }
    bound.bound_parameters.extend(generated);
}

fn missing_input() -> BoundValue {
    BoundValue::ImplicitInput {
        source: ImplicitInputSource::StdinData,
        domain: None,
    }
}

fn target_parameter(
    name: &SlotName,
    role: PathRole,
    source: &BoundValue,
    resolutions: Vec<SemanticValueResolution>,
) -> BoundParameter {
    let mut parameter = BoundParameter::new(
        name.clone(),
        SemanticType::Path(PathSemantic {
            role,
            purpose: Some(PathPurpose::GenericOperand),
        }),
    );
    // One source copy per effect class, never one full patch copy per file.
    parameter.values.push(source.clone());
    parameter.projected_values = Some(
        resolutions
            .into_iter()
            .map(|resolution| ProjectedSemanticValue {
                source_index: 0,
                resolution,
            })
            .collect(),
    );
    parameter.payload_generated = true;
    parameter
}

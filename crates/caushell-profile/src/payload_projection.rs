//! Opt-in data-protocol projections. No command names, execution or disk reads.
use crate::{
    BoundInvocation, BoundParameter, BoundValue, ImplicitInputSource, PathPurpose, PathRole,
    PathSemantic, PayloadFormat, PayloadInputSource, PayloadLanguage, PayloadSemantic,
    PayloadSource, ProjectedSemanticValue, ProjectionUnknownReason, SemanticType,
    SemanticValueResolution, SlotName, ValueProjection, project_value,
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
        let mut sources = match &projection.source {
            PayloadInputSource::Slot(slot) => {
                let parameter = bound.bound_parameters.iter().find(|p| p.name == *slot);
                parameter
                    .map(|p| p.values.clone())
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| vec![missing_input()])
            }
            PayloadInputSource::Stdin => vec![missing_input()],
        };
        let targets = decode_targets(projection, &sources, complete_stdin);
        let (reads, mut writes, deletes, executions) = match targets {
            Ok(targets) => (
                targets.reads,
                targets.writes,
                targets.deletes,
                targets.executions,
            ),
            Err(reason) => {
                let unknown = vec![(0, SemanticValueResolution::Unknown(reason))];
                let deletes = if projection.format == PayloadFormat::CodexApplyPatch {
                    unknown.clone()
                } else {
                    Vec::new()
                };
                (unknown.clone(), unknown, deletes, vec![0])
            }
        };
        for control in &projection.write_controls {
            if let Some(parameter) = bound.bound_parameters.iter().find(|p| p.name == *control) {
                for value in &parameter.values {
                    let unknown = match tool_text(value, projection.format) {
                        Some(SemanticValueResolution::Known(_)) => None,
                        Some(SemanticValueResolution::Unknown(reason)) => Some(reason),
                        None => Some(ProjectionUnknownReason::PayloadUnavailable),
                    };
                    if let Some(reason) = unknown {
                        let index = sources.len();
                        sources.push(value.clone());
                        writes.push((index, SemanticValueResolution::Unknown(reason)));
                    }
                }
            }
        }
        for (name, role, values) in [
            (&projection.reads, PathRole::Read, reads),
            (&projection.writes, PathRole::Write, writes),
            (&projection.deletes, PathRole::Target, deletes),
        ] {
            generated.push(target_parameter(name, role, &sources, values));
        }
        if let Some(name) = &projection.executions {
            let mut p = BoundParameter::new(
                name.clone(),
                SemanticType::Payload(PayloadSemantic {
                    language: PayloadLanguage::Opaque,
                    source: PayloadSource::InlineString,
                    recursive: true,
                }),
            );
            // Do not invent shell text from sed's pattern space. The original
            // program/source is evidence of an opaque executable boundary.
            let indices = executions
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            p.values = indices.into_iter().map(|i| sources[i].clone()).collect();
            if p.values.is_empty() {
                p.projected_values = Some(Vec::new());
            }
            p.payload_generated = true;
            generated.push(p);
        }
    }
    bound.bound_parameters.extend(generated);
}

type Resolutions = Vec<(usize, SemanticValueResolution)>;
#[derive(Default)]
struct Targets {
    reads: Resolutions,
    writes: Resolutions,
    deletes: Resolutions,
    executions: Vec<usize>,
}

fn decode_targets(
    projection: &crate::PayloadProjection,
    sources: &[BoundValue],
    complete_stdin: Option<&str>,
) -> Result<Targets, ProjectionUnknownReason> {
    let mut text = String::new();
    let mut starts = Vec::new();
    if projection.source == PayloadInputSource::Stdin {
        let input = complete_stdin.ok_or(ProjectionUnknownReason::PayloadUnavailable)?;
        if input.len() > projection.max_bytes {
            return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
        }
        text.push_str(input);
        starts.push(0);
    } else {
        if projection.format == PayloadFormat::CodexApplyPatch && sources.len() != 1 {
            return Err(ProjectionUnknownReason::InvalidPayload);
        }
        for (i, source) in sources.iter().enumerate() {
            if matches!(source,BoundValue::Argument { text, .. } if text.len()>projection.max_bytes)
            {
                return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
            }
            let value = match tool_text(source, projection.format) {
                Some(SemanticValueResolution::Known(text)) => text,
                Some(SemanticValueResolution::Unknown(reason)) => return Err(reason),
                None => return Err(ProjectionUnknownReason::PayloadUnavailable),
            };
            let size = text
                .len()
                .checked_add(value.len())
                .and_then(|n| n.checked_add(usize::from(i > 0)));
            if size.is_none_or(|n| n > projection.max_bytes) {
                return Err(ProjectionUnknownReason::PayloadBudgetExceeded);
            }
            if i > 0 {
                text.push('\n');
            }
            starts.push(text.len());
            text.push_str(&value);
        }
    }
    let index = |offset| starts.partition_point(|s| *s <= offset).saturating_sub(1);
    match projection.format {
        PayloadFormat::CodexApplyPatch => {
            let t = crate::patch_payload::decode(
                &text,
                projection.max_bytes,
                projection.max_operations,
            )?;
            let known = |v: Vec<String>| {
                v.into_iter()
                    .map(|s| (0, SemanticValueResolution::Known(s)))
                    .collect()
            };
            Ok(Targets {
                reads: known(t.reads),
                writes: known(t.writes),
                deletes: known(t.deletes),
                executions: vec![],
            })
        }
        PayloadFormat::SedProgram => {
            let t =
                crate::sed_payload::decode(&text, projection.max_bytes, projection.max_operations)?;
            let known = |v: Vec<(usize, String)>| {
                v.into_iter()
                    .map(|(offset, s)| (index(offset), SemanticValueResolution::Known(s)))
                    .collect()
            };
            Ok(Targets {
                reads: known(t.reads),
                writes: known(t.writes),
                deletes: vec![],
                executions: t.executions.into_iter().map(index).collect(),
            })
        }
    }
}

fn tool_text(source: &BoundValue, format: PayloadFormat) -> Option<SemanticValueResolution> {
    match project_value(&ValueProjection::Identity, source) {
        Some(SemanticValueResolution::Unknown(ProjectionUnknownReason::EmptyValue))
            if format == PayloadFormat::SedProgram =>
        {
            Some(SemanticValueResolution::Known(String::new()))
        }
        other => other,
    }
}

fn missing_input() -> BoundValue {
    BoundValue::ImplicitInput {
        source: ImplicitInputSource::StdinData,
        domain: None,
        origin: None,
    }
}

fn target_parameter(
    name: &SlotName,
    role: PathRole,
    sources: &[BoundValue],
    resolutions: Resolutions,
) -> BoundParameter {
    let mut parameter = BoundParameter::new(
        name.clone(),
        SemanticType::Path(PathSemantic {
            role,
            purpose: Some(PathPurpose::GenericOperand),
        }),
    );
    // One source copy per effect class, never one full patch copy per file.
    parameter.values = sources.to_vec();
    parameter.projected_values = Some(
        resolutions
            .into_iter()
            .map(|(source_index, resolution)| ProjectedSemanticValue {
                source_index,
                resolution,
            })
            .collect(),
    );
    parameter.payload_generated = true;
    parameter
}

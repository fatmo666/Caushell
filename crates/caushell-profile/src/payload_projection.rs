//! Opt-in data-protocol projections. No command names, execution or disk reads.
use crate::{
    BoundInvocation, BoundParameter, BoundValue, ImplicitInputSource, PathPurpose, PathRole,
    PathSemantic, PayloadFormat, PayloadInputSource, PayloadLanguage, PayloadSemantic,
    PayloadSource, ProjectedSemanticValue, ProjectionUnknownReason, SemanticType,
    SemanticValueResolution, SlotName, ValueProjection, project_value,
};

#[cfg(test)]
mod move_slot_tests {
    use super::*;
    use crate::load_command_profile_from_str;

    const PROFILE: &str = include_str!("../profiles/apply_patch.yaml");
    const MOVE_EFFECT: &str = "      - kind: move_path\n        target: {kind: slot, name: patch_moves}\n        host_risk: {semantic_class: move_source_path}\n";

    #[test]
    fn move_slots_require_distinct_names_matching_effects_and_native_format() {
        for invalid in [
            PROFILE.replace(MOVE_EFFECT, ""),
            PROFILE.replace("moves: patch_moves", "moves: patch_reads"),
            PROFILE.replace("format: codex_apply_patch", "format: sed_program"),
        ] {
            assert!(load_command_profile_from_str(&invalid).is_err());
        }
        assert!(load_command_profile_from_str(PROFILE).is_ok());
    }

    #[test]
    fn native_moves_are_distinct_but_legacy_projection_retains_source_removal() {
        let profile = load_command_profile_from_str(PROFILE).unwrap();
        let mut projection = profile.forms[1].payload_projections[0].clone();
        let patch = "*** Begin Patch\n*** Update File: old\n*** Move to: new\n@@\n-x\n+y\n*** Delete File: gone\n*** End Patch";
        let targets = decode_targets(&projection, &[], Some(patch)).unwrap();
        assert_eq!(
            targets.deletes,
            vec![(0, SemanticValueResolution::Known("gone".into()))]
        );
        assert_eq!(
            targets.moves,
            vec![(0, SemanticValueResolution::Known("old".into()))]
        );
        projection.moves = None;
        let targets = decode_targets(&projection, &[], Some(patch)).unwrap();
        assert!(targets.moves.is_empty());
        assert_eq!(
            targets.deletes,
            vec![
                (0, SemanticValueResolution::Known("gone".into())),
                (0, SemanticValueResolution::Known("old".into()))
            ]
        );
        let legacy = PROFILE
            .replace("        moves: patch_moves\n", "")
            .replace(MOVE_EFFECT, "");
        assert!(load_command_profile_from_str(&legacy).is_ok());
    }
}

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
        let (reads, mut writes, deletes, moves, executions, stdout_emissions) = match targets {
            Ok(targets) => (
                targets.reads,
                targets.writes,
                targets.deletes,
                targets.moves,
                targets.executions,
                targets.stdout_emissions,
            ),
            Err(reason) => {
                let unknown = vec![(0, SemanticValueResolution::Unknown(reason))];
                let deletes = if projection.format == PayloadFormat::CodexApplyPatch {
                    unknown.clone()
                } else {
                    Vec::new()
                };
                let moves = if projection.moves.is_some() {
                    unknown.clone()
                } else {
                    Vec::new()
                };
                (unknown.clone(), unknown, deletes, moves, vec![0], vec![0])
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
        if let Some(name) = &projection.moves {
            generated.push(target_parameter(name, PathRole::Target, &sources, moves));
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
            // Do not invent shell text from a tool program. The original
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
        if let Some(name) = &projection.stdout_emissions {
            let mut p = BoundParameter::new(name.clone(), SemanticType::PlainValue);
            let indices = stdout_emissions
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
    moves: Resolutions,
    executions: Vec<usize>,
    stdout_emissions: Vec<usize>,
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
            let mut t = crate::patch_payload::decode(
                &text,
                projection.max_bytes,
                projection.max_operations,
            )?;
            // Older profiles retain their conservative source-removal view.
            // Opt-in move slots use the existing relocation semantics instead.
            if projection.moves.is_none() {
                t.deletes.append(&mut t.moves);
            }
            let known = |v: Vec<String>| {
                v.into_iter()
                    .map(|s| (0, SemanticValueResolution::Known(s)))
                    .collect()
            };
            Ok(Targets {
                reads: known(t.reads),
                writes: known(t.writes),
                deletes: known(t.deletes),
                moves: known(t.moves),
                executions: vec![],
                stdout_emissions: vec![],
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
                moves: vec![],
                executions: t.executions.into_iter().map(index).collect(),
                stdout_emissions: t.stdout_emissions.into_iter().map(index).collect(),
            })
        }
        PayloadFormat::AwkProgram => {
            let t =
                crate::awk_payload::decode(&text, projection.max_bytes, projection.max_operations)?;
            let values = |v: Vec<(usize, Option<String>)>| {
                v.into_iter()
                    .map(|(offset, value)| {
                        (
                            index(offset),
                            value.map(SemanticValueResolution::Known).unwrap_or(
                                SemanticValueResolution::Unknown(
                                    ProjectionUnknownReason::DynamicArgument,
                                ),
                            ),
                        )
                    })
                    .collect()
            };
            Ok(Targets {
                reads: values(t.reads),
                writes: values(t.writes),
                deletes: vec![],
                moves: vec![],
                executions: t.executions.into_iter().map(index).collect(),
                stdout_emissions: t.stdout_emissions.into_iter().map(index).collect(),
            })
        }
    }
}

fn tool_text(source: &BoundValue, format: PayloadFormat) -> Option<SemanticValueResolution> {
    match project_value(&ValueProjection::Identity, source) {
        Some(SemanticValueResolution::Unknown(ProjectionUnknownReason::EmptyValue))
            if matches!(
                format,
                PayloadFormat::SedProgram | PayloadFormat::AwkProgram
            ) =>
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
                preserves_source: false,
                resolution,
            })
            .collect(),
    );
    parameter.payload_generated = true;
    parameter
}

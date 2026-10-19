use crate::{
    BoundValue, ResolvedInvocationArtifact, SemanticValueRef, SemanticValueResolution,
    StreamCountUnit, StreamGrowthContract, ValueProjection, project_semantic_value,
};
use caushell_types::{StreamGrowth, StreamRecordFraming};

impl ResolvedInvocationArtifact {
    pub fn proven_stdout_growth(&self) -> Option<StreamGrowth> {
        let contract = self.bound.stdout_growth.as_ref()?;
        let complete = self.bound.stdout_growth_complete && self.proven_stream_contract().is_some();
        let bound = &self.bound;
        match contract {
            StreamGrowthContract::Finite => complete.then_some(StreamGrowth::Finite),
            StreamGrowthContract::PreserveRecords { empty_slots } => (complete
                && slots_empty(self, empty_slots))
            .then_some(StreamGrowth::PreserveRecords),
            StreamGrowthContract::Continuous {
                records,
                required_modifier,
                finite_count_slots,
            } => {
                if required_modifier
                    .as_ref()
                    .is_some_and(|id| !bound.applied_modifiers.iter().any(|m| m.as_str() == id))
                {
                    return None;
                }
                if complete
                    && finite_count_slots
                        .iter()
                        .filter_map(|slot| last_count(self, slot))
                        .max_by_key(|(position, _)| *position)
                        .is_some_and(|(_, text)| finite_count(&text) == Some(false))
                {
                    return Some(StreamGrowth::Finite);
                }
                Some(StreamGrowth::Continuous {
                    records: if complete {
                        *records
                    } else {
                        StreamRecordFraming::Unknown
                    },
                })
            }
            StreamGrowthContract::Prefix {
                default_count,
                default_unit,
                counters,
                nul_modifier,
                record_bound_empty_slots,
            } => {
                if !complete {
                    return None;
                }
                let mut last = None;
                for counter in counters {
                    if let Some((position, text)) = last_count(self, &counter.slot) {
                        if last.as_ref().is_some_and(|(p, _, _)| position == *p) {
                            return None;
                        }
                        if last.as_ref().is_none_or(|(p, _, _)| position > *p) {
                            last = Some((position, text, counter.unit));
                        }
                    }
                }
                let (count, unit) = match last {
                    Some((_, text, unit)) => (finite_count(&text)?, unit),
                    None => (*default_count == 0, *default_unit),
                };
                if count || unit == StreamCountUnit::Bytes {
                    Some(StreamGrowth::Finite)
                } else if slots_empty(self, record_bound_empty_slots) {
                    Some(StreamGrowth::RecordPrefix {
                        records: if nul_modifier.as_ref().is_some_and(|id| {
                            bound.applied_modifiers.iter().any(|m| m.as_str() == id)
                        }) {
                            StreamRecordFraming::Nul
                        } else {
                            StreamRecordFraming::Lines
                        },
                    })
                } else {
                    None
                }
            }
        }
    }
}

fn slots_empty(resolved: &ResolvedInvocationArtifact, slots: &[String]) -> bool {
    slots.iter().all(|slot| {
        !resolved
            .bound
            .bound_parameters
            .iter()
            .any(|p| p.name.as_str() == slot && p.semantic_values().next().is_some())
    })
}

// Original owned occurrence order, not parameter declaration order. Unknown
// operands remain present, so they cannot reveal an earlier finite counter.
fn last_count(resolved: &ResolvedInvocationArtifact, slot: &str) -> Option<(usize, String)> {
    let parameter = resolved
        .bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == slot)?;
    parameter
        .semantic_values()
        .filter_map(|value| {
            let source = match value {
                SemanticValueRef::Original(s) | SemanticValueRef::Projected { source: s, .. } => s,
            };
            let BoundValue::Argument { span, .. } = source else {
                return None;
            };
            let text = match project_semantic_value(&ValueProjection::Identity, value) {
                Some(SemanticValueResolution::Known(text)) => text,
                _ => String::new(),
            };
            Some((span.start_byte, text))
        })
        .max_by_key(|(position, _)| *position)
}

/// A finite nonnegative counter. The boolean distinguishes zero from positive;
/// negative/all-but-last and unrecognized spellings supply no prefix bound.
fn finite_count(text: &str) -> Option<bool> {
    let text = text.strip_prefix('+').unwrap_or(text);
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let suffix = &text[digits..];
    if !matches!(
        suffix,
        "" | "b"
            | "kB"
            | "K"
            | "KB"
            | "KiB"
            | "M"
            | "MB"
            | "MiB"
            | "G"
            | "GB"
            | "GiB"
            | "T"
            | "TB"
            | "TiB"
            | "P"
            | "PB"
            | "PiB"
            | "E"
            | "EB"
            | "EiB"
            | "Z"
            | "ZB"
            | "ZiB"
            | "Y"
            | "YB"
            | "YiB"
            | "R"
            | "RB"
            | "RiB"
            | "Q"
            | "QB"
            | "QiB"
    ) {
        return None;
    }
    Some(text[..digits].bytes().all(|b| b == b'0'))
}

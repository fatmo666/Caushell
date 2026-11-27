//! Field and cardinality guarantees over newline-delimited stdout. Unknown
//! input bytes may influence record selection without influencing a field.
use crate::{
    ArgumentBindingSource, BoundValue, EnvironmentValueRef, ResolvedInvocationArtifact,
    SemanticValueResolution, SessionBindings, ValueProjection, project_value,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextRecordFields {
    DelimitedDecimalPrefix { delimiter: u8 },
    Decimal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextRecordStream {
    pub fields: TextRecordFields,
    pub max_records: Option<u64>,
}

impl ResolvedInvocationArtifact {
    /// The caller proves command identity and exclusive pipe ownership. This
    /// uses owned flags and the selected Profile, never a command-text match.
    pub fn proven_stdout_text_records(
        &self,
        input: Option<TextRecordStream>,
        bindings: &SessionBindings,
    ) -> Option<TextRecordStream> {
        self.proven_stream_contract()?;
        if let Some(limit) = self.proven_stdout_line_prefix_length() {
            let mut records = input?;
            records.max_records = Some(records.max_records.map_or(limit, |old| old.min(limit)));
            return Some(records);
        }
        match self.normalized_command_name.as_str() {
            "grep" if input.is_none() => self.grep_line_records(bindings),
            "cut" => self.cut_first_field(input?),
            _ => None,
        }
    }

    fn grep_line_records(&self, bindings: &SessionBindings) -> Option<TextRecordStream> {
        if !matches!(
            self.bound.form_id.as_str(),
            "positional_pattern_search" | "explicit_pattern_search"
        ) {
            return None;
        }
        let modifiers = &self.bound.applied_modifiers;
        if !modifiers
            .iter()
            .any(|modifier| modifier.as_str() == "line_number")
            || !modifiers.iter().all(|modifier| {
                matches!(
                    modifier.as_str(),
                    "line_number" | "as_text" | "regexp_dialect" | "inline_pattern"
                )
            })
        {
            return None;
        }
        // The observed variant denotes GNU grep with binary notices on stderr
        // and no GREP_OPTIONS support. Other implementations need an explicit
        // binary policy and known absence of injected options.
        let modern_gnu = bindings.native_variant("grep") == Some("gnu_grep_3_5_or_newer");
        if !modern_gnu
            && !(modifiers
                .iter()
                .any(|modifier| modifier.as_str() == "as_text")
                && matches!(
                    bindings.environment_value("GREP_OPTIONS"),
                    EnvironmentValueRef::Absent
                ))
        {
            return None;
        }
        let [path] = self.slot_values("input_paths")? else {
            return None;
        };
        let Some(SemanticValueResolution::Known(path)) =
            project_value(&ValueProjection::Identity, path)
        else {
            return None;
        };
        if path.is_empty() || path == "-" {
            return None;
        }
        Some(TextRecordStream {
            fields: TextRecordFields::DelimitedDecimalPrefix { delimiter: b':' },
            max_records: None,
        })
    }

    fn cut_first_field(&self, mut records: TextRecordStream) -> Option<TextRecordStream> {
        let TextRecordFields::DelimitedDecimalPrefix { delimiter } = records.fields else {
            return None;
        };
        if self.bound.form_id.as_str() != "select_fields_stdin"
            || self
                .slot_values("input_paths")
                .is_some_and(|paths| !paths.is_empty())
        {
            return None;
        }
        if !self
            .bound
            .applied_modifiers
            .iter()
            .all(|modifier| matches!(modifier.as_str(), "selection" | "delimiter"))
        {
            return None;
        }
        let (Some(selected), Some(separator)) = (
            self.single_option_value("selection_list", &["-f", "--fields"]),
            self.single_option_value("delimiter_value", &["-d", "--delimiter"]),
        ) else {
            return None;
        };
        if selected != "1" || separator.as_bytes() != [delimiter] {
            return None;
        }
        records.fields = TextRecordFields::Decimal;
        Some(records)
    }

    fn slot_values(&self, slot: &str) -> Option<&[BoundValue]> {
        self.bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == slot)
            .map(|p| p.values.as_slice())
    }

    fn single_option_value(&self, slot: &str, flags: &[&str]) -> Option<String> {
        let [
            value @ BoundValue::Argument {
                binding_source: ArgumentBindingSource::MatchedModifierFlag { flag_name, .. },
                ..
            },
        ] = self.slot_values(slot)?
        else {
            return None;
        };
        if !flags.contains(&flag_name.as_str()) {
            return None;
        }
        match project_value(&ValueProjection::Identity, value)? {
            SemanticValueResolution::Known(value) => Some(value),
            SemanticValueResolution::Unknown(_) => None,
        }
    }
}

//! Pure, opt-in operand projections. No command names, filesystem reads or
//! evaluation of shell/script payloads occur here.
use crate::{
    BoundArgumentMaterialization, BoundParameter, BoundValue, ProjectedSemanticValue,
    ProjectionAbsentPolicy, ProjectionUnknownReason, SemanticValueResolution, ValueProjection,
};

/// Rebuild only the semantic view. Raw values (and their source metadata) are
/// never edited. The resolver refreshes this view after materialization too.
pub fn refresh_parameter_semantic_values(parameter: &mut BoundParameter) {
    let Some(projection) = &parameter.value_projection else {
        parameter.projected_values = None;
        return;
    };
    parameter.projected_values = Some(
        parameter
            .values
            .iter()
            .enumerate()
            .filter_map(|(source_index, source)| {
                project_value(projection, source).map(|resolution| ProjectedSemanticValue {
                    source_index,
                    resolution,
                })
            })
            .collect(),
    );
}

pub fn project_value(
    projection: &ValueProjection,
    source: &BoundValue,
) -> Option<SemanticValueResolution> {
    let BoundValue::Argument {
        text,
        quoted,
        node_kind,
        materialization,
        ..
    } = source
    else {
        // A domain over the original operand is not automatically a domain over
        // a substring inside it. Do not inherit runtime path bounds.
        return Some(SemanticValueResolution::Unknown(
            ProjectionUnknownReason::DynamicArgument,
        ));
    };
    let (value, complete) = if !matches!(materialization, BoundArgumentMaterialization::Literal) {
        (text.clone(), true)
    } else {
        decode_argument_prefix(text, *quoted, node_kind)
    };
    // An unresolved unquoted expansion may introduce additional argv fields
    // and change parameter ownership. A static prefix alone cannot prove that
    // the currently bound operand represents all of those fields.
    if !complete && !(*quoted && node_kind == "string") {
        return Some(SemanticValueResolution::Unknown(
            ProjectionUnknownReason::DynamicArgument,
        ));
    }
    let selected = match projection {
        ValueProjection::TomlString { key } => {
            if !complete {
                return Some(SemanticValueResolution::Unknown(
                    ProjectionUnknownReason::DynamicArgument,
                ));
            }
            return match value.parse::<toml::Table>() {
                Ok(table) => table.get(key).map(|value| match value.as_str() {
                    Some(value) if !value.is_empty() => {
                        SemanticValueResolution::Known(value.into())
                    }
                    _ => SemanticValueResolution::Unknown(ProjectionUnknownReason::EmptyValue),
                }),
                // A file operand is not an explicit value for this setting.
                // Assignment-shaped or incomplete TOML stays unknown, not absent.
                Err(_) if value.contains('=') || value.starts_with('[') || value.is_empty() => {
                    Some(SemanticValueResolution::Unknown(
                        ProjectionUnknownReason::DynamicArgument,
                    ))
                }
                Err(_) => None,
            };
        }
        ValueProjection::Identity => {
            if !complete {
                return Some(SemanticValueResolution::Unknown(
                    ProjectionUnknownReason::DynamicArgument,
                ));
            }
            value.as_str()
        }
        ValueProjection::PrefixBefore {
            delimiter,
            if_absent,
        } => {
            if let Some((prefix, _)) = value.split_once(delimiter.as_str()) {
                prefix
            } else if complete && *if_absent == ProjectionAbsentPolicy::Original {
                value.as_str()
            } else {
                return Some(SemanticValueResolution::Unknown(if complete {
                    ProjectionUnknownReason::MissingDelimiter
                } else {
                    ProjectionUnknownReason::DynamicArgument
                }));
            }
        }
        ValueProjection::KeyValue { separator, key } => {
            let Some((actual_key, suffix)) = value.split_once(separator.as_str()) else {
                return Some(SemanticValueResolution::Unknown(if complete {
                    ProjectionUnknownReason::MissingDelimiter
                } else {
                    ProjectionUnknownReason::DynamicArgument
                }));
            };
            if actual_key != key {
                return None;
            }
            if !complete {
                return Some(SemanticValueResolution::Unknown(
                    ProjectionUnknownReason::DynamicArgument,
                ));
            }
            suffix
        }
    };
    Some(if selected.is_empty() {
        SemanticValueResolution::Unknown(ProjectionUnknownReason::EmptyValue)
    } else {
        SemanticValueResolution::Known(selected.to_string())
    })
}

/// Decode lexical shell quoting, stopping before the first unresolved fragment.
/// A completed delimiter in that static prefix can prove a key mismatch or a
/// prefix path. No characters after the unresolved fragment are inspected.
/// Raw/ANSI strings have already been decoded by the existing Bash parser.
pub(crate) fn decode_argument_prefix(text: &str, quoted: bool, node_kind: &str) -> (String, bool) {
    if matches!(node_kind, "raw_string" | "ansi_c_string") {
        return (text.to_string(), true);
    }
    if !matches!(node_kind, "word" | "number" | "string" | "concatenation") {
        return (String::new(), false);
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
    }
    let initial = if quoted && node_kind == "string" {
        Quote::Double
    } else {
        Quote::None
    };
    let mut quote = initial;
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match quote {
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                } else {
                    output.push(character);
                }
            }
            Quote::Double => match character {
                '"' if initial == Quote::None => quote = Quote::None,
                '$' if !dollar_starts_expansion(chars.clone(), true) => output.push('$'),
                '"' | '$' | '`' => return (output, false),
                '\\' => match chars.next() {
                    Some(escaped @ ('$' | '`' | '"' | '\\')) => output.push(escaped),
                    Some('\n') => {}
                    Some(other) => {
                        output.push('\\');
                        output.push(other);
                    }
                    None => return (output, false),
                },
                other => output.push(other),
            },
            Quote::None => match character {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => match chars.next() {
                    Some('\n') => {}
                    Some(other) => output.push(other),
                    None => return (output, false),
                },
                '$' if !dollar_starts_expansion(chars.clone(), false) => output.push('$'),
                '$' | '`' | '*' | '?' | '[' | '{' | '}' => return (output, false),
                '~' if output.is_empty() || output.ends_with('=') => return (output, false),
                other => output.push(other),
            },
        }
    }
    (output, quote == initial)
}

fn dollar_starts_expansion(
    mut remaining: std::iter::Peekable<std::str::Chars<'_>>,
    in_double_quotes: bool,
) -> bool {
    // Shell line continuations disappear before expansion recognition. Do not
    // mistake $ followed by backslash-newline and NAME/( for a literal anchor.
    while let Some(c) = remaining.next() {
        if c == '\\' && remaining.peek() == Some(&'\n') {
            remaining.next();
            continue;
        }
        return c.is_ascii_alphanumeric()
            || c == '_'
            || matches!(c, '{' | '(' | '[' | '$' | '!' | '?' | '#' | '-' | '@' | '*')
            || (!in_double_quotes && matches!(c, '\'' | '"'));
    }
    false
}

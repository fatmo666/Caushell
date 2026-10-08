use std::collections::BTreeMap;

use caushell_parse::{ParsedCommandArtifact, RedirectionFact, RedirectionKind};

use super::redirection_parent_command_index;

/// Origin of the final FD 0, after this command's redirections. This is a
/// syntax-only replay, not a probe of the shell's live descriptor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectiveStdinSource {
    Inherited,
    Redirect(usize),
    UnknownDescriptor(usize),
    Closed,
}

fn canonical_descriptor(text: &str) -> Option<&str> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let significant = text.trim_start_matches('0');
    Some(if significant.is_empty() {
        "0"
    } else {
        significant
    })
}

pub(crate) fn file_descriptor_targets_stdin(file_descriptor: Option<&str>) -> bool {
    file_descriptor.is_none_or(|descriptor| canonical_descriptor(descriptor) == Some("0"))
}

pub(crate) fn redirection_targets_stdin_payload(redirection: &RedirectionFact) -> bool {
    let operator = redirection.operator.as_deref().unwrap_or_default();
    // An output duplication defaults to FD 1, not FD 0.
    if redirection.file_descriptor.is_none() && operator.starts_with('>') {
        return false;
    }
    if !file_descriptor_targets_stdin(redirection.file_descriptor.as_deref()) {
        return false;
    }

    match redirection.kind {
        RedirectionKind::File => redirection.operator.as_deref().is_some_and(|operator| {
            matches!(
                operator,
                "<" | "<>" | "<&" | "<&-" | ">&" | ">&-" | ">" | ">>" | ">|"
            )
        }),
        RedirectionKind::HereString | RedirectionKind::HereDoc => true,
    }
}

pub(crate) fn effective_stdin_source(
    parsed: &ParsedCommandArtifact,
    command_index: usize,
) -> EffectiveStdinSource {
    let mut descriptors = BTreeMap::new();
    for (index, redirection) in parsed.redirections.iter().enumerate() {
        if redirection_parent_command_index(parsed, redirection) != Some(command_index) {
            continue;
        }
        let operator = redirection.operator.as_deref().unwrap_or_default();
        let descriptor = match redirection.file_descriptor.as_deref() {
            Some(text) => {
                let Some(descriptor) = canonical_descriptor(text) else {
                    continue;
                };
                descriptor
            }
            None if operator.starts_with('<') => "0",
            None if operator.starts_with('>') => "1",
            _ => continue,
        };
        let mut moved_descriptor = None;
        let origin =
            match operator {
                "<&-" | ">&-" => EffectiveStdinSource::Closed,
                "<&" | ">&" => {
                    match redirection
                        .target
                        .as_ref()
                        .map(|target| target.text.as_str())
                    {
                        Some("-") => EffectiveStdinSource::Closed,
                        Some(text) => {
                            let source = text.strip_suffix('-').unwrap_or(text);
                            match canonical_descriptor(source) {
                                Some(source) => {
                                    if source.len() != text.len() {
                                        moved_descriptor = Some(source);
                                    }
                                    descriptors.get(source).copied().unwrap_or_else(|| {
                                        if source == "0" {
                                            EffectiveStdinSource::Inherited
                                        } else {
                                            EffectiveStdinSource::UnknownDescriptor(index)
                                        }
                                    })
                                }
                                None => EffectiveStdinSource::UnknownDescriptor(index),
                            }
                        }
                        None => EffectiveStdinSource::UnknownDescriptor(index),
                    }
                }
                "<" | "<>" => {
                    if let Some(source) = redirection.target.as_ref().and_then(|token| {
                        caushell_query::IoTargetQuery::descriptor_alias(&token.text)
                    }) {
                        descriptors.get(source).copied().unwrap_or_else(|| {
                            if source == "0" {
                                EffectiveStdinSource::Inherited
                            } else {
                                EffectiveStdinSource::UnknownDescriptor(index)
                            }
                        })
                    } else {
                        EffectiveStdinSource::Redirect(index)
                    }
                }
                "<<" | "<<-" | "<<<" => EffectiveStdinSource::Redirect(index),
                // A write-only open is not evidence of readable file contents.
                ">" | ">>" | ">|" => EffectiveStdinSource::UnknownDescriptor(index),
                _ => continue,
            };
        descriptors.insert(descriptor, origin);
        if let Some(source) = moved_descriptor.filter(|source| *source != descriptor) {
            descriptors.insert(source, EffectiveStdinSource::Closed);
        }
    }
    descriptors
        .get("0")
        .copied()
        .unwrap_or(EffectiveStdinSource::Inherited)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(command: &str) -> EffectiveStdinSource {
        let parsed =
            caushell_parse::parse_command(command, caushell_types::ShellKind::Bash).unwrap();
        effective_stdin_source(&parsed, 0)
    }

    #[test]
    fn canonical_fd_zero_and_operator_defaults_are_distinct() {
        assert!(file_descriptor_targets_stdin(Some("000")));
        assert!(!file_descriptor_targets_stdin(Some("01")));
        assert!(!file_descriptor_targets_stdin(Some("$fd")));
        assert_eq!(source("sh >&2"), EffectiveStdinSource::Inherited);
        assert_eq!(
            source("sh 000<&2"),
            EffectiveStdinSource::UnknownDescriptor(0)
        );
        assert_eq!(source("sh 000<>input"), EffectiveStdinSource::Redirect(0));
    }

    #[test]
    fn descriptor_aliases_are_snapshots_not_forward_references() {
        assert_eq!(
            source("sh 3<<<'printf SAFE' 0<&3"),
            EffectiveStdinSource::Redirect(0)
        );
        assert_eq!(
            source("sh 0<&3 3<<<'printf SAFE'"),
            EffectiveStdinSource::UnknownDescriptor(0)
        );
        assert_eq!(
            source("sh <<<'printf SAFE' 0<&0"),
            EffectiveStdinSource::Redirect(0)
        );
        assert_eq!(source("sh 3<&0 0<&2 0<&3"), EffectiveStdinSource::Inherited);
    }

    #[test]
    fn closure_and_move_preserve_descriptor_state() {
        assert_eq!(source("sh 0<&-"), EffectiveStdinSource::Closed);
        assert_eq!(source("sh 0>&-"), EffectiveStdinSource::Closed);
        assert_eq!(source("sh 0<&0-"), EffectiveStdinSource::Inherited);
        assert_eq!(source("sh 3<&- 0<&3"), EffectiveStdinSource::Closed);
        assert_eq!(
            source("sh 3<<<'printf SAFE' 0<&3-"),
            EffectiveStdinSource::Redirect(0)
        );
        assert_eq!(
            source("sh 3<<<'printf SAFE' 0<&3- 0<&3"),
            EffectiveStdinSource::Closed
        );
    }
}

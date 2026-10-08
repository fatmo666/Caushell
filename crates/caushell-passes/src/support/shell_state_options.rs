//! One option interpretation for scalar overlays and function/session state.
//! The parser has already separated leading options from ordered operands.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportMode {
    Export,
    Unexport,
    Functions,
    Invalid,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsetMode {
    Default,
    Variables,
    Functions,
    Nameref,
    Invalid,
    Unresolved,
}

fn flags(options: &[String], allowed: &str) -> Result<Vec<char>, bool> {
    let mut result = Vec::new();
    for option in options {
        if option == "--" {
            continue;
        }
        if option.contains('$') || option.contains('`') || option.contains('\\') {
            return Err(false);
        }
        let Some(word) = option.strip_prefix('-').filter(|word| !word.is_empty()) else {
            return Err(false);
        };
        for flag in word.chars() {
            if !allowed.contains(flag) {
                return Err(true);
            }
            result.push(flag);
        }
    }
    Ok(result)
}

pub(crate) fn export_mode(options: &[String]) -> ExportMode {
    match flags(options, "fnp") {
        Ok(flags) if flags.contains(&'f') => ExportMode::Functions,
        Ok(flags) if flags.contains(&'n') => ExportMode::Unexport,
        Ok(_) => ExportMode::Export,
        Err(true) => ExportMode::Invalid,
        Err(false) => ExportMode::Unresolved,
    }
}

pub(crate) fn unset_mode(options: &[String]) -> UnsetMode {
    match flags(options, "fvn") {
        Ok(flags) if flags.contains(&'f') && flags.contains(&'v') => UnsetMode::Invalid,
        // Bash ignores -n when -f is present.
        Ok(flags) if flags.contains(&'f') => UnsetMode::Functions,
        Ok(flags) if flags.contains(&'n') => UnsetMode::Nameref,
        Ok(flags) if flags.contains(&'v') => UnsetMode::Variables,
        Ok(_) => UnsetMode::Default,
        Err(true) => UnsetMode::Invalid,
        Err(false) => UnsetMode::Unresolved,
    }
}

pub(crate) fn scalar_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

pub(crate) fn state_visible(scope: &Option<caushell_parse::SourceSpan>, target: usize) -> bool {
    scope
        .as_ref()
        .is_none_or(|s| target >= s.start_byte && target < s.end_byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_decode_clusters_terminators_and_invalid_forms() {
        let s = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        assert_eq!(export_mode(&s(&["-np", "--"])), ExportMode::Unexport);
        assert_eq!(export_mode(&s(&["-p"])), ExportMode::Export);
        assert_eq!(export_mode(&s(&["-fn"])), ExportMode::Functions);
        assert_eq!(export_mode(&s(&["-z"])), ExportMode::Invalid);
        assert_eq!(export_mode(&s(&["$option"])), ExportMode::Unresolved);
        assert_eq!(unset_mode(&s(&["-fn"])), UnsetMode::Functions);
        assert_eq!(unset_mode(&s(&["-v", "--"])), UnsetMode::Variables);
        assert_eq!(unset_mode(&s(&["-vf"])), UnsetMode::Invalid);
        assert_eq!(unset_mode(&s(&["-n"])), UnsetMode::Nameref);
    }
}

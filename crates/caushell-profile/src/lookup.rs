use crate::CommandProfile;

const POSIX_SYSTEM_COMMAND_PREFIXES: &[&str] = &[
    "/bin/",
    "/usr/bin/",
    "/usr/local/bin/",
    "/usr/ucb/",
    "/sbin/",
    "/usr/sbin/",
    "/opt/homebrew/bin/",
    "/opt/local/bin/",
];

const WINDOWS_COMMAND_SUFFIXES: &[&str] = &[".exe", ".com", ".cmd", ".bat"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileLookupResult {
    pub normalized_command_name: String,
    pub profile: Option<CommandProfile>,
}

pub fn lookup_command_profile<I>(command_name: &str, profiles: I) -> ProfileLookupResult
where
    I: IntoIterator<Item = CommandProfile>,
{
    let exact_normalized_command_name =
        normalize_command_name_without_family_coalescing(command_name);
    let coalesced_command_name = coalesce_command_family_name(&exact_normalized_command_name);
    let profiles: Vec<CommandProfile> = profiles.into_iter().collect();

    let exact_profile = profiles
        .iter()
        .find(|profile| profile.matches_name(&exact_normalized_command_name))
        .cloned();
    let normalized_profile = profiles
        .iter()
        .find(|profile| profile.matches_name(&coalesced_command_name))
        .cloned();
    let normalized_command_name = if exact_profile.is_some() {
        exact_normalized_command_name
    } else {
        coalesced_command_name
    };
    let profile = exact_profile.or(normalized_profile);

    ProfileLookupResult {
        normalized_command_name,
        profile,
    }
}

pub fn normalize_command_name(command_name: &str) -> String {
    coalesce_command_family_name(&normalize_command_name_without_family_coalescing(
        command_name,
    ))
}

pub(crate) fn normalize_command_name_without_family_coalescing(command_name: &str) -> String {
    if command_name.is_empty() {
        return String::new();
    }

    let mut normalized = command_name;

    if let Some(stripped) = normalized.strip_prefix('\\') {
        if stripped.chars().all(is_simple_command_char) {
            normalized = stripped;
        }
    }

    if is_windows_absolute_path(normalized) {
        return strip_windows_command_suffix(basename(normalized)).to_string();
    }

    if is_known_posix_system_command_path(normalized) {
        return basename(normalized).to_string();
    }

    normalized.to_string()
}

pub(crate) fn coalesce_command_family_name(name: &str) -> String {
    if name.starts_with("mkfs.") && name.len() > "mkfs.".len() {
        return match name {
            "mkfs.bfs" | "mkfs.cramfs" | "mkfs.minix" => name.to_string(),
            _ => "mkfs".to_string(),
        };
    }

    name.to_string()
}

fn is_simple_command_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')
}

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();

    path.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/'))
}

fn is_known_posix_system_command_path(path: &str) -> bool {
    POSIX_SYSTEM_COMMAND_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn basename(path: &str) -> &str {
    path.rsplit(|ch| ch == '/' || ch == '\\')
        .next()
        .unwrap_or(path)
}

fn strip_windows_command_suffix(name: &str) -> &str {
    for suffix in WINDOWS_COMMAND_SUFFIXES {
        if name.len() <= suffix.len() {
            continue;
        }

        let start = name.len() - suffix.len();
        let candidate = &name[start..];
        if candidate.eq_ignore_ascii_case(suffix) {
            return &name[..start];
        }
    }

    name
}

#[cfg(test)]
mod tests {
    use super::{lookup_command_profile, normalize_command_name, strip_windows_command_suffix};
    use crate::CommandProfile;

    fn test_profiles() -> Vec<CommandProfile> {
        vec![
            CommandProfile::new("cp").alias("copy"),
            CommandProfile::new("bash"),
            CommandProfile::new("tee"),
        ]
    }

    #[test]
    fn normalize_returns_empty_string_for_empty_input() {
        assert_eq!(normalize_command_name(""), "");
    }

    #[test]
    fn normalize_strips_leading_escape_for_simple_command_name() {
        assert_eq!(normalize_command_name(r"\cp"), "cp");
        assert_eq!(normalize_command_name(r"\bash"), "bash");
    }

    #[test]
    fn normalize_keeps_leading_escape_for_non_simple_command_name() {
        assert_eq!(normalize_command_name(r"\./cp"), r"\./cp");
        assert_eq!(normalize_command_name(r"\../bin/bash"), r"\../bin/bash");
    }

    #[test]
    fn normalize_extracts_basename_for_known_posix_system_paths() {
        assert_eq!(normalize_command_name("/bin/cp"), "cp");
        assert_eq!(normalize_command_name("/usr/bin/tee"), "tee");
        assert_eq!(normalize_command_name("/opt/homebrew/bin/bash"), "bash");
        assert_eq!(normalize_command_name("/sbin/mkfs.ext4"), "mkfs");
        assert_eq!(normalize_command_name("/usr/sbin/mkfs.bfs"), "mkfs.bfs");
    }

    #[test]
    fn normalize_keeps_non_whitelisted_posix_paths_unchanged() {
        assert_eq!(normalize_command_name("./cp"), "./cp");
        assert_eq!(normalize_command_name("../bin/bash"), "../bin/bash");
        assert_eq!(normalize_command_name("/tmp/custom/cp"), "/tmp/custom/cp");
    }

    #[test]
    fn normalize_coalesces_mkfs_family_names() {
        assert_eq!(normalize_command_name("mkfs"), "mkfs");
        assert_eq!(normalize_command_name("mkfs.ext4"), "mkfs");
        assert_eq!(normalize_command_name("mkfs.xfs"), "mkfs");
        assert_eq!(normalize_command_name("mkfs.bfs"), "mkfs.bfs");
        assert_eq!(normalize_command_name("mkfs.cramfs"), "mkfs.cramfs");
        assert_eq!(normalize_command_name("mkfs.minix"), "mkfs.minix");
        assert_eq!(normalize_command_name("mkswap"), "mkswap");
    }

    #[test]
    fn normalize_extracts_basename_for_windows_absolute_paths() {
        assert_eq!(
            normalize_command_name(r"C:\Windows\System32\bash.exe"),
            "bash"
        );
        assert_eq!(normalize_command_name(r"D:/Tools/rg.CmD"), "rg");
        assert_eq!(normalize_command_name(r"\\server\share\tee.BAT"), "tee");
    }

    #[test]
    fn normalize_keeps_non_absolute_windows_like_names_unchanged() {
        assert_eq!(normalize_command_name("bash.ExE"), "bash.ExE");
        assert_eq!(normalize_command_name("tools\\bash.exe"), "tools\\bash.exe");
    }

    #[test]
    fn strip_windows_command_suffix_supports_common_command_extensions() {
        assert_eq!(strip_windows_command_suffix("bash.exe"), "bash");
        assert_eq!(strip_windows_command_suffix("tool.CmD"), "tool");
        assert_eq!(strip_windows_command_suffix("script.BaT"), "script");
        assert_eq!(strip_windows_command_suffix("command.cOm"), "command");
    }

    #[test]
    fn strip_windows_command_suffix_keeps_non_matching_or_degenerate_names() {
        assert_eq!(strip_windows_command_suffix("archive.exec"), "archive.exec");
        assert_eq!(strip_windows_command_suffix(".exe"), ".exe");
        assert_eq!(strip_windows_command_suffix("cmd"), "cmd");
    }

    #[test]
    fn lookup_uses_normalized_name_for_primary_match() {
        let result = lookup_command_profile("/bin/cp", test_profiles());

        assert_eq!(result.normalized_command_name, "cp");
        assert_eq!(
            result.profile.as_ref().map(CommandProfile::primary_name),
            Some("cp")
        );
    }

    #[test]
    fn lookup_uses_normalized_name_for_alias_match() {
        let result = lookup_command_profile(r"\copy", test_profiles());

        assert_eq!(result.normalized_command_name, "copy");
        assert_eq!(
            result.profile.as_ref().map(CommandProfile::primary_name),
            Some("cp")
        );
    }

    #[test]
    fn lookup_prefers_exact_alias_before_family_coalescing() {
        let result = lookup_command_profile(
            "mkfs.ext4",
            vec![
                CommandProfile::new("mkfs"),
                CommandProfile::new("mke2fs").alias("mkfs.ext4"),
            ],
        );

        assert_eq!(result.normalized_command_name, "mkfs.ext4");
        assert_eq!(
            result.profile.as_ref().map(CommandProfile::primary_name),
            Some("mke2fs")
        );
    }

    #[test]
    fn lookup_returns_none_for_unknown_command() {
        let result = lookup_command_profile("unknown-tool", test_profiles());

        assert_eq!(result.normalized_command_name, "unknown-tool");
        assert!(result.profile.is_none());
    }
}

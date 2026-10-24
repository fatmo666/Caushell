use super::*;

pub(super) fn valid_contract(c: &PythonRuntimeContract) -> Result<(), String> {
    let path = caushell_runner::directory_path_is_resolved;
    if c.schema != "caushell.python-runtime/v1"
        || c.platform != "linux"
        || c.version[..2] != [3, 11]
        || !path(&c.executable)
        || !path(&c.account_home)
        || !c.files.contains_key(&c.executable)
        || c.files.len() > 4096
        || c.directories.len() > 512
        || c.symlinks.len() > 512
        || c.search_paths.is_empty()
        || c.search_paths.len() > 16
        || c.site_directories.len() > 16
        || c.stdlib_names.len() > 1024
        || c.builtin_modules.len() > 1024
        || c.frozen_modules.len() > 1024
        || c.absent_configuration.len() > 64
        || c.modules.len() > 32
        || c.files
            .values()
            .map(|f| f.size)
            .try_fold(0u64, |sum, n| sum.checked_add(n))
            .is_none_or(|sum| sum > 134_217_728)
    {
        return Err("unsupported Python runtime contract".into());
    }
    if c.account.uid != c.account.euid || c.account.gid != c.account.egid {
        return Err("Python changed-identity startup is unsupported".into());
    }
    if c.search_paths
        .iter()
        .chain(&c.site_directories)
        .chain(&c.absent_configuration)
        .any(|p| !path(p))
        || c.files.iter().any(|(p, f)| {
            !path(p)
                || f.size > caushell_runner::MAX_RUNTIME_FILE_BYTES as u64
                || f.sha256.len() != 64
                || !f.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        })
        || c.extension_suffixes.is_empty()
        || c.extension_suffixes.len() > 16
        || c.extension_suffixes
            .iter()
            .any(|s| !s.starts_with('.') || s.contains(['/', '\0']))
        || c.stdlib_names
            .iter()
            .chain(&c.builtin_modules)
            .chain(&c.frozen_modules)
            .any(|n| !caushell_profile::shell_identifier(n))
        || c.modules.keys().any(|n| {
            n.is_empty()
                || n.len() > 256
                || n.split('.').any(|s| !caushell_profile::shell_identifier(s))
        })
        || c.symlinks.iter().any(|(p, target)| {
            !path(p) || target.is_empty() || target.len() > 4096 || target.contains('\0')
        })
    {
        return Err("invalid Python runtime contract entries".into());
    }
    for (directory, entries) in &c.directories {
        if !path(directory) || entries.len() > 4096 {
            return Err("invalid Python runtime directory".into());
        }
        let mut previous = None;
        for entry in entries {
            if entry.name.is_empty()
                || entry.name.contains(['/', '\0'])
                || matches!(entry.name.as_str(), "." | "..")
                || previous.is_some_and(|p: &String| p.as_bytes() >= entry.name.as_bytes())
            {
                return Err("invalid Python runtime inventory order/name".into());
            }
            let child = format!("{directory}/{}", entry.name);
            let present = match entry.kind {
                DirectoryEntryKind::File => c.files.contains_key(&child),
                DirectoryEntryKind::Directory => c.directories.contains_key(&child),
                DirectoryEntryKind::Symlink => c.symlinks.contains_key(&child),
                _ => false,
            };
            if !present {
                return Err(format!("Python runtime inventory omits {child}"));
            }
            previous = Some(&entry.name);
        }
    }
    Ok(())
}

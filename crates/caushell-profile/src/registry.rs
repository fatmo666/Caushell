use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    BuiltInRegistryError, CommandProfile, LoadProfileError, load_command_profile_from_path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryLookupResult<'a> {
    pub normalized_command_name: String,
    pub profile: Option<&'a CommandProfile>,
}

#[derive(Debug, Clone, Default)]
pub struct ProfileRegistry {
    profiles: Vec<CommandProfile>,
    name_index: BTreeMap<String, usize>,
}

#[derive(Debug)]
pub enum RegistryError {
    ReadDir(std::io::Error),
    ReadDirEntry(std::io::Error),
    LoadProfile {
        path: PathBuf,
        source: LoadProfileError,
    },
    DuplicateName {
        name: String,
        first_profile: String,
        second_profile: String,
    },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadDir(error) => write!(f, "failed to read profile directory: {error}"),
            Self::ReadDirEntry(error) => {
                write!(f, "failed to read profile directory entry: {error}")
            }
            Self::LoadProfile { path, source } => {
                write!(
                    f,
                    "failed to load profile from {}: {source}",
                    path.display()
                )
            }
            Self::DuplicateName {
                name,
                first_profile,
                second_profile,
            } => write!(
                f,
                "duplicate profile name or alias {name:?} between {first_profile:?} and {second_profile:?}"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

impl ProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn built_in() -> Result<Self, BuiltInRegistryError> {
        crate::builtin::load_built_in_registry()
    }

    pub fn from_profiles(profiles: Vec<CommandProfile>) -> Result<Self, RegistryError> {
        let mut name_index = BTreeMap::new();

        for (index, profile) in profiles.iter().enumerate() {
            register_name(&mut name_index, &profiles, index, profile.primary_name())?;

            for alias in &profile.identity.aliases {
                register_name(&mut name_index, &profiles, index, alias.as_str())?;
            }
        }

        Ok(Self {
            profiles,
            name_index,
        })
    }

    pub fn load_dir(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let mut profile_paths = Vec::new();

        for entry in fs::read_dir(path).map_err(RegistryError::ReadDir)? {
            let entry = entry.map_err(RegistryError::ReadDirEntry)?;
            let entry_path = entry.path();

            if entry_path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "yaml")
            {
                profile_paths.push(entry_path);
            }
        }

        profile_paths.sort();

        let mut profiles = Vec::with_capacity(profile_paths.len());
        for profile_path in profile_paths {
            let profile = load_command_profile_from_path(&profile_path).map_err(|source| {
                RegistryError::LoadProfile {
                    path: profile_path.clone(),
                    source,
                }
            })?;
            profiles.push(profile);
        }

        Self::from_profiles(profiles)
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn profiles(&self) -> &[CommandProfile] {
        &self.profiles
    }

    pub fn lookup(&self, command_name: &str) -> RegistryLookupResult<'_> {
        let exact_normalized_command_name =
            super::lookup::normalize_command_name_without_family_coalescing(command_name);
        let coalesced_command_name =
            super::lookup::coalesce_command_family_name(&exact_normalized_command_name);
        let exact_profile = self
            .name_index
            .get(&exact_normalized_command_name)
            .map(|index| &self.profiles[*index]);
        let normalized_profile = self
            .name_index
            .get(&coalesced_command_name)
            .map(|index| &self.profiles[*index]);
        let profile = exact_profile.or(normalized_profile);
        let normalized_command_name = if exact_profile.is_some() {
            exact_normalized_command_name
        } else {
            coalesced_command_name
        };

        RegistryLookupResult {
            normalized_command_name,
            profile,
        }
    }
}

fn register_name(
    name_index: &mut BTreeMap<String, usize>,
    profiles: &[CommandProfile],
    index: usize,
    name: &str,
) -> Result<(), RegistryError> {
    if let Some(existing_index) = name_index.get(name) {
        return Err(RegistryError::DuplicateName {
            name: name.to_string(),
            first_profile: profiles[*existing_index].primary_name().to_string(),
            second_profile: profiles[index].primary_name().to_string(),
        });
    }

    name_index.insert(name.to_string(), index);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProfileRegistry, RegistryError};
    use std::path::PathBuf;

    use crate::CommandProfile;

    fn built_in_profile_file_count() -> usize {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profiles_dir = manifest_dir.join("profiles");
        std::fs::read_dir(profiles_dir)
            .expect("expected profiles directory to be readable")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("yaml"))
            .count()
    }

    #[test]
    fn registry_lookup_uses_primary_name_and_alias() {
        let registry = ProfileRegistry::from_profiles(vec![
            CommandProfile::new("bash").alias("sh-compatible"),
            CommandProfile::new("sh"),
        ])
        .expect("expected registry to build");

        let bash = registry.lookup("/bin/bash");
        assert_eq!(bash.normalized_command_name, "bash");
        assert_eq!(bash.profile.map(CommandProfile::primary_name), Some("bash"));

        let alias = registry.lookup(r"\sh-compatible");
        assert_eq!(alias.normalized_command_name, "sh-compatible");
        assert_eq!(
            alias.profile.map(CommandProfile::primary_name),
            Some("bash")
        );

        let sh = registry.lookup("sh");
        assert_eq!(sh.normalized_command_name, "sh");
        assert_eq!(sh.profile.map(CommandProfile::primary_name), Some("sh"));
    }

    #[test]
    fn registry_returns_none_for_unknown_command() {
        let registry = ProfileRegistry::from_profiles(vec![CommandProfile::new("bash")])
            .expect("expected registry to build");

        let result = registry.lookup("unknown-tool");

        assert_eq!(result.normalized_command_name, "unknown-tool");
        assert!(result.profile.is_none());
    }

    #[test]
    fn registry_rejects_duplicate_primary_names_or_aliases() {
        let error = ProfileRegistry::from_profiles(vec![
            CommandProfile::new("bash").alias("sh-compatible"),
            CommandProfile::new("sh-compatible"),
        ])
        .expect_err("expected duplicate name error");

        match error {
            RegistryError::DuplicateName {
                name,
                first_profile,
                second_profile,
            } => {
                assert_eq!(name, "sh-compatible");
                assert_eq!(first_profile, "bash");
                assert_eq!(second_profile, "sh-compatible");
            }
            other => panic!("unexpected registry error: {other:?}"),
        }
    }

    #[test]
    fn registry_load_dir_reads_built_in_profiles() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profiles_dir = manifest_dir.join("profiles");

        let registry = ProfileRegistry::load_dir(&profiles_dir)
            .expect("expected built-in profiles directory to load");

        assert_eq!(registry.len(), built_in_profile_file_count());
        assert_eq!(
            registry
                .lookup("alias")
                .profile
                .map(CommandProfile::primary_name),
            Some("alias")
        );
        assert_eq!(
            registry
                .lookup("bash")
                .profile
                .map(CommandProfile::primary_name),
            Some("bash")
        );
        assert_eq!(
            registry
                .lookup("base64")
                .profile
                .map(CommandProfile::primary_name),
            Some("base64")
        );
        assert_eq!(
            registry
                .lookup("iconv")
                .profile
                .map(CommandProfile::primary_name),
            Some("iconv")
        );
        assert_eq!(
            registry
                .lookup("jq")
                .profile
                .map(CommandProfile::primary_name),
            Some("jq")
        );
        assert_eq!(
            registry
                .lookup("gzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("gzip")
        );
        assert_eq!(
            registry
                .lookup("gunzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("gunzip")
        );
        assert_eq!(
            registry
                .lookup("gzcat")
                .profile
                .map(CommandProfile::primary_name),
            Some("zcat")
        );
        assert_eq!(
            registry
                .lookup("cargo")
                .profile
                .map(CommandProfile::primary_name),
            Some("cargo")
        );
        assert_eq!(
            registry
                .lookup("make")
                .profile
                .map(CommandProfile::primary_name),
            Some("make")
        );
        assert_eq!(
            registry
                .lookup("npm")
                .profile
                .map(CommandProfile::primary_name),
            Some("npm")
        );
        assert_eq!(
            registry
                .lookup("mkfs.ext4")
                .profile
                .map(CommandProfile::primary_name),
            Some("mke2fs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.xfs")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.bfs")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs.bfs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.cramfs")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs.cramfs")
        );
        assert_eq!(
            registry
                .lookup("mkfs.minix")
                .profile
                .map(CommandProfile::primary_name),
            Some("mkfs.minix")
        );
        assert_eq!(
            registry
                .lookup("mke2fs")
                .profile
                .map(CommandProfile::primary_name),
            Some("mke2fs")
        );
        assert_eq!(
            registry
                .lookup("openssl")
                .profile
                .map(CommandProfile::primary_name),
            Some("openssl")
        );
        assert_eq!(
            registry
                .lookup("git")
                .profile
                .map(CommandProfile::primary_name),
            Some("git")
        );
        assert_eq!(
            registry
                .lookup("dd")
                .profile
                .map(CommandProfile::primary_name),
            Some("dd")
        );
        assert_eq!(
            registry
                .lookup("gawk")
                .profile
                .map(CommandProfile::primary_name),
            Some("awk")
        );
        assert_eq!(
            registry
                .lookup("cp")
                .profile
                .map(CommandProfile::primary_name),
            Some("cp")
        );
        assert_eq!(
            registry
                .lookup("dd")
                .profile
                .map(CommandProfile::primary_name),
            Some("dd")
        );
        assert_eq!(
            registry
                .lookup("chmod")
                .profile
                .map(CommandProfile::primary_name),
            Some("chmod")
        );
        assert_eq!(
            registry
                .lookup("chown")
                .profile
                .map(CommandProfile::primary_name),
            Some("chown")
        );
        assert_eq!(
            registry
                .lookup("chgrp")
                .profile
                .map(CommandProfile::primary_name),
            Some("chgrp")
        );
        assert_eq!(
            registry
                .lookup("env")
                .profile
                .map(CommandProfile::primary_name),
            Some("env")
        );
        assert_eq!(
            registry
                .lookup("find")
                .profile
                .map(CommandProfile::primary_name),
            Some("find")
        );
        assert_eq!(
            registry
                .lookup("head")
                .profile
                .map(CommandProfile::primary_name),
            Some("head")
        );
        assert_eq!(
            registry
                .lookup("echo")
                .profile
                .map(CommandProfile::primary_name),
            Some("echo")
        );
        assert_eq!(
            registry
                .lookup("ls")
                .profile
                .map(CommandProfile::primary_name),
            Some("ls")
        );
        assert_eq!(
            registry
                .lookup("nl")
                .profile
                .map(CommandProfile::primary_name),
            Some("nl")
        );
        assert_eq!(
            registry
                .lookup("tail")
                .profile
                .map(CommandProfile::primary_name),
            Some("tail")
        );
        assert_eq!(
            registry
                .lookup("pwd")
                .profile
                .map(CommandProfile::primary_name),
            Some("pwd")
        );
        assert_eq!(
            registry
                .lookup("sort")
                .profile
                .map(CommandProfile::primary_name),
            Some("sort")
        );
        assert_eq!(
            registry
                .lookup("grep")
                .profile
                .map(CommandProfile::primary_name),
            Some("grep")
        );
        assert_eq!(
            registry
                .lookup("nodejs")
                .profile
                .map(CommandProfile::primary_name),
            Some("node")
        );
        assert_eq!(
            registry
                .lookup("perl")
                .profile
                .map(CommandProfile::primary_name),
            Some("perl")
        );
        assert_eq!(
            registry
                .lookup("scp")
                .profile
                .map(CommandProfile::primary_name),
            Some("scp")
        );
        assert_eq!(
            registry
                .lookup("mkfs.ext4")
                .profile
                .map(CommandProfile::primary_name),
            Some("mke2fs")
        );
        assert_eq!(
            registry.lookup("mkfs.ext4").normalized_command_name,
            "mkfs.ext4"
        );
        assert_eq!(registry.lookup("mkfs.xfs").normalized_command_name, "mkfs");
        assert_eq!(
            registry.lookup("mkfs.bfs").normalized_command_name,
            "mkfs.bfs"
        );
        assert_eq!(registry.lookup("mke2fs").normalized_command_name, "mke2fs");
        assert_eq!(
            registry
                .lookup("sgdisk")
                .profile
                .map(CommandProfile::primary_name),
            Some("sgdisk")
        );
        assert_eq!(
            registry
                .lookup("sgdisk")
                .profile
                .map(CommandProfile::primary_name),
            Some("sgdisk")
        );
        assert_eq!(
            registry
                .lookup("python3")
                .profile
                .map(CommandProfile::primary_name),
            Some("python")
        );
        assert_eq!(
            registry
                .lookup("python3.12")
                .profile
                .map(CommandProfile::primary_name),
            Some("python")
        );
        assert_eq!(
            registry
                .lookup("rsync")
                .profile
                .map(CommandProfile::primary_name),
            Some("rsync")
        );
        assert_eq!(
            registry
                .lookup("egrep")
                .profile
                .map(CommandProfile::primary_name),
            Some("grep")
        );
        assert_eq!(
            registry
                .lookup("sh")
                .profile
                .map(CommandProfile::primary_name),
            Some("sh")
        );
        assert_eq!(
            registry
                .lookup("ssh")
                .profile
                .map(CommandProfile::primary_name),
            Some("ssh")
        );
        assert_eq!(
            registry
                .lookup("sed")
                .profile
                .map(CommandProfile::primary_name),
            Some("sed")
        );
        assert_eq!(
            registry
                .lookup("nice")
                .profile
                .map(CommandProfile::primary_name),
            Some("nice")
        );
        assert_eq!(
            registry
                .lookup("stdbuf")
                .profile
                .map(CommandProfile::primary_name),
            Some("stdbuf")
        );
        assert_eq!(
            registry
                .lookup("sudo")
                .profile
                .map(CommandProfile::primary_name),
            Some("sudo")
        );
        assert_eq!(
            registry
                .lookup("tar")
                .profile
                .map(CommandProfile::primary_name),
            Some("tar")
        );
        assert_eq!(
            registry
                .lookup("tee")
                .profile
                .map(CommandProfile::primary_name),
            Some("tee")
        );
        assert_eq!(
            registry
                .lookup("unzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("unzip")
        );
        assert_eq!(
            registry
                .lookup("wget")
                .profile
                .map(CommandProfile::primary_name),
            Some("wget")
        );
        assert_eq!(
            registry
                .lookup("wipefs")
                .profile
                .map(CommandProfile::primary_name),
            Some("wipefs")
        );
        assert_eq!(
            registry
                .lookup("wipefs")
                .profile
                .map(CommandProfile::primary_name),
            Some("wipefs")
        );
        assert_eq!(
            registry
                .lookup("xxd")
                .profile
                .map(CommandProfile::primary_name),
            Some("xxd")
        );
        assert_eq!(
            registry
                .lookup("xargs")
                .profile
                .map(CommandProfile::primary_name),
            Some("xargs")
        );
        assert_eq!(
            registry
                .lookup(r"\sh-compatible")
                .profile
                .map(CommandProfile::primary_name),
            Some("bash")
        );
        assert_eq!(
            registry
                .lookup("unalias")
                .profile
                .map(CommandProfile::primary_name),
            Some("unalias")
        );
    }

    #[test]
    fn registry_built_in_loads_compiled_profiles() {
        let registry = ProfileRegistry::built_in().expect("expected built-in registry to load");

        assert_eq!(registry.len(), built_in_profile_file_count());
        assert_eq!(
            registry
                .lookup("alias")
                .profile
                .map(CommandProfile::primary_name),
            Some("alias")
        );
        assert_eq!(
            registry
                .lookup("bash")
                .profile
                .map(CommandProfile::primary_name),
            Some("bash")
        );
        assert_eq!(
            registry
                .lookup("busybox")
                .profile
                .map(CommandProfile::primary_name),
            Some("busybox")
        );
        assert_eq!(
            registry
                .lookup("ash")
                .profile
                .map(CommandProfile::primary_name),
            Some("sh")
        );
        assert_eq!(
            registry
                .lookup("gzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("gzip")
        );
        assert_eq!(
            registry
                .lookup("gunzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("gunzip")
        );
        assert_eq!(
            registry
                .lookup("base64")
                .profile
                .map(CommandProfile::primary_name),
            Some("base64")
        );
        assert_eq!(
            registry
                .lookup("iconv")
                .profile
                .map(CommandProfile::primary_name),
            Some("iconv")
        );
        assert_eq!(
            registry
                .lookup("jq")
                .profile
                .map(CommandProfile::primary_name),
            Some("jq")
        );
        assert_eq!(
            registry
                .lookup("cargo")
                .profile
                .map(CommandProfile::primary_name),
            Some("cargo")
        );
        assert_eq!(
            registry
                .lookup("make")
                .profile
                .map(CommandProfile::primary_name),
            Some("make")
        );
        assert_eq!(
            registry
                .lookup("npm")
                .profile
                .map(CommandProfile::primary_name),
            Some("npm")
        );
        assert_eq!(
            registry
                .lookup("openssl")
                .profile
                .map(CommandProfile::primary_name),
            Some("openssl")
        );
        assert_eq!(
            registry
                .lookup("gzcat")
                .profile
                .map(CommandProfile::primary_name),
            Some("zcat")
        );
        assert_eq!(
            registry
                .lookup("git")
                .profile
                .map(CommandProfile::primary_name),
            Some("git")
        );
        assert_eq!(
            registry
                .lookup("gawk")
                .profile
                .map(CommandProfile::primary_name),
            Some("awk")
        );
        assert_eq!(
            registry
                .lookup("cp")
                .profile
                .map(CommandProfile::primary_name),
            Some("cp")
        );
        assert_eq!(
            registry
                .lookup("chmod")
                .profile
                .map(CommandProfile::primary_name),
            Some("chmod")
        );
        assert_eq!(
            registry
                .lookup("chown")
                .profile
                .map(CommandProfile::primary_name),
            Some("chown")
        );
        assert_eq!(
            registry
                .lookup("chgrp")
                .profile
                .map(CommandProfile::primary_name),
            Some("chgrp")
        );
        assert_eq!(
            registry
                .lookup("env")
                .profile
                .map(CommandProfile::primary_name),
            Some("env")
        );
        assert_eq!(
            registry
                .lookup("find")
                .profile
                .map(CommandProfile::primary_name),
            Some("find")
        );
        assert_eq!(
            registry
                .lookup("head")
                .profile
                .map(CommandProfile::primary_name),
            Some("head")
        );
        assert_eq!(
            registry
                .lookup("echo")
                .profile
                .map(CommandProfile::primary_name),
            Some("echo")
        );
        assert_eq!(
            registry
                .lookup("ls")
                .profile
                .map(CommandProfile::primary_name),
            Some("ls")
        );
        assert_eq!(
            registry
                .lookup("nl")
                .profile
                .map(CommandProfile::primary_name),
            Some("nl")
        );
        assert_eq!(
            registry
                .lookup("tail")
                .profile
                .map(CommandProfile::primary_name),
            Some("tail")
        );
        assert_eq!(
            registry
                .lookup("pwd")
                .profile
                .map(CommandProfile::primary_name),
            Some("pwd")
        );
        assert_eq!(
            registry
                .lookup("sort")
                .profile
                .map(CommandProfile::primary_name),
            Some("sort")
        );
        assert_eq!(
            registry
                .lookup("grep")
                .profile
                .map(CommandProfile::primary_name),
            Some("grep")
        );
        assert_eq!(
            registry
                .lookup("nodejs")
                .profile
                .map(CommandProfile::primary_name),
            Some("node")
        );
        assert_eq!(
            registry
                .lookup("perl")
                .profile
                .map(CommandProfile::primary_name),
            Some("perl")
        );
        assert_eq!(
            registry
                .lookup("scp")
                .profile
                .map(CommandProfile::primary_name),
            Some("scp")
        );
        assert_eq!(
            registry
                .lookup("python3")
                .profile
                .map(CommandProfile::primary_name),
            Some("python")
        );
        assert_eq!(
            registry
                .lookup("python3.12")
                .profile
                .map(CommandProfile::primary_name),
            Some("python")
        );
        assert_eq!(
            registry
                .lookup("rsync")
                .profile
                .map(CommandProfile::primary_name),
            Some("rsync")
        );
        assert_eq!(
            registry
                .lookup("fgrep")
                .profile
                .map(CommandProfile::primary_name),
            Some("grep")
        );
        assert_eq!(
            registry
                .lookup("sh")
                .profile
                .map(CommandProfile::primary_name),
            Some("sh")
        );
        assert_eq!(
            registry
                .lookup("ssh")
                .profile
                .map(CommandProfile::primary_name),
            Some("ssh")
        );
        assert_eq!(
            registry
                .lookup("sed")
                .profile
                .map(CommandProfile::primary_name),
            Some("sed")
        );
        assert_eq!(
            registry
                .lookup("sudo")
                .profile
                .map(CommandProfile::primary_name),
            Some("sudo")
        );
        assert_eq!(
            registry
                .lookup("tar")
                .profile
                .map(CommandProfile::primary_name),
            Some("tar")
        );
        assert_eq!(
            registry
                .lookup("tee")
                .profile
                .map(CommandProfile::primary_name),
            Some("tee")
        );
        assert_eq!(
            registry
                .lookup("unzip")
                .profile
                .map(CommandProfile::primary_name),
            Some("unzip")
        );
        assert_eq!(
            registry
                .lookup("wget")
                .profile
                .map(CommandProfile::primary_name),
            Some("wget")
        );
        assert_eq!(
            registry
                .lookup("xxd")
                .profile
                .map(CommandProfile::primary_name),
            Some("xxd")
        );
        assert_eq!(
            registry
                .lookup("xargs")
                .profile
                .map(CommandProfile::primary_name),
            Some("xargs")
        );
        assert_eq!(
            registry
                .lookup(r"\sh-compatible")
                .profile
                .map(CommandProfile::primary_name),
            Some("bash")
        );
        assert_eq!(
            registry
                .lookup("unalias")
                .profile
                .map(CommandProfile::primary_name),
            Some("unalias")
        );
    }
}

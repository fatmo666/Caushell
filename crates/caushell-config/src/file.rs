use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use caushell_runtime_security::{
    ensure_private_directory, write_private_file_atomic, write_private_file_atomic_new,
};

use crate::{
    CaushellConfig, LoadConfigError, RawConfigFile, load_raw_config_from_str, normalize_config,
};

#[derive(Debug)]
pub enum ConfigFileError {
    Read { path: PathBuf, source: io::Error },
    Load(LoadConfigError),
    Serialize(serde_yaml::Error),
    Write { path: PathBuf, source: io::Error },
    AlreadyExists(PathBuf),
}

impl std::fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "failed to read config {}: {source}", path.display())
            }
            Self::Load(error) => error.fmt(f),
            Self::Serialize(error) => write!(f, "failed to serialize config YAML: {error}"),
            Self::Write { path, source } => {
                write!(f, "failed to write config {}: {source}", path.display())
            }
            Self::AlreadyExists(path) => {
                write!(f, "config already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } | Self::Write { source, .. } => Some(source),
            Self::Load(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::AlreadyExists(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfigFile {
    pub path: PathBuf,
    pub exists: bool,
    pub raw: RawConfigFile,
    pub effective: CaushellConfig,
}

pub fn load_config_file_or_default(
    path: impl AsRef<Path>,
) -> Result<LoadedConfigFile, ConfigFileError> {
    let path = path.as_ref();
    let input = match fs::read_to_string(path) {
        Ok(input) => Some(input),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(ConfigFileError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let exists = input.is_some();
    let raw = match input.as_deref() {
        Some(input) => load_raw_config_from_str(input).map_err(ConfigFileError::Load)?,
        None => RawConfigFile::default(),
    };
    let effective = normalize_config(raw.clone())
        .map_err(|error| ConfigFileError::Load(LoadConfigError::Normalize(error)))?;

    Ok(LoadedConfigFile {
        path: path.to_path_buf(),
        exists,
        raw,
        effective,
    })
}

pub fn initialize_config_file(path: impl AsRef<Path>) -> Result<(), ConfigFileError> {
    let path = path.as_ref();
    let yaml = serialize_config(&RawConfigFile::default())?;
    let parent = config_parent(path)?;
    ensure_private_directory(parent).map_err(|source| config_write_error(path, source))?;
    match write_private_file_atomic_new(path, yaml.as_bytes()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            Err(ConfigFileError::AlreadyExists(path.to_path_buf()))
        }
        Err(source) => Err(config_write_error(path, source)),
    }
}

pub fn write_config_file(
    path: impl AsRef<Path>,
    raw: &RawConfigFile,
) -> Result<(), ConfigFileError> {
    let path = path.as_ref();
    let yaml = serialize_config(raw)?;
    let parent = config_parent(path)?;
    ensure_private_directory(parent).map_err(|source| config_write_error(path, source))?;
    write_private_file_atomic(path, yaml.as_bytes())
        .map_err(|source| config_write_error(path, source))
}

fn serialize_config(raw: &RawConfigFile) -> Result<String, ConfigFileError> {
    normalize_config(raw.clone())
        .map_err(|error| ConfigFileError::Load(LoadConfigError::Normalize(error)))?;
    let mut yaml = serde_yaml::to_string(raw).map_err(ConfigFileError::Serialize)?;
    if !yaml.ends_with('\n') {
        yaml.push('\n');
    }
    Ok(yaml)
}

fn config_parent(path: &Path) -> Result<&Path, ConfigFileError> {
    path.parent().ok_or_else(|| {
        config_write_error(
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "config path has no parent"),
        )
    })
}

fn config_write_error(path: &Path, source: io::Error) -> ConfigFileError {
    ConfigFileError::Write {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigFileError, initialize_config_file, load_config_file_or_default, write_config_file,
    };
    use crate::{FailureAction, RawAction, RawConfigFile};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("caushell-config-file-{unique}"))
            .join("config.yaml")
    }

    #[test]
    fn missing_file_loads_effective_defaults() {
        let path = temp_config_path();
        let loaded = load_config_file_or_default(&path).unwrap();

        assert!(!loaded.exists);
        assert_eq!(loaded.path, path);
        assert_eq!(loaded.effective.failure_action, FailureAction::Allow);
    }

    #[test]
    fn initialize_creates_private_valid_config_without_overwriting() {
        let path = temp_config_path();
        initialize_config_file(&path).unwrap();
        let original = fs::read_to_string(&path).unwrap();

        assert!(load_config_file_or_default(&path).unwrap().exists);
        assert!(matches!(
            initialize_config_file(&path),
            Err(ConfigFileError::AlreadyExists(existing)) if existing == path
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);

        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn write_validates_before_replacing_existing_config() {
        let path = temp_config_path();
        initialize_config_file(&path).unwrap();
        let mut raw = RawConfigFile::default();
        raw.failure_action = RawAction::Deny;
        write_config_file(&path, &raw).unwrap();

        let loaded = load_config_file_or_default(&path).unwrap();
        assert_eq!(loaded.raw.failure_action, RawAction::Deny);

        raw.version = 999;
        assert!(write_config_file(&path, &raw).is_err());
        assert_eq!(
            load_config_file_or_default(&path)
                .unwrap()
                .raw
                .failure_action,
            RawAction::Deny
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

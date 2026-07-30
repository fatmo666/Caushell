use std::fs;
use std::path::{Path, PathBuf};

use crate::{CaushellConfig, NormalizeConfigError, RawConfigFile, normalize_config};

#[derive(Debug)]
pub enum LoadConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    ParseYaml(serde_yaml::Error),
    Normalize(NormalizeConfigError),
}

impl std::fmt::Display for LoadConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "failed to read config {}: {source}", path.display())
            }
            Self::ParseYaml(error) => write!(f, "failed to parse config YAML: {error}"),
            Self::Normalize(error) => write!(f, "invalid Caushell config: {error}"),
        }
    }
}

impl std::error::Error for LoadConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::ParseYaml(error) => Some(error),
            Self::Normalize(error) => Some(error),
        }
    }
}

pub fn load_raw_config_from_path(path: impl AsRef<Path>) -> Result<RawConfigFile, LoadConfigError> {
    let path = path.as_ref();
    let input = fs::read_to_string(path).map_err(|source| LoadConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    load_raw_config_from_str(&input)
}

pub fn load_raw_config_from_str(input: &str) -> Result<RawConfigFile, LoadConfigError> {
    if input.trim().is_empty() {
        return Ok(RawConfigFile::default());
    }

    serde_yaml::from_str(input).map_err(LoadConfigError::ParseYaml)
}

pub fn load_config_from_path(path: impl AsRef<Path>) -> Result<CaushellConfig, LoadConfigError> {
    let raw = load_raw_config_from_path(path)?;
    normalize_config(raw).map_err(LoadConfigError::Normalize)
}

pub fn load_config_from_str(input: &str) -> Result<CaushellConfig, LoadConfigError> {
    let raw = load_raw_config_from_str(input)?;
    normalize_config(raw).map_err(LoadConfigError::Normalize)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use caushell_types::{RuleAction, RuleId};

    use super::{
        LoadConfigError, load_config_from_path, load_config_from_str, load_raw_config_from_str,
    };
    use crate::{FailureAction, RawAction};

    fn temp_config_path() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("caushell-config-{unique}.yaml"))
    }

    #[test]
    fn empty_config_uses_non_disruptive_defaults() {
        let raw = load_raw_config_from_str("").expect("empty config should load");
        assert_eq!(raw.failure_action, RawAction::Allow);

        let config = load_config_from_str("").expect("empty config should normalize");
        assert_eq!(config.failure_action, FailureAction::Allow);
    }

    #[test]
    fn loads_config_from_path() {
        let path = temp_config_path();
        fs::write(
            &path,
            "version: 1\nfailure_action: deny\npolicy:\n  rules:\n    tainted_execution: allow\n",
        )
        .expect("temp config should be written");

        let config = load_config_from_path(&path).expect("config should load");
        fs::remove_file(path).expect("temp config should be removed");

        assert_eq!(config.failure_action, FailureAction::Deny);
        assert_eq!(
            config
                .policy
                .rule_policy
                .action_for(RuleId::TaintedExecution),
            RuleAction::Observe
        );
    }

    #[test]
    fn parse_error_preserves_yaml_location() {
        let error = load_config_from_str("version: 1\nunknown: true\n")
            .expect_err("unknown field should fail");

        match error {
            LoadConfigError::ParseYaml(error) => {
                let location = error.location().expect("YAML error should have a location");
                assert_eq!(location.line(), 2);
            }
            other => panic!("expected YAML parse error, got {other:?}"),
        }
    }
}

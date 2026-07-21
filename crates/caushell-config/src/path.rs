use std::ffi::OsString;
use std::path::PathBuf;

pub const CONFIG_PATH_ENV: &str = "CAUSHELL_CONFIG_PATH";
pub const CONFIG_FILE_NAME: &str = "config.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigPathError {
    RelativeEnvironmentPath {
        variable: &'static str,
        path: PathBuf,
    },
    HomeDirectoryUnavailable,
}

impl std::fmt::Display for ConfigPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RelativeEnvironmentPath { variable, path } => write!(
                f,
                "{variable} must be an absolute path, got {}",
                path.display()
            ),
            Self::HomeDirectoryUnavailable => write!(
                f,
                "cannot resolve Caushell config path because neither XDG_CONFIG_HOME nor HOME is available"
            ),
        }
    }
}

impl std::error::Error for ConfigPathError {}

pub fn resolve_config_path() -> Result<PathBuf, ConfigPathError> {
    resolve_config_path_from(
        std::env::var_os(CONFIG_PATH_ENV),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn resolve_config_path_from(
    explicit: Option<OsString>,
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, ConfigPathError> {
    if let Some(path) = non_empty_path(explicit) {
        return require_absolute(CONFIG_PATH_ENV, path);
    }
    if let Some(root) = non_empty_path(xdg_config_home) {
        return Ok(require_absolute("XDG_CONFIG_HOME", root)?
            .join("caushell")
            .join(CONFIG_FILE_NAME));
    }
    let home = non_empty_path(home).ok_or(ConfigPathError::HomeDirectoryUnavailable)?;
    Ok(require_absolute("HOME", home)?
        .join(".config")
        .join("caushell")
        .join(CONFIG_FILE_NAME))
}

fn non_empty_path(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

fn require_absolute(variable: &'static str, path: PathBuf) -> Result<PathBuf, ConfigPathError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(ConfigPathError::RelativeEnvironmentPath { variable, path })
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigPathError, resolve_config_path_from};
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn explicit_config_path_has_highest_precedence() {
        let path = resolve_config_path_from(
            Some(OsString::from("/custom/caushell.yaml")),
            Some(OsString::from("/xdg")),
            Some(OsString::from("/home/tester")),
        )
        .unwrap();

        assert_eq!(path, PathBuf::from("/custom/caushell.yaml"));
    }

    #[test]
    fn xdg_config_home_precedes_home_fallback() {
        let path = resolve_config_path_from(
            None,
            Some(OsString::from("/xdg")),
            Some(OsString::from("/home/tester")),
        )
        .unwrap();

        assert_eq!(path, PathBuf::from("/xdg/caushell/config.yaml"));
    }

    #[test]
    fn home_fallback_uses_standard_config_location() {
        let path =
            resolve_config_path_from(None, None, Some(OsString::from("/home/tester"))).unwrap();

        assert_eq!(
            path,
            PathBuf::from("/home/tester/.config/caushell/config.yaml")
        );
    }

    #[test]
    fn relative_environment_paths_are_rejected() {
        let error =
            resolve_config_path_from(Some(OsString::from("relative/config.yaml")), None, None)
                .unwrap_err();

        assert_eq!(
            error,
            ConfigPathError::RelativeEnvironmentPath {
                variable: "CAUSHELL_CONFIG_PATH",
                path: PathBuf::from("relative/config.yaml"),
            }
        );
    }
}

//! Immutable executor inventory; never inferred from guard-process state.
use serde::{Deserialize, Serialize};

pub const GIT_2_39_5_VARIANT: &str = "git_2_39_5";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitRuntimeLayout {
    pub variant: String,
    pub system_config: String,
    /// The owner holds the native executable/layout and configuration search
    /// snapshot for this check. A historic probe or user config is insufficient.
    pub configuration_snapshot_held: bool,
}
impl GitRuntimeLayout {
    pub fn validate(&self) -> Result<(), String> {
        let path = &self.system_config;
        if self.variant != GIT_2_39_5_VARIANT
            || !self.configuration_snapshot_held
            || !path.starts_with('/')
            || path.len() > 4096
            || path.contains(['\0', '\n', '\r'])
            || path
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err("Git native layout is unsupported or not held by the executor".into());
        }
        Ok(())
    }
}

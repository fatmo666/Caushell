//! Private executor facts, not model input or a filesystem permission.
use crate::RuntimeAccount;
use serde::{Deserialize, Serialize};

pub const PIP_25_3_LINUX_VARIANT: &str = "pypa_pip_25_3_linux";

/// A deployment owner attests the closed interpreter/import startup and layout.
/// The owning frame must separately prove the executable's native variant.
/// Hosts must not construct this from task output or mutable user metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipRuntimeLayout {
    pub variant: String,
    pub prefix: String,
    pub account_home: String,
    pub account: RuntimeAccount,
    pub startup_read_only: bool,
    /// The host retains the configuration content/search-namespace lease until
    /// the checked action is released; a mere past read is not such a lease.
    pub configuration_snapshot_held: bool,
}

impl PipRuntimeLayout {
    pub fn validate(&self) -> Result<(), String> {
        fn absolute(s: &str) -> bool {
            s.starts_with('/')
                && s.len() <= 4096
                && !s.contains(['\0', '\n', '\r'])
                && s.split('/').skip(1).all(|x| !matches!(x, "." | ".."))
        }
        if self.variant != PIP_25_3_LINUX_VARIANT
            || !absolute(&self.prefix)
            || !absolute(&self.account_home)
            || !self.startup_read_only
            || !self.configuration_snapshot_held
        {
            return Err("unsupported or incomplete trusted Pip runtime layout".into());
        }
        Ok(())
    }
}

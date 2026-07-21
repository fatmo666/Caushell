use std::collections::{BTreeMap, BTreeSet};

use caushell_types::{ResolveGapKind, RuleFamily, RuleId, UnresolvedExecutionPayloadSubtype};
use serde::{Deserialize, Serialize};

pub const CURRENT_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawConfigFile {
    pub version: u32,
    pub failure_action: RawAction,
    pub policy: RawPolicy,
    pub trusted_paths: Vec<RawTrustedPath>,
    pub analysis: RawAnalysisConfig,
}

impl Default for RawConfigFile {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            failure_action: RawAction::Allow,
            policy: RawPolicy::default(),
            trusted_paths: Vec::new(),
            analysis: RawAnalysisConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawAction {
    #[default]
    Allow,
    NeedApproval,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawPolicy {
    pub rules: BTreeMap<RuleId, RawAction>,
    pub families: BTreeMap<RuleFamily, RawAction>,
    pub unknown_commands: RawUnknownCommandPolicy,
    pub resolve_gaps: BTreeMap<ResolveGapKind, RawAction>,
    pub unresolved_payloads: BTreeMap<UnresolvedExecutionPayloadSubtype, RawAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawUnknownCommandPolicy {
    pub default: RawAction,
    pub overrides: BTreeMap<String, RawAction>,
}

impl Default for RawUnknownCommandPolicy {
    fn default() -> Self {
        Self {
            default: RawAction::Allow,
            overrides: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrustedPath {
    pub root: String,
    pub scopes: BTreeSet<RawTrustedPathScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawTrustedPathScope {
    ScriptExecute,
    StartupConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawAnalysisConfig {
    pub max_nested_parse_depth: u8,
    pub max_taint_hops: u32,
    pub max_taint_nodes: usize,
}

impl Default for RawAnalysisConfig {
    fn default() -> Self {
        Self {
            max_nested_parse_depth: 3,
            max_taint_hops: 12,
            max_taint_nodes: 256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CURRENT_CONFIG_VERSION, RawAction, RawConfigFile, RawTrustedPathScope};

    #[test]
    fn raw_config_defaults_to_non_disruptive_behavior() {
        let config = RawConfigFile::default();

        assert_eq!(config.version, CURRENT_CONFIG_VERSION);
        assert_eq!(config.failure_action, RawAction::Allow);
        assert_eq!(config.policy.unknown_commands.default, RawAction::Allow);
        assert!(config.policy.rules.is_empty());
        assert!(config.trusted_paths.is_empty());
    }

    #[test]
    fn raw_config_rejects_internal_observe_action_name() {
        let error = serde_yaml::from_str::<RawConfigFile>(
            "version: 1\npolicy:\n  rules:\n    tainted_execution: observe\n",
        )
        .expect_err("observe is not a user-facing action");

        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn trusted_path_scope_uses_user_facing_names() {
        let config = serde_yaml::from_str::<RawConfigFile>(
            "version: 1\ntrusted_paths:\n  - root: ~/.local/tools\n    scopes: [script_execute]\n",
        )
        .expect("trusted path should parse");

        assert!(
            config.trusted_paths[0]
                .scopes
                .contains(&RawTrustedPathScope::ScriptExecute)
        );
    }

    #[test]
    fn trusted_path_scope_rejects_unimplemented_read_and_write_names() {
        for scope in ["read", "write"] {
            let input = format!(
                "version: 1\ntrusted_paths:\n  - root: /opt/tools\n    scopes: [{scope}]\n"
            );
            serde_yaml::from_str::<RawConfigFile>(&input)
                .expect_err("unimplemented trust scope should be rejected");
        }
    }
}

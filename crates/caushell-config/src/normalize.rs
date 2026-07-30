use std::collections::{BTreeMap, BTreeSet};

use caushell_profile::normalize_command_name;
use caushell_types::{
    FamilyPolicy, NoProfilePolicy, PathTrustGrant, PathTrustScope, PathTrustSet, PolicyConfig,
    ResolveGapPolicy, RuleAction, RuleFamily, RuleId, RulePolicy, RulePolicyEntry,
    RuntimeTaintPolicy, SemanticExpansionPolicy,
};

use crate::{
    CURRENT_CONFIG_VERSION, CaushellConfig, FailureAction, RawAction, RawConfigFile,
    RawTrustedPath, RawTrustedPathScope,
};

const HARD_DENY_FLOOR_RULES: [RuleId; 2] = [
    RuleId::CatastrophicFileSystemDelete,
    RuleId::CatastrophicShellProcessExplosion,
];

const TRUSTED_PATH_RULES: [RuleId; 2] = [
    RuleId::OutsideWorkspaceScriptSource,
    RuleId::OutsideWorkspaceStartupConfig,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeConfigError {
    UnsupportedVersion {
        actual: u32,
        supported: u32,
    },
    DuplicateUnknownCommand {
        normalized_command_name: String,
        first_raw_key: String,
        second_raw_key: String,
    },
    EmptyTrustedPathRoot {
        index: usize,
    },
    RelativeTrustedPathRoot {
        index: usize,
        root: String,
    },
    EmptyTrustedPathScopes {
        index: usize,
    },
    HardDenyFloorCannotBeLowered {
        rule_id: RuleId,
        action: RawAction,
    },
    HardDenyAnalysisDepthCannotBeLowered {
        actual: u8,
        minimum: u8,
    },
}

impl std::fmt::Display for NormalizeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { actual, supported } => write!(
                f,
                "unsupported Caushell config version {actual}; supported version is {supported}"
            ),
            Self::DuplicateUnknownCommand {
                normalized_command_name,
                first_raw_key,
                second_raw_key,
            } => write!(
                f,
                "duplicate unknown command override for {normalized_command_name:?}: {first_raw_key:?} and {second_raw_key:?}"
            ),
            Self::EmptyTrustedPathRoot { index } => {
                write!(f, "trusted_paths[{index}].root must not be empty")
            }
            Self::RelativeTrustedPathRoot { index, root } => write!(
                f,
                "trusted_paths[{index}].root must be absolute or start with ~/: {root:?}"
            ),
            Self::EmptyTrustedPathScopes { index } => {
                write!(f, "trusted_paths[{index}].scopes must not be empty")
            }
            Self::HardDenyFloorCannotBeLowered { rule_id, action } => write!(
                f,
                "hard deny floor rule {rule_id:?} cannot be configured as {action:?}"
            ),
            Self::HardDenyAnalysisDepthCannotBeLowered { actual, minimum } => write!(
                f,
                "analysis.max_nested_parse_depth cannot be lower than the hard deny floor minimum {minimum}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for NormalizeConfigError {}

pub fn normalize_config(raw: RawConfigFile) -> Result<CaushellConfig, NormalizeConfigError> {
    if raw.version != CURRENT_CONFIG_VERSION {
        return Err(NormalizeConfigError::UnsupportedVersion {
            actual: raw.version,
            supported: CURRENT_CONFIG_VERSION,
        });
    }

    validate_hard_deny_overrides(&raw.policy.rules)?;
    validate_hard_deny_analysis_depth(raw.analysis.max_nested_parse_depth)?;

    let families = raw
        .policy
        .families
        .into_iter()
        .map(|(family, action)| (family, FamilyPolicy::new(normalize_action(action))))
        .collect::<BTreeMap<_, _>>();
    let mut rules = raw
        .policy
        .rules
        .into_iter()
        .map(|(rule_id, action)| (rule_id, RulePolicyEntry::new(normalize_action(action))))
        .collect::<BTreeMap<_, _>>();
    enforce_hard_deny_floor(&mut rules);
    let no_profile = normalize_unknown_commands(raw.policy.unknown_commands)?;
    let resolve_gap = ResolveGapPolicy {
        defaults: raw
            .policy
            .resolve_gaps
            .into_iter()
            .map(|(kind, action)| (kind, normalize_action(action)))
            .collect(),
        unresolved_execution_payload_subtypes: raw
            .policy
            .unresolved_payloads
            .into_iter()
            .map(|(kind, action)| (kind, normalize_action(action)))
            .collect(),
    };

    let path_trust_sets = normalize_trusted_paths(raw.trusted_paths)?;
    attach_trusted_paths(
        &mut rules,
        &families,
        path_trust_sets.keys().cloned().collect(),
    );

    Ok(CaushellConfig {
        version: raw.version,
        failure_action: normalize_failure_action(raw.failure_action),
        policy: PolicyConfig {
            rule_policy: RulePolicy {
                families,
                rules,
                resolve_gap,
                no_profile,
            },
            semantic_expansion: SemanticExpansionPolicy {
                max_nested_parse_depth: raw.analysis.max_nested_parse_depth,
            },
            runtime_taint: RuntimeTaintPolicy {
                max_hops: raw.analysis.max_taint_hops,
                max_visited_nodes: raw.analysis.max_taint_nodes,
            },
            path_trust_sets,
        },
    })
}

fn validate_hard_deny_overrides(
    rules: &BTreeMap<RuleId, RawAction>,
) -> Result<(), NormalizeConfigError> {
    for rule_id in HARD_DENY_FLOOR_RULES {
        if let Some(action) = rules.get(&rule_id).copied() {
            if action != RawAction::Deny {
                return Err(NormalizeConfigError::HardDenyFloorCannotBeLowered { rule_id, action });
            }
        }
    }
    Ok(())
}

fn enforce_hard_deny_floor(rules: &mut BTreeMap<RuleId, RulePolicyEntry>) {
    for rule_id in HARD_DENY_FLOOR_RULES {
        rules.insert(rule_id, RulePolicyEntry::new(RuleAction::Deny));
    }
}

fn validate_hard_deny_analysis_depth(depth: u8) -> Result<(), NormalizeConfigError> {
    let minimum = crate::RawAnalysisConfig::default().max_nested_parse_depth;
    if depth < minimum {
        return Err(NormalizeConfigError::HardDenyAnalysisDepthCannotBeLowered {
            actual: depth,
            minimum,
        });
    }
    Ok(())
}

fn normalize_unknown_commands(
    raw: crate::RawUnknownCommandPolicy,
) -> Result<NoProfilePolicy, NormalizeConfigError> {
    let mut commands = BTreeMap::new();
    let mut sources = BTreeMap::<String, String>::new();

    for (raw_key, action) in raw.overrides {
        let normalized = normalize_command_name(&raw_key);
        if let Some(first_raw_key) = sources.get(&normalized) {
            return Err(NormalizeConfigError::DuplicateUnknownCommand {
                normalized_command_name: normalized,
                first_raw_key: first_raw_key.clone(),
                second_raw_key: raw_key,
            });
        }
        sources.insert(normalized.clone(), raw_key);
        commands.insert(normalized, normalize_action(action));
    }

    Ok(NoProfilePolicy {
        action: normalize_action(raw.default),
        commands,
    })
}

fn normalize_trusted_paths(
    paths: Vec<RawTrustedPath>,
) -> Result<BTreeMap<String, PathTrustSet>, NormalizeConfigError> {
    let mut normalized = BTreeMap::new();

    for (index, trusted_path) in paths.into_iter().enumerate() {
        let root = trusted_path.root.trim();
        if root.is_empty() {
            return Err(NormalizeConfigError::EmptyTrustedPathRoot { index });
        }
        if !root.starts_with('/') && root != "~" && !root.starts_with("~/") {
            return Err(NormalizeConfigError::RelativeTrustedPathRoot {
                index,
                root: trusted_path.root,
            });
        }
        if trusted_path.scopes.is_empty() {
            return Err(NormalizeConfigError::EmptyTrustedPathScopes { index });
        }

        let scopes = trusted_path
            .scopes
            .into_iter()
            .map(normalize_trusted_path_scope)
            .collect::<BTreeSet<_>>();
        normalized.insert(
            format!("user_trusted_path_{index}"),
            PathTrustSet::new(vec![root.to_string()], PathTrustGrant::Scoped { scopes }),
        );
    }

    Ok(normalized)
}

fn attach_trusted_paths(
    rules: &mut BTreeMap<RuleId, RulePolicyEntry>,
    families: &BTreeMap<RuleFamily, FamilyPolicy>,
    trust_sets: Vec<String>,
) {
    if trust_sets.is_empty() {
        return;
    }

    for rule_id in TRUSTED_PATH_RULES {
        let fallback_action = families
            .get(&rule_id.family())
            .map(|family| family.action)
            .unwrap_or_else(|| RulePolicy::default().action_for(rule_id));
        rules
            .entry(rule_id)
            .or_insert_with(|| RulePolicyEntry::new(fallback_action))
            .trust_sets = trust_sets.clone();
    }
}

fn normalize_action(action: RawAction) -> RuleAction {
    match action {
        RawAction::Allow => RuleAction::Observe,
        RawAction::NeedApproval => RuleAction::NeedApproval,
        RawAction::Deny => RuleAction::Deny,
    }
}

fn normalize_failure_action(action: RawAction) -> FailureAction {
    match action {
        RawAction::Allow => FailureAction::Allow,
        RawAction::NeedApproval => FailureAction::NeedApproval,
        RawAction::Deny => FailureAction::Deny,
    }
}

fn normalize_trusted_path_scope(scope: RawTrustedPathScope) -> PathTrustScope {
    match scope {
        RawTrustedPathScope::ScriptExecute => PathTrustScope::ScriptSourceExecute,
        RawTrustedPathScope::StartupConfig => PathTrustScope::StartupConfigLoad,
    }
}

#[cfg(test)]
mod tests {
    use caushell_types::{PathTrustScope, RuleAction, RuleId};

    use crate::{FailureAction, NormalizeConfigError, RawAction, RawConfigFile, normalize_config};

    #[test]
    fn normalizes_user_actions_and_failure_action() {
        let raw = serde_yaml::from_str::<RawConfigFile>(
            r#"
version: 1
failure_action: need_approval
policy:
  rules:
    tainted_execution: need_approval
    interactive_escape_surface: allow
  unknown_commands:
    default: allow
    overrides:
      /usr/local/bin/custom-tool: deny
"#,
        )
        .expect("config should parse");

        let config = normalize_config(raw).expect("config should normalize");

        assert_eq!(config.failure_action, FailureAction::NeedApproval);
        assert_eq!(
            config
                .policy
                .rule_policy
                .action_for(RuleId::TaintedExecution),
            RuleAction::NeedApproval
        );
        assert_eq!(
            config
                .policy
                .rule_policy
                .action_for(RuleId::InteractiveEscapeSurface),
            RuleAction::Observe
        );
        assert_eq!(
            config
                .policy
                .rule_policy
                .action_for_no_profile("custom-tool"),
            RuleAction::Deny
        );
    }

    #[test]
    fn trusted_paths_are_attached_to_path_rules_with_scoped_grants() {
        let raw = serde_yaml::from_str::<RawConfigFile>(
            r#"
version: 1
trusted_paths:
  - root: ~/.local/tools
    scopes: [script_execute]
"#,
        )
        .expect("config should parse");

        let config = normalize_config(raw).expect("config should normalize");
        let trust_set = config
            .policy
            .path_trust_sets
            .get("user_trusted_path_0")
            .expect("trusted path should be normalized");

        assert!(!trust_set.trusts_scope(PathTrustScope::Read));
        assert!(trust_set.trusts_scope(PathTrustScope::ScriptSourceExecute));
        assert!(!trust_set.trusts_scope(PathTrustScope::Write));
        assert_eq!(
            config
                .policy
                .rule_policy
                .trusted_sets_for(RuleId::OutsideWorkspaceScriptSource),
            &["user_trusted_path_0".to_string()]
        );
    }

    #[test]
    fn rejects_hard_deny_floor_downgrade() {
        let mut raw = RawConfigFile::default();
        raw.policy
            .rules
            .insert(RuleId::CatastrophicFileSystemDelete, RawAction::Allow);

        assert_eq!(
            normalize_config(raw),
            Err(NormalizeConfigError::HardDenyFloorCannotBeLowered {
                rule_id: RuleId::CatastrophicFileSystemDelete,
                action: RawAction::Allow,
            })
        );
    }

    #[test]
    fn family_override_cannot_lower_hard_deny_floor() {
        let raw = serde_yaml::from_str::<RawConfigFile>(
            "version: 1\npolicy:\n  families:\n    host_safety: allow\n",
        )
        .expect("config should parse");

        let config = normalize_config(raw).expect("family override should remain valid");

        assert_eq!(
            config
                .policy
                .rule_policy
                .action_for(RuleId::CatastrophicFileSystemDelete),
            RuleAction::Deny
        );
        assert_eq!(
            config
                .policy
                .rule_policy
                .action_for(RuleId::CatastrophicShellProcessExplosion),
            RuleAction::Deny
        );
        assert_eq!(
            config
                .policy
                .rule_policy
                .action_for(RuleId::CatastrophicPathMetadataMutation),
            RuleAction::Observe
        );
    }

    #[test]
    fn rejects_relative_trusted_path() {
        let raw = serde_yaml::from_str::<RawConfigFile>(
            "version: 1\ntrusted_paths:\n  - root: relative/path\n    scopes: [script_execute]\n",
        )
        .expect("config should parse");

        assert!(matches!(
            normalize_config(raw),
            Err(NormalizeConfigError::RelativeTrustedPathRoot { .. })
        ));
    }

    #[test]
    fn rejects_analysis_depth_below_hard_deny_floor() {
        let mut raw = RawConfigFile::default();
        raw.analysis.max_nested_parse_depth = 2;

        assert_eq!(
            normalize_config(raw),
            Err(NormalizeConfigError::HardDenyAnalysisDepthCannotBeLowered {
                actual: 2,
                minimum: 3,
            })
        );
    }
}

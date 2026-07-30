use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ImportedPackageSourceClass, PackageLocatorKind, RuleFamily, RuleId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveGapKind {
    NoProfile,
    UnknownSubcommandPath,
    FormSelectionAmbiguous,
    FormSelectionUnmatched,
    MissingCommandName,
    DynamicCommandTarget,
    UnresolvedWrapperChild,
    UnresolvedExecutionPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedExecutionPayloadSubtype {
    StaticInlineLiteral,
    StaticHeredocLiteral,
    DynamicInlinePayload,
    RuntimeInputPayload,
    ExternalStreamPayload,
    UnknownPayloadShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Observe,
    NeedApproval,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub rule_policy: RulePolicy,
    #[serde(default)]
    pub semantic_expansion: SemanticExpansionPolicy,
    #[serde(default)]
    pub runtime_taint: RuntimeTaintPolicy,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub path_trust_sets: BTreeMap<String, PathTrustSet>,
}

impl PolicyConfig {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticExpansionPolicy {
    pub max_nested_parse_depth: u8,
}

impl Default for SemanticExpansionPolicy {
    fn default() -> Self {
        Self {
            max_nested_parse_depth: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTaintPolicy {
    pub max_hops: u32,
    pub max_visited_nodes: usize,
}

impl Default for RuntimeTaintPolicy {
    fn default() -> Self {
        Self {
            max_hops: 12,
            max_visited_nodes: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RulePolicy {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub families: BTreeMap<RuleFamily, FamilyPolicy>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<RuleId, RulePolicyEntry>,
    #[serde(default, skip_serializing_if = "ResolveGapPolicy::is_default")]
    pub resolve_gap: ResolveGapPolicy,
    #[serde(default, skip_serializing_if = "NoProfilePolicy::is_default")]
    pub no_profile: NoProfilePolicy,
}

impl RulePolicy {
    pub fn action_for(&self, rule_id: RuleId) -> RuleAction {
        self.rules
            .get(&rule_id)
            .map(|entry| entry.action)
            .or_else(|| {
                self.families
                    .get(&rule_id.family())
                    .map(|family| family.action)
            })
            .unwrap_or_else(|| default_rule_action(rule_id))
    }

    pub fn trusted_sets_for(&self, rule_id: RuleId) -> &[String] {
        if let Some(entry) = self.rules.get(&rule_id) {
            return &entry.trust_sets;
        }

        if let Some(family) = self.families.get(&rule_id.family()) {
            return &family.trust_sets;
        }

        &[]
    }

    pub fn action_for_no_profile(&self, normalized_command_name: &str) -> RuleAction {
        self.no_profile
            .commands
            .get(normalized_command_name)
            .copied()
            .unwrap_or(self.no_profile.action)
    }

    pub fn action_for_resolve_gap(&self, gap_kind: ResolveGapKind) -> RuleAction {
        self.resolve_gap
            .defaults
            .get(&gap_kind)
            .copied()
            .unwrap_or_else(|| default_resolve_gap_action(gap_kind))
    }

    pub fn action_for_unresolved_execution_payload_subtype(
        &self,
        subtype: UnresolvedExecutionPayloadSubtype,
    ) -> RuleAction {
        self.resolve_gap
            .unresolved_execution_payload_subtypes
            .get(&subtype)
            .copied()
            .unwrap_or_else(|| default_unresolved_execution_payload_subtype_action(subtype))
    }

    pub fn action_for_imported_package_locator_kind(&self, kind: PackageLocatorKind) -> RuleAction {
        self.rules
            .get(&RuleId::ImportedPackageExecution)
            .map(|entry| entry.action)
            .or_else(|| {
                self.families
                    .get(&RuleId::ImportedPackageExecution.family())
                    .map(|family| family.action)
            })
            .unwrap_or_else(|| default_imported_package_locator_kind_action(kind))
    }

    pub fn imported_package_source_class_for_locator_kind(
        kind: PackageLocatorKind,
    ) -> ImportedPackageSourceClass {
        match kind {
            PackageLocatorKind::RegistryRef => ImportedPackageSourceClass::RegistryRef,
            PackageLocatorKind::DirectUrl => ImportedPackageSourceClass::DirectUrl,
            PackageLocatorKind::VcsUrl => ImportedPackageSourceClass::VcsUrl,
            PackageLocatorKind::LocalPath => ImportedPackageSourceClass::LocalPath,
            PackageLocatorKind::RequirementFile => ImportedPackageSourceClass::RequirementFile,
            PackageLocatorKind::UnknownDynamic => ImportedPackageSourceClass::UnknownDynamic,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyPolicy {
    pub action: RuleAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_sets: Vec<String>,
}

impl FamilyPolicy {
    pub fn new(action: RuleAction) -> Self {
        Self {
            action,
            trust_sets: Vec::new(),
        }
    }

    pub fn with_trust_sets(mut self, trust_sets: Vec<String>) -> Self {
        self.trust_sets = trust_sets;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoProfilePolicy {
    pub action: RuleAction,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub commands: BTreeMap<String, RuleAction>,
}

impl Default for NoProfilePolicy {
    fn default() -> Self {
        Self {
            action: default_resolve_gap_action(ResolveGapKind::NoProfile),
            commands: BTreeMap::new(),
        }
    }
}

impl NoProfilePolicy {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResolveGapPolicy {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub defaults: BTreeMap<ResolveGapKind, RuleAction>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unresolved_execution_payload_subtypes:
        BTreeMap<UnresolvedExecutionPayloadSubtype, RuleAction>,
}

impl ResolveGapPolicy {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePolicyEntry {
    pub action: RuleAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_sets: Vec<String>,
}

impl RulePolicyEntry {
    pub fn new(action: RuleAction) -> Self {
        Self {
            action,
            trust_sets: Vec::new(),
        }
    }

    pub fn with_trust_sets(mut self, trust_sets: Vec<String>) -> Self {
        self.trust_sets = trust_sets;
        self
    }
}

fn default_rule_action(rule_id: RuleId) -> RuleAction {
    match rule_id {
        RuleId::CommandParseFailure => RuleAction::NeedApproval,
        RuleId::InteractiveEscapeSurface => RuleAction::Observe,
        RuleId::CwdOutsideWorkspaceRoot => RuleAction::NeedApproval,
        RuleId::OutsideWorkspaceScriptSource => RuleAction::Observe,
        RuleId::OutsideWorkspaceStartupConfig => RuleAction::Observe,
        RuleId::MissingCommandName => RuleAction::NeedApproval,
        RuleId::SelectionError => RuleAction::NeedApproval,
        RuleId::NoProfile => RuleAction::Observe,
        RuleId::NestedPayloadExpansion => RuleAction::Observe,
        RuleId::NonMonotonicSequence => RuleAction::Deny,
        RuleId::CatastrophicFileSystemDelete => RuleAction::Deny,
        RuleId::CatastrophicShellProcessExplosion => RuleAction::Deny,
        RuleId::CatastrophicPathMetadataMutation => RuleAction::NeedApproval,
        RuleId::CatastrophicPathContentOverwrite => RuleAction::NeedApproval,
        RuleId::CatastrophicPathRelocation => RuleAction::NeedApproval,
        RuleId::CatastrophicPartitionLayoutMutation => RuleAction::NeedApproval,
        RuleId::CatastrophicPartitionTableSession => RuleAction::NeedApproval,
        RuleId::CatastrophicPartitionTableStateMutation => RuleAction::NeedApproval,
        RuleId::CatastrophicPartitionTableMutation => RuleAction::NeedApproval,
        RuleId::GitTrackedWorktreeDiscard
        | RuleId::GitUntrackedWorktreeDelete
        | RuleId::GitForcedWorktreeSwitch
        | RuleId::GitTrackedPathDelete
        | RuleId::GitSavedStateDestroy
        | RuleId::GitLocalRefDestroy => RuleAction::NeedApproval,
        RuleId::TaintedExecution => RuleAction::NeedApproval,
        RuleId::ImportedPackageExecution => RuleAction::Observe,
    }
}

fn default_resolve_gap_action(gap_kind: ResolveGapKind) -> RuleAction {
    match gap_kind {
        ResolveGapKind::NoProfile => RuleAction::Observe,
        ResolveGapKind::UnknownSubcommandPath => RuleAction::Observe,
        ResolveGapKind::FormSelectionAmbiguous => RuleAction::Observe,
        ResolveGapKind::FormSelectionUnmatched => RuleAction::Observe,
        ResolveGapKind::MissingCommandName => RuleAction::NeedApproval,
        ResolveGapKind::DynamicCommandTarget => RuleAction::NeedApproval,
        ResolveGapKind::UnresolvedWrapperChild => RuleAction::NeedApproval,
        ResolveGapKind::UnresolvedExecutionPayload => RuleAction::NeedApproval,
    }
}

fn default_unresolved_execution_payload_subtype_action(
    subtype: UnresolvedExecutionPayloadSubtype,
) -> RuleAction {
    match subtype {
        UnresolvedExecutionPayloadSubtype::StaticInlineLiteral => RuleAction::Observe,
        UnresolvedExecutionPayloadSubtype::StaticHeredocLiteral => RuleAction::Observe,
        UnresolvedExecutionPayloadSubtype::DynamicInlinePayload => RuleAction::NeedApproval,
        UnresolvedExecutionPayloadSubtype::RuntimeInputPayload => RuleAction::NeedApproval,
        UnresolvedExecutionPayloadSubtype::ExternalStreamPayload => RuleAction::NeedApproval,
        UnresolvedExecutionPayloadSubtype::UnknownPayloadShape => RuleAction::NeedApproval,
    }
}

fn default_imported_package_locator_kind_action(kind: PackageLocatorKind) -> RuleAction {
    match kind {
        PackageLocatorKind::RegistryRef => RuleAction::Observe,
        PackageLocatorKind::LocalPath
        | PackageLocatorKind::DirectUrl
        | PackageLocatorKind::VcsUrl
        | PackageLocatorKind::RequirementFile
        | PackageLocatorKind::UnknownDynamic => RuleAction::NeedApproval,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTrustScope {
    Read,
    Write,
    ScriptSourceExecute,
    StartupConfigLoad,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathTrustSet {
    pub roots: Vec<String>,
    pub grant: PathTrustGrant,
}

impl PathTrustSet {
    pub fn new(roots: Vec<String>, grant: PathTrustGrant) -> Self {
        Self { roots, grant }
    }

    pub fn trusts_scope(&self, scope: PathTrustScope) -> bool {
        self.grant.trusts_scope(scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathTrustGrant {
    Full,
    Scoped { scopes: BTreeSet<PathTrustScope> },
}

impl PathTrustGrant {
    pub fn trusts_scope(&self, scope: PathTrustScope) -> bool {
        match self {
            Self::Full => true,
            Self::Scoped { scopes } => scopes.contains(&scope),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FamilyPolicy, NoProfilePolicy, PathTrustGrant, PathTrustScope, PathTrustSet, PolicyConfig,
        ResolveGapKind, ResolveGapPolicy, RuleAction, RulePolicy, RulePolicyEntry,
        RuntimeTaintPolicy, SemanticExpansionPolicy,
    };
    use crate::{PackageLocatorKind, RuleFamily, RuleId};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn policy_config_defaults_to_default_rule_policy_and_empty_trust_sets() {
        let config = PolicyConfig::default();

        assert_eq!(config.rule_policy, RulePolicy::default());
        assert!(config.path_trust_sets.is_empty());
        assert_eq!(
            config.rule_policy.action_for(RuleId::CommandParseFailure),
            RuleAction::NeedApproval
        );
        assert_eq!(
            config
                .rule_policy
                .action_for(RuleId::InteractiveEscapeSurface),
            RuleAction::Observe
        );
        assert_eq!(
            config.rule_policy.action_for(RuleId::NoProfile),
            RuleAction::Observe
        );
        assert_eq!(
            config
                .rule_policy
                .action_for(RuleId::NestedPayloadExpansion),
            RuleAction::Observe
        );
        assert_eq!(
            config.rule_policy.action_for(RuleId::NonMonotonicSequence),
            RuleAction::Deny
        );
        assert_eq!(
            config
                .rule_policy
                .action_for(RuleId::CatastrophicShellProcessExplosion),
            RuleAction::Deny
        );
        assert_eq!(
            config.rule_policy.action_for(RuleId::TaintedExecution),
            RuleAction::NeedApproval
        );
        assert_eq!(
            config
                .rule_policy
                .action_for(RuleId::ImportedPackageExecution),
            RuleAction::Observe
        );
        assert_eq!(
            config
                .rule_policy
                .action_for(RuleId::GitTrackedWorktreeDiscard),
            RuleAction::NeedApproval
        );
        assert_eq!(
            config
                .rule_policy
                .action_for_imported_package_locator_kind(PackageLocatorKind::RegistryRef),
            RuleAction::Observe
        );
        assert_eq!(
            config
                .rule_policy
                .action_for_imported_package_locator_kind(PackageLocatorKind::VcsUrl),
            RuleAction::NeedApproval
        );
        assert_eq!(config.runtime_taint, RuntimeTaintPolicy::default());
    }

    #[test]
    fn family_default_action_applies_when_no_rule_override_exists() {
        let policy = RulePolicy {
            families: BTreeMap::from([(
                RuleFamily::Path,
                FamilyPolicy::new(RuleAction::NeedApproval),
            )]),
            ..RulePolicy::default()
        };

        assert_eq!(
            policy.action_for(RuleId::OutsideWorkspaceScriptSource),
            RuleAction::NeedApproval
        );
        assert_eq!(
            policy.action_for(RuleId::OutsideWorkspaceStartupConfig),
            RuleAction::NeedApproval
        );
    }

    #[test]
    fn rule_override_wins_over_family_default() {
        let policy = RulePolicy {
            families: BTreeMap::from([(
                RuleFamily::Path,
                FamilyPolicy::new(RuleAction::NeedApproval),
            )]),
            rules: BTreeMap::from([(
                RuleId::OutsideWorkspaceStartupConfig,
                RulePolicyEntry::new(RuleAction::Deny),
            )]),
            ..RulePolicy::default()
        };

        assert_eq!(
            policy.action_for(RuleId::OutsideWorkspaceScriptSource),
            RuleAction::NeedApproval
        );
        assert_eq!(
            policy.action_for(RuleId::OutsideWorkspaceStartupConfig),
            RuleAction::Deny
        );
    }

    #[test]
    fn rule_specific_trust_sets_win_over_family_defaults() {
        let policy = RulePolicy {
            families: BTreeMap::from([(
                RuleFamily::Path,
                FamilyPolicy::new(RuleAction::Observe)
                    .with_trust_sets(vec!["family_paths".to_string()]),
            )]),
            rules: BTreeMap::from([(
                RuleId::OutsideWorkspaceScriptSource,
                RulePolicyEntry::new(RuleAction::NeedApproval)
                    .with_trust_sets(vec!["script_paths".to_string()]),
            )]),
            ..RulePolicy::default()
        };

        assert_eq!(
            policy.trusted_sets_for(RuleId::OutsideWorkspaceScriptSource),
            ["script_paths".to_string()]
        );
        assert_eq!(
            policy.trusted_sets_for(RuleId::OutsideWorkspaceStartupConfig),
            ["family_paths".to_string()]
        );
    }

    #[test]
    fn imported_package_locator_kind_honors_family_override() {
        let policy = RulePolicy {
            families: BTreeMap::from([(
                RuleFamily::Taint,
                FamilyPolicy::new(RuleAction::NeedApproval),
            )]),
            ..RulePolicy::default()
        };

        assert_eq!(
            policy.action_for_imported_package_locator_kind(PackageLocatorKind::RegistryRef),
            RuleAction::NeedApproval
        );
        assert_eq!(
            policy.action_for_imported_package_locator_kind(PackageLocatorKind::VcsUrl),
            RuleAction::NeedApproval
        );
    }

    #[test]
    fn imported_package_locator_kind_defaults_to_need_approval_for_dynamic_sources() {
        let policy = RulePolicy::default();

        assert_eq!(
            policy.action_for_imported_package_locator_kind(PackageLocatorKind::UnknownDynamic),
            RuleAction::NeedApproval
        );
        assert_eq!(
            policy.action_for_imported_package_locator_kind(PackageLocatorKind::RequirementFile),
            RuleAction::NeedApproval
        );
    }

    #[test]
    fn no_profile_override_falls_back_to_rule_action() {
        let policy = RulePolicy {
            no_profile: NoProfilePolicy {
                action: RuleAction::NeedApproval,
                commands: BTreeMap::from([("sudo".to_string(), RuleAction::Deny)]),
            },
            ..RulePolicy::default()
        };

        assert_eq!(policy.action_for_no_profile("sudo"), RuleAction::Deny);
        assert_eq!(
            policy.action_for_no_profile("unknown-tool"),
            RuleAction::NeedApproval
        );
    }

    #[test]
    fn resolve_gap_policy_defaults_to_relaxed_benign_gaps() {
        let policy = RulePolicy::default();

        assert_eq!(
            policy.action_for_resolve_gap(ResolveGapKind::NoProfile),
            RuleAction::Observe
        );
        assert_eq!(
            policy.action_for_resolve_gap(ResolveGapKind::UnknownSubcommandPath),
            RuleAction::Observe
        );
        assert_eq!(
            policy.action_for_resolve_gap(ResolveGapKind::MissingCommandName),
            RuleAction::NeedApproval
        );
        assert_eq!(
            policy.action_for_resolve_gap(ResolveGapKind::DynamicCommandTarget),
            RuleAction::NeedApproval
        );
        assert_eq!(
            policy.action_for_resolve_gap(ResolveGapKind::UnresolvedWrapperChild),
            RuleAction::NeedApproval
        );
        assert_eq!(
            policy.action_for_resolve_gap(ResolveGapKind::UnresolvedExecutionPayload),
            RuleAction::NeedApproval
        );
    }

    #[test]
    fn policy_config_roundtrips_through_json_contract() {
        let config = PolicyConfig {
            rule_policy: RulePolicy {
                families: BTreeMap::from([(
                    RuleFamily::Path,
                    FamilyPolicy::new(RuleAction::NeedApproval)
                        .with_trust_sets(vec!["system_scripts".to_string()]),
                )]),
                rules: BTreeMap::from([
                    (
                        RuleId::OutsideWorkspaceStartupConfig,
                        RulePolicyEntry::new(RuleAction::Deny)
                            .with_trust_sets(vec!["system_scripts".to_string()]),
                    ),
                    (
                        RuleId::SelectionError,
                        RulePolicyEntry::new(RuleAction::Deny),
                    ),
                ]),
                resolve_gap: ResolveGapPolicy {
                    defaults: BTreeMap::from([(
                        ResolveGapKind::UnknownSubcommandPath,
                        RuleAction::Observe,
                    )]),
                    unresolved_execution_payload_subtypes: BTreeMap::new(),
                },
                no_profile: NoProfilePolicy {
                    action: RuleAction::Observe,
                    commands: BTreeMap::from([("sudo".to_string(), RuleAction::NeedApproval)]),
                },
            },
            semantic_expansion: SemanticExpansionPolicy::default(),
            runtime_taint: RuntimeTaintPolicy::default(),
            path_trust_sets: BTreeMap::from([
                (
                    "system_scripts".to_string(),
                    PathTrustSet::new(
                        vec!["/usr/lib/git-core".to_string(), "/nix/store".to_string()],
                        PathTrustGrant::Full,
                    ),
                ),
                (
                    "user_scripts".to_string(),
                    PathTrustSet::new(
                        vec!["~/.local/share/trusted-scripts".to_string()],
                        PathTrustGrant::Scoped {
                            scopes: BTreeSet::from([PathTrustScope::ScriptSourceExecute]),
                        },
                    ),
                ),
            ]),
        };

        let value =
            serde_json::to_value(&config).expect("expected policy config to serialize to json");

        assert_eq!(
            value,
            json!({
                "rule_policy": {
                    "families": {
                        "path": {
                            "action": "need_approval",
                            "trust_sets": ["system_scripts"]
                        }
                    },
                    "rules": {
                        "outside_workspace_startup_config": {
                            "action": "deny",
                            "trust_sets": ["system_scripts"]
                        },
                        "selection_error": {
                            "action": "deny"
                        }
                    },
                    "resolve_gap": {
                        "defaults": {
                            "unknown_subcommand_path": "observe"
                        }
                    },
                    "no_profile": {
                        "action": "observe",
                        "commands": {
                            "sudo": "need_approval"
                        }
                    }
                },
                "semantic_expansion": {
                    "max_nested_parse_depth": 3
                },
                "runtime_taint": {
                    "max_hops": 12,
                    "max_visited_nodes": 256
                },
                "path_trust_sets": {
                    "system_scripts": {
                        "roots": ["/usr/lib/git-core", "/nix/store"],
                        "grant": {
                            "kind": "full"
                        }
                    },
                    "user_scripts": {
                        "roots": ["~/.local/share/trusted-scripts"],
                        "grant": {
                            "kind": "scoped",
                            "scopes": ["script_source_execute"]
                        }
                    }
                }
            })
        );

        let roundtrip: PolicyConfig =
            serde_json::from_value(value).expect("expected policy config to deserialize");

        assert_eq!(roundtrip, config);
    }

    #[test]
    fn path_trust_grant_full_trusts_all_scopes() {
        let grant = PathTrustGrant::Full;

        assert!(grant.trusts_scope(PathTrustScope::Read));
        assert!(grant.trusts_scope(PathTrustScope::Write));
        assert!(grant.trusts_scope(PathTrustScope::ScriptSourceExecute));
        assert!(grant.trusts_scope(PathTrustScope::StartupConfigLoad));
    }

    #[test]
    fn path_trust_grant_scoped_only_trusts_listed_scopes() {
        let grant = PathTrustGrant::Scoped {
            scopes: BTreeSet::from([PathTrustScope::Read, PathTrustScope::ScriptSourceExecute]),
        };

        assert!(grant.trusts_scope(PathTrustScope::Read));
        assert!(grant.trusts_scope(PathTrustScope::ScriptSourceExecute));
        assert!(!grant.trusts_scope(PathTrustScope::Write));
        assert!(!grant.trusts_scope(PathTrustScope::StartupConfigLoad));
    }
}

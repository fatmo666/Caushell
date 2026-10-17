//! Request-local, purpose-scoped path exemptions; never a final Allow decision.
use caushell_query::{PathScopeProof, PathScopeQuery, normalize_shell_path, path_is_within_root};
use caushell_types::{
    MutationExemptionOperation, PathResolution, PathTrustScope, PolicyConfig, RuleId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOperation {
    Write,
    OrdinaryMetadata,
    PermissionMetadata,
    MoveSource,
    UnspecifiedMutation,
    ExecuteFile,
    LoadCodeFile,
    StartupConfig,
    Delete,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathExemptionBasis {
    Workspace,
    Temporary,
    Configured,
    Combined,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathExemption {
    Exempt { basis: PathExemptionBasis },
    NotExempt,
    Unproven,
}
impl PathExemption {
    pub fn is_exempt(self) -> bool {
        matches!(self, Self::Exempt { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    root: String,
    operations: Vec<PathOperation>,
    rule: Option<RuleId>,
    basis: PathExemptionBasis,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathExemptionPolicy {
    grants: Vec<Grant>,
}

impl PathExemptionPolicy {
    pub fn new(workspace: Option<&str>, home: Option<&str>, policy: &PolicyConfig) -> Self {
        let mut grants = Vec::new();
        let mut add = |root: &str, operations: Vec<PathOperation>, rule, basis| {
            if root.starts_with('/') && !root.contains('\0') {
                grants.push(Grant {
                    root: normalize_shell_path(root),
                    operations,
                    rule,
                    basis,
                });
            }
        };
        if let Some(root) = workspace {
            add(
                root,
                vec![
                    PathOperation::Write,
                    PathOperation::OrdinaryMetadata,
                    PathOperation::PermissionMetadata,
                    PathOperation::MoveSource,
                    PathOperation::UnspecifiedMutation,
                    PathOperation::ExecuteFile,
                    PathOperation::LoadCodeFile,
                    PathOperation::StartupConfig,
                ],
                None,
                PathExemptionBasis::Workspace,
            );
        }
        for root in caushell_types::DEFAULT_TEMPORARY_PATH_ROOTS {
            add(
                root,
                vec![PathOperation::ExecuteFile, PathOperation::LoadCodeFile],
                None,
                PathExemptionBasis::Temporary,
            );
        }
        for entry in &policy.mutation_path_exemptions {
            let mut ops = Vec::new();
            for op in &entry.operations {
                match op {
                    MutationExemptionOperation::Write => ops.push(PathOperation::Write),
                    MutationExemptionOperation::OrdinaryMetadata => {
                        ops.push(PathOperation::OrdinaryMetadata)
                    }
                    MutationExemptionOperation::PermissionMetadata => ops.extend([
                        PathOperation::OrdinaryMetadata,
                        PathOperation::PermissionMetadata,
                    ]),
                }
            }
            add(
                &entry.root,
                ops,
                Some(RuleId::OutsideWorkspaceMutation),
                PathExemptionBasis::Configured,
            );
        }
        for (rule, scope, op) in [
            (
                RuleId::CodeLoadPath,
                PathTrustScope::InProcessCodeLoad,
                PathOperation::LoadCodeFile,
            ),
            (
                RuleId::OutsideWorkspaceScriptSource,
                PathTrustScope::ScriptSourceExecute,
                PathOperation::ExecuteFile,
            ),
            (
                RuleId::OutsideWorkspaceStartupConfig,
                PathTrustScope::StartupConfigLoad,
                PathOperation::StartupConfig,
            ),
        ] {
            for name in policy.rule_policy.trusted_sets_for(rule) {
                let Some(set) = policy
                    .path_trust_sets
                    .get(name)
                    .filter(|s| s.trusts_scope(scope))
                else {
                    continue;
                };
                for root in &set.roots {
                    let expanded;
                    let root = if root == "~" || root.starts_with("~/") {
                        let Some(home) = home.filter(|h| h.starts_with('/')) else {
                            continue;
                        };
                        expanded = if root == "~" {
                            home.to_owned()
                        } else {
                            format!("{}/{}", home.trim_end_matches('/'), &root[2..])
                        };
                        &expanded
                    } else {
                        root
                    };
                    add(root, vec![op], Some(rule), PathExemptionBasis::Configured);
                }
            }
        }
        Self { grants }
    }
    pub fn check(
        &self,
        resolution: &PathResolution,
        operation: PathOperation,
        rule: RuleId,
    ) -> PathExemption {
        let mut basis = None;
        let proof = PathScopeQuery::new(resolution).prove_all(|path| {
            let grant = self.grants.iter().find(|g| {
                g.rule.is_none_or(|r| r == rule)
                    && g.operations.contains(&operation)
                    && path_is_within_root(path, &g.root)
            });
            if let Some(g) = grant {
                basis = Some(match basis {
                    None => g.basis,
                    Some(b) if b == g.basis => b,
                    _ => PathExemptionBasis::Combined,
                });
            }
            grant.is_some()
        });
        match proof {
            PathScopeProof::Covered => PathExemption::Exempt {
                basis: basis.unwrap(),
            },
            PathScopeProof::Outside => PathExemption::NotExempt,
            PathScopeProof::Unproven => PathExemption::Unproven,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_types::{PathTrustGrant, PathTrustSet, RuleAction, RulePolicyEntry};

    #[test]
    fn configured_grants_require_both_selected_rule_and_operation_scope() {
        let mut config = PolicyConfig::default();
        config.path_trust_sets.insert(
            "scripts".into(),
            PathTrustSet::new(
                vec!["~/tools".into(), "relative".into()],
                PathTrustGrant::Scoped {
                    scopes: [PathTrustScope::ScriptSourceExecute].into_iter().collect(),
                },
            ),
        );
        for rule in [
            RuleId::OutsideWorkspaceScriptSource,
            RuleId::CodeLoadPath,
            RuleId::OutsideWorkspaceStartupConfig,
        ] {
            config.rule_policy.rules.insert(
                rule,
                RulePolicyEntry::new(RuleAction::NeedApproval)
                    .with_trust_sets(vec!["scripts".into()]),
            );
        }
        let path = PathResolution::Concrete {
            path: "/home/alice/tools/test".into(),
        };
        let policy = PathExemptionPolicy::new(None, Some("/home/alice"), &config);
        assert_eq!(
            policy.check(
                &path,
                PathOperation::ExecuteFile,
                RuleId::OutsideWorkspaceScriptSource
            ),
            PathExemption::Exempt {
                basis: PathExemptionBasis::Configured
            }
        );
        for (op, rule) in [
            (PathOperation::LoadCodeFile, RuleId::CodeLoadPath),
            (
                PathOperation::StartupConfig,
                RuleId::OutsideWorkspaceStartupConfig,
            ),
            (PathOperation::Write, RuleId::OutsideWorkspaceMutation),
        ] {
            assert_eq!(policy.check(&path, op, rule), PathExemption::NotExempt);
        }
        assert_eq!(
            PathExemptionPolicy::new(None, None, &config).check(
                &path,
                PathOperation::ExecuteFile,
                RuleId::OutsideWorkspaceScriptSource
            ),
            PathExemption::NotExempt
        );
        config
            .rule_policy
            .rules
            .remove(&RuleId::OutsideWorkspaceScriptSource);
        assert_eq!(
            PathExemptionPolicy::new(None, Some("/home/alice"), &config).check(
                &path,
                PathOperation::ExecuteFile,
                RuleId::OutsideWorkspaceScriptSource
            ),
            PathExemption::NotExempt
        );
    }

    #[test]
    fn mutation_configuration_cannot_grant_execution_or_deletion() {
        let mut config = PolicyConfig::default();
        config.mutation_path_exemptions = vec![caushell_types::MutationPathExemption {
            root: "/opt/cache".into(),
            operations: [MutationExemptionOperation::Write].into_iter().collect(),
        }];
        let p = PathExemptionPolicy::new(Some("/work"), None, &config);
        let path = PathResolution::Concrete {
            path: "/opt/cache/file".into(),
        };
        assert!(
            p.check(
                &path,
                PathOperation::Write,
                RuleId::OutsideWorkspaceMutation
            )
            .is_exempt()
        );
        assert!(
            !p.check(
                &path,
                PathOperation::PermissionMetadata,
                RuleId::OutsideWorkspaceMutation
            )
            .is_exempt()
        );
        assert!(
            !p.check(
                &path,
                PathOperation::ExecuteFile,
                RuleId::OutsideWorkspaceScriptSource
            )
            .is_exempt()
        );
        assert!(
            !p.check(&path, PathOperation::Delete, RuleId::FileDeletion)
                .is_exempt()
        );
        assert!(
            !p.check(
                &PathResolution::Concrete {
                    path: "/tmp/file".into()
                },
                PathOperation::Write,
                RuleId::OutsideWorkspaceMutation
            )
            .is_exempt()
        );
    }
    #[test]
    fn location_never_authorizes_a_different_purpose() {
        let p = PathExemptionPolicy::new(Some("/work"), None, &PolicyConfig::default());
        let path = |s: &str| PathResolution::Concrete { path: s.into() };
        assert!(
            p.check(
                &path("/work/a"),
                PathOperation::ExecuteFile,
                RuleId::OutsideWorkspaceScriptSource
            )
            .is_exempt()
        );
        assert!(
            p.check(
                &path("/tmp/a"),
                PathOperation::ExecuteFile,
                RuleId::OutsideWorkspaceScriptSource
            )
            .is_exempt()
        );
        assert!(
            !p.check(&path("/tmp/a"), PathOperation::Delete, RuleId::FileDeletion)
                .is_exempt()
        );
        assert!(
            !p.check(
                &path("/work/a"),
                PathOperation::Delete,
                RuleId::FileDeletion
            )
            .is_exempt()
        );
        assert!(
            !p.check(
                &path("/tmp/a"),
                PathOperation::StartupConfig,
                RuleId::OutsideWorkspaceStartupConfig
            )
            .is_exempt()
        );
        assert!(
            !p.check(
                &path("/tmp/a"),
                PathOperation::MoveSource,
                RuleId::OutsideWorkspaceMutation
            )
            .is_exempt()
        );
        let mixed = PathResolution::BoundedPathSet {
            roots: vec!["/work/a".into(), "/tmp/b".into()],
            may_escape: false,
        };
        assert!(
            p.check(
                &mixed,
                PathOperation::Write,
                RuleId::OutsideWorkspaceMutation
            )
            .is_exempt()
        );
        assert!(
            !p.check(
                &path("/tmp-extra/a"),
                PathOperation::Write,
                RuleId::OutsideWorkspaceMutation
            )
            .is_exempt()
        );
    }
}

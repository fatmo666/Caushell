use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedPathRole {
    Read,
    Write,
    MetadataMutation,
    Target,
    Config,
    CwdAnchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMetadataMutationKind {
    ChangeMode,
    ChangeOwner,
    ChangeGroup,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OwnerGroupSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default)]
    pub trailing_colon: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathMetadataMutation {
    pub mutation_kinds: Vec<PathMetadataMutationKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_operand: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_group: Option<OwnerGroupSpec>,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedPathPurpose {
    GenericOperand,
    ScriptSource,
    InProcessCode,
    StartupConfig,
    ProjectConfig,
    ToolConfig,
    TaskConfig,
    WorkingDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedMutationScopeOperation {
    Write,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryWorktreePathSet {
    Tracked,
    PatchSelectedTracked,
    RegisteredSubmoduleWorktrees,
    UntrackedOnly,
    IgnoredOnly,
    UntrackedAndIgnored,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepositoryWorktreeScopeResolution {
    WholeWorktree,
    Subtree { path: PathResolution },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MutationScopeResolution {
    RepositoryWorktree {
        root: PathResolution,
        path_set: RepositoryWorktreePathSet,
        scope: RepositoryWorktreeScopeResolution,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedPathRule {
    AppendSuffix { suffix: String },
    StripSuffix { suffix: String },
    ReplaceSuffix { from: String, to: String },
    UrlBasename,
    ArchiveMembers,
    ChildUnder { relative_path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedPathBasis {
    PathOperand {
        raw: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolved_input_path: Option<String>,
        slot_name: String,
    },
    EndpointOperand {
        raw: String,
        slot_name: String,
    },
    ToolConventionRoot {
        path: String,
        convention: String,
    },
    ConfigDerivedRoot {
        config_path: String,
        convention: String,
        key: String,
        value: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedPathUnresolvedReason {
    UnknownArchiveMembers,
    MissingUrlBasename,
    MissingWorkspaceRoot,
    UnsupportedOperandShape,
    UnsupportedRuntimeRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathResolution {
    Concrete {
        path: String,
    },
    ToolConvention {
        path: String,
        convention: String,
    },
    DerivedConcrete {
        path: String,
        basis: DerivedPathBasis,
        rule: DerivedPathRule,
    },
    DerivedUnresolved {
        basis: DerivedPathBasis,
        rule: DerivedPathRule,
        reason: DerivedPathUnresolvedReason,
    },
    MissingBinding {
        variable_name: String,
    },
    UnsupportedDynamicBinding {
        variable_name: String,
        repr: String,
    },
    UnsupportedDynamicText {
        text: String,
    },
    HomeUnavailable {
        text: String,
    },
}

impl PathResolution {
    pub fn concrete_path(&self) -> Option<&str> {
        match self {
            Self::Concrete { path }
            | Self::ToolConvention { path, .. }
            | Self::DerivedConcrete { path, .. } => Some(path.as_str()),
            Self::DerivedUnresolved { .. }
            | Self::MissingBinding { .. }
            | Self::UnsupportedDynamicBinding { .. }
            | Self::UnsupportedDynamicText { .. }
            | Self::HomeUnavailable { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DerivedPathBasis, DerivedPathRule, DerivedPathUnresolvedReason, MutationScopeResolution,
        PathResolution, RepositoryWorktreePathSet, RepositoryWorktreeScopeResolution,
    };
    use serde_json::json;

    #[test]
    fn tool_convention_path_resolution_uses_stable_json_contract() {
        let resolution = PathResolution::ToolConvention {
            path: "/tmp/project/package.json".to_string(),
            convention: "npm.package_json".to_string(),
        };

        let value = serde_json::to_value(&resolution).expect("expected resolution to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "tool_convention",
                "path": "/tmp/project/package.json",
                "convention": "npm.package_json"
            })
        );

        let roundtrip: PathResolution =
            serde_json::from_value(value).expect("expected resolution to deserialize");
        assert_eq!(roundtrip, resolution);
        assert_eq!(roundtrip.concrete_path(), Some("/tmp/project/package.json"));
    }

    #[test]
    fn derived_concrete_path_resolution_uses_stable_json_contract() {
        let resolution = PathResolution::DerivedConcrete {
            path: "/tmp/project/foo.txt.gz".to_string(),
            basis: DerivedPathBasis::PathOperand {
                raw: "foo.txt".to_string(),
                resolved_input_path: Some("/tmp/project/foo.txt".to_string()),
                slot_name: "input_paths".to_string(),
            },
            rule: DerivedPathRule::AppendSuffix {
                suffix: ".gz".to_string(),
            },
        };

        let value = serde_json::to_value(&resolution).expect("expected resolution to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "derived_concrete",
                "path": "/tmp/project/foo.txt.gz",
                "basis": {
                    "kind": "path_operand",
                    "raw": "foo.txt",
                    "resolved_input_path": "/tmp/project/foo.txt",
                    "slot_name": "input_paths"
                },
                "rule": {
                    "kind": "append_suffix",
                    "suffix": ".gz"
                }
            })
        );

        let roundtrip: PathResolution =
            serde_json::from_value(value).expect("expected resolution to deserialize");
        assert_eq!(roundtrip, resolution);
        assert_eq!(roundtrip.concrete_path(), Some("/tmp/project/foo.txt.gz"));
    }

    #[test]
    fn derived_unresolved_path_resolution_uses_stable_json_contract() {
        let resolution = PathResolution::DerivedUnresolved {
            basis: DerivedPathBasis::PathOperand {
                raw: "archive.tar".to_string(),
                resolved_input_path: Some("/tmp/project/archive.tar".to_string()),
                slot_name: "archive_path".to_string(),
            },
            rule: DerivedPathRule::ArchiveMembers,
            reason: DerivedPathUnresolvedReason::UnknownArchiveMembers,
        };

        let value = serde_json::to_value(&resolution).expect("expected resolution to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "derived_unresolved",
                "basis": {
                    "kind": "path_operand",
                    "raw": "archive.tar",
                    "resolved_input_path": "/tmp/project/archive.tar",
                    "slot_name": "archive_path"
                },
                "rule": {
                    "kind": "archive_members"
                },
                "reason": "unknown_archive_members"
            })
        );

        let roundtrip: PathResolution =
            serde_json::from_value(value).expect("expected resolution to deserialize");
        assert_eq!(roundtrip, resolution);
        assert_eq!(roundtrip.concrete_path(), None);
    }

    #[test]
    fn repository_worktree_mutation_scope_resolution_uses_stable_json_contract() {
        let resolution = MutationScopeResolution::RepositoryWorktree {
            root: PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            path_set: RepositoryWorktreePathSet::UntrackedAndIgnored,
            scope: RepositoryWorktreeScopeResolution::WholeWorktree,
        };

        let value = serde_json::to_value(&resolution).expect("expected resolution to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "repository_worktree",
                "root": {
                    "kind": "concrete",
                    "path": "/tmp/project"
                },
                "path_set": "untracked_and_ignored",
                "scope": {
                    "kind": "whole_worktree"
                }
            })
        );

        let roundtrip: MutationScopeResolution =
            serde_json::from_value(value).expect("expected resolution to deserialize");
        assert_eq!(roundtrip, resolution);
    }

    #[test]
    fn repository_worktree_patch_selected_resolution_uses_stable_json_contract() {
        let resolution = MutationScopeResolution::RepositoryWorktree {
            root: PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            path_set: RepositoryWorktreePathSet::PatchSelectedTracked,
            scope: RepositoryWorktreeScopeResolution::WholeWorktree,
        };

        let value = serde_json::to_value(&resolution).expect("expected resolution to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "repository_worktree",
                "root": {
                    "kind": "concrete",
                    "path": "/tmp/project"
                },
                "path_set": "patch_selected_tracked",
                "scope": {
                    "kind": "whole_worktree"
                }
            })
        );

        let roundtrip: MutationScopeResolution =
            serde_json::from_value(value).expect("expected resolution to deserialize");
        assert_eq!(roundtrip, resolution);
    }

    #[test]
    fn repository_worktree_registered_submodule_resolution_uses_stable_json_contract() {
        let resolution = MutationScopeResolution::RepositoryWorktree {
            root: PathResolution::Concrete {
                path: "/tmp/project".to_string(),
            },
            path_set: RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees,
            scope: RepositoryWorktreeScopeResolution::WholeWorktree,
        };

        let value = serde_json::to_value(&resolution).expect("expected resolution to serialize");

        assert_eq!(
            value,
            json!({
                "kind": "repository_worktree",
                "root": {
                    "kind": "concrete",
                    "path": "/tmp/project"
                },
                "path_set": "registered_submodule_worktrees",
                "scope": {
                    "kind": "whole_worktree"
                }
            })
        );

        let roundtrip: MutationScopeResolution =
            serde_json::from_value(value).expect("expected resolution to deserialize");
        assert_eq!(roundtrip, resolution);
    }
}

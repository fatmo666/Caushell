use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleFamily {
    InteractiveControl,
    Path,
    ResolveGap,
    SemanticExpansion,
    SessionIntegrity,
    HostSafety,
    RepositorySafety,
    Taint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    CommandParseFailure,
    InteractiveEscapeSurface,
    CwdOutsideWorkspaceRoot,
    OutsideWorkspaceScriptSource,
    OutsideWorkspaceStartupConfig,
    MissingCommandName,
    SelectionError,
    NoProfile,
    NestedPayloadExpansion,
    NonMonotonicSequence,
    CatastrophicFileSystemDelete,
    CatastrophicShellProcessExplosion,
    CatastrophicPathMetadataMutation,
    CatastrophicPathRelocation,
    CatastrophicPartitionLayoutMutation,
    CatastrophicPartitionTableSession,
    CatastrophicPartitionTableStateMutation,
    CatastrophicPartitionTableMutation,
    GitTrackedWorktreeDiscard,
    GitUntrackedWorktreeDelete,
    GitForcedWorktreeSwitch,
    GitTrackedPathDelete,
    GitSavedStateDestroy,
    GitLocalRefDestroy,
    TaintedExecution,
    ImportedPackageExecution,
}

impl RuleId {
    pub const fn family(self) -> RuleFamily {
        match self {
            Self::CommandParseFailure => RuleFamily::ResolveGap,
            Self::InteractiveEscapeSurface => RuleFamily::InteractiveControl,
            Self::CwdOutsideWorkspaceRoot => RuleFamily::Path,
            Self::OutsideWorkspaceScriptSource => RuleFamily::Path,
            Self::OutsideWorkspaceStartupConfig => RuleFamily::Path,
            Self::MissingCommandName => RuleFamily::ResolveGap,
            Self::SelectionError => RuleFamily::ResolveGap,
            Self::NoProfile => RuleFamily::ResolveGap,
            Self::NestedPayloadExpansion => RuleFamily::SemanticExpansion,
            Self::NonMonotonicSequence => RuleFamily::SessionIntegrity,
            Self::CatastrophicFileSystemDelete => RuleFamily::HostSafety,
            Self::CatastrophicShellProcessExplosion => RuleFamily::HostSafety,
            Self::CatastrophicPathMetadataMutation => RuleFamily::HostSafety,
            Self::CatastrophicPathRelocation => RuleFamily::HostSafety,
            Self::CatastrophicPartitionLayoutMutation => RuleFamily::HostSafety,
            Self::CatastrophicPartitionTableSession => RuleFamily::HostSafety,
            Self::CatastrophicPartitionTableStateMutation => RuleFamily::HostSafety,
            Self::CatastrophicPartitionTableMutation => RuleFamily::HostSafety,
            Self::GitTrackedWorktreeDiscard
            | Self::GitUntrackedWorktreeDelete
            | Self::GitForcedWorktreeSwitch
            | Self::GitTrackedPathDelete
            | Self::GitSavedStateDestroy
            | Self::GitLocalRefDestroy => RuleFamily::RepositorySafety,
            Self::TaintedExecution => RuleFamily::Taint,
            Self::ImportedPackageExecution => RuleFamily::Taint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuleFamily, RuleId};
    use serde_json::json;

    #[test]
    fn rule_ids_map_to_the_expected_family() {
        assert_eq!(RuleId::CommandParseFailure.family(), RuleFamily::ResolveGap);
        assert_eq!(
            RuleId::InteractiveEscapeSurface.family(),
            RuleFamily::InteractiveControl
        );
        assert_eq!(RuleId::CwdOutsideWorkspaceRoot.family(), RuleFamily::Path);
        assert_eq!(
            RuleId::OutsideWorkspaceScriptSource.family(),
            RuleFamily::Path
        );
        assert_eq!(
            RuleId::OutsideWorkspaceStartupConfig.family(),
            RuleFamily::Path
        );
        assert_eq!(RuleId::MissingCommandName.family(), RuleFamily::ResolveGap);
        assert_eq!(RuleId::SelectionError.family(), RuleFamily::ResolveGap);
        assert_eq!(RuleId::NoProfile.family(), RuleFamily::ResolveGap);
        assert_eq!(
            RuleId::NestedPayloadExpansion.family(),
            RuleFamily::SemanticExpansion
        );
        assert_eq!(
            RuleId::NonMonotonicSequence.family(),
            RuleFamily::SessionIntegrity
        );
        assert_eq!(
            RuleId::CatastrophicFileSystemDelete.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::CatastrophicShellProcessExplosion.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::CatastrophicPathMetadataMutation.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::CatastrophicPathRelocation.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::CatastrophicPartitionLayoutMutation.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::CatastrophicPartitionTableSession.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::CatastrophicPartitionTableStateMutation.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::CatastrophicPartitionTableMutation.family(),
            RuleFamily::HostSafety
        );
        assert_eq!(
            RuleId::GitTrackedWorktreeDiscard.family(),
            RuleFamily::RepositorySafety
        );
        assert_eq!(
            RuleId::GitUntrackedWorktreeDelete.family(),
            RuleFamily::RepositorySafety
        );
        assert_eq!(
            RuleId::GitForcedWorktreeSwitch.family(),
            RuleFamily::RepositorySafety
        );
        assert_eq!(
            RuleId::GitTrackedPathDelete.family(),
            RuleFamily::RepositorySafety
        );
        assert_eq!(
            RuleId::GitSavedStateDestroy.family(),
            RuleFamily::RepositorySafety
        );
        assert_eq!(
            RuleId::GitLocalRefDestroy.family(),
            RuleFamily::RepositorySafety
        );
        assert_eq!(RuleId::TaintedExecution.family(), RuleFamily::Taint);
        assert_eq!(RuleId::ImportedPackageExecution.family(), RuleFamily::Taint);
    }

    #[test]
    fn rule_family_uses_snake_case_wire_format() {
        let value = serde_json::to_value(RuleFamily::InteractiveControl)
            .expect("expected rule family to serialize");

        assert_eq!(value, json!("interactive_control"));

        let roundtrip: RuleFamily =
            serde_json::from_value(value).expect("expected rule family to deserialize");

        assert_eq!(roundtrip, RuleFamily::InteractiveControl);
    }

    #[test]
    fn rule_id_uses_snake_case_wire_format() {
        let value = serde_json::to_value(RuleId::InteractiveEscapeSurface)
            .expect("expected rule id to serialize");

        assert_eq!(value, json!("interactive_escape_surface"));

        let roundtrip: RuleId =
            serde_json::from_value(value).expect("expected rule id to deserialize");

        assert_eq!(roundtrip, RuleId::InteractiveEscapeSurface);
    }
}

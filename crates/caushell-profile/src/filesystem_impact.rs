//! Local filesystem namespace impact of an effect contract, not an authorization.
use crate::{Effect, EffectKind};

/// Mutation target extraction and native snapshot consumers use one kind
/// classification. Neutral says nothing about read contents, output shape,
/// grants, or whether an invocation's argv and other effects are complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemNamespaceImpact {
    Neutral,
    PathMutation,
    Delegated,
    Opaque,
}

impl EffectKind {
    pub fn filesystem_namespace_impact(self) -> FilesystemNamespaceImpact {
        use EffectKind::*;
        match self {
            ReadPath
            | TargetPath
            | SetCurrentWorkingDirectory
            | SetExecutionWorkingDirectory
            | ConsumeStdin
            | ConsumeAuxiliaryValue
            | ConsumeAuxiliaryEnvironment
            | NetworkEndpoint
            | TransformData => FilesystemNamespaceImpact::Neutral,
            WritePath | DeletePath | MovePath | ChangeMode | ChangeOwner | ChangeGroup
            | MetadataMutation => FilesystemNamespaceImpact::PathMutation,
            DispatchCommand => FilesystemNamespaceImpact::Delegated,
            LoadConfig
            | ExecutePayload
            | SourceScriptIntoCurrentShell
            | ExecuteRemoteCommand
            | ExecuteHook
            | ExecuteConfigDefinedTask
            | BindVariableFromRuntimeInput
            | TerminateCurrentShell
            | ReturnFromShellScope
            | ShellJobOperation
            | PrivilegeModifier
            | ListenNetwork
            | ImportPackage
            | ExecuteImportedPackageLogic
            | LoadInProcessCode
            | OpenInteractiveEscapeSurface
            | ControlProcess
            | RepositoryOperation
            | DatabaseOperation
            | StateOperation
            | TerminalSessionOperation => FilesystemNamespaceImpact::Opaque,
        }
    }
}

impl Effect {
    /// A neutral kind cannot erase attached state/execution/namespace facts.
    /// Explicit path mutations still require their complete target and alias
    /// proofs; delegated execution requires a separate closed child proof.
    pub fn filesystem_namespace_impact(&self) -> FilesystemNamespaceImpact {
        let impact = self.kind.filesystem_namespace_impact();
        if self.state_operation.is_some()
            || self.repository_operation.is_some()
            || self.database_operation.is_some()
            || self.terminal_session_operation.is_some()
            || self.shell_job_operation.is_some()
            || self.interactive_escape_surface.is_some()
        {
            return FilesystemNamespaceImpact::Opaque;
        }
        // A same-executor transfer belongs to the delegated child's existing
        // closure proof; it is not a standalone filesystem mutation. Other
        // effects cannot borrow that transfer as a neutrality certificate.
        match self.resource_namespace {
            None => {}
            Some(crate::ResourceNamespaceTransfer::SameExecutor)
                if impact == FilesystemNamespaceImpact::Delegated => {}
            Some(crate::ResourceNamespaceTransfer::SameExecutor) => {
                return FilesystemNamespaceImpact::Opaque;
            }
        }
        if impact == FilesystemNamespaceImpact::Neutral
            && (self.namespace_effect.is_some()
                || self.catastrophic.semantic_class.is_some()
                || self.host_risk.semantic_class.is_some()
                || !self.extensions_are_descriptive())
        {
            return FilesystemNamespaceImpact::Opaque;
        }
        impact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_types::{
        PathNamespaceEffect, StateOperation, StateOperationDomain, StateOperationKind,
    };

    #[test]
    fn a_path_reference_is_not_a_filesystem_mutation_or_a_content_read_grant() {
        let target = Effect::new(EffectKind::TargetPath).for_slot("names");
        assert_eq!(
            target.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Neutral
        );
        assert_eq!(target.kind, EffectKind::TargetPath);
        assert_ne!(target.kind, EffectKind::ReadPath);
        assert_eq!(
            Effect::new(EffectKind::WritePath)
                .for_slot("names")
                .filesystem_namespace_impact(),
            FilesystemNamespaceImpact::PathMutation
        );
        assert_eq!(
            Effect::new(EffectKind::ExecutePayload).filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Opaque
        );
        assert_eq!(
            Effect::new(EffectKind::DispatchCommand).filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Delegated
        );
    }

    #[test]
    fn a_neutral_kind_does_not_hide_namespace_or_state_annotations() {
        let mut effect = Effect::new(EffectKind::TargetPath).for_slot("names");
        effect.namespace_effect = Some(PathNamespaceEffect::DirectoryCreate);
        assert_eq!(
            effect.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Opaque
        );
        effect.namespace_effect = None;
        effect.state_operation = Some(StateOperation {
            domain: StateOperationDomain::FilesystemMount,
            operation: StateOperationKind::Mutate,
            resource: None,
        });
        assert_eq!(
            effect.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Opaque
        );
        effect.state_operation = None;
        effect
            .extensions
            .insert("unreviewed_effect".into(), serde_json::json!(true));
        assert_eq!(
            effect.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Opaque
        );
    }

    #[test]
    fn a_same_executor_transfer_still_requires_delegated_child_closure() {
        let mut effect = Effect::new(EffectKind::DispatchCommand);
        effect.resource_namespace = Some(crate::ResourceNamespaceTransfer::SameExecutor);
        assert_eq!(
            effect.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Delegated
        );
        effect.kind = EffectKind::TargetPath;
        assert_eq!(
            effect.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Opaque
        );
    }

    #[test]
    fn declared_namespace_mutations_keep_their_target_requirement() {
        let mut effect = Effect::new(EffectKind::WritePath).for_slot("output");
        effect.namespace_effect = Some(PathNamespaceEffect::DirectoryCreate);
        assert_eq!(
            effect.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::PathMutation
        );
        effect.state_operation = Some(StateOperation {
            domain: StateOperationDomain::ContainerRuntime,
            operation: StateOperationKind::Opaque,
            resource: None,
        });
        assert_eq!(
            effect.filesystem_namespace_impact(),
            FilesystemNamespaceImpact::Opaque
        );
    }
}

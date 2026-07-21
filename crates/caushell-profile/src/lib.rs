mod bind;
mod builtin;
mod dispatch;
mod loader;
mod lookup;
mod materialize;
mod normalize;
mod projection;
mod raw;
mod recursive;
mod registry;
mod resolve;
mod types;
mod value_shape;

pub use bind::{
    ArgumentScope, BindError, InvocationSelection, InvocationShape, SelectedModifier,
    bind_invocation, match_modifiers, select_form, select_invocation,
};
pub use builtin::BuiltInRegistryError;
pub use caushell_types::ResolveGapKind;
pub use dispatch::{
    DispatchArgument, DispatchCommandCandidate, DispatchCommandProjection,
    UnresolvedDispatchCommand, collect_dispatch_command_candidates,
    collect_dispatch_command_projection,
};
pub use loader::{
    LoadProfileError, load_command_profile_from_path, load_command_profile_from_str,
    load_raw_command_profile_from_path, load_raw_command_profile_from_str,
};
pub use lookup::{ProfileLookupResult, lookup_command_profile, normalize_command_name};
pub use materialize::{
    BindingOrigin, BindingValueRef, MaterializedProjectedInvocation,
    MaterializedRecursivePayloadCandidate, MaterializedShellField, SessionBindings, SessionValue,
    ShellAllPositionalsKind, ShellParameterExpansionOperator, ShellParameterName,
    ShellParameterReference, ValueMaterialization, exact_scalar_shell_parameter_reference_value,
    exact_scalar_shell_parameter_value, exact_shell_parameter_reference,
    materialize_exact_shell_parameter_reference_fields, materialize_projected_invocation,
    materialize_recursive_payload_candidate, parse_shell_parameter_reference_after_dollar,
};
pub use normalize::{NormalizeError, normalize_command_profile};
pub use projection::{
    InvocationRuntimeContext, ProjectedArg, ProjectedArgKind, ProjectedInvocation,
    project_invocation,
};
pub use raw::{
    RawBindingSpec, RawCardinality, RawCatastrophicEffectMetadata, RawCatastrophicSemanticClass,
    RawCommandIdentity, RawCommandProfile, RawDefaultSubcommandBehavior, RawDerivedPathRule,
    RawDerivedPathSource, RawDispatchKind, RawEffect, RawEffectKind, RawEffectTarget,
    RawEndpointKind, RawEndpointUsage, RawFlagOperandMode, RawForm, RawHostRiskEffectMetadata,
    RawHostRiskSemanticClass, RawImplicitInput, RawImplicitInputSource, RawInProcessCodeLoadKind,
    RawInteractiveEscapeCapability, RawInteractiveEscapeSurface, RawInteractiveEscapeSurfaceKind,
    RawModifier, RawModifierConstraint, RawModifierMatcher, RawMutationScopeKind, RawOsFamily,
    RawPackageLocatorKind, RawPackageManagerKind, RawParameter, RawPathPurpose, RawPathRole,
    RawPayloadLanguage, RawPayloadSource, RawPlatformConstraints, RawProcessTargetKind,
    RawProfileSourceKind, RawProfileTrustMetadata, RawProfileTrustTier, RawRepositoryOperationKind,
    RawRepositoryWorktreePathSet, RawRuntimeFeature, RawSelectorExpr, RawSemanticType,
    RawShellFamily, RawStreamContract, RawStreamInputMode, RawStreamOutputMode,
    RawStructuredValueContext, RawSubcommandNode, RawSubcommandTree, RawValueConstraint,
    RawValueMatcher,
};
pub use recursive::{
    ParsedRecursivePayload, RecursivePayloadArgumentFragment, RecursivePayloadCandidate,
    RecursivePayloadFragmentMaterialization, RecursivePayloadInput, RecursivePayloadOrigin,
    RecursivePayloadParseResult, collect_recursive_payload_candidates,
    joined_recursive_payload_text, parse_recursive_payload_candidate,
    parse_recursive_payload_candidates,
};
pub use registry::{ProfileRegistry, RegistryError, RegistryLookupResult};
pub use resolve::{
    ResolveInvocationArtifactResult, ResolveInvocationResult, ResolvedInvocation,
    ResolvedInvocationArtifact, resolve_invocation, resolve_invocation_artifact,
    resolve_invocation_artifact_with_bindings, resolve_invocation_artifact_with_summary,
    resolve_invocation_with_bindings, resolve_invocation_with_summary,
};
pub use types::{
    ArgumentBindingSource, BindingSpec, BoundArgumentMaterialization, BoundImplicitInput,
    BoundInvocation, BoundParameter, BoundValue, Cardinality, CatastrophicEffectMetadata,
    CatastrophicSemanticClass, CommandIdentity, CommandName, CommandProfile, CommandRefSemantic,
    DefaultSubcommandBehavior, DerivedPathSource, DerivedPathTarget, DispatchKind, DispatchTarget,
    Effect, EffectKind, EffectTarget, EndpointKind, EndpointSemantic, EndpointUsage, ExtensionMap,
    FlagName, FlagOperandMode, Form, FormId, HostRiskEffectMetadata, HostRiskSemanticClass,
    ImplicitInput, ImplicitInputSource, InProcessCodeLoadSemantic, InteractiveEscapeSurface,
    Modifier, ModifierConstraint, ModifierId, ModifierMatcher, MutationScopeTarget, OsFamily,
    PackageLocatorKind, PackageLocatorSemantic, PackageManagerKind, Parameter, PathPurpose,
    PathRole, PathSemantic, PayloadLanguage, PayloadSemantic, PayloadSource, PlatformConstraints,
    PositionalBindingSource, ProcessTargetKind, ProcessTargetSemantic, ProfileSourceKind,
    ProfileTrustMetadata, ProfileTrustTier, Residual, ResidualKind, ResidualSurface,
    RuntimeFeature, SelectorExpr, SelectorPredicate, SemanticType, ShellFamily, SlotName,
    StreamContract, StreamInputMode, StreamOutputMode, StructuredValueContext,
    StructuredValueSemantic, SubcommandNode, SubcommandTree, ToolConventionPathTarget,
    ValueConstraint, ValueMatcher,
};
pub use value_shape::parse_owner_group_spec;

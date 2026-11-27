mod apt_configuration;
mod archive;
mod av_filtergraph;
pub use apt_configuration::{AptConfiguration, parse_apt_configuration};
mod argument_ownership;
mod argument_regions;
mod argument_structure;
mod awk_payload;
mod bind;
mod binding_map;
mod brace_expansion;
mod builtin;
mod configuration;
mod pip_configuration;
pub use pip_configuration::{PIP_CONFIGURATION_ENVIRONMENT, PipConfiguration, pip_boolean};
mod dispatch;
mod dispatch_string;
mod environment_inputs;
mod environment_snapshot;
mod effect_annotations;
mod filesystem_impact;
pub use filesystem_impact::FilesystemNamespaceImpact;
pub use environment_snapshot::environment_observations;
mod option_environment;
pub use archive::{ArchiveInvocation, gnu_tar_extraction};
pub use configuration::{
    ConfigurationOption, ConfigurationParse, ConfigurationParseError, mark_configuration_pending,
    parse_configuration,
};
pub use option_environment::{option_environment_observation, option_environment_observations};
pub use types::{ConfigurationFileContract, ConfigurationSyntax, NativeConfigurationSyntax};
mod loader;
mod lookup;
mod materialize;
mod observation_requirements;
mod pathname;
pub use observation_requirements::execution_frame_requirements;
pub use pathname::{PathnameComponent, PathnamePattern, StaticBashPathnameDefaults};
mod diff_pagination;
mod native_effect_envelope;
pub use native_effect_envelope::{
    native_effect_contract_allows_effect, native_effect_contract_allows_parameter,
    native_effect_contract_is_closed, native_effect_contract_is_closed_in_domain,
    retain_symbolic_argv_stream_contract,
};
pub use caushell_types::NativeArgvEffectEnvelope;
mod native_operand;
mod normalize;
mod option_scope;
mod parameter_pattern;
mod patch_payload;
mod payload_projection;
mod projection;
mod raw;
mod recursive;
mod registry;
mod rename_payload;
mod resolve;
mod runtime_matcher;
mod runtime_variables;
mod native_variable_writes;
mod native_stdout;
pub use native_stdout::{NativeOutputOrigin, NativePathStdout, NativeStdoutSource, decode_native_stdout};
pub use types::NativeVariableWrites;
mod shell_read;
mod field_splitting;
pub use field_splitting::{
    OptionalBashField, ShellFieldFragment, materialize_bash_field_fragments,
    materialize_shell_field_fragments, observed_ifs_value,
};
pub use shell_read::{ShellReadResult, decode_shell_read};
pub use types::ResourceNamespaceTransfer;
pub use types::RuntimeInputBinding;
mod native_find_expression;
pub use native_find_expression::NativeFindEvaluation;
mod native_records;
mod sed_payload;
mod stdout_records;
pub use native_records::{
    NativeFormatPart, NativePathOutputPlan, NativePathPredicate, NativeRecordFormat,
};
pub use types::StdoutRecordSyntax;
mod stream_growth;
mod text_records;
pub use text_records::{TextRecordFields, TextRecordStream};
mod structured_parameters;
mod structured_projection;
pub use structured_parameters::{
    ResolvedShellValue, reference_name, resolve_shell_container, resolve_shell_reference,
    shell_array_index, shell_array_key, shell_identifier, shell_nameref_target,
    shell_reference_target, shell_write_target,
};
mod types;
pub use raw::RawDispatchOverride;
pub use types::DispatchOverride;
pub use types::{
    FirstArgumentDisable, ImplicitConfigFile, ImplicitConfigSource, ProtectedAccountDefaults,
};
pub use types::StaticOptionEnvironmentDefault;
pub use types::{GeneratedEnvironment, GeneratedEnvironmentValue};
mod value_projection;
mod value_shape;

pub use argument_regions::BoundArgumentRegion;
pub use argument_structure::{
    ArgumentFieldCount, ArgumentStructure, argument_structure, bash_pid_redirection_path_domain,
    shell_word_structure,
};
pub use bind::root_option_ownership;
pub use bind::{
    ArgumentScope, BindError, InvocationSelection, InvocationShape, SelectedModifier,
    bind_invocation, match_modifiers, select_form, select_invocation,
};
pub use builtin::BuiltInRegistryError;
pub use caushell_types::ResolveGapKind;
pub use dispatch::{
    DispatchArgument, DispatchCommandCandidate, DispatchCommandProjection,
    DispatchWorkingDirectory, UnresolvedDispatchCommand, collect_dispatch_command_candidates,
    collect_dispatch_command_projection,
};
pub use loader::{
    LoadProfileError, load_command_profile_from_path, load_command_profile_from_str,
    load_raw_command_profile_from_path, load_raw_command_profile_from_str,
};
pub use lookup::{ProfileLookupResult, lookup_command_profile, normalize_command_name};
pub use materialize::{
    ArgumentFieldLayout, ArgumentFieldsProof, BindingOrigin, BindingValueRef, EnvironmentValueRef, MaterializedProjectedInvocation,
    MaterializedRecursivePayloadCandidate, MaterializedShellField, SessionBindings, SessionValue,
    ShellAllPositionalsKind, ShellArrayKind, ShellParameterExpansionOperator, ShellParameterName,
    ShellParameterReference, ShellVariableFacts, ValueMaterialization, VariablePresence,
    ShellExpansionGap, ShellExpansionGapKind,
    exact_scalar_shell_parameter_reference_value, exact_scalar_shell_parameter_value,
    dot_relative_parent_assignment, exact_shell_parameter_reference, materialize_argument_domain, materialize_command_name,
    materialize_exact_shell_parameter_reference_fields, materialize_prefix_environment,
    materialize_projected_invocation, materialize_recursive_payload_candidate,
    materialize_shell_array_element, materialize_shell_assignment_value,
    parse_shell_parameter_reference_after_dollar, shell_parameter_dependencies,
};
pub use normalize::{NormalizeError, normalize_command_profile};
pub use option_scope::ScopedOptions;
pub use option_scope::{declared_options, native_diff_anchor};
pub use parameter_pattern::ShellPatternRemovalKind;
pub use payload_projection::refresh_payload_projections;
pub use projection::{
    InvocationRuntimeContext, ProjectedArg, ProjectedArgKind, ProjectedInvocation,
    SubstitutionOutputProof,
    project_invocation,
};
pub use raw::RawArgumentControlVocabulary;
pub use raw::RawEnvironmentInput;
pub use raw::RawModifierEffectCondition;
pub use raw::RawModifierParameterCondition;
pub use raw::RawPathScope;
pub use raw::{
    RawArgumentFileRule, RawBindingSpec, RawCardinality, RawCatastrophicEffectMetadata,
    RawCatastrophicSemanticClass, RawCommandIdentity, RawCommandProfile,
    RawConditionalEnvironmentUnset, RawConfiguredPathAnchor, RawConfiguredPathMissing,
    RawConfiguredPathSource, RawConfiguredScalar, RawDefaultSubcommandBehavior, RawDerivedPathRule,
    RawDerivedPathSource, RawDispatchCommandString, RawDispatchKind, RawDispatchStringSyntax,
    RawEffect, RawEffectKind, RawEffectTarget, RawEndpointKind, RawEndpointUsage,
    RawEnvironmentValueSource, RawFlagOperandMode, RawForm, RawHostRiskEffectMetadata,
    RawHostRiskSemanticClass, RawImplicitInput, RawImplicitInputSource, RawInProcessCodeLoadKind,
    RawInteractiveEscapeCapability, RawInteractiveEscapeSurface, RawInteractiveEscapeSurfaceKind,
    RawModifier, RawModifierConstraint, RawModifierMatcher, RawMutationScopeKind,
    RawOptionMatchingPolicy, RawOptionPrefixPolicy, RawOptionScopePolicy, RawOsFamily,
    RawPackageLocatorKind, RawPackageManagerKind, RawParameter, RawPathPurpose, RawPathRole,
    RawPayloadLanguage, RawPayloadSource, RawPlatformConstraints, RawProcessTargetKind,
    RawProfileSourceKind, RawProfileTrustMetadata, RawProfileTrustTier, RawProjectionAbsentPolicy,
    RawRepositoryOperationKind, RawRepositoryWorktreePathSet, RawRuntimeFeature, RawSelectorExpr,
    RawSemanticType, RawShellFamily, RawShellVariableValueSource, RawStreamContract,
    RawStreamInputMode, RawStreamOutputMode, RawStructuredValueContext, RawSubcommandNode,
    RawSubcommandTree, RawValueConstraint, RawValueMatcher, RawValueProjection,
};
pub use raw::{RawArgumentRegion, RawArgumentRegionTerminator};
pub use raw::{
    RawNativeOperandSyntax, RawStructuredProjection, RawStructuredProjectionBranch,
    RawStructuredProjectionMatcher, RawStructuredProjectionTarget,
};
pub use raw::{RawPayloadFormat, RawPayloadInputSource, RawPayloadProjection};
pub use raw::{RawStdoutRecordContract, RawStdoutRecordProjection, RawStreamRecordSeparator};
pub use recursive::{
    ParsedRecursivePayload, RecursivePayloadArgumentFragment, RecursivePayloadCandidate,
    RecursivePayloadFragmentMaterialization, RecursivePayloadInput, RecursivePayloadOrigin,
    RecursivePayloadParseResult, collect_recursive_payload_candidates,
    joined_recursive_payload_text, parse_recursive_payload_candidate,
    parse_recursive_payload_candidates,
};
pub use registry::{ProfileRegistry, RegistryError, RegistryLookupResult};
pub use resolve::{
    ExecutableWord, ResolveInvocationArtifactResult, ResolveInvocationResult, ResolvedInvocation,
    ResolvedInvocationArtifact, materialize_structured_command, resolve_invocation,
    resolve_invocation_artifact, resolve_invocation_artifact_with_bindings,
    resolve_invocation_artifact_with_argument_proofs, resolve_invocation_artifact_with_stdout_proofs, resolve_invocation_artifact_with_summary,
    resolve_invocation_in_lookup_domain_with_stdout_proofs, resolve_invocation_in_namespace,
    resolve_source_let_artifact,
    resolve_invocation_in_namespace_with_stdout_proofs, resolve_invocation_with_bindings,
    resolve_invocation_with_summary,
};
pub use runtime_variables::{RuntimeVariableWrites, runtime_variable_writes};
pub use types::ArgumentControlVocabulary;
pub use types::ArgumentOwnership;
pub use types::CompiledOperandRegex;
pub use types::EndpointInputScope;
pub use types::EnvironmentInput;
pub use types::ModifierEffectCondition;
pub use types::OptionOperandMatcher;
pub use types::PathAccessKind;
pub use types::PathScope;
pub use types::StdoutPathFormatSyntax;
pub use types::{StdoutScalarArgvGrammar, StdoutScalarShape};
pub use types::WordContext;
pub use types::{ArchiveExtraction, OptionEnvironment, OptionEnvironmentSyntax};
pub use types::{
    ArgumentBindingSource, ArgumentFileRule, ArgumentRegion, ArgumentRegionTerminator, BindingSpec,
    BoundArgumentMaterialization, BoundImplicitArgumentOrigin, BoundImplicitInput, BoundInvocation,
    BoundParameter, BoundValue, Cardinality, CatastrophicEffectMetadata, CatastrophicSemanticClass,
    CommandIdentity, CommandName, CommandProfile, CommandRefSemantic, ConditionalEnvironmentUnset,
    ConfiguredPathAnchor, ConfiguredPathMissing, ConfiguredPathSource, ConfiguredPathTarget,
    ConfiguredScalar, DefaultSubcommandBehavior, DerivedPathSource, DerivedPathTarget,
    DispatchCommandSource, DispatchKind, DispatchStringSyntax, DispatchTarget, Effect, EffectKind,
    EffectTarget, EndpointKind, EndpointSemantic, EndpointUsage, EnvironmentValueSource,
    ExtensionMap, FlagName, FlagOperandMode, Form, FormId, HostRiskEffectMetadata,
    HostRiskSemanticClass, ImplicitInput, ImplicitInputSource, InProcessCodeLoadSemantic,
    InteractiveEscapeSurface, Modifier, ModifierConstraint, ModifierId, ModifierMatcher,
    MutationScopeTarget, NetworkListenerTarget, OptionMatchingPolicy, OptionPrefixPolicy,
    OptionScopePolicy, OsFamily, PackageLocatorKind, PackageLocatorSemantic, PackageManagerKind,
    Parameter, PathPurpose, PathRole, PathSemantic, PayloadLanguage, PayloadSemantic,
    PayloadSource, PlatformConstraints, PositionalBindingSource, ProcessTargetKind,
    ProcessTargetSemantic, ProfileSourceKind, ProfileTrustMetadata, ProfileTrustTier,
    ProjectedSemanticValue, ProjectionAbsentPolicy, ProjectionUnknownReason, Residual,
    ResidualKind, ResidualSurface, RuntimeFeature, SelectorExpr, SelectorPredicate, SemanticType,
    SemanticValueRef, SemanticValueResolution, ShellFamily, ShellVariableValueSource, SlotName,
    StreamContract, StreamCountSlot, StreamCountUnit, StreamGrowthContract, StreamInputMode,
    StreamOutputMode, StructuredValueContext, StructuredValueSemantic, SubcommandNode,
    SubcommandTree, ToolConventionPathTarget, ValueConstraint, ValueMatcher, ValueProjection,
};
pub use types::{
    BoundPathList, PathListContract, PathListSeparator, StdoutRecordContract,
    StdoutRecordProjection, StreamRecordSeparator,
};
pub use types::{ModuleEntrypoint, PayloadFormat, PayloadInputSource, PayloadProjection};
pub use types::{
    NativeOperandSyntax, StructuredProjection, StructuredProjectionBranch,
    StructuredProjectionMatcher, StructuredProjectionTarget,
};
pub use value_projection::{
    project_semantic_value, project_value, refresh_parameter_semantic_values,
};
pub use value_shape::parse_owner_group_spec;

// Execution-object lookup is independent of shell syntax.
pub use types::{CommandLookupDomain, DispatchLookupDomain, ProfileExecutionDomain};

mod git_configuration;
pub use git_configuration::GIT_CONFIGURATION_ENVIRONMENT;
pub use git_configuration::{
    GitConfigEvent, GitConfigValue, GitConfiguration, git_boolean, parse_git_config_parameters,
    parse_git_configuration,
};

pub use types::{ConfiguredExecutionSource, ConfiguredExecutionValue, ConfiguredInputSource};

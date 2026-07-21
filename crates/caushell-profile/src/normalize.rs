use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value as JsonValue;

use crate::raw::{
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
use crate::{
    BindingSpec, Cardinality, CatastrophicEffectMetadata, CatastrophicSemanticClass,
    CommandIdentity, CommandName, CommandProfile, CommandRefSemantic, DefaultSubcommandBehavior,
    DerivedPathSource, DerivedPathTarget, DispatchKind, DispatchTarget, Effect, EffectKind,
    EffectTarget, EndpointKind, EndpointSemantic, EndpointUsage, ExtensionMap, FlagName,
    FlagOperandMode, Form, FormId, HostRiskEffectMetadata, HostRiskSemanticClass, ImplicitInput,
    ImplicitInputSource, InProcessCodeLoadSemantic, Modifier, ModifierConstraint, ModifierId,
    ModifierMatcher, MutationScopeTarget, OsFamily, PackageLocatorKind, PackageLocatorSemantic,
    PackageManagerKind, Parameter, PathPurpose, PathRole, PathSemantic, PayloadLanguage,
    PayloadSemantic, PayloadSource, PlatformConstraints, ProcessTargetKind, ProcessTargetSemantic,
    ProfileSourceKind, ProfileTrustMetadata, ProfileTrustTier, RuntimeFeature, SelectorExpr,
    SelectorPredicate, SemanticType, ShellFamily, SlotName, StreamContract, StreamInputMode,
    StreamOutputMode, StructuredValueContext, StructuredValueSemantic, SubcommandNode,
    SubcommandTree, ToolConventionPathTarget, ValueConstraint, ValueMatcher,
};
use caushell_types::{
    InteractiveEscapeCapability, InteractiveEscapeSurfaceKind, RepositoryWorktreePathSet,
};

const PROFILE_DSL_VERSION: &str = "caushell.profile/v1alpha1";
const PROFILE_KIND: &str = "command_profile";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    EmptyIdentifier { field: &'static str },
    InvalidDslVersion(String),
    InvalidProfileKind(String),
    InvalidRegexPattern(String),
    DuplicateAlias(String),
    DuplicateFormId(String),
    DuplicateModifierId(String),
    DuplicateParameterName(String),
    DuplicateSubcommandNameOrAlias(String),
    MissingInteractiveEscapeSurface,
    UnexpectedInteractiveEscapeSurface,
    MissingRepositoryOperation,
    UnexpectedRepositoryOperation,
    InvalidExtensionKey(String),
}

pub fn normalize_command_profile(raw: RawCommandProfile) -> Result<CommandProfile, NormalizeError> {
    if raw.dsl_version != PROFILE_DSL_VERSION {
        return Err(NormalizeError::InvalidDslVersion(raw.dsl_version));
    }

    if raw.kind != PROFILE_KIND {
        return Err(NormalizeError::InvalidProfileKind(raw.kind));
    }

    let identity = normalize_identity(raw.identity)?;
    let forms = normalize_forms(raw.forms)?;
    let modifiers = normalize_modifiers(raw.modifiers)?;
    let subcommands = raw.subcommands.map(normalize_subcommand_tree).transpose()?;

    Ok(CommandProfile {
        identity,
        trust: normalize_trust(raw.trust),
        platform: normalize_platform(raw.platform),
        forms,
        modifiers,
        subcommands,
        extensions: normalize_extensions(raw.extensions)?,
    })
}

fn normalize_identity(raw: RawCommandIdentity) -> Result<CommandIdentity, NormalizeError> {
    ensure_non_empty(&raw.canonical_name, "identity.canonical_name")?;

    let mut seen = BTreeSet::new();
    seen.insert(raw.canonical_name.clone());

    let mut aliases = Vec::with_capacity(raw.aliases.len());
    for alias in raw.aliases {
        ensure_non_empty(&alias, "identity.aliases")?;
        if !seen.insert(alias.clone()) {
            return Err(NormalizeError::DuplicateAlias(alias));
        }
        aliases.push(CommandName::new(alias));
    }

    Ok(CommandIdentity {
        canonical_name: CommandName::new(raw.canonical_name),
        aliases,
    })
}

fn normalize_trust(raw: RawProfileTrustMetadata) -> ProfileTrustMetadata {
    ProfileTrustMetadata {
        tier: match raw.tier {
            RawProfileTrustTier::TierA => ProfileTrustTier::TierA,
            RawProfileTrustTier::TierB => ProfileTrustTier::TierB,
            RawProfileTrustTier::TierC => ProfileTrustTier::TierC,
        },
        source: match raw.source {
            RawProfileSourceKind::BuiltIn => ProfileSourceKind::BuiltIn,
            RawProfileSourceKind::User => ProfileSourceKind::User,
            RawProfileSourceKind::ImportedLegacy => ProfileSourceKind::ImportedLegacy,
            RawProfileSourceKind::Generated => ProfileSourceKind::Generated,
        },
        reviewed_by: raw.reviewed_by,
        review_notes: raw.review_notes,
    }
}

fn normalize_platform(raw: RawPlatformConstraints) -> PlatformConstraints {
    PlatformConstraints {
        os_families: raw
            .os_families
            .into_iter()
            .map(|value| match value {
                RawOsFamily::Posix => OsFamily::Posix,
                RawOsFamily::Linux => OsFamily::Linux,
                RawOsFamily::Macos => OsFamily::MacOs,
                RawOsFamily::Windows => OsFamily::Windows,
            })
            .collect(),
        shell_families: raw
            .shell_families
            .into_iter()
            .map(|value| match value {
                RawShellFamily::Bourne => ShellFamily::Bourne,
                RawShellFamily::Bash => ShellFamily::Bash,
                RawShellFamily::Sh => ShellFamily::Sh,
                RawShellFamily::Dash => ShellFamily::Dash,
                RawShellFamily::Powershell => ShellFamily::PowerShell,
                RawShellFamily::Cmd => ShellFamily::Cmd,
            })
            .collect(),
        requires_features: raw
            .requires_features
            .into_iter()
            .map(|value| match value {
                RawRuntimeFeature::InteractiveSession => RuntimeFeature::InteractiveSession,
                RawRuntimeFeature::StdinPayloadAvailable => RuntimeFeature::StdinPayloadAvailable,
                RawRuntimeFeature::PipelineInputAvailable => RuntimeFeature::PipelineInputAvailable,
            })
            .collect(),
    }
}

fn normalize_forms(raw_forms: Vec<RawForm>) -> Result<Vec<Form>, NormalizeError> {
    ensure_unique_form_ids(&raw_forms)?;
    raw_forms.into_iter().map(normalize_form).collect()
}

fn normalize_form(raw: RawForm) -> Result<Form, NormalizeError> {
    ensure_non_empty(&raw.id, "forms.id")?;
    ensure_unique_parameter_names(&raw.parameters)?;

    Ok(Form {
        id: FormId::new(raw.id),
        selector: normalize_selector_expr(raw.selector)?,
        remaining_selector: normalize_selector_expr(raw.remaining_selector)?,
        parameters: raw
            .parameters
            .into_iter()
            .map(normalize_parameter)
            .collect::<Result<Vec<_>, _>>()?,
        implicit_inputs: raw
            .implicit_inputs
            .into_iter()
            .map(normalize_implicit_input)
            .collect::<Result<Vec<_>, _>>()?,
        effects: raw
            .effects
            .into_iter()
            .map(normalize_effect)
            .collect::<Result<Vec<_>, _>>()?,
        stream_contract: raw.stream_contract.map(normalize_stream_contract),
        extensions: normalize_extensions(raw.extensions)?,
    })
}

fn normalize_selector_expr(raw: RawSelectorExpr) -> Result<SelectorExpr, NormalizeError> {
    match raw {
        RawSelectorExpr::All { items } => Ok(SelectorExpr::All(
            items
                .into_iter()
                .map(normalize_selector_expr)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        RawSelectorExpr::Any { items } => Ok(SelectorExpr::Any(
            items
                .into_iter()
                .map(normalize_selector_expr)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        RawSelectorExpr::Not { item } => {
            Ok(SelectorExpr::Not(Box::new(normalize_selector_expr(*item)?)))
        }
        RawSelectorExpr::HasFlag { flag } => {
            ensure_non_empty(&flag, "selector.flag")?;
            Ok(SelectorExpr::Predicate(SelectorPredicate::HasFlag(
                FlagName::new(flag),
            )))
        }
        RawSelectorExpr::HasFlagAtLeast { flag, count } => {
            ensure_non_empty(&flag, "selector.flag")?;
            Ok(SelectorExpr::Predicate(SelectorPredicate::HasFlagAtLeast(
                FlagName::new(flag),
                count,
            )))
        }
        RawSelectorExpr::LacksFlag { flag } => {
            ensure_non_empty(&flag, "selector.flag")?;
            Ok(SelectorExpr::Predicate(SelectorPredicate::LacksFlag(
                FlagName::new(flag),
            )))
        }
        RawSelectorExpr::HasModifier { modifier } => {
            ensure_non_empty(&modifier, "selector.modifier")?;
            Ok(SelectorExpr::Predicate(SelectorPredicate::HasModifier(
                ModifierId::new(modifier),
            )))
        }
        RawSelectorExpr::HasModifierParameterMatching {
            modifier,
            parameter,
            matcher,
        } => {
            ensure_non_empty(&modifier, "selector.modifier")?;
            ensure_non_empty(&parameter, "selector.parameter")?;
            Ok(SelectorExpr::Predicate(
                SelectorPredicate::HasModifierParameterMatching(
                    ModifierId::new(modifier),
                    SlotName::new(parameter),
                    normalize_value_matcher(matcher)?,
                ),
            ))
        }
        RawSelectorExpr::HasPositionalAt { index } => Ok(SelectorExpr::Predicate(
            SelectorPredicate::HasPositionalAt(index),
        )),
        RawSelectorExpr::HasPositionalBeforeDashDashAt { index } => Ok(SelectorExpr::Predicate(
            SelectorPredicate::HasPositionalBeforeDashDashAt(index),
        )),
        RawSelectorExpr::HasPositionalAtMatching { index, matcher } => Ok(SelectorExpr::Predicate(
            SelectorPredicate::HasPositionalAtMatching(index, normalize_value_matcher(matcher)?),
        )),
        RawSelectorExpr::HasPositionalAtOrAfterMatching { index, matcher } => Ok(
            SelectorExpr::Predicate(SelectorPredicate::HasPositionalAtOrAfterMatching(
                index,
                normalize_value_matcher(matcher)?,
            )),
        ),
        RawSelectorExpr::HasPositionalAfterLeadingMatcher { matcher } => Ok(
            SelectorExpr::Predicate(SelectorPredicate::HasPositionalAfterLeadingMatcher(
                normalize_value_matcher(matcher)?,
            )),
        ),
        RawSelectorExpr::NoPositionalAfterLeadingMatcher { matcher } => Ok(
            SelectorExpr::Predicate(SelectorPredicate::NoPositionalAfterLeadingMatcher(
                normalize_value_matcher(matcher)?,
            )),
        ),
        RawSelectorExpr::LastPositionalMatches { matcher } => Ok(SelectorExpr::Predicate(
            SelectorPredicate::LastPositionalMatches(normalize_value_matcher(matcher)?),
        )),
        RawSelectorExpr::NoPositionalArgs => {
            Ok(SelectorExpr::Predicate(SelectorPredicate::NoPositionalArgs))
        }
        RawSelectorExpr::HasDashDash => Ok(SelectorExpr::Predicate(SelectorPredicate::HasDashDash)),
        RawSelectorExpr::NoDashDash => Ok(SelectorExpr::Predicate(SelectorPredicate::NoDashDash)),
        RawSelectorExpr::StdinPayloadAvailable => Ok(SelectorExpr::Predicate(
            SelectorPredicate::StdinPayloadAvailable,
        )),
        RawSelectorExpr::InteractiveSession => Ok(SelectorExpr::Predicate(
            SelectorPredicate::InteractiveSession,
        )),
        RawSelectorExpr::HasSubcommandPath { path } => Ok(SelectorExpr::Predicate(
            SelectorPredicate::HasSubcommandPath(path),
        )),
        RawSelectorExpr::HasRuntimeFeature { feature } => Ok(SelectorExpr::Predicate(
            SelectorPredicate::HasRuntimeFeature(normalize_runtime_feature(feature)),
        )),
    }
}

fn normalize_stream_contract(raw: RawStreamContract) -> StreamContract {
    StreamContract {
        stdin_mode: match raw.stdin_mode {
            RawStreamInputMode::Ignored => StreamInputMode::Ignored,
            RawStreamInputMode::DataOptional => StreamInputMode::DataOptional,
            RawStreamInputMode::DataRequired => StreamInputMode::DataRequired,
            RawStreamInputMode::PayloadOptional => StreamInputMode::PayloadOptional,
            RawStreamInputMode::PayloadRequired => StreamInputMode::PayloadRequired,
        },
        stdout_mode: normalize_stream_output_mode(raw.stdout_mode),
        stderr_mode: normalize_stream_output_mode(raw.stderr_mode),
    }
}

fn normalize_stream_output_mode(raw: RawStreamOutputMode) -> StreamOutputMode {
    match raw {
        RawStreamOutputMode::Opaque => StreamOutputMode::Opaque,
        RawStreamOutputMode::Data => StreamOutputMode::Data,
        RawStreamOutputMode::CommandText => StreamOutputMode::CommandText,
        RawStreamOutputMode::PathList => StreamOutputMode::PathList,
    }
}

fn normalize_modifiers(raw_modifiers: Vec<RawModifier>) -> Result<Vec<Modifier>, NormalizeError> {
    ensure_unique_modifier_ids(&raw_modifiers)?;
    raw_modifiers.into_iter().map(normalize_modifier).collect()
}

fn normalize_modifier(raw: RawModifier) -> Result<Modifier, NormalizeError> {
    ensure_non_empty(&raw.id, "modifiers.id")?;
    ensure_unique_parameter_names(&raw.parameters)?;

    Ok(Modifier {
        id: ModifierId::new(raw.id),
        matcher: normalize_modifier_matcher(raw.matcher)?,
        parameters: raw
            .parameters
            .into_iter()
            .map(normalize_parameter)
            .collect::<Result<Vec<_>, _>>()?,
        effects: raw
            .effects
            .into_iter()
            .map(normalize_effect)
            .collect::<Result<Vec<_>, _>>()?,
        constraints: raw
            .constraints
            .into_iter()
            .map(normalize_modifier_constraint)
            .collect::<Result<Vec<_>, _>>()?,
        extensions: normalize_extensions(raw.extensions)?,
    })
}

fn normalize_modifier_matcher(raw: RawModifierMatcher) -> Result<ModifierMatcher, NormalizeError> {
    let normalize_flags = |flags: Vec<String>| -> Result<Vec<FlagName>, NormalizeError> {
        flags
            .into_iter()
            .map(|flag| {
                ensure_non_empty(&flag, "modifiers.matcher.flags")?;
                Ok(FlagName::new(flag))
            })
            .collect()
    };

    match raw {
        RawModifierMatcher::AnyFlag { flags } => {
            Ok(ModifierMatcher::AnyFlag(normalize_flags(flags)?))
        }
        RawModifierMatcher::AllFlags { flags } => {
            Ok(ModifierMatcher::AllFlags(normalize_flags(flags)?))
        }
    }
}

fn normalize_modifier_constraint(
    raw: RawModifierConstraint,
) -> Result<ModifierConstraint, NormalizeError> {
    match raw {
        RawModifierConstraint::MutuallyExclusiveWith { modifier } => {
            ensure_non_empty(&modifier, "modifiers.constraints.modifier")?;
            Ok(ModifierConstraint::MutuallyExclusiveWith(ModifierId::new(
                modifier,
            )))
        }
        RawModifierConstraint::RequiresModifier { modifier } => {
            ensure_non_empty(&modifier, "modifiers.constraints.modifier")?;
            Ok(ModifierConstraint::RequiresModifier(ModifierId::new(
                modifier,
            )))
        }
        RawModifierConstraint::RequiresFlag { flag } => {
            ensure_non_empty(&flag, "modifiers.constraints.flag")?;
            Ok(ModifierConstraint::RequiresFlag(FlagName::new(flag)))
        }
    }
}

fn normalize_parameter(raw: RawParameter) -> Result<Parameter, NormalizeError> {
    ensure_non_empty(&raw.name, "parameters.name")?;

    Ok(Parameter {
        name: SlotName::new(raw.name),
        semantic: normalize_semantic(raw.semantic)?,
        binding: normalize_binding(raw.binding)?,
        cardinality: raw
            .cardinality
            .map(normalize_cardinality)
            .unwrap_or(Cardinality::RequiredOne),
        value_constraints: raw
            .value_constraints
            .into_iter()
            .map(normalize_value_constraint)
            .collect(),
        extensions: normalize_extensions(raw.extensions)?,
    })
}

fn normalize_cardinality(raw: RawCardinality) -> Cardinality {
    match raw {
        RawCardinality::RequiredOne => Cardinality::RequiredOne,
        RawCardinality::OptionalOne => Cardinality::OptionalOne,
        RawCardinality::RequiredMany => Cardinality::RequiredMany,
        RawCardinality::OptionalMany => Cardinality::OptionalMany,
    }
}

fn normalize_binding(raw: RawBindingSpec) -> Result<BindingSpec, NormalizeError> {
    match raw {
        RawBindingSpec::NextPositional => Ok(BindingSpec::NextPositional),
        RawBindingSpec::NextPositionalAfterDashDash => Ok(BindingSpec::NextPositionalAfterDashDash),
        RawBindingSpec::PositionalAt { index } => Ok(BindingSpec::PositionalAt(index)),
        RawBindingSpec::RemainingPositionals => Ok(BindingSpec::RemainingPositionals),
        RawBindingSpec::RemainingPositionalsAfterDashDash => {
            Ok(BindingSpec::RemainingPositionalsAfterDashDash)
        }
        RawBindingSpec::RemainingPositionalsBeforeLast => {
            Ok(BindingSpec::RemainingPositionalsBeforeLast)
        }
        RawBindingSpec::RemainingArgs => Ok(BindingSpec::RemainingArgs),
        RawBindingSpec::ArgsUntilLiteral {
            terminator,
            include_terminator,
        } => {
            ensure_non_empty(&terminator, "parameters.binding.terminator")?;
            Ok(BindingSpec::ArgsUntilLiteral {
                terminator,
                include_terminator,
            })
        }
        RawBindingSpec::LastPositional => Ok(BindingSpec::LastPositional),
        RawBindingSpec::LastPositionalBeforeLast => Ok(BindingSpec::LastPositionalBeforeLast),
        RawBindingSpec::FollowingFlag { flag, operand_mode } => {
            ensure_non_empty(&flag, "parameters.binding.flag")?;
            Ok(BindingSpec::FollowingFlag {
                flag_name: FlagName::new(flag),
                operand_mode: normalize_flag_operand_mode(operand_mode),
            })
        }
        RawBindingSpec::FollowingMatchedFlag { operand_mode } => {
            Ok(BindingSpec::FollowingMatchedFlag {
                operand_mode: normalize_flag_operand_mode(operand_mode),
            })
        }
        RawBindingSpec::ArgsWithPrefix { prefix } => {
            ensure_non_empty(&prefix, "binding.prefix")?;
            Ok(BindingSpec::ArgsWithPrefix(prefix))
        }
        RawBindingSpec::LeadingPositionalsWhile { matcher } => Ok(
            BindingSpec::LeadingPositionalsWhile(normalize_value_matcher(matcher)?),
        ),
    }
}

fn normalize_flag_operand_mode(raw: RawFlagOperandMode) -> FlagOperandMode {
    match raw {
        RawFlagOperandMode::NextPositional => FlagOperandMode::NextPositional,
        RawFlagOperandMode::NextArg => FlagOperandMode::NextArg,
        RawFlagOperandMode::SecondArg => FlagOperandMode::SecondArg,
        RawFlagOperandMode::InlineOnly => FlagOperandMode::InlineOnly,
        RawFlagOperandMode::InlineOrShortAttached => FlagOperandMode::InlineOrShortAttached,
        RawFlagOperandMode::NextPositionalAfterDashDash => {
            FlagOperandMode::NextPositionalAfterDashDash
        }
    }
}

fn normalize_value_matcher(raw: RawValueMatcher) -> Result<ValueMatcher, NormalizeError> {
    match raw {
        RawValueMatcher::StructuredValueContext { context } => Ok(
            ValueMatcher::StructuredValueContext(normalize_structured_value_context(context)),
        ),
        RawValueMatcher::Literal { value } => Ok(ValueMatcher::Literal(value)),
        RawValueMatcher::RegexPattern { pattern } => {
            ensure_non_empty(&pattern, "value_matcher.pattern")?;
            regex::Regex::new(&pattern)
                .map_err(|_| NormalizeError::InvalidRegexPattern(pattern.clone()))?;
            Ok(ValueMatcher::RegexPattern(pattern))
        }
    }
}

fn normalize_value_constraint(raw: RawValueConstraint) -> ValueConstraint {
    match raw {
        RawValueConstraint::ExcludeLiteral { value } => ValueConstraint::ExcludeLiteral(value),
    }
}

fn normalize_implicit_input(raw: RawImplicitInput) -> Result<ImplicitInput, NormalizeError> {
    Ok(ImplicitInput {
        source: normalize_implicit_input_source(raw.source),
        semantic: normalize_semantic(raw.semantic)?,
        extensions: normalize_extensions(raw.extensions)?,
    })
}

fn normalize_implicit_input_source(raw: RawImplicitInputSource) -> ImplicitInputSource {
    match raw {
        RawImplicitInputSource::StdinPayload => ImplicitInputSource::StdinPayload,
        RawImplicitInputSource::StdinData => ImplicitInputSource::StdinData,
        RawImplicitInputSource::InteractiveSession => ImplicitInputSource::InteractiveSession,
        RawImplicitInputSource::InheritedEnvironment => ImplicitInputSource::InheritedEnvironment,
    }
}

fn normalize_semantic(raw: RawSemanticType) -> Result<SemanticType, NormalizeError> {
    match raw {
        RawSemanticType::PlainValue => Ok(SemanticType::PlainValue),
        RawSemanticType::Path { role, purpose } => Ok(SemanticType::Path(PathSemantic {
            role: normalize_path_role(role),
            purpose: purpose.map(normalize_path_purpose),
        })),
        RawSemanticType::Payload {
            language,
            source,
            recursive,
        } => Ok(SemanticType::Payload(PayloadSemantic {
            language: normalize_payload_language(language),
            source: normalize_payload_source(source),
            recursive,
        })),
        RawSemanticType::CommandRef { dispatch } => {
            Ok(SemanticType::CommandRef(CommandRefSemantic {
                dispatch: normalize_dispatch_kind(dispatch),
            }))
        }
        RawSemanticType::StructuredValue { context } => {
            Ok(SemanticType::StructuredValue(StructuredValueSemantic {
                context: normalize_structured_value_context(context),
            }))
        }
        RawSemanticType::Endpoint {
            endpoint_kind,
            usage,
        } => Ok(SemanticType::Endpoint(EndpointSemantic {
            kind: normalize_endpoint_kind(endpoint_kind),
            usage: normalize_endpoint_usage(usage),
        })),
        RawSemanticType::PackageLocator {
            manager,
            locator_kinds,
        } => Ok(SemanticType::PackageLocator(PackageLocatorSemantic {
            manager: normalize_package_manager_kind(manager),
            locator_kinds: locator_kinds
                .into_iter()
                .map(normalize_package_locator_kind)
                .collect(),
        })),
        RawSemanticType::InProcessCodeLoad { load_kind } => {
            Ok(SemanticType::InProcessCodeLoad(InProcessCodeLoadSemantic {
                load_kind: normalize_in_process_code_load_kind(load_kind),
            }))
        }
        RawSemanticType::ProcessTarget {
            target_kind,
            broad_match,
        } => Ok(SemanticType::ProcessTarget(ProcessTargetSemantic {
            kind: normalize_process_target_kind(target_kind),
            broad_match,
        })),
    }
}

fn normalize_path_role(raw: RawPathRole) -> PathRole {
    match raw {
        RawPathRole::Read => PathRole::Read,
        RawPathRole::Write => PathRole::Write,
        RawPathRole::MetadataMutation => PathRole::MetadataMutation,
        RawPathRole::Target => PathRole::Target,
        RawPathRole::Config => PathRole::Config,
        RawPathRole::CwdAnchor => PathRole::CwdAnchor,
    }
}

fn normalize_path_purpose(raw: RawPathPurpose) -> PathPurpose {
    match raw {
        RawPathPurpose::GenericOperand => PathPurpose::GenericOperand,
        RawPathPurpose::ScriptSource => PathPurpose::ScriptSource,
        RawPathPurpose::InProcessCode => PathPurpose::InProcessCode,
        RawPathPurpose::StartupConfig => PathPurpose::StartupConfig,
        RawPathPurpose::ProjectConfig => PathPurpose::ProjectConfig,
        RawPathPurpose::ToolConfig => PathPurpose::ToolConfig,
        RawPathPurpose::TaskConfig => PathPurpose::TaskConfig,
        RawPathPurpose::WorkingDirectory => PathPurpose::WorkingDirectory,
    }
}

fn normalize_payload_language(raw: RawPayloadLanguage) -> PayloadLanguage {
    match raw {
        RawPayloadLanguage::Bash => PayloadLanguage::Bash,
        RawPayloadLanguage::Sh => PayloadLanguage::Sh,
        RawPayloadLanguage::Dash => PayloadLanguage::Dash,
        RawPayloadLanguage::Python => PayloadLanguage::Python,
        RawPayloadLanguage::Perl => PayloadLanguage::Perl,
        RawPayloadLanguage::Javascript => PayloadLanguage::Javascript,
    }
}

fn normalize_payload_source(raw: RawPayloadSource) -> PayloadSource {
    match raw {
        RawPayloadSource::InlineString => PayloadSource::InlineString,
        RawPayloadSource::ScriptFileRef => PayloadSource::ScriptFileRef,
        RawPayloadSource::Stdin => PayloadSource::Stdin,
        RawPayloadSource::Interactive => PayloadSource::Interactive,
        RawPayloadSource::DynamicReference => PayloadSource::DynamicReference,
    }
}

fn normalize_dispatch_kind(raw: RawDispatchKind) -> DispatchKind {
    match raw {
        RawDispatchKind::CommandName => DispatchKind::CommandName,
        RawDispatchKind::WrapperCommand => DispatchKind::WrapperCommand,
        RawDispatchKind::ShellPayload => DispatchKind::ShellPayload,
        RawDispatchKind::InterpreterModule => DispatchKind::InterpreterModule,
    }
}

fn normalize_structured_value_context(raw: RawStructuredValueContext) -> StructuredValueContext {
    match raw {
        RawStructuredValueContext::Regex => StructuredValueContext::Regex,
        RawStructuredValueContext::SedScript => StructuredValueContext::SedScript,
        RawStructuredValueContext::AwkProgram => StructuredValueContext::AwkProgram,
        RawStructuredValueContext::FormatString => StructuredValueContext::FormatString,
        RawStructuredValueContext::DateExpression => StructuredValueContext::DateExpression,
        RawStructuredValueContext::NumericQuantity => StructuredValueContext::NumericQuantity,
        RawStructuredValueContext::PathExpression => StructuredValueContext::PathExpression,
        RawStructuredValueContext::EnvAssignment => StructuredValueContext::EnvAssignment,
        RawStructuredValueContext::RemoteSpec => StructuredValueContext::RemoteSpec,
        RawStructuredValueContext::OwnerGroupSpec => StructuredValueContext::OwnerGroupSpec,
    }
}

fn normalize_endpoint_kind(raw: RawEndpointKind) -> EndpointKind {
    match raw {
        RawEndpointKind::Url => EndpointKind::Url,
        RawEndpointKind::HostPort => EndpointKind::HostPort,
        RawEndpointKind::SocketPath => EndpointKind::SocketPath,
        RawEndpointKind::RemoteSpec => EndpointKind::RemoteSpec,
    }
}

fn normalize_endpoint_usage(raw: RawEndpointUsage) -> EndpointUsage {
    match raw {
        RawEndpointUsage::FetchSource => EndpointUsage::FetchSource,
        RawEndpointUsage::UploadTarget => EndpointUsage::UploadTarget,
        RawEndpointUsage::ControlPlane => EndpointUsage::ControlPlane,
        RawEndpointUsage::GenericEndpoint => EndpointUsage::GenericEndpoint,
    }
}

fn normalize_package_manager_kind(raw: RawPackageManagerKind) -> PackageManagerKind {
    match raw {
        RawPackageManagerKind::Pip => PackageManagerKind::Pip,
        RawPackageManagerKind::Apt => PackageManagerKind::Apt,
        RawPackageManagerKind::Conan => PackageManagerKind::Conan,
        RawPackageManagerKind::Npm => PackageManagerKind::Npm,
    }
}

fn normalize_package_locator_kind(raw: RawPackageLocatorKind) -> PackageLocatorKind {
    match raw {
        RawPackageLocatorKind::RegistryRef => PackageLocatorKind::RegistryRef,
        RawPackageLocatorKind::LocalPath => PackageLocatorKind::LocalPath,
        RawPackageLocatorKind::DirectUrl => PackageLocatorKind::DirectUrl,
        RawPackageLocatorKind::VcsUrl => PackageLocatorKind::VcsUrl,
        RawPackageLocatorKind::RequirementFile => PackageLocatorKind::RequirementFile,
        RawPackageLocatorKind::UnknownDynamic => PackageLocatorKind::UnknownDynamic,
    }
}

fn normalize_process_target_kind(raw: RawProcessTargetKind) -> ProcessTargetKind {
    match raw {
        RawProcessTargetKind::Pid => ProcessTargetKind::Pid,
        RawProcessTargetKind::ProcessName => ProcessTargetKind::ProcessName,
        RawProcessTargetKind::ProcessPattern => ProcessTargetKind::ProcessPattern,
        RawProcessTargetKind::JobSpec => ProcessTargetKind::JobSpec,
        RawProcessTargetKind::Unknown => ProcessTargetKind::Unknown,
    }
}

fn normalize_in_process_code_load_kind(
    raw: RawInProcessCodeLoadKind,
) -> caushell_types::InProcessCodeLoadKind {
    match raw {
        RawInProcessCodeLoadKind::ModuleName => caushell_types::InProcessCodeLoadKind::ModuleName,
        RawInProcessCodeLoadKind::Path => caushell_types::InProcessCodeLoadKind::Path,
        RawInProcessCodeLoadKind::PluginName => caushell_types::InProcessCodeLoadKind::PluginName,
        RawInProcessCodeLoadKind::LibraryPath => caushell_types::InProcessCodeLoadKind::LibraryPath,
        RawInProcessCodeLoadKind::AgentPath => caushell_types::InProcessCodeLoadKind::AgentPath,
        RawInProcessCodeLoadKind::Unknown => caushell_types::InProcessCodeLoadKind::Unknown,
    }
}

fn normalize_effect(raw: RawEffect) -> Result<Effect, NormalizeError> {
    let kind = normalize_effect_kind(raw.kind);
    let surface = normalize_effect_surface(kind, raw.surface)?;
    let repository_operation = normalize_repository_operation(kind, raw.repository_operation)?;

    Ok(Effect {
        kind,
        target: normalize_effect_target(raw.target)?,
        interactive_escape_surface: surface,
        catastrophic: normalize_catastrophic_effect_metadata(raw.catastrophic)?,
        host_risk: normalize_host_risk_effect_metadata(raw.host_risk)?,
        repository_operation,
        extensions: normalize_extensions(raw.extensions)?,
    })
}

fn normalize_repository_operation(
    kind: EffectKind,
    raw: Option<RawRepositoryOperationKind>,
) -> Result<Option<caushell_types::RepositoryOperationKind>, NormalizeError> {
    match (kind, raw) {
        (EffectKind::RepositoryOperation, Some(operation)) => Ok(Some(match operation {
            RawRepositoryOperationKind::TrackedWorktreeDiscard => {
                caushell_types::RepositoryOperationKind::TrackedWorktreeDiscard
            }
            RawRepositoryOperationKind::UntrackedWorktreeDelete => {
                caushell_types::RepositoryOperationKind::UntrackedWorktreeDelete
            }
            RawRepositoryOperationKind::ForcedWorktreeSwitch => {
                caushell_types::RepositoryOperationKind::ForcedWorktreeSwitch
            }
            RawRepositoryOperationKind::TrackedPathDelete => {
                caushell_types::RepositoryOperationKind::TrackedPathDelete
            }
            RawRepositoryOperationKind::SavedStateDestroy => {
                caushell_types::RepositoryOperationKind::SavedStateDestroy
            }
            RawRepositoryOperationKind::LocalRefDestroy => {
                caushell_types::RepositoryOperationKind::LocalRefDestroy
            }
        })),
        (EffectKind::RepositoryOperation, None) => Err(NormalizeError::MissingRepositoryOperation),
        (_, Some(_)) => Err(NormalizeError::UnexpectedRepositoryOperation),
        (_, None) => Ok(None),
    }
}

fn normalize_catastrophic_effect_metadata(
    raw: Option<RawCatastrophicEffectMetadata>,
) -> Result<CatastrophicEffectMetadata, NormalizeError> {
    let Some(raw) = raw else {
        return Ok(CatastrophicEffectMetadata::default());
    };

    Ok(CatastrophicEffectMetadata {
        semantic_class: raw
            .semantic_class
            .map(normalize_catastrophic_semantic_class),
        required_modifiers: raw
            .required_modifiers
            .into_iter()
            .map(|modifier| {
                ensure_non_empty(&modifier, "effects.catastrophic.required_modifiers")?;
                Ok(crate::ModifierId::new(modifier))
            })
            .collect::<Result<Vec<_>, NormalizeError>>()?,
    })
}

fn normalize_catastrophic_semantic_class(
    raw: RawCatastrophicSemanticClass,
) -> CatastrophicSemanticClass {
    match raw {
        RawCatastrophicSemanticClass::DeletePath => CatastrophicSemanticClass::DeletePath,
        RawCatastrophicSemanticClass::RawWriteTarget => CatastrophicSemanticClass::RawWriteTarget,
        RawCatastrophicSemanticClass::FormatTarget => CatastrophicSemanticClass::FormatTarget,
        RawCatastrophicSemanticClass::FilesystemSignatureWipeTarget => {
            CatastrophicSemanticClass::FilesystemSignatureWipeTarget
        }
        RawCatastrophicSemanticClass::PartitionTableMutationTarget => {
            CatastrophicSemanticClass::PartitionTableMutationTarget
        }
    }
}

fn normalize_host_risk_effect_metadata(
    raw: Option<RawHostRiskEffectMetadata>,
) -> Result<HostRiskEffectMetadata, NormalizeError> {
    let Some(raw) = raw else {
        return Ok(HostRiskEffectMetadata::default());
    };

    Ok(HostRiskEffectMetadata {
        semantic_class: raw.semantic_class.map(normalize_host_risk_semantic_class),
        required_modifiers: raw
            .required_modifiers
            .into_iter()
            .map(|modifier| {
                ensure_non_empty(&modifier, "effects.host_risk.required_modifiers")?;
                Ok(crate::ModifierId::new(modifier))
            })
            .collect::<Result<Vec<_>, NormalizeError>>()?,
    })
}

fn normalize_host_risk_semantic_class(raw: RawHostRiskSemanticClass) -> HostRiskSemanticClass {
    match raw {
        RawHostRiskSemanticClass::MoveSourcePath => HostRiskSemanticClass::MoveSourcePath,
        RawHostRiskSemanticClass::PartitionLayoutMutationTarget => {
            HostRiskSemanticClass::PartitionLayoutMutationTarget
        }
        RawHostRiskSemanticClass::PartitionTableStateMutationTarget => {
            HostRiskSemanticClass::PartitionTableStateMutationTarget
        }
        RawHostRiskSemanticClass::PartitionTableSessionTarget => {
            HostRiskSemanticClass::PartitionTableSessionTarget
        }
    }
}

fn normalize_effect_kind(raw: RawEffectKind) -> EffectKind {
    match raw {
        RawEffectKind::ReadPath => EffectKind::ReadPath,
        RawEffectKind::WritePath => EffectKind::WritePath,
        RawEffectKind::DeletePath => EffectKind::DeletePath,
        RawEffectKind::MovePath => EffectKind::MovePath,
        RawEffectKind::ChangeMode => EffectKind::ChangeMode,
        RawEffectKind::ChangeOwner => EffectKind::ChangeOwner,
        RawEffectKind::ChangeGroup => EffectKind::ChangeGroup,
        RawEffectKind::MetadataMutation => EffectKind::MetadataMutation,
        RawEffectKind::TargetPath => EffectKind::TargetPath,
        RawEffectKind::LoadConfig => EffectKind::LoadConfig,
        RawEffectKind::ExecutePayload => EffectKind::ExecutePayload,
        RawEffectKind::SourceScriptIntoCurrentShell => EffectKind::SourceScriptIntoCurrentShell,
        RawEffectKind::SetCurrentWorkingDirectory => EffectKind::SetCurrentWorkingDirectory,
        RawEffectKind::ExecuteRemoteCommand => EffectKind::ExecuteRemoteCommand,
        RawEffectKind::ExecuteHook => EffectKind::ExecuteHook,
        RawEffectKind::ExecuteConfigDefinedTask => EffectKind::ExecuteConfigDefinedTask,
        RawEffectKind::DispatchCommand => EffectKind::DispatchCommand,
        RawEffectKind::ConsumeStdin => EffectKind::ConsumeStdin,
        RawEffectKind::BindVariableFromRuntimeInput => EffectKind::BindVariableFromRuntimeInput,
        RawEffectKind::PrivilegeModifier => EffectKind::PrivilegeModifier,
        RawEffectKind::NetworkEndpoint => EffectKind::NetworkEndpoint,
        RawEffectKind::TransformData => EffectKind::TransformData,
        RawEffectKind::ImportPackage => EffectKind::ImportPackage,
        RawEffectKind::ExecuteImportedPackageLogic => EffectKind::ExecuteImportedPackageLogic,
        RawEffectKind::LoadInProcessCode => EffectKind::LoadInProcessCode,
        RawEffectKind::OpenInteractiveEscapeSurface => EffectKind::OpenInteractiveEscapeSurface,
        RawEffectKind::ControlProcess => EffectKind::ControlProcess,
        RawEffectKind::RepositoryOperation => EffectKind::RepositoryOperation,
    }
}

fn normalize_effect_surface(
    kind: EffectKind,
    raw: Option<RawInteractiveEscapeSurface>,
) -> Result<Option<crate::InteractiveEscapeSurface>, NormalizeError> {
    match (kind, raw) {
        (EffectKind::OpenInteractiveEscapeSurface, Some(surface)) => {
            Ok(Some(normalize_interactive_escape_surface(surface)))
        }
        (EffectKind::OpenInteractiveEscapeSurface, None) => {
            Err(NormalizeError::MissingInteractiveEscapeSurface)
        }
        (_, Some(_)) => Err(NormalizeError::UnexpectedInteractiveEscapeSurface),
        (_, None) => Ok(None),
    }
}

fn normalize_interactive_escape_surface(
    raw: RawInteractiveEscapeSurface,
) -> crate::InteractiveEscapeSurface {
    crate::InteractiveEscapeSurface {
        kind: normalize_interactive_escape_surface_kind(raw.kind),
        requires_tty: raw.requires_tty,
        capabilities: raw
            .capabilities
            .into_iter()
            .map(normalize_interactive_escape_capability)
            .collect(),
    }
}

fn normalize_interactive_escape_surface_kind(
    raw: RawInteractiveEscapeSurfaceKind,
) -> InteractiveEscapeSurfaceKind {
    match raw {
        RawInteractiveEscapeSurfaceKind::Pager => InteractiveEscapeSurfaceKind::Pager,
        RawInteractiveEscapeSurfaceKind::Editor => InteractiveEscapeSurfaceKind::Editor,
        RawInteractiveEscapeSurfaceKind::TerminalUi => InteractiveEscapeSurfaceKind::TerminalUi,
        RawInteractiveEscapeSurfaceKind::LineEditor => InteractiveEscapeSurfaceKind::LineEditor,
        RawInteractiveEscapeSurfaceKind::Generic => InteractiveEscapeSurfaceKind::Generic,
    }
}

fn normalize_interactive_escape_capability(
    raw: RawInteractiveEscapeCapability,
) -> InteractiveEscapeCapability {
    match raw {
        RawInteractiveEscapeCapability::SpawnShell => InteractiveEscapeCapability::SpawnShell,
        RawInteractiveEscapeCapability::RunCommand => InteractiveEscapeCapability::RunCommand,
        RawInteractiveEscapeCapability::LaunchExternalEditor => {
            InteractiveEscapeCapability::LaunchExternalEditor
        }
        RawInteractiveEscapeCapability::WriteBufferToPath => {
            InteractiveEscapeCapability::WriteBufferToPath
        }
    }
}

fn normalize_effect_target(raw: RawEffectTarget) -> Result<EffectTarget, NormalizeError> {
    match raw {
        RawEffectTarget::Slot { name } => {
            ensure_non_empty(&name, "effects.target.name")?;
            Ok(EffectTarget::Slot(SlotName::new(name)))
        }
        RawEffectTarget::ToolConventionPath {
            path,
            convention,
            purpose,
        } => {
            ensure_non_empty(&path, "effects.target.path")?;
            ensure_non_empty(&convention, "effects.target.convention")?;
            Ok(EffectTarget::ToolConventionPath(ToolConventionPathTarget {
                path,
                convention,
                purpose: purpose.map(normalize_path_purpose),
            }))
        }
        RawEffectTarget::DerivedPath {
            source,
            root,
            rule,
            purpose,
        } => Ok(EffectTarget::DerivedPath(DerivedPathTarget {
            source: normalize_derived_path_source(source)?,
            root: root.map(normalize_derived_path_source).transpose()?,
            rule: normalize_derived_path_rule(rule)?,
            purpose: purpose.map(normalize_path_purpose),
        })),
        RawEffectTarget::MutationScope {
            scope_kind,
            root,
            path_set,
            subtree,
        } => Ok(EffectTarget::MutationScope(match scope_kind {
            RawMutationScopeKind::RepositoryWorktree => MutationScopeTarget::RepositoryWorktree {
                root: root
                    .map(|name| {
                        ensure_non_empty(&name, "effects.target.root")?;
                        Ok(SlotName::new(name))
                    })
                    .transpose()?,
                path_set: normalize_repository_worktree_path_set(path_set),
                subtree: subtree
                    .map(|name| {
                        ensure_non_empty(&name, "effects.target.subtree")?;
                        Ok(SlotName::new(name))
                    })
                    .transpose()?,
            },
        })),
        RawEffectTarget::ImplicitInput { source } => Ok(EffectTarget::ImplicitInput(
            normalize_implicit_input_source(source),
        )),
        RawEffectTarget::Dispatch {
            command,
            argv,
            environment,
        } => {
            ensure_non_empty(&command, "effects.target.command")?;
            Ok(EffectTarget::Dispatch(DispatchTarget {
                command: SlotName::new(command),
                argv: normalize_slot_names(argv, "effects.target.argv")?,
                environment: normalize_slot_names(environment, "effects.target.environment")?,
            }))
        }
        RawEffectTarget::None => Ok(EffectTarget::None),
    }
}

fn normalize_repository_worktree_path_set(
    raw: RawRepositoryWorktreePathSet,
) -> RepositoryWorktreePathSet {
    match raw {
        RawRepositoryWorktreePathSet::Tracked => RepositoryWorktreePathSet::Tracked,
        RawRepositoryWorktreePathSet::PatchSelectedTracked => {
            RepositoryWorktreePathSet::PatchSelectedTracked
        }
        RawRepositoryWorktreePathSet::RegisteredSubmoduleWorktrees => {
            RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees
        }
        RawRepositoryWorktreePathSet::UntrackedOnly => RepositoryWorktreePathSet::UntrackedOnly,
        RawRepositoryWorktreePathSet::IgnoredOnly => RepositoryWorktreePathSet::IgnoredOnly,
        RawRepositoryWorktreePathSet::UntrackedAndIgnored => {
            RepositoryWorktreePathSet::UntrackedAndIgnored
        }
    }
}

fn normalize_derived_path_source(
    raw: RawDerivedPathSource,
) -> Result<DerivedPathSource, NormalizeError> {
    match raw {
        RawDerivedPathSource::Slot { name } => {
            ensure_non_empty(&name, "effects.target.source.name")?;
            Ok(DerivedPathSource::Slot(SlotName::new(name)))
        }
        RawDerivedPathSource::ToolConventionRoot { convention } => {
            ensure_non_empty(&convention, "effects.target.source.convention")?;
            Ok(DerivedPathSource::ToolConventionRoot { convention })
        }
    }
}

fn normalize_derived_path_rule(
    raw: RawDerivedPathRule,
) -> Result<caushell_types::DerivedPathRule, NormalizeError> {
    match raw {
        RawDerivedPathRule::AppendSuffix { suffix } => {
            ensure_non_empty(&suffix, "effects.target.rule.suffix")?;
            Ok(caushell_types::DerivedPathRule::AppendSuffix { suffix })
        }
        RawDerivedPathRule::StripSuffix { suffix } => {
            ensure_non_empty(&suffix, "effects.target.rule.suffix")?;
            Ok(caushell_types::DerivedPathRule::StripSuffix { suffix })
        }
        RawDerivedPathRule::ReplaceSuffix { from, to } => {
            ensure_non_empty(&from, "effects.target.rule.from")?;
            ensure_non_empty(&to, "effects.target.rule.to")?;
            Ok(caushell_types::DerivedPathRule::ReplaceSuffix { from, to })
        }
        RawDerivedPathRule::UrlBasename => Ok(caushell_types::DerivedPathRule::UrlBasename),
        RawDerivedPathRule::ArchiveMembers => Ok(caushell_types::DerivedPathRule::ArchiveMembers),
        RawDerivedPathRule::ChildUnder { relative_path } => {
            ensure_non_empty(&relative_path, "effects.target.rule.relative_path")?;
            Ok(caushell_types::DerivedPathRule::ChildUnder { relative_path })
        }
    }
}

fn normalize_slot_names(
    raw: Vec<String>,
    field: &'static str,
) -> Result<Vec<SlotName>, NormalizeError> {
    raw.into_iter()
        .map(|name| {
            ensure_non_empty(&name, field)?;
            Ok(SlotName::new(name))
        })
        .collect()
}

fn normalize_subcommand_tree(raw: RawSubcommandTree) -> Result<SubcommandTree, NormalizeError> {
    let roots = normalize_subcommand_nodes(raw.roots)?;
    Ok(SubcommandTree { roots })
}

fn normalize_subcommand_nodes(
    raw_nodes: Vec<RawSubcommandNode>,
) -> Result<Vec<SubcommandNode>, NormalizeError> {
    ensure_unique_subcommand_names(&raw_nodes)?;
    raw_nodes
        .into_iter()
        .map(normalize_subcommand_node)
        .collect()
}

fn normalize_subcommand_node(raw: RawSubcommandNode) -> Result<SubcommandNode, NormalizeError> {
    ensure_non_empty(&raw.name, "subcommands.name")?;

    Ok(SubcommandNode {
        name: raw.name,
        aliases: raw
            .aliases
            .into_iter()
            .map(|alias| {
                ensure_non_empty(&alias, "subcommands.aliases")?;
                Ok(alias)
            })
            .collect::<Result<Vec<_>, _>>()?,
        forms: normalize_forms(raw.forms)?,
        modifiers: normalize_modifiers(raw.modifiers)?,
        children: normalize_subcommand_nodes(raw.children)?,
        default_behavior: raw.default_behavior.map(|value| match value {
            RawDefaultSubcommandBehavior::RejectUnknown => DefaultSubcommandBehavior::RejectUnknown,
            RawDefaultSubcommandBehavior::ResidualUnknownSubcommand => {
                DefaultSubcommandBehavior::ResidualUnknownSubcommand
            }
        }),
        extensions: normalize_extensions(raw.extensions)?,
    })
}

fn normalize_runtime_feature(raw: RawRuntimeFeature) -> RuntimeFeature {
    match raw {
        RawRuntimeFeature::InteractiveSession => RuntimeFeature::InteractiveSession,
        RawRuntimeFeature::StdinPayloadAvailable => RuntimeFeature::StdinPayloadAvailable,
        RawRuntimeFeature::PipelineInputAvailable => RuntimeFeature::PipelineInputAvailable,
    }
}

fn normalize_extensions(raw: BTreeMap<String, JsonValue>) -> Result<ExtensionMap, NormalizeError> {
    for key in raw.keys() {
        if !key.contains('.') {
            return Err(NormalizeError::InvalidExtensionKey(key.clone()));
        }
    }
    Ok(raw)
}

fn ensure_unique_form_ids(forms: &[RawForm]) -> Result<(), NormalizeError> {
    let mut seen = BTreeSet::new();

    for form in forms {
        ensure_non_empty(&form.id, "forms.id")?;
        if !seen.insert(form.id.clone()) {
            return Err(NormalizeError::DuplicateFormId(form.id.clone()));
        }
    }

    Ok(())
}

fn ensure_unique_modifier_ids(modifiers: &[RawModifier]) -> Result<(), NormalizeError> {
    let mut seen = BTreeSet::new();

    for modifier in modifiers {
        ensure_non_empty(&modifier.id, "modifiers.id")?;
        if !seen.insert(modifier.id.clone()) {
            return Err(NormalizeError::DuplicateModifierId(modifier.id.clone()));
        }
    }

    Ok(())
}

fn ensure_unique_parameter_names(parameters: &[RawParameter]) -> Result<(), NormalizeError> {
    let mut seen = BTreeSet::new();

    for parameter in parameters {
        ensure_non_empty(&parameter.name, "parameters.name")?;
        if !seen.insert(parameter.name.clone()) {
            return Err(NormalizeError::DuplicateParameterName(
                parameter.name.clone(),
            ));
        }
    }

    Ok(())
}

fn ensure_unique_subcommand_names(nodes: &[RawSubcommandNode]) -> Result<(), NormalizeError> {
    let mut seen = BTreeSet::new();

    for node in nodes {
        ensure_non_empty(&node.name, "subcommands.name")?;
        if !seen.insert(node.name.clone()) {
            return Err(NormalizeError::DuplicateSubcommandNameOrAlias(
                node.name.clone(),
            ));
        }

        for alias in &node.aliases {
            ensure_non_empty(alias, "subcommands.aliases")?;
            if !seen.insert(alias.clone()) {
                return Err(NormalizeError::DuplicateSubcommandNameOrAlias(
                    alias.clone(),
                ));
            }
        }
    }

    Ok(())
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), NormalizeError> {
    if value.is_empty() {
        return Err(NormalizeError::EmptyIdentifier { field });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{NormalizeError, normalize_command_profile};
    use crate::raw::{
        RawBindingSpec, RawCardinality, RawCommandIdentity, RawCommandProfile, RawEffect,
        RawEffectKind, RawEffectTarget, RawFlagOperandMode, RawForm, RawInProcessCodeLoadKind,
        RawModifier, RawModifierMatcher, RawParameter, RawPathPurpose, RawPathRole,
        RawPayloadLanguage, RawPayloadSource, RawPlatformConstraints, RawProfileSourceKind,
        RawProfileTrustMetadata, RawProfileTrustTier, RawSelectorExpr, RawSemanticType,
        RawValueConstraint,
    };
    use crate::{
        BindingSpec, EffectKind, EffectTarget, PathPurpose, PathRole, PayloadLanguage,
        PayloadSource, SelectorExpr, SelectorPredicate, SemanticType, ValueConstraint,
    };

    #[test]
    fn normalize_command_profile_maps_raw_schema_to_normalized_profile() {
        let raw = RawCommandProfile {
            dsl_version: "caushell.profile/v1alpha1".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "bash".to_string(),
                aliases: vec!["sh-compatible".to_string()],
            },
            trust: RawProfileTrustMetadata {
                tier: RawProfileTrustTier::TierA,
                source: RawProfileSourceKind::BuiltIn,
                reviewed_by: None,
                review_notes: None,
            },
            platform: Default::default(),
            forms: vec![RawForm {
                id: "command_string".to_string(),
                selector: RawSelectorExpr::HasFlag {
                    flag: "-c".to_string(),
                },
                remaining_selector: RawSelectorExpr::All { items: Vec::new() },
                parameters: vec![RawParameter {
                    name: "payload".to_string(),
                    semantic: RawSemanticType::Payload {
                        language: RawPayloadLanguage::Bash,
                        source: RawPayloadSource::InlineString,
                        recursive: true,
                    },
                    binding: RawBindingSpec::FollowingFlag {
                        flag: "-c".to_string(),
                        operand_mode: RawFlagOperandMode::NextPositionalAfterDashDash,
                    },
                    cardinality: None,
                    value_constraints: vec![RawValueConstraint::ExcludeLiteral {
                        value: "--".to_string(),
                    }],
                    extensions: BTreeMap::new(),
                }],
                implicit_inputs: Vec::new(),
                effects: vec![RawEffect {
                    kind: RawEffectKind::ExecutePayload,
                    target: RawEffectTarget::Slot {
                        name: "payload".to_string(),
                    },
                    surface: None,
                    catastrophic: None,
                    host_risk: None,
                    repository_operation: None,
                    extensions: BTreeMap::new(),
                }],
                stream_contract: None,
                extensions: BTreeMap::new(),
            }],
            modifiers: vec![RawModifier {
                id: "rcfile".to_string(),
                matcher: RawModifierMatcher::AnyFlag {
                    flags: vec!["--rcfile".to_string()],
                },
                parameters: vec![RawParameter {
                    name: "startup_config".to_string(),
                    semantic: RawSemanticType::Path {
                        role: RawPathRole::Config,
                        purpose: Some(RawPathPurpose::StartupConfig),
                    },
                    binding: RawBindingSpec::FollowingMatchedFlag {
                        operand_mode: RawFlagOperandMode::NextArg,
                    },
                    cardinality: None,
                    value_constraints: Vec::new(),
                    extensions: BTreeMap::new(),
                }],
                effects: vec![RawEffect {
                    kind: RawEffectKind::LoadConfig,
                    target: RawEffectTarget::Slot {
                        name: "startup_config".to_string(),
                    },
                    surface: None,
                    catastrophic: None,
                    host_risk: None,
                    repository_operation: None,
                    extensions: BTreeMap::new(),
                }],
                constraints: Vec::new(),
                extensions: BTreeMap::new(),
            }],
            subcommands: None,
            extensions: BTreeMap::from([(
                "builtin.review.notes".to_string(),
                json!({"ticket":"CR-1"}),
            )]),
        };

        let normalized = normalize_command_profile(raw).expect("expected normalized profile");

        assert_eq!(normalized.primary_name(), "bash");
        assert_eq!(normalized.identity.aliases.len(), 1);
        assert_eq!(normalized.forms.len(), 1);
        assert_eq!(normalized.modifiers.len(), 1);

        match &normalized.forms[0].selector {
            SelectorExpr::Predicate(SelectorPredicate::HasFlag(flag_name)) => {
                assert_eq!(flag_name.as_str(), "-c");
            }
            other => panic!("unexpected selector predicate: {other:?}"),
        }

        match &normalized.forms[0].parameters[0].semantic {
            SemanticType::Payload(semantic) => {
                assert_eq!(semantic.language, PayloadLanguage::Bash);
                assert_eq!(semantic.source, PayloadSource::InlineString);
                assert!(semantic.recursive);
            }
            other => panic!("unexpected semantic: {other:?}"),
        }

        assert_eq!(
            normalized.forms[0].parameters[0].value_constraints,
            vec![ValueConstraint::ExcludeLiteral("--".to_string())]
        );

        match &normalized.modifiers[0].parameters[0].semantic {
            SemanticType::Path(semantic) => {
                assert_eq!(semantic.role, PathRole::Config);
                assert_eq!(semantic.purpose, Some(PathPurpose::StartupConfig));
            }
            other => panic!("unexpected semantic: {other:?}"),
        }

        assert_eq!(
            normalized.forms[0].parameters[0].binding,
            BindingSpec::FollowingFlag {
                flag_name: crate::FlagName::new("-c"),
                operand_mode: crate::FlagOperandMode::NextPositionalAfterDashDash,
            }
        );
        assert_eq!(
            normalized.modifiers[0].parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::NextArg,
            }
        );
        assert_eq!(
            normalized.modifiers[0].effects[0].kind,
            EffectKind::LoadConfig
        );
        assert_eq!(
            normalized.modifiers[0].effects[0].target,
            EffectTarget::Slot(crate::SlotName::new("startup_config"))
        );
    }

    #[test]
    fn normalize_command_profile_accepts_inline_only_flag_operands() {
        let raw = RawCommandProfile {
            dsl_version: "caushell.profile/v1alpha1".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "cp".to_string(),
                aliases: Vec::new(),
            },
            trust: RawProfileTrustMetadata {
                tier: RawProfileTrustTier::TierA,
                source: RawProfileSourceKind::BuiltIn,
                reviewed_by: None,
                review_notes: None,
            },
            platform: RawPlatformConstraints::default(),
            forms: vec![RawForm {
                id: "copy".to_string(),
                selector: RawSelectorExpr::HasPositionalAt { index: 1 },
                remaining_selector: RawSelectorExpr::default(),
                parameters: vec![RawParameter {
                    name: "destination".to_string(),
                    semantic: RawSemanticType::Path {
                        role: RawPathRole::Write,
                        purpose: Some(RawPathPurpose::GenericOperand),
                    },
                    binding: RawBindingSpec::LastPositional,
                    cardinality: Some(RawCardinality::RequiredOne),
                    value_constraints: Vec::new(),
                    extensions: BTreeMap::new(),
                }],
                implicit_inputs: Vec::new(),
                effects: vec![RawEffect {
                    kind: RawEffectKind::WritePath,
                    target: RawEffectTarget::Slot {
                        name: "destination".to_string(),
                    },
                    surface: None,
                    catastrophic: None,
                    host_risk: None,
                    repository_operation: None,
                    extensions: BTreeMap::new(),
                }],
                stream_contract: None,
                extensions: BTreeMap::new(),
            }],
            modifiers: vec![RawModifier {
                id: "set_security_context".to_string(),
                matcher: RawModifierMatcher::AnyFlag {
                    flags: vec!["--context".to_string()],
                },
                parameters: vec![RawParameter {
                    name: "security_context".to_string(),
                    semantic: RawSemanticType::PlainValue,
                    binding: RawBindingSpec::FollowingMatchedFlag {
                        operand_mode: RawFlagOperandMode::InlineOnly,
                    },
                    cardinality: Some(RawCardinality::OptionalOne),
                    value_constraints: Vec::new(),
                    extensions: BTreeMap::new(),
                }],
                effects: Vec::new(),
                constraints: Vec::new(),
                extensions: BTreeMap::new(),
            }],
            subcommands: None,
            extensions: BTreeMap::new(),
        };

        let normalized = normalize_command_profile(raw).expect("expected normalized profile");

        assert_eq!(
            normalized.modifiers[0].parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::InlineOnly,
            }
        );
    }

    #[test]
    fn normalize_command_profile_accepts_inline_or_short_attached_flag_operands() {
        let raw = RawCommandProfile {
            dsl_version: "caushell.profile/v1alpha1".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "fdisk".to_string(),
                aliases: Vec::new(),
            },
            trust: RawProfileTrustMetadata {
                tier: RawProfileTrustTier::TierA,
                source: RawProfileSourceKind::BuiltIn,
                reviewed_by: None,
                review_notes: None,
            },
            platform: RawPlatformConstraints::default(),
            forms: vec![RawForm {
                id: "interactive".to_string(),
                selector: RawSelectorExpr::HasPositionalAt { index: 0 },
                remaining_selector: RawSelectorExpr::default(),
                parameters: vec![RawParameter {
                    name: "target".to_string(),
                    semantic: RawSemanticType::Path {
                        role: RawPathRole::Write,
                        purpose: Some(RawPathPurpose::GenericOperand),
                    },
                    binding: RawBindingSpec::NextPositional,
                    cardinality: Some(RawCardinality::RequiredOne),
                    value_constraints: Vec::new(),
                    extensions: BTreeMap::new(),
                }],
                implicit_inputs: Vec::new(),
                effects: vec![RawEffect {
                    kind: RawEffectKind::WritePath,
                    target: RawEffectTarget::Slot {
                        name: "target".to_string(),
                    },
                    surface: None,
                    catastrophic: None,
                    host_risk: None,
                    repository_operation: None,
                    extensions: BTreeMap::new(),
                }],
                stream_contract: None,
                extensions: BTreeMap::new(),
            }],
            modifiers: vec![RawModifier {
                id: "compatibility".to_string(),
                matcher: RawModifierMatcher::AnyFlag {
                    flags: vec!["-c".to_string(), "--compatibility".to_string()],
                },
                parameters: vec![RawParameter {
                    name: "compatibility_mode".to_string(),
                    semantic: RawSemanticType::PlainValue,
                    binding: RawBindingSpec::FollowingMatchedFlag {
                        operand_mode: RawFlagOperandMode::InlineOrShortAttached,
                    },
                    cardinality: Some(RawCardinality::OptionalOne),
                    value_constraints: Vec::new(),
                    extensions: BTreeMap::new(),
                }],
                effects: Vec::new(),
                constraints: Vec::new(),
                extensions: BTreeMap::new(),
            }],
            subcommands: None,
            extensions: BTreeMap::new(),
        };

        let normalized = normalize_command_profile(raw).expect("expected normalized profile");

        assert_eq!(
            normalized.modifiers[0].parameters[0].binding,
            BindingSpec::FollowingMatchedFlag {
                operand_mode: crate::FlagOperandMode::InlineOrShortAttached,
            }
        );
    }

    #[test]
    fn normalize_command_profile_accepts_positional_at_binding() {
        let raw = RawCommandProfile {
            dsl_version: "caushell.profile/v1alpha1".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "parted".to_string(),
                aliases: Vec::new(),
            },
            trust: RawProfileTrustMetadata {
                tier: RawProfileTrustTier::TierA,
                source: RawProfileSourceKind::BuiltIn,
                reviewed_by: None,
                review_notes: None,
            },
            platform: RawPlatformConstraints::default(),
            forms: vec![RawForm {
                id: "retargeted".to_string(),
                selector: RawSelectorExpr::HasPositionalAt { index: 2 },
                remaining_selector: RawSelectorExpr::default(),
                parameters: vec![RawParameter {
                    name: "target".to_string(),
                    semantic: RawSemanticType::Path {
                        role: RawPathRole::Write,
                        purpose: Some(RawPathPurpose::GenericOperand),
                    },
                    binding: RawBindingSpec::PositionalAt { index: 2 },
                    cardinality: Some(RawCardinality::RequiredOne),
                    value_constraints: Vec::new(),
                    extensions: BTreeMap::new(),
                }],
                implicit_inputs: Vec::new(),
                effects: Vec::new(),
                stream_contract: None,
                extensions: BTreeMap::new(),
            }],
            modifiers: Vec::new(),
            subcommands: None,
            extensions: BTreeMap::new(),
        };

        let normalized = normalize_command_profile(raw).expect("expected normalized profile");

        assert_eq!(
            normalized.forms[0].parameters[0].binding,
            BindingSpec::PositionalAt(2)
        );
    }

    #[test]
    fn normalize_command_profile_maps_metadata_mutation_semantics() {
        let raw = RawCommandProfile {
            dsl_version: "caushell.profile/v1alpha1".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "chmod".to_string(),
                aliases: Vec::new(),
            },
            forms: vec![RawForm {
                id: "change_mode".to_string(),
                selector: RawSelectorExpr::HasPositionalAt { index: 1 },
                remaining_selector: RawSelectorExpr::All { items: Vec::new() },
                parameters: vec![
                    RawParameter {
                        name: "mode".to_string(),
                        semantic: RawSemanticType::PlainValue,
                        binding: RawBindingSpec::NextPositional,
                        cardinality: None,
                        value_constraints: Vec::new(),
                        extensions: BTreeMap::new(),
                    },
                    RawParameter {
                        name: "path_targets".to_string(),
                        semantic: RawSemanticType::Path {
                            role: RawPathRole::MetadataMutation,
                            purpose: Some(RawPathPurpose::GenericOperand),
                        },
                        binding: RawBindingSpec::RemainingPositionals,
                        cardinality: None,
                        value_constraints: Vec::new(),
                        extensions: BTreeMap::new(),
                    },
                ],
                implicit_inputs: Vec::new(),
                effects: vec![RawEffect {
                    kind: RawEffectKind::ChangeMode,
                    target: RawEffectTarget::Slot {
                        name: "path_targets".to_string(),
                    },
                    surface: None,
                    catastrophic: None,
                    host_risk: None,
                    repository_operation: None,
                    extensions: BTreeMap::new(),
                }],
                stream_contract: None,
                extensions: BTreeMap::new(),
            }],
            ..Default::default()
        };

        let normalized = normalize_command_profile(raw).expect("expected normalized profile");

        match &normalized.forms[0].parameters[1].semantic {
            SemanticType::Path(semantic) => {
                assert_eq!(semantic.role, PathRole::MetadataMutation);
                assert_eq!(semantic.purpose, Some(PathPurpose::GenericOperand));
            }
            other => panic!("unexpected semantic: {other:?}"),
        }
        assert_eq!(normalized.forms[0].effects[0].kind, EffectKind::ChangeMode);
    }

    #[test]
    fn normalize_rejects_invalid_dsl_version() {
        let raw = RawCommandProfile {
            dsl_version: "wrong".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "bash".to_string(),
                aliases: Vec::new(),
            },
            ..Default::default()
        };

        let error = normalize_command_profile(raw).expect_err("expected invalid dsl version");
        assert_eq!(
            error,
            NormalizeError::InvalidDslVersion("wrong".to_string())
        );
    }

    #[test]
    fn normalize_rejects_duplicate_form_ids() {
        let raw = RawCommandProfile {
            dsl_version: "caushell.profile/v1alpha1".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "bash".to_string(),
                aliases: Vec::new(),
            },
            forms: vec![
                RawForm {
                    id: "command_string".to_string(),
                    ..Default::default()
                },
                RawForm {
                    id: "command_string".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let error = normalize_command_profile(raw).expect_err("expected duplicate form id");
        assert_eq!(
            error,
            NormalizeError::DuplicateFormId("command_string".to_string())
        );
    }

    #[test]
    fn normalize_command_profile_maps_in_process_code_load_semantics() {
        let raw = RawCommandProfile {
            dsl_version: "caushell.profile/v1alpha1".to_string(),
            kind: "command_profile".to_string(),
            identity: RawCommandIdentity {
                canonical_name: "node".to_string(),
                aliases: Vec::new(),
            },
            trust: Default::default(),
            platform: Default::default(),
            forms: vec![RawForm {
                id: "require_hook".to_string(),
                selector: RawSelectorExpr::HasFlag {
                    flag: "-r".to_string(),
                },
                remaining_selector: RawSelectorExpr::All { items: Vec::new() },
                parameters: vec![RawParameter {
                    name: "require_target".to_string(),
                    semantic: RawSemanticType::InProcessCodeLoad {
                        load_kind: RawInProcessCodeLoadKind::Unknown,
                    },
                    binding: RawBindingSpec::FollowingFlag {
                        flag: "-r".to_string(),
                        operand_mode: RawFlagOperandMode::NextArg,
                    },
                    cardinality: None,
                    value_constraints: Vec::new(),
                    extensions: BTreeMap::new(),
                }],
                implicit_inputs: Vec::new(),
                effects: vec![RawEffect {
                    kind: RawEffectKind::LoadInProcessCode,
                    target: RawEffectTarget::Slot {
                        name: "require_target".to_string(),
                    },
                    surface: None,
                    catastrophic: None,
                    host_risk: None,
                    repository_operation: None,
                    extensions: BTreeMap::new(),
                }],
                stream_contract: None,
                extensions: BTreeMap::new(),
            }],
            modifiers: Vec::new(),
            subcommands: None,
            extensions: BTreeMap::new(),
        };

        let normalized = normalize_command_profile(raw).expect("expected normalized profile");

        match &normalized.forms[0].parameters[0].semantic {
            SemanticType::InProcessCodeLoad(semantic) => {
                assert_eq!(
                    semantic.load_kind,
                    caushell_types::InProcessCodeLoadKind::Unknown
                );
            }
            other => panic!("unexpected in-process semantic: {other:?}"),
        }

        assert_eq!(
            normalized.forms[0].effects[0].kind,
            EffectKind::LoadInProcessCode
        );
    }
}

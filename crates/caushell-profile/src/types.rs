use std::collections::BTreeMap;

use caushell_parse::SourceSpan;
use caushell_types::{
    DerivedPathRule, InProcessCodeLoadKind, InteractiveEscapeCapability,
    InteractiveEscapeSurfaceKind, RepositoryWorktreePathSet,
};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundArgumentMaterialization {
    Literal,
    /// Already-materialized argv data; preserve its bytes without another
    /// shell-word expansion pass.
    RuntimeData,
    ResolvedExactScalar {
        variable_name: String,
    },
    ResolvedRuntimeProduced {
        variable_name: String,
    },
}

pub type ExtensionMap = BTreeMap<String, JsonValue>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandName(String);

impl CommandName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FormId(String);

impl FormId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotName(String);

impl SlotName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModifierId(String);

impl ModifierId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlagName(String);

impl FlagName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandIdentity {
    pub canonical_name: CommandName,
    pub aliases: Vec<CommandName>,
    pub module_only: bool,
    pub module_entrypoints: Vec<ModuleEntrypoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleEntrypoint {
    pub runtime: String,
    pub name: String,
}

impl CommandIdentity {
    pub fn new(canonical_name: impl Into<String>) -> Self {
        Self {
            canonical_name: CommandName::new(canonical_name),
            aliases: Vec::new(),
            module_only: false,
            module_entrypoints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTrustTier {
    TierA,
    TierB,
    TierC,
}

impl Default for ProfileTrustTier {
    fn default() -> Self {
        Self::TierC
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileSourceKind {
    BuiltIn,
    User,
    ImportedLegacy,
    Generated,
}

impl Default for ProfileSourceKind {
    fn default() -> Self {
        Self::Generated
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileTrustMetadata {
    pub tier: ProfileTrustTier,
    pub source: ProfileSourceKind,
    pub reviewed_by: Option<String>,
    pub review_notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Posix,
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellFamily {
    Bourne,
    Bash,
    Sh,
    Dash,
    PowerShell,
    Cmd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFeature {
    InteractiveSession,
    StdinPayloadAvailable,
    PipelineInputAvailable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformConstraints {
    pub os_families: Vec<OsFamily>,
    pub shell_families: Vec<ShellFamily>,
    pub requires_features: Vec<RuntimeFeature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorPredicate {
    HasFlag(FlagName),
    HasFlagAtLeast(FlagName, usize),
    LacksFlag(FlagName),
    HasModifier(ModifierId),
    HasModifierParameterMatching(ModifierId, SlotName, ValueMatcher),
    /// Known semantic argv value at a zero-based original tool argument index
    /// (excluding the executable). Independent of option/positional ownership.
    HasArgumentAtMatching(usize, ValueMatcher),
    HasPositionalAt(usize),
    HasPositionalBeforeDashDashAt(usize),
    HasPositionalAtMatching(usize, ValueMatcher),
    HasPositionalAtOrAfterMatching(usize, ValueMatcher),
    HasPositionalAfterLeadingMatcher(ValueMatcher),
    NoPositionalAfterLeadingMatcher(ValueMatcher),
    LastPositionalMatches(ValueMatcher),
    NoPositionalArgs,
    NoArguments,
    HasDashDash,
    NoDashDash,
    StdinPayloadAvailable,
    InteractiveSession,
    HasSubcommandPath(Vec<String>),
    HasRuntimeFeature(RuntimeFeature),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorExpr {
    All(Vec<SelectorExpr>),
    Any(Vec<SelectorExpr>),
    Not(Box<SelectorExpr>),
    Predicate(SelectorPredicate),
}

impl Default for SelectorExpr {
    fn default() -> Self {
        Self::All(Vec::new())
    }
}

impl SelectorExpr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_predicate(mut self, predicate: SelectorPredicate) -> Self {
        match &mut self {
            Self::All(items) => items.push(Self::Predicate(predicate)),
            _ => panic!("with_predicate is only supported on SelectorExpr::All"),
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInputMode {
    Ignored,
    /// Opt-in data input determined by the invocation's bound ConsumeStdin effects.
    /// This is resolved only after the complete-shape guarantee is established.
    DeclaredEffects,
    DataOptional,
    DataRequired,
    PayloadOptional,
    PayloadRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamOutputMode {
    Opaque,
    Data,
    CommandText,
    PathList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamContract {
    pub stdin_mode: StreamInputMode,
    pub stdout_mode: StreamOutputMode,
    pub stderr_mode: StreamOutputMode,
    pub stdout_dependency: caushell_types::StreamDataDependency,
    pub stderr_dependency: caushell_types::StreamDataDependency,
}

/// A positive guarantee about complete stdout records, separate from data
/// provenance. `path_list` alone makes no claim about record boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdoutRecordContract {
    pub projection: StdoutRecordProjection,
    pub required_modifiers: Vec<ModifierId>,
    pub excluded_modifiers: Vec<ModifierId>,
}

/// Complete stdout shape, after command substitution removes trailing LF.
/// Failure may produce no stdout. This is not a concrete value, path root,
/// filesystem fact, or guarantee that unquoted shell splitting is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdoutScalarShape {
    AbsolutePath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdoutRecordProjection {
    Paths {
        roots_slot: SlotName,
        default_root: Option<String>,
        separator: StreamRecordSeparator,
        escape_modifiers: Vec<ModifierId>,
    },
    /// Byte-preserving forwarding of effective stdin, not a generic transform.
    Stdin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRecordSeparator {
    Nul,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRole {
    Read,
    Write,
    MetadataMutation,
    Target,
    Config,
    CwdAnchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPurpose {
    IncidentalCache,
    GenericOperand,
    ScriptSource,
    InProcessCode,
    StartupConfig,
    ProjectConfig,
    ToolConfig,
    TaskConfig,
    WorkingDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSemantic {
    pub role: PathRole,
    pub purpose: Option<PathPurpose>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadLanguage {
    /// Explicit opt-in for executable code outside the modeled shell languages.
    /// Never parsed as Bash; its unresolved boundary defaults to approval.
    Opaque,
    Bash,
    Sh,
    Dash,
    Python,
    Perl,
    Javascript,
    /// SQL and SQLite shell dot-commands; never parsed as a shell program.
    SqliteCli,
    /// MySQL SQL and client commands; opaque, never parsed as Bash.
    MysqlCli,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadSource {
    InlineString,
    ScriptFileRef,
    Stdin,
    Interactive,
    DynamicReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadSemantic {
    pub language: PayloadLanguage,
    pub source: PayloadSource,
    pub recursive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchKind {
    CommandName,
    WrapperCommand,
    ShellPayload,
    InterpreterModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandRefSemantic {
    pub dispatch: DispatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredValueContext {
    Regex,
    SedScript,
    AwkProgram,
    FormatString,
    DateExpression,
    NumericQuantity,
    PathExpression,
    EnvAssignment,
    RemoteSpec,
    OwnerGroupSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredValueSemantic {
    pub context: StructuredValueContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Url,
    HostPort,
    SocketPath,
    RemoteSpec,
    EmailAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointUsage {
    FetchSource,
    UploadTarget,
    ControlPlane,
    GenericEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointSemantic {
    pub kind: EndpointKind,
    pub usage: EndpointUsage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManagerKind {
    Pip,
    Uv,
    Apt,
    Conan,
    Conda,
    Npm,
    Yum,
    Brew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageLocatorKind {
    RegistryRef,
    LocalPath,
    DirectUrl,
    VcsUrl,
    RequirementFile,
    UnknownDynamic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageLocatorSemantic {
    pub manager: PackageManagerKind,
    pub locator_kinds: Vec<PackageLocatorKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InProcessCodeLoadSemantic {
    pub load_kind: InProcessCodeLoadKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTargetKind {
    Pid,
    ProcessName,
    ProcessPattern,
    JobSpec,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTargetSemantic {
    pub kind: ProcessTargetKind,
    pub broad_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticType {
    PlainValue,
    Path(PathSemantic),
    Payload(PayloadSemantic),
    CommandRef(CommandRefSemantic),
    StructuredValue(StructuredValueSemantic),
    Endpoint(EndpointSemantic),
    PackageLocator(PackageLocatorSemantic),
    InProcessCodeLoad(InProcessCodeLoadSemantic),
    ProcessTarget(ProcessTargetSemantic),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    RequiredOne,
    OptionalOne,
    RequiredMany,
    OptionalMany,
}

impl Cardinality {
    pub fn is_optional(self) -> bool {
        matches!(self, Self::OptionalOne | Self::OptionalMany)
    }

    pub fn is_variadic(self) -> bool {
        matches!(self, Self::RequiredMany | Self::OptionalMany)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueMatcher {
    StructuredValueContext(StructuredValueContext),
    Literal(String),
    AsciiCaseInsensitiveLiterals(Vec<String>),
    RegexPattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingSpec {
    ArgumentRegionCommand(String),
    ArgumentRegionArgs(String),
    NextPositional,
    NextPositionalAfterDashDash,
    PositionalAt(usize),
    RemainingPositionals,
    RemainingPositionalsAfterDashDash,
    RemainingPositionalsBeforeLast,
    RemainingArgs,
    ArgsUntilLiteral {
        terminator: String,
        include_terminator: bool,
    },
    LastPositional,
    LastPositionalBeforeLast,
    FollowingFlag {
        flag_name: FlagName,
        operand_mode: FlagOperandMode,
    },
    FollowingMatchedFlag {
        operand_mode: FlagOperandMode,
    },
    ArgsWithPrefix(String),
    /// Opt-in prefix binding restricted to argv before the option terminator.
    ArgsWithPrefixBeforeDashDash(String),
    LeadingPositionalsWhile(ValueMatcher),
    /// Select matching unconsumed positionals without stripping or rewriting argv.
    PositionalsMatching(ValueMatcher),
    LeadingPositionalsBeforeModifier(ModifierId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagOperandMode {
    NextPositional,
    NextArg,
    /// Attached/inline value, otherwise the immediate non-option argv value.
    /// Absence is valid only when the parameter's cardinality is optional.
    OptionalNextArg,
    SecondArg,
    InlineOnly,
    /// A value is optional and may only be inline on a long option. A bare
    /// occurrence never owns a following argv token. Cardinality still applies.
    OptionalInlineOnly,
    /// Optional long-inline or short-attached value. A bare occurrence never
    /// owns the following argv token; required cardinality still applies.
    OptionalInlineOrShortAttached,
    InlineOrShortAttached,
    NextPositionalAfterDashDash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueConstraint {
    ExcludeLiteral(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    pub name: SlotName,
    pub semantic: SemanticType,
    pub binding: BindingSpec,
    pub value_projection: Option<ValueProjection>,
    pub structured_projection: Option<StructuredProjection>,
    pub cardinality: Cardinality,
    pub value_constraints: Vec<ValueConstraint>,
    pub extensions: ExtensionMap,
}

impl Parameter {
    pub fn new(name: &str, semantic: SemanticType, binding: BindingSpec) -> Self {
        Self {
            name: SlotName::new(name),
            semantic,
            binding,
            value_projection: None,
            structured_projection: None,
            cardinality: Cardinality::RequiredOne,
            value_constraints: Vec::new(),
            extensions: ExtensionMap::new(),
        }
    }

    pub fn optional(mut self) -> Self {
        self.cardinality = match self.cardinality {
            Cardinality::RequiredOne => Cardinality::OptionalOne,
            Cardinality::RequiredMany => Cardinality::OptionalMany,
            other => other,
        };
        self
    }

    pub fn variadic(mut self) -> Self {
        self.cardinality = match self.cardinality {
            Cardinality::RequiredOne => Cardinality::RequiredMany,
            Cardinality::OptionalOne => Cardinality::OptionalMany,
            other => other,
        };
        self
    }

    pub fn with_value_constraint(mut self, constraint: ValueConstraint) -> Self {
        self.value_constraints.push(constraint);
        self
    }

    pub fn with_value_projection(mut self, projection: ValueProjection) -> Self {
        self.value_projection = Some(projection);
        self
    }
}

/// A semantic view of an operand, never a replacement for execution argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueProjection {
    Identity,
    /// Decode a top-level string from an opaque file-or-TOML operand.
    TomlString {
        key: String,
    },
    PrefixBefore {
        delimiter: String,
        if_absent: ProjectionAbsentPolicy,
    },
    KeyValue {
        separator: String,
        key: String,
    },
}

/// A tool-owned operand grammar. Original argv and scalar projections are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredProjection {
    pub separator: Option<String>,
    /// Stop after the first matching operand (including disabled or unknown values).
    pub first_match_only: bool,
    pub branches: Vec<StructuredProjectionBranch>,
    pub fallback: Option<StructuredProjectionTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredProjectionBranch {
    pub matcher: StructuredProjectionMatcher,
    pub target: Option<StructuredProjectionTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuredProjectionMatcher {
    Literal(String),
    /// Matched prefixes are consumed before emitting the semantic value.
    Prefix(String),
    /// A tool-owned `keyword value` / `keyword=value` operand grammar.
    KeywordValue {
        keyword: String,
        case_insensitive: bool,
        allow_quoted_keyword: bool,
        disabled_values: Vec<String>,
        /// Tool substitutions are unknown, not literal shell syntax.
        unresolved_markers: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredProjectionTarget {
    pub name: SlotName,
    pub semantic: SemanticType,
    /// Prefer the first present source slot, including an unresolved value.
    /// Empty means use this operand's matched value.
    pub sources: Vec<SlotName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProjectionAbsentPolicy {
    #[default]
    Original,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionUnknownReason {
    DynamicArgument,
    MissingDelimiter,
    EmptyValue,
    InvalidPayload,
    PayloadBudgetExceeded,
    UnknownPayloadContext,
    PayloadUnavailable,
}

/// Opt-in decoding of data protocols, never executable shell payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    CodexApplyPatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadInputSource {
    Slot(SlotName),
    Stdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadProjection {
    pub format: PayloadFormat,
    pub source: PayloadInputSource,
    pub reads: SlotName,
    pub writes: SlotName,
    pub deletes: SlotName,
    pub max_bytes: usize,
    pub max_operations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticValueResolution {
    Known(String),
    Unknown(ProjectionUnknownReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedSemanticValue {
    /// Index into the untouched BoundParameter::values; retains spans,
    /// binding source and materialization provenance without copying them.
    pub source_index: usize,
    pub resolution: SemanticValueResolution,
}

#[derive(Debug, Clone, Copy)]
pub enum SemanticValueRef<'a> {
    Original(&'a BoundValue),
    Projected {
        source: &'a BoundValue,
        value: &'a ProjectedSemanticValue,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImplicitInputSource {
    StdinPayload,
    StdinData,
    InteractiveSession,
    DispatchOutput,
    InheritedEnvironment,
}

impl ImplicitInputSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StdinPayload => "stdin_payload",
            Self::StdinData => "stdin_data",
            Self::InteractiveSession => "interactive_session",
            Self::DispatchOutput => "dispatch_output",
            Self::InheritedEnvironment => "inherited_environment",
        }
    }

    pub fn to_caushell_types_implicit_input_source(self) -> caushell_types::ImplicitInputSource {
        match self {
            Self::StdinPayload => caushell_types::ImplicitInputSource::StdinPayload,
            Self::StdinData => caushell_types::ImplicitInputSource::StdinData,
            Self::InteractiveSession => caushell_types::ImplicitInputSource::InteractiveSession,
            Self::DispatchOutput => caushell_types::ImplicitInputSource::DispatchOutput,
            Self::InheritedEnvironment => caushell_types::ImplicitInputSource::InheritedEnvironment,
        }
    }

    pub fn from_caushell_types_implicit_input_source(
        source: caushell_types::ImplicitInputSource,
    ) -> Self {
        match source {
            caushell_types::ImplicitInputSource::StdinPayload => Self::StdinPayload,
            caushell_types::ImplicitInputSource::StdinData => Self::StdinData,
            caushell_types::ImplicitInputSource::InteractiveSession => Self::InteractiveSession,
            caushell_types::ImplicitInputSource::DispatchOutput => Self::DispatchOutput,
            caushell_types::ImplicitInputSource::InheritedEnvironment => Self::InheritedEnvironment,
        }
    }

    pub fn to_runtime_input_source(self) -> Option<caushell_types::RuntimeInputSource> {
        match self {
            Self::StdinPayload => Some(caushell_types::RuntimeInputSource::StdinPayload),
            Self::StdinData => Some(caushell_types::RuntimeInputSource::StdinData),
            Self::InteractiveSession => {
                Some(caushell_types::RuntimeInputSource::InteractiveSession)
            }
            Self::DispatchOutput => None,
            Self::InheritedEnvironment => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplicitInput {
    pub source: ImplicitInputSource,
    pub semantic: SemanticType,
    pub extensions: ExtensionMap,
}

impl ImplicitInput {
    pub fn new(source: ImplicitInputSource, semantic: SemanticType) -> Self {
        Self {
            source,
            semantic,
            extensions: ExtensionMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    pub id: FormId,
    pub selector: SelectorExpr,
    pub remaining_selector: SelectorExpr,
    pub parameters: Vec<Parameter>,
    pub payload_projections: Vec<PayloadProjection>,
    pub implicit_inputs: Vec<ImplicitInput>,
    pub effects: Vec<Effect>,
    pub stream_contract: Option<StreamContract>,
    pub stdout_records: Option<StdoutRecordContract>,
    pub stdout_scalar: Option<StdoutScalarShape>,
    pub extensions: ExtensionMap,
}

impl Form {
    pub fn new(id: &str) -> Self {
        Self {
            id: FormId::new(id),
            selector: SelectorExpr::new(),
            remaining_selector: SelectorExpr::new(),
            parameters: Vec::new(),
            payload_projections: Vec::new(),
            implicit_inputs: Vec::new(),
            effects: Vec::new(),
            stream_contract: None,
            stdout_records: None,
            stdout_scalar: None,
            extensions: ExtensionMap::new(),
        }
    }

    pub fn with_selector(mut self, selector: SelectorExpr) -> Self {
        self.selector = selector;
        self
    }

    pub fn with_remaining_selector(mut self, selector: SelectorExpr) -> Self {
        self.remaining_selector = selector;
        self
    }

    pub fn with_selector_predicate(mut self, predicate: SelectorPredicate) -> Self {
        match &mut self.selector {
            SelectorExpr::All(items) => items.push(SelectorExpr::Predicate(predicate)),
            _ => panic!("with_selector_predicate is only supported on SelectorExpr::All"),
        }
        self
    }

    pub fn with_remaining_selector_predicate(mut self, predicate: SelectorPredicate) -> Self {
        match &mut self.remaining_selector {
            SelectorExpr::All(items) => items.push(SelectorExpr::Predicate(predicate)),
            _ => panic!("with_remaining_selector_predicate is only supported on SelectorExpr::All"),
        }
        self
    }

    pub fn with_parameter(mut self, parameter: Parameter) -> Self {
        self.parameters.push(parameter);
        self
    }

    pub fn with_implicit_input(mut self, input: ImplicitInput) -> Self {
        self.implicit_inputs.push(input);
        self
    }

    pub fn with_effect(mut self, effect: Effect) -> Self {
        self.effects.push(effect);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModifierMatcher {
    AnyFlag(Vec<FlagName>),
    AllFlags(Vec<FlagName>),
}

impl Default for ModifierMatcher {
    fn default() -> Self {
        Self::AnyFlag(Vec::new())
    }
}

impl ModifierMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_flag_name(mut self, flag_name: &str) -> Self {
        match &mut self {
            Self::AnyFlag(flags) | Self::AllFlags(flags) => flags.push(FlagName::new(flag_name)),
        }
        self
    }

    pub fn flag_names(&self) -> &[FlagName] {
        match self {
            Self::AnyFlag(flags) | Self::AllFlags(flags) => flags.as_slice(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModifierConstraint {
    MutuallyExclusiveWith(ModifierId),
    RequiresModifier(ModifierId),
    RequiresFlag(FlagName),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectKind {
    ReadPath,
    WritePath,
    DeletePath,
    MovePath,
    ChangeMode,
    ChangeOwner,
    ChangeGroup,
    MetadataMutation,
    TargetPath,
    LoadConfig,
    ExecutePayload,
    SourceScriptIntoCurrentShell,
    SetCurrentWorkingDirectory,
    /// Changes the launched process and its descendants, never the caller shell.
    SetExecutionWorkingDirectory,
    ExecuteRemoteCommand,
    ExecuteHook,
    ExecuteConfigDefinedTask,
    DispatchCommand,
    ConsumeStdin,
    BindVariableFromRuntimeInput,
    /// Terminates the enclosing shell frame, not an arbitrary process.
    TerminateCurrentShell,
    /// Alters the enclosing shell's job management, without sending a signal.
    ShellJobOperation,
    PrivilegeModifier,
    NetworkEndpoint,
    ListenNetwork,
    TransformData,
    ImportPackage,
    ExecuteImportedPackageLogic,
    LoadInProcessCode,
    OpenInteractiveEscapeSurface,
    ControlProcess,
    RepositoryOperation,
    DatabaseOperation,
    TerminalSessionOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveEscapeSurface {
    pub kind: InteractiveEscapeSurfaceKind,
    pub requires_tty: bool,
    pub capabilities: Vec<InteractiveEscapeCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchCommandSource {
    Slot(SlotName),
    Literal(String),
    /// Each semantic value is a separate whitespace-delimited argv, not shell source.
    WhitespaceArgv(SlotName),
    /// The tool, not the caller shell, interprets this already-decoded string.
    CommandString {
        slot: SlotName,
        syntax: DispatchStringSyntax,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchStringSyntax {
    PosixShell,
    GnuWordsplit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTarget {
    /// Typed registry namespace; never executable-name fallback.
    pub module_runtime: Option<String>,
    pub command: DispatchCommandSource,
    /// Fixed argv data, e.g. the interpreter's `-m`; never shell source.
    pub argv_prefix: Vec<String>,
    pub argv: Vec<SlotName>,
    pub argv_suffix: Vec<String>,
    pub environment: Vec<SlotName>,
    pub clear_environment_when: Vec<ModifierId>,
    pub unset_environment: Vec<SlotName>,
    pub unset_environment_when: Vec<ConditionalEnvironmentUnset>,
    /// A file/configuration can replace child env values but its body is opaque.
    pub unknown_environment_when: Vec<ModifierId>,
    pub unknown_environment_from: Vec<EnvironmentValueSource>,
    /// Tool-generated values override inherited bindings, but only these names.
    pub unknown_environment_names: Vec<String>,
    pub stdin_from_parent: bool,
    /// Opaque tool-produced input; never borrow the caller's pipeline contents.
    pub stdin_from_tool: bool,
    /// Opt-in child stdout contribution; dispatch alone does not imply data flow.
    pub stdout_to_parent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalEnvironmentUnset {
    pub modifier: ModifierId,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolConventionPathTarget {
    pub path: String,
    pub convention: String,
    pub purpose: Option<PathPurpose>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedPathSource {
    Slot(SlotName),
    ToolConventionRoot { convention: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPathTarget {
    pub source: DerivedPathSource,
    pub root: Option<DerivedPathSource>,
    pub rule: DerivedPathRule,
    pub purpose: Option<PathPurpose>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationScopeTarget {
    RepositoryWorktree {
        root: Option<SlotName>,
        path_set: RepositoryWorktreePathSet,
        subtree: Option<SlotName>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectTarget {
    NetworkListener(NetworkListenerTarget),
    ConfiguredPath(ConfiguredPathTarget),
    Slot(SlotName),
    /// A statically declared shell-variable destination, not a path or argv slot.
    VariableName(String),
    ToolConventionPath(ToolConventionPathTarget),
    DerivedPath(DerivedPathTarget),
    MutationScope(MutationScopeTarget),
    ImplicitInput(ImplicitInputSource),
    Dispatch(DispatchTarget),
    None,
}

/// Ordered sources use the first applicable slot, and its last applicable argv
/// value. Raw arguments and their ownership/provenance remain unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPathSource {
    pub slot: SlotName,
    pub projection: ValueProjection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPathAnchor {
    pub slot: SlotName,
    pub expand_environment: bool,
    pub fallback_parent_slot: Option<SlotName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfiguredPathMissing {
    #[default]
    Skip,
    Unknown,
    IncidentalCache,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPathTarget {
    pub sources: Vec<ConfiguredPathSource>,
    pub environment: Option<EnvironmentValueSource>,
    pub relative_to: Option<ConfiguredPathAnchor>,
    /// Relative paths need a discovered root unavailable to static analysis.
    pub unresolved_relative_base: bool,
    pub expand_environment: bool,
    pub expand_user: bool,
    pub missing: ConfiguredPathMissing,
    pub default_value: Option<String>,
    /// Applicable only after configured sources are proven absent/unset.
    pub fallback_parent_slots: Vec<SlotName>,
    pub purpose: Option<PathPurpose>,
}

/// A tool-level default, not shell expansion. Empty-value handling is declared
/// explicitly because CLI libraries differ on whether an empty env var is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentValueSource {
    pub name: String,
    pub empty_is_unset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredScalar {
    pub slot: SlotName,
    pub environment: Option<EnvironmentValueSource>,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkListenerTarget {
    pub host: ConfiguredScalar,
    pub port: Option<ConfiguredScalar>,
    pub unix_socket: Option<ConfiguredScalar>,
    pub inherited_fd: Option<ConfiguredScalar>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatastrophicSemanticClass {
    DeletePath,
    RawWriteTarget,
    FormatTarget,
    FilesystemSignatureWipeTarget,
    PartitionTableMutationTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRiskSemanticClass {
    MoveSourcePath,
    PathContentOverwriteTarget,
    PartitionLayoutMutationTarget,
    PartitionTableStateMutationTarget,
    PartitionTableSessionTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CatastrophicEffectMetadata {
    pub semantic_class: Option<CatastrophicSemanticClass>,
    pub required_modifiers: Vec<ModifierId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostRiskEffectMetadata {
    pub semantic_class: Option<HostRiskSemanticClass>,
    pub required_modifiers: Vec<ModifierId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub kind: EffectKind,
    pub target: EffectTarget,
    pub path_access: Option<PathAccessKind>,
    pub interactive_escape_surface: Option<InteractiveEscapeSurface>,
    pub catastrophic: CatastrophicEffectMetadata,
    pub host_risk: HostRiskEffectMetadata,
    pub repository_operation: Option<caushell_types::RepositoryOperationKind>,
    pub database_operation: Option<caushell_types::DatabaseOperationKind>,
    pub terminal_session_operation: Option<caushell_types::TerminalSessionOperationKind>,
    pub shell_job_operation: Option<caushell_types::ShellJobOperationKind>,
    pub extensions: ExtensionMap,
}

impl Effect {
    pub fn new(kind: EffectKind) -> Self {
        Self {
            kind,
            target: EffectTarget::None,
            path_access: None,
            interactive_escape_surface: None,
            catastrophic: CatastrophicEffectMetadata::default(),
            host_risk: HostRiskEffectMetadata::default(),
            repository_operation: None,
            database_operation: None,
            terminal_session_operation: None,
            shell_job_operation: None,
            extensions: ExtensionMap::new(),
        }
    }

    pub fn for_slot(mut self, slot: &str) -> Self {
        self.target = EffectTarget::Slot(SlotName::new(slot));
        self
    }

    pub fn with_interactive_escape_surface(mut self, surface: InteractiveEscapeSurface) -> Self {
        self.interactive_escape_surface = Some(surface);
        self
    }
}

/// How a path is accessed, not a safety classification or a path whitelist.
/// Omitted metadata keeps the existing filesystem namespace semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathAccessKind {
    ContentOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modifier {
    pub id: ModifierId,
    pub matcher: ModifierMatcher,
    pub ends_option_scope: bool,
    pub parameters: Vec<Parameter>,
    pub effects: Vec<Effect>,
    pub constraints: Vec<ModifierConstraint>,
    pub extensions: ExtensionMap,
}

impl Modifier {
    pub fn new(id: &str) -> Self {
        Self {
            id: ModifierId::new(id),
            matcher: ModifierMatcher::new(),
            ends_option_scope: false,
            parameters: Vec::new(),
            effects: Vec::new(),
            constraints: Vec::new(),
            extensions: ExtensionMap::new(),
        }
    }

    pub fn with_matcher(mut self, matcher: ModifierMatcher) -> Self {
        self.matcher = matcher;
        self
    }

    pub fn with_flag_name(mut self, flag_name: &str) -> Self {
        self.matcher = self.matcher.with_flag_name(flag_name);
        self
    }

    pub fn with_parameter(mut self, parameter: Parameter) -> Self {
        self.parameters.push(parameter);
        self
    }

    pub fn with_effect(mut self, effect: Effect) -> Self {
        self.effects.push(effect);
        self
    }

    pub fn with_constraint(mut self, constraint: ModifierConstraint) -> Self {
        self.constraints.push(constraint);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultSubcommandBehavior {
    RejectUnknown,
    ResidualUnknownSubcommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubcommandNode {
    pub name: String,
    pub aliases: Vec<String>,
    pub forms: Vec<Form>,
    pub modifiers: Vec<Modifier>,
    pub option_scope: OptionScopePolicy,
    /// Effective policy after declarative inheritance is normalized.
    pub option_matching: OptionMatchingPolicy,
    pub children: Vec<SubcommandNode>,
    pub default_behavior: Option<DefaultSubcommandBehavior>,
    pub extensions: ExtensionMap,
}

/// Where this invocation's options may occur. Positional form parameters
/// still describe the whole argv, including a dispatched command's tail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OptionScopePolicy {
    #[default]
    AllArguments,
    /// Parse declared options and their operands, then stop at the first
    /// non-option or an option terminator. Never inspect the child argv.
    LeadingOptions,
    /// Parse declared options even after non-option data, up to the real
    /// terminator. Preserve original argv ordering and argument ownership.
    PermutedOptions,
}

/// How option names are recognized, independent of where options may occur.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OptionMatchingPolicy {
    /// Preserve the existing short-cluster and attached-operand behaviour.
    #[default]
    ShortClusters,
    /// Match complete declared names; long inline operands remain supported.
    /// Single-dash words are neither split nor guessed as attached operands.
    ExactNames,
}

/// Opt-in CLI grammar, applied after shell argv materialization. This never
/// changes Bash tokenization, argv text, or another command's option grammar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OptionPrefixPolicy {
    #[default]
    DashOnly,
    /// Both signs introduce options; `--` and `++` terminate them.
    DashAndPlus,
}

impl OptionPrefixPolicy {
    pub(crate) fn is_option(self, value: &str) -> bool {
        value.len() > 1
            && (value.starts_with('-') || (self == Self::DashAndPlus && value.starts_with('+')))
    }

    pub(crate) fn is_terminator(self, value: &str) -> bool {
        value == "--" || (self == Self::DashAndPlus && value == "++")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubcommandTree {
    pub roots: Vec<SubcommandNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidualKind {
    ParseGap,
    DynamicExpansion,
    AmbiguousBinding,
    UnknownSubcommand,
    UnmodeledModifier,
    UnboundControlSurface,
    UnboundPayload,
    UnboundPath,
    UnboundData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidualSurface {
    Control,
    Payload,
    Path,
    Data,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Residual {
    pub kind: ResidualKind,
    pub surface: ResidualSurface,
    pub reason: String,
    pub slot: Option<SlotName>,
}

impl Residual {
    pub fn new(kind: ResidualKind, surface: ResidualSurface, reason: impl Into<String>) -> Self {
        Self {
            kind,
            surface,
            reason: reason.into(),
            slot: None,
        }
    }

    pub fn for_slot(mut self, slot: &str) -> Self {
        self.slot = Some(SlotName::new(slot));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionalBindingSource {
    NextPositional,
    NextPositionalAfterDashDash,
    PositionalAt(usize),
    RemainingPositionals,
    RemainingPositionalsBeforeLast,
    LeadingPositionals,
    MatchingPositionals,
    LastPositional,
    LastPositionalBeforeLast,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentBindingSource {
    FollowingFlag {
        flag_name: FlagName,
        flag_span: SourceSpan,
    },
    MatchedModifierFlag {
        modifier_id: ModifierId,
        flag_name: FlagName,
        flag_span: SourceSpan,
    },
    ArgumentPrefix {
        prefix: String,
    },
    Positional {
        kind: PositionalBindingSource,
    },
    RemainingArg,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundValue {
    Argument {
        text: String,
        quoted: bool,
        node_kind: String,
        span: SourceSpan,
        binding_source: ArgumentBindingSource,
        materialization: BoundArgumentMaterialization,
    },
    ImplicitInput {
        source: ImplicitInputSource,
        domain: Option<caushell_types::RuntimeArgumentDomain>,
    },
}

impl BoundValue {
    pub fn argument(
        text: impl Into<String>,
        quoted: bool,
        span: SourceSpan,
        binding_source: ArgumentBindingSource,
    ) -> Self {
        let node_kind = if quoted { "string" } else { "word" };
        Self::argument_with_node_kind(text, quoted, node_kind, span, binding_source)
    }

    pub fn argument_with_node_kind(
        text: impl Into<String>,
        quoted: bool,
        node_kind: impl Into<String>,
        span: SourceSpan,
        binding_source: ArgumentBindingSource,
    ) -> Self {
        Self::Argument {
            text: text.into(),
            quoted,
            node_kind: node_kind.into(),
            span,
            binding_source,
            materialization: BoundArgumentMaterialization::Literal,
        }
    }

    pub fn with_materialization(self, materialization: BoundArgumentMaterialization) -> Self {
        match self {
            Self::Argument {
                text,
                quoted,
                node_kind,
                span,
                binding_source,
                ..
            } => Self::Argument {
                text,
                quoted,
                node_kind,
                span,
                binding_source,
                materialization,
            },
            other => other,
        }
    }

    pub fn implicit_input(source: ImplicitInputSource) -> Self {
        Self::ImplicitInput {
            source,
            domain: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundParameter {
    pub name: SlotName,
    pub semantic: SemanticType,
    pub values: Vec<BoundValue>,
    pub value_projection: Option<ValueProjection>,
    /// None is the legacy identity view, with no allocation. Some(empty)
    /// means all operands were proven inapplicable (not unresolved).
    pub projected_values: Option<Vec<ProjectedSemanticValue>>,
    pub structured_projection: Option<StructuredProjection>,
    /// Virtual semantic slot; its source values must not be reinterpreted as shell text.
    pub structured_source: Option<SlotName>,
    /// Protocol-decoded data must not undergo a second shell expansion.
    pub payload_generated: bool,
}

impl BoundParameter {
    pub fn new(name: SlotName, semantic: SemanticType) -> Self {
        Self {
            name,
            semantic,
            values: Vec::new(),
            value_projection: None,
            projected_values: None,
            structured_projection: None,
            structured_source: None,
            payload_generated: false,
        }
    }

    pub fn with_value(mut self, value: BoundValue) -> Self {
        self.values.push(value);
        if self.value_projection.is_some() {
            crate::refresh_parameter_semantic_values(&mut self);
        }
        self
    }

    pub fn semantic_values(&self) -> impl Iterator<Item = SemanticValueRef<'_>> {
        self.projected_values
            .iter()
            .flatten()
            .map(|value| SemanticValueRef::Projected {
                source: &self.values[value.source_index],
                value,
            })
            .chain(
                self.values
                    .iter()
                    .filter(|_| self.projected_values.is_none())
                    .map(SemanticValueRef::Original),
            )
    }

    pub fn semantic_values_are_inapplicable(&self) -> bool {
        self.projected_values.as_ref().is_some_and(Vec::is_empty)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundImplicitInput {
    pub source: ImplicitInputSource,
    pub semantic: SemanticType,
}

impl BoundImplicitInput {
    pub fn new(source: ImplicitInputSource, semantic: SemanticType) -> Self {
        Self { source, semantic }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundInvocation {
    pub command_name: CommandName,
    pub subcommand_path: Vec<String>,
    pub form_id: FormId,
    /// Retained after form selection for command-independent stream projection.
    pub stream_contract: Option<StreamContract>,
    pub stdout_records: Option<StdoutRecordContract>,
    pub stdout_scalar: Option<StdoutScalarShape>,
    pub bound_parameters: Vec<BoundParameter>,
    pub argument_regions: Vec<crate::BoundArgumentRegion>,
    pub payload_projections: Vec<PayloadProjection>,
    pub bound_implicit_inputs: Vec<BoundImplicitInput>,
    pub applied_modifiers: Vec<ModifierId>,
    pub effects: Vec<Effect>,
    pub residuals: Vec<Residual>,
    /// A declared operation may have additional, unmodeled semantics.
    pub operation_semantics_unresolved: bool,
}

impl BoundInvocation {
    pub fn new(command_name: CommandName, form_id: FormId) -> Self {
        Self {
            command_name,
            subcommand_path: Vec::new(),
            form_id,
            stream_contract: None,
            stdout_records: None,
            stdout_scalar: None,
            bound_parameters: Vec::new(),
            argument_regions: Vec::new(),
            payload_projections: Vec::new(),
            bound_implicit_inputs: Vec::new(),
            applied_modifiers: Vec::new(),
            effects: Vec::new(),
            residuals: Vec::new(),
            operation_semantics_unresolved: false,
        }
    }

    pub fn with_bound_parameter(mut self, bound_parameter: BoundParameter) -> Self {
        self.bound_parameters.push(bound_parameter);
        self
    }

    pub fn with_subcommand_path(mut self, path: Vec<String>) -> Self {
        self.subcommand_path = path;
        self
    }

    pub fn with_bound_implicit_input(mut self, bound_implicit_input: BoundImplicitInput) -> Self {
        self.bound_implicit_inputs.push(bound_implicit_input);
        self
    }

    pub fn with_modifier(mut self, modifier_id: ModifierId) -> Self {
        self.applied_modifiers.push(modifier_id);
        self
    }

    pub fn with_effect(mut self, effect: Effect) -> Self {
        self.effects.push(effect);
        self
    }

    pub fn with_residual(mut self, residual: Residual) -> Self {
        self.residuals.push(residual);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandProfile {
    pub identity: CommandIdentity,
    pub trust: ProfileTrustMetadata,
    pub platform: PlatformConstraints,
    pub argument_files: Vec<ArgumentFileRule>,
    pub argument_regions: Vec<ArgumentRegion>,
    /// Opt-in finite outer control vocabulary. Unknown dash words are invalid
    /// in the tool, not new actions. Valid but unmodeled controls stay opaque.
    pub argument_control_vocabulary: Option<ArgumentControlVocabulary>,
    /// Declared uncertainty effects, retained when no complete form can bind.
    pub selection_failure_effects: Vec<Effect>,
    /// Opt in to operation uncertainty for failed selection or binding residuals.
    /// The action is supplied by ResolvePolicy, not by the Profile.
    pub opaque_on_unresolved: bool,
    pub forms: Vec<Form>,
    pub modifiers: Vec<Modifier>,
    pub option_scope: OptionScopePolicy,
    pub option_matching: OptionMatchingPolicy,
    pub option_prefixes: OptionPrefixPolicy,
    pub subcommands: Option<SubcommandTree>,
    pub extensions: ExtensionMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentRegion {
    pub id: String,
    pub start_flags: Vec<String>,
    pub terminators: Vec<ArgumentRegionTerminator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentRegionTerminator {
    pub value: String,
    pub preceding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentControlVocabulary {
    pub unmodeled_words: Vec<String>,
    pub unmodeled_short_clusters: Vec<String>,
    /// Recognized controls after which new positional words are invalid.
    pub positional_boundary_words: Vec<String>,
}

impl CommandProfile {
    pub fn new(name: &str) -> Self {
        Self {
            identity: CommandIdentity::new(name),
            trust: ProfileTrustMetadata::default(),
            platform: PlatformConstraints::default(),
            argument_files: Vec::new(),
            argument_regions: Vec::new(),
            argument_control_vocabulary: None,
            selection_failure_effects: Vec::new(),
            opaque_on_unresolved: false,
            forms: Vec::new(),
            modifiers: Vec::new(),
            option_scope: OptionScopePolicy::default(),
            option_matching: OptionMatchingPolicy::default(),
            option_prefixes: OptionPrefixPolicy::default(),
            subcommands: None,
            extensions: ExtensionMap::new(),
        }
    }

    pub fn alias(mut self, name: &str) -> Self {
        self.identity.aliases.push(CommandName::new(name));
        self
    }

    pub fn with_form(mut self, form: Form) -> Self {
        self.forms.push(form);
        self
    }

    pub fn with_modifier(mut self, modifier: Modifier) -> Self {
        self.modifiers.push(modifier);
        self
    }

    pub fn with_option_scope(mut self, policy: OptionScopePolicy) -> Self {
        self.option_scope = policy;
        self
    }

    pub fn with_option_matching(mut self, policy: OptionMatchingPolicy) -> Self {
        self.option_matching = policy;
        self
    }

    pub fn with_option_prefixes(mut self, policy: OptionPrefixPolicy) -> Self {
        self.option_prefixes = policy;
        self
    }

    pub fn primary_name(&self) -> &str {
        self.identity.canonical_name.as_str()
    }

    pub fn matches_name(&self, name: &str) -> bool {
        if self.identity.module_only {
            return false;
        }
        self.identity.canonical_name.as_str() == name
            || self
                .identity
                .aliases
                .iter()
                .any(|candidate| candidate.as_str() == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentFileRule {
    pub prefix: String,
    /// Unknown targets: never reinterpret a response file as shell code.
    pub possible_effects: Vec<EffectKind>,
}

#[cfg(test)]
mod tests {
    use super::{
        ArgumentBindingSource, BoundImplicitInput, BoundInvocation, BoundParameter, BoundValue,
        CommandName, CommandProfile, CommandRefSemantic, DispatchKind, Effect, EffectKind,
        FlagName, Form, FormId, ImplicitInputSource, Modifier, ModifierId, Parameter, PathPurpose,
        PathRole, PathSemantic, PayloadLanguage, PayloadSemantic, PayloadSource,
        PositionalBindingSource, Residual, ResidualKind, ResidualSurface, SelectorPredicate,
        SemanticType, SlotName, StructuredValueContext, StructuredValueSemantic,
    };
    use caushell_parse::SourceSpan;

    fn empty_span() -> SourceSpan {
        SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_row: 0,
            start_column: 0,
            end_row: 0,
            end_column: 0,
        }
    }

    #[test]
    fn command_profile_matches_primary_name_and_alias() {
        let profile = CommandProfile::new("bash").alias("sh-compatible");

        assert!(profile.matches_name("bash"));
        assert!(profile.matches_name("sh-compatible"));
        assert!(!profile.matches_name("dash"));
    }

    #[test]
    fn form_can_hold_selector_and_typed_parameters() {
        let form = Form::new("script_file")
            .with_selector_predicate(SelectorPredicate::LacksFlag(FlagName::new("-c")))
            .with_selector_predicate(SelectorPredicate::LacksFlag(FlagName::new("-s")))
            .with_selector_predicate(SelectorPredicate::HasPositionalAt(0))
            .with_remaining_selector_predicate(SelectorPredicate::NoPositionalArgs)
            .with_parameter(Parameter::new(
                "script_path",
                SemanticType::Path(PathSemantic {
                    role: PathRole::Read,
                    purpose: Some(PathPurpose::ScriptSource),
                }),
                super::BindingSpec::NextPositional,
            ));

        assert_eq!(form.id.as_str(), "script_file");
        match &form.selector {
            super::SelectorExpr::All(items) => assert_eq!(items.len(), 3),
            other => panic!("unexpected selector shape: {other:?}"),
        }
        match &form.remaining_selector {
            super::SelectorExpr::All(items) => assert_eq!(items.len(), 1),
            other => panic!("unexpected remaining selector shape: {other:?}"),
        }
        assert_eq!(form.parameters.len(), 1);
    }

    #[test]
    fn bound_invocation_collects_effects_and_residuals() {
        let invocation =
            BoundInvocation::new(CommandName::new("bash"), FormId::new("command_string"))
                .with_bound_parameter(
                    BoundParameter::new(
                        SlotName::new("payload"),
                        SemanticType::Payload(PayloadSemantic {
                            language: PayloadLanguage::Bash,
                            source: PayloadSource::InlineString,
                            recursive: true,
                        }),
                    )
                    .with_value(BoundValue::argument(
                        "echo ok",
                        true,
                        empty_span(),
                        ArgumentBindingSource::FollowingFlag {
                            flag_name: FlagName::new("-c"),
                            flag_span: empty_span(),
                        },
                    )),
                )
                .with_modifier(ModifierId::new("rcfile"))
                .with_effect(Effect::new(EffectKind::ExecutePayload).for_slot("payload"))
                .with_residual(
                    Residual::new(
                        ResidualKind::DynamicExpansion,
                        ResidualSurface::Payload,
                        "payload comes from session dynamic reference",
                    )
                    .for_slot("payload"),
                );

        assert_eq!(invocation.command_name.as_str(), "bash");
        assert_eq!(invocation.form_id.as_str(), "command_string");
        assert_eq!(invocation.bound_parameters.len(), 1);
        assert_eq!(invocation.applied_modifiers.len(), 1);
        assert_eq!(invocation.effects.len(), 1);
        assert_eq!(invocation.residuals.len(), 1);
    }

    #[test]
    fn bound_invocation_can_hold_bound_implicit_input() {
        let invocation = BoundInvocation::new(CommandName::new("bash"), FormId::new("interactive"))
            .with_bound_implicit_input(BoundImplicitInput::new(
                ImplicitInputSource::InteractiveSession,
                SemanticType::Payload(PayloadSemantic {
                    language: PayloadLanguage::Bash,
                    source: PayloadSource::Interactive,
                    recursive: true,
                }),
            ));

        assert_eq!(invocation.command_name.as_str(), "bash");
        assert_eq!(invocation.form_id.as_str(), "interactive");
        assert_eq!(invocation.bound_implicit_inputs.len(), 1);
    }

    #[test]
    fn bound_parameter_can_hold_implicit_input() {
        let parameter = BoundParameter::new(
            SlotName::new("payload"),
            SemanticType::Payload(PayloadSemantic {
                language: PayloadLanguage::Bash,
                source: PayloadSource::Interactive,
                recursive: true,
            }),
        )
        .with_value(BoundValue::implicit_input(
            ImplicitInputSource::InteractiveSession,
        ));

        assert_eq!(parameter.name.as_str(), "payload");
        assert_eq!(parameter.values.len(), 1);
    }

    #[test]
    fn bound_parameter_can_hold_argument_binding_source() {
        let parameter = BoundParameter::new(
            SlotName::new("script_path"),
            SemanticType::Path(PathSemantic {
                role: PathRole::Read,
                purpose: Some(PathPurpose::ScriptSource),
            }),
        )
        .with_value(BoundValue::argument(
            "./scripts/build.sh",
            false,
            empty_span(),
            ArgumentBindingSource::Positional {
                kind: PositionalBindingSource::NextPositional,
            },
        ));

        match &parameter.values[0] {
            BoundValue::Argument { binding_source, .. } => {
                assert_eq!(
                    binding_source,
                    &ArgumentBindingSource::Positional {
                        kind: PositionalBindingSource::NextPositional,
                    }
                );
            }
            other => panic!("expected argument bound value, got {other:?}"),
        }
    }

    #[test]
    fn modifier_can_hold_matcher_parameters_and_effects() {
        let modifier = Modifier::new("rcfile")
            .with_flag_name("--rcfile")
            .with_parameter(Parameter::new(
                "startup_config",
                SemanticType::Path(PathSemantic {
                    role: PathRole::Config,
                    purpose: Some(PathPurpose::StartupConfig),
                }),
                super::BindingSpec::FollowingMatchedFlag {
                    operand_mode: super::FlagOperandMode::NextArg,
                },
            ))
            .with_effect(Effect::new(EffectKind::LoadConfig).for_slot("startup_config"));

        assert_eq!(modifier.id.as_str(), "rcfile");
        assert_eq!(modifier.matcher.flag_names().len(), 1);
        assert_eq!(modifier.matcher.flag_names()[0].as_str(), "--rcfile");
        assert_eq!(modifier.parameters.len(), 1);
        assert_eq!(modifier.effects.len(), 1);
    }

    #[test]
    fn semantic_type_covers_command_ref_and_structured_value() {
        let command_ref = SemanticType::CommandRef(CommandRefSemantic {
            dispatch: DispatchKind::WrapperCommand,
        });
        let structured = SemanticType::StructuredValue(StructuredValueSemantic {
            context: StructuredValueContext::EnvAssignment,
        });

        match command_ref {
            SemanticType::CommandRef(semantic) => {
                assert_eq!(semantic.dispatch, DispatchKind::WrapperCommand);
            }
            other => panic!("unexpected semantic type: {other:?}"),
        }

        match structured {
            SemanticType::StructuredValue(semantic) => {
                assert_eq!(semantic.context, StructuredValueContext::EnvAssignment);
            }
            other => panic!("unexpected semantic type: {other:?}"),
        }
    }
}

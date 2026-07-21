use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawCommandProfile {
    pub dsl_version: String,
    pub kind: String,
    pub identity: RawCommandIdentity,
    pub trust: RawProfileTrustMetadata,
    pub platform: RawPlatformConstraints,
    pub forms: Vec<RawForm>,
    pub modifiers: Vec<RawModifier>,
    pub subcommands: Option<RawSubcommandTree>,
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawCommandIdentity {
    pub canonical_name: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawProfileTrustTier {
    TierA,
    TierB,
    #[default]
    TierC,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawProfileSourceKind {
    BuiltIn,
    User,
    ImportedLegacy,
    #[default]
    Generated,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawProfileTrustMetadata {
    pub tier: RawProfileTrustTier,
    pub source: RawProfileSourceKind,
    pub reviewed_by: Option<String>,
    pub review_notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawOsFamily {
    Posix,
    Linux,
    Macos,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawShellFamily {
    Bourne,
    Bash,
    Sh,
    Dash,
    Powershell,
    Cmd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawRuntimeFeature {
    InteractiveSession,
    StdinPayloadAvailable,
    PipelineInputAvailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawPlatformConstraints {
    pub os_families: Vec<RawOsFamily>,
    pub shell_families: Vec<RawShellFamily>,
    pub requires_features: Vec<RawRuntimeFeature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawForm {
    pub id: String,
    pub selector: RawSelectorExpr,
    pub remaining_selector: RawSelectorExpr,
    pub parameters: Vec<RawParameter>,
    pub implicit_inputs: Vec<RawImplicitInput>,
    pub effects: Vec<RawEffect>,
    pub stream_contract: Option<RawStreamContract>,
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawSelectorExpr {
    All {
        items: Vec<RawSelectorExpr>,
    },
    Any {
        items: Vec<RawSelectorExpr>,
    },
    Not {
        item: Box<RawSelectorExpr>,
    },
    HasFlag {
        flag: String,
    },
    HasFlagAtLeast {
        flag: String,
        count: usize,
    },
    LacksFlag {
        flag: String,
    },
    HasModifier {
        modifier: String,
    },
    HasModifierParameterMatching {
        modifier: String,
        parameter: String,
        matcher: RawValueMatcher,
    },
    HasPositionalAt {
        index: usize,
    },
    HasPositionalBeforeDashDashAt {
        index: usize,
    },
    HasPositionalAtMatching {
        index: usize,
        matcher: RawValueMatcher,
    },
    HasPositionalAtOrAfterMatching {
        index: usize,
        matcher: RawValueMatcher,
    },
    HasPositionalAfterLeadingMatcher {
        matcher: RawValueMatcher,
    },
    NoPositionalAfterLeadingMatcher {
        matcher: RawValueMatcher,
    },
    LastPositionalMatches {
        matcher: RawValueMatcher,
    },
    NoPositionalArgs,
    HasDashDash,
    NoDashDash,
    StdinPayloadAvailable,
    InteractiveSession,
    HasSubcommandPath {
        path: Vec<String>,
    },
    HasRuntimeFeature {
        feature: RawRuntimeFeature,
    },
}

impl Default for RawSelectorExpr {
    fn default() -> Self {
        Self::All { items: Vec::new() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawStreamInputMode {
    Ignored,
    DataOptional,
    DataRequired,
    PayloadOptional,
    PayloadRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawStreamOutputMode {
    Opaque,
    Data,
    CommandText,
    PathList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStreamContract {
    pub stdin_mode: RawStreamInputMode,
    pub stdout_mode: RawStreamOutputMode,
    pub stderr_mode: RawStreamOutputMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawModifier {
    pub id: String,
    pub matcher: RawModifierMatcher,
    pub parameters: Vec<RawParameter>,
    pub effects: Vec<RawEffect>,
    pub constraints: Vec<RawModifierConstraint>,
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawModifierMatcher {
    AnyFlag { flags: Vec<String> },
    AllFlags { flags: Vec<String> },
}

impl Default for RawModifierMatcher {
    fn default() -> Self {
        Self::AnyFlag { flags: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawModifierConstraint {
    MutuallyExclusiveWith { modifier: String },
    RequiresModifier { modifier: String },
    RequiresFlag { flag: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawParameter {
    pub name: String,
    pub semantic: RawSemanticType,
    pub binding: RawBindingSpec,
    #[serde(default)]
    pub cardinality: Option<RawCardinality>,
    #[serde(default)]
    pub value_constraints: Vec<RawValueConstraint>,
    #[serde(default)]
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawValueConstraint {
    ExcludeLiteral { value: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCardinality {
    RequiredOne,
    OptionalOne,
    RequiredMany,
    OptionalMany,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawFlagOperandMode {
    NextPositional,
    NextArg,
    SecondArg,
    InlineOnly,
    InlineOrShortAttached,
    #[serde(rename = "next_positional_after_dashdash")]
    NextPositionalAfterDashDash,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawBindingSpec {
    NextPositional,
    #[serde(rename = "next_positional_after_dashdash")]
    NextPositionalAfterDashDash,
    PositionalAt {
        index: usize,
    },
    RemainingPositionals,
    RemainingPositionalsAfterDashDash,
    RemainingPositionalsBeforeLast,
    RemainingArgs,
    ArgsUntilLiteral {
        terminator: String,
        #[serde(default)]
        include_terminator: bool,
    },
    LastPositional,
    LastPositionalBeforeLast,
    FollowingFlag {
        flag: String,
        operand_mode: RawFlagOperandMode,
    },
    FollowingMatchedFlag {
        operand_mode: RawFlagOperandMode,
    },
    ArgsWithPrefix {
        prefix: String,
    },
    LeadingPositionalsWhile {
        matcher: RawValueMatcher,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawValueMatcher {
    StructuredValueContext { context: RawStructuredValueContext },
    Literal { value: String },
    RegexPattern { pattern: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawImplicitInput {
    pub source: RawImplicitInputSource,
    pub semantic: RawSemanticType,
    #[serde(default)]
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawImplicitInputSource {
    StdinPayload,
    StdinData,
    InteractiveSession,
    InheritedEnvironment,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawSemanticType {
    PlainValue,
    Path {
        role: RawPathRole,
        purpose: Option<RawPathPurpose>,
    },
    Payload {
        language: RawPayloadLanguage,
        source: RawPayloadSource,
        recursive: bool,
    },
    CommandRef {
        dispatch: RawDispatchKind,
    },
    StructuredValue {
        context: RawStructuredValueContext,
    },
    Endpoint {
        endpoint_kind: RawEndpointKind,
        usage: RawEndpointUsage,
    },
    PackageLocator {
        manager: RawPackageManagerKind,
        locator_kinds: Vec<RawPackageLocatorKind>,
    },
    InProcessCodeLoad {
        load_kind: RawInProcessCodeLoadKind,
    },
    ProcessTarget {
        target_kind: RawProcessTargetKind,
        #[serde(default)]
        broad_match: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPathRole {
    Read,
    Write,
    MetadataMutation,
    Target,
    Config,
    CwdAnchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPathPurpose {
    GenericOperand,
    ScriptSource,
    InProcessCode,
    StartupConfig,
    ProjectConfig,
    ToolConfig,
    TaskConfig,
    WorkingDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPayloadLanguage {
    Bash,
    Sh,
    Dash,
    Python,
    Perl,
    Javascript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPayloadSource {
    InlineString,
    ScriptFileRef,
    Stdin,
    Interactive,
    DynamicReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawDispatchKind {
    CommandName,
    WrapperCommand,
    ShellPayload,
    InterpreterModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawStructuredValueContext {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawEndpointKind {
    Url,
    HostPort,
    SocketPath,
    RemoteSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawEndpointUsage {
    FetchSource,
    UploadTarget,
    ControlPlane,
    GenericEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPackageManagerKind {
    Pip,
    Apt,
    Conan,
    Npm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPackageLocatorKind {
    RegistryRef,
    LocalPath,
    DirectUrl,
    VcsUrl,
    RequirementFile,
    UnknownDynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawInProcessCodeLoadKind {
    ModuleName,
    Path,
    PluginName,
    LibraryPath,
    AgentPath,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawProcessTargetKind {
    Pid,
    ProcessName,
    ProcessPattern,
    JobSpec,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEffect {
    pub kind: RawEffectKind,
    pub target: RawEffectTarget,
    #[serde(default)]
    pub surface: Option<RawInteractiveEscapeSurface>,
    #[serde(default)]
    pub catastrophic: Option<RawCatastrophicEffectMetadata>,
    #[serde(default)]
    pub host_risk: Option<RawHostRiskEffectMetadata>,
    #[serde(default)]
    pub repository_operation: Option<RawRepositoryOperationKind>,
    #[serde(default)]
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawCatastrophicEffectMetadata {
    pub semantic_class: Option<RawCatastrophicSemanticClass>,
    pub required_modifiers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCatastrophicSemanticClass {
    DeletePath,
    RawWriteTarget,
    FormatTarget,
    FilesystemSignatureWipeTarget,
    PartitionTableMutationTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawHostRiskSemanticClass {
    MoveSourcePath,
    PartitionLayoutMutationTarget,
    PartitionTableStateMutationTarget,
    PartitionTableSessionTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawHostRiskEffectMetadata {
    pub semantic_class: Option<RawHostRiskSemanticClass>,
    pub required_modifiers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawRepositoryOperationKind {
    TrackedWorktreeDiscard,
    UntrackedWorktreeDelete,
    ForcedWorktreeSwitch,
    TrackedPathDelete,
    SavedStateDestroy,
    LocalRefDestroy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawEffectKind {
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
    ExecuteRemoteCommand,
    ExecuteHook,
    ExecuteConfigDefinedTask,
    DispatchCommand,
    ConsumeStdin,
    BindVariableFromRuntimeInput,
    PrivilegeModifier,
    NetworkEndpoint,
    TransformData,
    ImportPackage,
    ExecuteImportedPackageLogic,
    LoadInProcessCode,
    OpenInteractiveEscapeSurface,
    ControlProcess,
    RepositoryOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawInteractiveEscapeSurfaceKind {
    Pager,
    Editor,
    TerminalUi,
    LineEditor,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawInteractiveEscapeCapability {
    SpawnShell,
    RunCommand,
    LaunchExternalEditor,
    WriteBufferToPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInteractiveEscapeSurface {
    pub kind: RawInteractiveEscapeSurfaceKind,
    #[serde(default)]
    pub requires_tty: bool,
    #[serde(default)]
    pub capabilities: Vec<RawInteractiveEscapeCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawDerivedPathSource {
    Slot { name: String },
    ToolConventionRoot { convention: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawDerivedPathRule {
    AppendSuffix { suffix: String },
    StripSuffix { suffix: String },
    ReplaceSuffix { from: String, to: String },
    UrlBasename,
    ArchiveMembers,
    ChildUnder { relative_path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawRepositoryWorktreePathSet {
    Tracked,
    PatchSelectedTracked,
    RegisteredSubmoduleWorktrees,
    UntrackedOnly,
    IgnoredOnly,
    UntrackedAndIgnored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawMutationScopeKind {
    RepositoryWorktree,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawEffectTarget {
    Slot {
        name: String,
    },
    ToolConventionPath {
        path: String,
        convention: String,
        #[serde(default)]
        purpose: Option<RawPathPurpose>,
    },
    DerivedPath {
        source: RawDerivedPathSource,
        #[serde(default)]
        root: Option<RawDerivedPathSource>,
        rule: RawDerivedPathRule,
        #[serde(default)]
        purpose: Option<RawPathPurpose>,
    },
    MutationScope {
        scope_kind: RawMutationScopeKind,
        #[serde(default)]
        root: Option<String>,
        path_set: RawRepositoryWorktreePathSet,
        #[serde(default)]
        subtree: Option<String>,
    },
    ImplicitInput {
        source: RawImplicitInputSource,
    },
    Dispatch {
        command: String,
        #[serde(default)]
        argv: Vec<String>,
        #[serde(default)]
        environment: Vec<String>,
    },
    None,
}

impl Default for RawEffectTarget {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawSubcommandTree {
    pub roots: Vec<RawSubcommandNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawSubcommandNode {
    pub name: String,
    pub aliases: Vec<String>,
    pub forms: Vec<RawForm>,
    pub modifiers: Vec<RawModifier>,
    pub children: Vec<RawSubcommandNode>,
    pub default_behavior: Option<RawDefaultSubcommandBehavior>,
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawDefaultSubcommandBehavior {
    RejectUnknown,
    ResidualUnknownSubcommand,
}

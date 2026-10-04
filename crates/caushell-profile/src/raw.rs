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
    pub argument_files: Vec<RawArgumentFileRule>,
    pub selection_failure_effects: Vec<RawEffect>,
    pub opaque_on_unresolved: bool,
    pub forms: Vec<RawForm>,
    pub modifiers: Vec<RawModifier>,
    pub option_scope: RawOptionScopePolicy,
    pub option_matching: RawOptionMatchingPolicy,
    pub option_prefixes: RawOptionPrefixPolicy,
    pub subcommands: Option<RawSubcommandTree>,
    pub extensions: BTreeMap<String, JsonValue>,
}

/// A tool expands matching argv before parsing its ordinary options.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawArgumentFileRule {
    pub prefix: String,
    pub possible_effects: Vec<RawEffectKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawOptionScopePolicy {
    #[default]
    AllArguments,
    LeadingOptions,
    PermutedOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawOptionMatchingPolicy {
    #[default]
    ShortClusters,
    ExactNames,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawOptionPrefixPolicy {
    #[default]
    DashOnly,
    DashAndPlus,
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
    pub payload_projections: Vec<RawPayloadProjection>,
    pub implicit_inputs: Vec<RawImplicitInput>,
    pub effects: Vec<RawEffect>,
    pub stream_contract: Option<RawStreamContract>,
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPayloadFormat {
    CodexApplyPatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawPayloadInputSource {
    Slot { name: String },
    Stdin,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPayloadProjection {
    pub format: RawPayloadFormat,
    pub source: RawPayloadInputSource,
    pub reads: String,
    pub writes: String,
    pub deletes: String,
    #[serde(default = "default_payload_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_payload_max_operations")]
    pub max_operations: usize,
}

fn default_payload_max_bytes() -> usize {
    1024 * 1024
}
fn default_payload_max_operations() -> usize {
    4096
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
    NoArguments,
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
    pub value_projection: Option<RawValueProjection>,
    #[serde(default)]
    pub structured_projection: Option<RawStructuredProjection>,
    #[serde(default)]
    pub cardinality: Option<RawCardinality>,
    #[serde(default)]
    pub value_constraints: Vec<RawValueConstraint>,
    #[serde(default)]
    pub extensions: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawValueProjection {
    Identity,
    TomlString {
        key: String,
    },
    PrefixBefore {
        delimiter: String,
        #[serde(default)]
        if_absent: RawProjectionAbsentPolicy,
    },
    KeyValue {
        separator: String,
        key: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStructuredProjection {
    #[serde(default)]
    pub separator: Option<String>,
    pub branches: Vec<RawStructuredProjectionBranch>,
    #[serde(default)]
    pub fallback: Option<RawStructuredProjectionTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStructuredProjectionBranch {
    pub matcher: RawStructuredProjectionMatcher,
    #[serde(default)]
    pub target: Option<RawStructuredProjectionTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawStructuredProjectionMatcher {
    Literal { value: String },
    Prefix { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStructuredProjectionTarget {
    pub name: String,
    pub semantic: RawSemanticType,
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawProjectionAbsentPolicy {
    #[default]
    Original,
    Unknown,
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
    OptionalNextArg,
    SecondArg,
    InlineOnly,
    OptionalInlineOnly,
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
        #[serde(default)]
        before_dash_dash: bool,
    },
    LeadingPositionalsWhile {
        matcher: RawValueMatcher,
    },
    PositionalsMatching {
        matcher: RawValueMatcher,
    },
    LeadingPositionalsBeforeModifier {
        modifier: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawValueMatcher {
    StructuredValueContext { context: RawStructuredValueContext },
    Literal { value: String },
    AsciiCaseInsensitiveLiterals { values: Vec<String> },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawPayloadLanguage {
    Bash,
    Sh,
    Dash,
    Python,
    Perl,
    Javascript,
    SqliteCli,
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
    EmailAddress,
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
    Uv,
    Apt,
    Conan,
    Conda,
    Npm,
    Yum,
    Brew,
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
    pub database_operation: Option<caushell_types::DatabaseOperationKind>,
    #[serde(default)]
    pub terminal_session_operation: Option<caushell_types::TerminalSessionOperationKind>,
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
    PathContentOverwriteTarget,
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
    SetExecutionWorkingDirectory,
    ExecuteRemoteCommand,
    ExecuteHook,
    ExecuteConfigDefinedTask,
    DispatchCommand,
    ConsumeStdin,
    BindVariableFromRuntimeInput,
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
    SiblingFiles,
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawEffectTarget {
    NetworkListener {
        host: RawConfiguredScalar,
        #[serde(default)]
        port: Option<RawConfiguredScalar>,
        #[serde(default)]
        unix_socket: Option<RawConfiguredScalar>,
        #[serde(default)]
        inherited_fd: Option<RawConfiguredScalar>,
    },
    ConfiguredPath {
        sources: Vec<RawConfiguredPathSource>,
        #[serde(default)]
        environment: Option<RawEnvironmentValueSource>,
        #[serde(default)]
        relative_to: Option<RawConfiguredPathAnchor>,
        #[serde(default)]
        unresolved_relative_base: bool,
        #[serde(default)]
        expand_environment: bool,
        #[serde(default)]
        expand_user: bool,
        #[serde(default)]
        missing: RawConfiguredPathMissing,
        #[serde(default)]
        default_value: Option<String>,
        #[serde(default)]
        purpose: Option<RawPathPurpose>,
    },
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
        #[serde(default)]
        command: Option<String>,
        #[serde(default)]
        command_literal: Option<String>,
        #[serde(default)]
        command_whitespace_argv: Option<String>,
        #[serde(default)]
        argv_prefix: Vec<String>,
        #[serde(default)]
        argv: Vec<String>,
        #[serde(default)]
        environment: Vec<String>,
        #[serde(default)]
        clear_environment_when: Vec<String>,
        #[serde(default)]
        unset_environment: Vec<String>,
        #[serde(default)]
        unknown_environment_when: Vec<String>,
        #[serde(default)]
        unknown_environment_from: Vec<RawEnvironmentValueSource>,
        #[serde(default)]
        stdin_from_parent: bool,
        #[serde(default)]
        stdout_to_parent: bool,
    },
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEnvironmentValueSource {
    pub name: String,
    #[serde(default)]
    pub empty_is_unset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfiguredScalar {
    pub slot: String,
    #[serde(default)]
    pub environment: Option<RawEnvironmentValueSource>,
    #[serde(default)]
    pub default_value: Option<String>,
}

impl Default for RawEffectTarget {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfiguredPathSource {
    pub slot: String,
    pub projection: RawValueProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfiguredPathAnchor {
    pub slot: String,
    #[serde(default)]
    pub expand_environment: bool,
    #[serde(default)]
    pub fallback_parent_slot: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawConfiguredPathMissing {
    #[default]
    Skip,
    Unknown,
    IncidentalCache,
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
    pub option_scope: RawOptionScopePolicy,
    /// Omission inherits the enclosing command/node's matching policy.
    pub option_matching: Option<RawOptionMatchingPolicy>,
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

use caushell_types::ShellKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticKind {
    ErrorNode,
    MissingNode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_row: usize,
    pub start_column: usize,
    pub end_row: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDiagnostic {
    pub kind: DiagnosticKind,
    pub node_kind: String,
    pub text: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandTokenKind {
    Flag,
    Arg,
    DashDash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandToken {
    pub text: String,
    /// Present when this token stands for runtime data rather than literal shell text.
    pub implicit_input_source: Option<caushell_types::ImplicitInputSource>,
    pub runtime_argument_domain: Option<caushell_types::RuntimeArgumentDomain>,
    /// True when text is argv data and must not undergo shell expansion.
    pub runtime_data: bool,
    pub kind: CommandTokenKind,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
    pub command_substitutions: Vec<CommandSubstitutionFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFact {
    pub command_name: Option<String>,
    /// The executable has already been decoded as argv data, not shell source.
    pub command_name_runtime_data: bool,
    pub text: String,
    pub prefix_assignments: Vec<VariableAssignmentFact>,
    pub tokens: Vec<CommandToken>,
    pub in_pipeline: bool,
    pub pipeline_position: Option<PipelinePosition>,
    pub pipeline_span: Option<SourceSpan>,
    pub terminator: Option<StatementTerminator>,
    pub guarded: bool,
    /// Conditional within this shell frame; isolation alone is not conditional.
    pub conditional_execution: bool,
    /// Nearest subshell, pipeline branch or asynchronous frame, if any.
    pub shell_scope_span: Option<SourceSpan>,
    pub subshell_span: Option<SourceSpan>,
    pub control_flow_span: Option<SourceSpan>,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelinePosition {
    First,
    Middle,
    Last,
    Only,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementTerminator {
    Sequence,
    Background,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationCommandKind {
    Declare,
    Typeset,
    Export,
    Readonly,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentOperator {
    Assign,
    Append,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentValueFact {
    pub text: String,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
    pub command_substitutions: Vec<CommandSubstitutionFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableAssignmentFact {
    pub name: String,
    pub operator: AssignmentOperator,
    pub value: AssignmentValueFact,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationCommandFact {
    /// False for conditional, isolated, pipeline or background execution.
    pub unconditional_current_shell: bool,
    pub shell_scope_span: Option<SourceSpan>,
    pub conditional_execution: bool,
    pub kind: DeclarationCommandKind,
    pub options: Vec<String>,
    pub names: Vec<String>,
    pub assignments: Vec<VariableAssignmentFact>,
    pub text: String,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentCommandFact {
    pub unconditional_current_shell: bool,
    pub shell_scope_span: Option<SourceSpan>,
    pub conditional_execution: bool,
    pub assignments: Vec<VariableAssignmentFact>,
    pub text: String,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsetCommandFact {
    pub unconditional_current_shell: bool,
    pub shell_scope_span: Option<SourceSpan>,
    pub conditional_execution: bool,
    pub options: Vec<String>,
    pub names: Vec<String>,
    pub text: String,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDefinitionFact {
    pub shell_scope_span: Option<SourceSpan>,
    pub conditional_execution: bool,
    pub name: String,
    pub body_text: String,
    pub text: String,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectionKind {
    File,
    HereString,
    HereDoc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectionOperandFact {
    pub text: String,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
    pub command_substitutions: Vec<CommandSubstitutionFact>,
    pub expansion_unresolved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectionFact {
    pub kind: RedirectionKind,
    pub text: String,
    pub file_descriptor: Option<String>,
    pub operator: Option<String>,
    pub heredoc_start: Option<RedirectionOperandFact>,
    pub target: Option<RedirectionOperandFact>,
    pub content: Option<RedirectionOperandFact>,
    pub parent_command_name: Option<String>,
    pub parent_command_span: Option<SourceSpan>,
    pub shell_scope_span: Option<SourceSpan>,
    pub conditional_execution: bool,
    /// Shell statement that opens an unowned redirect, before its body runs.
    /// This is syntax/context metadata, not an external command invocation.
    pub opening_statement: Option<CommandFact>,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSubstitutionFact {
    pub text: String,
    pub body_text: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSubstitutionOperator {
    Input,
    Output,
}

impl ProcessSubstitutionOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSubstitutionFact {
    pub text: String,
    pub body_text: String,
    pub operator: ProcessSubstitutionOperator,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForLoopFact {
    pub variable: String,
    /// None is the implicit positional-parameter list, not an empty list.
    pub items: Option<Vec<CommandToken>>,
    pub span: SourceSpan,
    pub body_span: SourceSpan,
    pub shell_scope_span: Option<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellEvaluationKind {
    /// Expansion performed by the shell while opening a redirection, even
    /// when the invoked command never reads from that descriptor.
    RedirectionExpansion {
        redirection_index: usize,
        unresolved: bool,
    },
    ParameterAssignment {
        name: Option<String>,
        array_element: bool,
        if_null: bool,
    },
    ArrayElementAssignment {
        name: String,
        index: String,
    },
    Arithmetic,
    UnresolvedArithmetic,
    ArrayIndex {
        name: String,
    },
    UnsetOperand {
        functions_only: bool,
    },
    ArithmeticBuiltin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellEvaluationSite {
    pub kind: ShellEvaluationKind,
    pub input: AssignmentValueFact,
    pub top_level_span: SourceSpan,
    pub shell_scope_span: Option<SourceSpan>,
    pub numeric_locals: Vec<String>,
    pub numeric_scope_span: Option<SourceSpan>,
    pub conditional_execution: bool,
}

/// Grammar facts only; no arithmetic, substitution or variable evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArithmeticReference {
    ArithmeticExpansion(String),
    Optional(Vec<ArithmeticReference>),
    Variable(String),
    ExpandedWord {
        text: String,
        quoted: bool,
        node_kind: String,
    },
    Array {
        name: String,
        index: String,
        read_value: bool,
    },
    CommandSubstitution(CommandSubstitutionFact),
    Assignment {
        name: String,
        reads_previous: bool,
        value: Vec<ArithmeticReference>,
    },
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommandArtifact {
    pub raw_command: String,
    pub shell_kind: ShellKind,
    pub status: ParseStatus,
    pub commands: Vec<CommandFact>,
    pub declaration_commands: Vec<DeclarationCommandFact>,
    pub assignment_commands: Vec<AssignmentCommandFact>,
    pub for_loops: Vec<ForLoopFact>,
    pub unset_commands: Vec<UnsetCommandFact>,
    pub shell_evaluations: Vec<ShellEvaluationSite>,
    pub function_definitions: Vec<FunctionDefinitionFact>,
    pub redirections: Vec<RedirectionFact>,
    pub diagnostics: Vec<ParseDiagnostic>,
}

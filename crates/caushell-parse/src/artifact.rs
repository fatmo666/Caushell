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
    pub kind: CommandTokenKind,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
    pub command_substitutions: Vec<CommandSubstitutionFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFact {
    pub command_name: Option<String>,
    pub text: String,
    pub prefix_assignments: Vec<VariableAssignmentFact>,
    pub tokens: Vec<CommandToken>,
    pub in_pipeline: bool,
    pub pipeline_position: Option<PipelinePosition>,
    pub pipeline_span: Option<SourceSpan>,
    pub terminator: Option<StatementTerminator>,
    pub guarded: bool,
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
    pub assignments: Vec<VariableAssignmentFact>,
    pub text: String,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsetCommandFact {
    pub options: Vec<String>,
    pub names: Vec<String>,
    pub text: String,
    pub top_level_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDefinitionFact {
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
pub struct ParsedCommandArtifact {
    pub raw_command: String,
    pub shell_kind: ShellKind,
    pub status: ParseStatus,
    pub commands: Vec<CommandFact>,
    pub declaration_commands: Vec<DeclarationCommandFact>,
    pub assignment_commands: Vec<AssignmentCommandFact>,
    pub unset_commands: Vec<UnsetCommandFact>,
    pub function_definitions: Vec<FunctionDefinitionFact>,
    pub redirections: Vec<RedirectionFact>,
    pub diagnostics: Vec<ParseDiagnostic>,
}

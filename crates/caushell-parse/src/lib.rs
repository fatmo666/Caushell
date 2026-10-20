mod artifact;
mod backtick;
mod error;
mod parser;
mod syntax_compat;

pub use artifact::{
    ArithmeticReference, AssignmentCommandFact, AssignmentOperator, AssignmentValueFact,
    CommandFact, CommandSubstitutionFact, CommandToken, CommandTokenKind, DeclarationCommandFact,
    DeclarationCommandKind, DiagnosticKind, ForLoopFact, FunctionDefinitionFact, ParseDiagnostic,
    ParseStatus, ParsedCommandArtifact, PipelinePosition, ProcessSubstitutionFact,
    ProcessSubstitutionOperator, RedirectionFact, RedirectionKind, RedirectionOperandFact,
    ShellEvaluationKind, ShellEvaluationSite, SourceSpan, StatementTerminator, UnsetCommandFact,
    VariableAssignmentFact,
};
pub use error::ParseError;
pub use parser::{
    concatenated_argument_is_scalar, decode_static_shell_argument, parse_arithmetic_references,
    parse_command, parse_command_substitutions, parse_process_substitutions, static_array_values,
};

mod artifact;
mod backtick;
mod error;
mod parser;
mod syntax_compat;

pub use artifact::{
    AssignmentCommandFact, AssignmentOperator, AssignmentValueFact, CommandFact,
    CommandSubstitutionFact, CommandToken, CommandTokenKind, DeclarationCommandFact,
    DeclarationCommandKind, DiagnosticKind, FunctionDefinitionFact, ParseDiagnostic, ParseStatus,
    ParsedCommandArtifact, PipelinePosition, ProcessSubstitutionFact, ProcessSubstitutionOperator,
    RedirectionFact, RedirectionKind, RedirectionOperandFact, SourceSpan, StatementTerminator,
    UnsetCommandFact, VariableAssignmentFact,
};
pub use error::ParseError;
pub use parser::{
    decode_static_shell_argument, parse_command, parse_command_substitutions,
    parse_process_substitutions,
};

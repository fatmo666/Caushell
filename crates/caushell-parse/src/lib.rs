mod artifact;
mod error;
mod parser;

pub use artifact::{
    AssignmentCommandFact, AssignmentOperator, AssignmentValueFact, CommandFact,
    CommandSubstitutionFact, CommandToken, CommandTokenKind, DeclarationCommandFact,
    DeclarationCommandKind, DiagnosticKind, FunctionDefinitionFact, ParseDiagnostic, ParseStatus,
    ParsedCommandArtifact, PipelinePosition, ProcessSubstitutionFact, ProcessSubstitutionOperator,
    RedirectionFact, RedirectionKind, RedirectionOperandFact, SourceSpan, StatementTerminator,
    UnsetCommandFact, VariableAssignmentFact,
};
pub use error::ParseError;
pub use parser::{parse_command, parse_command_substitutions, parse_process_substitutions};

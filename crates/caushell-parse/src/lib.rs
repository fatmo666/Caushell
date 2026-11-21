mod artifact;
mod backtick;
mod command_boundary;
mod error;
mod parser;
mod status_conditions;
mod syntax_compat;
mod word_boundary;

pub use artifact::{
    ArithmeticReference, AssignmentCommandFact, AssignmentOperator, AssignmentValueFact,
    CommandFact, CommandSubstitutionFact, CommandToken, CommandTokenKind, DeclarationCommandFact,
    DeclarationCommandKind, DiagnosticKind, ForLoopFact, FunctionDefinitionFact, ParseDiagnostic,
    ParseStatus, ParsedCommandArtifact, PipelinePosition, ProcessSubstitutionFact,
    ProcessSubstitutionOperator, RedirectionFact, RedirectionKind, RedirectionOperandFact,
    ShellEvaluationKind, ShellEvaluationSite, ShellStatusCondition, SourceSpan,
    StatementTerminator, UnsetCommandFact, VariableAssignmentFact,
};
pub use error::ParseError;
pub use parser::{
    ScalarArgumentPart, array_assignment_entries, assignment_dominates_use,
    bash_terminal_argument_escape,
    command_success_required_before, concatenated_argument_is_scalar, constant_arithmetic_word,
    decode_static_shell_argument,
    exhaustive_case_assignment_values, observed_shell_variables,
    parse_argument_process_substitutions, parse_arithmetic_references, parse_command,
    parse_command_substitutions, parse_process_substitutions, referenced_shell_variables,
    scalar_argument_parts, scalar_word_parts, static_array_entry_values, static_array_values,
};
pub use word_boundary::is_literal_dollar_follower;

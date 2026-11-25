//! Resolve empty Bash job targets for an isolated offline entry.
use caushell_parse::{
    CommandFact, CommandSubstitutionFact, CommandToken, ParseStatus, ParsedCommandArtifact,
    decode_static_shell_argument, parse_command,
};
use caushell_profile::{
    EffectKind, ProfileRegistry, ProfileSourceKind, ResidualKind, ResolveInvocationArtifactResult,
};
use caushell_runner::{ExecutionUnitOriginKind, ExecutionUnitResolveRecord, RunnerContext};
use caushell_types::{
    Evidence, EvidenceKind, RuleId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
};

pub(super) fn resolve_empty_job_targets(
    ctx: &mut RunnerContext,
    summary: &SessionSummary,
    parsed: &ParsedCommandArtifact,
    registry: &ProfileRegistry,
    records: &mut [ExecutionUnitResolveRecord],
) {
    let Some((name, origin, root_index)) = empty_job_target(parsed) else {
        return;
    };
    let request = ctx.request();
    let state = &request.shell_state_before;
    // Protected static defaults apply only at an independent Bash entry. A
    // startup script or a prior scope may already have created jobs or
    // changed which implementation a command name selects.
    if !ctx.assumes_protected_defaults()
        || request.shell_kind != ShellKind::Bash
        || request.runtime.shell_runtime_capabilities != ShellRuntimeCapabilities::request_only()
        || state.execution_frame.is_some()
        || summary.last_sequence_no().is_some()
        || summary.shell_state_uncertainty().is_some()
        || !state.aliases.is_empty()
        || !state.functions.is_empty()
        || summary.alias_bindings().next().is_some()
        || summary.function_bindings().next().is_some()
        || state
            .environment
            .iter()
            .map(|e| e.name.as_str())
            .chain(state.variables.iter().map(|v| v.name.as_str()))
            .any(|n| {
                matches!(
                    n,
                    "BASH_ENV" | "ENV" | "BASHOPTS" | "SHELLOPTS" | "POSIXLY_CORRECT" | "PATH"
                ) || n.starts_with("LD_")
                    || n.starts_with("BASH_FUNC_")
            })
    {
        return;
    }
    let mut candidates = records.iter_mut().filter(|record| {
        record.origin_kind == origin
            && record.root_command_index == root_index
            && matches!(&record.result, ResolveInvocationArtifactResult::Resolved(r)
                if r.normalized_command_name == name)
    });
    let Some(record) = candidates.next() else {
        return;
    };
    if candidates.next().is_some()
        || !registry
            .lookup(name)
            .profile
            .is_some_and(|p| p.trust.source == ProfileSourceKind::BuiltIn)
    {
        return;
    }
    let ResolveInvocationArtifactResult::Resolved(resolved) = &mut record.result else {
        return;
    };
    let bound = &mut resolved.bound;
    // Preserve independent effects, configuration inputs, and other kinds
    // of unresolved semantics. Only the process-target binding is refined.
    if bound.effects.is_empty()
        || bound
            .effects
            .iter()
            .any(|effect| effect.kind != EffectKind::ControlProcess)
        || !bound.configured_inputs.is_empty()
        || !bound.configured_execution_sources.is_empty()
        || !bound.payload_projections.is_empty()
        || bound.residuals.iter().any(|residual| {
            residual.kind != ResidualKind::UnboundControlSurface || residual.slot.is_some()
        })
    {
        return;
    }
    bound.effects.clear();
    bound.residuals.clear();
    bound.operation_semantics_unresolved = false;
    ctx.add_evidence(Evidence {
        rule_id: RuleId::ProcessControl,
        summary: "the independent Bash entry has no matching job target".into(),
        kind: EvidenceKind::StaticEmptyJobTargets {
            node_id: record.source_node_id.0.clone(),
            command: name.into(),
        },
    });
}

fn empty_job_target(
    parsed: &ParsedCommandArtifact,
) -> Option<(&str, ExecutionUnitOriginKind, usize)> {
    if parsed.status != ParseStatus::Complete || !parsed.redirections.is_empty() {
        return None;
    }
    let raw = parsed.raw_command.trim();
    match parsed.commands.as_slice() {
        [command] if command.text.trim() == raw && !command.in_pipeline && direct(command) => {
            let name = command.command_name.as_deref()?;
            let proven = match name {
                "fg" | "bg" => command.tokens.iter().all(resume_operand),
                "kill" => {
                    let operands = signal_operands(&command.tokens);
                    !operands.is_empty() && operands.iter().all(empty_kill_operand)
                }
                _ => false,
            };
            proven.then_some((name, ExecutionUnitOriginKind::TopLevel, 0))
        }
        [producer, consumer]
            if direct(producer)
                && direct(consumer)
                && job_pid_listing(producer)
                && consumer.command_name.as_deref() == Some("xargs")
                && raw
                    .strip_prefix(producer.text.trim())
                    .and_then(|middle| middle.strip_suffix(consumer.text.trim()))
                    .is_some_and(|separator| separator.trim() == "|") =>
        {
            // GNU xargs can launch the consumer on empty input. Resolve that
            // invocation with its fixed arguments and zero appended targets.
            let (executable, arguments) = consumer.tokens.split_first()?;
            (literal(executable) == Some("kill") && signal_operands(arguments).is_empty())
                .then_some(("kill", ExecutionUnitOriginKind::StaticXargs, 1))
        }
        _ => None,
    }
}

fn direct(command: &CommandFact) -> bool {
    command.command_name.as_deref().is_some_and(|name| {
        command
            .text
            .trim_start()
            .strip_prefix(name)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
    }) && !command.conditional_execution
        && command.prefix_assignments.is_empty()
        && command.terminator != Some(caushell_parse::StatementTerminator::Background)
}

fn literal(token: &CommandToken) -> Option<&str> {
    (!token.quoted && token.command_substitutions.is_empty()).then_some(token.text.as_str())
}

fn job_number(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit())
}

fn jobspec(word: &str) -> bool {
    word.strip_prefix('%')
        .is_some_and(|suffix| matches!(suffix, "" | "%" | "+" | "-") || job_number(suffix))
}

// Resume operands are job selectors. Even an invalid selector can only
// produce an error in the empty parent shell. A traditional command
// substitution runs in a separate shell; its own effects are still checked
// on the existing execution frontier.
fn resume_operand(token: &CommandToken) -> bool {
    whole_substitution(token).is_some()
        || (matches!(
            token.node_kind.as_str(),
            "word" | "number" | "raw_string" | "ansi_c_string" | "string" | "concatenation"
        ) && token.command_substitutions.is_empty()
            && (decode_static_shell_argument(&token.text, token.quoted, &token.node_kind)
                .is_some()
                || literal(token).is_some_and(|word| {
                    // An unmatched bracket cannot form a pathname pattern.
                    (word.contains('[') ^ word.contains(']'))
                        && word
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"[]._%-".contains(&byte))
                })))
}

fn whole_substitution(token: &CommandToken) -> Option<&CommandSubstitutionFact> {
    let [substitution] = token.command_substitutions.as_slice() else {
        return None;
    };
    (!token.quoted
        && substitution.span == token.span
        && substitution.text == token.text
        && (substitution.text.starts_with("$(") || substitution.text.starts_with('`')))
    .then_some(substitution)
}

fn signal_operands(tokens: &[CommandToken]) -> &[CommandToken] {
    if tokens.first().and_then(literal).is_some_and(|flag| {
        flag.strip_prefix('-').is_some_and(|signal| {
            job_number(signal)
                && signal
                    .parse::<u8>()
                    .is_ok_and(|number| (1..=64).contains(&number))
                || matches!(
                    signal,
                    "HUP"
                        | "INT"
                        | "QUIT"
                        | "KILL"
                        | "TERM"
                        | "STOP"
                        | "TSTP"
                        | "CONT"
                        | "USR1"
                        | "USR2"
                )
        })
    }) {
        &tokens[1..]
    } else {
        tokens
    }
}

fn job_pid_listing(command: &CommandFact) -> bool {
    command.command_name.as_deref() == Some("jobs")
        && matches!(command.tokens.as_slice(), [flag] if matches!(literal(flag), Some("-p" | "-lp" | "-pl")))
}

fn empty_kill_operand(token: &CommandToken) -> bool {
    if literal(token).is_some_and(jobspec)
        || !token.quoted && token.node_kind == "simple_expansion" && token.text == "$!"
    {
        return true;
    }
    let Some(substitution) = whole_substitution(token) else {
        return false;
    };
    let Ok(body) = parse_command(&substitution.body_text, ShellKind::Bash) else {
        return false;
    };
    body.status == ParseStatus::Complete
        && body.redirections.is_empty()
        && matches!(body.commands.as_slice(), [command]
            if command.text.trim() == body.raw_command.trim() && direct(command) && job_pid_listing(command))
}

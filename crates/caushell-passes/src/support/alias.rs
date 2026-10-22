use std::collections::{BTreeMap, BTreeSet};

use caushell_parse::{CommandFact, CommandToken, CommandTokenKind, ParseStatus, parse_command};
use caushell_types::{CommandSequenceNo, SessionAliasBinding, ShellKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasAssignment {
    pub name: String,
    pub body: String,
    pub source_start: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasExpansionHop {
    pub alias_name: String,
    pub command: CommandFact,
}

pub(crate) struct AliasExpansion {
    pub command: CommandFact,
    pub hops: Vec<AliasExpansionHop>,
    pub parsed: Option<caushell_parse::ParsedCommandArtifact>,
    pub incomplete: Option<&'static str>,
}

pub(crate) fn alias_assignments(command: &CommandFact) -> Vec<AliasAssignment> {
    if command.command_name.as_deref() != Some("alias") || has_option_tokens(command) {
        return Vec::new();
    }

    command
        .tokens
        .iter()
        .filter_map(parse_alias_assignment)
        .collect()
}

pub(crate) fn unalias_names(command: &CommandFact) -> Vec<String> {
    if command.command_name.as_deref() != Some("unalias") || has_option_tokens(command) {
        return Vec::new();
    }

    command
        .tokens
        .iter()
        .filter(|token| token.kind == CommandTokenKind::Arg && !token.text.is_empty())
        .map(|token| token.text.clone())
        .collect()
}

pub(crate) fn apply_alias_command(
    aliases: &mut BTreeMap<String, SessionAliasBinding>,
    command: &CommandFact,
    observed_at: CommandSequenceNo,
) {
    for assignment in alias_assignments(command) {
        aliases.insert(
            assignment.name.clone(),
            SessionAliasBinding::new(assignment.name, assignment.body, observed_at),
        );
    }

    for name in unalias_names(command) {
        aliases.remove(name.as_str());
    }
}

pub(crate) fn expand_alias_chain(
    command: &CommandFact,
    shell_kind: ShellKind,
    aliases: &BTreeMap<String, SessionAliasBinding>,
    max_hops: usize,
) -> (CommandFact, Vec<AliasExpansionHop>) {
    let expansion = expand_alias_scope(command, shell_kind, aliases, max_hops);
    let mut expanded = expansion.command;
    expanded.in_pipeline = command.in_pipeline;
    expanded.pipeline_position = command.pipeline_position;
    expanded.pipeline_span = command.pipeline_span.clone();
    expanded.terminator = command.terminator;
    expanded.guarded = command.guarded;
    expanded.conditional_execution = command.conditional_execution;
    expanded.shell_scope_span = command.shell_scope_span.clone();
    expanded.subshell_span = command.subshell_span.clone();
    expanded.control_flow_span = command.control_flow_span.clone();
    expanded.span = command.span.clone();
    (expanded, expansion.hops)
}

pub(crate) fn expand_alias_scope(
    command: &CommandFact,
    shell_kind: ShellKind,
    aliases: &BTreeMap<String, SessionAliasBinding>,
    max_hops: usize,
) -> AliasExpansion {
    let mut expansion = AliasExpansion {
        command: command.clone(),
        hops: Vec::new(),
        parsed: None,
        incomplete: None,
    };
    let mut seen_aliases = BTreeSet::new();
    let mut text = command.text.clone();
    loop {
        let current = &expansion.command;
        let Some(alias_name) = current.command_name.as_deref() else {
            break;
        };
        if current.command_name_runtime_data {
            break;
        }
        let Some(binding) = aliases.get(alias_name) else {
            break;
        };
        // Quoting the command word suppresses alias lookup in the shell.
        let offset = current.prefix_assignments.last().map_or(0, |assignment| {
            assignment
                .span
                .end_byte
                .saturating_sub(current.span.start_byte)
        });
        let Some(tail) = current.text.get(offset..) else {
            expansion.incomplete = Some("alias command word has no source location");
            break;
        };
        let word_offset = offset + tail.len() - tail.trim_start().len();
        if !current.text[word_offset..].starts_with(alias_name) {
            break;
        }
        if !seen_aliases.insert(alias_name.to_string()) {
            if expansion
                .hops
                .last()
                .is_none_or(|hop| hop.alias_name != alias_name)
            {
                expansion.incomplete = Some("alias expansion contains a cycle");
            }
            break;
        }
        if expansion.hops.len() == max_hops {
            expansion.incomplete = Some("alias expansion exceeded its hop budget");
            break;
        }
        if binding.body.ends_with([' ', '\t'])
            && current.tokens.first().is_some_and(|token| {
                !token.quoted && !token.runtime_data && aliases.contains_key(&token.text)
            })
        {
            expansion.incomplete = Some("alias requires following-word expansion");
            break;
        }
        let start = expansion
            .parsed
            .as_ref()
            .map_or(0, |_| current.span.start_byte)
            + word_offset;
        let Some(end) = start
            .checked_add(alias_name.len())
            .filter(|end| *end <= text.len())
        else {
            expansion.incomplete = Some("alias command word has no source location");
            break;
        };
        text.replace_range(start..end, &binding.body);
        let Ok(parsed) = parse_command(&text, shell_kind) else {
            expansion.incomplete = Some("alias body could not be parsed");
            break;
        };
        if parsed.status != ParseStatus::Complete
            || parsed.commands.len() != 1
            || !parsed.assignment_commands.is_empty()
            || !parsed.declaration_commands.is_empty()
            || !parsed.function_definitions.is_empty()
            || !parsed.unset_commands.is_empty()
        {
            expansion.incomplete = Some("alias body is not a complete single invocation");
            break;
        }
        let expanded = parsed.commands[0].clone();
        expansion.hops.push(AliasExpansionHop {
            alias_name: binding.name.clone(),
            command: expanded.clone(),
        });
        expansion.command = expanded;
        expansion.parsed = Some(parsed);
    }
    expansion
}

fn has_option_tokens(command: &CommandFact) -> bool {
    command
        .tokens
        .iter()
        .any(|token| token.kind != CommandTokenKind::Arg)
}

fn parse_alias_assignment(token: &CommandToken) -> Option<AliasAssignment> {
    let (name, body) = token.text.split_once('=')?;

    if !is_valid_alias_name(name) {
        return None;
    }

    Some(AliasAssignment {
        name: name.to_string(),
        body: caushell_profile::materialize_shell_assignment_value(
            body,
            false,
            "word",
            &caushell_profile::SessionBindings::default(),
        )
        .unwrap_or_else(|| strip_one_outer_quote_layer(body).to_string()),
        source_start: token.span.start_byte,
    })
}

fn is_valid_alias_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '\'' | '"'))
}

fn strip_one_outer_quote_layer(text: &str) -> &str {
    if text.len() >= 2
        && ((text.starts_with('\'') && text.ends_with('\''))
            || (text.starts_with('"') && text.ends_with('"')))
    {
        &text[1..text.len() - 1]
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::{alias_assignments, expand_alias_chain, unalias_names};
    use caushell_parse::parse_command;
    use caushell_types::{CommandSequenceNo, SessionAliasBinding, ShellKind};
    use std::collections::BTreeMap;

    fn parse_single_command(command: &str) -> caushell_parse::CommandFact {
        parse_command(command, ShellKind::Bash)
            .expect("expected command to parse")
            .commands
            .into_iter()
            .next()
            .expect("expected single command")
    }

    #[test]
    fn alias_assignments_extract_name_and_body() {
        let command = parse_single_command("alias ll='ls -l' g=\"grep --color=auto\"");

        assert_eq!(
            alias_assignments(&command),
            vec![
                super::AliasAssignment {
                    name: "ll".to_string(),
                    body: "ls -l".to_string(),
                    source_start: 6,
                },
                super::AliasAssignment {
                    name: "g".to_string(),
                    body: "grep --color=auto".to_string(),
                    source_start: 17,
                },
            ]
        );
    }

    #[test]
    fn alias_assignments_preserve_repeated_operand_positions() {
        let command =
            parse_single_command("alias a='printf FIRST' a='printf SECOND' a='printf FIRST'");
        let assignments = alias_assignments(&command);
        assert_eq!(
            assignments
                .iter()
                .map(|a| a.body.as_str())
                .collect::<Vec<_>>(),
            ["printf FIRST", "printf SECOND", "printf FIRST"]
        );
        assert!(
            assignments
                .windows(2)
                .all(|a| a[0].source_start < a[1].source_start)
        );
    }

    #[test]
    fn unalias_names_extract_plain_arguments() {
        let command = parse_single_command("unalias ll g");

        assert_eq!(unalias_names(&command), vec!["ll", "g"]);
    }

    #[test]
    fn expand_alias_chain_rewrites_first_word_repeatedly() {
        let command = parse_single_command("a target.txt");
        let aliases = BTreeMap::from([
            (
                "a".to_string(),
                SessionAliasBinding::new("a", "b", CommandSequenceNo::new(1)),
            ),
            (
                "b".to_string(),
                SessionAliasBinding::new("b", "cat", CommandSequenceNo::new(2)),
            ),
        ]);

        let (expanded, hops) = expand_alias_chain(&command, ShellKind::Bash, &aliases, 8);

        assert_eq!(expanded.command_name.as_deref(), Some("cat"));
        assert_eq!(expanded.text, "cat target.txt");
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].alias_name, "a");
        assert_eq!(hops[0].command.text, "b target.txt");
        assert_eq!(hops[1].alias_name, "b");
        assert_eq!(hops[1].command.text, "cat target.txt");
    }
}

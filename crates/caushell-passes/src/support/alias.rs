use std::collections::{BTreeMap, BTreeSet};

use caushell_parse::{CommandFact, CommandTokenKind, ParseStatus, parse_command};
use caushell_types::{CommandSequenceNo, SessionAliasBinding, ShellKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasAssignment {
    pub name: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasExpansionHop {
    pub alias_name: String,
    pub command: CommandFact,
}

pub(crate) fn alias_assignments(command: &CommandFact) -> Vec<AliasAssignment> {
    if command.command_name.as_deref() != Some("alias") || has_option_tokens(command) {
        return Vec::new();
    }

    command
        .tokens
        .iter()
        .filter_map(|token| parse_alias_assignment(token.text.as_str()))
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
    let mut current = command.clone();
    let mut seen_aliases = BTreeSet::new();
    let mut hops = Vec::new();

    for _ in 0..max_hops {
        let Some(alias_name) = current.command_name.as_deref() else {
            break;
        };
        let Some(binding) = aliases.get(alias_name) else {
            break;
        };

        if !seen_aliases.insert(alias_name.to_string()) {
            break;
        }

        let Some(expanded) = expand_alias_once(&current, binding.body.as_str(), shell_kind) else {
            break;
        };

        hops.push(AliasExpansionHop {
            alias_name: alias_name.to_string(),
            command: expanded.clone(),
        });
        current = expanded;
    }

    (current, hops)
}

fn has_option_tokens(command: &CommandFact) -> bool {
    command
        .tokens
        .iter()
        .any(|token| token.kind != CommandTokenKind::Arg)
}

fn parse_alias_assignment(text: &str) -> Option<AliasAssignment> {
    let (name, body) = text.split_once('=')?;

    if !is_valid_alias_name(name) {
        return None;
    }

    Some(AliasAssignment {
        name: name.to_string(),
        body: strip_one_outer_quote_layer(body).to_string(),
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

fn expand_alias_once(
    command: &CommandFact,
    alias_body: &str,
    shell_kind: ShellKind,
) -> Option<CommandFact> {
    let command_name = command.command_name.as_deref()?;
    let remainder = command.text.strip_prefix(command_name)?;
    let expanded_text = format!("{alias_body}{remainder}");
    let parsed = parse_command(&expanded_text, shell_kind).ok()?;

    if parsed.status != ParseStatus::Complete
        || parsed.commands.len() != 1
        || !parsed.declaration_commands.is_empty()
        || !parsed.unset_commands.is_empty()
        || !parsed.redirections.is_empty()
    {
        return None;
    }

    let mut expanded = parsed.commands[0].clone();
    expanded.text = expanded_text;
    expanded.in_pipeline = command.in_pipeline;
    expanded.pipeline_position = command.pipeline_position;
    expanded.pipeline_span = command.pipeline_span.clone();
    expanded.terminator = command.terminator;
    expanded.guarded = command.guarded;
    expanded.span = command.span.clone();
    Some(expanded)
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
                },
                super::AliasAssignment {
                    name: "g".to_string(),
                    body: "grep --color=auto".to_string(),
                },
            ]
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

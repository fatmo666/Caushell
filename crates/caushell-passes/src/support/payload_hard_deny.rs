use caushell_graph::NodeId;
use caushell_parse::{CommandFact, CommandTokenKind, ParsedCommandArtifact};
use caushell_profile::SessionBindings;
use caushell_query::QuerySession;
use caushell_runner::RunnerContext;
use caushell_types::CommandSequenceNo;

use crate::support::{
    block_device_path_for_arg_with_optional_cwd, materialize_static_token_text,
    static_stdin_payloads_for_scoped_command,
};
use crate::support::{
    collect_bare_shell_sink_hard_deny_reasons, collect_shell_sink_hard_deny_reasons_for_command,
    resolved_execution_records_for_local_analysis,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FdiskPayloadClassification {
    None,
    SessionWrite,
    PartitionTableDestruction,
}

#[cfg(test)]
pub(crate) fn collect_payload_destructive_hard_deny_reasons(
    parsed: &ParsedCommandArtifact,
) -> Vec<String> {
    let graph = caushell_graph::SessionGraph::new();
    let summary = caushell_types::SessionSummary::new();
    let session = QuerySession::new(&graph, &summary);
    let bindings = SessionBindings::new();

    parsed
        .commands
        .iter()
        .enumerate()
        .flat_map(|(command_index, _)| {
            collect_static_payload_partition_table_reasons(
                session,
                parsed,
                command_index,
                CommandSequenceNo::new(0),
                &bindings,
                Some("/"),
                "/",
                None,
                caushell_types::SemanticExpansionPolicy::default().max_nested_parse_depth,
            )
        })
        .collect()
}

pub(crate) fn collect_block_device_destructive_reasons(
    ctx: &RunnerContext,
    staged_session: QuerySession<'_>,
) -> Vec<String> {
    let sequence_no = ctx.request().sequence_no;
    let cwd = ctx.request().shell_state_before.cwd();
    let home = ctx.request().home.as_deref();
    let max_nested_parse_depth = ctx.policy().semantic_expansion.max_nested_parse_depth;
    let mut reasons = Vec::new();

    if let Some(parsed) = ctx.parsed_command() {
        reasons.extend(
            collect_bare_shell_sink_hard_deny_reasons(parsed, Some(cwd), home)
                .into_iter()
                .map(|reason| format!("{reason} in command {}", parsed.raw_command)),
        );
    }

    for record in resolved_execution_records_for_local_analysis(ctx) {
        let parsed = record.parsed_scope();
        let record_cwd_options = effective_cwd_options_for_node(ctx, record.source_node_id(), cwd);

        for record_cwd in record_cwd_options {
            let payload_cwd = record_cwd.unwrap_or(cwd);

            reasons.extend(
                collect_shell_sink_hard_deny_reasons_for_command(
                    parsed,
                    record.command_index(),
                    record_cwd,
                    home,
                )
                .into_iter()
                .map(|reason| {
                    format!(
                        "{reason} in command {}",
                        record_command_text(parsed, record.command_index())
                    )
                }),
            );

            let bindings = record_bindings(record, staged_session);
            reasons.extend(
                collect_static_payload_partition_table_reasons(
                    staged_session,
                    parsed,
                    record.command_index(),
                    sequence_no,
                    bindings.as_ref(),
                    record_cwd,
                    payload_cwd,
                    home,
                    max_nested_parse_depth,
                )
                .into_iter()
                .map(|reason| {
                    format!(
                        "{reason} in command {}",
                        record_command_text(parsed, record.command_index())
                    )
                }),
            );
        }
    }

    reasons
}

pub(crate) fn collect_block_device_session_reasons(
    ctx: &RunnerContext,
    staged_session: QuerySession<'_>,
) -> Vec<String> {
    let sequence_no = ctx.request().sequence_no;
    let cwd = ctx.request().shell_state_before.cwd();
    let home = ctx.request().home.as_deref();
    let max_nested_parse_depth = ctx.policy().semantic_expansion.max_nested_parse_depth;
    let mut reasons = Vec::new();

    for record in resolved_execution_records_for_local_analysis(ctx) {
        let parsed = record.parsed_scope();
        let record_cwd_options = effective_cwd_options_for_node(ctx, record.source_node_id(), cwd);

        for record_cwd in record_cwd_options {
            let payload_cwd = record_cwd.unwrap_or(cwd);

            let bindings = record_bindings(record, staged_session);
            reasons.extend(collect_static_payload_fdisk_session_reasons(
                staged_session,
                parsed,
                record.command_index(),
                sequence_no,
                bindings.as_ref(),
                record_cwd,
                payload_cwd,
                home,
                max_nested_parse_depth,
            ));
        }
    }

    reasons
}

fn record_command_text(parsed: &ParsedCommandArtifact, command_index: usize) -> &str {
    parsed
        .commands
        .get(command_index)
        .map(|command| command.text.as_str())
        .unwrap_or(parsed.raw_command.as_str())
}

fn record_bindings<'a>(
    record: crate::support::ExecutionResolveRecordRef<'a>,
    _staged_session: QuerySession<'a>,
) -> std::borrow::Cow<'a, SessionBindings> {
    std::borrow::Cow::Borrowed(record.bindings())
}

fn effective_cwd_options_for_node<'a>(
    ctx: &'a RunnerContext,
    node_id: &NodeId,
    fallback_cwd: &'a str,
) -> Vec<Option<&'a str>> {
    let mut options = Vec::new();
    match ctx.effective_cwd_for_node(node_id) {
        Some(cwd) if cwd.is_unreachable() => {}
        Some(cwd) => {
            for known in cwd.known_cwds() {
                push_unique_cwd_option(&mut options, Some(known));
            }
            if cwd.has_unknown() || options.is_empty() {
                push_unique_cwd_option(&mut options, None);
            }
        }
        None => push_unique_cwd_option(&mut options, Some(fallback_cwd)),
    }
    options
}

fn push_unique_cwd_option<'a>(options: &mut Vec<Option<&'a str>>, option: Option<&'a str>) {
    if !options.contains(&option) {
        options.push(option);
    }
}

fn fdisk_partition_table_destruction_command(line: &str) -> bool {
    matches!(
        line,
        // Main menu commands that explicitly replace the disk label / partition table.
        "g" | "G" | "o"
    )
}

pub(crate) fn classify_fdisk_payload_texts(payloads: &[String]) -> FdiskPayloadClassification {
    let mut saw_write = false;
    let mut saw_destruction = false;

    for payload in payloads {
        for line in payload
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if line == "w" {
                saw_write = true;
                continue;
            }

            if fdisk_partition_table_destruction_command(line) {
                saw_destruction = true;
            }
        }
    }

    if !saw_write {
        FdiskPayloadClassification::None
    } else if saw_destruction {
        FdiskPayloadClassification::PartitionTableDestruction
    } else {
        FdiskPayloadClassification::SessionWrite
    }
}

fn sfdisk_payload_is_partition_table_destruction(args: &[String], payloads: &[String]) -> bool {
    if sfdisk_is_no_act(args) {
        return false;
    }

    payloads
        .iter()
        .flat_map(|payload| payload.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(sfdisk_partition_table_rewrite_header)
}

fn sfdisk_is_no_act(args: &[String]) -> bool {
    args.iter()
        .any(|arg| arg.as_str() == "-n" || arg.as_str() == "--no-act")
}

fn sfdisk_partition_table_rewrite_header(line: &str) -> bool {
    line.strip_prefix("label:")
        .is_some_and(|rest| !rest.trim().is_empty())
}

fn collect_static_payload_partition_table_reasons(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: Option<&str>,
    payload_cwd: &str,
    home: Option<&str>,
    max_nested_parse_depth: u8,
) -> Vec<String> {
    let Some(command) = parsed.commands.get(command_index) else {
        return Vec::new();
    };

    let Some(command_name @ ("fdisk" | "sfdisk")) = command.command_name.as_deref() else {
        return Vec::new();
    };

    let args = materialized_command_args(command, bindings);
    let Some(target) = block_device_path_for_arg_with_optional_cwd(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        cwd,
        home,
    ) else {
        return Vec::new();
    };

    let payloads = static_stdin_payloads_for_scoped_command(
        session,
        parsed,
        command_index,
        sequence_no,
        bindings,
        bindings,
        payload_cwd,
        home,
        max_nested_parse_depth,
    );

    match command_name {
        "fdisk" => matches!(
            classify_fdisk_payload_texts(&payloads),
            FdiskPayloadClassification::PartitionTableDestruction
        )
        .then(|| format!("partition table destruction target {target} via fdisk")),
        "sfdisk" => sfdisk_payload_is_partition_table_destruction(&args, &payloads)
            .then(|| format!("partition table destruction target {target} via sfdisk")),
        _ => None,
    }
    .into_iter()
    .collect()
}

fn collect_static_payload_fdisk_session_reasons(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: Option<&str>,
    payload_cwd: &str,
    home: Option<&str>,
    max_nested_parse_depth: u8,
) -> Vec<String> {
    let Some(command) = parsed.commands.get(command_index) else {
        return Vec::new();
    };

    if command.command_name.as_deref() != Some("fdisk") {
        return Vec::new();
    }

    let args = materialized_command_args(command, bindings);
    let Some(target) = block_device_path_for_arg_with_optional_cwd(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        cwd,
        home,
    ) else {
        return Vec::new();
    };

    let payloads = static_stdin_payloads_for_scoped_command(
        session,
        parsed,
        command_index,
        sequence_no,
        bindings,
        bindings,
        payload_cwd,
        home,
        max_nested_parse_depth,
    );

    matches!(
        classify_fdisk_payload_texts(&payloads),
        FdiskPayloadClassification::SessionWrite
    )
    .then(|| format!("partition table session target {target} via fdisk"))
    .into_iter()
    .collect()
}

fn materialized_command_args(command: &CommandFact, bindings: &SessionBindings) -> Vec<String> {
    command
        .tokens
        .iter()
        .filter(|token| token.kind != CommandTokenKind::DashDash)
        .map(|token| materialize_static_token_text(&token.text, bindings))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::collect_payload_destructive_hard_deny_reasons;
    use caushell_parse::parse_command;
    use caushell_types::ShellKind;

    #[test]
    fn payload_hard_deny_detects_fdisk_partition_table_destruction() {
        let parsed = parse_command("fdisk /dev/sda <<'EOF'\no\nw\nEOF", ShellKind::Bash)
            .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert_eq!(
            reasons,
            vec!["partition table destruction target /dev/sda via fdisk"]
        );
    }

    #[test]
    fn payload_hard_deny_detects_fdisk_ansi_c_herestring_mutation() {
        let parsed = parse_command(r#"fdisk /dev/sda <<<$'g\nw\n'"#, ShellKind::Bash)
            .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert_eq!(
            reasons,
            vec!["partition table destruction target /dev/sda via fdisk"]
        );
    }

    #[test]
    fn payload_hard_deny_ignores_fdisk_expert_menu_mutations() {
        let parsed = parse_command(
            "fdisk /dev/sda <<'EOF'\nx\ni\n0x1234\nr\nw\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_fdisk_inspect_only_payload() {
        let parsed = parse_command("fdisk /dev/sda <<'EOF'\np\nq\nEOF", ShellKind::Bash)
            .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_fdisk_boot_flag_toggle_payload() {
        let parsed = parse_command("fdisk /dev/sda <<'EOF'\na\nw\nEOF", ShellKind::Bash)
            .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_fdisk_raw_string_literal_line_escapes() {
        let parsed = parse_command(r#"fdisk /dev/sda <<<'g\nw\n'"#, ShellKind::Bash)
            .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_detects_sfdisk_partition_table_destruction() {
        let parsed = parse_command("sfdisk /dev/sda <<'EOF'\nlabel: gpt\nEOF", ShellKind::Bash)
            .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert_eq!(
            reasons,
            vec!["partition table destruction target /dev/sda via sfdisk"]
        );
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_label_id_only_script() {
        let parsed = parse_command(
            "sfdisk /dev/sda <<'EOF'\nlabel-id: 0x1234abcd\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_device_header_only_script() {
        let parsed = parse_command(
            "sfdisk /dev/sda <<'EOF'\ndevice: /dev/sda\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_unit_header_only_script() {
        let parsed = parse_command(
            "sfdisk /dev/sda <<'EOF'\nunit: sectors\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_first_lba_only_script() {
        let parsed = parse_command(
            "sfdisk /dev/sda <<'EOF'\nfirst-lba: 2048\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_last_lba_only_script() {
        let parsed = parse_command(
            "sfdisk /dev/sda <<'EOF'\nlast-lba: 2097151\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_partition_entry_script() {
        let parsed = parse_command("sfdisk /dev/sda <<'EOF'\n,1G,L\nEOF", ShellKind::Bash)
            .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_no_act_partition_table_script() {
        let parsed = parse_command(
            "sfdisk --no-act /dev/sda <<'EOF'\nlabel: gpt\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }

    #[test]
    fn payload_hard_deny_ignores_sfdisk_short_no_act_partition_table_script() {
        let parsed = parse_command(
            "sfdisk -n /dev/sda <<'EOF'\nlabel: gpt\nEOF",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let reasons = collect_payload_destructive_hard_deny_reasons(&parsed);

        assert!(reasons.is_empty());
    }
}

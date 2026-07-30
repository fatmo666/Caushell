use std::collections::BTreeMap;

use caushell_graph::{NodeId, NodeKind};
use caushell_parse::{CommandFact, CommandTokenKind, ParsedCommandArtifact, RedirectionKind};
use caushell_profile::{SessionBindings, exact_scalar_shell_parameter_reference_value};
use caushell_query::{
    CommandInvocationRef, ExecutionUnitHistoryQuery, ExecutionUnitRef, PathContentProduceQuery,
    QuerySession,
};
use caushell_types::{CommandSequenceNo, ProvenanceProduceKind, SessionId};

use crate::{
    path::resolve_path_operand,
    support::{
        apply_visible_variable_bindings_before_span, is_file_write_redirection_operator,
        redirection_parent_command_index, redirection_targets_stdin_payload,
    },
};

const MAX_LITERAL_CONTENT_TRACE_HOPS: usize = 8;

pub(crate) fn static_stdout_payloads_for_command(
    session: QuerySession<'_>,
    command: &CommandFact,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
) -> Vec<String> {
    let mut payloads = static_literal_stdout_payloads_for_command(command, bindings);
    if command.command_name.as_deref() == Some("cat") {
        payloads.extend(cat_static_payloads(
            session,
            command,
            sequence_no,
            cwd,
            home,
        ));
    }
    payloads
}

pub(crate) fn static_stdout_payloads_for_scoped_command(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Vec<String> {
    let Some(command) = parsed.commands.get(command_index) else {
        return Vec::new();
    };

    match command.command_name.as_deref() {
        Some("cat") => cat_scoped_stdout_payloads(
            session,
            parsed,
            command_index,
            sequence_no,
            bindings,
            scope_base_bindings,
            cwd,
            home,
            remaining_depth,
        ),
        Some("bash" | "sh") => shell_scoped_stdout_payloads(
            session,
            command,
            sequence_no,
            bindings,
            cwd,
            home,
            remaining_depth,
        ),
        _ => static_stdout_payloads_for_command(session, command, sequence_no, bindings, cwd, home),
    }
}

pub(crate) fn static_stdin_payloads_for_scoped_command(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Vec<String> {
    let mut payloads = stdin_payloads_for_command(
        session,
        parsed,
        command_index,
        sequence_no,
        bindings,
        cwd,
        home,
        remaining_depth,
    );
    payloads.extend(file_stdin_payloads_for_command(
        session,
        parsed,
        command_index,
        sequence_no,
        bindings,
        scope_base_bindings,
        cwd,
        home,
    ));

    if remaining_depth == 0 {
        return payloads;
    }

    payloads.extend(process_substitution_stdin_payloads_for_command(
        session,
        parsed,
        command_index,
        sequence_no,
        bindings,
        cwd,
        home,
        remaining_depth,
    ));

    if let Some(upstream_index) = pipeline_upstream_by_consumer(parsed)
        .get(&command_index)
        .copied()
    {
        let Some(upstream_command) = parsed.commands.get(upstream_index) else {
            return payloads;
        };
        let upstream_bindings = apply_visible_variable_bindings_before_span(
            scope_base_bindings.clone(),
            parsed,
            upstream_command.span.start_byte,
            sequence_no,
        );
        payloads.extend(static_stdout_payloads_for_scoped_command(
            session,
            parsed,
            upstream_index,
            sequence_no,
            &upstream_bindings,
            scope_base_bindings,
            cwd,
            home,
            remaining_depth.saturating_sub(1),
        ));
    }

    payloads
}

pub(crate) fn static_literal_stdout_payloads_for_command(
    command: &CommandFact,
    bindings: &SessionBindings,
) -> Vec<String> {
    match command.command_name.as_deref() {
        Some("printf") => printf_literal_payloads(command, bindings),
        Some("echo") => echo_literal_payload(command, bindings)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn materialize_static_token_text(text: &str, bindings: &SessionBindings) -> String {
    materialize_token_text(text, bindings)
}

pub(crate) fn materialize_static_token_command_substitutions(
    text: &str,
    substitutions: &[caushell_parse::CommandSubstitutionFact],
    session: QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Option<String> {
    if substitutions.is_empty() {
        return Some(materialize_static_token_text(text, bindings));
    }

    let mut rendered = String::new();
    let mut cursor = 0usize;
    for substitution in substitutions {
        let relative_start = text.get(cursor..)?.find(&substitution.text)?;
        let start = cursor + relative_start;
        let end = start + substitution.text.len();
        rendered.push_str(text.get(cursor..start)?);
        rendered.push_str(&static_command_substitution_output(
            &substitution.text,
            session,
            shell_kind,
            sequence_no,
            bindings,
            cwd,
            home,
            remaining_depth,
        )?);
        cursor = end;
    }
    rendered.push_str(text.get(cursor..)?);

    Some(materialize_static_token_text(&rendered, bindings))
}

fn materialize_static_command_substitutions_for_text(
    text: &str,
    session: QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Option<String> {
    let substitutions = caushell_parse::parse_command_substitutions(text, shell_kind).ok()?;
    materialize_static_token_command_substitutions(
        text,
        &substitutions,
        session,
        shell_kind,
        sequence_no,
        bindings,
        cwd,
        home,
        remaining_depth,
    )
}

fn static_command_substitution_output(
    text: &str,
    session: QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Option<String> {
    if remaining_depth == 0 {
        return None;
    }

    let substitutions = caushell_parse::parse_command_substitutions(text, shell_kind).ok()?;
    let substitution = substitutions.first()?;
    let parsed = caushell_parse::parse_command(&substitution.body_text, shell_kind).ok()?;
    let mut payloads = Vec::new();

    for (command_index, _) in parsed.commands.iter().enumerate() {
        payloads.extend(static_stdout_payloads_for_scoped_command(
            session,
            &parsed,
            command_index,
            sequence_no,
            bindings,
            bindings,
            cwd,
            home,
            remaining_depth.saturating_sub(1),
        ));
    }

    (!payloads.is_empty()).then(|| payloads.join(""))
}

pub(crate) fn static_shell_payload_from_command(
    command: &CommandFact,
    bindings: &SessionBindings,
) -> Option<String> {
    match command.command_name.as_deref() {
        Some("bash") | Some("sh") => {}
        _ => return None,
    };
    let args = command
        .tokens
        .iter()
        .filter(|token| token.kind != CommandTokenKind::DashDash)
        .map(|token| materialize_token_text(&token.text, bindings))
        .collect::<Vec<_>>();
    static_shell_payload_from_args(&args)
}

pub(crate) fn static_shell_payload_from_args(args: &[String]) -> Option<String> {
    let payload_index = shell_command_payload_arg_index(args)?;
    let payload = args.get(payload_index)?.clone();
    let trailing_args = args
        .iter()
        .skip(payload_index + 1)
        .cloned()
        .collect::<Vec<_>>();

    Some(substitute_shell_positional_parameters(
        &unquote_static_shell_arg(&payload).unwrap_or(payload),
        &trailing_args,
    ))
}

pub(crate) fn substitute_static_shell_positional_parameters(
    payload: &str,
    trailing_args: &[String],
) -> String {
    let payload = unquote_static_shell_arg(payload).unwrap_or_else(|| payload.to_string());
    substitute_shell_positional_parameters(&payload, trailing_args)
}

fn cat_static_payloads(
    session: QuerySession<'_>,
    command: &CommandFact,
    sequence_no: CommandSequenceNo,
    cwd: &str,
    home: Option<&str>,
) -> Vec<String> {
    let args: Vec<&caushell_parse::CommandToken> = command
        .tokens
        .iter()
        .filter(|token| token.kind == CommandTokenKind::Arg)
        .collect();
    let mut payloads = Vec::new();

    for arg in args {
        let Some(path) = resolve_path_operand(&arg.text, arg.quoted, &arg.node_kind, cwd, home)
        else {
            continue;
        };
        if let Some(content) =
            known_literal_path_content_before_sequence(session, &path, sequence_no, cwd, home)
        {
            payloads.push(content);
        }
    }

    payloads
}

fn shell_scoped_stdout_payloads(
    session: QuerySession<'_>,
    command: &CommandFact,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Vec<String> {
    if remaining_depth == 0 {
        return Vec::new();
    }

    let shell_kind = match command.command_name.as_deref() {
        Some("bash") => caushell_types::ShellKind::Bash,
        Some("sh") => caushell_types::ShellKind::Sh,
        _ => return Vec::new(),
    };
    let Some(payload) = static_shell_payload_from_command(command, bindings) else {
        return Vec::new();
    };
    let Ok(parsed_payload) = caushell_parse::parse_command(&payload, shell_kind) else {
        return Vec::new();
    };
    let mut child_payloads = Vec::new();

    for (command_index, _) in parsed_payload.commands.iter().enumerate() {
        child_payloads.extend(static_stdout_payloads_for_scoped_command(
            session,
            &parsed_payload,
            command_index,
            sequence_no,
            bindings,
            bindings,
            cwd,
            home,
            remaining_depth.saturating_sub(1),
        ));
    }

    if child_payloads.is_empty() {
        Vec::new()
    } else {
        vec![child_payloads.join("")]
    }
}

fn cat_scoped_stdout_payloads(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Vec<String> {
    let Some(command) = parsed.commands.get(command_index) else {
        return Vec::new();
    };
    let args = arg_tokens(command);

    if args.is_empty() {
        let stdin_payloads = static_stdin_payloads_for_scoped_command(
            session,
            parsed,
            command_index,
            sequence_no,
            bindings,
            scope_base_bindings,
            cwd,
            home,
            remaining_depth,
        );
        if !stdin_payloads.is_empty() {
            return vec![stdin_payloads.join("")];
        }

        return Vec::new();
    }

    let mut fragments = Vec::new();
    for arg in args {
        if let Some(path) = resolve_path_operand(&arg.text, arg.quoted, &arg.node_kind, cwd, home) {
            let Some(content) =
                known_literal_path_content_before_sequence(session, &path, sequence_no, cwd, home)
            else {
                return Vec::new();
            };
            fragments.push(content);
            continue;
        }

        if arg.node_kind == "process_substitution" {
            let payloads = static_stdout_payloads_for_process_substitution_text(
                session,
                &arg.text,
                parsed.shell_kind,
                sequence_no,
                bindings,
                cwd,
                home,
                remaining_depth,
            );
            if payloads.is_empty() {
                return Vec::new();
            }
            fragments.extend(payloads);
            continue;
        }

        return Vec::new();
    }

    if fragments.is_empty() {
        Vec::new()
    } else {
        vec![fragments.join("")]
    }
}

pub(crate) fn known_literal_path_content_before_sequence(
    session: QuerySession<'_>,
    path: &str,
    before_sequence: CommandSequenceNo,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    known_literal_path_content_before_sequence_with_depth(
        session,
        path,
        before_sequence,
        cwd,
        home,
        0,
    )
}

pub(crate) fn known_literal_path_content_before_execution_unit(
    session: QuerySession<'_>,
    path: &str,
    before_execution_unit_node_id: &NodeId,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    known_literal_path_content_before_execution_unit_with_depth(
        session,
        path,
        before_execution_unit_node_id,
        cwd,
        home,
        0,
    )
}

pub(crate) fn known_literal_path_content_before_scoped_command(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    before_command_index: usize,
    path: &str,
    sequence_no: CommandSequenceNo,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
) -> Option<String> {
    known_literal_path_content_before_scoped_command_with_depth(
        session,
        parsed,
        before_command_index,
        path,
        sequence_no,
        scope_base_bindings,
        cwd,
        home,
        0,
    )
}

fn known_literal_path_content_before_scoped_command_with_depth(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    before_command_index: usize,
    path: &str,
    sequence_no: CommandSequenceNo,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    depth: usize,
) -> Option<String> {
    if depth >= MAX_LITERAL_CONTENT_TRACE_HOPS {
        return None;
    }

    let mut latest_content = None;
    for (command_index, command) in parsed.commands.iter().enumerate() {
        if command_index >= before_command_index {
            break;
        }

        let bindings = apply_visible_variable_bindings_before_span(
            scope_base_bindings.clone(),
            parsed,
            command.span.start_byte,
            sequence_no,
        );
        if let Some(content) = literal_content_written_by_scoped_command(
            session,
            parsed,
            command_index,
            path,
            sequence_no,
            &bindings,
            scope_base_bindings,
            cwd,
            home,
            depth + 1,
        ) {
            latest_content = Some(content);
        }
    }

    latest_content
}

fn known_literal_path_content_before_execution_unit_with_depth(
    session: QuerySession<'_>,
    path: &str,
    before_execution_unit_node_id: &NodeId,
    cwd: &str,
    home: Option<&str>,
    depth: usize,
) -> Option<String> {
    if depth >= MAX_LITERAL_CONTENT_TRACE_HOPS {
        return None;
    }

    let produces = PathContentProduceQuery::new()
        .path(path)
        .produce_kind(ProvenanceProduceKind::PathWrite)
        .before_execution_unit_node_id(before_execution_unit_node_id.clone())
        .execute(session);

    for produce in produces.produces().iter().rev() {
        let unit = produce.execution_unit();
        let producer_cwd = unit
            .top_level()
            .map(|command| command.cwd_before())
            .unwrap_or(cwd);
        let base_bindings = producer_base_bindings(session, unit);
        if let Some(content) = literal_content_written_by_command(
            session,
            unit.raw_text(),
            unit.shell_kind(),
            produce.path(),
            unit.root_command_sequence_no(),
            producer_cwd,
            home,
            depth + 1,
            &base_bindings,
        ) {
            return Some(content);
        }
    }

    let Some(root_sequence) = session
        .graph()
        .get_node(before_execution_unit_node_id)
        .and_then(root_sequence_no_for_execution_unit_node)
    else {
        return None;
    };
    let same_sequence_floor = CommandSequenceNo::new(root_sequence.0.saturating_sub(1));
    let history = ExecutionUnitHistoryQuery::new()
        .after_sequence(same_sequence_floor)
        .before_execution_unit_node_id(before_execution_unit_node_id.clone())
        .execute(session);
    let mut bindings = SessionBindings::from_session_summary(session.summary());
    let mut latest_content = None;
    for unit in history.execution_units() {
        let producer_cwd = unit
            .top_level()
            .map(|command| command.cwd_before())
            .unwrap_or(cwd);
        if let Some(content) = literal_content_written_by_command(
            session,
            unit.raw_text(),
            unit.shell_kind(),
            path,
            unit.root_command_sequence_no(),
            producer_cwd,
            home,
            depth + 1,
            &bindings,
        ) {
            latest_content = Some(content);
        }

        if let Ok(parsed) = caushell_parse::parse_command(unit.raw_text(), unit.shell_kind()) {
            bindings = apply_visible_variable_bindings_before_span(
                bindings,
                &parsed,
                usize::MAX,
                unit.root_command_sequence_no(),
            );
        }
    }

    latest_content
}

fn root_sequence_no_for_execution_unit_node(
    node: &caushell_graph::GraphNode,
) -> Option<CommandSequenceNo> {
    match &node.kind {
        NodeKind::CommandInvocation { sequence_no, .. } => Some(*sequence_no),
        NodeKind::DerivedInvocation {
            root_command_sequence_no,
            ..
        } => Some(*root_command_sequence_no),
        _ => None,
    }
}

fn known_literal_path_content_before_sequence_with_depth(
    session: QuerySession<'_>,
    path: &str,
    before_sequence: CommandSequenceNo,
    cwd: &str,
    home: Option<&str>,
    depth: usize,
) -> Option<String> {
    if depth >= MAX_LITERAL_CONTENT_TRACE_HOPS {
        return None;
    }

    let produces = PathContentProduceQuery::new()
        .path(path)
        .produce_kind(ProvenanceProduceKind::PathWrite)
        .before_sequence(before_sequence)
        .execute(session);

    for produce in produces.produces().iter().rev() {
        let unit = produce.execution_unit();
        let producer_cwd = unit
            .top_level()
            .map(|command| command.cwd_before())
            .unwrap_or(cwd);
        let base_bindings = producer_base_bindings(session, unit);
        if let Some(content) = literal_content_written_by_command(
            session,
            unit.raw_text(),
            unit.shell_kind(),
            produce.path(),
            unit.root_command_sequence_no(),
            producer_cwd,
            home,
            depth + 1,
            &base_bindings,
        ) {
            return Some(content);
        }
    }

    None
}

fn producer_base_bindings(
    session: QuerySession<'_>,
    unit: ExecutionUnitRef<'_>,
) -> SessionBindings {
    let bindings = SessionBindings::from_session_summary(session.summary());
    let Some(command) = unit.top_level() else {
        return bindings;
    };
    let Some(command_index) = top_level_command_index(command) else {
        return bindings;
    };
    let Some(raw_text) =
        request_anchor_raw_text(session, command.session_id(), command.sequence_no())
    else {
        return bindings;
    };
    let Ok(parsed) = caushell_parse::parse_command(raw_text, command.shell_kind()) else {
        return bindings;
    };
    let Some(producer_command) = parsed_command_for_top_level_index(&parsed, command_index)
        .or_else(|| {
            parsed.commands.iter().find(|candidate| {
                raw_text
                    .get(candidate.span.start_byte..candidate.span.end_byte)
                    .is_some_and(|text| text.trim() == command.raw_text().trim())
            })
        })
    else {
        return bindings;
    };

    let bindings = apply_visible_variable_bindings_before_span(
        bindings,
        &parsed,
        producer_command.span.start_byte,
        command.sequence_no(),
    );

    let Some(prelude) = raw_text.get(..producer_command.span.start_byte) else {
        return bindings;
    };
    let Ok(prelude_parsed) = caushell_parse::parse_command(prelude, command.shell_kind()) else {
        return bindings;
    };
    apply_visible_variable_bindings_before_span(
        bindings,
        &prelude_parsed,
        usize::MAX,
        command.sequence_no(),
    )
}

fn parsed_command_for_top_level_index(
    parsed: &ParsedCommandArtifact,
    command_index: usize,
) -> Option<&CommandFact> {
    let mut entries = Vec::new();
    for (index, command) in parsed.commands.iter().enumerate() {
        entries.push((command.span.start_byte, command.span.end_byte, Some(index)));
    }
    for assignment in &parsed.assignment_commands {
        entries.push((assignment.span.start_byte, assignment.span.end_byte, None));
    }

    entries.sort_by_key(|(start_byte, end_byte, _)| (*start_byte, *end_byte));
    let (_, _, parsed_command_index) = entries.get(command_index)?;
    parsed_command_index.and_then(|index| parsed.commands.get(index))
}

fn request_anchor_raw_text<'a>(
    session: QuerySession<'a>,
    session_id: &SessionId,
    sequence_no: CommandSequenceNo,
) -> Option<&'a str> {
    let node_id = caushell_runner::request_anchor_node_id_for(session_id, sequence_no);
    let node = session.graph().get_node(&node_id)?;
    match &node.kind {
        NodeKind::RequestAnchor { raw_text, .. } => Some(raw_text.as_str()),
        _ => None,
    }
}

fn top_level_command_index(command: CommandInvocationRef<'_>) -> Option<usize> {
    let prefix = format!(
        "command:{}:{}:",
        command.session_id().0,
        command.sequence_no().0
    );
    command.node_id().0.strip_prefix(&prefix)?.parse().ok()
}

pub(crate) fn static_stdout_payloads_for_process_substitution_text(
    session: QuerySession<'_>,
    text: &str,
    shell_kind: caushell_types::ShellKind,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Vec<String> {
    if remaining_depth == 0 {
        return Vec::new();
    }

    let Ok(substitutions) = caushell_parse::parse_process_substitutions(text, shell_kind) else {
        return Vec::new();
    };
    let mut payloads = Vec::new();

    for substitution in substitutions {
        let Ok(parsed_substitution) =
            caushell_parse::parse_command(&substitution.body_text, shell_kind)
        else {
            continue;
        };
        let mut child_payloads = Vec::new();

        for (command_index, _) in parsed_substitution.commands.iter().enumerate() {
            child_payloads.extend(static_stdout_payloads_for_scoped_command(
                session,
                &parsed_substitution,
                command_index,
                sequence_no,
                bindings,
                bindings,
                cwd,
                home,
                remaining_depth.saturating_sub(1),
            ));
        }

        if !child_payloads.is_empty() {
            payloads.push(child_payloads.join(""));
        }
    }

    payloads
}

fn literal_content_written_by_command(
    session: QuerySession<'_>,
    raw_text: &str,
    shell_kind: caushell_types::ShellKind,
    target_path: &str,
    write_sequence: CommandSequenceNo,
    cwd: &str,
    home: Option<&str>,
    depth: usize,
    base_bindings: &SessionBindings,
) -> Option<String> {
    if let Some(content) =
        literal_heredoc_write_from_raw(raw_text, target_path, cwd, home, base_bindings)
    {
        return Some(content);
    }

    let parsed = caushell_parse::parse_command(raw_text, shell_kind).ok()?;

    for (command_index, command) in parsed.commands.iter().enumerate() {
        let bindings = apply_visible_variable_bindings_before_span(
            base_bindings.clone(),
            &parsed,
            command.span.start_byte,
            write_sequence,
        );
        if let Some(content) = literal_content_written_by_scoped_command(
            session,
            &parsed,
            command_index,
            target_path,
            write_sequence,
            &bindings,
            base_bindings,
            cwd,
            home,
            depth,
        ) {
            return Some(content);
        }
    }

    None
}

fn literal_content_written_by_scoped_command(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    target_path: &str,
    write_sequence: CommandSequenceNo,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    depth: usize,
) -> Option<String> {
    let command = parsed.commands.get(command_index)?;
    match command.command_name.as_deref() {
        Some("printf" | "echo") => {
            if command_writes_path(parsed, command_index, target_path, cwd, home, bindings) {
                return static_literal_stdout_payloads_for_command(command, bindings)
                    .into_iter()
                    .next();
            }
        }
        Some("cat") => {
            if command_writes_path(parsed, command_index, target_path, cwd, home, bindings) {
                return cat_literal_payload_or_source_content(
                    session,
                    parsed,
                    command_index,
                    write_sequence,
                    bindings,
                    scope_base_bindings,
                    cwd,
                    home,
                    depth,
                );
            }
        }
        Some("cp" | "mv") => {
            return copy_or_move_source_content(
                session,
                parsed,
                command_index,
                target_path,
                write_sequence,
                bindings,
                scope_base_bindings,
                cwd,
                home,
                depth,
            );
        }
        _ => {}
    }

    None
}

fn literal_heredoc_write_from_raw(
    raw_text: &str,
    target_path: &str,
    cwd: &str,
    home: Option<&str>,
    bindings: &SessionBindings,
) -> Option<String> {
    let (first_line, body) = raw_text.split_once('\n')?;
    if !first_line.trim_start().starts_with("cat ") {
        return None;
    }

    let delimiter_token = token_after_operator(first_line, "<<")?;
    let delimiter = delimiter_token
        .trim_matches('\'')
        .trim_matches('"')
        .to_string();
    if delimiter.is_empty() {
        return None;
    }

    let redirect_target_token = token_after_operator(first_line, ">")?;
    let redirect_target = resolve_materialized_path_operand(
        redirect_target_token,
        false,
        "word",
        cwd,
        home,
        bindings,
    )?;
    if redirect_target != target_path {
        return None;
    }

    let mut lines = Vec::new();
    for line in body.lines() {
        if line == delimiter {
            return Some(lines.join("\n"));
        }
        lines.push(line);
    }

    None
}

fn token_after_operator<'a>(line: &'a str, operator: &str) -> Option<&'a str> {
    let start = line.find(operator)? + operator.len();
    let rest = line[start..].trim_start();
    if rest.starts_with(operator) {
        return None;
    }
    rest.split_whitespace().next()
}

fn command_writes_path(
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    target_path: &str,
    cwd: &str,
    home: Option<&str>,
    bindings: &SessionBindings,
) -> bool {
    parsed.redirections.iter().any(|redirection| {
        redirection_parent_command_index(parsed, redirection) == Some(command_index)
            && redirection
                .operator
                .as_deref()
                .is_some_and(is_file_write_redirection_operator)
            && redirection.target.as_ref().is_some_and(|target| {
                resolve_materialized_path_operand(
                    &target.text,
                    target.quoted,
                    &target.node_kind,
                    cwd,
                    home,
                    bindings,
                )
                .as_deref()
                    == Some(target_path)
            })
    })
}

fn stdin_payloads_for_command(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Vec<String> {
    parsed
        .redirections
        .iter()
        .filter(|redirection| {
            redirection_parent_command_index(parsed, redirection) == Some(command_index)
                && redirection_targets_stdin_payload(redirection)
        })
        .filter_map(|redirection| {
            static_inline_stdin_payload(
                session,
                parsed.shell_kind,
                redirection,
                sequence_no,
                bindings,
                cwd,
                home,
                remaining_depth,
            )
        })
        .collect()
}

fn static_inline_stdin_payload(
    session: QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    redirection: &caushell_parse::RedirectionFact,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Option<String> {
    let content = redirection.content.as_ref()?;
    match redirection.kind {
        RedirectionKind::HereString if content.quoted => Some(content.text.clone()),
        RedirectionKind::HereString => materialize_unquoted_herestring_content(
            session,
            shell_kind,
            &content.text,
            sequence_no,
            bindings,
            cwd,
            home,
            remaining_depth,
        ),
        RedirectionKind::HereDoc
            if redirection
                .heredoc_start
                .as_ref()
                .is_some_and(|start| start.quoted) =>
        {
            Some(content.text.clone())
        }
        RedirectionKind::HereDoc => materialize_unquoted_heredoc_content(
            session,
            shell_kind,
            &content.text,
            sequence_no,
            bindings,
            cwd,
            home,
            remaining_depth,
        ),
        RedirectionKind::File => None,
    }
}

fn materialize_unquoted_heredoc_content(
    session: QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    text: &str,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Option<String> {
    let mut rendered = String::with_capacity(text.len());

    for line in text.split_inclusive('\n') {
        let (body, newline) = line
            .strip_suffix('\n')
            .map(|body| (body, "\n"))
            .unwrap_or((line, ""));
        rendered.push_str(&materialize_unquoted_heredoc_line(
            session,
            shell_kind,
            body,
            sequence_no,
            bindings,
            cwd,
            home,
            remaining_depth,
        )?);
        rendered.push_str(newline);
    }

    Some(rendered)
}

fn materialize_unquoted_heredoc_line(
    session: QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    line: &str,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Option<String> {
    let rendered = materialize_static_command_substitutions_for_text(
        line,
        session,
        shell_kind,
        sequence_no,
        bindings,
        cwd,
        home,
        remaining_depth,
    )?;

    is_static_unquoted_inline_shell_text(&rendered).then_some(rendered)
}

fn materialize_unquoted_herestring_content(
    session: QuerySession<'_>,
    shell_kind: caushell_types::ShellKind,
    text: &str,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Option<String> {
    let rendered = materialize_static_command_substitutions_for_text(
        text,
        session,
        shell_kind,
        sequence_no,
        bindings,
        cwd,
        home,
        remaining_depth,
    )?;

    let unescaped = unescape_static_unquoted_shell_word(&rendered)?;
    is_static_unquoted_inline_shell_text(&unescaped).then_some(unescaped)
}

fn is_static_unquoted_inline_shell_text(text: &str) -> bool {
    !text.contains('\\') && !contains_unescaped_dynamic_shell_syntax(text)
}

fn unescape_static_unquoted_shell_word(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            if matches!(ch, '$' | '`') {
                return None;
            }
            out.push(ch);
            continue;
        }

        let escaped = chars.next()?;
        if escaped == '\n' {
            continue;
        }
        out.push(escaped);
    }

    Some(out)
}

fn contains_unescaped_dynamic_shell_syntax(text: &str) -> bool {
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if matches!(ch, '$' | '`') {
            return true;
        }
    }

    escaped
}

fn file_stdin_payloads_for_command(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
) -> Vec<String> {
    parsed
        .redirections
        .iter()
        .filter(|redirection| {
            redirection_parent_command_index(parsed, redirection) == Some(command_index)
                && redirection.kind == RedirectionKind::File
                && redirection.operator.as_deref() == Some("<")
                && redirection_targets_stdin_payload(redirection)
        })
        .filter_map(|redirection| {
            let target = redirection.target.as_ref()?;
            if target.node_kind == "process_substitution" {
                return None;
            }
            let path = resolve_materialized_path_operand(
                &target.text,
                target.quoted,
                &target.node_kind,
                cwd,
                home,
                bindings,
            )?;
            known_literal_path_content_before_scoped_command_with_depth(
                session,
                parsed,
                command_index,
                &path,
                sequence_no,
                scope_base_bindings,
                cwd,
                home,
                0,
            )
            .or_else(|| {
                known_literal_path_content_before_sequence(session, &path, sequence_no, cwd, home)
            })
        })
        .collect()
}

fn process_substitution_stdin_payloads_for_command(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    sequence_no: CommandSequenceNo,
    bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    remaining_depth: u8,
) -> Vec<String> {
    parsed
        .redirections
        .iter()
        .filter(|redirection| {
            redirection_parent_command_index(parsed, redirection) == Some(command_index)
                && redirection_targets_stdin_payload(redirection)
                && redirection
                    .target
                    .as_ref()
                    .is_some_and(|target| target.node_kind == "process_substitution")
        })
        .flat_map(|redirection| {
            redirection.target.as_ref().into_iter().flat_map(|target| {
                static_stdout_payloads_for_process_substitution_text(
                    session,
                    &target.text,
                    parsed.shell_kind,
                    sequence_no,
                    bindings,
                    cwd,
                    home,
                    remaining_depth,
                )
            })
        })
        .collect()
}

fn pipeline_upstream_by_consumer(parsed: &ParsedCommandArtifact) -> BTreeMap<usize, usize> {
    let mut upstream = BTreeMap::new();

    for group in super::pipeline::collect_pipeline_groups(parsed) {
        for pair in group.commands.windows(2) {
            let [producer, consumer] = pair else {
                continue;
            };
            upstream.insert(consumer.command_index, producer.command_index);
        }
    }

    upstream
}

fn cat_literal_payload_or_source_content(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    write_sequence: CommandSequenceNo,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    depth: usize,
) -> Option<String> {
    let command = parsed.commands.get(command_index)?;
    let args = arg_tokens(command);
    if args.is_empty() {
        let payloads: Vec<String> = parsed
            .redirections
            .iter()
            .filter(|redirection| {
                redirection_parent_command_index(parsed, redirection) == Some(command_index)
                    && redirection_targets_stdin_payload(redirection)
            })
            .filter_map(|redirection| {
                redirection
                    .content
                    .as_ref()
                    .map(|content| content.text.clone())
            })
            .collect();
        return (!payloads.is_empty()).then(|| payloads.join("\n"));
    }

    if args.len() == 1 {
        let source_path = resolve_materialized_path_operand(
            &args[0].text,
            args[0].quoted,
            &args[0].node_kind,
            cwd,
            home,
            bindings,
        )?;
        if let Some(content) = known_literal_path_content_before_scoped_command_with_depth(
            session,
            parsed,
            command_index,
            &source_path,
            write_sequence,
            scope_base_bindings,
            cwd,
            home,
            depth,
        ) {
            return Some(content);
        }
        return known_literal_path_content_before_sequence_with_depth(
            session,
            &source_path,
            write_sequence,
            cwd,
            home,
            depth,
        );
    }

    None
}

fn copy_or_move_source_content(
    session: QuerySession<'_>,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    target_path: &str,
    write_sequence: CommandSequenceNo,
    bindings: &SessionBindings,
    scope_base_bindings: &SessionBindings,
    cwd: &str,
    home: Option<&str>,
    depth: usize,
) -> Option<String> {
    let command = parsed.commands.get(command_index)?;
    let args = arg_tokens(command);
    if args.len() != 2 {
        return None;
    }

    let source_path = resolve_materialized_path_operand(
        &args[0].text,
        args[0].quoted,
        &args[0].node_kind,
        cwd,
        home,
        bindings,
    )?;
    let destination_path = resolve_materialized_path_operand(
        &args[1].text,
        args[1].quoted,
        &args[1].node_kind,
        cwd,
        home,
        bindings,
    )?;
    if destination_path != target_path {
        return None;
    }

    if let Some(content) = known_literal_path_content_before_scoped_command_with_depth(
        session,
        parsed,
        command_index,
        &source_path,
        write_sequence,
        scope_base_bindings,
        cwd,
        home,
        depth,
    ) {
        return Some(content);
    }

    known_literal_path_content_before_sequence_with_depth(
        session,
        &source_path,
        write_sequence,
        cwd,
        home,
        depth,
    )
}

fn resolve_materialized_path_operand(
    text: &str,
    quoted: bool,
    node_kind: &str,
    cwd: &str,
    home: Option<&str>,
    bindings: &SessionBindings,
) -> Option<String> {
    let materialized = materialize_token_text(text, bindings);
    let node_kind = if materialized != text {
        "word"
    } else {
        node_kind
    };
    resolve_path_operand(&materialized, quoted, node_kind, cwd, home)
}

fn arg_tokens(command: &CommandFact) -> Vec<&caushell_parse::CommandToken> {
    command
        .tokens
        .iter()
        .filter(|token| token.kind == CommandTokenKind::Arg)
        .collect()
}

fn printf_literal_payloads(command: &CommandFact, bindings: &SessionBindings) -> Vec<String> {
    let args: Vec<String> = command
        .tokens
        .iter()
        .filter(|token| token.kind == CommandTokenKind::Arg)
        .map(|token| materialize_token_text(&token.text, bindings))
        .collect();
    if args.is_empty() {
        return Vec::new();
    }

    render_static_printf_payload(&args[0], &args[1..])
        .into_iter()
        .collect()
}

fn echo_literal_payload(command: &CommandFact, bindings: &SessionBindings) -> Option<String> {
    let mut decode_escapes = false;
    let mut segments = Vec::new();

    for token in &command.tokens {
        match token.kind {
            CommandTokenKind::Flag => match token.text.as_str() {
                "-e" => decode_escapes = true,
                "-n" | "-E" => {}
                _ => return None,
            },
            CommandTokenKind::Arg => {
                let text = materialize_token_text(&token.text, bindings);
                if decode_escapes {
                    let decoded = decode_printf_escapes_with_control(&text);
                    segments.push(decoded.text);
                    if decoded.stopped {
                        break;
                    }
                } else {
                    segments.push(text);
                }
            }
            CommandTokenKind::DashDash => {}
        }
    }

    (!segments.is_empty()).then(|| segments.join(" "))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticPrintfPiece {
    StringArgument,
    EscapedStringArgument,
}

fn render_static_printf_payload(format: &str, args: &[String]) -> Option<String> {
    let format = parse_static_printf_format(format)?;
    let conversion_count = format
        .pieces
        .iter()
        .filter(|piece| matches!(piece, StaticPrintfFormatPiece::Conversion(_)))
        .count();

    if conversion_count == 0 {
        return Some(format.render(args, 0).rendered);
    }

    let mut rendered = String::new();
    let mut arg_index = 0usize;

    loop {
        let chunk = format.render(args, arg_index);
        let stopped = chunk.stopped;
        arg_index = chunk.next_arg_index;
        rendered.push_str(&chunk.rendered);

        if stopped || arg_index >= args.len() {
            break;
        }
    }

    Some(rendered)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StaticPrintfFormatPiece {
    Literal(String),
    Stop,
    Conversion(StaticPrintfPiece),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticPrintfFormat {
    pieces: Vec<StaticPrintfFormatPiece>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticPrintfRenderedChunk {
    rendered: String,
    next_arg_index: usize,
    stopped: bool,
}

impl StaticPrintfFormat {
    fn render(&self, args: &[String], mut arg_index: usize) -> StaticPrintfRenderedChunk {
        let mut rendered = String::new();

        for piece in &self.pieces {
            match piece {
                StaticPrintfFormatPiece::Literal(text) => rendered.push_str(text),
                StaticPrintfFormatPiece::Stop => {
                    return StaticPrintfRenderedChunk {
                        rendered,
                        next_arg_index: arg_index,
                        stopped: true,
                    };
                }
                StaticPrintfFormatPiece::Conversion(StaticPrintfPiece::StringArgument) => {
                    if let Some(arg) = args.get(arg_index) {
                        rendered.push_str(arg);
                    }
                    arg_index = arg_index.saturating_add(1);
                }
                StaticPrintfFormatPiece::Conversion(StaticPrintfPiece::EscapedStringArgument) => {
                    if let Some(arg) = args.get(arg_index) {
                        let decoded = decode_printf_escapes_with_control(arg);
                        rendered.push_str(&decoded.text);
                        arg_index = arg_index.saturating_add(1);
                        if decoded.stopped {
                            return StaticPrintfRenderedChunk {
                                rendered,
                                next_arg_index: arg_index,
                                stopped: true,
                            };
                        }
                        continue;
                    }
                    arg_index = arg_index.saturating_add(1);
                }
            }
        }

        StaticPrintfRenderedChunk {
            rendered,
            next_arg_index: arg_index,
            stopped: false,
        }
    }
}

fn parse_static_printf_format(format: &str) -> Option<StaticPrintfFormat> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut chars = format.chars();

    while let Some(ch) = chars.next() {
        if ch != '%' {
            literal.push(ch);
            continue;
        }

        let conversion = chars.next()?;
        match conversion {
            '%' => literal.push('%'),
            's' => {
                if flush_static_printf_literal(&mut pieces, &mut literal) {
                    return Some(StaticPrintfFormat { pieces });
                }
                pieces.push(StaticPrintfFormatPiece::Conversion(
                    StaticPrintfPiece::StringArgument,
                ));
            }
            'b' => {
                if flush_static_printf_literal(&mut pieces, &mut literal) {
                    return Some(StaticPrintfFormat { pieces });
                }
                pieces.push(StaticPrintfFormatPiece::Conversion(
                    StaticPrintfPiece::EscapedStringArgument,
                ));
            }
            _ => return None,
        }
    }

    flush_static_printf_literal(&mut pieces, &mut literal);
    Some(StaticPrintfFormat { pieces })
}

fn flush_static_printf_literal(
    pieces: &mut Vec<StaticPrintfFormatPiece>,
    literal: &mut String,
) -> bool {
    if literal.is_empty() {
        return false;
    }

    let decoded = decode_printf_escapes_with_control(literal);
    if !decoded.text.is_empty() {
        pieces.push(StaticPrintfFormatPiece::Literal(decoded.text));
    }
    if decoded.stopped {
        pieces.push(StaticPrintfFormatPiece::Stop);
    }
    literal.clear();
    decoded.stopped
}

fn materialize_token_text(text: &str, bindings: &SessionBindings) -> String {
    if let Some(value) = exact_scalar_shell_parameter_reference_value(text, bindings) {
        return value;
    }

    text.to_string()
}

fn shell_command_payload_arg_index(args: &[String]) -> Option<usize> {
    for (index, arg) in args.iter().enumerate() {
        if arg == "-c" {
            return Some(index + 1);
        }

        if !arg.starts_with('-') || arg == "--" {
            break;
        }

        if let Some(cluster) = arg.strip_prefix('-') {
            if !arg.starts_with("--")
                && cluster.len() > 1
                && cluster.chars().all(|ch| ch.is_ascii_alphabetic())
                && cluster.contains('c')
            {
                return Some(index + 1);
            }
        }
    }

    None
}

fn substitute_shell_positional_parameters(payload: &str, trailing_args: &[String]) -> String {
    let mut out = String::with_capacity(payload.len());
    let chars: Vec<char> = payload.chars().collect();
    let mut index = 0usize;
    let mut quote = StaticShellQuote::None;

    while index < chars.len() {
        match quote {
            StaticShellQuote::None => match chars[index] {
                '\'' => {
                    quote = StaticShellQuote::Single;
                    out.push(chars[index]);
                    index += 1;
                    continue;
                }
                '"' => {
                    quote = StaticShellQuote::Double;
                    out.push(chars[index]);
                    index += 1;
                    continue;
                }
                '\\' => {
                    out.push(chars[index]);
                    index += 1;
                    if index < chars.len() {
                        out.push(chars[index]);
                        index += 1;
                    }
                    continue;
                }
                '$' => {}
                _ => {
                    out.push(chars[index]);
                    index += 1;
                    continue;
                }
            },
            StaticShellQuote::Single => {
                if chars[index] == '\'' {
                    quote = StaticShellQuote::None;
                }
                out.push(chars[index]);
                index += 1;
                continue;
            }
            StaticShellQuote::Double => match chars[index] {
                '"' => {
                    quote = StaticShellQuote::None;
                    out.push(chars[index]);
                    index += 1;
                    continue;
                }
                '\\' => {
                    out.push(chars[index]);
                    index += 1;
                    if index < chars.len() {
                        out.push(chars[index]);
                        index += 1;
                    }
                    continue;
                }
                '$' => {}
                _ => {
                    out.push(chars[index]);
                    index += 1;
                    continue;
                }
            },
        }

        if let Some((consumed, reference)) = parse_shell_positional_reference(&chars[index..]) {
            if let Some(replacement) = shell_positional_replacement(reference, trailing_args, quote)
            {
                out.push_str(&replacement);
                index += consumed;
                continue;
            }
        }

        out.push(chars[index]);
        index += 1;
    }

    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticShellQuote {
    None,
    Single,
    Double,
}

fn unquote_static_shell_arg(text: &str) -> Option<String> {
    if text.len() < 2 {
        return None;
    }

    if let Some(unquoted) = unquote_concatenated_single_quoted_arg(text) {
        return Some(unquoted);
    }

    if text.starts_with('\'') && text.ends_with('\'') {
        return Some(text[1..text.len() - 1].replace("'\"'\"'", "'"));
    }

    if text.starts_with('"') && text.ends_with('"') {
        let mut out = String::with_capacity(text.len().saturating_sub(2));
        let mut chars = text[1..text.len() - 1].chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                } else {
                    out.push(ch);
                }
            } else {
                out.push(ch);
            }
        }
        return Some(out);
    }

    None
}

fn unquote_concatenated_single_quoted_arg(text: &str) -> Option<String> {
    if !text.starts_with('\'') {
        return None;
    }

    let mut rest = text;
    let mut out = String::new();

    while !rest.is_empty() {
        let quoted = rest.strip_prefix('\'')?;
        let end = quoted.find('\'')?;
        out.push_str(&quoted[..end]);
        rest = &quoted[end + 1..];

        if rest.is_empty() {
            return Some(out);
        }

        if let Some(next) = rest.strip_prefix("\"'\"") {
            out.push('\'');
            rest = next;
        } else {
            return None;
        }
    }

    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticShellPositionalReference {
    Position(usize),
    AllAt,
    AllStar,
}

fn parse_shell_positional_reference(
    chars: &[char],
) -> Option<(usize, StaticShellPositionalReference)> {
    if chars.len() < 2 || chars[0] != '$' {
        return None;
    }

    if chars[1] == '{' {
        if chars.get(3) == Some(&'}') {
            return match chars.get(2) {
                Some('@') => Some((4, StaticShellPositionalReference::AllAt)),
                Some('*') => Some((4, StaticShellPositionalReference::AllStar)),
                _ => None,
            };
        }

        let mut end = 2usize;
        while end < chars.len() && chars[end].is_ascii_digit() {
            end += 1;
        }
        if end == 2 || chars.get(end) != Some(&'}') {
            return None;
        }
        let position = chars[2..end]
            .iter()
            .collect::<String>()
            .parse::<usize>()
            .ok()?;
        return Some((end + 1, StaticShellPositionalReference::Position(position)));
    }

    if chars[1] == '@' {
        return Some((2, StaticShellPositionalReference::AllAt));
    }
    if chars[1] == '*' {
        return Some((2, StaticShellPositionalReference::AllStar));
    }

    if !chars[1].is_ascii_digit() {
        return None;
    }

    let mut end = 1usize;
    while end < chars.len() && chars[end].is_ascii_digit() {
        end += 1;
    }
    let position = chars[1..end]
        .iter()
        .collect::<String>()
        .parse::<usize>()
        .ok()?;
    Some((end, StaticShellPositionalReference::Position(position)))
}

fn shell_positional_replacement(
    reference: StaticShellPositionalReference,
    trailing_args: &[String],
    quote: StaticShellQuote,
) -> Option<String> {
    match reference {
        StaticShellPositionalReference::Position(position) => {
            let value = shell_positional_value(position, trailing_args);
            Some(match quote {
                StaticShellQuote::Double => escape_double_quoted_shell_text(&value),
                StaticShellQuote::None => value,
                StaticShellQuote::Single => return None,
            })
        }
        StaticShellPositionalReference::AllAt => {
            let values = shell_all_positional_values(trailing_args);
            Some(match quote {
                StaticShellQuote::Double => values
                    .iter()
                    .map(|value| escape_double_quoted_shell_text(value))
                    .collect::<Vec<_>>()
                    .join("\" \""),
                StaticShellQuote::None => values
                    .iter()
                    .map(|value| shell_single_quote_word(value))
                    .collect::<Vec<_>>()
                    .join(" "),
                StaticShellQuote::Single => return None,
            })
        }
        StaticShellPositionalReference::AllStar => {
            let value = shell_all_positional_values(trailing_args).join(" ");
            Some(match quote {
                StaticShellQuote::Double => escape_double_quoted_shell_text(&value),
                StaticShellQuote::None => shell_all_positional_values(trailing_args)
                    .iter()
                    .map(|value| shell_single_quote_word(value))
                    .collect::<Vec<_>>()
                    .join(" "),
                StaticShellQuote::Single => return None,
            })
        }
    }
}

fn shell_positional_value(position: usize, trailing_args: &[String]) -> String {
    trailing_args.get(position).cloned().unwrap_or_default()
}

fn shell_all_positional_values(trailing_args: &[String]) -> Vec<String> {
    trailing_args.iter().skip(1).cloned().collect()
}

fn escape_double_quoted_shell_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '"' | '\\' | '$' | '`') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn shell_single_quote_word(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedPrintfEscapes {
    text: String,
    stopped: bool,
}

fn decode_printf_escapes_with_control(text: &str) -> DecodedPrintfEscapes {
    let mut decoded = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut stopped = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let Some(escape) = chars.next() else {
            decoded.push('\\');
            break;
        };
        match escape {
            'a' => decoded.push('\u{0007}'),
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{000b}'),
            '\\' => decoded.push('\\'),
            'c' => {
                stopped = true;
                break;
            }
            'x' => {
                if let Some(value) = consume_hex_escape(&mut chars) {
                    push_u8(&mut decoded, value);
                } else {
                    decoded.push('x');
                }
            }
            '0'..='7' => {
                let value = consume_octal_escape(escape, &mut chars);
                push_u8(&mut decoded, value);
            }
            other => decoded.push(other),
        }
    }

    DecodedPrintfEscapes {
        text: decoded,
        stopped,
    }
}

fn consume_hex_escape<I>(chars: &mut std::iter::Peekable<I>) -> Option<u8>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u16;
    let mut consumed = 0usize;

    while consumed < 2 {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        let Some(digit) = next.to_digit(16) else {
            break;
        };
        chars.next();
        value = (value << 4) | digit as u16;
        consumed += 1;
    }

    (consumed > 0 && value <= u8::MAX as u16).then_some(value as u8)
}

fn consume_octal_escape<I>(first: char, chars: &mut std::iter::Peekable<I>) -> u8
where
    I: Iterator<Item = char>,
{
    let mut value = first.to_digit(8).unwrap_or_default() as u16;
    let mut consumed = 0usize;

    while consumed < 2 {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        let Some(digit) = next.to_digit(8) else {
            break;
        };
        chars.next();
        value = (value << 3) | digit as u16;
        consumed += 1;
    }

    value.min(u8::MAX as u16) as u8
}

fn push_u8(decoded: &mut String, value: u8) {
    decoded.push(char::from(value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_printf_payload_renders_string_format_with_literal_escape() {
        let args = vec!["/".to_string()];

        assert_eq!(
            render_static_printf_payload("%s\\n", &args),
            Some("/\n".to_string())
        );
    }

    #[test]
    fn static_printf_payload_reuses_format_until_arguments_are_consumed() {
        let args = vec!["one".to_string(), "two".to_string()];

        assert_eq!(
            render_static_printf_payload("%s\\n", &args),
            Some("one\ntwo\n".to_string())
        );
    }

    #[test]
    fn static_printf_payload_keeps_literal_only_format_compatible() {
        assert_eq!(
            render_static_printf_payload("/\\n", &[]),
            Some("/\n".to_string())
        );
    }

    #[test]
    fn static_printf_payload_stops_at_format_control_escape() {
        let args = vec!["/".to_string(), "ignored".to_string()];

        assert_eq!(
            render_static_printf_payload("%s\\c%s", &args),
            Some("/".to_string())
        );
    }

    #[test]
    fn static_printf_payload_stops_at_escaped_string_control_escape() {
        let args = vec!["/\\c".to_string(), "ignored".to_string()];

        assert_eq!(
            render_static_printf_payload("%b%s", &args),
            Some("/".to_string())
        );
    }

    #[test]
    fn static_printf_payload_declines_complex_formats() {
        let args = vec!["/".to_string()];

        assert_eq!(render_static_printf_payload("%10s\\n", &args), None);
        assert_eq!(render_static_printf_payload("%d\\n", &args), None);
    }

    #[test]
    fn shell_payload_substitutes_quoted_all_positional_parameters_as_fields() {
        let trailing_args = vec!["runner".to_string(), "/".to_string(), "/etc".to_string()];

        assert_eq!(
            substitute_shell_positional_parameters(r#"rm -rf "$@""#, &trailing_args),
            r#"rm -rf "/" "/etc""#
        );
    }

    #[test]
    fn shell_payload_substitutes_quoted_star_positional_parameters_as_one_field() {
        let trailing_args = vec!["runner".to_string(), "/".to_string(), "/etc".to_string()];

        assert_eq!(
            substitute_shell_positional_parameters(r#"rm -rf "$*""#, &trailing_args),
            r#"rm -rf "/ /etc""#
        );
    }

    #[test]
    fn shell_payload_substitutes_braced_all_positional_parameters() {
        let trailing_args = vec!["runner".to_string(), "/".to_string(), "/etc".to_string()];

        assert_eq!(
            substitute_shell_positional_parameters(r#"rm -rf "${@}""#, &trailing_args),
            r#"rm -rf "/" "/etc""#
        );
    }
}

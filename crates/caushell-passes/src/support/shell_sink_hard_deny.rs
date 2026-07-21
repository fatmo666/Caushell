use caushell_parse::{ParsedCommandArtifact, RedirectionKind};

use crate::support::redirection_parent_command_index;
use crate::support::{
    HostTargetOperand, block_device_write_reason_for_redirection_with_optional_cwd,
};

pub(crate) fn collect_bare_shell_sink_hard_deny_reasons(
    parsed: &ParsedCommandArtifact,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Vec<String> {
    parsed
        .redirections
        .iter()
        .filter(|redirection| redirection_parent_command_index(parsed, redirection).is_none())
        .filter_map(|redirection| shell_sink_hard_deny_reason(redirection, cwd, home))
        .collect()
}

pub(crate) fn collect_shell_sink_hard_deny_reasons_for_command(
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Vec<String> {
    parsed
        .redirections
        .iter()
        .filter(|redirection| {
            redirection_parent_command_index(parsed, redirection) == Some(command_index)
        })
        .filter_map(|redirection| shell_sink_hard_deny_reason(redirection, cwd, home))
        .collect()
}

fn shell_sink_hard_deny_reason(
    redirection: &caushell_parse::RedirectionFact,
    cwd: Option<&str>,
    home: Option<&str>,
) -> Option<String> {
    if redirection.kind != RedirectionKind::File {
        return None;
    }

    let operator = redirection.operator.as_deref()?;
    if !is_file_write_redirection_operator(operator) {
        return None;
    }

    let target = redirection.target.as_ref()?;
    block_device_write_reason_for_redirection_with_optional_cwd(
        HostTargetOperand {
            text: target.text.trim(),
            quoted: target.quoted,
            node_kind: target.node_kind.as_str(),
        },
        cwd,
        home,
    )
}

pub(crate) fn is_file_write_redirection_operator(operator: &str) -> bool {
    matches!(operator, ">" | ">>" | ">|" | "&>" | "&>>")
}

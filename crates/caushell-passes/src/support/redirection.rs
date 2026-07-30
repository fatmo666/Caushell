use caushell_parse::{RedirectionFact, RedirectionKind};

pub(crate) fn file_descriptor_targets_stdin(file_descriptor: Option<&str>) -> bool {
    matches!(file_descriptor, None | Some("0"))
}

pub(crate) fn redirection_targets_stdin_payload(redirection: &RedirectionFact) -> bool {
    if !file_descriptor_targets_stdin(redirection.file_descriptor.as_deref()) {
        return false;
    }

    match redirection.kind {
        RedirectionKind::File => redirection
            .operator
            .as_deref()
            .is_some_and(|operator| matches!(operator, "<" | "<&")),
        RedirectionKind::HereString | RedirectionKind::HereDoc => true,
    }
}

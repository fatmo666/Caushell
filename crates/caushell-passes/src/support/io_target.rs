use std::collections::BTreeMap;

use caushell_parse::ParsedCommandArtifact;
use caushell_profile::{
    BoundInvocation, EffectKind, EffectTarget, PathAccessKind, ResolveInvocationArtifactResult,
};
use caushell_query::{IoTarget, IoTargetQuery};
use caushell_types::PathResolution;

use super::redirection_parent_command_index;
use crate::path::{derived_path_slot_name, path_operand_depends_on_cwd, resolve_path_operand};

pub(crate) fn bound_invocation(
    result: &ResolveInvocationArtifactResult,
) -> Option<&BoundInvocation> {
    match result {
        ResolveInvocationArtifactResult::Resolved(resolved) => Some(&resolved.bound),
        ResolveInvocationArtifactResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => Some(bound),
        _ => None,
    }
}

/// An effect must explicitly describe content opening. A namespace effect on
/// the same slot cannot be erased by another annotated effect.
pub(crate) fn slot_uses_content_open(
    bound: &BoundInvocation,
    slot: &str,
    kind: EffectKind,
) -> bool {
    let mut found = false;
    for (index, effect) in bound.effects.iter().enumerate() {
        let matches_slot = match &effect.target {
            EffectTarget::Slot(name) => name.as_str() == slot,
            EffectTarget::DerivedPath(_) => derived_path_slot_name(index) == slot,
            _ => false,
        };
        if effect.kind != kind || !matches_slot {
            continue;
        }
        if effect.path_access != Some(PathAccessKind::ContentOpen) {
            return false;
        }
        found = true;
    }
    found
}

/// Build a sparse syntax-only FD snapshot only for a stream-alias candidate.
/// Redirection operands are opened before their own FD update; tool operands
/// are opened after all redirections. Never replay across shell actions.
pub(crate) fn content_io_target(
    parsed: &ParsedCommandArtifact,
    command_index: Option<usize>,
    before_redirection: Option<usize>,
    resolution: &PathResolution,
    cwd_dependent: bool,
    shell_cwd: &str,
    home: Option<&str>,
    bindings: Option<&caushell_profile::SessionBindings>,
) -> IoTarget {
    content_io_target_with_entry(
        parsed,
        command_index,
        before_redirection,
        resolution,
        cwd_dependent,
        shell_cwd,
        home,
        bindings,
        &BTreeMap::new(),
    )
}

pub(super) fn content_io_target_with_entry(
    parsed: &ParsedCommandArtifact,
    command_index: Option<usize>,
    before_redirection: Option<usize>,
    resolution: &PathResolution,
    cwd_dependent: bool,
    shell_cwd: &str,
    home: Option<&str>,
    bindings: Option<&caushell_profile::SessionBindings>,
    inherited: &BTreeMap<String, IoTarget>,
) -> IoTarget {
    let Some(path) = resolution.concrete_path() else {
        return IoTarget::Path {
            resolution: resolution.clone(),
            cwd_dependent,
        };
    };
    if path == "/dev/null" {
        return IoTarget::Discard;
    }
    if IoTargetQuery::descriptor_alias(path).is_none() {
        return IoTarget::Path {
            resolution: resolution.clone(),
            cwd_dependent,
        };
    }
    let mut snapshot = inherited.clone();
    for (index, redirection) in parsed.redirections.iter().enumerate() {
        if before_redirection.is_some_and(|stop| index >= stop) {
            break;
        }
        if redirection_parent_command_index(parsed, redirection) != command_index {
            continue;
        }
        // Unowned bare redirects belong to separate top-level actions.
        if command_index.is_none()
            && before_redirection.is_some_and(|stop| {
                redirection.top_level_span != parsed.redirections[stop].top_level_span
            })
        {
            continue;
        }
        let operator = redirection.operator.as_deref().unwrap_or_default();
        let descriptor = match redirection.file_descriptor.as_deref() {
            Some(text) => match IoTargetQuery::canonical_descriptor(text) {
                Some(fd) => fd,
                None => {
                    // A dynamic destination could replace any previously known FD.
                    for target in snapshot.values_mut() {
                        *target = IoTarget::UnknownDescriptor {
                            descriptor: text.into(),
                        };
                    }
                    for fd in ["0", "1", "2"] {
                        snapshot.insert(
                            fd.into(),
                            IoTarget::UnknownDescriptor {
                                descriptor: text.into(),
                            },
                        );
                    }
                    continue;
                }
            },
            None if operator.starts_with('<') => "0",
            None if operator.starts_with('>') || operator.starts_with('&') => "1",
            _ => continue,
        };
        let mut moved = None;
        let target = match operator {
            "<&-" | ">&-" => IoTarget::Closed,
            "<&" | ">&" => match redirection.target.as_ref().map(|token| token.text.as_str()) {
                Some("-") => IoTarget::Closed,
                Some(text) => {
                    let source = text.strip_suffix('-').unwrap_or(text);
                    if source.len() != text.len() {
                        moved = IoTargetQuery::canonical_descriptor(source);
                    }
                    IoTargetQuery::descriptor(source, &snapshot)
                }
                None => IoTarget::UnknownDescriptor {
                    descriptor: descriptor.into(),
                },
            },
            "<<" | "<<-" | "<<<" => IoTarget::InlineContent {
                redirection_index: index,
            },
            "<" | "<>" | ">" | ">>" | ">|" | "&>" | "&>>" => {
                if redirection
                    .target
                    .as_ref()
                    .is_some_and(|token| token.node_kind == "process_substitution")
                {
                    let target = IoTarget::ProcessSubstitution {
                        redirection_index: index,
                    };
                    snapshot.insert(descriptor.into(), target.clone());
                    if matches!(operator, "&>" | "&>>") {
                        snapshot.insert("2".into(), target);
                    }
                    continue;
                }
                let (resolution, dependent) = redirection.target.as_ref().map_or_else(
                    || {
                        (
                            PathResolution::UnsupportedDynamicText {
                                text: "missing redirection target".into(),
                            },
                            true,
                        )
                    },
                    |token| {
                        (
                            resolve_path_operand(
                                &token.text,
                                token.quoted,
                                &token.node_kind,
                                shell_cwd,
                                home,
                            )
                            .map(|path| PathResolution::Concrete { path })
                            .unwrap_or_else(|| {
                                PathResolution::UnsupportedDynamicText {
                                    text: token.text.clone(),
                                }
                            }),
                            path_operand_depends_on_cwd(
                                &token.text,
                                token.quoted,
                                &token.node_kind,
                                None,
                            ),
                        )
                    },
                );
                network_redirect_target(parsed, index, bindings, shell_cwd, home).unwrap_or_else(
                    || IoTargetQuery::content_path(&resolution, dependent, &snapshot),
                )
            }
            _ => continue,
        };
        if matches!(operator, "&>" | "&>>") {
            snapshot.insert("2".into(), target.clone());
        }
        snapshot.insert(descriptor.into(), target);
        if let Some(source) = moved.filter(|source| *source != descriptor) {
            snapshot.insert(source.into(), IoTarget::Closed);
        }
    }
    // Bash applies |&'s implicit stderr duplication after explicit redirections.
    // Tool operands see it; redirection operands evaluated earlier do not.
    if before_redirection.is_none()
        && command_index.is_some_and(|index| pipeline_merges_stderr(parsed, index))
    {
        let stdout = IoTargetQuery::descriptor("1", &snapshot);
        snapshot.insert("2".into(), stdout);
    }
    IoTargetQuery::content_path(resolution, cwd_dependent, &snapshot)
}

/// Same shared FD query, with concrete inherited shell-frame targets. Local
/// updates always win. No host descriptor scan and no command-specific rule.
pub(crate) fn execution_content_io_target(
    ctx: &caushell_runner::RunnerContext,
    source: &caushell_graph::NodeId,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    before_redirection: Option<usize>,
    resolution: &PathResolution,
    cwd_dependent: bool,
    shell_cwd: &str,
    home: Option<&str>,
) -> IoTarget {
    let bindings = ctx
        .execution_unit_resolve_records()
        .iter()
        .find(|record| &record.source_node_id == source)
        .map(|r| &r.bindings);
    let Some(descriptor) = resolution
        .concrete_path()
        .and_then(IoTargetQuery::descriptor_alias)
    else {
        return content_io_target(
            parsed,
            Some(command_index),
            before_redirection,
            resolution,
            cwd_dependent,
            shell_cwd,
            home,
            bindings,
        );
    };
    // Seed only referenced entry FDs, BEFORE ordered local changes. Resolving
    // an unknown final alias afterwards would confuse an earlier copy with a
    // later source reassignment (0<&3 3<other), losing the real data origin.
    let mut needed = std::collections::BTreeSet::from([descriptor]);
    for (index, redirection) in parsed.redirections.iter().enumerate() {
        if before_redirection.is_some_and(|stop| index >= stop) {
            break;
        }
        if redirection_parent_command_index(parsed, redirection) != Some(command_index) {
            continue;
        }
        let fd = redirection.target.as_ref().and_then(|token| {
            if matches!(redirection.operator.as_deref(), Some("<&" | ">&")) {
                IoTargetQuery::canonical_descriptor(
                    token.text.strip_suffix('-').unwrap_or(&token.text),
                )
            } else {
                IoTargetQuery::descriptor_alias(&token.text)
            }
        });
        if let Some(fd) = fd {
            needed.insert(fd);
        }
    }
    let mut inherited =
        super::shell_redirections::syntax_descriptor_entries(ctx, source, parsed, command_index);
    inherited.extend(
        needed
            .into_iter()
            .filter(|fd| !matches!(*fd, "0" | "1" | "2"))
            .filter_map(|fd| {
                super::shell_io_scope::inherited_shell_descriptor_target(ctx, source, fd)
                    .map(|target| (fd.into(), target))
            })
            .collect::<BTreeMap<_, _>>(),
    );
    content_io_target_with_entry(
        parsed,
        Some(command_index),
        before_redirection,
        resolution,
        cwd_dependent,
        shell_cwd,
        home,
        bindings,
        &inherited,
    )
}

/// A shell redirect opening has native syntax that an ordinary tool content
/// operand does not. FD snapshot queries remain independent of this spelling.
pub(crate) fn redirection_io_target(
    parsed: &ParsedCommandArtifact,
    command_index: Option<usize>,
    index: usize,
    resolution: &PathResolution,
    cwd_dependent: bool,
    cwd: &str,
    home: Option<&str>,
    bindings: Option<&caushell_profile::SessionBindings>,
) -> IoTarget {
    network_redirect_target(parsed, index, bindings, cwd, home).unwrap_or_else(|| {
        content_io_target(
            parsed,
            command_index,
            Some(index),
            resolution,
            cwd_dependent,
            cwd,
            home,
            bindings,
        )
    })
}

pub(crate) fn execution_redirection_io_target(
    ctx: &caushell_runner::RunnerContext,
    source: &caushell_graph::NodeId,
    parsed: &ParsedCommandArtifact,
    command_index: usize,
    index: usize,
    resolution: &PathResolution,
    cwd_dependent: bool,
    cwd: &str,
    home: Option<&str>,
) -> IoTarget {
    let bindings = ctx
        .execution_unit_resolve_records()
        .iter()
        .find(|r| &r.source_node_id == source)
        .map(|r| &r.bindings);
    network_redirect_target(parsed, index, bindings, cwd, home).unwrap_or_else(|| {
        execution_content_io_target(
            ctx,
            source,
            parsed,
            command_index,
            Some(index),
            resolution,
            cwd_dependent,
            cwd,
            home,
        )
    })
}

fn network_redirect_target(
    parsed: &ParsedCommandArtifact,
    index: usize,
    bindings: Option<&caushell_profile::SessionBindings>,
    cwd: &str,
    home: Option<&str>,
) -> Option<IoTarget> {
    if parsed.shell_kind != caushell_types::ShellKind::Bash {
        return None;
    }
    let redirect = parsed.redirections.get(index)?;
    if !matches!(
        redirect.operator.as_deref(),
        Some("<" | "<>" | ">" | ">>" | ">|" | "&>" | "&>>")
    ) {
        return None;
    }
    let original = redirect.target.as_ref()?;
    // Literal opens need only quote removal, not a variable/path projection.
    if let Some(value) = caushell_parse::decode_static_shell_argument(
        &original.text,
        original.quoted,
        &original.node_kind,
    ) {
        return IoTargetQuery::bash_network_redirection(&value);
    }
    let fact = crate::path::collect_redirection_path_fact(
        redirect,
        index,
        cwd,
        home,
        bindings,
        parsed.shell_kind,
    )?;
    let token = fact.fact.target.as_ref()?;
    let arg = caushell_profile::ProjectedArg {
        word_context: Default::default(),
        text: token.text.clone(),
        quoted: token.quoted,
        node_kind: token.node_kind.clone(),
        span: token.span.clone(),
        kind: caushell_profile::ProjectedArgKind::Positional,
        implicit_input_source: None,
        runtime_argument_domain: None,
        runtime_data: false,
        substitution_shape: None,
        lexical_field_prefix: None,
    };
    let shape = caushell_profile::argument_structure(&arg);
    if let Some(value) = shape.exact_value() {
        return IoTargetQuery::bash_network_redirection(value);
    }
    // Mask one opaque scalar expansion only to prove the surrounding native
    // open grammar. The marker is never an address or a materialized value.
    if token.quoted
        && token.node_kind == "string"
        && token.text.len() <= 8192
        && let [substitution] = original.command_substitutions.as_slice()
    {
        let masked = token
            .text
            .replacen(&substitution.text, "UNKNOWN_SOCKET_COMPONENT", 1);
        if caushell_parse::decode_static_shell_argument(&masked, true, "string")
            .is_some_and(|value| IoTargetQuery::bash_network_redirection(&value).is_some())
        {
            return Some(IoTarget::Network { endpoint: None });
        }
    }
    let rest = shape
        .static_prefix
        .strip_prefix("/dev/tcp/")
        .or_else(|| shape.static_prefix.strip_prefix("/dev/udp/"))?;
    // Every possible spelling must match the native socket-open grammar.
    // Unknown host/service bytes never stand in for a proven destination.
    (shape.fields == caushell_profile::ArgumentFieldCount::ExactlyOne
        && (rest.contains('/') || shape.static_suffix.contains('/')))
    .then_some(IoTarget::Network { endpoint: None })
}

fn pipeline_merges_stderr(parsed: &ParsedCommandArtifact, index: usize) -> bool {
    let Some(command) = parsed
        .commands
        .get(index)
        .filter(|command| command.in_pipeline)
    else {
        return false;
    };
    let Some(next) = parsed
        .commands
        .iter()
        .filter(|next| {
            next.in_pipeline
                && next.top_level_span == command.top_level_span
                && next.span.start_byte > command.span.start_byte
        })
        .min_by_key(|next| next.span.start_byte)
    else {
        return false;
    };
    let end = parsed
        .redirections
        .iter()
        .filter(|redirect| redirection_parent_command_index(parsed, redirect) == Some(index))
        .map(|redirect| redirect.span.end_byte)
        .fold(command.span.end_byte, usize::max);
    parsed
        .raw_command
        .get(end..next.span.start_byte)
        .is_some_and(|separator| separator.trim_start().starts_with("|&"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn inherited_sources_are_replayed_before_local_alias_opens_and_rebinding() {
        use caushell_runner::{PassRunner, RunnerContext, SessionView};
        let request = caushell_types::CheckRequest {
            session_id: caushell_types::SessionId::new("io-scope"),
            sequence_no: caushell_types::CommandSequenceNo::new(1),
            command: "sh -c 'cat < /dev/fd/3 3<public.txt' 3<.env | cat".into(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project"),
            shell_kind: caushell_types::ShellKind::Bash,
            home: None,
            workspace_root: Some("/tmp/project".into()),
            runtime: caushell_types::RuntimeMetadata {
                runtime_name: "unit".into(),
                tool_name: None,
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
        };
        let mut ctx = RunnerContext::new(request);
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(crate::ParseCommandPass);
        runner.register_session_transform_pass(crate::ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(crate::ResolveInvocationPass::new(
            caushell_profile::ProfileRegistry::built_in().unwrap(),
        ));
        runner.run(
            SessionView::new(
                &caushell_graph::SessionGraph::new(),
                &caushell_types::SessionSummary::new(),
            ),
            &mut ctx,
        );
        let child = ctx
            .execution_unit_resolve_records()
            .iter()
            .find(|r| {
                r.origin_kind == caushell_runner::ExecutionUnitOriginKind::ShellCommandStringPayload
            })
            .unwrap();
        let result = super::execution_content_io_target(
            &ctx,
            &child.source_node_id,
            &child.parsed_scope,
            child.command_ref.command_index,
            None,
            &caushell_types::PathResolution::Concrete {
                path: "/dev/stdin".into(),
            },
            false,
            "/tmp/project",
            None,
        );
        assert_eq!(
            result,
            path("/tmp/project/.env", true),
            "{:#?}",
            child.parsed_scope
        );
    }
    use super::*;

    fn query(command: &str, path: &str, before: Option<usize>) -> IoTarget {
        let parsed =
            caushell_parse::parse_command(command, caushell_types::ShellKind::Bash).unwrap();
        content_io_target(
            &parsed,
            Some(0),
            before,
            &PathResolution::Concrete { path: path.into() },
            false,
            "/tmp/project",
            None,
            None,
        )
    }

    fn path(path: &str, dependent: bool) -> IoTarget {
        IoTarget::Path {
            resolution: PathResolution::Concrete { path: path.into() },
            cwd_dependent: dependent,
        }
    }

    #[test]
    fn snapshots_distinguish_operand_open_from_redirection_open() {
        assert_eq!(
            query("tee /dev/stdout > /opt/shared/out", "/dev/stdout", None),
            path("/opt/shared/out", false)
        );
        assert_eq!(
            query(
                "printf DATA > /dev/stdout > /opt/shared/out",
                "/dev/stdout",
                Some(0)
            ),
            IoTarget::InheritedDescriptor {
                descriptor: "1".into()
            }
        );
        assert_eq!(
            query(
                "printf DATA > /opt/shared/out > /dev/stdout",
                "/dev/stdout",
                Some(1)
            ),
            path("/opt/shared/out", false)
        );
    }

    #[test]
    fn socket_opening_does_not_reinterpret_arbitrary_snapshot_path_queries() {
        let command = "printf x >/dev/tcp/127.0.0.1/80";
        assert_eq!(
            query(command, "/dev/stdout", Some(0)),
            IoTarget::InheritedDescriptor {
                descriptor: "1".into()
            }
        );
        assert_eq!(
            query(command, "/dev/stdout", None),
            IoTarget::Network {
                endpoint: Some("127.0.0.1:80".into())
            }
        );
        assert_eq!(
            query(command, "/dev/tcp/127.0.0.1/80", None),
            path("/dev/tcp/127.0.0.1/80", false)
        );
    }

    #[test]
    fn aliases_capture_the_previous_target_not_future_rebinding() {
        assert_eq!(
            query("tee /dev/fd/3 3>&1 > /opt/shared/out", "/dev/fd/3", None),
            IoTarget::InheritedDescriptor {
                descriptor: "1".into()
            }
        );
        assert_eq!(
            query("tee /dev/fd/3 > /opt/shared/out 3>&1", "/dev/fd/3", None),
            path("/opt/shared/out", false)
        );
        assert_eq!(
            query("tee /dev/stdout 1>&3 3>cache/out", "/dev/stdout", None),
            IoTarget::UnknownDescriptor {
                descriptor: "3".into()
            }
        );
        assert_eq!(
            query("tee /dev/fd/3 3>cache/out", "/dev/fd/3", None),
            path("/tmp/project/cache/out", true)
        );
    }

    #[test]
    fn combined_output_closure_and_moves_are_retained() {
        assert_eq!(
            query("tee /dev/stderr &> /opt/shared/out", "/dev/stderr", None),
            path("/opt/shared/out", false)
        );
        assert_eq!(
            query("tee /dev/fd/3 3>&-", "/dev/fd/3", None),
            IoTarget::Closed
        );
        assert_eq!(
            query("tee /dev/fd/3 3>cache/out 1>&3-", "/dev/fd/3", None),
            IoTarget::Closed
        );
        assert_eq!(
            query("tee /dev/stdout 3>cache/out 1>&3-", "/dev/stdout", None),
            path("/tmp/project/cache/out", true)
        );
    }

    #[test]
    fn implicit_pipe_stderr_duplication_is_after_explicit_opens() {
        assert_eq!(
            query("tee /dev/stderr >cache/out |& cat", "/dev/stderr", None),
            path("/tmp/project/cache/out", true)
        );
        assert_eq!(
            query(
                "tee /dev/stderr >cache/out 2>/dev/stderr |& cat",
                "/dev/stderr",
                Some(1)
            ),
            IoTarget::InheritedDescriptor {
                descriptor: "2".into()
            }
        );
        assert_eq!(
            query(
                "tee /dev/stderr >cache/out 2>other |& cat",
                "/dev/stderr",
                None
            ),
            path("/tmp/project/cache/out", true)
        );
        assert_eq!(
            query("tee /dev/stderr >cache/out | cat", "/dev/stderr", None),
            IoTarget::InheritedDescriptor {
                descriptor: "2".into()
            }
        );
    }
}

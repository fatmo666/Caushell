//! Shared projection of already-admitted shell syntax. No parsing or tool names.
use crate::path::{
    RedirectionPathFactCandidate, collect_redirection_path_fact, effective_cwd_cases,
    project_path_at_cwd,
};
use caushell_graph::NodeId;
use caushell_profile::{ProjectedArg, ProjectedArgKind, ProjectedInvocation, ValueMaterialization};
use caushell_query::IoTarget;
use caushell_runner::{CwdPathContext, RunnerContext};

pub(crate) struct ShellSyntaxRedirection {
    pub source: NodeId,
    pub path: RedirectionPathFactCandidate,
    pub io: IoTarget,
    pub unknown_cwd: bool,
    pub exact_cwd: Option<String>,
    pub home: Option<String>,
}

/// Every unit is anchored at the opening statement, not at its last inner
/// invocation. Targets are materialized once in that statement's lexical frame.
pub(crate) fn shell_syntax_redirections(ctx: &RunnerContext) -> Vec<ShellSyntaxRedirection> {
    let mut result = Vec::new();
    let fallback = ctx.request().shell_state_before.cwd();
    for scope in ctx.shell_redirection_scopes() {
        for unit in &scope.units {
            let home = unit
                .bindings
                .tilde_home_with_default(ctx.request().home.as_deref());
            let parsed = materialized_opening_frame(scope, unit);
            for case in
                effective_cwd_cases(ctx.effective_cwd_for_node(&unit.source_node_id), fallback)
            {
                for (local_index, &index) in unit.redirection_indexes.iter().enumerate() {
                    let Some(mut path) = collect_redirection_path_fact(
                        &parsed.redirections[local_index],
                        index,
                        case.resolution_base(fallback),
                        home,
                    ) else {
                        continue;
                    };
                    let io = super::content_io_target(
                        &parsed,
                        None,
                        Some(local_index),
                        &path.resolution,
                        path.cwd_dependent,
                        case.resolution_base(fallback),
                        home,
                    );
                    let io = match io {
                        IoTarget::Path {
                            resolution,
                            cwd_dependent,
                        } => {
                            path.resolution = project_path_at_cwd(resolution, cwd_dependent, case);
                            path.cwd_dependent = cwd_dependent;
                            IoTarget::Path {
                                resolution: path.resolution.clone(),
                                cwd_dependent,
                            }
                        }
                        other => other,
                    };
                    result.push(ShellSyntaxRedirection {
                        source: unit.source_node_id.clone(),
                        path,
                        io,
                        unknown_cwd: matches!(case, CwdPathContext::Unknown),
                        exact_cwd: match case {
                            CwdPathContext::Exact(cwd) => Some(cwd.into()),
                            _ => None,
                        },
                        home: home.map(str::to_owned),
                    });
                }
            }
        }
    }
    result
}

/// Descriptor inheritance from admitted compound statements. Replay the
/// opening frame before local command redirects; pipeline ports replace only
/// their own inherited descriptor. No additional shell parsing is performed.
pub(crate) fn syntax_descriptor_entries(
    ctx: &RunnerContext,
    source: &NodeId,
    parsed: &caushell_parse::ParsedCommandArtifact,
    index: usize,
) -> std::collections::BTreeMap<String, IoTarget> {
    use caushell_types::PathResolution;
    let mut entries = std::collections::BTreeMap::new();
    if ctx.shell_redirection_scopes().is_empty() {
        return entries;
    }
    let Some(command) = parsed.commands.get(index) else {
        return entries;
    };
    let record = ctx
        .execution_unit_resolve_records()
        .iter()
        .find(|r| &r.source_node_id == source);
    let Some(scope) = ctx.shell_redirection_scopes().iter().find(|scope| {
        scope.parsed.raw_command == parsed.raw_command
            && if scope.is_request_scope {
                ctx.parsed_command()
                    .is_some_and(|p| p.raw_command == parsed.raw_command)
                    && record.is_none_or(|r| {
                        r.origin_kind == caushell_runner::ExecutionUnitOriginKind::TopLevel
                    })
            } else {
                record.is_some_and(|r| {
                    r.parent_execution_node_id == scope.parent_execution_node_id
                        && r.origin_kind == scope.origin_kind
                        && r.origin_locator == scope.origin_locator
                        && r.root_command_index == scope.root_command_index
                })
            }
    }) else {
        return entries;
    };
    let mut units: Vec<_> = scope
        .units
        .iter()
        .filter(|u| {
            let span = &u.opening_statement.span;
            span.start_byte <= command.span.start_byte
                && span.end_byte >= command.span.end_byte
                && span != &command.span
        })
        .collect();
    units.sort_by_key(|u| {
        std::cmp::Reverse(u.opening_statement.span.end_byte - u.opening_statement.span.start_byte)
    });
    for unit in units {
        let home = unit
            .bindings
            .tilde_home_with_default(ctx.request().home.as_deref());
        let cwd = ctx.known_effective_cwd_for_node(&unit.source_node_id);
        let frame = materialized_opening_frame(scope, unit);
        let mut descriptors =
            std::collections::BTreeSet::from(["0".to_string(), "1".to_string(), "2".to_string()]);
        descriptors.extend(entries.keys().cloned());
        descriptors.extend(
            frame
                .redirections
                .iter()
                .filter_map(|r| r.file_descriptor.as_deref())
                .filter_map(caushell_query::IoTargetQuery::canonical_descriptor)
                .map(str::to_string),
        );
        let prior = entries.clone();
        for fd in descriptors {
            let mut target = super::io_target::content_io_target_with_entry(
                &frame,
                None,
                None,
                &PathResolution::Concrete {
                    path: format!("/dev/fd/{fd}"),
                },
                false,
                cwd.unwrap_or(ctx.request().shell_state_before.cwd()),
                home,
                &prior,
            );
            if cwd.is_none()
                && matches!(
                    target,
                    IoTarget::Path {
                        cwd_dependent: true,
                        ..
                    }
                )
            {
                target = IoTarget::UnknownDescriptor {
                    descriptor: fd.clone(),
                };
            }
            entries.insert(fd, target);
        }
    }
    if matches!(
        command.pipeline_position,
        Some(caushell_parse::PipelinePosition::First | caushell_parse::PipelinePosition::Middle)
    ) {
        entries.insert(
            "1".into(),
            IoTarget::InheritedDescriptor {
                descriptor: "1".into(),
            },
        );
    }
    if matches!(
        command.pipeline_position,
        Some(caushell_parse::PipelinePosition::Middle | caushell_parse::PipelinePosition::Last)
    ) {
        entries.insert(
            "0".into(),
            IoTarget::InheritedDescriptor {
                descriptor: "0".into(),
            },
        );
    }
    entries
}

fn materialized_opening_frame(
    scope: &caushell_runner::ShellRedirectionScope,
    unit: &caushell_runner::ShellRedirectionUnit,
) -> caushell_parse::ParsedCommandArtifact {
    let mut parsed = caushell_parse::ParsedCommandArtifact {
        raw_command: String::new(),
        shell_kind: scope.parsed.shell_kind,
        status: scope.parsed.status.clone(),
        commands: Vec::new(),
        declaration_commands: Vec::new(),
        assignment_commands: Vec::new(),
        for_loops: Vec::new(),
        unset_commands: Vec::new(),
        function_definitions: Vec::new(),
        redirections: Vec::new(),
        diagnostics: Vec::new(),
    };
    parsed.redirections = unit
        .redirection_indexes
        .iter()
        .map(|&index| {
            let mut r = scope.parsed.redirections[index].clone();
            if let Some(target) = &mut r.target {
                let p = ProjectedInvocation {
                    shell_kind: scope.parsed.shell_kind,
                    option_prefixes: Default::default(),
                    command_name: None,
                    stdin_payload_available: false,
                    interactive_session: false,
                    args: vec![ProjectedArg {
                        text: target.text.clone(),
                        quoted: target.quoted,
                        node_kind: target.node_kind.clone(),
                        span: target.span.clone(),
                        kind: ProjectedArgKind::Positional,
                        implicit_input_source: None,
                        runtime_argument_domain: None,
                        runtime_data: false,
                        substitution_shape: None,
                        lexical_field_prefix: None,
                    }],
                };
                let m = caushell_profile::materialize_projected_invocation(&p, &unit.bindings);
                if let ([arg], [resolution]) = (&m.invocation.args[..], &m.arg_resolutions[..])
                    && matches!(
                        resolution,
                        ValueMaterialization::ResolvedExactScalar { .. }
                            | ValueMaterialization::ResolvedRuntimeProduced { .. }
                            | ValueMaterialization::ResolvedShellWord { .. }
                    )
                {
                    target.text = arg.text.clone();
                    target.quoted = true;
                    target.node_kind = "raw_string".into();
                }
            }
            r
        })
        .collect();
    parsed
}

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
            // The FD query needs only the redirects in this opening statement.
            // Do not clone every command and payload in the containing scope.
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
                        let m =
                            caushell_profile::materialize_projected_invocation(&p, &unit.bindings);
                        if let ([arg], [resolution]) =
                            (&m.invocation.args[..], &m.arg_resolutions[..])
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

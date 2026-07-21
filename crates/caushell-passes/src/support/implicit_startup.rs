use std::collections::BTreeSet;

use caushell_graph::NodeId;
use caushell_profile::{
    ResolveInvocationArtifactResult, exact_scalar_shell_parameter_reference_value,
};
use caushell_runner::{ExecutionUnitResolveRecord, RunnerContext};
use caushell_types::{PathResolution, ProvenanceArtifact, ProvenanceVariableValueState};

use crate::path::{join_shell_path, normalize_shell_path};

const STARTUP_CONFIG_SLOT_NAME: &str = "startup_config";
const IMPLICIT_STARTUP_PATH_INDEX_BASE: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImplicitStartupConfigCandidate {
    pub source_node_id: NodeId,
    pub command_index: usize,
    pub normalized_command_name: String,
    pub environment_name: String,
    pub environment_state: ProvenanceVariableValueState,
    pub environment_source: ImplicitStartupEnvironmentSource,
    pub resolution: PathResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImplicitStartupEnvironmentSource {
    InheritedEnvironment,
    CommandPrefixAssignment,
}

pub(crate) fn collect_implicit_startup_config_candidates(
    ctx: &RunnerContext,
) -> Vec<ImplicitStartupConfigCandidate> {
    let request = ctx.request();
    let mut candidates = Vec::new();

    collect_candidates_from_records(
        ctx.execution_unit_resolve_records(),
        request.shell_state_before.cwd(),
        &request.shell_state_before,
        &mut candidates,
    );

    candidates
}

pub(crate) fn implicit_startup_source_node_ids(ctx: &RunnerContext) -> BTreeSet<NodeId> {
    collect_implicit_startup_config_candidates(ctx)
        .into_iter()
        .map(|candidate| candidate.source_node_id)
        .collect()
}

pub(crate) fn implicit_startup_path_fact_index(
    command_index: usize,
    environment_name: &str,
) -> usize {
    IMPLICIT_STARTUP_PATH_INDEX_BASE
        + (command_index * 8)
        + match environment_name {
            "BASH_ENV" => 0,
            "ENV" => 1,
            _ => 7,
        }
}

pub(crate) fn implicit_startup_slot_name() -> &'static str {
    STARTUP_CONFIG_SLOT_NAME
}

pub(crate) fn inherited_env_artifact_node_id(name: &str, version: u64) -> NodeId {
    NodeId::new(format!("artifact:inherited-env-value:{name}:{version}"))
}

pub(crate) fn inherited_env_value_artifact(
    name: &str,
    state: ProvenanceVariableValueState,
    version: u64,
) -> ProvenanceArtifact {
    ProvenanceArtifact::InheritedEnvValue {
        name: name.to_string(),
        state,
        version,
    }
}

pub(crate) fn command_env_artifact_node_id(source_node_id: &NodeId, name: &str) -> NodeId {
    NodeId::new(format!(
        "artifact:command-env-value:{}:{name}",
        source_node_id.0
    ))
}

pub(crate) fn command_env_value_artifact(
    name: &str,
    state: ProvenanceVariableValueState,
    version: u64,
) -> ProvenanceArtifact {
    ProvenanceArtifact::VariableValue {
        name: name.to_string(),
        state,
        exported: true,
        version,
    }
}

pub(crate) fn implicit_startup_environment_name(
    normalized_command_name: &str,
    form_id: &str,
) -> Option<&'static str> {
    match (normalized_command_name, form_id) {
        ("bash", "interactive") => None,
        ("bash", _) => Some("BASH_ENV"),
        ("sh", "interactive") => Some("ENV"),
        ("sh", _) => None,
        _ => None,
    }
}

fn collect_candidates_from_records(
    records: &[ExecutionUnitResolveRecord],
    cwd: &str,
    shell_state: &caushell_types::ShellStateSnapshot,
    out: &mut Vec<ImplicitStartupConfigCandidate>,
) {
    for record in records {
        let ResolveInvocationArtifactResult::Resolved(resolved) = &record.result else {
            continue;
        };

        let Some(environment_name) = implicit_startup_environment_name(
            &resolved.normalized_command_name,
            resolved.bound.form_id.as_str(),
        ) else {
            continue;
        };

        if let Some((environment_value, environment_state)) = record
            .parsed_scope
            .commands
            .get(record.command_ref.command_index)
            .and_then(|command| {
                command_prefix_environment_value(command, environment_name, &record.bindings)
            })
        {
            if environment_value.is_empty() {
                continue;
            }

            out.push(ImplicitStartupConfigCandidate {
                source_node_id: record.source_node_id.clone(),
                command_index: record.command_ref.command_index,
                normalized_command_name: resolved.normalized_command_name.clone(),
                environment_name: environment_name.to_string(),
                resolution: resolve_implicit_startup_path(&environment_value, cwd),
                environment_state,
                environment_source: ImplicitStartupEnvironmentSource::CommandPrefixAssignment,
            });
            continue;
        }

        let Some((environment_value, environment_state)) = shell_state
            .exported_variable(environment_name)
            .and_then(|binding| match &binding.value {
                caushell_types::ShellValueSnapshot::ExactScalar { value } => Some((
                    value.clone(),
                    ProvenanceVariableValueState::ExactScalar {
                        value: value.clone(),
                    },
                )),
                caushell_types::ShellValueSnapshot::RuntimeProduced { value, value_kind } => {
                    Some((
                        value.clone(),
                        ProvenanceVariableValueState::RuntimeProduced {
                            value: value.clone(),
                            value_kind: *value_kind,
                        },
                    ))
                }
                caushell_types::ShellValueSnapshot::OpaqueDynamic { repr } => Some((
                    repr.clone(),
                    ProvenanceVariableValueState::OpaqueDynamic { repr: repr.clone() },
                )),
                caushell_types::ShellValueSnapshot::RuntimeInput { source, capture } => Some((
                    String::new(),
                    ProvenanceVariableValueState::RuntimeInput {
                        source: *source,
                        capture: capture.clone(),
                    },
                )),
            })
        else {
            continue;
        };

        if environment_value.is_empty() {
            continue;
        }

        out.push(ImplicitStartupConfigCandidate {
            source_node_id: record.source_node_id.clone(),
            command_index: record.command_ref.command_index,
            normalized_command_name: resolved.normalized_command_name.clone(),
            environment_name: environment_name.to_string(),
            resolution: resolve_implicit_startup_path(&environment_value, cwd),
            environment_state,
            environment_source: ImplicitStartupEnvironmentSource::InheritedEnvironment,
        });
    }
}

fn command_prefix_environment_value(
    command: &caushell_parse::CommandFact,
    environment_name: &str,
    bindings: &caushell_profile::SessionBindings,
) -> Option<(String, ProvenanceVariableValueState)> {
    command
        .prefix_assignments
        .iter()
        .rev()
        .find(|assignment| {
            assignment.name == environment_name
                && assignment.operator == caushell_parse::AssignmentOperator::Assign
        })
        .map(|assignment| environment_assignment_value(&assignment.value, bindings))
}

fn environment_assignment_value(
    value: &caushell_parse::AssignmentValueFact,
    bindings: &caushell_profile::SessionBindings,
) -> (String, ProvenanceVariableValueState) {
    if let Some(value) = literal_assignment_value(value) {
        return (
            value.clone(),
            ProvenanceVariableValueState::ExactScalar { value },
        );
    }

    if let Some(value) = exact_scalar_shell_parameter_reference_value(&value.text, bindings) {
        return (
            value.clone(),
            ProvenanceVariableValueState::ExactScalar { value },
        );
    }

    (
        value.text.clone(),
        ProvenanceVariableValueState::OpaqueDynamic {
            repr: value.text.clone(),
        },
    )
}

fn literal_assignment_value(value: &caushell_parse::AssignmentValueFact) -> Option<String> {
    match value.node_kind.as_str() {
        "empty" => Some(String::new()),
        "raw_string" | "ansi_c_string" | "number" => Some(value.text.clone()),
        "string" if is_plain_quoted_literal(&value.text) => Some(value.text.clone()),
        "word" if is_plain_unquoted_literal(&value.text) => Some(value.text.clone()),
        _ => None,
    }
}

fn is_plain_quoted_literal(text: &str) -> bool {
    !text.contains('\\') && !contains_unescaped_dynamic_syntax(text)
}

fn is_plain_unquoted_literal(text: &str) -> bool {
    !text.contains('\\') && !text.contains('~') && !contains_unescaped_dynamic_syntax(text)
}

fn contains_unescaped_dynamic_syntax(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }

        if bytes[index] == b'$' || bytes[index] == b'`' {
            return true;
        }

        index += 1;
    }

    false
}

fn resolve_implicit_startup_path(text: &str, cwd: &str) -> PathResolution {
    if text.contains('$') || text.contains('`') || text.starts_with('~') {
        return PathResolution::UnsupportedDynamicText {
            text: text.to_string(),
        };
    }

    if text.starts_with('/') {
        return PathResolution::Concrete {
            path: normalize_shell_path(text),
        };
    }

    PathResolution::Concrete {
        path: join_shell_path(cwd, text),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        implicit_startup_environment_name, implicit_startup_path_fact_index,
        resolve_implicit_startup_path,
    };
    use caushell_types::PathResolution;

    #[test]
    fn implicit_startup_environment_name_matches_bash_noninteractive() {
        assert_eq!(
            implicit_startup_environment_name("bash", "command_string"),
            Some("BASH_ENV")
        );
        assert_eq!(
            implicit_startup_environment_name("bash", "script_file"),
            Some("BASH_ENV")
        );
        assert_eq!(
            implicit_startup_environment_name("bash", "interactive"),
            None
        );
    }

    #[test]
    fn implicit_startup_environment_name_matches_sh_interactive_only() {
        assert_eq!(
            implicit_startup_environment_name("sh", "interactive"),
            Some("ENV")
        );
        assert_eq!(
            implicit_startup_environment_name("sh", "command_string"),
            None
        );
    }

    #[test]
    fn implicit_startup_path_resolution_treats_shell_dynamic_text_as_opaque() {
        assert_eq!(
            resolve_implicit_startup_path("$HOME/team.rc", "/tmp/project"),
            PathResolution::UnsupportedDynamicText {
                text: "$HOME/team.rc".to_string(),
            }
        );
        assert_eq!(
            resolve_implicit_startup_path("~/team.rc", "/tmp/project"),
            PathResolution::UnsupportedDynamicText {
                text: "~/team.rc".to_string(),
            }
        );
    }

    #[test]
    fn implicit_startup_path_resolution_resolves_relative_paths_from_cwd() {
        assert_eq!(
            resolve_implicit_startup_path("../shared/team.rc", "/tmp/project/work"),
            PathResolution::Concrete {
                path: "/tmp/project/shared/team.rc".to_string(),
            }
        );
    }

    #[test]
    fn implicit_startup_path_fact_index_keeps_env_sources_distinct() {
        assert_ne!(
            implicit_startup_path_fact_index(0, "BASH_ENV"),
            implicit_startup_path_fact_index(0, "ENV")
        );
    }
}

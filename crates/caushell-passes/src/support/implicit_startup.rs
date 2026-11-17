use std::collections::BTreeSet;

use caushell_graph::NodeId;
use caushell_profile::{EnvironmentValueRef, ResolveInvocationArtifactResult, SessionValue};
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
    pub resolution: PathResolution,
}

pub(crate) fn collect_implicit_startup_config_candidates(
    ctx: &RunnerContext,
) -> Vec<ImplicitStartupConfigCandidate> {
    let request = ctx.request();
    let mut candidates = Vec::new();

    collect_candidates_from_records(
        ctx.execution_unit_resolve_records(),
        request.shell_state_before.cwd(),
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

        let environment = super::ExecutionEnvironment::for_command(
            &record.bindings,
            &record.parsed_scope,
            &record.command_ref,
        );
        let environment_state = match environment.value(environment_name) {
            EnvironmentValueRef::Absent => continue,
            EnvironmentValueRef::Present(value) => ProvenanceVariableValueState::from(value),
            EnvironmentValueRef::Unknown => ProvenanceVariableValueState::OpaqueDynamic {
                repr: format!("execution environment {environment_name} is unobserved"),
            },
        };
        let environment_value = match environment.value(environment_name) {
            EnvironmentValueRef::Present(SessionValue::ExactScalar(value))
            | EnvironmentValueRef::Present(SessionValue::RuntimeProduced { value, .. }) => {
                value.as_str()
            }
            _ => "",
        };

        if known_empty(&environment_state) {
            continue;
        }

        out.push(ImplicitStartupConfigCandidate {
            source_node_id: record.source_node_id.clone(),
            command_index: record.command_ref.command_index,
            normalized_command_name: resolved.normalized_command_name.clone(),
            environment_name: environment_name.to_string(),
            resolution: resolve_candidate_path(environment_value, &environment_state, cwd),
            environment_state,
        });
    }
}

fn known_empty(state: &ProvenanceVariableValueState) -> bool {
    matches!(state, ProvenanceVariableValueState::ExactScalar { value } | ProvenanceVariableValueState::RuntimeProduced { value, .. } if value.is_empty())
}

fn resolve_candidate_path(
    value: &str,
    state: &ProvenanceVariableValueState,
    cwd: &str,
) -> PathResolution {
    match state {
        ProvenanceVariableValueState::ExactScalar { .. }
        | ProvenanceVariableValueState::RuntimeProduced { .. } => {
            resolve_implicit_startup_path(value, cwd)
        }
        _ => PathResolution::UnsupportedDynamicText {
            text: "startup environment value is unresolved".into(),
        },
    }
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

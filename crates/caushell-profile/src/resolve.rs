use caushell_parse::CommandFact;
use caushell_types::{ResolveGapKind, SessionSummary};

use crate::bind::bind_modifier_only_invocation;
use crate::materialize::materialize_argument_text;
use crate::{
    BindError, BoundArgumentMaterialization, BoundInvocation, BoundValue, CommandProfile,
    InvocationRuntimeContext, InvocationSelection, MaterializedProjectedInvocation,
    ProfileRegistry, ProjectedInvocation, SessionBindings, ValueMaterialization, bind_invocation,
    materialize_projected_invocation, project_invocation, select_invocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInvocation<'a> {
    pub normalized_command_name: String,
    pub profile: &'a CommandProfile,
    pub projection: ProjectedInvocation,
    pub materialized_projection: MaterializedProjectedInvocation,
    pub selection: InvocationSelection<'a>,
    pub bound: BoundInvocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInvocationArtifact {
    pub normalized_command_name: String,
    pub projection: ProjectedInvocation,
    pub materialized_projection: MaterializedProjectedInvocation,
    pub bound: BoundInvocation,
}

impl<'a> ResolvedInvocation<'a> {
    pub fn into_artifact(self) -> ResolvedInvocationArtifact {
        ResolvedInvocationArtifact {
            normalized_command_name: self.normalized_command_name,
            projection: self.projection,
            materialized_projection: self.materialized_projection,
            bound: self.bound,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveInvocationResult<'a> {
    MissingCommandName {
        gap_kind: ResolveGapKind,
    },
    NoProfile {
        normalized_command_name: String,
        gap_kind: ResolveGapKind,
    },
    Resolved(ResolvedInvocation<'a>),
    SelectionError {
        normalized_command_name: String,
        gap_kind: ResolveGapKind,
        error: BindError,
        partial_bound: Option<BoundInvocation>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveInvocationArtifactResult {
    MissingCommandName {
        gap_kind: ResolveGapKind,
    },
    NoProfile {
        normalized_command_name: String,
        gap_kind: ResolveGapKind,
    },
    Resolved(ResolvedInvocationArtifact),
    SelectionError {
        normalized_command_name: String,
        gap_kind: ResolveGapKind,
        error: BindError,
        partial_bound: Option<BoundInvocation>,
    },
}

impl<'a> ResolveInvocationResult<'a> {
    pub fn into_artifact(self) -> ResolveInvocationArtifactResult {
        match self {
            Self::MissingCommandName { gap_kind } => {
                ResolveInvocationArtifactResult::MissingCommandName { gap_kind }
            }
            Self::NoProfile {
                normalized_command_name,
                gap_kind,
            } => ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name,
                gap_kind,
            },
            Self::Resolved(resolved) => {
                ResolveInvocationArtifactResult::Resolved(resolved.into_artifact())
            }
            Self::SelectionError {
                normalized_command_name,
                gap_kind,
                error,
                partial_bound,
            } => ResolveInvocationArtifactResult::SelectionError {
                normalized_command_name,
                gap_kind,
                error,
                partial_bound,
            },
        }
    }
}

pub fn resolve_invocation<'a>(
    registry: &'a ProfileRegistry,
    command: &CommandFact,
    context: InvocationRuntimeContext,
) -> ResolveInvocationResult<'a> {
    resolve_invocation_with_bindings(registry, command, context, &SessionBindings::new())
}

pub fn resolve_invocation_with_summary<'a>(
    registry: &'a ProfileRegistry,
    command: &CommandFact,
    context: InvocationRuntimeContext,
    summary: &SessionSummary,
) -> ResolveInvocationResult<'a> {
    let bindings = SessionBindings::from_session_summary(summary);
    resolve_invocation_with_bindings(registry, command, context, &bindings)
}

pub fn resolve_invocation_with_bindings<'a>(
    registry: &'a ProfileRegistry,
    command: &CommandFact,
    context: InvocationRuntimeContext,
    bindings: &SessionBindings,
) -> ResolveInvocationResult<'a> {
    if let Some(gap_kind) = dynamic_command_target_gap(command) {
        return ResolveInvocationResult::MissingCommandName { gap_kind };
    }

    let Some(command_name) = command.command_name.as_deref() else {
        return ResolveInvocationResult::MissingCommandName {
            gap_kind: gap_kind_for_missing_command_name(command),
        };
    };

    let lookup = registry.lookup(command_name);
    let normalized_command_name = lookup.normalized_command_name;
    let Some(profile) = lookup.profile else {
        return ResolveInvocationResult::NoProfile {
            normalized_command_name,
            gap_kind: ResolveGapKind::NoProfile,
        };
    };

    let projection = project_invocation(command, context);
    let materialized_projection = materialize_projected_invocation(&projection, bindings);

    match select_invocation(profile, &materialized_projection.invocation) {
        Ok(selection) => {
            let bound = bind_invocation(profile, &materialized_projection.invocation, &selection);
            let bound =
                attach_bound_argument_materialization(bound, &materialized_projection, bindings);

            ResolveInvocationResult::Resolved(ResolvedInvocation {
                normalized_command_name,
                profile,
                projection,
                materialized_projection,
                selection,
                bound,
            })
        }
        Err(error) => ResolveInvocationResult::SelectionError {
            normalized_command_name,
            gap_kind: gap_kind_for_bind_error(&error),
            error,
            partial_bound: bind_modifier_only_invocation(
                profile,
                &materialized_projection.invocation,
            ),
        },
    }
}

fn attach_bound_argument_materialization(
    mut bound: BoundInvocation,
    materialized_projection: &MaterializedProjectedInvocation,
    bindings: &SessionBindings,
) -> BoundInvocation {
    for parameter in &mut bound.bound_parameters {
        for value in &mut parameter.values {
            let BoundValue::Argument {
                text,
                quoted,
                node_kind,
                span,
                materialization,
                ..
            } = value
            else {
                continue;
            };

            let materialized_bound_value =
                materialize_argument_text(text, *quoted, node_kind, bindings);
            let resolution = materialized_projection
                .invocation
                .args
                .iter()
                .zip(materialized_projection.arg_resolutions.iter())
                .find(|(arg, _)| {
                    arg.text == *text && arg.node_kind == *node_kind && arg.span == *span
                })
                .map(|(_, resolution)| resolution);
            let bound_resolution = materialized_bound_value.resolution;
            let effective_resolution = match resolution {
                Some(
                    resolved @ (ValueMaterialization::ResolvedExactScalar { .. }
                    | ValueMaterialization::ResolvedRuntimeProduced { .. }),
                ) => resolved,
                Some(resolved) if matches!(bound_resolution, ValueMaterialization::Static) => {
                    resolved
                }
                _ => &bound_resolution,
            };

            *text = materialized_bound_value.text;
            *materialization = match effective_resolution {
                ValueMaterialization::ResolvedExactScalar { variable_name, .. } => {
                    BoundArgumentMaterialization::ResolvedExactScalar {
                        variable_name: variable_name.clone(),
                    }
                }
                ValueMaterialization::ResolvedRuntimeProduced { variable_name, .. } => {
                    BoundArgumentMaterialization::ResolvedRuntimeProduced {
                        variable_name: variable_name.clone(),
                    }
                }
                _ => BoundArgumentMaterialization::Literal,
            };
        }
    }

    bound
}

pub fn resolve_invocation_artifact(
    registry: &ProfileRegistry,
    command: &CommandFact,
    context: InvocationRuntimeContext,
) -> ResolveInvocationArtifactResult {
    resolve_invocation(registry, command, context).into_artifact()
}

pub fn resolve_invocation_artifact_with_summary(
    registry: &ProfileRegistry,
    command: &CommandFact,
    context: InvocationRuntimeContext,
    summary: &SessionSummary,
) -> ResolveInvocationArtifactResult {
    resolve_invocation_with_summary(registry, command, context, summary).into_artifact()
}

pub fn resolve_invocation_artifact_with_bindings(
    registry: &ProfileRegistry,
    command: &CommandFact,
    context: InvocationRuntimeContext,
    bindings: &SessionBindings,
) -> ResolveInvocationArtifactResult {
    resolve_invocation_with_bindings(registry, command, context, bindings).into_artifact()
}

fn gap_kind_for_bind_error(error: &BindError) -> ResolveGapKind {
    match error {
        BindError::UnknownSubcommand { .. } => ResolveGapKind::UnknownSubcommandPath,
        BindError::MultipleFormsMatched { .. } => ResolveGapKind::FormSelectionAmbiguous,
        BindError::NoFormMatched { .. } | BindError::UnsupportedProfileFeature { .. } => {
            ResolveGapKind::FormSelectionUnmatched
        }
    }
}

fn gap_kind_for_missing_command_name(command: &CommandFact) -> ResolveGapKind {
    if command
        .tokens
        .first()
        .is_some_and(|token| is_dynamic_command_token_kind(token.node_kind.as_str()))
    {
        ResolveGapKind::DynamicCommandTarget
    } else {
        ResolveGapKind::MissingCommandName
    }
}

fn dynamic_command_target_gap(command: &CommandFact) -> Option<ResolveGapKind> {
    let command_name = command.command_name.as_deref()?;
    if looks_like_dynamic_command_name(command_name) {
        Some(ResolveGapKind::DynamicCommandTarget)
    } else {
        None
    }
}

fn looks_like_dynamic_command_name(command_name: &str) -> bool {
    command_name.contains('$')
        || command_name.contains("`")
        || command_name.contains("<(")
        || command_name.contains(">(")
}

fn is_dynamic_command_token_kind(node_kind: &str) -> bool {
    matches!(
        node_kind,
        "simple_expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion"
            | "concatenation"
    )
}

#[cfg(test)]
mod tests {
    use caushell_parse::{CommandFact, SourceSpan, parse_command};
    use caushell_types::{CommandSequenceNo, InProcessCodeLoadKind, SessionSummary, ShellKind};

    use super::{
        ResolveGapKind, ResolveInvocationArtifactResult, ResolveInvocationResult,
        resolve_invocation, resolve_invocation_artifact, resolve_invocation_artifact_with_bindings,
        resolve_invocation_artifact_with_summary, resolve_invocation_with_bindings,
        resolve_invocation_with_summary,
    };
    use crate::{
        BindError, BindingOrigin, BoundInvocation, BoundValue, CatastrophicSemanticClass,
        EffectKind, InvocationRuntimeContext, ProcessTargetKind, ProfileRegistry, ResidualKind,
        SemanticType, SessionBindings, StructuredValueContext, StructuredValueSemantic,
        ValueMaterialization, collect_dispatch_command_candidates,
    };

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn empty_span() -> SourceSpan {
        SourceSpan {
            start_byte: 0,
            end_byte: 0,
            start_row: 0,
            start_column: 0,
            end_row: 0,
            end_column: 0,
        }
    }

    fn first_argument_text<'a>(invocation: &'a BoundInvocation, slot_name: &str) -> &'a str {
        let parameter = invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name.as_str() == slot_name)
            .expect("expected bound parameter to exist");

        match &parameter.values[0] {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("expected argument bound value, got {other:?}"),
        }
    }

    fn first_argument_materialization<'a>(
        invocation: &'a BoundInvocation,
        slot_name: &str,
    ) -> &'a crate::BoundArgumentMaterialization {
        let parameter = invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name.as_str() == slot_name)
            .expect("expected bound parameter to exist");

        match &parameter.values[0] {
            BoundValue::Argument {
                materialization, ..
            } => materialization,
            other => panic!("expected argument bound value, got {other:?}"),
        }
    }

    fn find_bound_parameter_opt<'a>(
        invocation: &'a BoundInvocation,
        slot_name: &str,
    ) -> Option<&'a crate::BoundParameter> {
        invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name.as_str() == slot_name)
    }

    fn argument_texts<'a>(invocation: &'a BoundInvocation, slot_name: &str) -> Vec<&'a str> {
        let parameter = invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name.as_str() == slot_name)
            .expect("expected bound parameter to exist");

        parameter
            .values
            .iter()
            .map(|value| match value {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("expected argument bound value, got {other:?}"),
            })
            .collect()
    }

    fn effect_kinds(invocation: &BoundInvocation) -> Vec<EffectKind> {
        invocation
            .effects
            .iter()
            .map(|effect| effect.kind)
            .collect()
    }

    fn assert_resolves_command_with_effects(
        registry: &ProfileRegistry,
        command_line: &str,
        expected_command_name: &str,
        expected_form_id: &str,
        expected_effects: &[EffectKind],
    ) {
        let artifact =
            parse_command(command_line, ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, expected_command_name);
                assert_eq!(resolved.bound.command_name.as_str(), expected_command_name);
                assert_eq!(resolved.selection.form.id.as_str(), expected_form_id);
                let effects = effect_kinds(&resolved.bound);
                for expected_effect in expected_effects {
                    assert!(
                        effects.contains(expected_effect),
                        "expected {command_line:?} to include effect {expected_effect:?}; got {effects:?}",
                    );
                }
            }
            other => panic!("unexpected resolve result for {command_line:?}: {other:?}"),
        }
    }

    fn assert_resolves_command_without_catastrophic_semantic(
        registry: &ProfileRegistry,
        command_line: &str,
        expected_command_name: &str,
        expected_form_id: &str,
        expected_effects: &[EffectKind],
    ) {
        let artifact =
            parse_command(command_line, ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, expected_command_name);
                assert_eq!(resolved.bound.command_name.as_str(), expected_command_name);
                assert_eq!(resolved.selection.form.id.as_str(), expected_form_id);
                let effects = effect_kinds(&resolved.bound);
                for expected_effect in expected_effects {
                    assert!(
                        effects.contains(expected_effect),
                        "expected {command_line:?} to include effect {expected_effect:?}; got {effects:?}",
                    );
                }
                assert!(
                    catastrophic_semantic_classes(&resolved.bound).is_empty(),
                    "expected {command_line:?} to resolve without catastrophic semantic classes; got {:?}",
                    catastrophic_semantic_classes(&resolved.bound)
                );
            }
            other => panic!("unexpected resolve result for {command_line:?}: {other:?}"),
        }
    }

    fn catastrophic_semantic_classes(
        invocation: &BoundInvocation,
    ) -> Vec<CatastrophicSemanticClass> {
        invocation
            .effects
            .iter()
            .filter_map(|effect| effect.catastrophic.semantic_class)
            .collect()
    }

    fn host_risk_semantic_classes(
        invocation: &BoundInvocation,
    ) -> Vec<crate::HostRiskSemanticClass> {
        invocation
            .effects
            .iter()
            .filter_map(|effect| effect.host_risk.semantic_class)
            .collect()
    }

    #[test]
    fn resolve_invocation_resolves_known_command() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"bash --rcfile ./team.rc -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.profile.primary_name(), "bash");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(resolved.bound.command_name.as_str(), "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "echo ok");
                assert_eq!(
                    first_argument_text(&resolved.bound, "startup_config"),
                    "./team.rc"
                );
                assert_eq!(modifier_ids, vec!["rcfile"]);
                assert_eq!(resolved.bound.effects.len(), 2);
                assert_eq!(resolved.bound.effects[0].kind, EffectKind::ExecutePayload);
                assert_eq!(resolved.bound.effects[1].kind, EffectKind::LoadConfig);
                assert!(resolved.bound.residuals.is_empty());

                assert_eq!(
                    resolved
                        .projection
                        .args
                        .iter()
                        .map(|arg| arg.text.as_str())
                        .collect::<Vec<_>>(),
                    vec!["--rcfile", "./team.rc", "-c", "echo ok"],
                );
                assert_eq!(
                    resolved
                        .materialized_projection
                        .invocation
                        .args
                        .iter()
                        .map(|arg| arg.text.as_str())
                        .collect::<Vec<_>>(),
                    vec!["--rcfile", "./team.rc", "-c", "echo ok"],
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_runtime_observed_profiles() {
        let registry = built_in_registry();

        assert_resolves_command_with_effects(
            &registry,
            r#"pgrep -af "scope_llm_triage|codex|probe_""#,
            "pgrep",
            "find_processes",
            &[EffectKind::TransformData],
        );

        assert_resolves_command_with_effects(
            &registry,
            r#"strings "$f""#,
            "strings",
            "extract_from_files",
            &[EffectKind::ReadPath, EffectKind::TransformData],
        );

        assert_resolves_command_with_effects(
            &registry,
            r#"PGPASSWORD=src_password_2026 psql -h localhost -U src_user -d src_pipeline_core -At -F $'\t' -c "SELECT 1""#,
            "psql",
            "execute_sql_command",
            &[EffectKind::NetworkEndpoint, EffectKind::TransformData],
        );
    }

    #[test]
    fn resolve_invocation_resolves_psql_command_and_file_operands() {
        let registry = built_in_registry();
        let artifact = parse_command(
            r#"PGPASSWORD=secret psql -h localhost -U src_user -d src_pipeline_core -c "SELECT 1""#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "psql");
                assert_eq!(resolved.selection.form.id.as_str(), "execute_sql_command");
                assert_eq!(first_argument_text(&resolved.bound, "host"), "localhost");
                assert_eq!(first_argument_text(&resolved.bound, "username"), "src_user");
                assert_eq!(
                    first_argument_text(&resolved.bound, "dbname"),
                    "src_pipeline_core"
                );
                assert_eq!(first_argument_text(&resolved.bound, "sql"), "SELECT 1");
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::NetworkEndpoint));
                assert!(effects.contains(&EffectKind::TransformData));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command(
            r#"psql --host db.internal --file migrations/check.sql -o out.tsv appdb"#,
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "psql");
                assert_eq!(resolved.selection.form.id.as_str(), "execute_sql_file");
                assert_eq!(first_argument_text(&resolved.bound, "host"), "db.internal");
                assert_eq!(
                    first_argument_text(&resolved.bound, "sql_file"),
                    "migrations/check.sql"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "out.tsv"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "database_names"),
                    "appdb"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::NetworkEndpoint));
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::WritePath));
                assert!(effects.contains(&EffectKind::TransformData));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_default_copy() {
        let registry = built_in_registry();
        let artifact = parse_command("cp src-a src-b dest", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_copy");
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["src-a", "src-b"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_target_directory_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("cp -t out src-a src-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.selection.form.id.as_str(), "target_directory");
                assert_eq!(modifier_ids, vec!["target_directory"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["src-a", "src-b"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_target_directory_mode_with_inline_operand() {
        let registry = built_in_registry();
        let artifact = parse_command("cp --target-directory=out src-a src-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.selection.form.id.as_str(), "target_directory");
                assert_eq!(modifier_ids, vec!["target_directory"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["src-a", "src-b"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_help_without_copy_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cp --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_help_without_target_directory_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("cp --help --target-directory=out src", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"target_directory"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_version_without_target_directory_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("cp --version --target-directory=out src", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"target_directory"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_backup_and_suffix_modifiers() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "cp --backup=numbered --suffix=.bak --reflink=always --sparse=never src dest",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_copy");
                assert!(modifier_ids.contains(&"backup_numbered"));
                assert!(modifier_ids.contains(&"reflink"));
                assert!(modifier_ids.contains(&"sparse"));
                assert!(modifier_ids.contains(&"suffix"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "reflink_mode"),
                    "always"
                );
                assert_eq!(first_argument_text(&resolved.bound, "sparse_mode"), "never");
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_suffix"),
                    ".bak"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_preserve_and_context_inline_operands() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "cp --preserve=mode,ownership --no-preserve=links --context=system_u:object_r:bin_t:s0 src dest",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_copy");
                assert_eq!(
                    modifier_ids,
                    vec!["preserve_default", "no_preserve", "set_security_context"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "preserve_attr_list"),
                    "mode,ownership"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "excluded_preserve_attr_list"),
                    "links"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "security_context"),
                    "system_u:object_r:bin_t:s0"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_reflink_without_explicit_mode_as_auto() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cp --reflink src dest", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_copy");
                assert_eq!(modifier_ids, vec!["reflink"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "reflink_mode").is_none());
                assert_eq!(argument_texts(&resolved.bound, "source_paths"), vec!["src"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_sparse_inline_mode() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cp --sparse=auto src dest", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_copy");
                assert_eq!(modifier_ids, vec!["sparse"]);
                assert_eq!(first_argument_text(&resolved.bound, "sparse_mode"), "auto");
                assert_eq!(argument_texts(&resolved.bound, "source_paths"), vec!["src"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_sparse_without_explicit_mode() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cp --sparse src dest", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_copy");
                assert_eq!(modifier_ids, vec!["sparse"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "sparse_mode").is_none());
                assert_eq!(argument_texts(&resolved.bound, "source_paths"), vec!["src"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_dd_prefixed_operands() {
        let registry = built_in_registry();
        let artifact = parse_command("dd if=payload.img of=/dev/sda bs=4M", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "dd");
                assert_eq!(resolved.selection.form.id.as_str(), "raw_copy");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_target"),
                    "payload.img"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_target"),
                    "/dev/sda"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_dd_help_without_copy_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("dd --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "dd");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_dd_help_without_prefixed_operand_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("dd --help if=payload.img of=/dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "dd");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "input_target").is_none());
                assert!(find_bound_parameter_opt(&resolved.bound, "output_target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_dd_version_without_prefixed_operand_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("dd --version if=payload.img of=/dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "dd");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "input_target").is_none());
                assert!(find_bound_parameter_opt(&resolved.bound, "output_target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_xargs_inline_and_attached_operands() {
        let registry = built_in_registry();
        for (command_line, slot_name, expected) in [
            ("xargs -d, rm -rf", "delimiter", ","),
            ("xargs --delimiter=, rm -rf", "delimiter", ","),
            ("xargs -apayload.txt rm -rf", "arg_file", "payload.txt"),
            (
                "xargs --arg-file=payload.txt rm -rf",
                "arg_file",
                "payload.txt",
            ),
            ("xargs -ESTOP rm -rf", "eof_marker", "STOP"),
            ("xargs -eSTOP rm -rf", "eof_marker", "STOP"),
            ("xargs --eof=STOP rm -rf", "eof_marker", "STOP"),
        ] {
            let artifact = parse_command(command_line, ShellKind::Bash).expect("expected parse");
            let command = artifact.commands.first().expect("expected one command");
            let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

            match result {
                ResolveInvocationResult::Resolved(resolved) => {
                    assert!(
                        find_bound_parameter_opt(&resolved.bound, slot_name).is_some(),
                        "missing {slot_name} binding for {command_line}; bound: {:?}",
                        resolved.bound
                    );
                    assert_eq!(
                        first_argument_text(&resolved.bound, slot_name),
                        expected,
                        "unexpected {slot_name} binding for {command_line}"
                    );
                    assert_eq!(
                        first_argument_text(&resolved.bound, "wrapped_command"),
                        "rm",
                        "unexpected wrapped command for {command_line}"
                    );
                }
                other => panic!("unexpected resolve result for {command_line}: {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_invocation_prefers_explicit_mke2fs_aliases_before_mkfs_family_coalescing() {
        let registry = built_in_registry();

        for command_line in [
            "mkfs.ext2 /dev/nvme0n1p1",
            "mkfs.ext3 /dev/nvme0n1p1",
            "mkfs.ext4 /dev/nvme0n1p1",
        ] {
            let artifact =
                parse_command(command_line, ShellKind::Bash).expect("expected parse to succeed");

            let command = artifact.commands.first().expect("expected one command");
            let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

            match result {
                ResolveInvocationResult::Resolved(resolved) => {
                    assert_eq!(
                        resolved.normalized_command_name,
                        command.command_name.as_deref().unwrap()
                    );
                    assert_eq!(resolved.profile.primary_name(), "mke2fs");
                    assert_eq!(resolved.selection.form.id.as_str(), "create_filesystem");
                    assert_eq!(
                        first_argument_text(&resolved.bound, "target"),
                        "/dev/nvme0n1p1"
                    );
                    assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                }
                other => panic!("unexpected resolve result for {command_line:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_invocation_still_coalesces_unknown_mkfs_family_to_mkfs_profile() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs.xfs /dev/nvme0n1p1", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.profile.primary_name(), "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "filesystem_target");
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_bracket_test_alias() {
        let registry = built_in_registry();
        let artifact =
            parse_command("[ -f Cargo.toml ]", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "[");
                assert_eq!(resolved.profile.primary_name(), "test");
                assert_eq!(resolved.selection.form.id.as_str(), "evaluate_expression");
                assert_eq!(
                    argument_texts(&resolved.bound, "expression"),
                    vec!["-f", "Cargo.toml", "]"]
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkfs --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_help_without_inline_type_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs --help --type=ext4 /dev/nvme0n1p1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"filesystem_type"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_dash_v_as_version_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkfs -V", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["verbose"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_version_without_inline_type_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs --version --type=ext4 /dev/nvme0n1p1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"filesystem_type"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_version_with_target_without_write_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs --version /dev/nvme0n1p1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_target_with_trailing_size() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs -t ext4 /dev/nvme0n1p1 1024", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "filesystem_target_with_trailing_size"
                );
                assert_eq!(modifier_ids, vec!["filesystem_type"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(first_argument_text(&resolved.bound, "size_blocks"), "1024");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_inline_long_filesystem_type() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs --type=ext4 /dev/nvme0n1p1 1024", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "filesystem_target_with_trailing_size"
                );
                assert_eq!(modifier_ids, vec!["filesystem_type"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(first_argument_text(&resolved.bound, "size_blocks"), "1024");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_dash_v_with_target_as_write_surface() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs -V -t ext4 /dev/nvme0n1p1", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "filesystem_target");
                assert_eq!(modifier_ids, vec!["filesystem_type", "verbose"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_double_dash_v_as_dry_run_read_surface() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs -V -V -t ext4 /dev/nvme0n1p1", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "dry_run_filesystem_target"
                );
                assert_eq!(modifier_ids, vec!["filesystem_type", "verbose"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_double_dash_v_with_size_as_dry_run_read_surface() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs -V -V -t ext4 /dev/nvme0n1p1 1024", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "dry_run_filesystem_target_with_trailing_size"
                );
                assert_eq!(modifier_ids, vec!["filesystem_type", "verbose"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(first_argument_text(&resolved.bound, "size_blocks"), "1024");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_double_dash_verbose_as_dry_run_read_surface() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkfs --verbose --verbose --type=ext4 /dev/nvme0n1p1",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "dry_run_filesystem_target"
                );
                assert_eq!(modifier_ids, vec!["filesystem_type", "verbose"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_dash_v_plus_verbose_as_dry_run_read_surface() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkfs -V --verbose --type=ext4 /dev/nvme0n1p1",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "dry_run_filesystem_target"
                );
                assert_eq!(modifier_ids, vec!["filesystem_type", "verbose"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_target_with_builder_operands_and_size() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkfs -t ext4 -E stride=16 /dev/nvme0n1p1 1024",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "filesystem_target_with_trailing_size"
                );
                assert_eq!(modifier_ids, vec!["filesystem_type"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(first_argument_text(&resolved.bound, "size_blocks"), "1024");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_target_with_forwarded_builder_operands() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs -t ext4 -L data -m 1 /dev/nvme0n1p1", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs");
                assert_eq!(resolved.selection.form.id.as_str(), "filesystem_target");
                assert_eq!(modifier_ids, vec!["filesystem_type"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "filesystem_type_name"),
                    "ext4"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1p1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_with_dedicated_profile() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkswap /dev/sda2", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.profile.primary_name(), "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "initialize_swap_area");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda2");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkswap --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_help_without_lock_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("mkswap --help --lock=yes /dev/sda2", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"lock"));
                assert_eq!(first_argument_text(&resolved.bound, "lock_mode"), "yes");
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_help_without_endianness_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkswap --help --endianness=native /dev/sda2",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"endianness"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "endianness_value"),
                    "native"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_version_without_target_side_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkswap -V /dev/sda2", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_version_without_inline_optional_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkswap --version --endianness=native --lock=nonblock /dev/sda2",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"endianness"));
                assert!(modifier_ids.contains(&"lock"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "endianness_value"),
                    "native"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_inline_optional_operands_without_consuming_target() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkswap --endianness=native --lock=yes --verbose /dev/sda2",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "initialize_swap_area");
                assert!(modifier_ids.contains(&"endianness"));
                assert!(modifier_ids.contains(&"lock"));
                assert!(modifier_ids.contains(&"verbose"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "endianness_value"),
                    "native"
                );
                assert_eq!(first_argument_text(&resolved.bound, "lock_mode"), "yes");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda2");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_bare_lock_without_consuming_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkswap --lock /dev/sda2", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "initialize_swap_area");
                assert_eq!(modifier_ids, vec!["lock"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "lock_mode").is_none());
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda2");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkswap_next_arg_optional_operands_without_consuming_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkswap -e native /dev/sda2", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkswap");
                assert_eq!(resolved.selection.form.id.as_str(), "initialize_swap_area");
                assert_eq!(modifier_ids, vec!["endianness"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "endianness_value"),
                    "native"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda2");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cfdisk_read_only_as_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cfdisk -r /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cfdisk");
                assert_eq!(resolved.profile.primary_name(), "cfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_table"
                );
                assert_eq!(modifier_ids, vec!["read_only"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cfdisk_default_as_partition_editor() {
        let registry = built_in_registry();
        let artifact = parse_command("cfdisk /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cfdisk");
                assert_eq!(resolved.profile.primary_name(), "cfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_partition_editor"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_gdisk_list_as_read_only() {
        let registry = built_in_registry();
        let artifact = parse_command("gdisk -l /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "gdisk");
                assert_eq!(resolved.profile.primary_name(), "gdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_table");
                assert_eq!(modifier_ids, vec!["list"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_gdisk_default_as_partition_editor() {
        let registry = built_in_registry();
        let artifact = parse_command("gdisk /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "gdisk");
                assert_eq!(resolved.profile.primary_name(), "gdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_partition_editor"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_bfs_as_format_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkfs.bfs /dev/sda1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkfs.bfs");
                assert_eq!(resolved.profile.primary_name(), "mkfs.bfs");
                assert_eq!(resolved.selection.form.id.as_str(), "create_filesystem");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda1");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_bfs_dash_upper_v_as_version_without_write_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs.bfs -V", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs.bfs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["volume_name"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_cramfs_as_directory_to_image() {
        let registry = built_in_registry();
        let artifact = parse_command("mkfs.cramfs ./rootfs rootfs.cramfs", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkfs.cramfs");
                assert_eq!(resolved.profile.primary_name(), "mkfs.cramfs");
                assert_eq!(resolved.selection.form.id.as_str(), "build_image");
                assert_eq!(
                    first_argument_text(&resolved.bound, "source_dir"),
                    "./rootfs"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_file"),
                    "rootfs.cramfs"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_cramfs_insert_file_as_additional_read_surface() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkfs.cramfs -i boot.img ./rootfs rootfs.cramfs",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs.cramfs");
                assert_eq!(resolved.selection.form.id.as_str(), "build_image");
                assert_eq!(modifier_ids, vec!["insert_file"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "insert_file_path"),
                    "boot.img"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "source_dir"),
                    "./rootfs"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_file"),
                    "rootfs.cramfs"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_minix_as_format_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkfs.minix /dev/sda1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkfs.minix");
                assert_eq!(resolved.profile.primary_name(), "mkfs.minix");
                assert_eq!(resolved.selection.form.id.as_str(), "create_filesystem");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda1");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfs_minix_badblocks_file_without_consuming_target() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mkfs.minix --badblocks badblocks.txt /dev/sda1",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mkfs.minix");
                assert_eq!(resolved.selection.form.id.as_str(), "create_filesystem");
                assert_eq!(modifier_ids, vec!["badblocks_file"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "badblocks_file_path"),
                    "badblocks.txt"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda1");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_as_format_target() {
        let registry = built_in_registry();
        let artifact = parse_command("mke2fs /dev/sda1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.profile.primary_name(), "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "create_filesystem");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda1");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_no_create_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mke2fs -n /dev/sda1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_layout");
                assert_eq!(modifier_ids, vec!["no_create"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda1");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_dash_upper_v_as_version_without_write_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("mke2fs -V", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_dash_upper_v_with_target_as_version_without_write_effects()
     {
        let registry = built_in_registry();
        let artifact =
            parse_command("mke2fs -V /dev/sda1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_dash_upper_v_with_other_operands_as_version_without_write_effects()
     {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mke2fs -V -l badblocks.txt -d /tmp/rootdir /dev/sda1",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"list_bad_blocks_from_file"));
                assert!(modifier_ids.contains(&"root_directory"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "bad_blocks_file"),
                    "badblocks.txt"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "root_directory_path"),
                    "/tmp/rootdir"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_extended_options_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("mke2fs -E help", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["extended_options"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "extended_options_value"),
                    "help"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_usage_type_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mke2fs -T help /dev/sda1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["usage_type"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "usage_type_name"),
                    "help"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_dash_lower_v_as_format_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mke2fs -v /dev/sda1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "create_filesystem");
                assert_eq!(modifier_ids, vec!["verbose"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda1");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mke2fs_extended_operands_as_format_target() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "mke2fs -C 65536 -g 32768 -L data -M /mnt/data -e continue -z undo.e2undo /dev/sda1 1024",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mke2fs");
                assert_eq!(resolved.selection.form.id.as_str(), "create_filesystem");
                assert_eq!(
                    modifier_ids,
                    vec![
                        "cluster_size",
                        "blocks_per_group",
                        "volume_label",
                        "last_mounted_directory",
                        "error_behavior",
                        "undo_file",
                    ]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "cluster_size_value"),
                    "65536"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "blocks_per_group_value"),
                    "32768"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "volume_label_value"),
                    "data"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "last_mounted_directory_path"),
                    "/mnt/data"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "error_behavior_value"),
                    "continue"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "undo_file_path"),
                    "undo.e2undo"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda1");
                assert_eq!(argument_texts(&resolved.bound, "size"), vec!["1024"]);
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_blkdiscard_destructive_device_target() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "blkdiscard --secure --offset 4096 /dev/nvme0n1",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "blkdiscard");
                assert_eq!(resolved.selection.form.id.as_str(), "discard_device");
                assert!(modifier_ids.contains(&"secure"));
                assert!(modifier_ids.contains(&"offset"));
                assert_eq!(first_argument_text(&resolved.bound, "offset_bytes"), "4096");
                assert_eq!(
                    first_argument_text(&resolved.bound, "target"),
                    "/dev/nvme0n1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_blkdiscard_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("blkdiscard --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "blkdiscard");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_blkdiscard_help_without_offset_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("blkdiscard --help -o 4096 /dev/nvme0n1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "blkdiscard");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"offset"));
                assert_eq!(first_argument_text(&resolved.bound, "offset_bytes"), "4096");
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_blkdiscard_help_without_inline_optional_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "blkdiscard --help --offset=4096 --length=8192 /dev/nvme0n1",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "blkdiscard");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"offset"));
                assert!(modifier_ids.contains(&"length"));
                assert_eq!(first_argument_text(&resolved.bound, "offset_bytes"), "4096");
                assert_eq!(first_argument_text(&resolved.bound, "length_bytes"), "8192");
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_blkdiscard_version_without_target_side_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("blkdiscard -V /dev/nvme0n1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "blkdiscard");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_blkdiscard_version_without_inline_optional_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "blkdiscard --version --offset=4096 --length=8192 /dev/nvme0n1",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "blkdiscard");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"offset"));
                assert!(modifier_ids.contains(&"length"));
                assert_eq!(first_argument_text(&resolved.bound, "offset_bytes"), "4096");
                assert_eq!(first_argument_text(&resolved.bound, "length_bytes"), "8192");
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_with_destructive_modifier() {
        let registry = built_in_registry();
        let artifact = parse_command("wipefs -a /dev/sda", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "wipe_device_signatures"
                );
                assert_eq!(modifier_ids, vec!["destructive_all"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_offset_as_destructive_write() {
        let registry = built_in_registry();
        let artifact = parse_command("wipefs -o 0x438 /dev/sda /dev/sdb", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "wipe_device_signatures"
                );
                assert_eq!(modifier_ids, vec!["offset"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "offset_value"),
                    vec!["0x438"]
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda", "/dev/sdb"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_non_destructive_inspect_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("wipefs -n /dev/sda", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device");
                assert_eq!(modifier_ids, vec!["no_act"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_lock_mode_without_consuming_targets() {
        let registry = built_in_registry();
        let artifact = parse_command("wipefs --lock=nonblock /dev/sda /dev/sdb", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device");
                assert_eq!(modifier_ids, vec!["lock"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda", "/dev/sdb"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_bare_lock_without_consuming_targets() {
        let registry = built_in_registry();
        let artifact = parse_command("wipefs --lock /dev/sda /dev/sdb", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device");
                assert_eq!(modifier_ids, vec!["lock"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "lock_mode").is_none());
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda", "/dev/sdb"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_help_without_lock_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("wipefs --help --lock=nonblock /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"lock"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_help_without_inline_optional_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "wipefs --help --offset=4096 --lock=nonblock /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"offset"));
                assert!(modifier_ids.contains(&"lock"));
                assert_eq!(first_argument_text(&resolved.bound, "offset_value"), "4096");
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_version_without_inline_optional_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "wipefs --version --offset=4096 --lock=nonblock /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"offset"));
                assert!(modifier_ids.contains(&"lock"));
                assert_eq!(first_argument_text(&resolved.bound, "offset_value"), "4096");
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wipefs_destructive_no_act_as_preview() {
        let registry = built_in_registry();
        let artifact = parse_command("wipefs -a -n /dev/sda /dev/sdb", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "wipefs");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "preview_wipe_device_signatures"
                );
                assert_eq!(modifier_ids, vec!["destructive_all", "no_act"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda", "/dev/sdb"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_shred_block_device_overwrite() {
        let registry = built_in_registry();
        let artifact =
            parse_command("shred -n 5 /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "shred");
                assert_eq!(resolved.profile.primary_name(), "shred");
                assert_eq!(resolved.selection.form.id.as_str(), "overwrite_targets");
                assert_eq!(modifier_ids, vec!["iterations"]);
                assert_eq!(first_argument_text(&resolved.bound, "iteration_count"), "5");
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_shred_remove_mode_with_delete_effect() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "shred --remove=wipesync ./payload.bin ./payload-2.bin",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "shred");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "overwrite_and_remove_targets"
                );
                assert_eq!(modifier_ids, vec!["remove_targets"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "remove_how"),
                    "wipesync"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["./payload.bin", "./payload-2.bin"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::DeletePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_shred_random_source_as_read_effect() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "shred --random-source=/dev/urandom /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "shred");
                assert_eq!(resolved.selection.form.id.as_str(), "overwrite_targets");
                assert_eq!(modifier_ids, vec!["random_source"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "random_source_path"),
                    "/dev/urandom"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["/dev/sda"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_shred_inline_long_operands() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "shred --iterations=5 --size=4K --random-source=/dev/urandom /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "shred");
                assert_eq!(resolved.selection.form.id.as_str(), "overwrite_targets");
                assert!(modifier_ids.contains(&"iterations"));
                assert!(modifier_ids.contains(&"size"));
                assert!(modifier_ids.contains(&"random_source"));
                assert_eq!(first_argument_text(&resolved.bound, "iteration_count"), "5");
                assert_eq!(first_argument_text(&resolved.bound, "size_value"), "4K");
                assert_eq!(
                    first_argument_text(&resolved.bound, "random_source_path"),
                    "/dev/urandom"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["/dev/sda"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_shred_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("shred --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "shred");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_shred_help_without_inline_long_operand_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "shred --help --iterations=5 --size=4K --random-source=/dev/urandom /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "shred");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"iterations"));
                assert!(modifier_ids.contains(&"size"));
                assert!(modifier_ids.contains(&"random_source"));
                assert_eq!(first_argument_text(&resolved.bound, "iteration_count"), "5");
                assert_eq!(first_argument_text(&resolved.bound, "size_value"), "4K");
                assert_eq!(
                    first_argument_text(&resolved.bound, "random_source_path"),
                    "/dev/urandom"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_shred_help_without_random_source_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "shred --help --random-source=/dev/urandom /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "shred");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"random_source"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "random_source_path"),
                    "/dev/urandom"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_help_without_modifier_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --help --backup table.gpt /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"backup_partition_table"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_file"),
                    "table.gpt"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_usage_without_modifier_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sgdisk --usage --backup table.gpt /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_usage");
                assert!(modifier_ids.contains(&"usage"));
                assert!(modifier_ids.contains(&"backup_partition_table"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_file"),
                    "table.gpt"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_version_with_device_as_operational_form() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sgdisk --version --backup table.gpt /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "backup_partition_table"
                );
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"backup_partition_table"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_file"),
                    "table.gpt"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_with_destructive_modifier() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --zap-all /dev/sda", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(modifier_ids, vec!["destructive_partition_table"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_print_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -p /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device");
                assert_eq!(modifier_ids, vec!["inspect_device"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_display_alignment_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -D /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device");
                assert_eq!(modifier_ids, vec!["inspect_device"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_print_mbr_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -O /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device");
                assert_eq!(modifier_ids, vec!["inspect_device"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_set_alignment_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -a 2048 -p /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device");
                assert_eq!(modifier_ids, vec!["set_alignment", "inspect_device"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "alignment_value"),
                    "2048"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_backup_as_read_plus_write() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --backup table.gpt /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "backup_partition_table"
                );
                assert_eq!(modifier_ids, vec!["backup_partition_table"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_file"),
                    "table.gpt"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_partition_delete_as_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk --delete=2 /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_partition_layout"
                );
                assert_eq!(modifier_ids, vec!["delete_partition"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionLayoutMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_mbr_to_gpt_as_layout_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk --mbrtogpt /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_partition_layout"
                );
                assert_eq!(modifier_ids, vec!["convert_mbr_to_gpt"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionLayoutMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_randomize_guids_as_state_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --randomize-guids /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_partition_table_state"
                );
                assert_eq!(modifier_ids, vec!["randomize_guids"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_sort_as_state_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk --sort /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_partition_table_state"
                );
                assert_eq!(modifier_ids, vec!["sort_partition_table"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_pretend_delete_as_read_only_simulation() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --pretend --delete=2 /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "simulate_partition_table_mutation"
                );
                assert_eq!(modifier_ids, vec!["pretend", "delete_partition"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_partition_info_as_read_only() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk --info=2 /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_info"
                );
                assert_eq!(modifier_ids, vec!["inspect_partition_info"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_load_backup_as_mutation_with_read_effect() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --load-backup table.gpt /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_partition_layout"
                );
                assert_eq!(modifier_ids, vec!["load_partition_table_backup"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_file"),
                    "table.gpt"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::ReadPath]
                );
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionLayoutMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_pretend_load_backup_as_read_only_simulation() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sgdisk --pretend --load-backup table.gpt /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "simulate_partition_table_mutation"
                );
                assert_eq!(modifier_ids, vec!["pretend", "load_partition_table_backup"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_file"),
                    "table.gpt"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_replicate_as_mutation_with_read_effect() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --replicate /dev/src /dev/dst", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_partition_layout"
                );
                assert_eq!(modifier_ids, vec!["replicate_partition_table"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "source_device"),
                    "/dev/src"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/dst");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::ReadPath]
                );
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionLayoutMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_attribute_show_as_read_only() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -A 4:show /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_attributes"
                );
                assert_eq!(modifier_ids, vec!["change_partition_attributes"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "attribute_spec"),
                    "4:show"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_attribute_get_as_read_only() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -A 4:get:10 /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_attributes"
                );
                assert_eq!(modifier_ids, vec!["change_partition_attributes"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "attribute_spec"),
                    "4:get:10"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_attribute_get_hex_mask_as_read_only() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -A 4:get:0x2 /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_attributes"
                );
                assert_eq!(modifier_ids, vec!["change_partition_attributes"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "attribute_spec"),
                    "4:get:0x2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_attribute_set_as_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sgdisk -A 4:set:2 /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_partition_table_state"
                );
                assert_eq!(modifier_ids, vec!["change_partition_attributes"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "attribute_spec"),
                    "4:set:2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_pretend_attribute_set_as_read_only_simulation() {
        let registry = built_in_registry();
        let artifact = parse_command("sgdisk --pretend -A 4:set:2 /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "simulate_partition_table_mutation"
                );
                assert_eq!(modifier_ids, vec!["pretend", "change_partition_attributes"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "attribute_spec"),
                    "4:set:2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sgdisk_pretend_change_name_as_read_only_simulation() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sgdisk --pretend --change-name=1:root /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sgdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "simulate_partition_table_mutation"
                );
                assert_eq!(modifier_ids, vec!["pretend", "change_partition_name"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_name_spec"),
                    "1:root"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_destructive_device_command() {
        let registry = built_in_registry();
        let artifact = parse_command("parted --script /dev/sda mklabel gpt", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(resolved.selection.form.id.as_str(), "mutate_disk_label");
                assert_eq!(modifier_ids, vec!["script"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_destructive_device_command_after_setup_tokens() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "parted --script /dev/sda unit s mklabel gpt",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(resolved.selection.form.id.as_str(), "mutate_disk_label");
                assert_eq!(modifier_ids, vec!["script"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_destructive_command_after_select_retargeting() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "parted /dev/sda select /dev/sdb mklabel gpt",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "mutate_disk_label_after_select"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sdb");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_create_partition_after_select_retargeting() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "parted /dev/sda select /dev/sdb mkpart primary ext4 1MiB 100MiB",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "create_partition_after_select"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sdb");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionLayoutMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_set_metadata_after_select_retargeting() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "parted /dev/sda select /dev/sdb name 1 rootfs",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "set_partition_metadata_after_select"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sdb");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_print_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("parted /dev/sda print", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(resolved.selection.form.id.as_str(), "print_device");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_help_command_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("parted /dev/sda help", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(resolved.selection.form.id.as_str(), "help_command");
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_quit_command_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("parted /dev/sda quit", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(resolved.selection.form.id.as_str(), "quit_command");
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_select_command_without_write_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("parted /dev/sda select /dev/sdb", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(resolved.selection.form.id.as_str(), "select_device");
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_unit_command_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("parted /dev/sda unit s", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(resolved.selection.form.id.as_str(), "set_display_unit");
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_parted_interactive_device_session_as_write_surface() {
        let registry = built_in_registry();
        let artifact = parse_command("parted /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "parted");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_list_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact = parse_command("fdisk -l /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(modifier_ids, vec!["list"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "device_paths"),
                    "/dev/sda"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_list_details_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact = parse_command("fdisk --list-details /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(modifier_ids, vec!["list_details"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "device_paths"),
                    "/dev/sda"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_get_size_with_bytes_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("fdisk --bytes -s /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_device_size");
                assert!(modifier_ids.contains(&"bytes"));
                assert!(modifier_ids.contains(&"get_size"));
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_optional_inline_operands_without_consuming_target() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "fdisk --color=always --compatibility=dos --units=sectors --lock=nonblock --wipe=always --wipe-partitions=never /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert!(modifier_ids.contains(&"color"));
                assert!(modifier_ids.contains(&"compatibility"));
                assert!(modifier_ids.contains(&"units"));
                assert!(modifier_ids.contains(&"lock"));
                assert!(modifier_ids.contains(&"wipe"));
                assert!(modifier_ids.contains(&"wipe_partitions"));
                assert_eq!(first_argument_text(&resolved.bound, "color_mode"), "always");
                assert_eq!(
                    first_argument_text(&resolved.bound, "compatibility_mode"),
                    "dos"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "units_value"),
                    "sectors"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert_eq!(first_argument_text(&resolved.bound, "wipe_mode"), "always");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wipe_partitions_mode"),
                    "never"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_bare_lock_without_consuming_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("fdisk --lock /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert_eq!(modifier_ids, vec!["lock"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "lock_mode").is_none());
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_help_without_lock_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("fdisk --help --lock=nonblock /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"lock"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_help_without_inline_optional_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "fdisk --help --lock=nonblock --wipe=always --wipe-partitions=never /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"lock"));
                assert!(modifier_ids.contains(&"wipe"));
                assert!(modifier_ids.contains(&"wipe_partitions"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert_eq!(first_argument_text(&resolved.bound, "wipe_mode"), "always");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wipe_partitions_mode"),
                    "never"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_version_without_target_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("fdisk -V /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_version_without_inline_optional_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "fdisk --version --lock=nonblock --wipe=always --wipe-partitions=never /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"lock"));
                assert!(modifier_ids.contains(&"wipe"));
                assert!(modifier_ids.contains(&"wipe_partitions"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert_eq!(first_argument_text(&resolved.bound, "wipe_mode"), "always");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wipe_partitions_mode"),
                    "never"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_short_attached_optional_operands_without_consuming_target()
    {
        let registry = built_in_registry();
        let artifact = parse_command(
            "fdisk -cnondos -Lalways -usectors -wnever -Wauto /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert!(modifier_ids.contains(&"compatibility"));
                assert!(modifier_ids.contains(&"color"));
                assert!(modifier_ids.contains(&"units"));
                assert!(modifier_ids.contains(&"wipe"));
                assert!(modifier_ids.contains(&"wipe_partitions"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "compatibility_mode"),
                    "nondos"
                );
                assert_eq!(first_argument_text(&resolved.bound, "color_mode"), "always");
                assert_eq!(
                    first_argument_text(&resolved.bound, "units_value"),
                    "sectors"
                );
                assert_eq!(first_argument_text(&resolved.bound, "wipe_mode"), "never");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wipe_partitions_mode"),
                    "auto"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_scripted_session_with_stdin_payload() {
        let registry = built_in_registry();
        let artifact = parse_command("fdisk /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(
            &registry,
            command,
            InvocationRuntimeContext::new().with_stdin_payload_available(),
        );

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "scripted_device_session"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::ConsumeStdin]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fdisk_interactive_device_session_as_write_surface() {
        let registry = built_in_registry();
        let artifact = parse_command("fdisk /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "fdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_json_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --json /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert!(modifier_ids.is_empty());
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_list_free_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --list-free /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_show_geometry_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --show-geometry /dev/sda /dev/sdb", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda", "/dev/sdb"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_show_size_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --show-size /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_lock_mode_without_consuming_target() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --lock=nonblock --json /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(modifier_ids, vec!["lock"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_bare_lock_without_consuming_target() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --lock --json /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(modifier_ids, vec!["lock"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "lock_mode").is_none());
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_help_without_lock_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --help --lock=nonblock --json /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"lock"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "lock_mode"),
                    "nonblock"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_help_without_backup_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --help --backup-pt-sectors --backup-file table.bin /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(
                    find_bound_parameter_opt(&resolved.bound, "backup_output_path_long").is_none()
                );
                assert!(find_bound_parameter_opt(&resolved.bound, "target").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_version_without_target_side_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk -v /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "device_paths").is_none());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_color_inline_without_consuming_target() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --color=always --json /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "list_partition_tables");
                assert_eq!(modifier_ids, vec!["color"]);
                assert_eq!(first_argument_text(&resolved.bound, "color_mode"), "always");
                assert_eq!(
                    argument_texts(&resolved.bound, "device_paths"),
                    vec!["/dev/sda"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_unit_short_attached_without_consuming_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk -uS /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert!(modifier_ids.contains(&"unit"));
                assert_eq!(first_argument_text(&resolved.bound, "unit_name"), "S");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_delete_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --delete /dev/sda 1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_partitions");
                assert!(modifier_ids.is_empty());
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    argument_texts(&resolved.bound, "delete_partition_numbers"),
                    vec!["1"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionLayoutMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_backup_as_read_plus_write() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --backup-pt-sectors -O table.bin /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "backup_partition_table"
                );
                assert!(modifier_ids.is_empty());
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_output_path"),
                    "table.bin"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_backup_with_inline_long_output_path() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --backup-pt-sectors --backup-file=table.bin /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "backup_partition_table"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_output_path_long"),
                    "table.bin"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_backup_with_default_output_path() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --backup-pt-sectors /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "backup_partition_table"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_backup_flag_as_read_only_backup_form() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --backup /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "backup_partition_table"
                );
                assert_eq!(modifier_ids, vec!["backup"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_short_backup_flag_as_read_only_backup_form() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk -b /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "backup_partition_table"
                );
                assert_eq!(modifier_ids, vec!["backup"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_scripted_session_with_stdin_payload() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(
            &registry,
            command,
            InvocationRuntimeContext::new().with_stdin_payload_available(),
        );

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "scripted_device_session"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::ConsumeStdin]
                );
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableSessionTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_no_act_scripted_session_as_read_only() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --no-act /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(
            &registry,
            command,
            InvocationRuntimeContext::new().with_stdin_payload_available(),
        );

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "dry_run_scripted_device_session"
                );
                assert_eq!(modifier_ids, vec!["no_act"]);
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::ConsumeStdin]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_partno_partition_session() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk -N 2 /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert_eq!(modifier_ids, vec!["partno"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number_selector"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableSessionTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_no_act_partno_session_as_read_only() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --no-act -N 2 /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "dry_run_interactive_device_session"
                );
                assert!(modifier_ids.contains(&"no_act"));
                assert!(modifier_ids.contains(&"partno"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number_selector"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_move_data_partition_session() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --move-data -N 2 /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert_eq!(modifier_ids, vec!["move_data", "partno"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number_selector"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_move_data_inline_mode_without_consuming_target() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --move-data=auto -N 2 /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert_eq!(modifier_ids, vec!["move_data", "partno"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "move_data_mode"),
                    "auto"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number_selector"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_rejects_sfdisk_move_data_without_partno() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --move-data /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        assert!(matches!(
            result,
            ResolveInvocationResult::SelectionError {
                gap_kind: ResolveGapKind::FormSelectionUnmatched,
                error: BindError::NoFormMatched { .. },
                partial_bound: None,
                ..
            }
        ));
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_move_use_fsync_with_move_data_and_partno() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --move-data --move-use-fsync -N 2 /dev/sda",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "interactive_device_session"
                );
                assert_eq!(modifier_ids, vec!["move_data", "move_use_fsync", "partno"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number_selector"),
                    "2"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_rejects_sfdisk_move_use_fsync_without_move_data() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --move-use-fsync -N 2 /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        assert!(matches!(
            result,
            ResolveInvocationResult::SelectionError {
                gap_kind: ResolveGapKind::FormSelectionUnmatched,
                error: BindError::NoFormMatched { .. },
                ..
            }
        ));
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_label_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --part-label /dev/sda 1 rootfs", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "set_partition_label");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "label_value"),
                    vec!["rootfs"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_label_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --part-label /dev/sda 1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_label"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_disk_id_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --disk-id /dev/sda 0x1234abcd", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "set_disk_id");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    argument_texts(&resolved.bound, "disk_id_value"),
                    vec!["0x1234abcd"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_disk_id_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --disk-id /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_disk_id");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_type_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --part-type /dev/sda 1 0fc63daf-8483-4772-8e79-3d69d8477de4",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "set_partition_type");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "type_value"),
                    vec!["0fc63daf-8483-4772-8e79-3d69d8477de4"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_short_c_alias_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk -c /dev/sda 1 0x83", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "set_partition_type");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(argument_texts(&resolved.bound, "type_value"), vec!["0x83"]);
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_type_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --part-type /dev/sda 1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_type"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_id_alias_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --id /dev/sda 1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_type"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_uuid_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --part-uuid /dev/sda 1 11111111-2222-3333-4444-555555555555",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "set_partition_uuid");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "uuid_value"),
                    vec!["11111111-2222-3333-4444-555555555555"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_uuid_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --part-uuid /dev/sda 1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_uuid"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_attrs_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sfdisk --part-attrs /dev/sda 1 RequiredPartition",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "set_partition_attributes"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "attrs_value"),
                    vec!["RequiredPartition"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_part_attrs_as_read_only_inspection() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --part-attrs /dev/sda 1", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_partition_attributes"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    first_argument_text(&resolved.bound, "partition_number"),
                    "1"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_activate_as_read_only_without_partition_numbers() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --activate /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_active_partitions"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_activate_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --activate /dev/sda 1", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "set_active_partitions");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(
                    argument_texts(&resolved.bound, "activate_partition_numbers"),
                    vec!["1"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_reorder_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact =
            parse_command("sfdisk --reorder /dev/sda", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(resolved.selection.form.id.as_str(), "reorder_partitions");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::PartitionTableStateMutationTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sfdisk_relocate_as_partition_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command("sfdisk --relocate gpt-bak-std /dev/sda", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sfdisk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "relocate_partition_headers"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "relocate_operation"),
                    "gpt-bak-std"
                );
                assert_eq!(first_argument_text(&resolved.bound, "target"), "/dev/sda");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_attributes_only_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("cp --attributes-only src dest", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "default_attributes_only"
                );
                assert_eq!(modifier_ids, vec!["attributes_only"]);
                assert_eq!(argument_texts(&resolved.bound, "source_paths"), vec!["src"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_hard_link_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("cp -l src dest", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_hard_link");
                assert_eq!(modifier_ids, vec!["hard_link"]);
                assert_eq!(argument_texts(&resolved.bound, "source_paths"), vec!["src"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TargetPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_symbolic_link_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("cp -s src dest", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_symbolic_link");
                assert_eq!(modifier_ids, vec!["symbolic_link"]);
                assert_eq!(argument_texts(&resolved.bound, "source_paths"), vec!["src"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TargetPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_target_directory_attributes_only_without_raw_write_catastrophic_semantic()
     {
        let registry = built_in_registry();
        let artifact = parse_command("cp --attributes-only -t out src-a src-b", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "target_directory_attributes_only"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_target_directory_hard_link_without_raw_write_catastrophic_semantic()
     {
        let registry = built_in_registry();
        let artifact =
            parse_command("cp -l -t out src-a src-b", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "target_directory_hard_link"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TargetPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_target_directory_symbolic_link_without_raw_write_catastrophic_semantic()
     {
        let registry = built_in_registry();
        let artifact =
            parse_command("cp -s -t out src-a src-b", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "target_directory_symbolic_link"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TargetPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cmake_build_dir_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cmake -S . -B build", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cmake");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "configure_or_build_project"
                );
                assert_eq!(first_argument_text(&resolved.bound, "source_dir"), ".");
                assert_eq!(first_argument_text(&resolved.bound, "build_dir"), "build");
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_meson_prefix_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("meson setup builddir --prefix /usr/local", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "meson");
                assert_eq!(resolved.selection.form.id.as_str(), "project_operation");
                assert_eq!(
                    first_argument_text(&resolved.bound, "install_prefix"),
                    "/usr/local"
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkdocs_site_dir_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("mkdocs build --site-dir public", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkdocs");
                assert_eq!(resolved.selection.form.id.as_str(), "build_site");
                assert_eq!(first_argument_text(&resolved.bound, "site_dir"), "public");
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_nikola_output_dir_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact =
            parse_command("nikola build -o output-alt", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "nikola");
                assert_eq!(resolved.selection.form.id.as_str(), "site_command");
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_dir"),
                    "output-alt"
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_pyreverse_output_dir_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("pyreverse -d diagrams src/pkg", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "pyreverse");
                assert_eq!(resolved.selection.form.id.as_str(), "generate_diagrams");
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_dir"),
                    "diagrams"
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_split_prefix_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("split -b 1M big.bin chunks/part-", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "split");
                assert_eq!(resolved.selection.form.id.as_str(), "split_with_prefix");
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_prefix"),
                    "chunks/part-"
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_csplit_prefix_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("csplit -f pref input.txt /END/", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "csplit");
                assert_eq!(resolved.selection.form.id.as_str(), "split_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_prefix"),
                    "pref"
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_truncate_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact =
            parse_command("truncate -s 0 ./build.log", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "truncate");
                assert_eq!(resolved.selection.form.id.as_str(), "resize_targets");
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["./build.log"]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mypy_report_directory_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("mypy --html-report reports src", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mypy");
                assert_eq!(resolved.selection.form.id.as_str(), "type_check_project");
                assert_eq!(
                    argument_texts(&resolved.bound, "report_directory"),
                    vec!["reports"]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mypy_junit_xml_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("mypy --junit-xml report.xml src", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mypy");
                assert_eq!(resolved.selection.form.id.as_str(), "type_check_project");
                assert_eq!(
                    first_argument_text(&resolved.bound, "junit_xml_output"),
                    "report.xml"
                );
                assert!(effect_kinds(&resolved.bound).contains(&EffectKind::WritePath));
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cp_default_copy_with_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("cp src dest", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cp");
                assert_eq!(resolved.selection.form.id.as_str(), "default_copy");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert_eq!(
                    catastrophic_semantic_classes(&resolved.bound),
                    vec![CatastrophicSemanticClass::RawWriteTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_default_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "install src dest",
            "install",
            "default_install",
            &[EffectKind::ReadPath, EffectKind::WritePath],
        );
    }

    #[test]
    fn resolve_invocation_resolves_tee_with_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("tee out.log", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "tee");
                assert_eq!(resolved.selection.form.id.as_str(), "duplicate_stream");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert_eq!(
                    catastrophic_semantic_classes(&resolved.bound),
                    vec![CatastrophicSemanticClass::RawWriteTarget]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_tree_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "tree -o tree.txt src",
            "tree",
            "tree_to_file",
            &[EffectKind::ReadPath, EffectKind::WritePath],
        );
    }

    #[test]
    fn resolve_invocation_resolves_uniq_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "uniq in.txt out.txt",
            "uniq",
            "unique_to_file",
            &[
                EffectKind::ReadPath,
                EffectKind::WritePath,
                EffectKind::TransformData,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_sort_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "sort -o sorted.txt input.txt",
            "sort",
            "sort_to_file",
            &[
                EffectKind::ReadPath,
                EffectKind::TransformData,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_shuf_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "shuf -o shuffled.txt input.txt",
            "shuf",
            "shuffle_to_file",
            &[
                EffectKind::ReadPath,
                EffectKind::TransformData,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_pygmentize_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "pygmentize -o out.html app.py",
            "pygmentize",
            "highlight_to_file",
            &[
                EffectKind::ReadPath,
                EffectKind::TransformData,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_scrapy_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "scrapy crawl quotes -o out.json",
            "scrapy",
            "project_command",
            &[
                EffectKind::LoadConfig,
                EffectKind::NetworkEndpoint,
                EffectKind::ExecuteImportedPackageLogic,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_safety_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "safety check --save-json report.json",
            "safety",
            "scan_dependencies",
            &[
                EffectKind::ReadPath,
                EffectKind::NetworkEndpoint,
                EffectKind::TransformData,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_deep_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "deep --output report.json input.json",
            "deep",
            "analyze_inputs",
            &[
                EffectKind::ReadPath,
                EffectKind::TransformData,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_flake8_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "flake8 --output-file lint.txt src",
            "flake8",
            "lint_targets",
            &[
                EffectKind::ReadPath,
                EffectKind::LoadConfig,
                EffectKind::ExecuteImportedPackageLogic,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_gtts_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "gtts-cli -o voice.mp3 hello",
            "gtts-cli",
            "synthesize_speech",
            &[
                EffectKind::NetworkEndpoint,
                EffectKind::TransformData,
                EffectKind::WritePath,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_qr_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "qr --output code.png hello",
            "qr",
            "encode_qr",
            &[EffectKind::TransformData, EffectKind::WritePath],
        );
    }

    #[test]
    fn resolve_invocation_resolves_sqlfluff_write_surfaces_without_raw_write_catastrophic_semantic()
    {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "sqlfluff fix query.sql",
            "sqlfluff",
            "fix_sql",
            &[
                EffectKind::LoadConfig,
                EffectKind::WritePath,
                EffectKind::ExecuteImportedPackageLogic,
            ],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "sqlfluff lint query.sql --write-output fixed.sql",
            "sqlfluff",
            "lint_sql",
            &[
                EffectKind::ReadPath,
                EffectKind::LoadConfig,
                EffectKind::TransformData,
                EffectKind::WritePath,
                EffectKind::ExecuteImportedPackageLogic,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_gcc_outputs_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "gcc main.c",
            "gcc",
            "compile_to_default_output",
            &[EffectKind::ReadPath, EffectKind::WritePath],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "gcc -o app main.c",
            "gcc",
            "compile_to_explicit_output",
            &[EffectKind::ReadPath, EffectKind::WritePath],
        );
    }

    #[test]
    fn resolve_invocation_resolves_bunzip2_output_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "bunzip2 data.txt.bz2",
            "bunzip2",
            "decompress_files",
            &[EffectKind::ReadPath, EffectKind::WritePath],
        );
    }

    #[test]
    fn resolve_invocation_resolves_ssh_keygen_modes_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "ssh-keygen -f key",
            "ssh-keygen",
            "mutate_or_generate_key",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "ssh-keygen -l -f key.pub",
            "ssh-keygen",
            "read_key_material",
            &[EffectKind::ReadPath],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "ssh-keygen -D /tmp/pkcs11.so",
            "ssh-keygen",
            "load_pkcs11_provider",
            &[EffectKind::LoadInProcessCode],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "ssh-keygen -R example.com -f known_hosts",
            "ssh-keygen",
            "mutate_known_hosts",
            &[EffectKind::WritePath],
        );
    }

    #[test]
    fn resolve_invocation_resolves_cpio_modes_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "cpio -F archive.cpio -i",
            "cpio",
            "extract_archive",
            &[EffectKind::ReadPath],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "cpio -I archive.cpio -i",
            "cpio",
            "extract_archive",
            &[EffectKind::ReadPath],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "cpio -O archive.cpio -o src.txt",
            "cpio",
            "create_archive",
            &[EffectKind::ReadPath, EffectKind::WritePath],
        );
    }

    #[test]
    fn resolve_invocation_resolves_dotenv_modes_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "dotenv list",
            "dotenv",
            "query_default_env_file",
            &[EffectKind::LoadConfig, EffectKind::TransformData],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "dotenv -f local.env get API_KEY",
            "dotenv",
            "query_named_env_file",
            &[EffectKind::LoadConfig, EffectKind::TransformData],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "dotenv set API_KEY value",
            "dotenv",
            "edit_default_env_file",
            &[EffectKind::LoadConfig, EffectKind::WritePath],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "dotenv -f local.env unset API_KEY",
            "dotenv",
            "edit_named_env_file",
            &[EffectKind::LoadConfig, EffectKind::WritePath],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "dotenv run -- python app.py",
            "dotenv",
            "run_default_env_file",
            &[EffectKind::LoadConfig, EffectKind::DispatchCommand],
        );

        let artifact = parse_command("dotenv run python app.py", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "dotenv");
                assert_eq!(resolved.bound.form_id.as_str(), "run_default_env_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "python"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["app.py"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::LoadConfig, EffectKind::DispatchCommand]
                );

                let dispatch = collect_dispatch_command_candidates(&resolved.bound);
                assert_eq!(dispatch.len(), 1);
                assert_eq!(dispatch[0].command.text, "python");
                assert_eq!(
                    dispatch[0]
                        .argv
                        .iter()
                        .map(|argument| argument.text.as_str())
                        .collect::<Vec<_>>(),
                    vec!["app.py"]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command("dotenv run -- python app.py", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "python"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["app.py"]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command("dotenv -f local.env run python app.py", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "run_named_env_file");
                assert_eq!(
                    argument_texts(&resolved.bound, "env_file"),
                    vec!["local.env"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "python"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["app.py"]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mv_default_move() {
        let registry = built_in_registry();
        let artifact = parse_command("mv old-a old-b dest", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mv");
                assert_eq!(resolved.selection.form.id.as_str(), "default_move");
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["old-a", "old-b"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::MovePath, EffectKind::WritePath]
                );
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::MoveSourcePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mv_target_directory_with_move_source_hard_deny() {
        let registry = built_in_registry();
        let artifact = parse_command("mv -t dest old-a old-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "mv");
                assert_eq!(resolved.selection.form.id.as_str(), "target_directory");
                assert_eq!(modifier_ids, vec!["target_directory"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["old-a", "old-b"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "dest"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::MovePath, EffectKind::WritePath]
                );
                assert_eq!(
                    host_risk_semantic_classes(&resolved.bound),
                    vec![crate::HostRiskSemanticClass::MoveSourcePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("install --help", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_help_without_target_directory_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command("install --help --target-directory=out src", ShellKind::Bash)
            .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"target_directory"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_version_without_target_directory_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "install --version --target-directory=out src",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"target_directory"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_target_directory_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("install -t out src-a src-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "target_directory");
                assert_eq!(modifier_ids, vec!["target_directory"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["src-a", "src-b"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_inline_long_operands() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "install --group=staff --mode=755 --owner=root --suffix=.bak --target-directory=out src-a src-b",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "target_directory");
                assert!(modifier_ids.contains(&"group"));
                assert!(modifier_ids.contains(&"mode"));
                assert!(modifier_ids.contains(&"owner"));
                assert!(modifier_ids.contains(&"suffix"));
                assert!(modifier_ids.contains(&"target_directory"));
                assert_eq!(first_argument_text(&resolved.bound, "group_name"), "staff");
                assert_eq!(first_argument_text(&resolved.bound, "mode_value"), "755");
                assert_eq!(first_argument_text(&resolved.bound, "owner_name"), "root");
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_suffix"),
                    ".bak"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_directory"),
                    "out"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["src-a", "src-b"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mknod_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mknod fifo p", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mknod");
                assert_eq!(resolved.selection.form.id.as_str(), "create_special_file");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::MetadataMutation]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkfifo_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkfifo pipe", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkfifo");
                assert_eq!(resolved.selection.form.id.as_str(), "create_fifo");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_link_without_raw_write_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact =
            parse_command("link source dest", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "link");
                assert_eq!(resolved.selection.form.id.as_str(), "create_hard_link");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TargetPath, EffectKind::WritePath]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_strip_program_inline_operand() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "install -s --strip-program=/bin/true src dest",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "default_install");
                assert!(modifier_ids.contains(&"strip"));
                assert!(modifier_ids.contains(&"strip_program"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "strip_program_path"),
                    "/bin/true"
                );
                assert_eq!(first_argument_text(&resolved.bound, "source_paths"), "src");
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_directory_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("install -d dir-a dir-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "create_directories");
                assert_eq!(
                    argument_texts(&resolved.bound, "directory_paths"),
                    vec!["dir-a", "dir-b"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_install_backup_and_context_modifiers() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "install -b --suffix=.bak --preserve-context --context=system_u:object_r:bin_t:s0 src dest",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "install");
                assert_eq!(resolved.selection.form.id.as_str(), "default_install");
                assert_eq!(
                    modifier_ids,
                    vec![
                        "backup_default",
                        "suffix",
                        "preserve_security_context",
                        "set_security_context"
                    ]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "backup_suffix"),
                    ".bak"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "security_context"),
                    "system_u:object_r:bin_t:s0"
                );
                assert_eq!(first_argument_text(&resolved.bound, "source_paths"), "src");
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "dest"
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_ln_default_link() {
        let registry = built_in_registry();
        let artifact = parse_command("ln target-path link-path", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "ln");
                assert_eq!(resolved.selection.form.id.as_str(), "default_link");
                assert_eq!(
                    argument_texts(&resolved.bound, "link_targets"),
                    vec!["target-path"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "link_path"),
                    "link-path"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TargetPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_delete_paths() {
        let registry = built_in_registry();
        let artifact = parse_command("rm victim-a victim-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["victim-a", "victim-b"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_help_without_delete_effect() {
        let registry = built_in_registry();
        let artifact =
            parse_command("rm --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_help_without_destructive_modifier_side_effects() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "rm --help --interactive=never --no-preserve-root /",
            ShellKind::Bash,
        )
        .expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert!(modifier_ids.contains(&"help"));
                assert!(modifier_ids.contains(&"interactive_never"));
                assert!(modifier_ids.contains(&"no_preserve_root"));
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_version_without_delete_effect() {
        let registry = built_in_registry();
        let artifact =
            parse_command("rm --version", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert_eq!(modifier_ids, vec!["version"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_version_without_destructive_modifier_side_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("rm --version -rf /", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "show_version");
                assert!(modifier_ids.contains(&"version"));
                assert!(modifier_ids.contains(&"recursive"));
                assert!(modifier_ids.contains(&"force"));
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_destructive_modifiers() {
        let registry = built_in_registry();
        let artifact = parse_command("rm -rfv --no-preserve-root /", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(
                    modifier_ids,
                    vec!["recursive", "force", "no_preserve_root", "verbose"]
                );
                assert_eq!(argument_texts(&resolved.bound, "path_targets"), vec!["/"]);
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_optional_operand_long_modifiers() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "rm --interactive=never --preserve-root=all victim",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(modifier_ids, vec!["interactive_never", "preserve_root_all"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["victim"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_interactive_always_long_modifier() {
        let registry = built_in_registry();
        let artifact = parse_command("rm --interactive=always victim", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(modifier_ids, vec!["interactive_always"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["victim"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_interactive_once_short_modifier() {
        let registry = built_in_registry();
        let artifact =
            parse_command("rm -I victim", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(modifier_ids, vec!["interactive_once"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["victim"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_interactive_default_long_modifier() {
        let registry = built_in_registry();
        let artifact = parse_command("rm --interactive victim", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(modifier_ids, vec!["interactive_always"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["victim"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_preserve_root_default_long_modifier() {
        let registry = built_in_registry();
        let artifact = parse_command("rm --preserve-root victim", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(modifier_ids, vec!["preserve_root"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["victim"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_directory_only_modifier() {
        let registry = built_in_registry();
        let artifact =
            parse_command("rm -d empty-dir", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(modifier_ids, vec!["dir"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["empty-dir"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_one_file_system_recursive_modifiers() {
        let registry = built_in_registry();
        let artifact = parse_command("rm --one-file-system -r victim-dir", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(modifier_ids, vec!["recursive", "one_file_system"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["victim-dir"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rm_dashdash_literal_path_target() {
        let registry = built_in_registry();
        let artifact = parse_command("rm -- -dangerous-looking-name", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "rm");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["-dangerous-looking-name"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_mkdir_create_directories() {
        let registry = built_in_registry();
        let artifact =
            parse_command("mkdir dir-a dir-b", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mkdir");
                assert_eq!(resolved.selection.form.id.as_str(), "create_directories");
                assert_eq!(
                    argument_texts(&resolved.bound, "directory_paths"),
                    vec!["dir-a", "dir-b"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_chmod_metadata_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command("chmod -R +x script-a script-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "chmod");
                assert_eq!(resolved.selection.form.id.as_str(), "change_mode");
                assert_eq!(modifier_ids, vec!["recursive"]);
                assert_eq!(first_argument_text(&resolved.bound, "mode"), "+x");
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["script-a", "script-b"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ChangeMode, EffectKind::MetadataMutation]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
                assert_eq!(
                    resolved.bound.effects[0]
                        .extensions
                        .get("metadata_mutation.raw_operand_slot")
                        .and_then(|value| value.as_str()),
                    Some("mode")
                );
                assert!(
                    resolved.bound.effects[0]
                        .catastrophic
                        .required_modifiers
                        .is_empty()
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_chown_owner_group_operand_shape() {
        let registry = built_in_registry();
        let artifact = parse_command("chown root:staff script.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "chown");
                assert_eq!(resolved.selection.form.id.as_str(), "change_owner_or_group");
                assert_eq!(
                    first_argument_text(&resolved.bound, "owner_spec"),
                    "root:staff"
                );
                assert!(matches!(
                    resolved.bound.bound_parameters[0].semantic,
                    SemanticType::StructuredValue(StructuredValueSemantic {
                        context: StructuredValueContext::OwnerGroupSpec
                    })
                ));
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["script.sh"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::MetadataMutation]
                );
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_recursive_chown_metadata_mutation_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("chown -R root:root script.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "chown");
                assert_eq!(modifier_ids, vec!["recursive"]);
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_rejects_invalid_chown_owner_group_shape() {
        let registry = built_in_registry();
        let artifact =
            parse_command("chown : script.sh", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        assert!(matches!(
            result,
            ResolveInvocationResult::SelectionError {
                error: BindError::NoFormMatched { .. },
                ..
            }
        ));
    }

    #[test]
    fn resolve_invocation_resolves_chgrp_metadata_mutation() {
        let registry = built_in_registry();
        let artifact = parse_command("chgrp staff script.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "chgrp");
                assert_eq!(resolved.selection.form.id.as_str(), "change_group");
                assert_eq!(first_argument_text(&resolved.bound, "group"), "staff");
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["script.sh"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ChangeGroup]);
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_recursive_chgrp_metadata_mutation_catastrophic_semantic() {
        let registry = built_in_registry();
        let artifact = parse_command("chgrp -R root script.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "chgrp");
                assert_eq!(modifier_ids, vec!["recursive"]);
                assert!(catastrophic_semantic_classes(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_metadata_mutation_commands_without_catastrophic_semantic_classes()
     {
        let registry = built_in_registry();

        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "mount /dev/sda1 /mnt",
            "mount",
            "mount_filesystem",
            &[
                EffectKind::TargetPath,
                EffectKind::WritePath,
                EffectKind::MetadataMutation,
            ],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "hostname buildbox",
            "hostname",
            "set_hostname",
            &[EffectKind::MetadataMutation],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "ifconfig eth0 up",
            "ifconfig",
            "configure_interface",
            &[EffectKind::MetadataMutation],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "crontab -r",
            "crontab",
            "remove_crontab",
            &[EffectKind::MetadataMutation],
        );
        assert_resolves_command_without_catastrophic_semantic(
            &registry,
            "chcon user_u:object_r:file_t:s0 file",
            "chcon",
            "change_security_context",
            &[EffectKind::MetadataMutation],
        );
    }

    #[test]
    fn resolve_invocation_resolves_base64_decode_transform() {
        let registry = built_in_registry();
        let artifact = parse_command("base64 -d payload.b64", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "base64");
                assert_eq!(resolved.selection.form.id.as_str(), "decode_stream");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["payload.b64"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::TransformData]
                );
                assert_eq!(
                    resolved.bound.effects[1]
                        .extensions
                        .get("transform.kind")
                        .and_then(|value| value.as_str()),
                    Some("decode")
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_zcat_decompress_stream() {
        let registry = built_in_registry();
        let artifact = parse_command("zcat payload.gz other.gz", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "zcat");
                assert_eq!(resolved.selection.form.id.as_str(), "decompress_stream");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["payload.gz", "other.gz"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::TransformData]
                );
                assert_eq!(
                    resolved.bound.effects[1]
                        .extensions
                        .get("transform.kind")
                        .and_then(|value| value.as_str()),
                    Some("decompress")
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_iconv_file_to_file_transform() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "iconv -f utf-8 -t ascii -o output.txt input.txt",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "iconv");
                assert_eq!(resolved.selection.form.id.as_str(), "convert_to_file");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["input.txt"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "output.txt"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::TransformData,
                        EffectKind::WritePath
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_jq_filter_program_file() {
        let registry = built_in_registry();
        let artifact = parse_command("jq -f filter.jq input.json", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "jq");
                assert_eq!(resolved.selection.form.id.as_str(), "filter_program_file");
                assert_eq!(
                    argument_texts(&resolved.bound, "filter_files"),
                    vec!["filter.jq"]
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["input.json"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::TransformData,
                        EffectKind::ReadPath
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_jq_multi_operand_file_flags() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "jq --rawfile secret secret.txt --slurpfile rows rows.json --argfile cfg config.json --arg name value --argjson count 3 '.x' input.json",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "jq");
                assert_eq!(resolved.selection.form.id.as_str(), "filter_program");
                assert_eq!(first_argument_text(&resolved.bound, "filter_program"), ".x");
                assert_eq!(
                    argument_texts(&resolved.bound, "rawfile_paths"),
                    vec!["secret.txt"]
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "slurpfile_paths"),
                    vec!["rows.json"]
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "argfile_paths"),
                    vec!["config.json"]
                );
                assert_eq!(argument_texts(&resolved.bound, "arg_values"), vec!["value"]);
                assert_eq!(argument_texts(&resolved.bound, "argjson_values"), vec!["3"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["input.json"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::TransformData,
                        EffectKind::ReadPath,
                        EffectKind::ReadPath,
                        EffectKind::ReadPath,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_does_not_bind_jq_second_arg_flags_from_inline_long_operand() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "jq --rawfile=secret secret.txt '.x' input.json",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert!(find_bound_parameter_opt(&resolved.bound, "rawfile_paths").is_none());
            }
            ResolveInvocationResult::SelectionError { .. } => {}
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_jq_null_input_filter_program() {
        let registry = built_in_registry();
        let artifact = parse_command("jq -n '.items | length'", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "jq");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "null_input_filter_program"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "filter_program"),
                    ".items | length"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TransformData]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_xxd_reverse_file_to_file_transform() {
        let registry = built_in_registry();
        let artifact = parse_command("xxd -r -p payload.hex payload.bin", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "xxd");
                assert_eq!(resolved.selection.form.id.as_str(), "reverse_file_to_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_path"),
                    "payload.hex"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "payload.bin"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::WritePath,
                        EffectKind::TransformData
                    ]
                );
                assert_eq!(
                    resolved.bound.effects[2]
                        .extensions
                        .get("transform.kind")
                        .and_then(|value| value.as_str()),
                    Some("decode")
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_openssl_enc_decrypt_file_to_file_transform() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "openssl enc -d -aes-256-cbc -in payload.enc -out payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "openssl");
                assert_eq!(resolved.bound.subcommand_path, vec!["enc".to_string()]);
                assert_eq!(resolved.selection.form.id.as_str(), "decrypt_file_to_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_path"),
                    "payload.enc"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::TransformData,
                        EffectKind::ReadPath,
                        EffectKind::WritePath
                    ]
                );
                assert_eq!(
                    resolved.bound.effects[0]
                        .extensions
                        .get("transform.kind")
                        .and_then(|value| value.as_str()),
                    Some("decrypt")
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_make_default_task_config_execution() {
        let registry = built_in_registry();
        let artifact =
            parse_command("make build", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "make");
                assert_eq!(resolved.selection.form.id.as_str(), "run_default");
                assert_eq!(argument_texts(&resolved.bound, "targets"), vec!["build"]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::LoadConfig, EffectKind::ExecuteConfigDefinedTask]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::ToolConventionPath(target)
                        if target.path == "Makefile"
                            && target.convention == "make.makefile"
                            && target.purpose == Some(crate::PathPurpose::TaskConfig)
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_kill_process_control() {
        let registry = built_in_registry();
        let artifact =
            parse_command("kill 1234", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "kill");
                assert_eq!(resolved.selection.form.id.as_str(), "signal_targets");
                assert_eq!(argument_texts(&resolved.bound, "targets"), vec!["1234"]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ControlProcess]
                );

                let semantic = &find_bound_parameter_opt(&resolved.bound, "targets")
                    .expect("expected targets parameter")
                    .semantic;
                assert!(matches!(
                    semantic,
                    SemanticType::ProcessTarget(process)
                        if process.kind == ProcessTargetKind::Unknown && !process.broad_match
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_pkill_full_pattern_process_control() {
        let registry = built_in_registry();
        let artifact =
            parse_command("pkill -f bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "pkill");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "process_pattern_targets"
                );
                assert_eq!(modifier_ids, vec!["full"]);
                assert_eq!(first_argument_text(&resolved.bound, "targets"), "bash");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ControlProcess]
                );

                let semantic = &find_bound_parameter_opt(&resolved.bound, "targets")
                    .expect("expected targets parameter")
                    .semantic;
                assert!(matches!(
                    semantic,
                    SemanticType::ProcessTarget(process)
                        if process.kind == ProcessTargetKind::ProcessPattern
                            && process.broad_match
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_fg_job_control() {
        let registry = built_in_registry();
        let artifact = parse_command("fg %1", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "fg");
                assert_eq!(resolved.selection.form.id.as_str(), "resume_job");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "%1");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ControlProcess]
                );

                let semantic = &find_bound_parameter_opt(&resolved.bound, "target")
                    .expect("expected target parameter")
                    .semantic;
                assert!(matches!(
                    semantic,
                    SemanticType::ProcessTarget(process)
                        if process.kind == ProcessTargetKind::JobSpec && !process.broad_match
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_killall_process_control() {
        let registry = built_in_registry();
        let artifact =
            parse_command("killall ssh-agent", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "killall");
                assert_eq!(resolved.selection.form.id.as_str(), "process_name_targets");
                assert_eq!(
                    argument_texts(&resolved.bound, "targets"),
                    vec!["ssh-agent"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ControlProcess]
                );

                let semantic = &find_bound_parameter_opt(&resolved.bound, "targets")
                    .expect("expected targets parameter")
                    .semantic;
                assert!(matches!(
                    semantic,
                    SemanticType::ProcessTarget(process)
                        if process.kind == ProcessTargetKind::ProcessName && process.broad_match
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_bg_job_control() {
        let registry = built_in_registry();
        let artifact = parse_command("bg %1", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bg");
                assert_eq!(resolved.selection.form.id.as_str(), "resume_job");
                assert_eq!(first_argument_text(&resolved.bound, "target"), "%1");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ControlProcess]
                );

                let semantic = &find_bound_parameter_opt(&resolved.bound, "target")
                    .expect("expected target parameter")
                    .semantic;
                assert!(matches!(
                    semantic,
                    SemanticType::ProcessTarget(process)
                        if process.kind == ProcessTargetKind::JobSpec && !process.broad_match
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_npm_run_script_subcommand() {
        let registry = built_in_registry();
        let artifact =
            parse_command("npm run build", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "npm");
                assert_eq!(resolved.selection.form.id.as_str(), "run_script");
                assert_eq!(resolved.bound.subcommand_path, vec!["run".to_string()]);
                assert_eq!(first_argument_text(&resolved.bound, "script_name"), "build");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::LoadConfig, EffectKind::ExecuteConfigDefinedTask]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::ToolConventionPath(target)
                        if target.path == "package.json"
                            && target.convention == "npm.package_json"
                            && target.purpose == Some(crate::PathPurpose::TaskConfig)
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_npm_install_as_imported_package_execution() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "npm install -D https://example.test/pkg.tgz",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "npm");
                assert_eq!(resolved.selection.form.id.as_str(), "install_packages");
                assert_eq!(resolved.bound.subcommand_path, vec!["install".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["https://example.test/pkg.tgz"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::LoadConfig,
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_npm_ci_as_lockfile_import_execution_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("npm ci --ignore-scripts", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "npm");
                assert_eq!(resolved.selection.form.id.as_str(), "install_from_lockfile");
                assert_eq!(resolved.bound.subcommand_path, vec!["ci".to_string()]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::LoadConfig,
                        EffectKind::LoadConfig,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_npm_exec_package_modifier() {
        let registry = built_in_registry();
        let artifact = parse_command("npm exec --package cowsay -- cowsay hello", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "npm");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "exec_package_from_modifier"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["exec".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["cowsay"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_npx_package_execution() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "npx -y https://example.test/tool.tgz --help",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "npx");
                assert_eq!(resolved.selection.form.id.as_str(), "exec_package");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["https://example.test/tool.tgz"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cargo_build_config_loads() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cargo build", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cargo");
                assert_eq!(resolved.selection.form.id.as_str(), "build_project");
                assert_eq!(resolved.bound.subcommand_path, vec!["build".to_string()]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::LoadConfig, EffectKind::LoadConfig]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::ToolConventionPath(target)
                        if target.path == "Cargo.toml"
                            && target.convention == "cargo.manifest"
                            && target.purpose == Some(crate::PathPurpose::ProjectConfig)
                ));
                assert!(matches!(
                    &resolved.bound.effects[1].target,
                    crate::EffectTarget::ToolConventionPath(target)
                        if target.path == ".cargo/config.toml"
                            && target.convention == "cargo.tool_config"
                            && target.purpose == Some(crate::PathPurpose::ToolConfig)
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clone_repository() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "git clone https://example.test/repo.git ./repo",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.selection.form.id.as_str(), "clone_repository");
                assert_eq!(resolved.bound.subcommand_path, vec!["clone".to_string()]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "repository"),
                    "https://example.test/repo.git"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination"),
                    "./repo"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clone_recursive_submodules_with_destination() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "git clone --recurse-submodules https://example.test/repo.git ./repo",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "clone_repository_with_recursive_submodules"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clone".to_string()]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "repository"),
                    "https://example.test/repo.git"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination"),
                    "./repo"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::NetworkEndpoint,
                        EffectKind::WritePath,
                        EffectKind::LoadConfig,
                        EffectKind::WritePath
                    ]
                );
                assert!(matches!(
                    &resolved.bound.effects[3].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree {
                            root: Some(slot),
                            path_set,
                            ..
                        }
                    ) if slot.as_str() == "destination"
                        && *path_set
                            == caushell_types::RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_agent_readonly_queries() {
        let registry = built_in_registry();

        let cases = [
            (
                "git status --short",
                "status",
                "inspect_worktree_status",
                &[EffectKind::TransformData][..],
            ),
            (
                "git status -- src/main.rs",
                "status",
                "inspect_worktree_status",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "git diff --check",
                "diff",
                "inspect_diff",
                &[EffectKind::TransformData],
            ),
            (
                "git diff -- integrations/vscode/extension.js",
                "diff",
                "inspect_diff_pathspecs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "git log --oneline -8",
                "log",
                "inspect_history",
                &[EffectKind::TransformData],
            ),
            (
                "git rev-parse --short HEAD",
                "rev-parse",
                "parse_revisions",
                &[EffectKind::TransformData],
            ),
            (
                "git ls-files -- src/cli/probe.py docs/readme.md",
                "ls-files",
                "list_index_paths",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "git show --stat HEAD",
                "show",
                "inspect_object_or_history",
                &[EffectKind::TransformData],
            ),
        ];

        for (command_line, subcommand, form_id, expected_effects) in cases {
            let artifact =
                parse_command(command_line, ShellKind::Bash).expect("expected parse to succeed");
            let command = artifact.commands.first().expect("expected one command");
            let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

            match result {
                ResolveInvocationResult::Resolved(resolved) => {
                    assert_eq!(resolved.normalized_command_name, "git");
                    assert_eq!(resolved.bound.subcommand_path, vec![subcommand.to_string()]);
                    assert_eq!(resolved.selection.form.id.as_str(), form_id);
                    let effects = effect_kinds(&resolved.bound);
                    for expected_effect in expected_effects {
                        assert!(
                            effects.contains(expected_effect),
                            "expected {command_line:?} to include effect {expected_effect:?}; got {effects:?}",
                        );
                    }
                    assert!(
                        !effects.contains(&EffectKind::WritePath),
                        "expected {command_line:?} to remain read-only; got {effects:?}",
                    );
                    assert!(
                        !effects.contains(&EffectKind::DeletePath),
                        "expected {command_line:?} not to delete paths; got {effects:?}",
                    );
                }
                other => panic!("unexpected resolve result for {command_line:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_add_index_updates() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "git add crates/caushell-profile/profiles/git.yaml crates/caushell-profile/src/resolve.rs",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.bound.subcommand_path, vec!["add".to_string()]);
                assert_eq!(resolved.selection.form.id.as_str(), "update_index");
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec![
                        "crates/caushell-profile/profiles/git.yaml",
                        "crates/caushell-profile/src/resolve.rs"
                    ]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert!(matches!(
                    &resolved.bound.effects[1].target,
                    crate::EffectTarget::ToolConventionPath(target)
                        if target.path == ".git/index"
                            && target.convention == "git.index"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command("git add --dry-run src/main.rs", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_index_update");
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::TransformData));
                assert!(
                    !effects.contains(&EffectKind::WritePath),
                    "dry-run add must not write the index; got {effects:?}",
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_diff_output_write() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "git diff --output patch.diff -- src/main.rs",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.bound.subcommand_path, vec!["diff".to_string()]);
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_diff_pathspecs"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "patch.diff"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::TransformData));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_network_sync_commands() {
        let registry = built_in_registry();

        assert_resolves_command_with_effects(
            &registry,
            "git push",
            "git",
            "upload_refs",
            &[EffectKind::LoadConfig, EffectKind::NetworkEndpoint],
        );

        let artifact = parse_command("git fetch --dry-run origin main", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.bound.subcommand_path, vec!["fetch".to_string()]);
                assert_eq!(resolved.selection.form.id.as_str(), "fetch_refs_dry_run");
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::LoadConfig));
                assert!(effects.contains(&EffectKind::NetworkEndpoint));
                assert!(effects.contains(&EffectKind::TransformData));
                assert!(
                    !effects.contains(&EffectKind::WritePath),
                    "dry-run fetch must not write repository metadata; got {effects:?}",
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        assert_resolves_command_with_effects(
            &registry,
            "git fetch origin main",
            "git",
            "fetch_refs",
            &[
                EffectKind::LoadConfig,
                EffectKind::NetworkEndpoint,
                EffectKind::WritePath,
            ],
        );

        let artifact = parse_command("git pull --ff-only origin main", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.bound.subcommand_path, vec!["pull".to_string()]);
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "pull_and_update_worktree"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::LoadConfig));
                assert!(effects.contains(&EffectKind::NetworkEndpoint));
                assert!(effects.contains(&EffectKind::WritePath));
                assert!(resolved.bound.effects.iter().any(|effect| matches!(
                    &effect.target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
                )));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_commit_hook_execution() {
        let registry = built_in_registry();
        let artifact = parse_command("git commit -m 'ship it'", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "commit_message_with_hooks"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["commit".to_string()]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::LoadConfig,
                        EffectKind::ReadPath,
                        EffectKind::WritePath,
                        EffectKind::WritePath,
                        EffectKind::ExecuteHook
                    ]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::ToolConventionPath(target)
                        if target.path == ".git/config"
                            && target.convention == "git.local_config"
                            && target.purpose == Some(crate::PathPurpose::ToolConfig)
                ));
                assert!(matches!(
                    &resolved.bound.effects[4].target,
                    crate::EffectTarget::None
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_commit_editor_and_no_verify_modes() {
        let registry = built_in_registry();

        let artifact =
            parse_command("git commit", ShellKind::Bash).expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "commit_editor_with_hooks"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ExecuteHook));
                assert!(effects.contains(&EffectKind::OpenInteractiveEscapeSurface));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command("git commit --no-verify -m 'ship it'", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "commit_message_no_verify"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(!effects.contains(&EffectKind::ExecuteHook));
                assert!(!effects.contains(&EffectKind::OpenInteractiveEscapeSurface));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command("git commit --no-verify", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "commit_editor_no_verify"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(!effects.contains(&EffectKind::ExecuteHook));
                assert!(effects.contains(&EffectKind::OpenInteractiveEscapeSurface));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_branch_tag_and_remote_modes() {
        let registry = built_in_registry();

        assert_resolves_command_with_effects(
            &registry,
            "git branch --show-current",
            "git",
            "list_branches",
            &[EffectKind::TransformData],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git branch feature/main",
            "git",
            "create_branch_ref",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git branch -d old-topic",
            "git",
            "delete_branch_refs",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git branch -D old-topic",
            "git",
            "delete_branch_refs",
            &[EffectKind::WritePath, EffectKind::RepositoryOperation],
        );

        assert_resolves_command_with_effects(
            &registry,
            "git tag -l 'v*'",
            "git",
            "list_tags",
            &[EffectKind::TransformData],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git tag -a v1.2.3",
            "git",
            "create_tag_editor",
            &[
                EffectKind::WritePath,
                EffectKind::OpenInteractiveEscapeSurface,
            ],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git tag -a v1.2.3 -m release",
            "git",
            "create_tag",
            &[EffectKind::WritePath],
        );

        assert_resolves_command_with_effects(
            &registry,
            "git remote -v",
            "git",
            "list_remotes",
            &[EffectKind::LoadConfig, EffectKind::TransformData],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git remote set-url origin https://example.test/repo.git",
            "git",
            "set_remote_url",
            &[EffectKind::NetworkEndpoint, EffectKind::WritePath],
        );

        let artifact = parse_command("git remote prune -n origin", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.selection.form.id.as_str(), "prune_remote_dry_run");
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::NetworkEndpoint));
                assert!(!effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_stash_switch_merge_rebase_and_cherry_pick_modes() {
        let registry = built_in_registry();

        assert_resolves_command_with_effects(
            &registry,
            "git stash list",
            "git",
            "list_stashes",
            &[EffectKind::TransformData],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git stash push -m savepoint -- src",
            "git",
            "push_stash",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git stash pop",
            "git",
            "pop_stash",
            &[EffectKind::WritePath],
        );

        assert_resolves_command_with_effects(
            &registry,
            "git switch main",
            "git",
            "switch_worktree",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git switch -c feature/main",
            "git",
            "create_and_switch_branch",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git switch -C feature/main origin/main",
            "git",
            "create_and_switch_branch",
            &[EffectKind::WritePath],
        );

        assert_resolves_command_with_effects(
            &registry,
            "git merge --abort",
            "git",
            "merge_abort_or_continue",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git merge --edit feature/main",
            "git",
            "merge_editor_with_hooks",
            &[
                EffectKind::WritePath,
                EffectKind::ExecuteHook,
                EffectKind::OpenInteractiveEscapeSurface,
            ],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git merge --no-verify feature/main",
            "git",
            "merge_no_verify",
            &[EffectKind::WritePath],
        );

        assert_resolves_command_with_effects(
            &registry,
            "git rebase --show-current-patch",
            "git",
            "rebase_show_current_patch",
            &[EffectKind::TransformData],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git rebase -i main",
            "git",
            "interactive_rebase_with_hooks",
            &[
                EffectKind::WritePath,
                EffectKind::ExecuteHook,
                EffectKind::OpenInteractiveEscapeSurface,
            ],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git rebase --exec 'make test' main",
            "git",
            "rebase_with_hooks",
            &[
                EffectKind::WritePath,
                EffectKind::ExecuteHook,
                EffectKind::ExecutePayload,
            ],
        );

        assert_resolves_command_with_effects(
            &registry,
            "git cherry-pick --abort",
            "git",
            "cherry_pick_abort_skip_continue",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git cherry-pick -n abc123",
            "git",
            "cherry_pick_no_commit",
            &[EffectKind::WritePath],
        );
        assert_resolves_command_with_effects(
            &registry,
            "git cherry-pick -e abc123",
            "git",
            "cherry_pick_editor",
            &[
                EffectKind::WritePath,
                EffectKind::OpenInteractiveEscapeSurface,
            ],
        );
    }

    #[test]
    fn resolve_invocation_resolves_git_rm_delete_paths() {
        let registry = built_in_registry();
        let artifact = parse_command("git rm Cargo.lock target/debug.log", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.selection.form.id.as_str(), "delete_paths");
                assert_eq!(resolved.bound.subcommand_path, vec!["rm".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["Cargo.lock", "target/debug.log"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DeletePath, EffectKind::RepositoryOperation]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_rm_preview_without_delete_effect() {
        let registry = built_in_registry();
        let artifact = parse_command("git rm -n tracked.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_delete_paths");
                assert_eq!(resolved.bound.subcommand_path, vec!["rm".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["tracked.txt"]
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_rm_cached_without_delete_effect() {
        let registry = built_in_registry();
        let artifact = parse_command("git rm --cached tracked.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.selection.form.id.as_str(), "unstage_paths");
                assert_eq!(resolved.bound.subcommand_path, vec!["rm".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["tracked.txt"]
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_rm_pathspec_from_file_as_read_surface() {
        let registry = built_in_registry();
        let artifact = parse_command("git rm --pathspec-from-file list.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_paths_from_file"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["rm".to_string()]);
                assert!(modifier_ids.contains(&"pathspec_from_file"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "pathspec_file"),
                    "list.txt"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::DeletePath,
                        EffectKind::RepositoryOperation,
                        EffectKind::ReadPath
                    ]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_rm_pathspec_file_nul_as_file_driven_delete_surface() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "git rm --pathspec-from-file listnul.bin --pathspec-file-nul",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_paths_from_file"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["rm".to_string()]);
                assert!(modifier_ids.contains(&"pathspec_from_file"));
                assert!(modifier_ids.contains(&"pathspec_file_nul"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "pathspec_file"),
                    "listnul.bin"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::DeletePath,
                        EffectKind::RepositoryOperation,
                        EffectKind::ReadPath
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_rm_inline_long_pathspec_from_file() {
        let registry = built_in_registry();
        let artifact = parse_command("git rm --pathspec-from-file=list.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_paths_from_file"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["rm".to_string()]);
                assert!(modifier_ids.contains(&"pathspec_from_file"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "pathspec_file"),
                    "list.txt"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::DeletePath,
                        EffectKind::RepositoryOperation,
                        EffectKind::ReadPath
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_explicit_delete_paths() {
        let registry = built_in_registry();
        let artifact = parse_command("git clean -fdx build/ tmp/", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_untracked_and_ignored_pathspecs"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["build/", "tmp/"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DeletePath, EffectKind::RepositoryOperation]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_repo_scoped_delete() {
        let registry = built_in_registry();
        let artifact =
            parse_command("git clean -fdx", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_untracked_and_ignored_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DeletePath, EffectKind::RepositoryOperation]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::UntrackedAndIgnored
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_force_as_untracked_delete() {
        let registry = built_in_registry();
        let artifact =
            parse_command("git clean -f", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_untracked_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DeletePath, EffectKind::RepositoryOperation]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::UntrackedOnly
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_force_x_as_ignored_delete() {
        let registry = built_in_registry();
        let artifact =
            parse_command("git clean -fX", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_ignored_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DeletePath, EffectKind::RepositoryOperation]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::IgnoredOnly
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_preview_without_force() {
        let registry = built_in_registry();
        let artifact = parse_command("git clean -n build/", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_untracked_pathspecs"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert_eq!(argument_texts(&resolved.bound, "pathspecs"), vec!["build/"]);
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_preview_x_without_force() {
        let registry = built_in_registry();
        let artifact = parse_command("git clean -nX ignored.top", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_ignored_pathspecs"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["ignored.top"]
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_preview_quiet_without_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("git clean -nq", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_untracked_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert!(modifier_ids.contains(&"dry_run"));
                assert!(modifier_ids.contains(&"quiet"));
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_preview_with_exclude_pattern() {
        let registry = built_in_registry();
        let artifact = parse_command("git clean -n -e a.tmp", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "inspect_untracked_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert!(modifier_ids.contains(&"dry_run"));
                assert!(modifier_ids.contains(&"exclude_pattern"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "exclude_pattern_value"),
                    "a.tmp"
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_clean_force_with_exclude_pattern_as_coarse_scope() {
        let registry = built_in_registry();
        let artifact = parse_command("git clean -f -e a.tmp", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "delete_untracked_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["clean".to_string()]);
                assert!(modifier_ids.contains(&"force"));
                assert!(modifier_ids.contains(&"exclude_pattern"));
                assert_eq!(
                    first_argument_text(&resolved.bound, "exclude_pattern_value"),
                    "a.tmp"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DeletePath, EffectKind::RepositoryOperation]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::UntrackedOnly
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_reset_hard_repo_scoped_write() {
        let registry = built_in_registry();
        let artifact =
            parse_command("git reset --hard", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.selection.form.id.as_str(), "reset_hard_worktree");
                assert_eq!(resolved.bound.subcommand_path, vec!["reset".to_string()]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::RepositoryOperation]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_reset_hard_revision() {
        let registry = built_in_registry();
        let artifact = parse_command("git -C repo reset --hard origin/main", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.selection.form.id.as_str(), "reset_hard_worktree");
                assert_eq!(resolved.bound.subcommand_path, vec!["reset".to_string()]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "revision"),
                    "origin/main"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::WritePath,
                        EffectKind::RepositoryOperation,
                        EffectKind::TargetPath
                    ]
                );
                assert!(matches!(
                    resolved.bound.effects.iter().find_map(|effect| match &effect.target {
                        crate::EffectTarget::MutationScope(
                            crate::MutationScopeTarget::RepositoryWorktree { path_set, .. },
                        ) => Some(path_set),
                        _ => None,
                    }),
                    Some(path_set) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_apply_patch_mutation_scope() {
        let registry = built_in_registry();
        let artifact = parse_command("git apply patch.diff", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "apply_patch_to_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["apply".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "patch_paths"),
                    vec!["patch.diff"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert!(matches!(
                    &resolved.bound.effects[1].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::PatchSelectedTracked
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_apply_check_as_read_only() {
        let registry = built_in_registry();
        let artifact = parse_command("git apply --check patch.diff", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(resolved.selection.form.id.as_str(), "inspect_patch_only");
                assert_eq!(resolved.bound.subcommand_path, vec!["apply".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "patch_paths"),
                    vec!["patch.diff"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_apply_index_as_index_and_worktree_write() {
        let registry = built_in_registry();
        let artifact = parse_command("git apply --index patch.diff", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "apply_patch_to_index_and_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["apply".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "patch_paths"),
                    vec!["patch.diff"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::WritePath,
                        EffectKind::WritePath
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_am_with_hooks() {
        let registry = built_in_registry();
        let artifact =
            parse_command("git am patch.mbox", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "apply_mailbox_with_hooks"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["am".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "mailbox_paths"),
                    vec!["patch.mbox"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::LoadConfig,
                        EffectKind::WritePath,
                        EffectKind::ExecuteHook
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_am_no_verify_without_hook() {
        let registry = built_in_registry();
        let artifact = parse_command("git am --no-verify patch.mbox", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "apply_mailbox_no_verify"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["am".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "mailbox_paths"),
                    vec!["patch.mbox"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::LoadConfig,
                        EffectKind::WritePath
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_restore_explicit_pathspecs() {
        let registry = built_in_registry();
        let artifact = parse_command("git restore -- src/main.rs Cargo.toml", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "restore_dashdash_pathspecs"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["restore".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["src/main.rs", "Cargo.toml"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::RepositoryOperation]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_restore_plain_and_source_pathspecs() {
        let registry = built_in_registry();

        let artifact = parse_command("git restore src/main.rs Cargo.toml", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "restore_explicit_pathspecs"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["src/main.rs", "Cargo.toml"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::RepositoryOperation]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command("git restore --source HEAD -- src/main.rs", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "restore_dashdash_pathspecs"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["src/main.rs"]
                );
                assert_eq!(argument_texts(&resolved.bound, "treeish"), vec!["HEAD"]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::RepositoryOperation]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_restore_worktree_subtree() {
        let registry = built_in_registry();
        let artifact = parse_command("git restore --source=HEAD~1 --worktree .", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "restore_worktree_subtree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["restore".to_string()]);
                assert_eq!(argument_texts(&resolved.bound, "subtree"), vec!["."]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::RepositoryOperation]
                );
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree {
                            path_set,
                            subtree: Some(slot),
                            ..
                        }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
                        && slot.as_str() == "subtree"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_checkout_explicit_pathspecs() {
        let registry = built_in_registry();
        let artifact = parse_command("git checkout -- src/main.rs", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "checkout_explicit_pathspecs"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["checkout".to_string()]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["src/main.rs"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::RepositoryOperation]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_checkout_treeish_pathspecs() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "git checkout HEAD~1 -- src/main.rs Cargo.toml",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "checkout_treeish_pathspecs"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["checkout".to_string()]);
                assert_eq!(first_argument_text(&resolved.bound, "treeish"), "HEAD~1");
                assert_eq!(
                    argument_texts(&resolved.bound, "pathspecs"),
                    vec!["src/main.rs", "Cargo.toml"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::RepositoryOperation]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_checkout_branch_worktree() {
        let registry = built_in_registry();
        let artifact =
            parse_command("git checkout main", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "checkout_branch_worktree"
                );
                assert_eq!(resolved.bound.subcommand_path, vec!["checkout".to_string()]);
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
                assert!(matches!(
                    &resolved.bound.effects[0].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set == caushell_types::RepositoryWorktreePathSet::Tracked
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_git_submodule_update_recursive_scope() {
        let registry = built_in_registry();
        let artifact = parse_command("git submodule update --init --recursive", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "git");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "update_registered_submodules"
                );
                assert_eq!(
                    resolved.bound.subcommand_path,
                    vec!["submodule".to_string(), "update".to_string()]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::LoadConfig,
                        EffectKind::LoadConfig,
                        EffectKind::WritePath
                    ]
                );
                assert!(matches!(
                    &resolved.bound.effects[2].target,
                    crate::EffectTarget::MutationScope(
                        crate::MutationScopeTarget::RepositoryWorktree { path_set, .. }
                    ) if *path_set
                        == caushell_types::RepositoryWorktreePathSet::RegisteredSubmoduleWorktrees
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_touch_create_or_update_paths() {
        let registry = built_in_registry();
        let artifact = parse_command("touch file-a file-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "touch");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "create_or_update_paths"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["file-a", "file-b"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_touch_reference_and_timestamp_operands() {
        let registry = built_in_registry();
        let artifact = parse_command("touch -r ref.txt target.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "touch");
                assert_eq!(
                    first_argument_text(&resolved.bound, "reference_file"),
                    "ref.txt"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["target.txt"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let artifact = parse_command("touch -d '2020-01-01' target.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    first_argument_text(&resolved.bound, "timestamp"),
                    "2020-01-01"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["target.txt"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cat_with_optional_paths() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cat file-a file-b", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cat");
                assert_eq!(resolved.selection.form.id.as_str(), "concatenate");
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["file-a", "file-b"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_gzip_default_file_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("gzip foo.txt bar.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "gzip");
                assert_eq!(resolved.selection.form.id.as_str(), "default_file_mode");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["foo.txt", "bar.txt"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert!(matches!(
                    resolved.bound.effects[1].target,
                    crate::EffectTarget::DerivedPath(crate::DerivedPathTarget {
                        source: crate::DerivedPathSource::Slot(ref slot),
                        root: None,
                        rule: caushell_types::DerivedPathRule::AppendSuffix { ref suffix },
                        purpose: Some(crate::PathPurpose::GenericOperand),
                    }) if slot.as_str() == "input_paths" && suffix == ".gz"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_gunzip_default_file_mode() {
        let registry = built_in_registry();
        let artifact =
            parse_command("gunzip foo.txt.gz", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "gunzip");
                assert_eq!(resolved.selection.form.id.as_str(), "default_file_mode");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["foo.txt.gz"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
                assert!(matches!(
                    resolved.bound.effects[1].target,
                    crate::EffectTarget::DerivedPath(crate::DerivedPathTarget {
                        source: crate::DerivedPathSource::Slot(ref slot),
                        root: None,
                        rule: caushell_types::DerivedPathRule::StripSuffix { ref suffix },
                        purpose: Some(crate::PathPurpose::GenericOperand),
                    }) if slot.as_str() == "input_paths" && suffix == ".gz"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_tar_extract_archive() {
        let registry = built_in_registry();
        let artifact = parse_command("tar -x -f archive.tar -C ./out member.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "tar");
                assert_eq!(resolved.selection.form.id.as_str(), "extract_archive");
                assert_eq!(
                    first_argument_text(&resolved.bound, "archive_file"),
                    "archive.tar"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "member_filters"),
                    vec!["member.sh"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "working_directory"),
                    "./out"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::WritePath,
                        EffectKind::TargetPath
                    ]
                );
                assert!(matches!(
                    resolved.bound.effects[1].target,
                    crate::EffectTarget::DerivedPath(crate::DerivedPathTarget {
                        source: crate::DerivedPathSource::Slot(ref slot),
                        root: None,
                        rule: caushell_types::DerivedPathRule::ArchiveMembers,
                        purpose: Some(crate::PathPurpose::GenericOperand),
                    }) if slot.as_str() == "archive_file"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_tar_create_archive() {
        let registry = built_in_registry();
        let artifact = parse_command("tar -c -f out.tar ./src ./README.md", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "tar");
                assert_eq!(resolved.selection.form.id.as_str(), "create_archive");
                assert_eq!(
                    first_argument_text(&resolved.bound, "archive_file"),
                    "out.tar"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["./src", "./README.md"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::WritePath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_unzip_extract_archive() {
        let registry = built_in_registry();
        let artifact = parse_command("unzip archive.zip member.sh -d ./out", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "unzip");
                assert_eq!(resolved.selection.form.id.as_str(), "extract_archive");
                assert_eq!(
                    first_argument_text(&resolved.bound, "archive_file"),
                    "archive.zip"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "member_filters"),
                    vec!["member.sh"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_directory"),
                    "./out"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::WritePath,
                        EffectKind::WritePath
                    ]
                );
                assert!(matches!(
                    resolved.bound.effects[1].target,
                    crate::EffectTarget::DerivedPath(crate::DerivedPathTarget {
                        source: crate::DerivedPathSource::Slot(ref slot),
                        root: None,
                        rule: caushell_types::DerivedPathRule::ArchiveMembers,
                        purpose: Some(crate::PathPurpose::GenericOperand),
                    }) if slot.as_str() == "archive_file"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_unzip_list_archive_without_write() {
        let registry = built_in_registry();
        let artifact =
            parse_command("unzip -l archive.zip", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "unzip");
                assert_eq!(resolved.selection.form.id.as_str(), "list_archive");
                assert_eq!(
                    first_argument_text(&resolved.bound, "archive_file"),
                    "archive.zip"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sed_script_file_and_inputs() {
        let registry = built_in_registry();
        let artifact = parse_command("sed -f rewrite.sed input-a input-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sed");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "explicit_script_transform"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_files"),
                    "rewrite.sed"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["input-a", "input-b"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sed_in_place_as_read_and_write() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"sed -i 's/a/b/' input.txt"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sed");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "positional_script_transform"
                );
                assert_eq!(first_argument_text(&resolved.bound, "script"), "s/a/b/");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["input.txt"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_awk_program_file_and_inputs() {
        let registry = built_in_registry();
        let artifact = parse_command("awk -f report.awk data.tsv", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "awk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "explicit_program_transform"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "program_files"),
                    "report.awk"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["data.tsv"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_awk_positional_program_and_stdin() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"awk '{print $1}' -"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "awk");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "positional_program_transform"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "program"),
                    "{print $1}"
                );
                assert!(
                    resolved
                        .bound
                        .bound_parameters
                        .iter()
                        .all(|parameter| parameter.name.as_str() != "input_paths")
                );
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wget_fetch_to_explicit_file() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "wget -O payload.sh https://example.test/payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "wget");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "fetch_to_explicit_file"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "endpoints"),
                    vec!["https://example.test/payload.sh"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wget_stdout_with_common_value_options() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "wget --timeout=1 --tries 1 --header 'Accept: text/plain' -O - https://example.test/payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "wget");
                assert_eq!(resolved.selection.form.id.as_str(), "fetch_to_stdout");
                assert_eq!(
                    argument_texts(&resolved.bound, "endpoints"),
                    vec!["https://example.test/payload.sh"]
                );
                assert_eq!(first_argument_text(&resolved.bound, "output_path"), "-");
                assert_eq!(
                    argument_texts(&resolved.bound, "option_value"),
                    vec!["1", "1", "Accept: text/plain"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wget_compact_stdout_option() {
        let registry = built_in_registry();
        let artifact = parse_command("wget -qO- https://example.test/payload.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "wget");
                assert_eq!(resolved.selection.form.id.as_str(), "fetch_to_stdout");
                assert_eq!(
                    argument_texts(&resolved.bound, "endpoints"),
                    vec!["https://example.test/payload.sh"]
                );
                assert_eq!(first_argument_text(&resolved.bound, "output_path"), "-");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wget_default_file_output() {
        let registry = built_in_registry();
        let artifact = parse_command("wget https://example.test/payload.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "wget");
                assert_eq!(resolved.selection.form.id.as_str(), "fetch_to_default_file");
                assert_eq!(
                    argument_texts(&resolved.bound, "endpoints"),
                    vec!["https://example.test/payload.sh"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint, EffectKind::WritePath]
                );
                assert!(matches!(
                    resolved.bound.effects[1].target,
                    crate::EffectTarget::DerivedPath(crate::DerivedPathTarget {
                        source: crate::DerivedPathSource::Slot(ref slot),
                        root: None,
                        rule: caushell_types::DerivedPathRule::UrlBasename,
                        purpose: Some(crate::PathPurpose::GenericOperand),
                    }) if slot.as_str() == "endpoints"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_wget_fetch_to_directory() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "wget -P ./downloads https://example.test/a https://example.test/b",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "wget");
                assert_eq!(resolved.selection.form.id.as_str(), "fetch_to_directory");
                assert_eq!(
                    argument_texts(&resolved.bound, "endpoints"),
                    vec!["https://example.test/a", "https://example.test/b"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_directory"),
                    "./downloads"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::NetworkEndpoint,
                        EffectKind::WritePath,
                        EffectKind::WritePath
                    ]
                );
                assert!(resolved.bound.effects.iter().any(|effect| matches!(
                    effect.target,
                    crate::EffectTarget::DerivedPath(crate::DerivedPathTarget {
                        source: crate::DerivedPathSource::Slot(ref source_slot),
                        root: Some(crate::DerivedPathSource::Slot(ref root_slot)),
                        rule: caushell_types::DerivedPathRule::UrlBasename,
                        purpose: Some(crate::PathPurpose::GenericOperand),
                    }) if source_slot.as_str() == "endpoints"
                        && root_slot.as_str() == "output_directory"
                )));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_curl_remote_name_output() {
        let registry = built_in_registry();
        let artifact = parse_command("curl -O https://example.test/payload.sh", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "curl");
                assert_eq!(resolved.selection.form.id.as_str(), "fetch_to_remote_name");
                assert_eq!(
                    first_argument_text(&resolved.bound, "endpoint"),
                    "https://example.test/payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint, EffectKind::WritePath]
                );
                assert!(matches!(
                    resolved.bound.effects[1].target,
                    crate::EffectTarget::DerivedPath(crate::DerivedPathTarget {
                        source: crate::DerivedPathSource::Slot(ref slot),
                        root: None,
                        rule: caushell_types::DerivedPathRule::UrlBasename,
                        purpose: Some(crate::PathPurpose::GenericOperand),
                    }) if slot.as_str() == "endpoint"
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_curl_common_value_options_before_url() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "curl -fsS --connect-timeout 1 --max-time=2 -H 'Accept: text/plain' -A agent https://example.test/payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "curl");
                assert_eq!(resolved.selection.form.id.as_str(), "fetch_to_stdout");
                assert_eq!(
                    first_argument_text(&resolved.bound, "endpoint"),
                    "https://example.test/payload.sh"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "option_value"),
                    vec!["1", "2", "Accept: text/plain", "agent"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_curl_explicit_url_option() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "curl --url=https://example.test/payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "curl");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "fetch_explicit_url_to_stdout"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "endpoint"),
                    "https://example.test/payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_ssh_remote_command() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"ssh build.example.test "echo ok""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "ssh");
                assert_eq!(resolved.selection.form.id.as_str(), "remote_command");
                assert_eq!(
                    first_argument_text(&resolved.bound, "remote_host"),
                    "build.example.test"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "remote_command"),
                    vec!["echo ok"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::NetworkEndpoint,
                        EffectKind::ExecuteRemoteCommand
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_scp_import_from_remote() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "scp build.example.test:/tmp/payload.sh ./payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "scp");
                assert_eq!(resolved.selection.form.id.as_str(), "import_from_remote");
                assert_eq!(
                    argument_texts(&resolved.bound, "remote_sources"),
                    vec!["build.example.test:/tmp/payload.sh"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "./payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_scp_export_to_remote() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "scp ./payload.sh build.example.test:/tmp/payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "scp");
                assert_eq!(resolved.selection.form.id.as_str(), "export_to_remote");
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["./payload.sh"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "remote_destination"),
                    "build.example.test:/tmp/payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::NetworkEndpoint]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rsync_import_from_remote() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "rsync -e ssh build.example.test:/tmp/payload.sh ./payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "rsync");
                assert_eq!(resolved.selection.form.id.as_str(), "import_from_remote");
                assert_eq!(
                    argument_texts(&resolved.bound, "remote_sources"),
                    vec!["build.example.test:/tmp/payload.sh"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "destination_path"),
                    "./payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::NetworkEndpoint, EffectKind::WritePath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_rsync_export_to_remote() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "rsync ./payload.sh build.example.test:/tmp/payload.sh",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "rsync");
                assert_eq!(resolved.selection.form.id.as_str(), "export_to_remote");
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["./payload.sh"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "remote_destination"),
                    "build.example.test:/tmp/payload.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::NetworkEndpoint]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_skips_cat_stdin_sentinel_from_path_bindings() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cat - file-a", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(
                    argument_texts(&resolved.bound, "source_paths"),
                    vec!["file-a"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_grep_positional_pattern_and_files() {
        let registry = built_in_registry();
        let artifact = parse_command("grep TODO src/lib.rs README.md", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "grep");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "positional_pattern_search"
                );
                assert_eq!(first_argument_text(&resolved.bound, "pattern"), "TODO");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["src/lib.rs", "README.md"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_grep_explicit_pattern_without_treating_pattern_as_path() {
        let registry = built_in_registry();
        let artifact = parse_command("grep -e TODO src/lib.rs", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "grep");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "explicit_pattern_search"
                );
                assert_eq!(modifier_ids, vec!["inline_pattern"]);
                assert_eq!(argument_texts(&resolved.bound, "patterns"), vec!["TODO"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["src/lib.rs"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_grep_pattern_file_and_input_files() {
        let registry = built_in_registry();
        let artifact = parse_command("grep --file patterns.txt src/lib.rs", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "grep");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "explicit_pattern_search"
                );
                assert_eq!(modifier_ids, vec!["pattern_file"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "pattern_files"),
                    vec!["patterns.txt"]
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["src/lib.rs"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::ReadPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_skips_grep_stdin_sentinels_from_path_bindings() {
        let registry = built_in_registry();
        let artifact = parse_command("grep -e TODO -f - - src/lib.rs", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(modifier_ids, vec!["inline_pattern", "pattern_file"]);
                assert_eq!(argument_texts(&resolved.bound, "patterns"), vec!["TODO"]);
                assert!(
                    resolved
                        .bound
                        .bound_parameters
                        .iter()
                        .all(|parameter| parameter.name.as_str() != "pattern_files")
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["src/lib.rs"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_grep_alias() {
        let registry = built_in_registry();
        let artifact = parse_command("egrep TODO README.md", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "egrep");
                assert_eq!(resolved.bound.command_name.as_str(), "grep");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "positional_pattern_search"
                );
                assert_eq!(first_argument_text(&resolved.bound, "pattern"), "TODO");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["README.md"]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_python_patch_version_alias() {
        let registry = built_in_registry();
        let artifact = parse_command("python3.12 -c 'print(1)'", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "python3.12");
                assert_eq!(resolved.bound.command_name.as_str(), "python");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "print(1)");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ExecutePayload]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_profile_coverage_batch_one() {
        let registry = built_in_registry();

        let echo = parse_command("echo -n hello world", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            echo.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "echo");
                assert_eq!(resolved.selection.form.id.as_str(), "emit_arguments");
                assert_eq!(
                    argument_texts(&resolved.bound, "arguments"),
                    vec!["hello", "world"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TransformData]
                );
            }
            other => panic!("unexpected echo resolve result: {other:?}"),
        }

        let ls = parse_command("ls -l src", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            ls.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "ls");
                assert_eq!(resolved.selection.form.id.as_str(), "list_paths");
                assert_eq!(argument_texts(&resolved.bound, "path_targets"), vec!["src"]);
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected ls resolve result: {other:?}"),
        }

        let nl = parse_command("nl --body-numbering a src/lib.rs", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            nl.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "nl");
                assert_eq!(resolved.selection.form.id.as_str(), "number_lines");
                assert_eq!(first_argument_text(&resolved.bound, "style"), "a");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["src/lib.rs"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::TransformData]
                );
            }
            other => panic!("unexpected nl resolve result: {other:?}"),
        }

        let tail = parse_command("tail -n 20 logs/app.log", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            tail.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "tail");
                assert_eq!(resolved.selection.form.id.as_str(), "read_inputs");
                assert_eq!(first_argument_text(&resolved.bound, "line_count"), "20");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["logs/app.log"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected tail resolve result: {other:?}"),
        }

        let pwd = parse_command("pwd -P", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            pwd.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "pwd");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "print_working_directory"
                );
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected pwd resolve result: {other:?}"),
        }

        let sort = parse_command("sort -o sorted.txt input.txt", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            sort.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sort");
                assert_eq!(resolved.selection.form.id.as_str(), "sort_to_file");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["input.txt"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "sorted.txt"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::TransformData));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected sort resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_profile_coverage_batch_two() {
        let registry = built_in_registry();

        let gcc =
            parse_command("gcc -o app main.c", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            gcc.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "gcc");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "compile_to_explicit_output"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["main.c"]
                );
                assert_eq!(first_argument_text(&resolved.bound, "output_path"), "app");
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected gcc resolve result: {other:?}"),
        }

        let code = parse_command("code .", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            code.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "code");
                assert_eq!(resolved.selection.form.id.as_str(), "open_workspace");
                assert_eq!(argument_texts(&resolved.bound, "path_targets"), vec!["."]);
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::TargetPath));
                assert!(effects.contains(&EffectKind::OpenInteractiveEscapeSurface));
            }
            other => panic!("unexpected code resolve result: {other:?}"),
        }

        let split = parse_command("split -b 1M big.bin chunks/part-", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            split.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "split");
                assert_eq!(resolved.selection.form.id.as_str(), "split_with_prefix");
                assert_eq!(first_argument_text(&resolved.bound, "chunk_spec"), "1M");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["big.bin"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_prefix"),
                    "chunks/part-"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected split resolve result: {other:?}"),
        }

        let zsh =
            parse_command("zsh -c 'echo ok'", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            zsh.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "zsh");
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "echo ok");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ExecutePayload]
                );
            }
            other => panic!("unexpected zsh resolve result: {other:?}"),
        }

        let yarn =
            parse_command("yarn run build", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            yarn.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "yarn");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "package_script_or_install"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "arguments"),
                    vec!["run", "build"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::LoadConfig, EffectKind::ExecuteConfigDefinedTask]
                );
            }
            other => panic!("unexpected yarn resolve result: {other:?}"),
        }

        let nc = parse_command("nc -e /bin/sh 127.0.0.1 4444", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            nc.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "nc");
                assert_eq!(resolved.selection.form.id.as_str(), "network_session");
                assert_eq!(
                    argument_texts(&resolved.bound, "remote_endpoint"),
                    vec!["127.0.0.1", "4444"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "/bin/sh"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::NetworkEndpoint));
                assert!(effects.contains(&EffectKind::DispatchCommand));
            }
            other => panic!("unexpected nc resolve result: {other:?}"),
        }

        let crontab =
            parse_command("crontab -l", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            crontab.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "crontab");
                assert_eq!(resolved.selection.form.id.as_str(), "list_crontab");
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::LoadConfig]);
            }
            other => panic!("unexpected crontab resolve result: {other:?}"),
        }

        let csplit = parse_command("csplit input.txt /END/", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            csplit.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "csplit");
                assert_eq!(resolved.selection.form.id.as_str(), "split_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_path"),
                    "input.txt"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "split_patterns"),
                    vec!["/END/"]
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected csplit resolve result: {other:?}"),
        }

        let ssh_keygen = parse_command("ssh-keygen -D /tmp/pkcs11.so", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            ssh_keygen.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "ssh-keygen");
                assert_eq!(resolved.selection.form.id.as_str(), "load_pkcs11_provider");
                assert_eq!(
                    first_argument_text(&resolved.bound, "provider_path"),
                    "/tmp/pkcs11.so"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::LoadInProcessCode));
                assert!(!effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected ssh-keygen resolve result: {other:?}"),
        }

        let mypy = parse_command("mypy --cache-dir .mypy_cache src", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            mypy.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mypy");
                assert_eq!(resolved.selection.form.id.as_str(), "type_check_project");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_targets"),
                    vec!["src"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "cache_dir"),
                    ".mypy_cache"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected mypy resolve result: {other:?}"),
        }

        let shuf = parse_command("shuf -o out.txt input.txt", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            shuf.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "shuf");
                assert_eq!(resolved.selection.form.id.as_str(), "shuffle_to_file");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["input.txt"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "out.txt"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::TransformData));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected shuf resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_profile_coverage_batch_three() {
        let registry = built_in_registry();

        let cut = parse_command("cut -d : -f 1 passwd", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            cut.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cut");
                assert_eq!(resolved.selection.form.id.as_str(), "select_fields");
                assert_eq!(first_argument_text(&resolved.bound, "delimiter_value"), ":");
                assert_eq!(first_argument_text(&resolved.bound, "selection_list"), "1");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["passwd"]
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::TransformData));
            }
            other => panic!("unexpected cut resolve result: {other:?}"),
        }

        let wc =
            parse_command("wc -l README.md", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            wc.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "wc");
                assert_eq!(resolved.selection.form.id.as_str(), "count_inputs");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["README.md"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::TransformData]
                );
            }
            other => panic!("unexpected wc resolve result: {other:?}"),
        }

        let printf =
            parse_command("printf '%s' hi", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            printf.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "printf");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "emit_formatted_arguments"
                );
                assert_eq!(first_argument_text(&resolved.bound, "format_string"), "%s");
                assert_eq!(argument_texts(&resolved.bound, "arguments"), vec!["hi"]);
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::TransformData]
                );
            }
            other => panic!("unexpected printf resolve result: {other:?}"),
        }

        let od =
            parse_command("od -t x1 file.bin", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            od.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "od");
                assert_eq!(resolved.selection.form.id.as_str(), "dump_inputs");
                assert_eq!(first_argument_text(&resolved.bound, "format_value"), "x1");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["file.bin"]
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::TransformData));
            }
            other => panic!("unexpected od resolve result: {other:?}"),
        }

        let diff = parse_command("diff -u a.txt b.txt", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            diff.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "diff");
                assert_eq!(resolved.selection.form.id.as_str(), "compare_paths");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["a.txt", "b.txt"]
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::TransformData));
            }
            other => panic!("unexpected diff resolve result: {other:?}"),
        }

        let which =
            parse_command("which python", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            which.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "which");
                assert_eq!(resolved.selection.form.id.as_str(), "locate_commands");
                assert_eq!(
                    first_argument_text(&resolved.bound, "command_names"),
                    "python"
                );
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected which resolve result: {other:?}"),
        }

        let sleep = parse_command("sleep 1", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            sleep.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "sleep");
                assert_eq!(resolved.selection.form.id.as_str(), "delay");
                assert_eq!(first_argument_text(&resolved.bound, "durations"), "1");
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected sleep resolve result: {other:?}"),
        }

        let true_command =
            parse_command("true", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            true_command.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "true");
                assert_eq!(resolved.selection.form.id.as_str(), "no_op_success");
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected true resolve result: {other:?}"),
        }

        let file =
            parse_command("file README.md", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            file.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "file");
                assert_eq!(resolved.selection.form.id.as_str(), "classify_files");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["README.md"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected file resolve result: {other:?}"),
        }

        let uniq = parse_command("uniq in.txt out.txt", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            uniq.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "uniq");
                assert_eq!(resolved.selection.form.id.as_str(), "unique_to_file");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["in.txt"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "out.txt"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::WritePath));
                assert!(effects.contains(&EffectKind::TransformData));
            }
            other => panic!("unexpected uniq resolve result: {other:?}"),
        }

        let mktemp = parse_command("mktemp -p tmp template.XXXX", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            mktemp.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "mktemp");
                assert_eq!(resolved.selection.form.id.as_str(), "create_temporary_path");
                assert_eq!(
                    argument_texts(&resolved.bound, "template_paths"),
                    vec!["template.XXXX"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "target_directory"),
                    "tmp"
                );
                assert!(effect_kinds(&resolved.bound).contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected mktemp resolve result: {other:?}"),
        }

        let tr = parse_command("tr a-z A-Z", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            tr.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "tr");
                assert_eq!(resolved.selection.form.id.as_str(), "translate_stream");
                assert_eq!(first_argument_text(&resolved.bound, "set1"), "a-z");
                assert_eq!(argument_texts(&resolved.bound, "set2"), vec!["A-Z"]);
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ConsumeStdin));
                assert!(effects.contains(&EffectKind::TransformData));
            }
            other => panic!("unexpected tr resolve result: {other:?}"),
        }

        let df = parse_command("df .", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            df.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "df");
                assert_eq!(resolved.selection.form.id.as_str(), "report_filesystems");
                assert_eq!(argument_texts(&resolved.bound, "path_targets"), vec!["."]);
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected df resolve result: {other:?}"),
        }

        let rmdir =
            parse_command("rmdir olddir", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            rmdir.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "rmdir");
                assert_eq!(
                    resolved.selection.form.id.as_str(),
                    "remove_empty_directories"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "path_targets"),
                    vec!["olddir"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::DeletePath]);
            }
            other => panic!("unexpected rmdir resolve result: {other:?}"),
        }

        let tree = parse_command("tree -o tree.txt src", ShellKind::Bash)
            .expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            tree.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "tree");
                assert_eq!(resolved.selection.form.id.as_str(), "tree_to_file");
                assert_eq!(argument_texts(&resolved.bound, "path_targets"), vec!["src"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_path"),
                    "tree.txt"
                );
                let effects = effect_kinds(&resolved.bound);
                assert!(effects.contains(&EffectKind::ReadPath));
                assert!(effects.contains(&EffectKind::WritePath));
            }
            other => panic!("unexpected tree resolve result: {other:?}"),
        }

        let whoami = parse_command("whoami", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            whoami.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "whoami");
                assert_eq!(resolved.selection.form.id.as_str(), "print_effective_user");
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected whoami resolve result: {other:?}"),
        }

        let ps = parse_command("ps -p 1234", ShellKind::Bash).expect("expected parse to succeed");
        let result = resolve_invocation(
            &registry,
            ps.commands.first().expect("expected one command"),
            InvocationRuntimeContext::new(),
        );
        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "ps");
                assert_eq!(resolved.selection.form.id.as_str(), "list_processes");
                assert_eq!(
                    first_argument_text(&resolved.bound, "process_targets"),
                    "1234"
                );
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected ps resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_profile_coverage_batch_four() {
        let registry = built_in_registry();

        let cases = [
            (
                "dvc repro",
                "dvc",
                "repository_operation",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::WritePath,
                    EffectKind::ExecuteConfigDefinedTask,
                ][..],
            ),
            (
                "hexdump data.bin",
                "hexdump",
                "dump_files",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "scrapy crawl quotes -o out.json",
                "scrapy",
                "project_command",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::NetworkEndpoint,
                    EffectKind::ExecuteImportedPackageLogic,
                    EffectKind::WritePath,
                ],
            ),
            (
                "flake8 --output-file lint.txt src",
                "flake8",
                "lint_targets",
                &[
                    EffectKind::ReadPath,
                    EffectKind::LoadConfig,
                    EffectKind::ExecuteImportedPackageLogic,
                    EffectKind::WritePath,
                ],
            ),
            (
                "yamllint -c .yamllint.yml config.yml",
                "yamllint",
                "lint_yaml",
                &[
                    EffectKind::ReadPath,
                    EffectKind::LoadConfig,
                    EffectKind::TransformData,
                ],
            ),
            (
                "gtts-cli -o voice.mp3 hello",
                "gtts-cli",
                "synthesize_speech",
                &[
                    EffectKind::NetworkEndpoint,
                    EffectKind::TransformData,
                    EffectKind::WritePath,
                ],
            ),
            (
                "cmake -S . -B build",
                "cmake",
                "configure_or_build_project",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::ReadPath,
                    EffectKind::WritePath,
                    EffectKind::ExecuteConfigDefinedTask,
                ],
            ),
            (
                "tldextract example.co.uk",
                "tldextract",
                "extract_domains",
                &[
                    EffectKind::NetworkEndpoint,
                    EffectKind::WritePath,
                    EffectKind::TransformData,
                ],
            ),
            (
                "pygmentize -o out.html app.py",
                "pygmentize",
                "highlight_to_file",
                &[
                    EffectKind::ReadPath,
                    EffectKind::TransformData,
                    EffectKind::WritePath,
                ],
            ),
            (
                "mkdocs build --site-dir public",
                "mkdocs",
                "build_site",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::ReadPath,
                    EffectKind::WritePath,
                    EffectKind::ExecuteImportedPackageLogic,
                ],
            ),
            (
                "qr --output code.png hello",
                "qr",
                "encode_qr",
                &[EffectKind::TransformData, EffectKind::WritePath],
            ),
            (
                "pipdeptree --packages requests",
                "pipdeptree",
                "inspect_environment",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "glom data.json a.b",
                "glom",
                "transform_data_file",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "pkg-config --libs openssl",
                "pkg-config",
                "query_packages",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "deep --output report.json input.json",
                "deep",
                "analyze_inputs",
                &[
                    EffectKind::ReadPath,
                    EffectKind::TransformData,
                    EffectKind::WritePath,
                ],
            ),
            (
                "sqlfluff fix query.sql",
                "sqlfluff",
                "fix_sql",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::WritePath,
                    EffectKind::ExecuteImportedPackageLogic,
                ],
            ),
            (
                "nikola build",
                "nikola",
                "site_command",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::ReadPath,
                    EffectKind::WritePath,
                    EffectKind::ExecuteConfigDefinedTask,
                    EffectKind::ExecuteImportedPackageLogic,
                ],
            ),
            (
                "pyright -p pyrightconfig.json src",
                "pyright",
                "type_check_project",
                &[EffectKind::ReadPath, EffectKind::LoadConfig],
            ),
            (
                "safety check -r requirements.txt",
                "safety",
                "scan_dependencies",
                &[
                    EffectKind::ReadPath,
                    EffectKind::NetworkEndpoint,
                    EffectKind::TransformData,
                ],
            ),
            (
                "meson setup builddir",
                "meson",
                "project_operation",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::WritePath,
                    EffectKind::ExecuteConfigDefinedTask,
                ],
            ),
            (
                "dotenv run -- python app.py",
                "dotenv",
                "run_default_env_file",
                &[EffectKind::LoadConfig, EffectKind::DispatchCommand],
            ),
            (
                "dpkg-query -W bash",
                "dpkg-query",
                "query_package_database",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "pyreverse -d diagrams src/pkg",
                "pyreverse",
                "generate_diagrams",
                &[
                    EffectKind::ReadPath,
                    EffectKind::WritePath,
                    EffectKind::ExecuteImportedPackageLogic,
                ],
            ),
            (
                "rg TODO src",
                "rg",
                "search_paths",
                &[
                    EffectKind::ReadPath,
                    EffectKind::LoadConfig,
                    EffectKind::TransformData,
                ],
            ),
        ];

        for (command_line, expected_command_name, expected_form_id, expected_effects) in cases {
            assert_resolves_command_with_effects(
                &registry,
                command_line,
                expected_command_name,
                expected_form_id,
                expected_effects,
            );
        }
    }

    #[test]
    fn resolve_invocation_resolves_profile_coverage_batch_five() {
        let registry = built_in_registry();

        let cases = [
            (
                "dirname src/main.rs",
                "dirname",
                "extract_directory",
                &[EffectKind::TransformData][..],
            ),
            (
                "readlink -f ./link",
                "readlink",
                "resolve_links",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "basename src/main.rs",
                "basename",
                "extract_basename",
                &[EffectKind::TransformData],
            ),
            (
                "date -f dates.txt",
                "date",
                "print_or_parse_date",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "du -sh src",
                "du",
                "summarize_usage",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "md5sum file.bin",
                "md5sum",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "mount /dev/sda1 /mnt",
                "mount",
                "mount_filesystem",
                &[
                    EffectKind::TargetPath,
                    EffectKind::WritePath,
                    EffectKind::MetadataMutation,
                ],
            ),
            (
                "comm a.txt b.txt",
                "comm",
                "compare_sorted_files",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "set -e",
                "set",
                "mutate_shell_options",
                &[EffectKind::MetadataMutation],
            ),
            (
                "rename foo bar file.txt",
                "rename",
                "rename_paths",
                &[EffectKind::MovePath],
            ),
            (
                "ifconfig eth0 up",
                "ifconfig",
                "configure_interface",
                &[EffectKind::MetadataMutation],
            ),
            (
                "rev notes.txt",
                "rev",
                "reverse_lines",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "history -w",
                "history",
                "read_or_write_history",
                &[EffectKind::LoadConfig, EffectKind::WritePath],
            ),
            (
                "yes ok",
                "yes",
                "repeat_output",
                &[EffectKind::TransformData],
            ),
            (
                "shopt -s extglob",
                "shopt",
                "mutate_shell_options",
                &[EffectKind::MetadataMutation],
            ),
            (
                "hostname buildbox",
                "hostname",
                "set_hostname",
                &[EffectKind::MetadataMutation],
            ),
            (
                "ping -c 1 example.com",
                "ping",
                "probe_host",
                &[EffectKind::NetworkEndpoint, EffectKind::TransformData],
            ),
            (
                "column -t table.txt",
                "column",
                "format_columns",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "dig example.com",
                "dig",
                "dns_query",
                &[EffectKind::NetworkEndpoint, EffectKind::TransformData],
            ),
            (
                "paste a.txt b.txt",
                "paste",
                "merge_lines",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "tac log.txt",
                "tac",
                "reverse_files",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "seq 1 10",
                "seq",
                "generate_sequence",
                &[EffectKind::TransformData],
            ),
            (
                "join a.txt b.txt",
                "join",
                "join_files",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "fold -w 80 text.txt",
                "fold",
                "fold_lines",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "cpio -F archive.cpio -i",
                "cpio",
                "extract_archive",
                &[EffectKind::ReadPath],
            ),
            ("cal", "cal", "print_calendar", &[EffectKind::TransformData]),
            (
                "who",
                "who",
                "list_sessions",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "uname -a",
                "uname",
                "print_system_name",
                &[EffectKind::TransformData],
            ),
            (
                "bzip2 data.txt",
                "bzip2",
                "compress_files",
                &[EffectKind::ReadPath, EffectKind::WritePath],
            ),
            (
                "pstree 1",
                "pstree",
                "show_process_tree",
                &[EffectKind::TransformData],
            ),
            ("jobs -l", "jobs", "list_jobs", &[EffectKind::TransformData]),
            (
                "finger user@example.com",
                "finger",
                "query_user_info",
                &[EffectKind::NetworkEndpoint, EffectKind::TransformData],
            ),
            (
                "bind -f inputrc",
                "bind",
                "mutate_readline_bindings",
                &[EffectKind::LoadConfig, EffectKind::MetadataMutation],
            ),
            (
                "watch -n 1 ls -l",
                "watch",
                "repeat_command",
                &[
                    EffectKind::DispatchCommand,
                    EffectKind::OpenInteractiveEscapeSurface,
                ],
            ),
            (
                "w",
                "w",
                "list_logged_in_users",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "groups user",
                "groups",
                "print_groups",
                &[EffectKind::TransformData],
            ),
            (
                "man ls",
                "man",
                "show_manual_page",
                &[
                    EffectKind::ReadPath,
                    EffectKind::OpenInteractiveEscapeSurface,
                ],
            ),
            (
                "compress file.txt",
                "compress",
                "compress_files",
                &[EffectKind::ReadPath, EffectKind::WritePath],
            ),
            ("false", "false", "no_op_failure", &[]),
            (
                "pushd src",
                "pushd",
                "change_directory_stack",
                &[
                    EffectKind::TargetPath,
                    EffectKind::SetCurrentWorkingDirectory,
                ],
            ),
        ];

        for (command_line, expected_command_name, expected_form_id, expected_effects) in cases {
            assert_resolves_command_with_effects(
                &registry,
                command_line,
                expected_command_name,
                expected_form_id,
                expected_effects,
            );
        }
    }

    #[test]
    fn resolve_invocation_resolves_profile_coverage_batch_six() {
        let registry = built_in_registry();

        let cases = [
            (
                "base32 -d data.b32",
                "base32",
                "decode_stream",
                &[EffectKind::ReadPath, EffectKind::TransformData][..],
            ),
            (
                "cmp old.bin new.bin",
                "cmp",
                "compare_files",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "expand tabs.txt",
                "expand",
                "expand_tabs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "fmt notes.txt",
                "fmt",
                "format_paragraphs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "pr report.txt",
                "pr",
                "paginate_files",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "ptx index.txt",
                "ptx",
                "permuted_index",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "unexpand spaces.txt",
                "unexpand",
                "unexpand_spaces",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            ("test -f Cargo.toml", "test", "evaluate_expression", &[]),
            (
                "nano README.md",
                "nano",
                "interactive_editor",
                &[
                    EffectKind::TargetPath,
                    EffectKind::OpenInteractiveEscapeSurface,
                ],
            ),
            (
                "chcp 65001",
                "chcp",
                "set_code_page",
                &[EffectKind::MetadataMutation],
            ),
            (
                "prisma migrate dev --schema prisma/schema.prisma",
                "prisma",
                "project_database_command",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::NetworkEndpoint,
                    EffectKind::WritePath,
                    EffectKind::ExecuteConfigDefinedTask,
                ],
            ),
            (
                "drizzle-kit generate --config drizzle.config.ts",
                "drizzle-kit",
                "project_database_command",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::LoadInProcessCode,
                    EffectKind::NetworkEndpoint,
                    EffectKind::WritePath,
                ],
            ),
            (
                "docker run alpine echo hi",
                "docker",
                "daemon_control",
                &[
                    EffectKind::NetworkEndpoint,
                    EffectKind::ExecuteImportedPackageLogic,
                    EffectKind::MetadataMutation,
                ],
            ),
            (
                "gh repo view",
                "gh",
                "github_control",
                &[
                    EffectKind::NetworkEndpoint,
                    EffectKind::LoadConfig,
                    EffectKind::WritePath,
                ],
            ),
            (
                "ghcs list files",
                "ghcs",
                "copilot_shell_suggest",
                &[EffectKind::NetworkEndpoint, EffectKind::TransformData],
            ),
            (
                "aider-chat src/main.rs",
                "aider-chat",
                "coding_agent_session",
                &[
                    EffectKind::NetworkEndpoint,
                    EffectKind::ReadPath,
                    EffectKind::WritePath,
                    EffectKind::OpenInteractiveEscapeSurface,
                ],
            ),
        ];

        for (command_line, expected_command_name, expected_form_id, expected_effects) in cases {
            assert_resolves_command_with_effects(
                &registry,
                command_line,
                expected_command_name,
                expected_form_id,
                expected_effects,
            );
        }

        assert_eq!(
            registry
                .lookup("[")
                .profile
                .map(crate::CommandProfile::primary_name),
            Some("test")
        );
    }

    #[test]
    fn resolve_invocation_resolves_profile_coverage_batch_seven() {
        let registry = built_in_registry();

        let cases = [
            (
                "su -c 'id' root",
                "su",
                "switch_user_shell",
                &[
                    EffectKind::PrivilegeModifier,
                    EffectKind::ExecutePayload,
                    EffectKind::OpenInteractiveEscapeSurface,
                ][..],
            ),
            (
                "md5 file.bin",
                "md5",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "apropos printf",
                "apropos",
                "search_manual_database",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "info coreutils",
                "info",
                "show_info_page",
                &[
                    EffectKind::ReadPath,
                    EffectKind::OpenInteractiveEscapeSurface,
                ],
            ),
            (
                "tmux -f tmux.conf new-session",
                "tmux",
                "terminal_multiplexer_control",
                &[
                    EffectKind::LoadConfig,
                    EffectKind::OpenInteractiveEscapeSurface,
                ],
            ),
            (
                "zless log.gz",
                "zless",
                "page_compressed_files",
                &[
                    EffectKind::ReadPath,
                    EffectKind::OpenInteractiveEscapeSurface,
                ],
            ),
            (
                "clear",
                "clear",
                "clear_terminal",
                &[EffectKind::TransformData],
            ),
            (
                "bunzip2 data.txt.bz2",
                "bunzip2",
                "decompress_files",
                &[EffectKind::ReadPath, EffectKind::WritePath],
            ),
            ("vdir src", "vdir", "list_paths", &[EffectKind::ReadPath]),
            (
                "users",
                "users",
                "list_users",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "unlink old.sock",
                "unlink",
                "unlink_path",
                &[EffectKind::DeletePath],
            ),
            (
                "tty",
                "tty",
                "print_terminal_name",
                &[EffectKind::TransformData],
            ),
            (
                "tsort deps.txt",
                "tsort",
                "topological_sort",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "sync data.bin",
                "sync",
                "flush_filesystem_buffers",
                &[EffectKind::TargetPath, EffectKind::MetadataMutation],
            ),
            (
                "sum data.bin",
                "sum",
                "checksum_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "stty -a",
                "stty",
                "display_terminal_settings",
                &[EffectKind::TransformData],
            ),
            (
                "stat Cargo.toml",
                "stat",
                "inspect_paths",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "sha512sum file.bin",
                "sha512sum",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "sha384sum file.bin",
                "sha384sum",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "sha256sum file.bin",
                "sha256sum",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "sha224sum file.bin",
                "sha224sum",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "sha1sum file.bin",
                "sha1sum",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "runcon -t user_t id root",
                "runcon",
                "run_with_context_flags",
                &[EffectKind::PrivilegeModifier, EffectKind::DispatchCommand],
            ),
            (
                "realpath src",
                "realpath",
                "resolve_paths",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "printenv PATH",
                "printenv",
                "print_environment",
                &[EffectKind::TransformData],
            ),
            (
                "popd +1",
                "popd",
                "change_directory_stack",
                &[
                    EffectKind::SetCurrentWorkingDirectory,
                    EffectKind::MetadataMutation,
                ],
            ),
            (
                "pinky user",
                "pinky",
                "print_user_info",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "pathchk src/main.rs",
                "pathchk",
                "check_path_names",
                &[EffectKind::TransformData],
            ),
            (
                "numfmt --to iec 1024",
                "numfmt",
                "format_numbers",
                &[EffectKind::TransformData],
            ),
            (
                "nproc",
                "nproc",
                "print_processor_count",
                &[EffectKind::TransformData],
            ),
            (
                "mknod fifo p",
                "mknod",
                "create_special_file",
                &[EffectKind::WritePath, EffectKind::MetadataMutation],
            ),
            (
                "mkfifo pipe",
                "mkfifo",
                "create_fifo",
                &[EffectKind::WritePath],
            ),
            (
                "logname",
                "logname",
                "print_login_name",
                &[EffectKind::TransformData],
            ),
            (
                "link source dest",
                "link",
                "create_hard_link",
                &[EffectKind::TargetPath, EffectKind::WritePath],
            ),
            (
                "id user",
                "id",
                "print_identity",
                &[EffectKind::TransformData],
            ),
            (
                "hostid",
                "hostid",
                "print_host_id",
                &[EffectKind::TransformData],
            ),
            (
                "factor 12",
                "factor",
                "factor_numbers",
                &[EffectKind::TransformData],
            ),
            (
                "expr 1 + 1",
                "expr",
                "evaluate_expression",
                &[EffectKind::TransformData],
            ),
            (
                "dircolors colors.conf",
                "dircolors",
                "generate_ls_colors",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            ("dir src", "dir", "list_paths", &[EffectKind::ReadPath]),
            (
                "cksum file.bin",
                "cksum",
                "checksum_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "chcon user_u:object_r:file_t:s0 file",
                "chcon",
                "change_security_context",
                &[EffectKind::MetadataMutation],
            ),
            (
                "b2sum file.bin",
                "b2sum",
                "hash_inputs",
                &[EffectKind::ReadPath, EffectKind::TransformData],
            ),
            (
                "arch",
                "arch",
                "print_architecture",
                &[EffectKind::TransformData],
            ),
        ];

        for (command_line, expected_command_name, expected_form_id, expected_effects) in cases {
            assert_resolves_command_with_effects(
                &registry,
                command_line,
                expected_command_name,
                expected_form_id,
                expected_effects,
            );
        }

        let artifact = parse_command("md5sum.textutils file.bin", ShellKind::Bash)
            .expect("expected parse to succeed");
        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "md5sum.textutils");
                assert_eq!(resolved.bound.command_name.as_str(), "md5sum");
                assert_eq!(resolved.selection.form.id.as_str(), "hash_inputs");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["file.bin"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::TransformData]
                );
            }
            other => panic!("unexpected md5sum.textutils resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_tee_with_optional_output_paths() {
        let registry = built_in_registry();
        let artifact =
            parse_command("tee out-a out-b", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "tee");
                assert_eq!(resolved.selection.form.id.as_str(), "duplicate_stream");
                assert_eq!(
                    argument_texts(&resolved.bound, "output_paths"),
                    vec!["out-a", "out-b"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_tee_output_error_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("tee --output-error=warn out-a", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "tee");
                assert_eq!(resolved.selection.form.id.as_str(), "duplicate_stream");
                assert_eq!(modifier_ids, vec!["output_error"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "output_error_mode"),
                    "warn"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "output_paths"),
                    vec!["out-a"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_tee_output_error_literal_path_not_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("tee --output-error warn out-a", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "tee");
                assert_eq!(resolved.selection.form.id.as_str(), "duplicate_stream");
                assert_eq!(modifier_ids, vec!["output_error"]);
                assert!(find_bound_parameter_opt(&resolved.bound, "output_error_mode").is_none());
                assert_eq!(
                    argument_texts(&resolved.bound, "output_paths"),
                    vec!["warn", "out-a"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::WritePath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_tee_help_without_write_effects() {
        let registry = built_in_registry();
        let artifact =
            parse_command("tee --help", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "tee");
                assert_eq!(resolved.selection.form.id.as_str(), "show_help");
                assert_eq!(modifier_ids, vec!["help"]);
                assert!(resolved.bound.bound_parameters.is_empty());
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_head_with_optional_input_paths() {
        let registry = built_in_registry();
        let artifact = parse_command("head file-a file-b", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "head");
                assert_eq!(resolved.selection.form.id.as_str(), "read_inputs");
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["file-a", "file-b"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_skips_head_stdin_sentinel_from_path_bindings() {
        let registry = built_in_registry();
        let artifact =
            parse_command("head - file-a", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "head");
                assert_eq!(resolved.selection.form.id.as_str(), "read_inputs");
                assert_eq!(modifier_ids, Vec::<&str>::new());
                assert_eq!(
                    argument_texts(&resolved.bound, "input_paths"),
                    vec!["file-a"]
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_env_dispatch_with_env_overlay() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "env -i FOO=bar BAR=baz python -m http.server",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "env");
                assert_eq!(resolved.selection.form.id.as_str(), "dispatch_with_env");
                assert_eq!(modifier_ids, vec!["ignore_environment"]);
                assert_eq!(
                    argument_texts(&resolved.bound, "scoped_env"),
                    vec!["FOO=bar", "BAR=baz"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "python"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-m", "http.server"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DispatchCommand]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_python_module_load_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("python -m http.server", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "python");
                assert_eq!(resolved.selection.form.id.as_str(), "module");
                assert_eq!(
                    first_argument_text(&resolved.bound, "module_name"),
                    "http.server"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::LoadInProcessCode]
                );
                assert!(matches!(
                    find_bound_parameter_opt(&resolved.bound, "module_name")
                        .expect("expected module_name")
                        .semantic,
                    SemanticType::InProcessCodeLoad(ref semantic)
                        if semantic.load_kind == InProcessCodeLoadKind::ModuleName
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_node_preload_surface_alongside_script_file() {
        let registry = built_in_registry();
        let artifact =
            parse_command("node -r ./hook.js app.js", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "node");
                assert_eq!(resolved.selection.form.id.as_str(), "script_file");
                assert_eq!(modifier_ids, vec!["preload"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "preload_targets"),
                    "./hook.js"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "app.js"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::ExecutePayload,
                        EffectKind::LoadInProcessCode
                    ]
                );
                assert!(matches!(
                    find_bound_parameter_opt(&resolved.bound, "preload_targets")
                        .expect("expected preload_targets")
                        .semantic,
                    SemanticType::InProcessCodeLoad(ref semantic)
                        if semantic.load_kind == InProcessCodeLoadKind::Unknown
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_perl_attached_module_import_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("perl -Mstrict script.pl", ShellKind::Bash).expect("expected parse");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "perl");
                assert_eq!(resolved.selection.form.id.as_str(), "script_file");
                assert_eq!(modifier_ids, vec!["module_import"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "module_specs"),
                    "strict"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "script.pl"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::ExecutePayload,
                        EffectKind::LoadInProcessCode
                    ]
                );
                assert!(matches!(
                    find_bound_parameter_opt(&resolved.bound, "module_specs")
                        .expect("expected module_specs")
                        .semantic,
                    SemanticType::InProcessCodeLoad(ref semantic)
                        if semantic.load_kind == InProcessCodeLoadKind::ModuleName
                ));
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_env_print_environment_without_dispatch() {
        let registry = built_in_registry();
        let artifact = parse_command("env FOO=bar BAR=baz", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "env");
                assert_eq!(resolved.selection.form.id.as_str(), "print_environment");
                assert_eq!(
                    argument_texts(&resolved.bound, "scoped_env"),
                    vec!["FOO=bar", "BAR=baz"]
                );
                assert!(resolved.bound.effects.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_env_dispatch_with_inline_chdir_operand() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "env --chdir=/tmp FOO=bar python -m http.server",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "env");
                assert_eq!(resolved.selection.form.id.as_str(), "dispatch_with_env");
                assert_eq!(modifier_ids, vec!["chdir"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "working_directory"),
                    "/tmp"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "scoped_env"),
                    vec!["FOO=bar"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "python"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-m", "http.server"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DispatchCommand, EffectKind::TargetPath]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sudo_wrapper_command_with_env_overlay() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "sudo -u root BUILD_MODE=debug rm -rf /tmp/project",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sudo");
                assert_eq!(resolved.selection.form.id.as_str(), "wrapped_command");
                assert_eq!(modifier_ids, vec!["user"]);
                assert_eq!(first_argument_text(&resolved.bound, "run_as_user"), "root");
                assert_eq!(
                    argument_texts(&resolved.bound, "scoped_env"),
                    vec!["BUILD_MODE=debug"]
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "rm"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-rf", "/tmp/project"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::PrivilegeModifier, EffectKind::DispatchCommand]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_sudo_wrapper_command_with_inline_user_operand() {
        let registry = built_in_registry();
        let artifact = parse_command("sudo --user=root rm -rf /tmp/project", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "sudo");
                assert_eq!(resolved.selection.form.id.as_str(), "wrapped_command");
                assert_eq!(modifier_ids, vec!["user"]);
                assert_eq!(first_argument_text(&resolved.bound, "run_as_user"), "root");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "rm"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-rf", "/tmp/project"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::PrivilegeModifier, EffectKind::DispatchCommand]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_timeout_wrapper_command_with_duration_and_signal() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "timeout --signal=KILL --kill-after=10s 5 bash -c 'echo ok'",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "timeout");
                assert_eq!(resolved.selection.form.id.as_str(), "wrapped_command");
                assert_eq!(modifier_ids, vec!["signal", "kill_after"]);
                assert_eq!(first_argument_text(&resolved.bound, "signal_name"), "KILL");
                assert_eq!(
                    first_argument_text(&resolved.bound, "kill_after_duration"),
                    "10s"
                );
                assert_eq!(first_argument_text(&resolved.bound, "duration"), "5");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "bash"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-c", "echo ok"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DispatchCommand]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_nice_wrapper_command_with_inline_adjustment() {
        let registry = built_in_registry();
        let artifact = parse_command("nice --adjustment=5 python -m http.server", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "nice");
                assert_eq!(resolved.selection.form.id.as_str(), "wrapped_command");
                assert_eq!(modifier_ids, vec!["adjustment"]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "adjustment_value"),
                    "5"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "python"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-m", "http.server"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DispatchCommand]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_nohup_wrapper_command() {
        let registry = built_in_registry();
        let artifact = parse_command("nohup bash -c 'echo ok'", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "nohup");
                assert_eq!(resolved.selection.form.id.as_str(), "wrapped_command");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "bash"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-c", "echo ok"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DispatchCommand]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_stdbuf_wrapper_command_with_short_attached_operands() {
        let registry = built_in_registry();
        let artifact = parse_command("stdbuf -oL -e0 bash -c 'echo ok'", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                let modifier_ids: Vec<&str> = resolved
                    .bound
                    .applied_modifiers
                    .iter()
                    .map(|modifier| modifier.as_str())
                    .collect();

                assert_eq!(resolved.normalized_command_name, "stdbuf");
                assert_eq!(resolved.selection.form.id.as_str(), "wrapped_command");
                assert_eq!(modifier_ids, vec!["output", "error"]);
                assert_eq!(first_argument_text(&resolved.bound, "output_mode"), "L");
                assert_eq!(first_argument_text(&resolved.bound, "error_mode"), "0");
                assert_eq!(
                    first_argument_text(&resolved.bound, "wrapped_command"),
                    "bash"
                );
                assert_eq!(
                    argument_texts(&resolved.bound, "wrapped_args"),
                    vec!["-c", "echo ok"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::DispatchCommand]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_returns_no_profile_for_unknown_command() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"custom-tool --help"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::NoProfile {
                normalized_command_name,
                gap_kind,
            } => {
                assert_eq!(normalized_command_name, "custom-tool");
                assert_eq!(gap_kind, ResolveGapKind::NoProfile);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_returns_missing_command_name() {
        let registry = built_in_registry();
        let command = CommandFact {
            command_name: None,
            text: "$USER_CMD".to_string(),
            prefix_assignments: Vec::new(),
            tokens: Vec::new(),
            in_pipeline: false,
            pipeline_position: None,
            pipeline_span: None,
            terminator: None,
            guarded: false,
            subshell_span: None,
            control_flow_span: None,
            top_level_span: empty_span(),
            span: empty_span(),
        };

        let result = resolve_invocation(&registry, &command, InvocationRuntimeContext::new());

        assert_eq!(
            result,
            ResolveInvocationResult::MissingCommandName {
                gap_kind: ResolveGapKind::MissingCommandName
            }
        );
    }

    #[test]
    fn resolve_invocation_classifies_dynamic_command_target_as_risky_gap() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"$USER_CMD --help"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        assert_eq!(
            result,
            ResolveInvocationResult::MissingCommandName {
                gap_kind: ResolveGapKind::DynamicCommandTarget
            }
        );
    }

    #[test]
    fn resolve_invocation_surfaces_selection_error() {
        let registry = built_in_registry();
        let artifact = parse_command("bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(
            &registry,
            command,
            InvocationRuntimeContext::new()
                .with_stdin_payload_available()
                .with_interactive_session(),
        );

        match result {
            ResolveInvocationResult::SelectionError {
                normalized_command_name,
                gap_kind,
                error:
                    BindError::MultipleFormsMatched {
                        command_name,
                        form_ids,
                    },
                partial_bound,
            } => {
                assert_eq!(normalized_command_name, "bash");
                assert_eq!(gap_kind, ResolveGapKind::FormSelectionAmbiguous);
                assert_eq!(command_name, "bash");
                assert_eq!(
                    form_ids,
                    vec![
                        "stdin_script_implicit".to_string(),
                        "interactive".to_string(),
                    ],
                );
                assert!(partial_bound.is_none());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_keeps_modifier_only_binding_on_selection_error() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"bash --rcfile ~/team.rc"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::SelectionError {
                normalized_command_name,
                gap_kind,
                error: BindError::NoFormMatched { command_name },
                partial_bound: Some(bound),
            } => {
                assert_eq!(normalized_command_name, "bash");
                assert_eq!(gap_kind, ResolveGapKind::FormSelectionUnmatched);
                assert_eq!(command_name, "bash");
                assert_eq!(bound.command_name.as_str(), "bash");
                assert_eq!(bound.form_id.as_str(), "__modifier_only__");
                assert_eq!(bound.applied_modifiers.len(), 1);
                assert_eq!(bound.applied_modifiers[0].as_str(), "rcfile");
                assert_eq!(first_argument_text(&bound, "startup_config"), "~/team.rc");
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_emits_unbound_payload_when_c_operand_is_missing() {
        let registry = built_in_registry();
        let artifact =
            parse_command(r#"bash -c -s"#, ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert!(resolved.bound.effects.is_empty());
                assert_eq!(resolved.bound.residuals.len(), 1);
                assert_eq!(
                    resolved.bound.residuals[0].kind,
                    ResidualKind::UnboundPayload
                );
                assert_eq!(
                    resolved.bound.residuals[0]
                        .slot
                        .as_ref()
                        .map(|slot| slot.as_str()),
                    Some("payload")
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_treats_dashdash_as_command_string_barrier() {
        let registry = built_in_registry();
        let artifact =
            parse_command(r#"bash -c -- -s"#, ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "-s");
                assert_eq!(resolved.bound.effects.len(), 1);
                assert_eq!(resolved.bound.effects[0].kind, EffectKind::ExecutePayload);
                assert!(resolved.bound.residuals.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_treats_flag_like_modifier_operand_as_startup_config() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"bash --rcfile -c 'echo ok'"#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "echo ok"
                );
                assert_eq!(first_argument_text(&resolved.bound, "startup_config"), "-c");
                assert_eq!(resolved.bound.effects.len(), 3);
                assert_eq!(resolved.bound.effects[0].kind, EffectKind::ReadPath);
                assert_eq!(resolved.bound.effects[1].kind, EffectKind::ExecutePayload);
                assert_eq!(resolved.bound.effects[2].kind, EffectKind::LoadConfig);
                assert!(resolved.bound.residuals.is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_source_builtin_as_current_shell_script_sink() {
        let registry = built_in_registry();
        let artifact =
            parse_command("source ./env.sh", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "source");
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "./env.sh"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::SourceScriptIntoCurrentShell,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_dot_alias_to_source_profile() {
        let registry = built_in_registry();
        let artifact =
            parse_command(". ./env.sh", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, ".");
                assert_eq!(resolved.profile.primary_name(), "source");
                assert_eq!(resolved.bound.form_id.as_str(), "script_file");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_path"),
                    "./env.sh"
                );
                assert_eq!(
                    resolved.bound.effects[1].kind,
                    EffectKind::SourceScriptIntoCurrentShell
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_read_builtin_as_runtime_input_variable_binding() {
        let registry = built_in_registry();
        let artifact =
            parse_command("read USER_CMD", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "read");
                assert_eq!(resolved.bound.form_id.as_str(), "bind_from_stdin");
                assert_eq!(
                    first_argument_text(&resolved.bound, "variable_name"),
                    "USER_CMD"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ConsumeStdin,
                        EffectKind::BindVariableFromRuntimeInput,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cd_builtin_as_working_directory_target() {
        let registry = built_in_registry();
        let artifact =
            parse_command("cd ./subdir", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cd");
                assert_eq!(resolved.bound.form_id.as_str(), "change_directory");
                assert_eq!(
                    first_argument_text(&resolved.bound, "target_dir"),
                    "./subdir"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::TargetPath,
                        EffectKind::SetCurrentWorkingDirectory,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_cd_without_arguments_as_home_form() {
        let registry = built_in_registry();
        let artifact = parse_command("cd", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "cd");
                assert_eq!(resolved.bound.form_id.as_str(), "change_directory_home");
                assert!(resolved.bound.bound_parameters.is_empty());
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::SetCurrentWorkingDirectory]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_with_bindings_materializes_before_form_selection() {
        let registry = built_in_registry();
        let artifact =
            parse_command("bash $mode", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let bindings = SessionBindings::new().with_exact_scalar("mode", "-s");
        let result = resolve_invocation_with_bindings(
            &registry,
            command,
            InvocationRuntimeContext::new(),
            &bindings,
        );

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.projection.args[0].text, "$mode");
                assert_eq!(
                    resolved.materialized_projection.invocation.args[0].text,
                    "-s"
                );
                assert_eq!(
                    resolved.materialized_projection.invocation.args[0].kind,
                    crate::ProjectedArgKind::Flag
                );
                assert_eq!(resolved.selection.form.id.as_str(), "stdin_script_explicit");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_explicit");
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[0],
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: "mode".to_string(),
                        value: "-s".to_string(),
                        origin: BindingOrigin::SessionBinding,
                    }
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_with_summary_preserves_dynamic_binding_uncertainty() {
        let registry = built_in_registry();
        let artifact =
            parse_command(r#"bash -c "$cmd""#, ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let mut summary = SessionSummary::new();
        summary.set_opaque_dynamic_variable("cmd", "$payload", true, CommandSequenceNo::new(3));

        let result = resolve_invocation_with_summary(
            &registry,
            command,
            InvocationRuntimeContext::new(),
            &summary,
        );

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.selection.form.id.as_str(), "command_string");
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "$cmd");
                assert_eq!(resolved.projection.args[1].text, "$cmd");
                assert_eq!(
                    resolved.materialized_projection.invocation.args[1].text,
                    "$cmd"
                );
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[1],
                    ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: "cmd".to_string(),
                        repr: "$payload".to_string(),
                        origin: BindingOrigin::SessionBinding,
                    }
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_artifact_with_bindings_keeps_raw_and_materialized_views() {
        let registry = built_in_registry();
        let artifact =
            parse_command("bash $mode", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let bindings = SessionBindings::new().with_exact_scalar("mode", "-s");

        let result = resolve_invocation_artifact_with_bindings(
            &registry,
            command,
            InvocationRuntimeContext::new(),
            &bindings,
        );

        match result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "bash");
                assert_eq!(resolved.projection.args[0].text, "$mode");
                assert_eq!(
                    resolved.materialized_projection.invocation.args[0].text,
                    "-s"
                );
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[0],
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: "mode".to_string(),
                        value: "-s".to_string(),
                        origin: BindingOrigin::SessionBinding,
                    }
                );
                assert_eq!(resolved.bound.command_name.as_str(), "bash");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_explicit");
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_artifact_keeps_exact_scalar_materialization_for_dynamic_payload_text() {
        let registry = built_in_registry();
        let artifact =
            parse_command(r#"bash -c "$payload""#, ShellKind::Bash).expect("expected parse");
        let command = artifact.commands.first().expect("expected one command");
        let payload = r#"inner="f(){ f|f; }; f"; eval "$inner""#;
        let bindings = SessionBindings::new().with_exact_scalar("payload", payload);

        let result = resolve_invocation_artifact_with_bindings(
            &registry,
            command,
            InvocationRuntimeContext::new(),
            &bindings,
        );

        match result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(first_argument_text(&resolved.bound, "payload"), payload);
                assert_eq!(
                    first_argument_materialization(&resolved.bound, "payload"),
                    &crate::BoundArgumentMaterialization::ResolvedExactScalar {
                        variable_name: "payload".to_string(),
                    }
                );
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[1],
                    ValueMaterialization::ResolvedExactScalar {
                        variable_name: "payload".to_string(),
                        value: payload.to_string(),
                        origin: BindingOrigin::SessionBinding,
                    }
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_artifact_with_summary_preserves_dynamic_uncertainty() {
        let registry = built_in_registry();
        let artifact =
            parse_command(r#"bash -c "$cmd""#, ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let mut summary = SessionSummary::new();
        summary.set_opaque_dynamic_variable("cmd", "$payload", true, CommandSequenceNo::new(3));

        let result = resolve_invocation_artifact_with_summary(
            &registry,
            command,
            InvocationRuntimeContext::new(),
            &summary,
        );

        match result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.projection.args[1].text, "$cmd");
                assert_eq!(
                    resolved.materialized_projection.invocation.args[1].text,
                    "$cmd"
                );
                assert_eq!(
                    resolved.materialized_projection.arg_resolutions[1],
                    ValueMaterialization::UnsupportedDynamicBinding {
                        variable_name: "cmd".to_string(),
                        repr: "$payload".to_string(),
                        origin: BindingOrigin::SessionBinding,
                    }
                );
                assert_eq!(resolved.bound.form_id.as_str(), "command_string");
                assert_eq!(first_argument_text(&resolved.bound, "payload"), "$cmd");
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_artifact_preserves_no_profile_outcome() {
        let registry = built_in_registry();
        let artifact = parse_command("unknown-tool --help", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result =
            resolve_invocation_artifact(&registry, command, InvocationRuntimeContext::new());

        assert_eq!(
            result,
            ResolveInvocationArtifactResult::NoProfile {
                normalized_command_name: "unknown-tool".to_string(),
                gap_kind: ResolveGapKind::NoProfile,
            }
        );
    }

    #[test]
    fn resolve_invocation_carries_interactive_implicit_input() {
        let registry = built_in_registry();
        let artifact = parse_command("bash", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(
            &registry,
            command,
            InvocationRuntimeContext::new().with_interactive_session(),
        );

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.form_id.as_str(), "interactive");
                assert_eq!(resolved.bound.bound_implicit_inputs.len(), 1);
                assert_eq!(
                    resolved.bound.bound_implicit_inputs[0].source,
                    crate::ImplicitInputSource::InteractiveSession
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_less_as_read_plus_interactive_escape_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("less README.md", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "less");
                assert_eq!(resolved.bound.form_id.as_str(), "interactive_read");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_paths"),
                    "README.md"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::OpenInteractiveEscapeSurface,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_more_as_read_plus_interactive_escape_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("more file.txt", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "more");
                assert_eq!(resolved.bound.form_id.as_str(), "interactive_read");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_paths"),
                    "file.txt"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::OpenInteractiveEscapeSurface,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_apt_get_install_as_imported_package_execution() {
        let registry = built_in_registry();
        let artifact = parse_command("apt-get install curl", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "apt-get");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["curl"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_apt_get_install_dynamic_package_locator() {
        let registry = built_in_registry();
        let artifact = parse_command("apt-get install \"$APT_PKG\"", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "apt-get");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["$APT_PKG"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_apt_get_install_with_yes_flag() {
        let registry = built_in_registry();
        let artifact = parse_command("apt-get install -y curl", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "apt-get");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["curl"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_apt_get_source_as_import_only() {
        let registry = built_in_registry();
        let artifact = parse_command("apt-get source curl", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "apt-get");
                assert_eq!(resolved.bound.form_id.as_str(), "source_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["curl"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ImportPackage]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_conan_install_as_imported_package_execution() {
        let registry = built_in_registry();
        let artifact = parse_command("conan install --requires zlib/1.3.1", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "conan");
                assert_eq!(resolved.bound.form_id.as_str(), "install_requirements");
                assert_eq!(
                    first_argument_text(&resolved.bound, "requires"),
                    "zlib/1.3.1"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_conan_install_positional_requirement() {
        let registry = built_in_registry();
        let artifact = parse_command("conan install zlib/1.3.1", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "conan");
                assert_eq!(
                    resolved.bound.form_id.as_str(),
                    "install_requirement_reference"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "requires"),
                    "zlib/1.3.1"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_conan_install_local_recipe_path() {
        let registry = built_in_registry();
        let artifact =
            parse_command("conan install .", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "conan");
                assert_eq!(
                    resolved.bound.form_id.as_str(),
                    "install_requirement_reference"
                );
                assert_eq!(first_argument_text(&resolved.bound, "requires"), ".");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_pip_requirement_file_as_imported_package_execution() {
        let registry = built_in_registry();
        let artifact = parse_command("pip install -r requirements.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "pip");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "requirement_files"),
                    vec!["requirements.txt"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_pip_editable_target_install() {
        let registry = built_in_registry();
        let artifact = parse_command("pip install -e . --target vendor", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "pip");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(argument_texts(&resolved.bound, "editable_specs"), vec!["."]);
                assert_eq!(
                    first_argument_text(&resolved.bound, "target_directory"),
                    "vendor"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                        EffectKind::WritePath,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_projects_python_m_pip_to_pip_dispatch() {
        let registry = built_in_registry();
        let artifact = parse_command(
            "python -m pip install --dry-run https://example.test/pkg.whl",
            ShellKind::Bash,
        )
        .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "python");
                assert_eq!(resolved.bound.form_id.as_str(), "pip_module_dispatch");
                assert_eq!(first_argument_text(&resolved.bound, "module_name"), "pip");
                assert_eq!(
                    argument_texts(&resolved.bound, "module_args"),
                    vec!["install", "--dry-run", "https://example.test/pkg.whl"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::LoadInProcessCode, EffectKind::DispatchCommand]
                );

                let dispatch = collect_dispatch_command_candidates(&resolved.bound);
                assert_eq!(dispatch.len(), 1);
                assert_eq!(dispatch[0].command.text, "pip");
                assert_eq!(
                    dispatch[0]
                        .argv
                        .iter()
                        .map(|argument| argument.text.as_str())
                        .collect::<Vec<_>>(),
                    vec!["install", "--dry-run", "https://example.test/pkg.whl"]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_pip_dynamic_package_locator() {
        let registry = built_in_registry();
        let artifact = parse_command("pip install \"$PKG\"", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "pip");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["$PKG"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_pip_direct_url_package_locator() {
        let registry = built_in_registry();
        let artifact = parse_command("pip install https://example.test/pkg.whl", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "pip");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["https://example.test/pkg.whl"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_pip_local_path_package_locator() {
        let registry = built_in_registry();
        let artifact = parse_command("pip install ./dist/pkg.whl", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "pip");
                assert_eq!(resolved.bound.form_id.as_str(), "install_packages");
                assert_eq!(
                    argument_texts(&resolved.bound, "package_specs"),
                    vec!["./dist/pkg.whl"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ImportPackage,
                        EffectKind::ExecuteImportedPackageLogic,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_top_interactive_and_batch_modes() {
        let registry = built_in_registry();

        let top_artifact =
            parse_command("top", ShellKind::Bash).expect("expected parse to succeed");
        let top_command = top_artifact.commands.first().expect("expected one command");
        let top_result =
            resolve_invocation(&registry, top_command, InvocationRuntimeContext::new());

        match top_result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "top");
                assert_eq!(resolved.bound.form_id.as_str(), "interactive");
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::OpenInteractiveEscapeSurface]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }

        let batch_artifact =
            parse_command("top -b", ShellKind::Bash).expect("expected parse to succeed");
        let batch_command = batch_artifact
            .commands
            .first()
            .expect("expected one command");
        let batch_result =
            resolve_invocation(&registry, batch_command, InvocationRuntimeContext::new());

        match batch_result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "top");
                assert_eq!(resolved.bound.form_id.as_str(), "batch");
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_vim_interactive_escape_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("vim notes.txt", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "vim");
                assert_eq!(resolved.bound.form_id.as_str(), "interactive_editor");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_paths"),
                    "notes.txt"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::OpenInteractiveEscapeSurface,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_vim_short_cluster_as_script_mode() {
        let registry = built_in_registry();
        let artifact = parse_command("vim -es -S script.vim", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "vim");
                assert_eq!(resolved.bound.form_id.as_str(), "script_mode");
                assert_eq!(
                    first_argument_text(&resolved.bound, "session_file"),
                    "script.vim"
                );
                assert!(find_bound_parameter_opt(&resolved.bound, "input_paths").is_none());
                assert!(effect_kinds(&resolved.bound).is_empty());
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_vim_script_input_mode_without_interactive_surface() {
        let registry = built_in_registry();
        let artifact = parse_command("vim -s commands.vim notes.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "vim");
                assert_eq!(resolved.bound.form_id.as_str(), "script_mode");
                assert_eq!(
                    first_argument_text(&resolved.bound, "script_input"),
                    "commands.vim"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_paths"),
                    "notes.txt"
                );
                assert_eq!(effect_kinds(&resolved.bound), vec![EffectKind::ReadPath]);
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_vim_session_file_as_interactive_without_fake_input_read() {
        let registry = built_in_registry();
        let artifact = parse_command("vim -S session.vim notes.txt", ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "vim");
                assert_eq!(resolved.bound.form_id.as_str(), "interactive_editor");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_paths"),
                    "notes.txt"
                );
                assert_eq!(
                    first_argument_text(&resolved.bound, "session_file"),
                    "session.vim"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::OpenInteractiveEscapeSurface,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_ed_interactive_escape_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("ed file.txt", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(&registry, command, InvocationRuntimeContext::new());

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "ed");
                assert_eq!(resolved.bound.form_id.as_str(), "interactive_editor");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_paths"),
                    "file.txt"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![
                        EffectKind::ReadPath,
                        EffectKind::OpenInteractiveEscapeSurface,
                    ]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_ed_stdin_script_mode_without_interactive_surface() {
        let registry = built_in_registry();
        let artifact =
            parse_command("ed file.txt", ShellKind::Bash).expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let result = resolve_invocation(
            &registry,
            command,
            InvocationRuntimeContext::new().with_stdin_payload_available(),
        );

        match result {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "ed");
                assert_eq!(resolved.bound.form_id.as_str(), "stdin_script_mode");
                assert_eq!(
                    first_argument_text(&resolved.bound, "input_paths"),
                    "file.txt"
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ReadPath, EffectKind::ConsumeStdin]
                );
            }
            other => panic!("unexpected resolve result: {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_eval_joined_payload_form() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"eval "$LEFT" "$RIGHT""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let bindings = SessionBindings::new()
            .with_exact_scalar("LEFT", "echo")
            .with_exact_scalar("RIGHT", "ok");
        let result = resolve_invocation_artifact_with_bindings(
            &registry,
            command,
            InvocationRuntimeContext::new(),
            &bindings,
        );

        match result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "eval");
                assert_eq!(resolved.bound.form_id.as_str(), "joined_payload");
                assert_eq!(
                    argument_texts(&resolved.bound, "payload"),
                    vec!["echo", "ok"]
                );
                assert_eq!(
                    effect_kinds(&resolved.bound),
                    vec![EffectKind::ExecutePayload]
                );
            }
            other => panic!("expected resolved eval invocation, got {other:?}"),
        }
    }

    #[test]
    fn resolve_invocation_resolves_eval_joined_payload_form_after_dashdash() {
        let registry = built_in_registry();
        let artifact = parse_command(r#"eval -- "$LEFT" "$RIGHT""#, ShellKind::Bash)
            .expect("expected parse to succeed");

        let command = artifact.commands.first().expect("expected one command");
        let bindings = SessionBindings::new()
            .with_exact_scalar("LEFT", "echo")
            .with_exact_scalar("RIGHT", "ok");
        let result = resolve_invocation_artifact_with_bindings(
            &registry,
            command,
            InvocationRuntimeContext::new(),
            &bindings,
        );

        match result {
            ResolveInvocationArtifactResult::Resolved(resolved) => {
                assert_eq!(resolved.normalized_command_name, "eval");
                assert_eq!(resolved.bound.form_id.as_str(), "joined_payload");
                assert_eq!(
                    argument_texts(&resolved.bound, "payload"),
                    vec!["echo", "ok"]
                );
            }
            other => panic!("expected resolved eval invocation, got {other:?}"),
        }
    }
}

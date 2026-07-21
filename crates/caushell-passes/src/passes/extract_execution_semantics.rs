use caushell_profile::{
    BoundInvocation, DerivedPathTarget, EffectKind, EffectTarget, PathPurpose, PayloadSource,
    ResolveInvocationArtifactResult, SemanticType,
};
use caushell_runner::{PendingMutation, RunnerContext, SessionTransformPass, SessionView};
use caushell_types::{
    ExecutionPayloadMode, ExecutionSemantics, InProcessCodeLoadKind, InteractiveEscapeCapability,
    InteractiveEscapeSurfaceKind, ProcessControlAction, ProcessControlTargetKind,
};

use crate::support::{
    execution_semantics_node_id, graph_backed_execution_resolve_records,
    implicit_startup_source_node_ids,
};

pub struct ExtractExecutionSemanticsPass;

impl SessionTransformPass for ExtractExecutionSemanticsPass {
    fn name(&self) -> &'static str {
        "extract_execution_semantics"
    }

    fn run(&self, _session: SessionView<'_>, ctx: &mut RunnerContext) {
        for mutation in collect_execution_semantics_mutations(ctx) {
            ctx.stage_mutation(mutation);
        }
    }
}

fn collect_execution_semantics_mutations(ctx: &RunnerContext) -> Vec<PendingMutation> {
    let implicit_startup_sources = implicit_startup_source_node_ids(ctx);

    graph_backed_execution_resolve_records(ctx)
        .into_iter()
        .filter_map(|record| {
            project_execution_semantics_mutation(
                record,
                implicit_startup_sources.contains(record.source_node_id()),
            )
        })
        .collect()
}

fn project_execution_semantics_mutation(
    record: crate::support::ExecutionResolveRecordRef<'_>,
    has_implicit_startup_config: bool,
) -> Option<PendingMutation> {
    let ResolveInvocationArtifactResult::Resolved(resolved) = record.result() else {
        return None;
    };

    Some(PendingMutation::AddExecutionSemantics {
        source_node_id: record.source_node_id().clone(),
        node_id: execution_semantics_node_id(record.source_node_id()),
        semantics: execution_semantics_for_bound(
            &resolved.normalized_command_name,
            &resolved.bound,
            has_implicit_startup_config,
        ),
    })
}

fn execution_semantics_for_bound(
    normalized_command_name: &str,
    invocation: &BoundInvocation,
    has_implicit_startup_config: bool,
) -> ExecutionSemantics {
    let mut semantics =
        ExecutionSemantics::new(normalized_command_name, invocation.form_id.as_str());

    if invocation.effects.iter().any(|effect| {
        matches!(
            effect.kind,
            EffectKind::ExecutePayload
                | EffectKind::SourceScriptIntoCurrentShell
                | EffectKind::ExecuteHook
        )
    }) {
        semantics = semantics.executing_payload();
    }

    if invocation
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::ExecuteImportedPackageLogic)
    {
        semantics = semantics.executing_imported_package_logic();
    }

    for load_kind in in_process_code_load_kinds_for_invocation(invocation) {
        semantics = semantics.loading_in_process_code(load_kind);
    }

    if let Some(surface) = invocation
        .effects
        .iter()
        .find(|effect| effect.kind == EffectKind::OpenInteractiveEscapeSurface)
        .and_then(|effect| effect.interactive_escape_surface.as_ref())
    {
        semantics = semantics.opening_interactive_escape_surface(
            map_interactive_escape_surface_kind(surface.kind),
            surface
                .capabilities
                .iter()
                .copied()
                .map(map_interactive_escape_capability),
            surface.requires_tty,
        );
    }

    if let Some((action, target_kind, broad_target)) =
        process_control_semantics_for_invocation(normalized_command_name, invocation)
    {
        semantics = semantics.controlling_process(action, target_kind, broad_target);
    }

    if invocation.effects.iter().any(|effect| {
        matches!(
            effect.kind,
            EffectKind::SourceScriptIntoCurrentShell
                | EffectKind::SetCurrentWorkingDirectory
                | EffectKind::BindVariableFromRuntimeInput
        )
    }) {
        semantics = semantics.mutating_current_shell();
    }

    if invocation
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::ExecuteHook)
    {
        semantics = semantics.executing_hook();
    }

    if invocation
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::ExecuteRemoteCommand)
    {
        semantics = semantics.executing_remote_command();
    }

    for effect in invocation
        .effects
        .iter()
        .filter(|effect| effect.kind == EffectKind::LoadConfig)
    {
        match config_purpose_for_effect_target(invocation, &effect.target) {
            Some(PathPurpose::ProjectConfig) | Some(PathPurpose::TaskConfig) => {
                semantics = semantics.loading_project_config();
            }
            Some(PathPurpose::ToolConfig) => {
                semantics = semantics.loading_tool_config();
            }
            Some(PathPurpose::StartupConfig)
            | Some(PathPurpose::GenericOperand)
            | Some(PathPurpose::InProcessCode)
            | Some(PathPurpose::ScriptSource)
            | Some(PathPurpose::WorkingDirectory)
            | None => {
                semantics = semantics.loading_startup_config();
            }
        }
    }

    if invocation
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::ExecuteConfigDefinedTask)
    {
        semantics = semantics.executing_config_defined_task();
    }

    if has_implicit_startup_config {
        semantics = semantics.loading_startup_config();
    }

    if invocation
        .effects
        .iter()
        .any(|effect| effect.kind == EffectKind::DispatchCommand)
    {
        semantics = semantics.dispatching_child_command();
    }

    if let Some(payload_mode) = payload_mode_for_invocation(invocation) {
        semantics = semantics.with_payload_mode(payload_mode);
    }

    semantics
}

fn map_interactive_escape_surface_kind(
    kind: caushell_types::InteractiveEscapeSurfaceKind,
) -> InteractiveEscapeSurfaceKind {
    kind
}

fn map_interactive_escape_capability(
    capability: caushell_types::InteractiveEscapeCapability,
) -> InteractiveEscapeCapability {
    capability
}

fn config_purpose_for_effect_target(
    invocation: &BoundInvocation,
    target: &EffectTarget,
) -> Option<PathPurpose> {
    match target {
        EffectTarget::Slot(slot_name) => invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name == *slot_name)
            .and_then(|parameter| match &parameter.semantic {
                SemanticType::Path(path) => path.purpose,
                _ => None,
            }),
        EffectTarget::ToolConventionPath(target) => target.purpose,
        EffectTarget::DerivedPath(target) => target.purpose,
        EffectTarget::MutationScope(_)
        | EffectTarget::ImplicitInput(_)
        | EffectTarget::Dispatch(_)
        | EffectTarget::None => None,
    }
}

fn payload_mode_for_invocation(invocation: &BoundInvocation) -> Option<ExecutionPayloadMode> {
    invocation
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.kind,
                EffectKind::ExecutePayload
                    | EffectKind::SourceScriptIntoCurrentShell
                    | EffectKind::ExecuteHook
            )
        })
        .find_map(|effect| payload_mode_for_effect(invocation, effect))
}

fn process_control_semantics_for_invocation(
    normalized_command_name: &str,
    invocation: &BoundInvocation,
) -> Option<(ProcessControlAction, ProcessControlTargetKind, bool)> {
    let effect = invocation
        .effects
        .iter()
        .find(|effect| effect.kind == EffectKind::ControlProcess)?;
    let action = process_control_action(normalized_command_name, invocation.form_id.as_str())?;
    let (target_kind, broad_target) =
        process_control_target_kind_for_effect_target(invocation, &effect.target)?;

    Some((action, target_kind, broad_target))
}

fn in_process_code_load_kinds_for_invocation(
    invocation: &BoundInvocation,
) -> impl Iterator<Item = InProcessCodeLoadKind> + '_ {
    invocation
        .effects
        .iter()
        .filter(|effect| effect.kind == EffectKind::LoadInProcessCode)
        .map(|effect| in_process_code_load_kind_for_effect(invocation, effect))
}

fn in_process_code_load_kind_for_effect(
    invocation: &BoundInvocation,
    effect: &caushell_profile::Effect,
) -> InProcessCodeLoadKind {
    let EffectTarget::Slot(slot_name) = &effect.target else {
        return InProcessCodeLoadKind::Unknown;
    };

    invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name == *slot_name)
        .and_then(|parameter| match &parameter.semantic {
            SemanticType::InProcessCodeLoad(semantic) => Some(semantic.load_kind),
            SemanticType::Path(path) if path.purpose == Some(PathPurpose::InProcessCode) => {
                Some(InProcessCodeLoadKind::Path)
            }
            _ => None,
        })
        .unwrap_or(InProcessCodeLoadKind::Unknown)
}

fn process_control_action(
    normalized_command_name: &str,
    form_id: &str,
) -> Option<ProcessControlAction> {
    match (normalized_command_name, form_id) {
        ("kill", _) | ("pkill", _) | ("killall", _) => Some(ProcessControlAction::Signal),
        ("fg", _) => Some(ProcessControlAction::ResumeForeground),
        ("bg", _) => Some(ProcessControlAction::ResumeBackground),
        _ => None,
    }
}

fn process_control_target_kind_for_effect_target(
    invocation: &BoundInvocation,
    target: &EffectTarget,
) -> Option<(ProcessControlTargetKind, bool)> {
    let EffectTarget::Slot(slot_name) = target else {
        return None;
    };
    let parameter = invocation
        .bound_parameters
        .iter()
        .find(|parameter| parameter.name == *slot_name)?;
    let caushell_profile::SemanticType::ProcessTarget(semantic) = &parameter.semantic else {
        return None;
    };

    Some((
        match semantic.kind {
            caushell_profile::ProcessTargetKind::Pid => ProcessControlTargetKind::Pid,
            caushell_profile::ProcessTargetKind::ProcessName => {
                ProcessControlTargetKind::ProcessName
            }
            caushell_profile::ProcessTargetKind::ProcessPattern => {
                ProcessControlTargetKind::ProcessPattern
            }
            caushell_profile::ProcessTargetKind::JobSpec => ProcessControlTargetKind::JobSpec,
            caushell_profile::ProcessTargetKind::Unknown => ProcessControlTargetKind::Unknown,
        },
        semantic.broad_match,
    ))
}

fn payload_mode_for_effect(
    invocation: &BoundInvocation,
    effect: &caushell_profile::Effect,
) -> Option<ExecutionPayloadMode> {
    if effect.kind == EffectKind::SourceScriptIntoCurrentShell {
        return Some(ExecutionPayloadMode::SourcedScript);
    }

    if effect.kind == EffectKind::ExecuteHook {
        return Some(ExecutionPayloadMode::ScriptFile);
    }

    match &effect.target {
        EffectTarget::Slot(slot_name) => invocation
            .bound_parameters
            .iter()
            .find(|parameter| parameter.name == *slot_name)
            .and_then(|parameter| payload_mode_for_semantic(&parameter.semantic, invocation)),
        EffectTarget::ImplicitInput(source) => invocation
            .bound_implicit_inputs
            .iter()
            .find(|input| input.source == *source)
            .and_then(|input| payload_mode_for_semantic(&input.semantic, invocation)),
        EffectTarget::ToolConventionPath(target) => (target.purpose
            == Some(PathPurpose::ScriptSource))
        .then_some(ExecutionPayloadMode::ScriptFile),
        EffectTarget::DerivedPath(target) => payload_mode_for_derived_path_target(target),
        EffectTarget::MutationScope(_) | EffectTarget::Dispatch(_) | EffectTarget::None => None,
    }
}

fn payload_mode_for_derived_path_target(
    target: &DerivedPathTarget,
) -> Option<ExecutionPayloadMode> {
    (target.purpose == Some(PathPurpose::ScriptSource)).then_some(ExecutionPayloadMode::ScriptFile)
}

fn payload_mode_for_semantic(
    semantic: &SemanticType,
    invocation: &BoundInvocation,
) -> Option<ExecutionPayloadMode> {
    match semantic {
        SemanticType::Payload(payload) => match payload.source {
            PayloadSource::InlineString | PayloadSource::DynamicReference => {
                Some(ExecutionPayloadMode::CommandString)
            }
            PayloadSource::ScriptFileRef => Some(ExecutionPayloadMode::ScriptFile),
            PayloadSource::Stdin => match invocation.form_id.as_str() {
                "stdin_script_explicit" => Some(ExecutionPayloadMode::StdinExplicit),
                "stdin_script_implicit" => Some(ExecutionPayloadMode::StdinImplicit),
                _ => None,
            },
            PayloadSource::Interactive => Some(ExecutionPayloadMode::Interactive),
        },
        SemanticType::Path(path) if path.purpose == Some(PathPurpose::ScriptSource) => {
            Some(ExecutionPayloadMode::ScriptFile)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::ExtractExecutionSemanticsPass;
    use crate::{
        ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass,
        ResolveInvocationPass, support::execution_semantics_node_id,
    };
    use caushell_graph::NodeId;
    use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
    use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
    use caushell_types::{
        CheckRequest, CommandSequenceNo, ExecutionPayloadMode, ExecutionSemantics,
        InProcessCodeLoadKind, ProcessControlAction, ProcessControlTargetKind, RuntimeMetadata,
        SessionId, SessionSummary, ShellKind,
    };

    fn sample_request(command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("sess-1"),
            sequence_no: CommandSequenceNo::new(1),
            command: command.to_string(),
            shell_state_before: caushell_types::ShellStateSnapshot::new("/tmp/project".to_string()),
            shell_kind: ShellKind::Bash,
            runtime: RuntimeMetadata {
                runtime_name: "codex".to_string(),
                tool_name: Some("Bash".to_string()),
                shell_runtime_capabilities:
                    caushell_types::ShellRuntimeCapabilities::persistent_shell(),
            },
            home: Some("/home/alice".to_string()),
            workspace_root: Some("/tmp/project".to_string()),
        }
    }

    fn built_in_registry() -> ProfileRegistry {
        ProfileRegistry::built_in().expect("expected built-in registry to load")
    }

    fn registry_from_yaml(yaml: &str) -> ProfileRegistry {
        let profile = load_command_profile_from_str(yaml).expect("expected profile to load");
        ProfileRegistry::from_profiles(vec![profile]).expect("expected registry to build")
    }

    fn run_pass(command: &str) -> RunnerContext {
        run_pass_with_request(sample_request(command))
    }

    fn run_pass_with_request(request: CheckRequest) -> RunnerContext {
        run_pass_with_registry(request, built_in_registry())
    }

    fn run_pass_with_registry(request: CheckRequest, registry: ProfileRegistry) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
        runner.register_session_transform_pass(ExtractPipelineFlowPass);
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);

        let graph = caushell_graph::SessionGraph::new();
        let summary = SessionSummary::default();
        let mut ctx = RunnerContext::new(request);

        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        ctx
    }

    fn run_pass_with_summary(summary: &SessionSummary, command: &str) -> RunnerContext {
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(built_in_registry()));
        runner.register_session_transform_pass(ExtractPipelineFlowPass);
        runner.register_session_transform_pass(ExtractExecutionSemanticsPass);

        let graph = caushell_graph::SessionGraph::new();
        let mut ctx = RunnerContext::new(sample_request(command));

        runner.run(SessionView::new(&graph, summary), &mut ctx);
        ctx
    }

    fn semantics_mutation_for_node<'a>(
        ctx: &'a RunnerContext,
        node_id: &NodeId,
    ) -> &'a ExecutionSemantics {
        ctx.pending_mutations()
            .iter()
            .find_map(|mutation| match mutation {
                PendingMutation::AddExecutionSemantics {
                    source_node_id,
                    semantics,
                    ..
                } if source_node_id == node_id => Some(semantics),
                _ => None,
            })
            .expect("expected execution semantics mutation to exist")
    }

    #[test]
    fn extract_execution_semantics_projects_top_level_payload_and_config() {
        let ctx = run_pass(r#"bash --rcfile ./team.rc -c 'echo ok'"#);
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("bash", "command_string")
                .with_payload_mode(ExecutionPayloadMode::CommandString)
                .executing_payload()
                .loading_startup_config()
        );
    }

    #[test]
    fn extract_execution_semantics_projects_pipeline_sink_to_segment_node() {
        let ctx = run_pass("cat ./payload.sh | bash");
        let source_node_id = NodeId::new("pipeline-segment:sess-1:1:1");
        let semantics = semantics_mutation_for_node(&ctx, &source_node_id);

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("bash", "stdin_script_implicit")
                .with_payload_mode(ExecutionPayloadMode::StdinImplicit)
                .executing_payload()
        );

        let semantics_node_id = execution_semantics_node_id(&source_node_id);
        assert!(ctx.pending_mutations().iter().any(|mutation| matches!(
            mutation,
            PendingMutation::AddExecutionSemantics { node_id, .. } if node_id == &semantics_node_id
        )));
    }

    #[test]
    fn extract_execution_semantics_projects_dispatch_derived_payload_consumer() {
        let ctx = run_pass("sudo bash ./scripts/build.sh");
        let semantics =
            semantics_mutation_for_node(&ctx, &NodeId::new("derived-dispatch:sess-1:1:0:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("bash", "script_file")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload()
        );
    }

    #[test]
    fn extract_execution_semantics_projects_python_module_load_surface() {
        let ctx = run_pass("python -m http.server");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("python", "module")
                .loading_in_process_code(InProcessCodeLoadKind::ModuleName)
        );
    }

    #[test]
    fn extract_execution_semantics_projects_node_preload_and_script_surface_together() {
        let ctx = run_pass("node -r ./hook.js app.js");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("node", "script_file")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload()
                .loading_in_process_code(InProcessCodeLoadKind::Unknown)
        );
    }

    #[test]
    fn extract_execution_semantics_projects_vim_interactive_escape_surface() {
        let ctx = run_pass("vim notes.txt");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("vim", "interactive_editor")
                .opening_interactive_escape_surface(
                    caushell_types::InteractiveEscapeSurfaceKind::Editor,
                    [
                        caushell_types::InteractiveEscapeCapability::SpawnShell,
                        caushell_types::InteractiveEscapeCapability::RunCommand,
                        caushell_types::InteractiveEscapeCapability::WriteBufferToPath,
                    ],
                    true,
                )
        );
    }

    #[test]
    fn extract_execution_semantics_projects_more_interactive_escape_surface() {
        let ctx = run_pass("more file.txt");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("more", "interactive_read")
                .opening_interactive_escape_surface(
                    caushell_types::InteractiveEscapeSurfaceKind::Pager,
                    [caushell_types::InteractiveEscapeCapability::SpawnShell],
                    true,
                )
        );
    }

    #[test]
    fn extract_execution_semantics_projects_top_interactive_escape_surface() {
        let ctx = run_pass("top");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("top", "interactive").opening_interactive_escape_surface(
                caushell_types::InteractiveEscapeSurfaceKind::TerminalUi,
                [caushell_types::InteractiveEscapeCapability::RunCommand],
                true,
            )
        );
    }

    #[test]
    fn extract_execution_semantics_skips_top_batch_mode_escape_surface() {
        let ctx = run_pass("top -b");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(semantics, &ExecutionSemantics::new("top", "batch"));
    }

    #[test]
    fn extract_execution_semantics_skips_vim_script_mode_escape_surface() {
        let ctx = run_pass("vim -es -S script.vim");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(semantics, &ExecutionSemantics::new("vim", "script_mode"));
    }

    #[test]
    fn extract_execution_semantics_projects_ed_interactive_escape_surface() {
        let ctx = run_pass("ed file.txt");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("ed", "interactive_editor")
                .opening_interactive_escape_surface(
                    caushell_types::InteractiveEscapeSurfaceKind::LineEditor,
                    [
                        caushell_types::InteractiveEscapeCapability::SpawnShell,
                        caushell_types::InteractiveEscapeCapability::WriteBufferToPath,
                    ],
                    true,
                )
        );
    }

    #[test]
    fn extract_execution_semantics_projects_pipeline_ed_as_stdin_script_mode() {
        let ctx = run_pass("printf 'a\\n' | ed file.txt");
        let semantics =
            semantics_mutation_for_node(&ctx, &NodeId::new("pipeline-segment:sess-1:1:1"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("ed", "stdin_script_mode")
        );
    }

    #[test]
    fn extract_execution_semantics_projects_function_derived_payload_consumer() {
        let mut summary = SessionSummary::default();
        summary.set_function(
            "deploy",
            "bash ./scripts/build.sh;",
            CommandSequenceNo::new(1),
        );

        let ctx = run_pass_with_summary(&summary, "deploy");
        let semantics =
            semantics_mutation_for_node(&ctx, &NodeId::new("derived-function:sess-1:1:0:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("bash", "script_file")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload()
        );
    }

    #[test]
    fn extract_execution_semantics_marks_bash_env_as_startup_config_load() {
        let mut request = sample_request(r#"bash -c 'echo ok'"#);
        request.shell_state_before = request
            .shell_state_before
            .clone()
            .with_exact_scalar_variable("BASH_ENV", "../shared/team.rc", true)
            .with_variable_knowledge(caushell_types::ShellStateKnowledge::ExportedOnly);

        let ctx = run_pass_with_request(request);
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("bash", "command_string")
                .with_payload_mode(ExecutionPayloadMode::CommandString)
                .executing_payload()
                .loading_startup_config()
        );
    }

    #[test]
    fn extract_execution_semantics_marks_tool_convention_project_config_load() {
        let registry = registry_from_yaml(
            r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile

identity:
  canonical_name: projtool
  aliases: []

trust:
  tier: tier_a
  source: built_in

platform:
  os_families: [posix, linux, macos]
  shell_families: []
  requires_features: []

forms:
  - id: load_convention
    selector:
      kind: all
      items: []
    effects:
      - kind: load_config
        target:
          kind: tool_convention_path
          path: package.json
          convention: npm.package_json
          purpose: project_config
      - kind: execute_config_defined_task
        target:
          kind: none

modifiers: []
subcommands: null
extensions: {}
"#,
        );

        let ctx = run_pass_with_registry(sample_request("projtool"), registry);
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("projtool", "load_convention")
                .loading_project_config()
                .executing_config_defined_task()
        );
    }

    #[test]
    fn extract_execution_semantics_marks_git_commit_hook_execution() {
        let ctx = run_pass("git commit -m 'ship it'");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("git", "commit_message_with_hooks")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload()
                .executing_hook()
                .loading_tool_config()
        );
    }

    #[test]
    fn extract_execution_semantics_skips_git_hook_when_no_verify_is_present() {
        let ctx = run_pass("git commit --no-verify -m 'ship it'");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("git", "commit_message_no_verify").loading_tool_config()
        );
    }

    #[test]
    fn extract_execution_semantics_marks_git_am_hook_execution() {
        let ctx = run_pass("git am patch.mbox");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("git", "apply_mailbox_with_hooks")
                .with_payload_mode(ExecutionPayloadMode::ScriptFile)
                .executing_payload()
                .executing_hook()
                .loading_tool_config()
        );
    }

    #[test]
    fn extract_execution_semantics_skips_git_am_hook_when_no_verify_is_present() {
        let ctx = run_pass("git am --no-verify patch.mbox");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("git", "apply_mailbox_no_verify").loading_tool_config()
        );
    }

    #[test]
    fn extract_execution_semantics_distinguishes_sourced_script_from_child_shell_script() {
        let ctx = run_pass("source ./env.sh");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("source", "script_file")
                .with_payload_mode(ExecutionPayloadMode::SourcedScript)
                .executing_payload()
                .mutating_current_shell()
        );
    }

    #[test]
    fn extract_execution_semantics_marks_cd_as_current_shell_mutator() {
        let ctx = run_pass("cd ./subdir");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("cd", "change_directory").mutating_current_shell()
        );
    }

    #[test]
    fn extract_execution_semantics_marks_read_as_current_shell_mutator() {
        let ctx = run_pass("read USER_CMD");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("read", "bind_from_stdin").mutating_current_shell()
        );
    }

    #[test]
    fn extract_execution_semantics_projects_kill_process_control() {
        let ctx = run_pass("kill 1234");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("kill", "signal_targets").controlling_process(
                ProcessControlAction::Signal,
                ProcessControlTargetKind::Unknown,
                false,
            )
        );
    }

    #[test]
    fn extract_execution_semantics_projects_pkill_full_pattern_process_control() {
        let ctx = run_pass("pkill -f bash");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("pkill", "process_pattern_targets").controlling_process(
                ProcessControlAction::Signal,
                ProcessControlTargetKind::ProcessPattern,
                true,
            )
        );
    }

    #[test]
    fn extract_execution_semantics_projects_fg_job_control() {
        let ctx = run_pass("fg %1");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("fg", "resume_job").controlling_process(
                ProcessControlAction::ResumeForeground,
                ProcessControlTargetKind::JobSpec,
                false,
            )
        );
    }

    #[test]
    fn extract_execution_semantics_projects_killall_process_control() {
        let ctx = run_pass("killall ssh-agent");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("killall", "process_name_targets").controlling_process(
                ProcessControlAction::Signal,
                ProcessControlTargetKind::ProcessName,
                true,
            )
        );
    }

    #[test]
    fn extract_execution_semantics_projects_bg_job_control() {
        let ctx = run_pass("bg %1");
        let semantics = semantics_mutation_for_node(&ctx, &NodeId::new("command:sess-1:1:0"));

        assert_eq!(
            semantics,
            &ExecutionSemantics::new("bg", "resume_job").controlling_process(
                ProcessControlAction::ResumeBackground,
                ProcessControlTargetKind::JobSpec,
                false,
            )
        );
    }
}

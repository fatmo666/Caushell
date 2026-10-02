//! These tests analyze shell text; none of the example commands is executed.
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    CatastrophicDeleteGuardPass, ComputeEffectiveCwdPass, DecisionAssemblyPass,
    ExtractExecutionSemanticsPass, ExtractPathFactsPass, ExtractPipelineFlowPass,
    OutsideWorkspaceMutationGuardPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass, ResolvePolicyPass,
};
use caushell_profile::{
    BoundValue, ProfileRegistry, ResolveInvocationArtifactResult, load_command_profile_from_str,
};
use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, DerivedPathBasis, MutationScopeResolution,
    PathResolution, ProvenanceArtifact, ResolvedPathRole, RuleId, RuntimeMetadata,
    RuntimeProducedValueKind, SessionId, SessionSummary, ShellKind, ShellStateSnapshot,
};

const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: projection-tool}
forms:
  - id: run
    parameters:
      - name: cache
        semantic: {kind: path, role: write, purpose: generic_operand}
        binding: {kind: following_flag, flag: '--override', operand_mode: next_arg}
        cardinality: optional_many
        value_projection: {kind: key_value, separator: '=', key: cache_dir}
      - name: selectors
        semantic: {kind: path, role: read, purpose: generic_operand}
        binding: {kind: remaining_positionals}
        cardinality: optional_many
        value_projection: {kind: prefix_before, delimiter: '::', if_absent: original}
    effects:
      - {kind: read_path, target: {kind: slot, name: selectors}}
      - {kind: write_path, target: {kind: slot, name: cache}}
"#;

const DELETE_PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: delete-projection}
forms:
  - id: delete
    parameters:
      - name: paths
        semantic: {kind: path, role: target, purpose: generic_operand}
        binding: {kind: remaining_positionals}
        cardinality: required_many
        value_projection: {kind: key_value, separator: '=', key: target}
    effects:
      - kind: delete_path
        target: {kind: slot, name: paths}
        catastrophic: {semantic_class: delete_path}
"#;

const SCOPE_PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: scope-projection}
forms:
  - id: mutate
    parameters:
      - name: root
        semantic: {kind: path, role: target, purpose: generic_operand}
        binding: {kind: next_positional}
        value_projection: {kind: key_value, separator: '=', key: root}
    effects:
      - kind: write_path
        target: {kind: mutation_scope, scope_kind: repository_worktree, root: root, path_set: tracked}
"#;

fn derived_profile(rooted: bool) -> String {
    let name = if rooted {
        "rooted-tool"
    } else {
        "derived-tool"
    };
    let root = if rooted {
        "root: {kind: slot, name: root}"
    } else {
        ""
    };
    format!(
        r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {{canonical_name: {name}}}
forms:
  - id: run
    parameters:
      - name: root
        semantic: {{kind: path, role: target, purpose: generic_operand}}
        binding: {{kind: following_flag, flag: '--root', operand_mode: next_arg}}
        cardinality: optional_many
        value_projection: {{kind: key_value, separator: '=', key: root}}
      - name: source
        semantic: {{kind: path, role: read, purpose: generic_operand}}
        binding: {{kind: remaining_positionals}}
        cardinality: required_many
        value_projection: {{kind: prefix_before, delimiter: '::'}}
    effects:
      - kind: write_path
        target:
          kind: derived_path
          source: {{kind: slot, name: source}}
          {root}
          rule: {{kind: append_suffix, suffix: '.cache'}}
          purpose: generic_operand
"#
    )
}

fn registry() -> ProfileRegistry {
    let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
    for yaml in [
        PROFILE.to_string(),
        DELETE_PROFILE.to_string(),
        SCOPE_PROFILE.to_string(),
        derived_profile(false),
        derived_profile(true),
    ] {
        profiles.push(load_command_profile_from_str(&yaml).unwrap());
    }
    ProfileRegistry::from_profiles(profiles).unwrap()
}

fn request(command: &str, state: ShellStateSnapshot) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("projection-session"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "projection-tests".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: caushell_types::ShellRuntimeCapabilities::persistent_shell(
            ),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn run_with_registry(
    command: &str,
    state: ShellStateSnapshot,
    registry: ProfileRegistry,
) -> RunnerContext {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    runner.register_request_analysis_pass(ResolvePolicyPass);
    runner.register_session_analysis_pass(OutsideWorkspaceMutationGuardPass);
    runner.register_session_analysis_pass(CatastrophicDeleteGuardPass);
    runner.register_final_decision_pass(DecisionAssemblyPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command, state));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    for mutation in ctx.pending_mutations() {
        if let PendingMutation::AddPathFact {
            node_id,
            resolution,
            ..
        } = mutation
        {
            assert!(matches!(&staged.graph().get_node(node_id).unwrap().kind,
                NodeKind::PathFact { resolution: graph_resolution, .. } if graph_resolution == resolution));
        }
    }
    ctx
}

fn run(command: &str) -> RunnerContext {
    run_with_registry(command, ShellStateSnapshot::new("/tmp/project"), registry())
}

fn paths<'a>(ctx: &'a RunnerContext, slot: &str) -> Vec<&'a PathResolution> {
    ctx.pending_mutations()
        .iter()
        .filter_map(|mutation| match mutation {
            PendingMutation::AddPathFact {
                slot_name,
                resolution,
                ..
            } if slot_name == slot => Some(resolution),
            _ => None,
        })
        .collect()
}

fn concrete_paths(ctx: &RunnerContext, slot: &str) -> Vec<String> {
    paths(ctx, slot)
        .into_iter()
        .filter_map(PathResolution::concrete_path)
        .map(str::to_string)
        .collect()
}

fn assert_decision(ctx: &RunnerContext, decision: Decision) {
    assert_eq!(
        ctx.final_decision,
        Some(decision),
        "{:?}: {:?}",
        ctx.request().command,
        ctx.findings
    );
}

#[test]
fn selector_path_enters_graph_but_execution_argument_retains_selector() {
    let ctx = run("projection-tool tests/test_api.py::test_login");
    assert_eq!(
        concrete_paths(&ctx, "selectors"),
        ["/tmp/project/tests/test_api.py"]
    );
    let resolved = ctx
        .execution_unit_resolve_records()
        .iter()
        .find_map(|r| match &r.result {
            ResolveInvocationArtifactResult::Resolved(r)
                if r.normalized_command_name == "projection-tool" =>
            {
                Some(r)
            }
            _ => None,
        })
        .unwrap();
    assert!(
        matches!(&resolved.bound.bound_parameters[0].values[0], BoundValue::Argument { text, .. } if text == "tests/test_api.py::test_login")
    );
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn external_keyed_cache_path_is_not_misread_as_workspace_relative_text() {
    let ctx = run("projection-tool --override cache_dir=/etc/pytest-cache");
    assert_eq!(concrete_paths(&ctx, "cache"), ["/etc/pytest-cache"]);
    assert_decision(&ctx, Decision::NeedApproval);
    assert!(
        ctx.findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
    );
}

#[test]
fn workspace_cache_path_is_allowed() {
    let ctx = run("projection-tool --override cache_dir=.cache/run");
    assert_eq!(concrete_paths(&ctx, "cache"), ["/tmp/project/.cache/run"]);
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn nonmatching_key_produces_no_path_no_provenance_and_no_mutation_fallback() {
    let ctx = run(
        "projection-tool --override console_output_style=classic --override \"unrelated=$UNKNOWN\"",
    );
    assert!(paths(&ctx, "cache").is_empty());
    assert!(!ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::AddProvenanceArtifact { artifact: ProvenanceArtifact::PathContent { path, .. }, .. } if path.contains("console_output_style") || path.contains("unrelated"))));
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn unresolved_and_empty_cache_values_remain_unknown_and_require_approval() {
    for value in [
        "cache_dir=$UNKNOWN",
        "$KEY=/etc/cache",
        "cache_dir",
        "cache_dir=",
    ] {
        let ctx = run(&format!("projection-tool --override {value}"));
        assert_eq!(paths(&ctx, "cache").len(), 1, "{value}");
        assert!(matches!(
            paths(&ctx, "cache")[0],
            PathResolution::UnsupportedDynamicText { .. }
        ));
        assert_decision(&ctx, Decision::NeedApproval);
    }
}

#[test]
fn repeated_override_values_preserve_matching_paths_and_indices() {
    let ctx = run(
        "projection-tool --override unrelated=/etc/unused --override cache_dir=.cache --override cache_dir=/etc/cache",
    );
    assert_eq!(
        concrete_paths(&ctx, "cache"),
        ["/tmp/project/.cache", "/etc/cache"]
    );
    assert_decision(&ctx, Decision::NeedApproval);
}

#[test]
fn decoded_quoted_data_is_not_expanded_again_by_path_resolution() {
    let state =
        ShellStateSnapshot::new("/tmp/project").with_exact_scalar_variable("ROOT", "/etc", true);
    let ctx = run_with_registry(
        "projection-tool --override 'cache_dir=/tmp/project/$ROOT*'",
        state,
        registry(),
    );
    assert_eq!(concrete_paths(&ctx, "cache"), ["/tmp/project/$ROOT*"]);
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn exact_and_runtime_produced_session_values_are_projected_after_materialization() {
    for state in [
        ShellStateSnapshot::new("/tmp/project").with_exact_scalar_variable(
            "VALUE",
            "cache_dir=/etc/cache",
            true,
        ),
        ShellStateSnapshot::new("/tmp/project").with_runtime_produced_variable(
            "VALUE",
            "cache_dir=/etc/cache",
            RuntimeProducedValueKind::Scalar,
            true,
        ),
    ] {
        let ctx = run_with_registry("projection-tool --override \"$VALUE\"", state, registry());
        assert_eq!(concrete_paths(&ctx, "cache"), ["/etc/cache"]);
        assert_decision(&ctx, Decision::NeedApproval);
    }
}

#[test]
fn projected_paths_have_normal_path_content_provenance() {
    let ctx = run("projection-tool tests/test_api.py::test_login --override cache_dir=.cache/run");
    for expected in ["/tmp/project/tests/test_api.py", "/tmp/project/.cache/run"] {
        assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::AddProvenanceArtifact { artifact: ProvenanceArtifact::PathContent { path, .. }, .. } if path == expected)));
    }
}

#[test]
fn derived_suffix_uses_projected_source_but_retains_original_basis() {
    let ctx = run("derived-tool /etc/input.txt::selector");
    assert_eq!(
        concrete_paths(&ctx, "derived_path_0"),
        ["/etc/input.txt.cache"]
    );
    assert!(
        matches!(paths(&ctx, "derived_path_0")[0], PathResolution::DerivedConcrete { basis: DerivedPathBasis::PathOperand { raw, resolved_input_path: Some(path), .. }, .. } if raw == "/etc/input.txt::selector" && path == "/etc/input.txt")
    );
    assert_decision(&ctx, Decision::NeedApproval);
}

#[test]
fn workspace_derived_suffix_remains_allowed() {
    let ctx = run("derived-tool input.txt::selector");
    assert_eq!(
        concrete_paths(&ctx, "derived_path_0"),
        ["/tmp/project/input.txt.cache"]
    );
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn unknown_derived_source_remains_an_unresolved_effect() {
    let ctx = run("derived-tool $UNKNOWN::selector");
    assert!(matches!(
        paths(&ctx, "derived_path_0")[0],
        PathResolution::DerivedUnresolved { .. }
    ));
    assert_decision(&ctx, Decision::NeedApproval);
}

#[test]
fn rooted_derived_path_uses_projected_root_not_raw_key_value_operand() {
    let ctx = run("rooted-tool --root root=/etc/cache input.txt::selector");
    assert_eq!(
        concrete_paths(&ctx, "derived_path_0"),
        ["/etc/cache/input.txt.cache"]
    );
    assert_decision(&ctx, Decision::NeedApproval);
    let ctx = run("rooted-tool --root root=.cache /etc/input.txt::selector");
    assert_eq!(
        concrete_paths(&ctx, "derived_path_0"),
        ["/tmp/project/.cache/input.txt.cache"]
    );
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn unknown_root_cannot_erase_a_derived_effect() {
    let ctx = run("rooted-tool --root root=$UNKNOWN input.txt::selector");
    assert_eq!(paths(&ctx, "derived_path_0").len(), 1);
    assert!(matches!(
        paths(&ctx, "derived_path_0")[0],
        PathResolution::UnsupportedDynamicText { .. }
    ));
    assert_decision(&ctx, Decision::NeedApproval);
}

#[test]
fn mixed_known_and_unknown_roots_retain_uncertainty() {
    let ctx = run("rooted-tool --root root=.cache --root root=$UNKNOWN input.txt::selector");
    assert_eq!(paths(&ctx, "derived_path_0").len(), 2);
    assert_eq!(
        concrete_paths(&ctx, "derived_path_0"),
        ["/tmp/project/.cache/input.txt.cache"]
    );
    assert_decision(&ctx, Decision::NeedApproval);
}

#[test]
fn inapplicable_derived_root_does_not_create_a_fallback_mutation() {
    let ctx = run("rooted-tool --root unrelated=/etc/cache input.txt::selector");
    assert!(paths(&ctx, "derived_path_0").is_empty());
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn mutation_scope_root_uses_projected_path_without_defaulting_unknown_to_cwd() {
    let ctx = run("scope-projection root=/etc/repo");
    assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::AddMutationScopeFact { resolution: MutationScopeResolution::RepositoryWorktree { root: PathResolution::Concrete { path }, .. }, .. } if path == "/etc/repo")));
    assert_decision(&ctx, Decision::NeedApproval);
    let ctx = run("scope-projection root=$UNKNOWN");
    assert!(ctx.pending_mutations().iter().any(|m| matches!(
        m,
        PendingMutation::AddMutationScopeFact {
            resolution: MutationScopeResolution::RepositoryWorktree {
                root: PathResolution::UnsupportedDynamicText { .. },
                ..
            },
            ..
        }
    )));
    assert_decision(&ctx, Decision::NeedApproval);
}

#[test]
fn unknown_effective_cwd_requires_approval_for_relative_but_not_absolute_projection() {
    let ctx = run("cd \"$UNKNOWN\"; projection-tool --override cache_dir=.cache");
    assert_decision(&ctx, Decision::NeedApproval);
    let ctx = run("cd \"$UNKNOWN\"; projection-tool --override cache_dir=/tmp/project/.cache");
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn derived_projection_keeps_effective_cwd_dependency() {
    assert_decision(
        &run("cd \"$UNKNOWN\"; derived-tool input.txt::selector"),
        Decision::NeedApproval,
    );
    assert_decision(
        &run("cd \"$UNKNOWN\"; derived-tool /tmp/project/input.txt::selector"),
        Decision::Allow,
    );
    assert_decision(
        &run("cd \"$UNKNOWN\"; rooted-tool --root root=.cache input.txt::selector"),
        Decision::NeedApproval,
    );
    assert_decision(
        &run("cd \"$UNKNOWN\"; rooted-tool --root root=/tmp/project/.cache input.txt::selector"),
        Decision::Allow,
    );
}

#[test]
fn catastrophe_guard_sees_projected_root_as_a_delete_target() {
    let ctx = run("delete-projection target=/");
    assert_decision(&ctx, Decision::Deny);
    assert!(
        ctx.findings
            .iter()
            .any(|f| f.rule_id == RuleId::CatastrophicFileSystemDelete)
    );
}

#[test]
fn catastrophe_guard_does_not_reexpand_projected_literal_data() {
    let state =
        ShellStateSnapshot::new("/tmp/project").with_exact_scalar_variable("ROOT", "/", true);
    let ctx = run_with_registry("delete-projection 'target=$ROOT'", state, registry());
    assert_eq!(concrete_paths(&ctx, "paths"), ["/tmp/project/$ROOT"]);
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn catastrophe_guard_skips_nonmatching_key_but_unknown_delete_still_requires_approval() {
    assert_decision(&run("delete-projection unrelated=/"), Decision::Allow);
    assert_decision(
        &run("delete-projection target=$UNKNOWN"),
        Decision::NeedApproval,
    );
}

#[test]
fn partial_selection_retains_known_projected_path_in_graph() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: partial-tool}
forms:
  - id: run
    selector: {kind: no_positional_args}
modifiers:
  - id: override
    matcher: {kind: any_flag, flags: ['--override']}
    parameters:
      - name: cache
        semantic: {kind: path, role: write, purpose: generic_operand}
        binding: {kind: following_matched_flag, operand_mode: next_arg}
        value_projection: {kind: key_value, separator: '=', key: cache_dir}
"#;
    let mut profiles = registry().profiles().to_vec();
    profiles.push(load_command_profile_from_str(yaml).unwrap());
    let state = ShellStateSnapshot::new("/tmp/project").with_exact_scalar_variable(
        "VALUE",
        "cache_dir=/etc/cache",
        true,
    );
    let ctx = run_with_registry(
        "partial-tool --override \"$VALUE\" unsupported",
        state,
        ProfileRegistry::from_profiles(profiles).unwrap(),
    );
    assert_eq!(concrete_paths(&ctx, "cache"), ["/etc/cache"]);
    assert!(
        ctx.execution_unit_resolve_records()
            .iter()
            .any(|r| matches!(
                r.result,
                ResolveInvocationArtifactResult::SelectionError { .. }
            ))
    );
    // Projection preserves known partial facts; it does not change the
    // existing policy for unmatched forms or invent an absent write effect.
}

#[test]
fn omitted_projection_preserves_legacy_operand_and_path_behavior() {
    let mut profile = load_command_profile_from_str(PROFILE).unwrap();
    for p in &mut profile.forms[0].parameters {
        p.value_projection = None;
    }
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let ctx = run_with_registry(
        "projection-tool --override cache_dir=/etc/cache tests/test.py::test_login",
        ShellStateSnapshot::new("/tmp/project"),
        registry,
    );
    assert_eq!(
        concrete_paths(&ctx, "cache"),
        ["/tmp/project/cache_dir=/etc/cache"]
    );
    assert_eq!(
        concrete_paths(&ctx, "selectors"),
        ["/tmp/project/tests/test.py::test_login"]
    );
    assert_decision(&ctx, Decision::Allow);
}

#[test]
fn graph_path_roles_survive_projection() {
    let ctx = run("projection-tool tests/test.py::login --override cache_dir=.cache");
    for (slot, expected) in [
        ("cache", ResolvedPathRole::Write),
        ("selectors", ResolvedPathRole::Read),
    ] {
        assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::AddPathFact { slot_name, role, .. } if slot_name == slot && *role == expected)));
    }
}

#[test]
fn unresolved_unquoted_fields_require_approval_even_after_a_nonmatching_prefix() {
    assert_decision(
        &run("projection-tool --override unrelated=$UNKNOWN"),
        Decision::NeedApproval,
    );
    assert_decision(
        &run("derived-tool input.txt::$UNKNOWN"),
        Decision::NeedApproval,
    );
}

#[test]
fn typed_dispatch_runtime_domain_cannot_bound_a_projected_substring() {
    let ctx = run("find /tmp/project -exec delete-projection '{}' ';'");
    assert!(!paths(&ctx, "paths").is_empty());
    assert!(
        paths(&ctx, "paths")
            .iter()
            .all(|r| matches!(r, PathResolution::UnsupportedDynamicText { .. }))
    );
    assert_decision(&ctx, Decision::NeedApproval);
}

#[test]
fn dispatched_known_argv_data_is_projected_without_becoming_shell_source() {
    let ctx =
        run("printf '%s\\n' 'cache_dir=/etc/cache' | xargs -I{} projection-tool --override '{}'");
    assert_eq!(concrete_paths(&ctx, "cache"), ["/etc/cache"]);
    assert_decision(&ctx, Decision::NeedApproval);
    let state =
        ShellStateSnapshot::new("/tmp/project").with_exact_scalar_variable("ROOT", "/", true);
    let ctx = run_with_registry(
        "printf '%s\\n' 'target=$ROOT' | xargs -I{} delete-projection '{}'",
        state,
        registry(),
    );
    assert_eq!(concrete_paths(&ctx, "paths"), ["/tmp/project/$ROOT"]);
    assert_decision(&ctx, Decision::Allow);
}

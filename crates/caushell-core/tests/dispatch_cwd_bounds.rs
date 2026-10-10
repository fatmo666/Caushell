//! Static checks only: no benchmark command or filesystem probe is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, ResolveInvocationArtifactResult, StdoutScalarShape};
use caushell_runner::{EffectiveCwd, PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathResolution, ResolvedPathRole, RuleId,
    RuntimeMetadata, SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("dispatch-cwd-bounds"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn context(command: &str, registry: ProfileRegistry) -> RunnerContext {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let mut ctx = RunnerContext::new(request(command));
    runner.run(
        SessionView::new(&SessionGraph::new(), &SessionSummary::new()),
        &mut ctx,
    );
    ctx
}

fn decision(command: &str, expected: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, expected, "{command}: {result:?}");
    if expected == Decision::Allow {
        assert!(
            !result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::SelectionError),
            "{result:?}"
        );
    }
}

#[test]
fn unchanged_scalar_proofs_survive_xargs_and_nested_wrappers_without_reexecuting_ast() {
    for command in [
        r#"xargs -n 1 -I '{}' find "$(pwd)" -type f -inum '{}' -print"#,
        r#"env xargs -I '{}' find "$(pwd)" -inum '{}' -print"#,
        r#"xargs -I '{}' env find "$(pwd)" -inum '{}' -print"#,
        r#"xargs -I '{}' env -i find "$(pwd)" -inum '{}' -print"#,
    ] {
        decision(command, Decision::Allow);
        let ctx = context(command, ProfileRegistry::built_in().unwrap());
        let finds: Vec<_> = ctx
            .execution_unit_resolve_records()
            .iter()
            .filter_map(|r| match &r.result {
                ResolveInvocationArtifactResult::Resolved(v)
                    if v.normalized_command_name.as_str() == "find" =>
                {
                    Some((r, v))
                }
                _ => None,
            })
            .collect();
        assert!(!finds.is_empty(), "{command}");
        for (record, resolved) in finds {
            assert!(
                resolved
                    .materialized_projection
                    .invocation
                    .args
                    .iter()
                    .any(|a| a.substitution_shape == Some(StdoutScalarShape::AbsolutePath)),
                "{command}"
            );
            assert!(
                record
                    .parsed_scope
                    .commands
                    .iter()
                    .flat_map(|c| &c.tokens)
                    .all(|a| a.command_substitutions.is_empty()),
                "forward argv, not AST: {command}"
            );
        }
        // The existing audit frontier can retain several possible xargs
        // groups. None is allowed to create another substitution producer.
        assert!(ctx.execution_unit_resolve_records().iter().filter(|r| matches!(&r.result,
            ResolveInvocationArtifactResult::Resolved(v) if v.normalized_command_name.as_str() == "pwd"))
            .all(|r| r.origin_kind != caushell_runner::ExecutionUnitOriginKind::StaticXargs));
    }
}

#[test]
fn scalar_proofs_are_profile_driven_not_pwd_name_exceptions() {
    let mut profiles = ProfileRegistry::built_in().unwrap().profiles().to_vec();
    profiles.push(caushell_profile::load_command_profile_from_str(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_path_producer}\noption_scope: all_arguments\nopaque_on_unresolved: true\nforms:\n  - id: path\n    stdout_scalar: absolute_path\n    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n"
    ).unwrap());
    let ctx = context(
        r#"xargs -I '{}' find "$(arbitrary_path_producer)" -inum '{}' -print"#,
        ProfileRegistry::from_profiles(profiles).unwrap(),
    );
    assert!(ctx.execution_unit_resolve_records().iter().any(|r| matches!(&r.result,
        ResolveInvocationArtifactResult::Resolved(v) if v.normalized_command_name.as_str() == "find"
        && v.materialized_projection.invocation.args.iter().any(|a| a.substitution_shape.is_some()))));
}

#[test]
fn value_uncertainty_shadowing_splitting_and_replaced_words_do_not_borrow_proofs() {
    for command in [
        r#"xargs -I '{}' find "$(pwd)" -inum '{}' -delete"#,
        r#"xargs -I '{}' find $(pwd) -inum '{}' -print"#,
        r#"pwd() { printf -- '-delete'; }; xargs -I '{}' find "$(pwd)" -inum '{}' -print"#,
        r#"xargs -I '{}' find "$(pwd)/{}" -print"#,
        r"xargs env find . -print",
    ] {
        decision(command, Decision::NeedApproval);
    }
}

#[test]
fn local_directory_sets_allow_relative_effects_and_survive_wrappers() {
    for command in [
        r"find . -mindepth 1 -execdir touch marker \;",
        r"find . -execdir touch marker \;",
        r"find /tmp/project -mindepth '1' -execdir touch marker \;",
        r"find ./sub -execdir touch marker \;",
        r"find . -mindepth 1 -execdir rm -- {} \;",
        r"find . -execdir env sh -c 'touch marker' \;",
        r"find . -execdir sh -c 'cd sub && touch marker' \;",
        r"find . -execdir sh -c 'f() { touch marker; }; f' \;",
        r"find /opt/shared -mindepth 1 -execdir sh -c 'cd /tmp/project && touch marker' \;",
        r"find . -execdir tar -cf archive.tar ./input \;",
        r"find . -execdir tar -C sub -cf archive.tar ./input \;",
        r"find . -execdir cp {} {}.bak \;",
        r"find '$UNKNOWN' -type d -execdir rmdir -p {} \;",
        r"find . -execdir sh -c 'echo x > marker' \;",
    ] {
        decision(command, Decision::Allow);
    }
}

#[test]
fn root_events_escapes_unknowns_and_absolute_overrides_keep_approval() {
    for command in [
        r"find /tmp/project -execdir touch marker \;",
        r"find /tmp/project -mindepth 1 -mindepth 0 -execdir touch marker \;",
        r#"find /tmp/project -mindepth 1 -mindepth "$DEPTH" -execdir touch marker \;"#,
        r"find /opt/shared -mindepth 1 -execdir touch marker \;",
        r"find . /opt/shared -mindepth 1 -execdir touch marker \;",
        r"find -L . -mindepth 1 -execdir touch marker \;",
        r#"find "$ROOT" -mindepth 1 -execdir touch marker \;"#,
        r"find . -execdir touch ../marker \;",
        r"find . -execdir sh -c 'cd ..; touch marker' \;",
        r"find . -execdir sh -c 'f() { cd ..; }; f && touch marker' \;",
        r"find /opt/shared -mindepth 1 -execdir sh -c 'f() { touch marker; }; f' \;",
        r"find . -execdir sh -c 'cd /opt/shared && touch marker' \;",
        r"find . -execdir touch /opt/marker \;",
        r"find . -execdir sh -c 'touch /opt/marker' \;",
        r"find . -execdir tar -C .. -xf archive.tar \;",
        r"find . -execdir sh -c 'echo x > marker' > /opt/outer \;",
        r"find . -execdir sh -c 'echo x > /dev/fd/3' 3> /opt/outer \;",
        // Cross-dispatch nonstandard FD identity remains unproven. A bounded
        // directory must not fabricate an inherited descriptor backing path.
        r"find . -execdir sh -c 'echo x > /dev/fd/3' 3> ./outer \;",
    ] {
        decision(command, Decision::NeedApproval);
    }
}

#[test]
fn tool_selected_cwd_does_not_materialize_parent_relative_static_input_as_child_code() {
    for command in [
        r"printf 'touch marker' > input; find . -execdir sh -c 'sh < input' \;",
        r"printf 'touch marker' > input; find . -execdir env xargs -a input sh -c \;",
    ] {
        // A relative child lookup is not a proven lookup of the parent's file.
        // No filesystem probing or fabricated source contents are permitted.
        decision(command, Decision::NeedApproval);
    }
    // An outer redirect is opened before find selects any child directory.
    // Its proven stream contents must retain that original shell identity.
    decision(
        r"printf 'touch marker' > input; find . -execdir sh < input \;",
        Decision::Allow,
    );
}

#[test]
fn derived_functions_keep_local_parameters_and_do_not_hide_unresolved_launches() {
    decision(
        r#"find . -execdir sh -c 'f() { touch "$1"; }; f marker' \;"#,
        Decision::Allow,
    );
    decision(
        r#"find . -execdir sh -c 'f() { true; }; f "$UNKNOWN"' \;"#,
        Decision::Allow,
    );
    decision(
        r#"find . -execdir sh -c 'f() { echo "$@"; }; f ${VALUES[@]}' \;"#,
        Decision::Allow,
    );
    decision(
        r"find . -execdir sh -c 'touch() { true; }; touch /opt/shared/out' \;",
        Decision::Allow,
    );
    for command in [
        r#"find . -execdir sh -c 'f() { touch "$1"; }; f /opt/shared/out' \;"#,
        r#"find . -execdir sh -c 'f() { touch "$@"; }; f marker /opt/shared/out' \;"#,
        r#"find . -execdir sh -c 'f() { touch "$1"; }; f /opt/shared/out' _ /tmp/project/marker \;"#,
        r#"find . -execdir sh -c 'f() { touch "$1"; }; f "$UNKNOWN"' \;"#,
        r#"find . -execdir sh -c 'f() { shift; touch "$2"; }; f $UNKNOWN marker local' \;"#,
        r#"find . -execdir sh -c 'f() { target=$2; }; f $UNKNOWN marker; touch "$target"' \;"#,
        r#"find . -execdir sh -c 'f() { target=$VALUE; }; VALUE=/opt/shared/out f; touch "$target"' \;"#,
        r#"find . -execdir sh -c 'f() { true; }; f "$(touch /opt/shared/out)"' \;"#,
        r"find . -execdir bash -c 'f() { true; }; f <(touch /opt/shared/out)' \;",
        r"find . -execdir sh -c 'f() { f; }; f' \;",
        r"find . -execdir sh -c 'f() { g; }; g() { cd ..; }; f && touch marker' \;",
        r#"find . -execdir sh -c 'f() { eval "touch /opt/shared/out"; }; f' \;"#,
        r"find . -execdir sh -c 'f() { v=$(touch /opt/shared/out); }; f' \;",
    ] {
        decision(command, Decision::NeedApproval);
    }
    let ctx = context(
        r"find . -execdir sh -c 'f() { touch marker; }; f' \;",
        ProfileRegistry::built_in().unwrap(),
    );
    assert!(
        ctx.execution_unit_resolve_records()
            .iter()
            .any(|record| record.origin_kind
                == caushell_runner::ExecutionUnitOriginKind::FunctionExpansion
                && matches!(&record.result, ResolveInvocationArtifactResult::Resolved(v)
            if v.normalized_command_name.as_str() == "touch")),
        "a passing function test must contain its real effect, not just an ignored callee"
    );
}

#[test]
fn scope_is_anchored_after_cd_not_at_request_entry_and_does_not_change_caller() {
    decision(
        r"cd /opt/shared; find . -execdir touch marker \;",
        Decision::NeedApproval,
    );
    decision(
        r"cd /opt/shared; find /tmp/project -mindepth 1 -execdir touch marker \;",
        Decision::Allow,
    );
    decision(
        r"cd /opt/shared; find /tmp/project -mindepth 1 -execdir echo {} \; > outer",
        Decision::NeedApproval,
    );
    decision(
        r"find /opt/shared -mindepth 1 -execdir echo {} \; > outer",
        Decision::Allow,
    );
    let ctx = context(
        r"find /opt/shared -mindepth 1 -execdir echo {} \; ; touch marker",
        ProfileRegistry::built_in().unwrap(),
    );
    assert_eq!(ctx.known_request_exit_cwd(), Some("/tmp/project"));
}

#[test]
fn graph_contains_bounds_not_invented_filenames_and_cwd_is_not_exact() {
    let ctx = context(
        r"find . -mindepth 1 -execdir touch marker \;",
        ProfileRegistry::built_in().unwrap(),
    );
    let child = ctx.execution_unit_resolve_records().iter().find(|r| matches!(&r.result,
        ResolveInvocationArtifactResult::Resolved(v) if v.normalized_command_name.as_str() == "touch")).unwrap();
    let cwd = ctx.execution_cwd_for_node(&child.source_node_id).unwrap();
    assert!(matches!(cwd, EffectiveCwd::Bounded { unknown: false, .. }));
    assert_eq!(cwd.as_known(), None);
    assert_eq!(cwd.bounded_roots(), &["/tmp/project".to_string()]);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let writes: Vec<_> = staged
        .graph()
        .nodes()
        .filter_map(|n| match &n.kind {
            NodeKind::PathFact {
                role: ResolvedPathRole::Write,
                resolution,
                ..
            } => Some(resolution),
            _ => None,
        })
        .collect();
    assert!(!writes.is_empty());
    assert!(
        writes.iter().all(
            |p| matches!(p, PathResolution::BoundedPathSet { roots, may_escape: false }
        if roots == &["/tmp/project".to_string()])
        ),
        "{writes:?}"
    );
}

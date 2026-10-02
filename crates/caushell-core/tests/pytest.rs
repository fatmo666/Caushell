//! Static checks only. None of the shell commands or Python tests is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_graph::{SessionGraph, SessionRead};
use caushell_passes::{
    CatastrophicDeleteGuardPass, ComputeEffectiveCwdPass, DecisionAssemblyPass,
    ExtractPathFactsPass, ExtractPipelineFlowPass, OutsideWorkspaceMutationGuardPass,
    ParseCommandPass, ProjectTopLevelCommandsPass, ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathResolution, ResolvedPathPurpose,
    ResolvedPathRole, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("pytest-profile-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn inspect(
    command: &str,
    expected: Decision,
) -> Vec<(
    ResolvedPathRole,
    Option<ResolvedPathPurpose>,
    PathResolution,
)> {
    inspect_request(request(command), expected)
}

fn inspect_request(
    request: CheckRequest,
    expected: Decision,
) -> Vec<(
    ResolvedPathRole,
    Option<ResolvedPathPurpose>,
    PathResolution,
)> {
    let mut core = ShellQueryCore::new();
    let response = core.check(request.clone());
    assert_eq!(
        response.decision, expected,
        "{}: {:?}",
        request.command, response.decision_trace.findings
    );
    if expected != Decision::Allow {
        // Core correctly commits only allowed requests. Inspect the genuine
        // staged path facts through the same passes, without forcing approval
        // or changing the product's decision/commit policy.
        let mut runner = PassRunner::new();
        runner.register_request_transform_pass(ParseCommandPass);
        runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
        runner.register_session_transform_pass(ResolveInvocationPass::new(
            ProfileRegistry::built_in().unwrap(),
        ));
        runner.register_session_transform_pass(ComputeEffectiveCwdPass);
        runner.register_session_transform_pass(ExtractPipelineFlowPass);
        runner.register_session_transform_pass(ExtractPathFactsPass);
        runner.register_session_analysis_pass(OutsideWorkspaceMutationGuardPass);
        runner.register_session_analysis_pass(CatastrophicDeleteGuardPass);
        runner.register_final_decision_pass(DecisionAssemblyPass);
        let graph = SessionGraph::new();
        let summary = SessionSummary::new();
        let mut ctx = RunnerContext::new(request);
        runner.run(SessionView::new(&graph, &summary), &mut ctx);
        assert_eq!(ctx.final_decision, Some(expected));
        let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
        return ctx.pending_mutations().iter().filter_map(|mutation| match mutation {
            PendingMutation::AddPathFact { node_id, role, purpose, resolution, .. } => {
                assert!(matches!(&staged.graph().get_node(node_id).unwrap().kind, NodeKind::PathFact { resolution: actual, .. } if actual == resolution));
                Some((*role, *purpose, resolution.clone()))
            }
            _ => None,
        }).collect();
    }
    core.session_graph(&request.session_id)
        .unwrap()
        .nodes()
        .filter_map(|node| match &node.kind {
            NodeKind::PathFact {
                role,
                purpose,
                resolution,
                ..
            } => Some((*role, *purpose, resolution.clone())),
            _ => None,
        })
        .collect()
}

fn writes(command: &str, expected: Decision) -> Vec<PathResolution> {
    inspect(command, expected)
        .into_iter()
        .filter_map(|(role, _, resolution)| (role == ResolvedPathRole::Write).then_some(resolution))
        .collect()
}

#[test]
fn default_unknown_cache_allows_but_is_present_in_graph() {
    for command in [
        "pytest",
        "pytest tests/",
        "pytest --rootdir=/tmp/project tests/",
        "pytest -o console_output_style=classic tests/",
    ] {
        let facts = inspect(command, Decision::Allow);
        let caches: Vec<_> = facts
            .iter()
            .filter(|(role, purpose, _)| {
                *role == ResolvedPathRole::Write
                    && *purpose == Some(ResolvedPathPurpose::IncidentalCache)
            })
            .collect();
        assert_eq!(caches.len(), 1, "{command}: {facts:?}");
        assert!(caches[0].2.concrete_path().is_none());
    }
}

#[test]
fn selector_path_is_stripped_but_not_treated_as_a_write() {
    let facts = inspect("pytest tests/test_api.py::test_login", Decision::Allow);
    assert!(facts.iter().any(
        |(role, purpose, resolution)| *role == ResolvedPathRole::Read
            && *purpose == Some(ResolvedPathPurpose::InProcessCode)
            && resolution.concrete_path() == Some("/tmp/project/tests/test_api.py")
    ));
}

#[test]
fn explicit_cache_inside_workspace_is_concrete() {
    assert_eq!(
        writes(
            "pytest -o cache_dir=/tmp/project/cache tests/",
            Decision::Allow
        )[0]
        .concrete_path(),
        Some("/tmp/project/cache")
    );
}

#[test]
fn explicit_outside_cache_requires_approval() {
    assert_eq!(
        writes(
            "pytest -o cache_dir=/etc/pytest-cache tests/",
            Decision::NeedApproval
        )[0]
        .concrete_path(),
        Some("/etc/pytest-cache")
    );
}

#[test]
fn explicit_unknown_cache_is_not_exempt() {
    for command in [
        "pytest -o \"cache_dir=$UNKNOWN\" tests/",
        "pytest -o cache_dir=cache tests/",
        "pytest -o cache_dir= tests/",
        "pytest -o cache_dir=$UNKNOWN tests/",
    ] {
        let targets = writes(command, Decision::NeedApproval);
        assert!(!targets.is_empty(), "{command}");
        assert!(
            targets
                .iter()
                .all(|target| target.concrete_path().is_none())
        );
    }
}

#[test]
fn relative_cache_uses_explicit_rootdir_not_cwd() {
    for (command, expected, target) in [
        (
            "pytest --rootdir=/tmp/project/sub -o cache_dir=cache tests/",
            Decision::Allow,
            "/tmp/project/sub/cache",
        ),
        (
            "pytest --rootdir=/opt/app -o cache_dir=cache tests/",
            Decision::NeedApproval,
            "/opt/app/cache",
        ),
        (
            "pytest --rootdir=sub -o cache_dir=../cache tests/",
            Decision::Allow,
            "/tmp/project/cache",
        ),
        (
            "pytest --rootdir=/tmp/project -o cache_dir=../../etc/cache tests/",
            Decision::NeedApproval,
            "/etc/cache",
        ),
    ] {
        assert_eq!(
            writes(command, expected)[0].concrete_path(),
            Some(target),
            "{command}"
        );
    }
}

#[test]
fn explicit_config_parent_can_anchor_a_relative_cache() {
    assert_eq!(
        writes(
            "pytest -c config/pytest.ini -o cache_dir=cache tests/",
            Decision::Allow
        )[0]
        .concrete_path(),
        Some("/tmp/project/config/cache")
    );
}

#[test]
fn rootdir_wins_over_config_parent_without_probing_either() {
    assert_eq!(
        writes(
            "pytest -c /etc/pytest.ini --rootdir=/tmp/project -o cache_dir=cache tests/",
            Decision::Allow
        )[0]
        .concrete_path(),
        Some("/tmp/project/cache")
    );
}

#[test]
fn unknown_high_priority_root_does_not_fall_back_to_config_parent() {
    let targets = writes(
        "pytest -c config/pytest.ini --rootdir=\"$ROOT\" -o cache_dir=cache tests/",
        Decision::NeedApproval,
    );
    assert!(targets[0].concrete_path().is_none());
}

#[test]
fn absolute_cache_is_independent_of_unknown_rootdir() {
    assert_eq!(
        writes(
            "pytest --rootdir=\"$ROOT\" -o cache_dir=/tmp/project/cache tests/",
            Decision::Allow
        )[0]
        .concrete_path(),
        Some("/tmp/project/cache")
    );
}

#[test]
fn last_matching_override_wins_without_losing_other_keys() {
    for (command, expected, target) in [
        (
            "pytest -o cache_dir=/etc/old -o cache_dir=/tmp/project/cache -o console_output_style=classic tests/",
            Decision::Allow,
            "/tmp/project/cache",
        ),
        (
            "pytest -o cache_dir=/tmp/project/cache -o cache_dir=/etc/new tests/",
            Decision::NeedApproval,
            "/etc/new",
        ),
        (
            "pytest --rootdir=/etc --rootdir=/tmp/project -o cache_dir=cache tests/",
            Decision::Allow,
            "/tmp/project/cache",
        ),
    ] {
        assert_eq!(
            writes(command, expected)[0].concrete_path(),
            Some(target),
            "{command}"
        );
    }
}

#[test]
fn later_unknown_override_remains_unknown() {
    let targets = writes(
        "pytest -o cache_dir=/tmp/project/cache -o \"cache_dir=$UNKNOWN\" tests/",
        Decision::NeedApproval,
    );
    assert!(targets[0].concrete_path().is_none());
}

#[test]
fn tool_environment_expansion_is_not_mistaken_for_literal_path_data() {
    for command in [
        "pytest -o 'cache_dir=/tmp/project/$CACHE' tests/",
        "pytest --junitxml='/tmp/project/$REPORT' tests/",
        "pytest --rootdir='/tmp/project/$ROOT' -o cache_dir=cache tests/",
    ] {
        assert!(
            writes(command, Decision::NeedApproval)
                .iter()
                .any(|target| target.concrete_path().is_none())
        );
    }
}

#[test]
fn known_shell_variables_materialize_without_reading_host_environment() {
    assert!(
        writes(
            "OVERRIDE=cache_dir=/tmp/project/cache; pytest -o \"$OVERRIDE\" tests/",
            Decision::Allow
        )
        .iter()
        .any(|target| target.concrete_path() == Some("/tmp/project/cache"))
    );
}

#[test]
fn home_expansion_uses_supplied_home_and_unknown_users_are_not_guessed() {
    assert_eq!(
        writes(
            "pytest -o 'cache_dir=~/cache' tests/",
            Decision::NeedApproval
        )[0]
        .concrete_path(),
        Some("/home/alice/cache")
    );
    assert!(
        writes(
            "pytest -o 'cache_dir=~unknown/cache' tests/",
            Decision::NeedApproval
        )[0]
        .concrete_path()
        .is_none()
    );
}

#[test]
fn junit_reports_and_aliases_do_not_share_the_cache_exemption() {
    for (command, expected, target) in [
        (
            "pytest --junitxml=report.xml tests/",
            Decision::Allow,
            "/tmp/project/report.xml",
        ),
        (
            "pytest --rootdir=/etc --junit-xml=report.xml tests/",
            Decision::Allow,
            "/tmp/project/report.xml",
        ),
        (
            "pytest --junit-xml=/etc/report.xml tests/",
            Decision::NeedApproval,
            "/etc/report.xml",
        ),
    ] {
        assert!(
            writes(command, expected)
                .iter()
                .any(|path| path.concrete_path() == Some(target))
        );
    }
    writes(
        "pytest --junitxml=\"$OUTPUT\" tests/",
        Decision::NeedApproval,
    );
}

#[test]
fn log_cli_and_override_share_one_view_with_cli_priority() {
    for (command, expected, target) in [
        (
            "pytest --rootdir=/etc -o log_file=logs/test.log tests/",
            Decision::Allow,
            "/tmp/project/logs/test.log",
        ),
        (
            "pytest -o log_file=/etc/test.log tests/",
            Decision::NeedApproval,
            "/etc/test.log",
        ),
        (
            "pytest --log-file=/tmp/project/log -o log_file=/etc/ignored tests/",
            Decision::Allow,
            "/tmp/project/log",
        ),
        (
            "pytest --log-file=/etc/log -o log_file=/tmp/project/ignored tests/",
            Decision::NeedApproval,
            "/etc/log",
        ),
    ] {
        assert!(
            writes(command, expected)
                .iter()
                .any(|path| path.concrete_path() == Some(target)),
            "{command}"
        );
    }
    assert!(
        writes("pytest --log-file=log tests/", Decision::Allow)
            .iter()
            .any(|path| path.concrete_path() == Some("/tmp/project/log"))
    );
}

#[test]
fn multiple_override_keys_cannot_hide_an_outside_log_write() {
    let targets = writes(
        "pytest -o cache_dir=/tmp/project/cache -o log_file=/etc/log tests/",
        Decision::NeedApproval,
    );
    assert!(
        targets
            .iter()
            .any(|path| path.concrete_path() == Some("/tmp/project/cache"))
    );
    assert!(
        targets
            .iter()
            .any(|path| path.concrete_path() == Some("/etc/log"))
    );
}

#[test]
fn basetemp_cleanup_is_independent_of_incidental_cache_writes() {
    for (command, expected) in [
        ("pytest --basetemp=scratch tests/", Decision::Allow),
        ("pytest --basetemp=/opt/old tests/", Decision::NeedApproval),
        ("pytest --basetemp=\"$TMP\" tests/", Decision::NeedApproval),
    ] {
        assert!(
            inspect(command, expected)
                .iter()
                .any(|(role, _, _)| *role == ResolvedPathRole::Target)
        );
    }
}

#[test]
fn cache_clearing_unknown_or_outside_target_is_not_exempt() {
    inspect("pytest --cache-clear tests/", Decision::NeedApproval);
    inspect(
        "pytest --cache-clear -o cache_dir=/etc/cache tests/",
        Decision::NeedApproval,
    );
    inspect(
        "pytest --cache-clear -o cache_dir=/tmp/project/cache tests/",
        Decision::Allow,
    );
}

#[test]
fn disabled_cache_has_no_write_fact_even_with_an_explicit_cache_override() {
    for command in [
        "pytest -p no:cacheprovider tests/",
        "pytest -p no:cacheprovider --cache-clear -o cache_dir=/etc/cache tests/",
    ] {
        assert!(writes(command, Decision::Allow).is_empty(), "{command}");
    }
}

#[test]
fn cache_show_is_a_read_not_a_write() {
    assert!(
        writes(
            "pytest --cache-show -o cache_dir=/etc/cache",
            Decision::Allow
        )
        .is_empty()
    );
}

#[test]
fn help_and_version_do_not_invent_cache_writes() {
    for command in ["pytest -h", "pytest -V", "py.test --version"] {
        assert!(writes(command, Decision::Allow).is_empty());
    }
}

#[test]
fn debug_default_is_a_real_cwd_output_not_an_unknown_cache() {
    assert!(
        writes("pytest --debug tests/", Decision::Allow)
            .iter()
            .any(|path| path.concrete_path() == Some("/tmp/project/pytestdebug.log"))
    );
    writes("pytest --debug=/etc/debug tests/", Decision::NeedApproval);
}

#[test]
fn shell_redirections_and_other_commands_remain_independently_checked() {
    for command in [
        "pytest tests/ > /etc/report",
        "pytest tests/; rm -f /etc/old",
        "pytest tests/ | tee /etc/report",
    ] {
        inspect(command, Decision::NeedApproval);
    }
    inspect("pytest tests/; rm -rf /", Decision::Deny);
}

#[test]
fn unknown_cwd_does_not_contaminate_an_absolute_output() {
    writes(
        "cd \"$UNKNOWN\"; pytest -o cache_dir=/tmp/project/cache",
        Decision::Allow,
    );
    writes(
        "cd \"$UNKNOWN\"; pytest --junitxml=report.xml",
        Decision::NeedApproval,
    );
}

#[test]
fn missing_workspace_does_not_grant_an_explicit_output_the_default_exemption() {
    let mut req = request("pytest");
    req.workspace_root = None;
    inspect_request(req, Decision::Allow);
    let mut req = request("pytest -o cache_dir=/tmp/project/cache");
    req.workspace_root = None;
    inspect_request(req, Decision::NeedApproval);
}

#[test]
fn disabled_cache_and_cache_display_do_not_hide_explicit_log_outputs() {
    for command in [
        "pytest -p no:cacheprovider --log-file=/etc/log tests/",
        "pytest --cache-show -o log_file=/etc/log",
        "pytest --pyargs pkg.tests --log-file=/etc/log",
        "pytest --pyargs -p no:cacheprovider pkg.tests -o log_file=/etc/log",
    ] {
        assert!(
            writes(command, Decision::NeedApproval)
                .iter()
                .any(|path| path.concrete_path() == Some("/etc/log")),
            "{command}"
        );
    }
}

#[test]
fn separate_option_operands_and_last_cli_outputs_are_checked() {
    for (command, expected, target) in [
        (
            "pytest --log-file /tmp/project/old --log-file /etc/log tests/",
            Decision::NeedApproval,
            "/etc/log",
        ),
        (
            "pytest --junitxml /etc/old --junit-xml /tmp/project/report.xml tests/",
            Decision::Allow,
            "/tmp/project/report.xml",
        ),
        (
            "pytest --basetemp /etc/base tests/",
            Decision::NeedApproval,
            "/etc/base",
        ),
    ] {
        assert!(
            writes(command, expected)
                .iter()
                .any(|path| path.concrete_path() == Some(target)),
            "{command}"
        );
    }
}

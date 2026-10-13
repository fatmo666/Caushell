//! Commands are static proposals only. No ln/cp/cwd mutation is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathResolution, ResolvedPathRole, RuntimeMetadata,
    SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str, home: Option<&str>) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("bound-path-word-origin"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: home.map(str::to_string),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-path-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check_path(command: &str, home: Option<&str>, expected: &str, decision: Decision) {
    let mut core = ShellQueryCore::new();
    let result = core.check(request(command, home));
    assert_eq!(result.decision, decision, "{command}: {result:#?}");
    // Inspect staged facts, including proposals that require approval and
    // therefore are intentionally not committed to the session graph.
    let nodes = path_facts(command, home);
    assert!(
        nodes
            .iter()
            .any(|node| matches!(&node.kind, NodeKind::PathFact {
        role: ResolvedPathRole::Write, resolution: PathResolution::Concrete { path }, ..
    } if path == expected)),
        "{command}: missing write path {expected}; {nodes:#?}"
    );
}

fn path_facts(command: &str, home: Option<&str>) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command, home));
    runner.run(SessionView::new(&base, &summary), &mut ctx);
    StagedSession::new(&base, ctx.request(), &summary, ctx.pending_mutations())
        .graph()
        .nodes()
        .cloned()
        .collect()
}

#[test]
fn attached_option_values_stay_relative_to_cwd_without_tilde_expansion() {
    for command in [
        "ln --force --target-directory=~/staging ~/mirror/*",
        "ln --target-directory=~/staging source",
        "cp --target-directory=~/staging input",
        "cp -t~/staging input",
        "cp -vt~/staging input",
    ] {
        check_path(
            command,
            Some("/home/benchmark-user"),
            "/bench/workspace/~/staging",
            Decision::Allow,
        );
    }
}

#[test]
fn standalone_option_operands_still_expand_home() {
    for command in [
        "cp --target-directory ~/staging input",
        "cp -t ~/staging input",
        "ln --target-directory ~/staging source",
    ] {
        check_path(
            command,
            Some("/home/benchmark-user"),
            "/home/benchmark-user/staging",
            Decision::NeedApproval,
        );
    }
}

#[test]
fn quoted_escaped_and_materialized_tildes_are_literal_path_bytes() {
    for command in [
        "cp -t '~/staging' input",
        r"cp -t \~/staging input",
        "cp --target-directory='~/staging' input",
        "cp --target-directory=\"~/staging\" input",
        "d='~/staging'; cp --target-directory=\"$d\" input",
        "d='~/staging'; cp --target-directory=$d input",
    ] {
        check_path(
            command,
            Some("/home/benchmark-user"),
            "/bench/workspace/~/staging",
            Decision::Allow,
        );
    }
}

#[test]
fn variable_expansion_is_not_disabled_for_attached_option_values() {
    for command in [
        "d=/opt/shared; cp --target-directory=\"$d\" input",
        "cp --target-directory=\"$HOME/staging\" input",
        "cp --target-directory=$HOME/staging input",
    ] {
        let path = if command.starts_with("d=") {
            "/opt/shared"
        } else {
            "/home/benchmark-user/staging"
        };
        check_path(
            command,
            Some("/home/benchmark-user"),
            path,
            Decision::NeedApproval,
        );
    }
    let result = ShellQueryCore::new().check(request(
        "cp --target-directory=\"$unknown\" input",
        Some("/home/benchmark-user"),
    ));
    assert_eq!(result.decision, Decision::NeedApproval);
}

#[test]
fn relative_tilde_paths_follow_known_and_unknown_effective_cwd() {
    check_path(
        "cd sub; cp -t~/staging input",
        Some("/home/benchmark-user"),
        "/bench/workspace/sub/~/staging",
        Decision::Allow,
    );
    check_path(
        "cd /opt/shared; cp -t~/staging input",
        Some("/home/benchmark-user"),
        "/opt/shared/~/staging",
        Decision::NeedApproval,
    );
    let result = ShellQueryCore::new().check(request(
        "cd \"$unknown\"; cp -t~/staging input",
        Some("/home/benchmark-user"),
    ));
    assert_eq!(result.decision, Decision::NeedApproval);
    assert!(
        result
            .reasons
            .iter()
            .any(|reason| reason.contains("unknown effective working directory")),
        "{result:#?}"
    );
}

#[test]
fn tool_local_cwd_uses_the_same_bound_word_origin_rules() {
    check_path(
        "env -C~/staging touch file",
        Some("/home/benchmark-user"),
        "/bench/workspace/~/staging/file",
        Decision::Allow,
    );
    check_path(
        "env -C ~/staging touch file",
        Some("/home/benchmark-user"),
        "/home/benchmark-user/staging/file",
        Decision::NeedApproval,
    );
    check_path(
        "env -C~/sub cp -t~/out input",
        Some("/home/benchmark-user"),
        "/bench/workspace/~/sub/~/out",
        Decision::Allow,
    );
}

#[test]
fn attached_literal_tilde_does_not_require_home_but_standalone_tilde_does() {
    check_path(
        "cp -t~/staging input",
        None,
        "/bench/workspace/~/staging",
        Decision::Allow,
    );
    assert_eq!(
        ShellQueryCore::new()
            .check(request("cp -t ~/staging input", None))
            .decision,
        Decision::NeedApproval
    );
}

#[test]
fn catastrophic_target_check_does_not_expand_literal_or_variable_tildes() {
    for command in [
        "rm -rf '~'",
        r"rm -rf \~",
        "p='~'; rm -rf \"$p\"",
        "cp --target-directory=~ input",
    ] {
        let result = ShellQueryCore::new().check(request(command, Some("/usr")));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
    let result = ShellQueryCore::new().check(request("rm -rf ~", Some("/usr")));
    assert_eq!(result.decision, Decision::Deny, "{result:#?}");
}

#[test]
fn prefix_binding_distinguishes_options_from_assignment_shaped_argv() {
    for command in ["ss -D~/dump", "ss '-D~/dump'", "ss \"-D~/dump\""] {
        check_path(
            command,
            Some("/home/benchmark-user"),
            "/bench/workspace/~/dump",
            Decision::Allow,
        );
    }
    check_path(
        "dd if=input of=~/output",
        Some("/home/benchmark-user"),
        "/home/benchmark-user/output",
        Decision::NeedApproval,
    );
    assert_eq!(
        ShellQueryCore::new()
            .check(request("ss -D~/$unknown", Some("/home/benchmark-user")))
            .decision,
        Decision::NeedApproval
    );
}

#[test]
fn derived_filename_prefixes_keep_the_same_origin_semantics() {
    for command in [
        "csplit --prefix=~/pieces/part input '/x/'",
        "csplit -f~/pieces/part input '/x/'",
    ] {
        let mut core = ShellQueryCore::new();
        let result = core.check(request(command, Some("/home/benchmark-user")));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
        assert!(core.session_graph(&SessionId::new("bound-path-word-origin")).unwrap().nodes().any(|n| matches!(&n.kind,
            NodeKind::PathFact { resolution: PathResolution::FileNamePrefix { directory, prefix }, .. }
                if directory == "/bench/workspace/~/pieces" && prefix == "part")), "{command}");
    }
}

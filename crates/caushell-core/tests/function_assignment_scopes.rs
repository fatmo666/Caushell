//! Static function-scope regressions; no shell action is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("function-assignment-scope"),
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

#[test]
fn assignments_are_executable_scopes_without_an_ordinary_command_seed() {
    for (command, name) in [
        ("f() { x=$(touch /opt/shared/marker); }; f", "touch"),
        ("f() { local x=$(touch /opt/shared/marker); }; f", "touch"),
        ("f() { export x=$(touch /opt/shared/marker); }; f", "touch"),
        ("f() { x=$(rm -f /opt/shared/marker); }; f", "rm"),
        (
            "f() { target=$1; x=$(touch \"$target\"); }; f /opt/shared/marker",
            "touch",
        ),
        ("f() { x=$(touch marker); }; cd /opt/shared; f", "touch"),
        ("f() { x=$(touch marker); }; cd /opt/shared && f", "touch"),
        (
            "f() { x=$(inner=$(touch /opt/shared/marker)); }; f",
            "touch",
        ),
        (
            "f() { g() { x=$(touch /opt/shared/marker); }; g; }; f",
            "touch",
        ),
        (
            "bash -c 'f() { x=$(touch /opt/shared/marker); }; f'",
            "touch",
        ),
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == name),
            "missing {name}: {command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.source_pass == "outside_workspace_mutation_guard"),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn harmless_and_uncalled_functions_do_not_gain_fictitious_effects() {
    for command in [
        "f() { x=1; }; f",
        "f() { x=$(touch marker); }; f",
        "f() { x=$(touch marker); }; cd /opt/shared || f",
        "f() { x=$(touch marker); }; (cd /opt/shared); f",
        "f() { x=$(date); }; f",
        "f() { x=$(touch /opt/shared/marker); }; echo unused",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        if command.ends_with("echo unused") {
            assert!(
                !response
                    .decision_trace
                    .execution_semantics
                    .iter()
                    .any(|s| s.normalized_command_name == "touch")
            );
        }
    }
}

#[test]
fn function_call_arguments_execute_even_when_the_body_never_uses_them() {
    for command in [
        "f() { x=1; }; f $(touch /opt/shared/marker)",
        "f() { x=1; }; cd /opt/shared; f $(touch marker)",
        "f() { x=1; }; cd /opt/shared; f <(touch marker)",
        "f() { x=1; }; f <(touch /opt/shared/marker)",
        "f() { echo done; }; f $(touch /opt/shared/marker)",
        "f() { x=$(date); }; f $(touch /opt/shared/marker)",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert_eq!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .filter(|s| s.normalized_command_name == "touch")
                .count(),
            1,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn assignment_only_function_expansion_cannot_bypass_the_depth_budget() {
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 1;
    let response = ShellQueryCore::with_policy(policy)
        .check(request("f() { x=$(touch /opt/shared/marker); }; f"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::ExecutionExpansionLimit),
        "{response:#?}"
    );
}

#[test]
fn observed_functions_and_alias_expanded_calls_keep_their_effects() {
    let mut observed = request("f");
    observed
        .shell_state_before
        .functions
        .push(ShellFunctionSnapshot::new(
            "f",
            "x=$(touch /opt/shared/marker)",
        ));
    let response = ShellQueryCore::new().check(observed);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "touch")
    );

    let mut aliased = request("invoke");
    aliased
        .shell_state_before
        .functions
        .push(ShellFunctionSnapshot::new("f", "x=1"));
    aliased
        .shell_state_before
        .aliases
        .push(ShellAliasSnapshot::new(
            "invoke",
            "f $(touch /opt/shared/marker)",
        ));
    let response = ShellQueryCore::new().check(aliased);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert_eq!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .filter(|s| s.normalized_command_name == "touch")
            .count(),
        1,
        "{response:#?}"
    );
}

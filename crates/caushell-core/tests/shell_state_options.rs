//! Static checks: no action under test is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::SessionGraph;
use caushell_passes::*;
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, PendingMutation, RunnerContext, SessionView};
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/tmp/project");
    shell.observability.variables = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("state-options-test"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: shell,
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
fn inspect(command: &str) -> RunnerContext {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ExtractAliasBindingsPass);
    runner.register_session_transform_pass(ExtractFunctionBindingsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ExtractVariableBindingsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(1, command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    ctx
}
fn binding(command: &str, name: &str, value: &str, exported: bool) {
    let ctx = inspect(command);
    let b = ctx
        .pending_mutations()
        .iter()
        .filter_map(|m| match m {
            PendingMutation::UpsertVariableBinding { binding } if binding.name == name => {
                Some(binding)
            }
            _ => None,
        })
        .last()
        .unwrap_or_else(|| panic!("{command}: {:?}", ctx.pending_mutations()));
    assert_eq!(
        b.value,
        SessionVariableValue::exact_scalar(value),
        "{command}"
    );
    assert_eq!(b.exported, exported, "{command}");
}
fn decision(command: &str, expected: Decision) {
    let r = ShellQueryCore::new().check(request(1, command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
}

#[test]
fn unexport_preserves_scalar_and_changes_only_child_environment() {
    for command in [
        "export target=/opt/shared/file; export -n target",
        "export target=/opt/shared/file; export -np target",
        "export target=/opt/shared/file; export '-n' -- target",
    ] {
        binding(command, "target", "/opt/shared/file", false);
        decision(
            &format!("{command}; rm -f \"$target\""),
            Decision::NeedApproval,
        );
    }
    binding(
        "export target=old; export -n target=cache/file",
        "target",
        "cache/file",
        false,
    );
}
#[test]
fn export_print_is_query_only_without_operands() {
    binding("target=LAB; export -p", "target", "LAB", false);
    binding("target=LAB; export -p target", "target", "LAB", true);
    binding("export -p target=LAB", "target", "LAB", true);
    binding("target=LAB; export -- target", "target", "LAB", true);
}
#[test]
fn ordered_replay_preserves_value_and_export_attribute() {
    for (command, value, exported) in [
        ("target=old; export target; target=LAB", "LAB", true),
        ("export target=old; target=LAB", "LAB", true),
        (
            "export target=old; unset -v target; target=LAB",
            "LAB",
            false,
        ),
        ("target=old; unset target; export target=LAB", "LAB", true),
        ("target=LAB; export -n target; export target", "LAB", true),
        ("target=LAB; export -n target; copy=$target", "LAB", false),
    ] {
        binding(
            command,
            if command.contains("copy=") {
                "copy"
            } else {
                "target"
            },
            value,
            exported,
        );
    }
}
#[test]
fn declaration_operands_expand_before_any_of_their_assignments() {
    for mode in ["", "-n"] {
        let c =
            format!("target=/opt/shared/file; export {mode} target=cache/file copy=\"$target\"");
        binding(&c, "copy", "/opt/shared/file", mode.is_empty());
        decision(&format!("{c}; rm -f \"$copy\""), Decision::NeedApproval);
    }
    binding(
        "target=/opt/shared/file; target=cache/file copy=\"$target\"",
        "copy",
        "cache/file",
        false,
    );
}

#[test]
fn unset_variable_does_not_remove_same_named_function() {
    for option in ["-v", "-v --", "--"] {
        let command = format!("target=LAB; target() {{ printf LAB; }}; unset {option} target");
        let ctx = inspect(&command);
        assert!(
            ctx.pending_mutations().iter().any(
                |m| matches!(m, PendingMutation::UnsetVariable { name, .. } if name == "target")
            )
        );
        assert!(
            !ctx.pending_mutations()
                .iter()
                .any(|m| matches!(m, PendingMutation::UnsetFunction { .. }))
        );
        decision(&format!("{command}; target"), Decision::Allow);
    }
}
#[test]
fn unset_function_does_not_remove_same_named_variable() {
    for option in ["-f", "-fn", "-f -n", "-f --"] {
        binding(
            &format!("target=LAB; target() {{ printf LAB; }}; unset {option} target"),
            "target",
            "LAB",
            false,
        );
    }
}
#[test]
fn invalid_option_combinations_are_noops() {
    for option in ["-vf", "-v -f", "-z"] {
        let command = format!("target=LAB; target() {{ printf LAB; }}; unset {option} target");
        binding(&command, "target", "LAB", false);
        assert!(
            !inspect(&command)
                .pending_mutations()
                .iter()
                .any(|m| matches!(m, PendingMutation::UnsetFunction { .. }))
        );
    }
    binding("target=LAB; export -z target", "target", "LAB", false);
}
#[test]
fn operands_after_boundary_do_not_become_options() {
    binding("target=LAB; export target -n", "target", "LAB", true);
    binding("target=LAB; export -- -n target", "target", "LAB", true);
    let ctx = inspect("target=LAB; target() { printf LAB; }; unset target -f");
    assert!(
        !ctx.pending_mutations()
            .iter()
            .any(|m| matches!(m, PendingMutation::UnsetFunction { .. }))
    );
    assert!(
        ctx.pending_mutations()
            .iter()
            .any(|m| matches!(m, PendingMutation::UnsetVariable { name, .. } if name == "target"))
    );
}
#[test]
fn function_removal_and_redefinition_follow_source_order() {
    decision(
        "f() { exit; }; unset -f f; f() { printf LAB; }; f; rm -f /opt/shared/file",
        Decision::NeedApproval,
    );
    binding(
        "f() { exit; }; unset -f f; f() { printf LAB; }; f; target=LAB",
        "target",
        "LAB",
        false,
    );
    let ctx = inspect("f() { exit; }; unset -f f; f() { printf LAB; }; f");
    assert!(!ctx.root_shell_terminates());
}
#[test]
fn option_state_does_not_escape_isolated_frames() {
    for middle in [
        "(unset -v target)",
        "{ unset -v target; } | cat",
        "{ unset -v target; } &",
        "(export -n target)",
    ] {
        binding(
            &format!("export target=LAB; {middle}\nprintf LAB"),
            "target",
            "LAB",
            true,
        );
    }
    for middle in ["(unset -f f)", "{ unset -f f; } | cat", "{ unset -f f; } &"] {
        assert!(
            inspect(&format!("f() {{ exit; }}; {middle}\nf")).root_shell_terminates(),
            "{middle}"
        );
    }
}
#[test]
fn options_apply_within_their_own_isolated_frame() {
    decision(
        "target=/opt/shared/file; (export -n target=cache/file; rm -f \"$target\")",
        Decision::Allow,
    );
    decision(
        "target=/opt/shared/file; (export -n target=cache/file); rm -f \"$target\"",
        Decision::NeedApproval,
    );
}
#[test]
fn conditional_unset_or_unexport_does_not_claim_precise_state() {
    for c in [
        "target=cache/file; false && unset -v target",
        "export target=cache/file; false && export -n target",
    ] {
        decision(&format!("{c}; rm -f \"$target\""), Decision::NeedApproval);
        assert!(inspect(c).pending_mutations().iter().any(|m| matches!(m, PendingMutation::UpsertVariableBinding { binding } if binding.name == "target" && matches!(binding.value, SessionVariableValue::OpaqueDynamic { .. }))));
    }
}
#[test]
fn ordinary_function_calls_propagate_scalar_option_changes() {
    binding(
        "export target=LAB; f() { export -n target; }; f",
        "target",
        "LAB",
        false,
    );
    binding(
        "target=old; f() { export -n target=LAB; }; f",
        "target",
        "LAB",
        false,
    );
    let ctx = inspect("target=LAB; f() { unset -v target; }; f");
    assert!(
        ctx.pending_mutations()
            .iter()
            .any(|m| matches!(m, PendingMutation::UnsetVariable { name, .. } if name == "target"))
    );
}
#[test]
fn nameref_and_dynamic_targets_are_not_reported_as_exact() {
    for c in [
        "target=cache/file; unset -n target",
        "target=cache/file; unset \"$name\"",
        "target=cache/file; export \"$option\" target",
    ] {
        let ctx = inspect(c);
        assert!(ctx.pending_mutations().iter().any(|m| matches!(m, PendingMutation::UpsertVariableBinding { binding } if binding.name == "target" && matches!(binding.value, SessionVariableValue::OpaqueDynamic { .. }))), "{c}");
        decision(&format!("{c}; rm -f \"$target\""), Decision::NeedApproval);
    }
    binding("target=LAB; export -f target", "target", "LAB", false);
}
#[test]
fn exit_fences_still_exclude_later_option_state() {
    binding(
        "export target=LAB; exit; export -n target; unset -v target",
        "target",
        "LAB",
        true,
    );
}
#[test]
fn persistent_actions_reuse_unexported_scalar_but_not_removed_values() {
    for (first, expected) in [
        (
            "export target=/opt/shared/file; export -n target",
            Decision::NeedApproval,
        ),
        ("target=cache/file; unset -v target", Decision::NeedApproval),
        (
            "export target=old; unset -v target; target=cache/file",
            Decision::Allow,
        ),
        (
            "target=old; unset target; export -n target=cache/file",
            Decision::Allow,
        ),
    ] {
        let mut core = ShellQueryCore::new();
        assert_eq!(
            core.check(request(1, first)).decision,
            Decision::Allow,
            "{first}"
        );
        let mut next = request(2, "rm -f \"$target\"");
        next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
        assert_eq!(core.check(next).decision, expected, "{first}");
    }
}

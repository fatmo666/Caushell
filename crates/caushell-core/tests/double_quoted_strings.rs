//! These are static analysis inputs; no shell string is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PolicyConfig, ResolveGapKind, RuleAction,
    RuntimeMetadata, SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn inspect(command: &str, expected: Decision) -> Vec<GraphNode> {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.no_profile.action = RuleAction::Deny;
    for kind in [
        ResolveGapKind::NoProfile,
        ResolveGapKind::UnknownSubcommandPath,
        ResolveGapKind::FormSelectionUnmatched,
        ResolveGapKind::FormSelectionAmbiguous,
    ] {
        policy
            .rule_policy
            .resolve_gap
            .defaults
            .insert(kind, RuleAction::Deny);
    }
    let mut core = ShellQueryCore::try_with_policy(policy).unwrap();
    let request = CheckRequest {
        session_id: SessionId::new("double-quoted"),
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
    };
    let response = core.check(request.clone());
    assert_eq!(response.decision, expected, "{command}: {response:?}");
    // A proposal requiring approval does not enter executed session history.
    // Inspect the staged candidate graph without approving or executing it.
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request);
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    staged.graph().nodes().cloned().collect()
}

fn has_path(graph: &[GraphNode], path: &str) -> bool {
    graph.iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact { resolution, .. }
            if resolution.concrete_path() == Some(path))
    })
}

#[test]
fn multiline_nested_shell_does_not_hide_external_mutations_in_first_command() {
    for command in [
        "bash -c \"echo ok\nrm -f /etc/quoted-outside\"",
        "bash -c \"echo ok # comment\nrm -f /etc/quoted-outside\"",
        "bash -c \"sh -c 'echo ok\nrm -f /etc/quoted-outside'\"",
    ] {
        let core = inspect(command, Decision::NeedApproval);
        assert!(has_path(&core, "/etc/quoted-outside"));
    }
}

#[test]
fn multiline_workspace_nested_shell_keeps_child_command_and_path() {
    let core = inspect("bash -c \"echo ok\nrm -f local\"", Decision::Allow);
    assert!(has_path(&core, "/tmp/project/local"));
    assert!(core.iter().any(
        |node| matches!(&node.kind, NodeKind::DerivedInvocation { command_name, .. }
            if command_name.as_deref() == Some("rm"))
    ));
}

#[test]
fn single_and_double_quoted_multiline_scripts_retain_the_same_modification() {
    for (target, expected) in [
        ("local", Decision::Allow),
        ("/etc/quoted-outside", Decision::NeedApproval),
    ] {
        let script = format!("echo ok\nrm -f {target}");
        let single = inspect(&format!("bash -c '{script}'"), expected.clone());
        let double = inspect(&format!("bash -c \"{script}\""), expected);
        let path = if target.starts_with('/') {
            target.to_string()
        } else {
            format!("/tmp/project/{target}")
        };
        assert!(has_path(&single, &path));
        assert!(has_path(&double, &path));
    }
}

#[test]
fn escaped_substitution_text_is_data_not_a_derived_command() {
    let core = inspect(
        "printf '%s' \"first\n\\$(unknown-command)\n\\`unknown-command\\`\nlast\"",
        Decision::Allow,
    );
    assert!(
        core.iter()
            .all(|node| !matches!(node.kind, NodeKind::DerivedInvocation { .. }))
    );
}

#[test]
fn real_substitutions_keep_external_mutation_evidence_in_multiline_data() {
    let core = inspect(
        "printf '%s' \"first\n$(rm -f /etc/quoted-outside)\nlast\"",
        Decision::NeedApproval,
    );
    assert!(has_path(&core, "/etc/quoted-outside"));
}

#[test]
fn multiline_here_string_and_assignment_keep_nested_shell_effects() {
    for command in [
        "bash <<< \"echo ok\nrm -f /etc/quoted-outside\"",
        "SCRIPT=\"echo ok\nrm -f /etc/quoted-outside\"; bash -c \"$SCRIPT\"",
    ] {
        let core = inspect(command, Decision::NeedApproval);
        assert!(has_path(&core, "/etc/quoted-outside"));
    }
}

fn double_quote(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        if matches!(character, '\\' | '"' | '$' | '`') {
            encoded.push('\\');
        }
        encoded.push(character);
    }
    encoded.push('"');
    encoded
}

#[test]
fn escaped_script_argv_retains_one_child_mutation_and_the_real_target() {
    for shell in ["bash", "sh"] {
        for (target, expected) in [
            ("/etc/quoted-outside", Decision::NeedApproval),
            ("/tmp/project/local", Decision::Allow),
        ] {
            let script = format!("TARGET={target}\nrm -f \"$TARGET\"");
            let command = format!("{shell} -c {}", double_quote(&script));
            let graph = inspect(&command, expected);
            assert!(has_path(&graph, target), "{command}: {graph:?}");
            let deletes: Vec<_> = graph
                .iter()
                .filter(|node| {
                    matches!(&node.kind,
                NodeKind::DerivedInvocation { command_name, .. }
                    if command_name.as_deref() == Some("rm"))
                })
                .collect();
            // Graph keeps historical and canonical representations. Both must
            // agree on child text, while the effective mutation is modeled once.
            assert!(!deletes.is_empty());
            assert!(deletes.iter().all(|node| matches!(&node.kind,
                NodeKind::DerivedInvocation { raw_text, .. }
                    if raw_text == "rm -f \"$TARGET\"")));
            assert_eq!(
                graph
                    .iter()
                    .filter(|node| matches!(&node.kind,
                NodeKind::PathFact { resolution, normalized_command_name, .. }
                    if normalized_command_name.as_deref() == Some("rm")
                        && resolution.concrete_path() == Some(target)))
                    .count(),
                1
            );
        }
    }
}

#[test]
fn wrappers_functions_find_and_multiple_shell_layers_use_decoded_payloads() {
    let script = "TARGET=/etc/quoted-outside\nrm -f \"$TARGET\"";
    let child = format!("sh -c {}", double_quote(script));
    for command in [
        format!("env {child}"),
        format!("f() {{ {child}; }}; f"),
        format!("find . -exec {child} _ {{}} \\;"),
        format!("bash -c {}", double_quote(&child)),
        format!("eval {}", double_quote(script)),
    ] {
        let graph = inspect(&command, Decision::NeedApproval);
        assert!(
            has_path(&graph, "/etc/quoted-outside"),
            "{command}: {graph:?}"
        );
    }
}

#[test]
fn escaped_child_variable_does_not_expand_in_the_outer_shell() {
    let script = "TARGET=/tmp/project/local\nrm -f \"$TARGET\"";
    let command = format!(
        "TARGET=/etc/quoted-outside; bash -c {}",
        double_quote(script)
    );
    let graph = inspect(&command, Decision::Allow);
    assert!(has_path(&graph, "/tmp/project/local"));
    assert!(!has_path(&graph, "/etc/quoted-outside"));
}

#[test]
fn escaped_dollar_inside_child_quotes_is_not_decoded_a_second_time() {
    let script = "TARGET=/etc/quoted-outside\nrm -f \"\\$TARGET\"";
    let graph = inspect(
        &format!("bash -c {}", double_quote(script)),
        Decision::Allow,
    );
    assert!(!has_path(&graph, "/etc/quoted-outside"));
    assert!(graph.iter().any(|node| matches!(&node.kind,
        NodeKind::DerivedInvocation { raw_text, .. } if raw_text == "rm -f \"\\$TARGET\"")));
}

#[test]
fn scalar_payload_with_inner_expansion_is_not_reinterpreted_as_outer_syntax() {
    let command = "SCRIPT='INNER=/etc/quoted-outside\nrm -f \"$INNER\"'; bash -c \"$SCRIPT\"";
    let graph = inspect(command, Decision::NeedApproval);
    assert!(has_path(&graph, "/etc/quoted-outside"));
}

#[test]
fn unresolved_outer_payload_is_approval_not_a_fabricated_static_child() {
    for command in [
        "bash -c \"rm -f \\\"$UNKNOWN\\\"\"",
        "bash -c \"echo safe; $UNKNOWN\"",
        "bash -c script*.sh",
    ] {
        let graph = inspect(command, Decision::NeedApproval);
        assert!(
            graph.iter().any(|node| matches!(&node.kind,
            NodeKind::NestedPayload { resolution_kind, .. }
                if resolution_kind == "unresolved_materialization")),
            "{command}: {graph:?}"
        );
        assert!(!graph.iter().any(|node| matches!(&node.kind,
            NodeKind::DerivedInvocation { command_name, .. }
                if command_name.as_deref() == Some("rm"))));
    }
}

#[test]
fn concatenated_outer_quotes_recover_a_patch_without_command_special_cases() {
    for (target, expected) in [
        ("local", Decision::Allow),
        ("/etc/quoted-outside", Decision::NeedApproval),
    ] {
        let child =
            format!("apply_patch '*** Begin Patch\n*** Add File: {target}\n+x\n*** End Patch'");
        let argument = format!("'{}'", child.replace('\'', "'\\''"));
        let graph = inspect(&format!("bash -c {argument}"), expected);
        let concrete = if target.starts_with('/') {
            target.into()
        } else {
            format!("/tmp/project/{target}")
        };
        assert!(has_path(&graph, &concrete));
    }
}

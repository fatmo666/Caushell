//! Static decision and Graph regressions; none of these commands executes.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("backtick-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-backtick-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn harmless_siblings_have_separate_real_graph_effects() {
    for command in [
        "echo `date` `hostname`",
        "echo \"`date` `hostname`\"",
        "value=\"`date` `hostname`\"",
        "echo pre`date``hostname`post",
        "bash -c 'echo `date` `hostname`'",
        "f() { echo `date` `hostname`; }; f",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        for name in ["date", "hostname"] {
            assert_eq!(
                response
                    .decision_trace
                    .execution_semantics
                    .iter()
                    .filter(|s| s.normalized_command_name == name)
                    .count(),
                1,
                "{command}: {response:#?}"
            );
        }
    }
}

#[test]
fn sibling_and_escaped_nested_mutations_reach_existing_guards() {
    for (command, name) in [
        ("echo `true` `touch /opt/shared/marker`", "touch"),
        (r"echo `printf '%s' \`touch /opt/shared/marker\``", "touch"),
        (r"value=`printf '%s' \`rm -f /opt/shared/marker\``", "rm"),
        (
            r#"echo "`printf '%s' \`touch /opt/shared/marker\``""#,
            "touch",
        ),
        (
            r"export value=`printf '%s' \`touch /opt/shared/marker\``",
            "touch",
        ),
        (
            r"value=`printf '%s' \`touch /opt/shared/marker\`` true",
            "touch",
        ),
        (r"echo $(printf '%s' `touch /opt/shared/marker`)", "touch"),
        ("unmodeled_tool `touch /opt/shared/marker`", "touch"),
        ("unmodeled_tool $(touch /opt/shared/marker)", "touch"),
        ("unmodeled_tool <(touch /opt/shared/marker)", "touch"),
        ("value=$(inner=$(touch /opt/shared/marker))", "touch"),
        (
            "export value=$(export inner=$(touch /opt/shared/marker))",
            "touch",
        ),
        (
            "echo `true`; touch /opt/shared/marker; echo `true`",
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
            "mutation missing from Graph: {command}: {response:#?}"
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
fn literal_ticks_are_data_and_local_nested_mutations_remain_local() {
    for command in [
        "echo '`touch /opt/shared/marker`'",
        r"echo \`touch /opt/shared/marker\`",
        "echo $'`touch /opt/shared/marker`'",
        "echo okay # `touch /opt/shared/marker`",
        r"echo `printf '%s' \`touch marker\``",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn nested_assignment_outputs_keep_distinct_graph_identity() {
    use caushell_graph::NodeKind;
    let command = "value=$(printf '%s' outer; inner=$(printf '%s' inner))";
    let mut core = ShellQueryCore::new();
    let response = core.check(request(command));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    let graph = core
        .session_graph(&SessionId::new("backtick-test"))
        .unwrap();
    for expression in [
        "$(printf '%s' outer; inner=$(printf '%s' inner))",
        "$(printf '%s' inner)",
    ] {
        assert_eq!(graph.nodes().filter(|node| matches!(&node.kind,
            NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::CommandSubstitutionOutput {expression: actual, ..} }
            if actual == expression)).count(), 1, "{expression}");
    }
}

#[test]
fn assignment_substitutions_inherit_their_source_position_cwd() {
    for command in [
        "cd /opt/shared; value=$(touch marker)",
        "cd /opt/shared && value=$(touch marker)",
        "cd /opt/shared && ignored=1; value=$(touch marker)",
        "cd /opt/shared && value=$(touch marker) || true",
        "cd $UNKNOWN; value=$(touch marker)",
        "cd /opt/shared; export value=$(touch marker)",
        "cd /opt/shared; value=$(touch marker) true",
        "value=$(cd /opt/shared; inner=$(touch marker))",
        "value=$(cd /opt/shared; export inner=$(touch marker))",
        "echo \"$(cd /opt/shared; inner=$(touch marker))\"",
        "echo \"$(cd /opt/shared; inner=$(touch marker) true)\"",
        "bash -c 'cd /opt/shared; value=$(touch marker)'",
        "cat <(cd /opt/shared; value=$(touch marker))",
        "unmodeled_tool <(cd /opt/shared; value=$(touch marker))",
        "f() { cd /opt/shared; value=$(touch marker); }; f",
        "value=$(cd /opt/shared; inner=$(next=$(touch marker)))",
        "value=$(cd /opt/shared; inner=$(touch marker); cd /tmp/project)",
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
                .decision_proposals
                .iter()
                .any(|p| p.source_pass == "outside_workspace_mutation_guard"),
            "{command}: {response:#?}"
        );
    }
    for command in [
        "cd /tmp/project && value=$(touch marker)",
        "(cd /opt/shared); value=$(touch marker)",
        "cd /opt/shared || value=$(touch marker)",
        "cd /opt/shared & value=$(touch marker)",
        "value=$(cd /opt/shared || inner=$(touch marker))",
        "value=$((0)) ; echo okay",
        "value=$( (cd /opt/shared); inner=$(touch marker))",
        "value=$(cd /opt/shared & inner=$(touch marker))",
        "value=$(cd /tmp/project && inner=$(touch marker))",
        "value=$(inner=$(next=$(touch marker)))",
        "echo \"$(cd /tmp/project && inner=$(touch marker))\"",
        "bash -c 'cd /tmp/project && value=$(touch marker)'",
        "cat <(cd /tmp/project && value=$(touch marker))",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn expansion_limit_remains_enforced_for_escaped_nesting() {
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 1;
    let response = ShellQueryCore::with_policy(policy)
        .check(request(r"echo `printf '%s' \`touch /opt/shared/marker\``"));
    assert_ne!(response.decision, Decision::Allow, "{response:#?}");
    let too_many = format!("echo {}", vec!["`true`"; 40].join(" "));
    let response = ShellQueryCore::new().check(request(&too_many));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    let response = ShellQueryCore::new().check(request(&format!("bash -c '{too_many}'")));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    // An outer escaped substitution is short to parse, but decoding it exposes
    // a body over the parser's boundary budget. It must not vanish as output.
    let inner = vec![r"\`true\`"; 40].join(" ");
    let command = format!("echo `printf '%s' {inner}`");
    let response = ShellQueryCore::new().check(request(&command));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .reasons
            .iter()
            .any(|reason| reason.contains("parse budget")),
        "{response:#?}"
    );
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 1;
    let response = ShellQueryCore::with_policy(policy)
        .check(request("echo \"$(inner=$(touch /opt/shared/marker))\""));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::ExecutionExpansionLimit),
        "{response:#?}"
    );
    let command = "value=$(inner=$(next=$(touch /opt/shared/marker)))";
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 1;
    let response = ShellQueryCore::with_policy(policy).check(request(command));
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
fn restored_curl_output_is_content_io_not_path_mutation() {
    for command in [
        "value=$(curl -s -o /dev/null http://127.0.0.1/)",
        "export value=$(curl -s -o /dev/null http://127.0.0.1/)",
        "value=$(curl -s -o result http://127.0.0.1/)",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
    let response = ShellQueryCore::new().check(request(
        "value=$(curl -s -o /opt/shared/result http://127.0.0.1/)",
    ));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.source_pass == "outside_workspace_mutation_guard"),
        "{response:#?}"
    );
}

#[test]
fn top_level_function_arguments_reach_assignment_substitutions() {
    for command in [
        "f() { local input=$1; result=$(eval \"$input\"); echo okay; }; f 'ls -a /bin'",
        "f() { local target=$1; value=$(touch \"$target\"); echo okay; }; f marker",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
    for command in [
        "f() { local input=$1; result=$(eval \"$input\"); echo okay; }; f 'touch /opt/shared/marker'",
        "f() { local target=$1; value=$(touch \"$target\"); echo okay; }; f /opt/shared/marker",
        "target=/opt/shared/marker; f() { local target=marker; value=$(touch \"$target\"); echo okay; }; f; touch \"$target\"",
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
                .any(|s| s.normalized_command_name == "touch"),
            "{command}: {response:#?}"
        );
    }
    for command in [
        "local target=marker; value=$(touch \"$target\")",
        "target=/opt/shared/marker; readonly target; f() { local target=marker; value=$(touch \"$target\"); echo okay; }; f",
        "target=/opt/shared/marker; f() { local -n target=marker; value=$(touch \"$target\"); echo okay; }; f",
        "f() { value=$(bash -c 'local target=marker; touch \"$target\"'); echo okay; }; f",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
}

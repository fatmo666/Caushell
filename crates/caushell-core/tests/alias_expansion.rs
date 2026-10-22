use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("alias-expansion"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn check_aliases(aliases: &[(&str, &str)], command: &str) -> CheckResponse {
    let mut core = ShellQueryCore::new();
    for (index, (name, body)) in aliases.iter().enumerate() {
        let definition = format!("alias {name}={}", quoted(body));
        let response = core.check(request(index as u64 + 1, &definition));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{definition}: {response:#?}"
        );
    }
    core.check(request(aliases.len() as u64 + 1, command))
}

fn assert_decision(aliases: &[(&str, &str)], command: &str, expected: Decision) -> CheckResponse {
    let response = check_aliases(aliases, command);
    assert_eq!(response.decision, expected, "{command}: {response:#?}");
    response
}

#[test]
fn alias_redirections_follow_the_actual_target() {
    for target in ["./result", "/tmp/alias-result", "/opt/shared/result"] {
        let body = format!("printf '%s' 'LAB_RESULT\n' > {}", quoted(target));
        let expected = if target.starts_with("/opt/") {
            Decision::NeedApproval
        } else {
            Decision::Allow
        };
        let response = assert_decision(&[("emit", &body)], "emit", expected);
        if expected == Decision::NeedApproval {
            assert!(
                response
                    .decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
            );
        }
    }
}

#[test]
fn alias_chains_keep_all_redirection_opens() {
    for (body, command) in [
        ("next > /opt/shared/first", "emit > ./last"),
        ("next > ./first", "emit > /opt/shared/last"),
    ] {
        assert_decision(
            &[("emit", body), ("next", "printf DATA")],
            command,
            Decision::NeedApproval,
        );
    }
    assert_decision(
        &[("emit", "next > ./first"), ("next", "printf DATA")],
        "emit > ./last",
        Decision::Allow,
    );
}

#[test]
fn quoted_arguments_remain_data_and_dynamic_targets_keep_their_bindings() {
    assert_decision(
        &[("emit", "printf '%s'")],
        "emit '$(touch /opt/shared/not-executed)' > ./result",
        Decision::Allow,
    );
    for (target, expected) in [
        ("./result", Decision::Allow),
        ("/opt/shared/result", Decision::NeedApproval),
    ] {
        let mut core = ShellQueryCore::new();
        core.check(request(
            1,
            &format!(
                "target={}; alias emit='printf DATA > \"$target\"'",
                quoted(target)
            ),
        ));
        let response = core.check(request(2, "emit"));
        assert_eq!(response.decision, expected, "{response:#?}");
    }
}

#[test]
fn alias_redirection_substitutions_enter_the_execution_frontier() {
    assert_decision(
        &[(
            "emit",
            "printf DATA > \"$(touch /opt/shared/marker; printf ./result)\"",
        )],
        "emit",
        Decision::NeedApproval,
    );
}

#[test]
fn incomplete_known_aliases_never_fall_back_to_unknown_command_allow() {
    for aliases in [
        vec![("emit", "next"), ("next", "emit")],
        vec![("emit", "printf '")],
        vec![("emit", "printf A; touch /opt/shared/result")],
    ] {
        let response = assert_decision(&aliases, "emit", Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError
                    || p.rule_id == RuleId::ExecutionExpansionLimit)
        );
    }
}

#[test]
fn nested_function_calls_use_the_same_alias_analysis() {
    let mut core = ShellQueryCore::new();
    core.check(request(1, "alias emit='printf DATA > /opt/shared/result'"));
    core.check(request(2, "perform() { emit; }"));
    let response = core.check(request(3, "perform"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn ordinary_aliases_and_unrelated_unknown_commands_keep_their_policy() {
    assert_decision(&[("inspect", "cat")], "inspect ./input", Decision::Allow);
    assert_decision(
        &[("inspect", "inspect --number")],
        "inspect ./input",
        Decision::Allow,
    );
    assert_decision(&[], "unregistered-tool ./input", Decision::Allow);
    assert_decision(
        &[("emit", "touch /opt/shared/result")],
        "command emit",
        Decision::Allow,
    );
}

#[test]
fn caller_cwd_and_pipeline_context_are_preserved() {
    for (body, expected) in [
        ("printf DATA > ./result", Decision::Allow),
        ("printf DATA > /opt/shared/result", Decision::NeedApproval),
    ] {
        assert_decision(&[("emit", body)], "emit | cat", expected);
    }
    assert_decision(
        &[("emit", "printf DATA > ./result")],
        "cd /opt/shared; emit",
        Decision::NeedApproval,
    );
    assert_decision(
        &[("emit", "printf DATA > ./result")],
        "cd /bench/workspace; emit",
        Decision::Allow,
    );
}

#[test]
fn alias_budget_and_errors_survive_argument_substitution_refresh() {
    assert_decision(
        &[("emit", "next"), ("next", "emit")],
        "emit \"$(printf DATA)\"",
        Decision::NeedApproval,
    );
    let mut core = ShellQueryCore::new();
    for index in 0..10 {
        let body = if index == 9 {
            "printf DATA".to_owned()
        } else {
            format!("step{}", index + 1)
        };
        core.check(request(
            index + 1,
            &format!("alias step{index}={}", quoted(&body)),
        ));
    }
    let response = core.check(request(11, "step0"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .reasons
            .iter()
            .any(|reason| reason.contains("hop budget"))
    );
}

#[test]
fn quoted_names_and_executable_dispatch_do_not_expand_shell_aliases() {
    for command in [
        "command emit",
        "env emit",
        "bash -c 'emit'",
        "\\emit",
        "\"emit\"",
    ] {
        assert_decision(
            &[("emit", "touch /opt/shared/result")],
            command,
            Decision::Allow,
        );
    }

    assert_decision(&[("cat", "cat --number")], "cat ./input", Decision::Allow);
}

#[test]
fn aliased_interpreters_keep_pipeline_payload_effects() {
    assert_decision(
        &[("run", "bash")],
        "printf 'touch /opt/shared/result' | run",
        Decision::NeedApproval,
    );
    assert_decision(
        &[("run", "bash")],
        "printf 'touch ./result' | run",
        Decision::Allow,
    );
    assert_decision(
        &[("cat", "touch /opt/shared/result; cat")],
        "cat ./input",
        Decision::NeedApproval,
    );
}

#[test]
fn alias_namespace_follows_shell_frames_and_unalias() {
    assert_decision(
        &[("emit", "touch /opt/shared/result")],
        "printf \"$(emit)\"",
        Decision::NeedApproval,
    );
    assert_decision(
        &[("emit", "touch /opt/shared/result")],
        "bash -c 'printf \"$(emit)\"'",
        Decision::Allow,
    );
    let mut core = ShellQueryCore::new();
    core.check(request(1, "alias emit='touch /opt/shared/result'"));
    core.check(request(2, "unalias emit"));
    assert_eq!(core.check(request(3, "emit")).decision, Decision::Allow);
}

#[test]
fn prefix_assignments_and_aliases_to_functions_keep_caller_redirections() {
    assert_decision(
        &[("emit", "printf DATA > /opt/shared/result")],
        "X=local emit",
        Decision::NeedApproval,
    );
    let mut core = ShellQueryCore::new();
    core.check(request(1, "perform() { printf DATA; }"));
    core.check(request(2, "alias emit='perform > /opt/shared/result'"));
    let response = core.check(request(3, "emit"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn alias_compound_redirections_are_not_lost() {
    for (target, expected) in [
        ("./result", Decision::Allow),
        ("/opt/shared/result", Decision::NeedApproval),
    ] {
        let body = format!("{{ printf DATA; }} > {target}");
        let response = assert_decision(&[("emit", &body)], "emit", expected);
        if expected == Decision::NeedApproval {
            assert!(
                response
                    .decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
            );
        }
    }
}

#[test]
fn unsupported_following_word_expansion_is_explicit() {
    let response = assert_decision(
        &[
            ("emit", "printf "),
            ("payload", "$(touch /opt/shared/result)"),
        ],
        "emit payload",
        Decision::NeedApproval,
    );
    assert!(
        response
            .reasons
            .iter()
            .any(|reason| reason.contains("following-word expansion"))
    );
    assert_decision(
        &[("emit", "printf ")],
        "emit ordinary-data",
        Decision::Allow,
    );
}

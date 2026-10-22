//! Static input only: none of the shell commands under test is executed.
use caushell_core::{SessionState, ShellQueryCore};
use caushell_types::*;

fn library(core: &mut ShellQueryCore, sequence: u64, path: &str, body: &str) {
    let response = core.check(request(
        sequence,
        &format!("cat > {path} <<'LIBRARY'\n{body}\nLIBRARY"),
    ));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn sourced_definitions_reach_the_calling_shell() {
    for (body, expected) in [
        ("perform_step() { printf SAFE; }", Decision::Allow),
        (
            "perform_step() { touch /opt/shared/from-library; }",
            Decision::NeedApproval,
        ),
    ] {
        let mut core = ShellQueryCore::new();
        library(&mut core, 1, "library.sh", body);
        let loaded = core.check(request(2, "source library.sh"));
        assert_eq!(loaded.decision, Decision::Allow, "{loaded:#?}");
        let response = core.check(request(3, "perform_step"));
        assert_eq!(response.decision, expected, "{response:#?}");
        if expected == Decision::NeedApproval {
            assert!(
                response
                    .decision_trace
                    .decision_proposals
                    .iter()
                    .any(|proposal| proposal.rule_id == RuleId::OutsideWorkspaceMutation),
                "{response:#?}"
            );
        }
    }
}

#[test]
fn nested_source_replays_helpers_before_the_library_definition() {
    let mut core = ShellQueryCore::new();
    library(
        &mut core,
        1,
        "helpers.sh",
        "make_output() { mkdir -- \"$1\"; }",
    );
    library(
        &mut core,
        2,
        "library.sh",
        "source helpers.sh\nperform_step() { make_output /opt/shared/from-library; }",
    );
    let loaded = core.check(request(3, "source library.sh"));
    assert_eq!(loaded.decision, Decision::Allow, "{loaded:#?}");
    let response = core.check(request(4, "perform_step"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn same_request_source_updates_functions_variables_and_aliases() {
    for body in [
        "perform_step() { touch /opt/shared/from-library; }",
        "target=/opt/shared/from-library\nperform_step() { touch \"$target\"; }",
        "alias perform_step='touch /opt/shared/from-library'",
    ] {
        let command = format!(
            "cat > library.sh <<'LIBRARY'\n{body}\nLIBRARY\nsource library.sh; perform_step"
        );
        let response = ShellQueryCore::new().check(request(1, &command));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    }
}

#[test]
fn sourced_aliases_and_variables_are_persisted() {
    let mut core = ShellQueryCore::new();
    library(
        &mut core,
        1,
        "library.sh",
        "target=/opt/shared/from-library\nalias perform_step='touch /opt/shared/from-alias'",
    );
    assert_eq!(
        core.check(request(2, "source library.sh")).decision,
        Decision::Allow
    );
    let mut next = request(3, "touch \"$target\"");
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(core.check(next).decision, Decision::NeedApproval);
    assert_eq!(
        core.check(request(4, "perform_step")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn incomplete_source_state_never_becomes_an_unknown_command_allow() {
    let mut core = ShellQueryCore::new();
    let response = core.check(request(1, "source missing-library.sh; unknown_function"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    // A rejected proposal does not claim the source command executed. Model
    // the persisted incomplete state separately, without an approval receipt.
    let mut state = SessionState::new();
    state.summary_mut().mark_shell_state_uncertain(
        "sourced shell state is incomplete",
        CommandSequenceNo::new(1),
    );
    core.insert_session_state(SessionId::new("function-uncertainty"), state);
    assert_eq!(
        core.check(request(2, "unknown_function")).decision,
        Decision::NeedApproval
    );
    let snapshot = core
        .session_snapshot(&SessionId::new("function-uncertainty"), 1)
        .unwrap();
    let mut reloaded = ShellQueryCore::new();
    reloaded.insert_session_state(
        snapshot.session_id.clone(),
        SessionState::from_snapshot(snapshot).unwrap(),
    );
    assert_eq!(
        reloaded.check(request(3, "unknown_function")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn complete_runtime_snapshot_can_reconcile_an_incomplete_source() {
    let mut core = ShellQueryCore::new();
    let mut state = SessionState::new();
    state.summary_mut().mark_shell_state_uncertain(
        "sourced shell state is incomplete",
        CommandSequenceNo::new(1),
    );
    core.insert_session_state(SessionId::new("function-uncertainty"), state);
    let mut next = request(2, "printf SAFE");
    next.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
    next.shell_state_before.observability.functions = ShellStateKnowledge::Complete;
    next.shell_state_before.observability.aliases = ShellStateKnowledge::Complete;
    next.shell_state_before.observability.positional_parameters = ShellStateKnowledge::Complete;
    assert_eq!(core.check(next).decision, Decision::Allow);
    assert_eq!(
        core.check(request(3, "printf SAFE")).decision,
        Decision::Allow
    );
}

#[test]
fn isolated_source_does_not_replace_the_callers_function() {
    for command in [
        "(source library.sh)",
        "source library.sh | cat",
        "source library.sh &",
        "bash -c 'source library.sh'",
    ] {
        let mut core = ShellQueryCore::new();
        library(
            &mut core,
            1,
            "library.sh",
            "perform_step() { touch /opt/shared/from-library; }",
        );
        core.check(request(2, "perform_step() { printf SAFE; }"));
        core.check(request(3, command));
        let response = core.check(request(4, "perform_step"));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn source_arguments_are_temporary_but_unparameterized_set_is_shared() {
    let mut core = ShellQueryCore::new();
    core.check(request(1, "set -- /opt/shared/entry"));
    library(&mut core, 2, "library.sh", "set -- cache/local");
    assert_eq!(
        core.check(request(3, "source library.sh argument"))
            .decision,
        Decision::Allow
    );
    assert_eq!(
        core.check(request(4, "touch \"$1\"")).decision,
        Decision::NeedApproval
    );
    // A fresh source image has no intervening unmodelled file-content effects.
    library(&mut core, 5, "other.sh", "set -- /opt/shared/updated");
    assert_eq!(
        core.check(request(6, "source other.sh")).decision,
        Decision::Allow
    );
    assert_eq!(
        core.check(request(7, "touch \"$1\"")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn same_request_known_source_does_not_require_a_blanket_approval() {
    for body in [
        "perform_step() { printf SAFE; }",
        "alias perform_step='printf SAFE'",
    ] {
        let command = format!(
            "cat > library.sh <<'LIBRARY'\n{body}\nLIBRARY\nsource library.sh; perform_step"
        );
        let response = ShellQueryCore::new().check(request(1, &command));
        assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    }
}

#[test]
fn complete_stream_sources_share_the_same_state_replay() {
    for command in [
        "source /dev/stdin <<'CODE'\nf() { touch /opt/shared/file; }\nCODE\nf",
        "source <(printf '%s\\n' 'f() { touch /opt/shared/file; }'); f",
        "source /dev/stdin <<'CODE'\nf() { printf SAFE; }\nCODE\nf",
    ] {
        let expected = if command.contains("/opt/shared") {
            Decision::NeedApproval
        } else {
            Decision::Allow
        };
        let response = ShellQueryCore::new().check(request(1, command));
        assert_eq!(response.decision, expected, "{response:#?}");
    }
}

#[test]
fn source_replay_does_not_reuse_content_before_an_ancestor_write() {
    let mut core = ShellQueryCore::new();
    library(&mut core, 1, "helpers.sh", "f() { printf SAFE; }");
    library(&mut core, 2, "library.sh", "source helpers.sh");
    let response = core.check(request(3, "cat unknown > helpers.sh; source library.sh; f"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn conditional_partial_and_cyclic_sources_keep_an_explicit_gap() {
    for (body, call) in [
        (
            "f() { printf SAFE; }",
            "test -n \"$flag\" && source library.sh; f",
        ),
        ("source library.sh", "source library.sh; f"),
        ("f() {", "source library.sh; f"),
        ("eval 'f() { printf SAFE; }'", "source library.sh; f"),
    ] {
        let mut core = ShellQueryCore::new();
        library(&mut core, 1, "library.sh", body);
        let response = core.check(request(2, call));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(
            response
                .reasons
                .iter()
                .any(|reason| reason.contains("sourced")),
            "{response:#?}"
        );
    }
}

#[test]
fn sourced_function_removal_reaches_later_requests() {
    let mut core = ShellQueryCore::new();
    core.check(request(1, "touch() { printf SAFE; }"));
    library(&mut core, 2, "library.sh", "unset -f touch");
    assert_eq!(
        core.check(request(3, "source library.sh")).decision,
        Decision::Allow
    );
    let response = core.check(request(4, "touch /opt/shared/file"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
}

#[test]
fn alias_dispatched_sources_keep_their_argument_frame() {
    let mut core = ShellQueryCore::new();
    library(&mut core, 1, "library.sh", "target=\"$1\"");
    core.check(request(
        2,
        "alias load='source library.sh /opt/shared/target'",
    ));
    assert_eq!(core.check(request(3, "load")).decision, Decision::Allow);
    let mut next = request(4, "touch \"$target\"");
    next.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(core.check(next).decision, Decision::NeedApproval);
}

#[test]
fn unresolved_source_frame_lifetimes_cannot_install_exact_global_values() {
    for (body, call) in [
        (
            "target=\"$INPUT\"",
            "INPUT=/opt/shared/target source library.sh",
        ),
        (
            "local target=/opt/shared/target",
            "f() { source library.sh; }; f",
        ),
    ] {
        let mut core = ShellQueryCore::new();
        library(&mut core, 1, "library.sh", body);
        let response = core.check(request(2, call));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(
            response
                .reasons
                .iter()
                .any(|reason| reason.contains("sourced")),
            "{response:#?}"
        );
    }
}

#[test]
fn a_function_loading_a_library_propagates_its_alias_state() {
    for (body, expected) in [
        (
            "alias perform_step='touch /opt/shared/from-library'",
            Decision::NeedApproval,
        ),
        ("alias perform_step='printf SAFE'", Decision::Allow),
    ] {
        let mut core = ShellQueryCore::new();
        library(&mut core, 1, "library.sh", body);
        core.check(request(2, "load() { source library.sh; }"));
        let response = core.check(request(3, "load; perform_step"));
        assert_eq!(response.decision, expected, "{response:#?}");
    }
}

fn request(sequence: u64, command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("function-uncertainty"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project")
            .with_variable_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    }
}

fn decision(command: &str, expected: Decision) {
    let reply = ShellQueryCore::new().check(request(1, command));
    assert_eq!(
        reply.decision, expected,
        "{command}: {:?}",
        reply.decision_trace
    );
}

#[test]
fn plain_unset_falls_back_only_after_variable_absence() {
    decision(
        "rm() { printf SAFE; }; unset rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm=LAB; rm() { printf SAFE; }; unset rm; rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm=LAB; rm() { printf SAFE; }; unset rm rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; unset -v rm; rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; export rm; unset rm; rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; export -n rm; unset rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn conditional_function_deletion_is_uncertain_only_when_called() {
    decision(
        "f() { printf SAFE; }; if test -n \"$flag\"; then unset -f f; fi; printf DONE",
        Decision::Allow,
    );
    decision(
        "f() { printf SAFE; }; if test -n \"$flag\"; then unset -f f; fi; f",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; test -n \"$flag\" && unset -f rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn unconditional_definition_or_deletion_restores_certainty() {
    decision(
        "f() { printf SAFE; }; test -n \"$flag\" && unset -f f; f() { printf NEW; }; f",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; test -n \"$flag\" && unset -f rm; unset -f rm; rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn isolated_unset_does_not_change_caller_but_changes_its_own_frame() {
    decision(
        "rm() { printf SAFE; }; (unset rm); rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "rm() { printf SAFE; }; (unset rm; rm /opt/shared/file)",
        Decision::NeedApproval,
    );
}

#[test]
fn unknown_variable_namespace_does_not_prove_function_removal_or_survival() {
    let mut r = request(1, "f() { printf SAFE; }; unset f; f");
    r.shell_state_before.observability.variables = ShellStateKnowledge::Unknown;
    assert_eq!(
        ShellQueryCore::new().check(r).decision,
        Decision::NeedApproval
    );
    decision(
        "f() { printf SAFE; }; wait -p f; unset f; f",
        Decision::NeedApproval,
    );
    decision(
        "f() { printf SAFE; }; declare f; unset f; f",
        Decision::NeedApproval,
    );
}

#[test]
fn uncertain_binding_survives_snapshot_reload_and_runtime_facts_override_it() {
    let mut core = ShellQueryCore::new();
    let seed = core.check(request(
        1,
        "f() { printf SAFE; }; test -n \"$flag\" && unset -f f",
    ));
    assert_eq!(seed.decision, Decision::Allow);
    let saved = core
        .session_snapshot(&SessionId::new("function-uncertainty"), 1)
        .unwrap();
    let mut reloaded = ShellQueryCore::new();
    reloaded.insert_session_state(
        saved.session_id.clone(),
        SessionState::from_snapshot(saved).unwrap(),
    );
    let reply = reloaded.check(request(2, "f"));
    assert_eq!(reply.decision, Decision::NeedApproval);
    let mut r = request(3, "f");
    r.shell_state_before = r
        .shell_state_before
        .with_function_knowledge(ShellStateKnowledge::Complete)
        .with_function("f", "printf FACT;");
    assert_eq!(reloaded.check(r).decision, Decision::Allow);
}

#[test]
fn same_shell_nested_calls_keep_uncertainty_but_executables_do_not() {
    let prefix = "f() { printf SAFE; }; test -n \"$flag\" && unset -f f";
    for call in [
        "f",
        "eval 'f'",
        "printf '%s' \"$(f)\"",
        "cat <(f)",
        "alias a=f; a",
    ] {
        decision(&format!("{prefix}; {call}"), Decision::NeedApproval);
    }
    for call in [
        "command f",
        "env f",
        "bash -c 'f'",
        "printf LAB | xargs f",
        "find . -exec f \\;",
    ] {
        decision(&format!("{prefix}; {call}"), Decision::Allow);
    }
}

#[test]
fn unsupported_unset_targets_do_not_keep_stale_exact_functions() {
    for unset in [
        "unset -f \"$target\"",
        "unset \"$target\"",
        "unset \"$options\" f",
    ] {
        decision(
            &format!("f() {{ printf SAFE; }}; {unset}; f"),
            Decision::NeedApproval,
        );
        decision(
            &format!("f() {{ printf SAFE; }}; {unset}; printf DONE"),
            if unset.starts_with("unset -f ") {
                Decision::Allow
            } else {
                Decision::NeedApproval
            },
        );
    }
    decision("f() { printf SAFE; }; unset -vf f; f", Decision::Allow);
}

#[test]
fn conditional_and_isolated_definitions_do_not_create_exact_caller_bindings() {
    decision(
        "if test -n \"$flag\"; then f() { printf SAFE; }; fi; f",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; (rm() { printf NEW; }); rm /opt/shared/file",
        Decision::Allow,
    );
    decision(
        "(rm() { printf SAFE; }); rm /opt/shared/file",
        Decision::NeedApproval,
    );
}

#[test]
fn known_function_effects_update_the_callers_function_state() {
    decision(
        "rm() { printf SAFE; }; cleanup() { unset -f rm; }; cleanup; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; cleanup() { unset -f rm; }; test -n \"$flag\" && cleanup; rm /opt/shared/file",
        Decision::NeedApproval,
    );
    decision(
        "rm() { printf SAFE; }; cleanup() { unset -f rm; }; (cleanup); rm /opt/shared/file",
        Decision::Allow,
    );
}

#[test]
fn known_unexported_variable_is_not_confused_with_absent_environment() {
    let mut r = request(1, "rm() { printf SAFE; }; unset rm; rm /opt/shared/file");
    r.shell_state_before = r
        .shell_state_before
        .with_variable_knowledge(ShellStateKnowledge::Unknown);
    r.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "rm",
            ShellValueSnapshot::exact_scalar("LAB"),
            false,
        ));
    assert_eq!(ShellQueryCore::new().check(r).decision, Decision::Allow);
    let mut r = request(1, "f() { printf SAFE; }; unset f; f");
    r.shell_state_before.observability.variables = ShellStateKnowledge::ExportedOnly;
    assert_eq!(
        ShellQueryCore::new().check(r).decision,
        Decision::NeedApproval
    );
}

#[test]
fn exit_fences_do_not_commit_later_function_uncertainty() {
    let mut core = ShellQueryCore::new();
    assert_eq!(
        core.check(request(
            1,
            "f() { printf SAFE; }; exit; test -n \"$flag\" && unset -f f"
        ))
        .decision,
        Decision::Allow
    );
    assert_eq!(core.check(request(2, "f")).decision, Decision::Allow);
}

#[test]
fn bash_function_names_need_not_be_variable_identifiers() {
    for option in ["", "-f", "--"] {
        let mut core = ShellQueryCore::new();
        let reply = core.check(request(
            1,
            &format!("lab-f() {{ printf SAFE; }}; unset {option} lab-f; lab-f"),
        ));
        assert_eq!(reply.decision, Decision::Allow);
        assert!(reply.decision_trace.derived_invocations.is_empty());
        assert!(
            core.session_snapshot(&SessionId::new("function-uncertainty"), 1)
                .unwrap()
                .summary
                .function_binding("lab-f")
                .is_none()
        );
    }
}

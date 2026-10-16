//! Static checks only: no source command, generator, or nested Bash is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str, sequence: u64) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("sourced-streams"),
        sequence_no: CommandSequenceNo::new(sequence),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

fn external(r: &CheckResponse) -> bool {
    r.decision_trace.evidence.iter().any(|e| matches!(
        &e.kind, EvidenceKind::NestedPayloadUnresolved(u)
        if u.unresolved_execution_payload_subtype == Some(UnresolvedExecutionPayloadSubtype::ExternalStreamPayload)
    ))
}

fn check(command: &str, decision: Decision, unknown_stream: bool) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(r.decision, decision, "{command}: {r:#?}");
    assert_eq!(external(&r), unknown_stream, "{command}: {r:#?}");
    r
}

#[test]
fn unknown_script_streams_leave_an_explicit_execution_gap() {
    for command in [
        "source <(./generate_commands)",
        "source <(grep = file.ini | sed 's/ *= */=/g')",
        "source <(grep -v \"mesg\" /etc/bashrc)",
        "grep \"=\" myfile | source /dev/stdin",
        "source <(grep \"marker\" config.sh)",
        "source <(./script.sh | sed -rn '/volume/{s#/dev/([^[:space:]]+)[[:space:]]+#\\1=#;p}')",
        "source <(sed 's/:\\(.*\\)/=\"\\1\"/' msgs.config)",
        "source <(metaflac --show-tag ARTIST myfile.flac)",
        ". <(./generate_commands)",
    ] {
        let r = check(command, Decision::NeedApproval, true);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::NestedPayloadExpansion
                    && p.decision == Decision::NeedApproval),
            "{r:#?}"
        );
    }
}

#[test]
fn complete_known_streams_are_judged_by_their_actual_shell_effects() {
    for command in [
        "source <(printf '%s\\n' 'echo safe')",
        ". <(printf '%s\\n' 'touch ./out')",
        "printf '%s\\n' 'echo safe' | source /dev/stdin",
        "source /dev/stdin <<< 'touch ./out'",
        "source /dev/fd/3 3<<< 'touch ./out'",
        "source /proc/self/fd/3 3< <(printf '%s\\n' 'echo safe')",
        "source /dev/stdin <<'BODY'\necho safe\nBODY",
        "source /dev/null",
        "source <(printf '')",
        "source <(printf '%s\\n' 'echo safe' | cat)",
        "source <(cat <<'BODY'\necho safe\nBODY\n)",
    ] {
        check(command, Decision::Allow, false);
    }
    for command in [
        "source <(printf '%s\\n' 'touch /opt/shared/out')",
        "printf '%s\\n' 'touch /opt/shared/out' | source /dev/stdin",
        "source /dev/fd/3 3<<< 'touch /opt/shared/out'",
        "source /dev/stdin <<'BODY'\ntouch /opt/shared/out\nBODY",
    ] {
        let r = check(command, Decision::NeedApproval, false);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{r:#?}"
        );
    }
}

#[test]
fn partial_known_output_does_not_certify_the_whole_script() {
    for command in [
        "source <(printf '%s\\n' 'echo safe'; ./generate_commands)",
        "source <(./generate_commands; printf '%s\\n' 'echo safe')",
        "source <(printf '%s\\n' 'echo safe' | ./filter)",
        "source <(printf '#' & printf 'touch /opt/out\\n')",
        r#"source <(bash -c "printf '#' & printf 'touch /opt/out\n'")"#,
        "source <(printf '%s\\n' 'touch /opt/shared/out' > /dev/null)",
        "source /dev/fd/3",
    ] {
        check(command, Decision::NeedApproval, true);
    }
}

#[test]
fn stream_redirection_order_and_descriptor_aliases_are_respected() {
    for command in [
        "printf '%s\\n' 'touch /opt/out' | source /dev/stdin <<< 'echo safe'",
        "source /dev/fd/3 3<<< 'touch /opt/out' 3<<< 'echo safe'",
        "source /dev/fd/3 0<<< 'echo safe' 3<&0",
        "source /dev/stdin < /dev/null",
        "source /dev/stdin <&-",
    ] {
        check(command, Decision::Allow, false);
    }
    check(
        "source /dev/fd/3 3<<< 'echo safe' 3<<< 'touch /opt/out'",
        Decision::NeedApproval,
        false,
    );
    check(
        "source /dev/fd/3 3<&0 0<<< 'echo safe'",
        Decision::NeedApproval,
        true,
    );
}

#[test]
fn nested_scopes_do_not_lose_unknown_stream_execution() {
    for command in [
        "bash -c 'source <(./generate_commands)'",
        "f() { source <(./generate_commands); }; f",
        "echo $(source <(./generate_commands))",
        "find . -maxdepth 0 -exec bash -c 'source <(./generate_commands)' \\;",
        "bash -c 'source <(printf \"echo safe\"); source <(./generate_commands)'",
        "bash <(./generate_commands)",
        "echo $(bash <(./generate_commands))",
        "f() { bash <(./generate_commands); }; f",
    ] {
        check(command, Decision::NeedApproval, true);
    }
}

#[test]
fn ordinary_local_script_references_are_not_reclassified_as_streams() {
    for command in [
        "source ./env.sh",
        ". ./env.sh",
        "source '/bench/workspace/<(literal)'",
        "source /dev/stdin < ./unknown.sh",
        "source /dev/fd/3 3< ./unknown.sh",
        "cat ./data.txt",
    ] {
        check(command, Decision::Allow, false);
    }
}

#[test]
fn external_stream_rule_can_be_overridden_without_hiding_the_gap() {
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .resolve_gap
        .unresolved_execution_payload_subtypes
        .insert(
            UnresolvedExecutionPayloadSubtype::ExternalStreamPayload,
            RuleAction::Observe,
        );
    let r = ShellQueryCore::with_policy(policy).check(request("source <(./generate_commands)", 1));
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
    assert!(external(&r));
}

#[test]
fn descriptor_file_contents_do_not_use_a_stale_known_prefix() {
    check(
        "printf '%s\\n' 'touch /opt/out' >./code; source /dev/fd/3 3<./code",
        Decision::NeedApproval,
        false,
    );
    let response = check(
        "printf '%s\\n' 'echo safe' >./code; ./generator >./code; source /dev/fd/3 3<./code",
        Decision::Allow,
        false,
    );
    assert!(!response.decision_trace.nested_payloads.iter().any(|payload|
        payload.source == NestedPayloadSource::ScriptFileRef
            && payload.resolution.kind == NestedPayloadResolutionKind::Parsed
    ), "stale bytes were parsed as the current script: {response:#?}");
}

#[test]
fn descriptor_copy_keeps_the_original_pipeline_stream() {
    check(
        "printf '%s\\n' 'touch /opt/out' | source /dev/fd/3 3<&0 0<<< 'echo safe'",
        Decision::NeedApproval,
        false,
    );
}

//! Static proposals only: none of these shell commands is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("xargs-bounded-batches"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}

fn expect(commands: &[&str], decision: Decision) {
    for command in commands {
        let response = check(command);
        assert_eq!(response.decision, decision, "{command}: {response:#?}");
    }
}

#[test]
fn file_batches_reuse_source_and_terminal_target_profile_bindings() {
    expect(
        &[
            "find . -type f -print0 | xargs -0 -n2 cp -n --",
            "find . -type f -print0 | xargs -0 -n2 mv --",
            "find . -type f -print0 | xargs -0 -n2 ln -s --",
            "find . -type f -print0 | xargs -0 -n3 cp --",
            "find . -type f -print0 | xargs -0 -n2 env cp --",
            "find . -type f -print0 | xargs -0 -L2 cp -n --",
            "find . -type f -print0 | xargs -0 -n1 cp --",
            "find /opt/input -type f -print0 | xargs -0 -n1 ln -s --",
        ],
        Decision::Allow,
    );
}

#[test]
fn smaller_final_batches_are_not_lost() {
    // A one-item ln call writes in cwd; a two-item call uses its last operand.
    // An absolute workspace input therefore makes only the full batch local.
    expect(
        &[
            r#"find /bench/workspace/ -print0 | xargs -r0 -n2 sh -c 'cd /opt/shared; ln -s -- "$@"' arg0"#,
        ],
        Decision::NeedApproval,
    );
    expect(
        &["find /opt/input -print0 | xargs -r0 -n2 ln -s --"],
        Decision::NeedApproval,
    );
}

#[test]
fn run_if_empty_is_a_separate_possible_invocation() {
    expect(
        &["find . -print0 | xargs -0 -n1 cp -- /etc/source /opt/target"],
        Decision::NeedApproval,
    );
    expect(
        &["find . -print0 | xargs -r0 -n1 cp -- /etc/source /opt/target"],
        Decision::Allow,
    );
}

#[test]
fn path_and_cwd_uncertainty_still_require_approval() {
    expect(
        &[
            "find /opt/input -type f -print0 | xargs -0 -n2 cp --",
            "find /opt/input -type f -print0 | xargs -0 -n2 mv --",
            "cat list | xargs -0 -n2 cp --",
            "find . -print | xargs -n2 cp --",
            "cd /opt/shared; find . -print0 | xargs -0 -n2 cp --",
            "cd \"$UNKNOWN\"; find . -print0 | xargs -0 -n2 cp --",
            "find -L . -print0 | xargs -0 -n2 cp --",
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn data_arity_is_not_a_proof_of_safe_control_words_or_code() {
    expect(
        &[
            "cat list | xargs -0 -n2 cp",
            "cat list | xargs -0 -n1 bash -c",
            "cat list | xargs -n1 env",
        ],
        Decision::NeedApproval,
    );
    expect(&["find . -print0 | xargs -r0 -n2 rm -rf /"], Decision::Deny);
}

#[test]
fn unbounded_or_over_budget_batches_keep_the_existing_unknown_tail() {
    expect(
        &[
            "find . -print0 | xargs -0 cp --",
            "find . -print0 | xargs -0 -n9 cp --",
            "find . -print0 | xargs -0 -n1000000 cp --",
            "find . -print | xargs -L2 cp --",
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn ln_missing_operands_do_not_claim_a_write_or_hide_unknown_width() {
    expect(&["ln", "ln -s --", "ln -s -t /opt/target"], Decision::Allow);
    let response = check("ln ./*.txt");
    assert!(
        !response
            .decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "ln" && s.form_id == "missing_operands"),
        "{response:#?}"
    );
    expect(&["ln \"$UNKNOWN\""], Decision::NeedApproval);
}

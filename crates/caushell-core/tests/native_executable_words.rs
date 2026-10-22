//! Static checks only: the tested shell commands are not executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("native-executable-words"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn check(commands: &[&str], expected: Decision) {
    for command in commands {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(response.decision, expected, "{command}: {response:#?}");
    }
}

#[test]
fn native_wrappers_do_not_turn_literal_names_into_shell_variables() {
    for command in [
        "CMD=rm; '$CMD' -rf /",
        "CMD=rm; env '$CMD' -rf /",
        "CMD=rm; timeout 1 '$CMD' -rf /",
        "CMD=rm; env timeout 1 '$CMD' -rf /",
        "CMD=rm; command '$CMD' -rf /",
        "CMD=rm; printf item | xargs '$CMD' -rf /",
        "CMD=rm; find . -exec '$CMD' -rf / \\;",
        "CMD=rm; sort --compress-program='$CMD' input",
        "env 'rm${IFS}' -rf /",
        "env '\\rm' -rf /",
        "'\\rm' -rf /",
        "printf item | xargs 'rm${IFS}' -rf /",
        "export CMD=rm; env CMD='$CMD' sh -c '$CMD -rf /'",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            !response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "rm"),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn literal_substitution_syntax_is_not_a_code_entry_point() {
    check(
        &[
            "env '$(printf rm)' -rf /",
            "timeout 1 '$(printf rm)' -rf /",
            "printf item | xargs '$(printf rm)' -rf /",
            "env '`printf rm`' -rf /",
        ],
        Decision::Allow,
    );
}

#[test]
fn native_pathnames_preserve_dollar_tilde_and_space_bytes() {
    check(
        &[
            "env './$UNKNOWN'",
            "timeout 1 './$UNKNOWN'",
            "printf item | xargs './$UNKNOWN'",
            "find . -exec './$UNKNOWN' {} \\;",
            "env '~/hello'",
            "printf item | xargs '~/hello'",
            "env './hello world'",
        ],
        Decision::Allow,
    );
    check(
        &[
            "env '/opt/shared/$UNKNOWN'",
            "printf item | xargs '/opt/shared/$UNKNOWN'",
            "env ~/hello",
            "timeout 1 ~/hello",
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn unknown_parent_expansions_are_not_promoted_to_literal_programs() {
    check(
        &[
            "env \"$UNKNOWN\"",
            "timeout 1 \"$UNKNOWN\"",
            "printf item | xargs \"$UNKNOWN\"",
            "env ./bin/*",
            "env ''",
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn unresolved_dispatch_targets_keep_parent_shell_effects() {
    check(
        &[
            "env \"$(rm -rf /)\"",
            "timeout 1 \"$(rm -rf /)\"",
            "printf item | xargs \"$(rm -rf /)\"",
        ],
        Decision::Deny,
    );
}

#[test]
fn real_expansions_and_explicit_shell_code_remain_guarded() {
    check(
        &[
            "CMD=rm; env \"$CMD\" -rf /",
            "CMD=rm; printf item | xargs \"$CMD\" -rf /",
            "CMD=rm; timeout 1 \"$CMD\" -rf /",
            "env sh -c 'rm -rf /'",
            "env timeout 1 sh -c 'rm -rf /'",
            "printf item | xargs sh -c 'rm -rf /'",
            "export CMD=rm; env sh -c '$CMD -rf /'",
            "rm${IFS}-rf${IFS}/",
            "\\rm -rf /",
        ],
        Decision::Deny,
    );
    check(&["env sh -c \"$UNKNOWN\""], Decision::NeedApproval);
}

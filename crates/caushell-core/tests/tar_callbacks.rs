//! Static checks only; do not run the command strings in this file.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn check(command: &str) -> caushell_types::CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("tar-callbacks"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-tar".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    })
}

fn expect(command: &str, decision: Decision, child: Option<&str>) -> caushell_types::CheckResponse {
    let response = check(command);
    assert_eq!(response.decision, decision, "{command}: {response:#?}");
    if let Some(child) = child {
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == child),
            "{command}: {response:#?}"
        );
    }
    response
}

#[test]
fn checkpoints_reuse_real_shell_semantics_and_existing_mutation_guard() {
    for command in [
        "tar cf archive.tar input --checkpoint=1 --checkpoint-action='exec=rm /opt/shared/file'",
        "tar -c -f archive.tar input --checkpoint-action='exec=printf DATA > /opt/shared/output'",
        "tar --create --file=archive.tar input --checkpoint-action='exec=printf SAFE; rm /opt/shared/file'",
    ] {
        expect(command, Decision::NeedApproval, Some("sh"));
    }
    for command in [
        "tar cf archive.tar input --checkpoint-action='exec=printf SAFE'",
        "tar -cf archive.tar input --checkpoint-action='exec=printf DATA > local'",
        "tar -c --file archive.tar input --checkpoint-action=echo",
        "tar cf archive.tar input --checkpoint-action='echo=rm /opt/shared/file'",
        "tar -cvf archive.tar input",
        "tar -czvf archive.tar input",
    ] {
        expect(command, Decision::Allow, None);
    }
}

#[test]
fn compression_and_decompression_use_different_execution_modes() {
    expect(
        "tar cf archive.tar input -I 'printf SAFE; rm /opt/shared/file'",
        Decision::NeedApproval,
        Some("rm"),
    );
    for command in [
        "tar tf archive.tar -I 'sh -c \"rm /opt/shared/file\"'",
        "tar -tf archive.tar --use-compress-program='sh -c \"printf DATA > /opt/shared/output\"'",
    ] {
        expect(command, Decision::NeedApproval, Some("sh"));
    }
    for command in [
        "tar cf archive.tar input -I 'gzip -9'",
        "tar tf archive.tar -I 'gzip -9'",
        "tar tf archive.tar -I 'printf \"%s\" \"rm /opt/shared/file; true\"'",
        "tar tf archive.tar -I 'printf \"%s\" \"$(rm /opt/shared/file)\"'",
    ] {
        let response = expect(command, Decision::Allow, None);
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
fn tool_generated_environment_cannot_reuse_caller_values() {
    for command in [
        "TAR_ARCHIVE=local; export TAR_ARCHIVE; tar cf archive.tar input --checkpoint-action='exec=rm \"$TAR_ARCHIVE\"'",
        "TAR_FILENAME=local; export TAR_FILENAME; tar xf archive.tar --to-command='rm \"$TAR_FILENAME\"'",
        "tar tf archive.tar -I 'gzip $MODE'",
        "tar tf archive.tar -I \"$unknown_command\"",
    ] {
        expect(command, Decision::NeedApproval, None);
    }
    expect(
        "OUTPUT=local; export OUTPUT; tar cf archive.tar input --checkpoint-action='exec=touch \"$OUTPUT\"'",
        Decision::Allow,
        Some("touch"),
    );
    expect(
        "TAR_ARCHIVE=local; export TAR_ARCHIVE; tar cf archive.tar input --checkpoint-action='exec=printf SAFE'; touch \"$TAR_ARCHIVE\"",
        Decision::Allow,
        Some("touch"),
    );
}

#[test]
fn archive_input_is_opaque_runtime_input_not_absent_or_caller_pipeline() {
    for command in [
        "tar xf archive.tar --to-command /bin/sh",
        "tar xf archive.tar -I '/bin/sh -c \"/bin/sh\"'",
        "tar cf archive.tar input --checkpoint-action=exec=/bin/sh",
    ] {
        let r = expect(command, Decision::NeedApproval, Some("sh"));
        assert!(
            r.reasons
                .iter()
                .any(|reason| reason.contains("runtime_input") && reason.contains("stdin_payload")),
            "{command}: {r:#?}"
        );
    }
    // FD ownership must select stdin execution, not a script named "0".
    // Listing isolates the runtime-input rule from archive-write policy.
    for command in [
        "tar xf /dev/null -I '/bin/sh -c \"/bin/sh 0<&2 1>&2\"'",
        "tar tf archive.tar -I '/bin/sh -c \"/bin/sh 0<&2 1>&2\"'",
    ] {
        let response = expect(command, Decision::NeedApproval, Some("sh"));
        assert!(
            response.decision_trace.execution_semantics.iter().any(|s| {
                s.normalized_command_name == "sh" && s.form_id == "stdin_script_implicit"
            }),
            "{command}: {response:#?}"
        );
        assert!(
            response.reasons.iter().any(|reason| {
                reason.contains("runtime_input") && reason.contains("stdin_payload")
            }),
            "{command}: {response:#?}"
        );
    }
    // A preceding literal stream must not be used as the archive member body.
    expect(
        "printf 'printf SAFE' | tar xf archive.tar --to-command sh",
        Decision::NeedApproval,
        Some("sh"),
    );
}

#[test]
fn malformed_or_unmodeled_strings_and_old_option_arities_keep_explicit_gaps() {
    for command in [
        "tar tf archive.tar -I 'gzip \"'",
        "tar tf archive.tar -I ''",
        "tar cf archive.tar input --checkpoint-action='exec='",
        "tar cIf gzip archive.tar input",
        "tar -c input",
    ] {
        expect(command, Decision::NeedApproval, None);
    }
    expect(
        "tar --help --checkpoint-action='exec=rm /opt/shared/file'",
        Decision::Allow,
        None,
    );
    expect(
        "tar --version --checkpoint-action='exec=rm /opt/shared/file'",
        Decision::Allow,
        None,
    );
}

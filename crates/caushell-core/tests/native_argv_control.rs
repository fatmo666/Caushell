//! Static modeling only: sample shell commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("native-argv"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    })
}
fn has_command(r: &CheckResponse, name: &str) -> bool {
    r.decision_trace
        .execution_semantics
        .iter()
        .any(|s| s.normalized_command_name == name)
}

#[test]
fn static_input_options_reach_tar_and_its_executable_callback() {
    for command in [
        r"tar -cf backup.tar --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input",
        r"printf '%s\0' --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input | xargs -0 tar -cf backup.tar",
        r"printf '%s\n' --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input | xargs -d '\n' tar -cf backup.tar",
        r"printf '%s\0' '--checkpoint-action=exec=rm /opt/shared/file' | xargs -0 -I{} tar -cf backup.tar --checkpoint=1 {} input",
        r"printf '%s\0' --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input | xargs -0 -p tar -cf backup.tar",
        r#"printf '%s\n' "'--checkpoint-action=exec=rm /opt/shared/file'" | xargs -I{} tar -cf backup.tar --checkpoint=1 {} input"#,
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
        assert!(has_command(&r, "rm"), "{command}: {r:#?}");
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::FileDeletion),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn unknown_native_options_and_variable_width_operands_require_resolution() {
    for command in [
        "cat args | xargs -0 tar -cf backup.tar",
        "cat args | xargs -I{} tar -cf backup.tar {}",
        "sed '2q;d' $FILE",
        "sed '2q;d' \"$FILE\"",
        "awk -v v1=$MYPID '$1==v1{print $3}' file",
        r#"printf '%s\0' 'input --checkpoint=1 --checkpoint-action=exec=rm${IFS}/opt/shared/file' | xargs -0 sh -c 'tar -cf backup.tar $1' _"#,
        r"printf '%s\0' --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input > args; xargs -0 -a args tar -cf backup.tar",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
        assert!(
            !has_command(&r, "rm"),
            "must not invent an unknown callback: {r:#?}"
        );
    }
}

#[test]
fn prior_session_argument_file_retains_option_data_and_callback_effects() {
    let mut core = ShellQueryCore::new();
    let mut request = CheckRequest {
        session_id: SessionId::new("native-argv-file"), sequence_no: CommandSequenceNo::new(1),
        command: r"printf '%s\0' --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input > args".into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"), shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()), workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {runtime_name: "static-test".into(), tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell()},
    };
    assert_eq!(core.check(request.clone()).decision, Decision::Allow);
    request.sequence_no = CommandSequenceNo::new(2);
    request.command = "xargs -0 -a args tar -cf backup.tar".into();
    let r = core.check(request);
    assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
    assert!(has_command(&r, "rm"), "{r:#?}");
}

#[test]
fn explicit_separator_keeps_control_shaped_input_as_data() {
    for command in [
        r"printf '%s\0' '--checkpoint-action=exec=rm /opt/shared/file' | xargs -0 tar -cf backup.tar --",
        r"printf '%s\0' 'file;rm /opt/shared/file' | xargs -0 tar -cf backup.tar --",
        "cat args | xargs -0 tar -cf backup.tar --",
        "sed '2q;d' -- \"$FILE\"",
        "awk -v v1=\"$MYPID\" '$1==v1{print $3}' file",
        "find ./input -print0 | xargs -0 tar -cf backup.tar",
        "find ~/Library -name '* *' -print0 | xargs -0 tar rf backup.tar",
        r#"find . -exec sh -c 'tar -cf backup.tar "$0"' {} \;"#,
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
        assert!(
            !has_command(&r, "rm"),
            "input bytes must not be parsed as shell code: {r:#?}"
        );
    }
}

#[test]
fn current_action_prelude_cannot_reuse_stale_argument_file_bytes() {
    let mut core = ShellQueryCore::new();
    let mut request = CheckRequest {
        session_id: SessionId::new("native-argv-stale"),
        sequence_no: CommandSequenceNo::new(1),
        command: "printf '%s\\0' input > args".into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    };
    assert_eq!(core.check(request.clone()).decision, Decision::Allow);
    request.sequence_no = CommandSequenceNo::new(2);
    request.command = r"printf '%s\0' --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input > args; xargs -0 -a args tar -cf backup.tar".into();
    let r = core.check(request);
    assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "tar" && s.operation_semantics_unresolved)
    );
}

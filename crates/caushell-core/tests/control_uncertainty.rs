//! Static checks only; no sample command is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("control-uncertainty"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "isolated-bash".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn only_reading_changes_or_errors_do_not_require_approval() {
    for command in [
        "ls \"$FILE\"",
        "ls -d */",
        "readlink -f \"$FILE\"",
        "md5sum \"$FILE\"",
        "du -sh *",
        "stat \"$FILE\"",
        "comm -23 <(sort a) <(sort b)",
        "join <(sort a) <(sort b)",
        "diff <(sort a) <(sort b)",
        "find . -type f -print0 | sort -z | xargs -0 md5sum",
        "find . -type f | xargs ls -l",
        r"sort -t$'\t' -k6V -k7n file",
        r"sort -t$'\t' -k2,2 | uniq -u | sort -k1,1 -t$'\t'",
        r#"awk -v hostname="$(hostname)" '{print hostname, $0}'"#,
        r"find htdocs cgi-bin -name '*.cgi' -type f -exec chmod 755 {} \;",
        r"find . -type f -print0 | xargs -0 perl -pi -e 's/old/new/g'",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn quoted_scalar_date_operand_retains_field_proof_without_blessing_empty_attached_ownership() {
    let separate = r#"touch -d "$(date --date="@$old_time")" B"#;
    assert_eq!(check(separate).decision, Decision::Allow);
    // Scalar width alone cannot certify the native short-option boundary:
    // an empty attached value may consume the next argv word instead.
    let attached = r#"touch -d"$(date --date="@$old_time")" B"#;
    assert_eq!(check(attached).decision, Decision::NeedApproval);
}

#[test]
fn independent_side_effects_and_real_native_control_uncertainty_are_preserved() {
    for command in [
        "ls \"$FILE\" > /opt/shared/output",
        "ls \"$FILE\"; rm file",
        "sudo ls \"$FILE\"",
        "comm -23 <(rm file; sort a) <(sort b)",
        "find . -type f | xargs tar -cf backup.tar",
        "tar -cf backup.tar *",
        "sort \"$FILE\"",
        "file \"$FILE\"",
        "sed '2q;d' \"$FILE\"",
        "awk -v value=$UNKNOWN '{print value}'",
        "lsof -u $UNKNOWN",
        r"printf '%s\0' --checkpoint=1 '--checkpoint-action=exec=rm /opt/shared/file' input | xargs -0 tar -cf backup.tar",
        r"find /opt/shared -type f -print0 | xargs -0 perl -pi -e 's/old/new/g'",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
    assert_eq!(check("ls \"$FILE\"; rm -rf /").decision, Decision::Deny);
}

#[test]
fn native_external_path_domain_survives_control_boundary_proof() {
    for command in [
        r"find /system -type f -exec rm {} +",
        r"find /var/tmp -type f -exec chmod 600 {} \;",
    ] {
        let mut core = ShellQueryCore::new();
        let session = SessionId::new("native-external-domain");
        let response = core.check(CheckRequest {
            session_id: session.clone(),
            sequence_no: CommandSequenceNo::new(1),
            command: command.into(),
            shell_state_before: ShellStateSnapshot::new("/workspace"),
            shell_kind: ShellKind::Bash,
            home: Some("/home/alice".into()),
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "isolated-bash".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        });
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {response:#?}"
        );
    }
}

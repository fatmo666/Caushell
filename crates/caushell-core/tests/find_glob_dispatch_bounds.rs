//! Static checks only: no find, link creation, or filesystem mutation executes.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("find-glob-dispatch-bounds"),
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
    }
}

fn expect(command: &str, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(request(command));
    assert_eq!(response.decision, expected, "{command}: {response:#?}");
    response
}

#[test]
fn filesystem_globs_retain_path_identity_for_local_link_creation() {
    for command in [
        r"find /usr/share/* -type f -exec ln -s -- {} \;",
        r"find /usr/share/* -type f -exec ln -s {} \;",
        r"find /home/folder1/*.txt -type f -exec ln -s {} \;",
        r"find /home/michael/foxpro/mount/A[1FV]/[12][0-9][0-9][0-9] -name '*.dbf' -type f -exec ln -s {} \;",
        r"find ../[12][0-9][0-9][0-9] -type f -exec ln -s {} \;",
        r"find /usr/share/* -type f -exec env ln -s -- {} \;",
        r"find ./src/* -type f -exec cp -- {} ./copy \;",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn local_mutations_preserve_relative_bounds_through_wrappers_and_shells() {
    for command in [
        r"find ./src/* -type f -exec chmod 644 -- {} \;",
        r"find ./src/* -type f -exec env touch -- {} \;",
        r#"find ./src/* -type f -exec sh -c 'touch -- "$1"' arg0 {} \;"#,
        r"find ./src/* -type f -exec touch -- {} +",
        r"find ./src/* -type f -exec touch -- {}.bak \;",
        r"find ./src/* -type f -execdir touch -- {} \;",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn external_or_unknown_execution_cwd_cannot_use_the_initial_workspace_bound() {
    for command in [
        r"cd /opt/shared; find ./src/* -type f -exec touch -- {} \;",
        r#"cd "$UNKNOWN"; find ./src/* -type f -exec touch -- {} \;"#,
        r"(cd /opt/shared; find ./src/* -type f -exec touch -- {} \;)",
        r"find /opt/shared/* -type f -exec touch -- {} \;",
        r"find /opt/shared/* -type f -execdir ln -s -- {} \;",
        r"find ../src/* -type f -exec touch -- {} \;",
        r"find -L ./src/* -type f -exec touch -- {} \;",
        r"find ~/src/* -type f -exec touch -- {} \;",
    ] {
        let response = expect(command, Decision::NeedApproval);
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

#[test]
fn uncertain_expansions_and_option_injection_keep_approval() {
    for command in [
        r"find ./$UNKNOWN/* -type f -exec touch -- {} \;",
        r"find ./src/*/../* -type f -exec touch -- {} \;",
        r"find ./{..,src}/* -type f -exec touch -- {} \;",
        r"find ./[.][.] -type f -exec touch -- {} \;",
        r"find * -type f -exec touch -- {} \;",
        r#"find "$UNKNOWN" -type f -exec ln -s -- {} \;"#,
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn known_argv_bytes_with_glob_characters_are_not_reexpanded() {
    for command in [
        r"find './src/*' -type f -exec touch -- {} \;",
        r#"root='./src/*'; find "$root" -type f -exec touch -- {} \;"#,
    ] {
        expect(command, Decision::Allow);
    }
    expect(
        r#"root='/opt/shared/*'; find "$root" -type f -exec touch -- {} \;"#,
        Decision::NeedApproval,
    );
}

#[test]
fn external_deletion_does_not_become_allowed() {
    for command in [
        r"find /opt/shared/* -type f -exec rm -- {} \;",
        r"find ./src/* -type f -exec rm -- {} \;",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn concrete_dangerous_child_effects_remain_denied() {
    for command in [
        r"find ./src/* -type f -exec rm -rf / \;",
        r"find /usr/share/* -type f -exec env rm -rf / \;",
    ] {
        expect(command, Decision::Deny);
    }
}

#[test]
fn disappearing_globs_do_not_hide_find_defaulting_to_the_execution_cwd() {
    for command in [
        r"cd /opt/shared; find ~/src/* -type f -exec touch -- {} \;",
        r"cd /opt/shared; find ~/src/* ~/other/* -type f -exec touch -- {} \;",
    ] {
        let mut req = request(command);
        req.home = Some("/bench/workspace".into());
        let response = ShellQueryCore::new().check(req);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
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

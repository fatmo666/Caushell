//! Only static guard checks; none of these commands are executed.
use caushell_core::ShellQueryCore;
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, RuleId, RuntimeMetadata, SessionId, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("argv-structure"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn bounded_dynamic_read_roots_and_reference_values_are_not_blanket_approved() {
    for command in [
        r#"find "./$dir" -print"#,
        r#"find ./"$dir" -print"#,
        "find /home/*/public_html -print",
        "find ./* -print",
        "find CACHE_* -print",
        "find /var/spool/{deferred,active}/ -print",
        "find /path/folder{1..50} -print",
        r#"find . -name "$pattern" -print"#,
        r#"find . -newer "/tmp/$stamp" -print"#,
        r#"find . -exec echo "./$value" \;"#,
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
        assert!(
            !result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn known_structure_does_not_turn_unknown_mutation_paths_into_local_paths() {
    for command in [
        r#"find "./$dir" -delete"#,
        "find /home/*/public_html -delete",
        "find /opt/{shared,cache}/ -delete",
        "find ./{..,cache} -delete",
        "cd /opt/shared; find /tmp/project/* -delete",
        r"cd /opt/shared; find /tmp/project/* -exec rm {} \;",
        r#"find . -fprint "./$output""#,
        r#"find . -exec rm "/opt/$target" \;"#,
        r#"find "./$dir" -exec rm {} \;"#,
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn root_controls_splitting_arrays_and_conditional_delimiters_keep_approval() {
    for command in [
        r#"find "$dir""#,
        "find ./$dir -print",
        "find . -name *.py -print",
        r#"find . -name "$@" -print"#,
        r#"find . -newer "$@" -delete"#,
        r#"find . -name "./${array[@]}" -print"#,
        "find {-delete,-print}",
        r#"find . -exec echo "{}$value" + extra \;"#,
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn known_variable_controls_and_external_child_effects_are_not_hidden() {
    for command in [
        r#"mode=-delete; cd /opt/shared; find "$mode""#,
        r#"set -- '*.py' '-delete'; find /opt/shared -name "$@""#,
        r#"find "./$dir" -exec rm /opt/shared/file \;"#,
        r#"find . -exec echo "./$value" \; -fprint /opt/output"#,
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn complete_parent_ownership_does_not_approve_unknown_shell_code() {
    for command in [
        r#"find . -exec bash "/tmp/$script" \;"#,
        r#"find . -exec sh "/tmp/$script" \;"#,
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
    }
}

#[test]
fn quoted_regex_anchors_and_scalar_substitutions_do_not_change_owned_operand_width() {
    for command in [
        r#"find . -regex ".*\\.rb$""#,
        r#"find . -regex "^.*~$\\|^.*#$""#,
        r#"find /home/ -type f -regex ".*(string1|$(hostname)).*""#,
        r#"find . -newermt "$(date -d @1494500000 '+%Y-%m-%d')" -print"#,
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
        assert!(
            !result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{command}: {result:?}"
        );
    }
    let result = ShellQueryCore::new().check(request(r#"find "./$(rm -rf /)" -print"#));
    assert_eq!(result.decision, Decision::Deny, "{result:?}");
}

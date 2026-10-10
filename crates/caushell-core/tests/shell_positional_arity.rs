//! Guard checks only: no sample shell commands execute.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("shell-positional-arity"),
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
    })
}

#[test]
fn unknown_width_arg0_is_not_a_known_empty_positional_list() {
    for command in [
        r#"find . -exec sh -c 'cp "$@" /opt/shared' {} +"#,
        r#"find . -exec sh -c 'shift; cp "$@" /opt/shared' {} +"#,
        r#"find . -exec sh -c 'cp "$2" /opt/shared' {} +"#,
        r#"producer | xargs -0 sh -c 'cp "$@" /opt/shared'"#,
        r#"producer | xargs -0 sh -c 'shift; cp "$@" /opt/shared'"#,
        r#"sh -c 'cp "$@" /opt/shared' "${arr[@]}""#,
        r#"sh -c 'cp "$@" /opt/shared' $args"#,
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "cp"),
            "{command}: {result:#?}"
        );
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:#?}"
        );
    }
}

#[test]
fn real_empty_lists_fixed_scalars_and_read_only_batches_still_pass() {
    for command in [
        r#"sh -c 'cp "$@" /opt/shared'"#,
        r#"sh -c 'cp "$@" /opt/shared' file"#,
        r#"sh -c 'cp "$@" ./cache' _ file"#,
        r#"find . -exec sh -c 'cp "$@" /opt/shared' {} \;"#,
        r#"producer | xargs -0 -I{} sh -c 'cp "$@" /opt/shared' {}"#,
        r#"find . -exec sh -c 'printf "%s\n" "$@"' {} +"#,
        r#"find . -exec sh -c 'echo okay' {} +"#,
        r#"find . -exec sh -c 'rm "$0"' {} \;"#,
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}

#[test]
fn scalar_domains_and_fixed_prefix_operands_are_retained() {
    for command in [
        r#"find /opt/shared -exec sh -c 'rm "$0"' {} \;"#,
        r#"find . -exec sh -c 'cp "$1" /opt/shared' _ {} \;"#,
        r#"find . -exec sh -c 'touch "$1"' _ /opt/shared/file {} +"#,
        r#"producer | xargs -0 -I{} sh -c 'cp "$1" /opt/shared' _ {}"#,
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
    }
    for command in [
        r"find -type d -exec find {} -maxdepth 1 \! -type d -iname '.note' \;",
        r#"find . -type d -name "cpp" -exec find {} -type f \;"#,
        r"find /opt/shared -exec find {} -type f \;",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
    let result = check(r"find /opt/shared -exec find {} -delete \;");
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
}

#[test]
fn positional_mutation_does_not_use_stale_numeric_startup_arguments() {
    for command in [
        r#"sh -c 'shift; touch "$1"' _ ./safe /opt/shared/file"#,
        r#"sh -c 'set -- /opt/shared/file; touch "$1"' _ ./safe"#,
        r#"sh -c 'shift "$count"; touch "$1"' _ ./safe /opt/shared/file"#,
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
    }
    for command in [
        r#"sh -c 'shift; touch "$1"' _ /opt/shared/file ./safe"#,
        r#"sh -c 'set -- ./safe; touch "$1"' _ /opt/shared/file"#,
        r#"sh -c 'shift nonsense; touch "$1"' _ ./safe /opt/shared/file"#,
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {result:#?}");
    }
}

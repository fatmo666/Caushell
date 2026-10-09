//! Static guard/Graph regression. Sample shell commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("stdout-shape-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "stdout-shape-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn quoted_absolute_outputs_do_not_manufacture_find_controls() {
    for command in [
        "find \"$(pwd)\" -type f",
        "find \"`pwd`\" -type f",
        "find \"$(pwd -P)\" -mtime 0 -print",
        "find \"$(pwd -L)\" -type d -print",
        "find \"$(/bin/pwd -P)\" -type f",
        "find \"$(pwd)/child\" -type f",
        r#"find "$("pwd")" -type f"#,
        r#"find "$('pwd')" -type f"#,
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "pwd"),
            "producer must stay in Graph: {response:#?}"
        );
    }
}

#[test]
fn no_proof_for_unquoted_mixed_or_incomplete_output() {
    for command in [
        "find $(pwd) -type f",
        "find `pwd` -type f",
        "find \"$(pwd; printf '%s' -delete)\" -type f",
        "find \"$(if true; then pwd; fi)\" -type f",
        "find \"$(pwd | cat)\" -type f",
        "find \"$(pwd 2>&1)\" -type f",
        "find \"$(pwd --help)\" -type f",
        "find \"$(pwd --version)\" -type f",
        "find \"$(pwd --unknown)\" -type f",
        "find \"$(pwd unexpected)\" -type f",
        "find \"$(pwd $options)\" -type f",
        "find \"$(pwd)$(other)\" -type f",
        "find \"$(pwd)\"$suffix -type f",
        "find \"$(pwd)-delete\" -type f",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn stdout_shape_does_not_authorize_unknown_mutation_paths() {
    for command in [
        "find \"$(pwd)\" -delete",
        "rm -rf \"$(pwd -P)\"",
        "chmod 777 \"$(pwd)\"",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn known_shadowing_does_not_borrow_the_builtin_contract() {
    for command in [
        "pwd() { printf '%s' -delete; }; find \"$(pwd)\" -type f",
        "pwd() { printf '%s' -delete; }; env find \"$(pwd)\" -type f",
        r#"pwd() { printf '%s' -delete; }; find "$(\pwd)" -type f"#,
        r#"pwd() { printf '%s' -delete; }; find "$("pwd")" -type f"#,
        r#"pwd() { printf '%s' -delete; }; find "$('pwd')" -type f"#,
        r#"pwd() { printf '%s' -delete; }; target=pwd; find "$("$target")" -type f"#,
        r#"pwd() { printf '%s' -delete; }; env find "$("pwd")" -type f"#,
        "alias pwd='printf %s -delete'; find \"$(pwd)\" -type f",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
    let mut input = request("find \"$(pwd)\" -type f");
    input
        .shell_state_before
        .aliases
        .push(ShellAliasSnapshot::new("pwd", "printf %s -delete"));
    assert_ne!(ShellQueryCore::new().check(input).decision, Decision::Allow);
}

#[test]
fn directory_changes_do_not_turn_a_shape_into_a_cwd_value() {
    let response = ShellQueryCore::new().check(request("cd /opt; find \"$(pwd -P)\" -delete"));
    assert_ne!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn nested_shell_and_dispatch_use_the_same_proof_without_stale_gaps() {
    for command in [
        "bash -c 'find \"$(pwd)\" -type f'",
        "env find \"$(pwd -P)\" -type f",
        "env env find \"$(pwd)\" -type f",
        "sh -c 'find \"$(pwd)\" -type f'",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn snapshots_and_expansion_limits_keep_conservative_boundaries() {
    let mut input = request("find \"$(pwd)\" -type f");
    input
        .shell_state_before
        .functions
        .push(ShellFunctionSnapshot::new("pwd", "printf '%s' -delete"));
    assert_ne!(ShellQueryCore::new().check(input).decision, Decision::Allow);
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 0;
    let response = ShellQueryCore::with_policy(policy).check(request("find \"$(pwd)\" -type f"));
    assert_ne!(response.decision, Decision::Allow, "{response:#?}");
}

//! Judge-only controls; these shell command strings are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("native-stdout"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/work/project")
            .with_function_knowledge(ShellStateKnowledge::Complete)
            .with_alias_knowledge(ShellStateKnowledge::Complete),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/work/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}
#[test]
fn format_and_octal_suffixes_reach_the_execution_graph() {
    for command in [
        r"printf 'printf SAFE\c; rm -rf /' | sh",
        r"printf '%b' 'printf SAFE\0073 rm -rf /' | sh",
        r"echo -e 'printf SAFE\0073 rm -rf /' | sh",
        r"printf 'printf SAFE\q; rm -rf /' | sh",
        r"printf '%s' 'printf SAFE\c; rm -rf /' | sh",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Deny, "{command}: {r:#?}");
    }
}
#[test]
fn every_static_source_consumer_retains_the_same_dangerous_tail() {
    for command in [
        r"printf 'printf SAFE\c; rm -rf /' > payload.sh; sh payload.sh",
        r"sh < <(printf 'printf SAFE\c; rm -rf /')",
        r#"sh <<< "$(printf 'printf SAFE\c; rm -rf /')""#,
        r#"bash -c "printf 'printf SAFE\c; rm -rf /' | sh""#,
        r"command printf 'printf SAFE\c; rm -rf /' | sh",
        r"builtin printf 'printf SAFE\c; rm -rf /' | sh",
    ] {
        let r = check(command);
        assert_ne!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}
#[test]
fn percent_b_stop_is_real_and_does_not_reparse_string_data() {
    for command in [
        r"printf '%b' 'printf SAFE\c; rm -rf /' | sh",
        r"echo -e 'printf SAFE\c; rm -rf /' | sh",
        r"printf 'printf SAFE\n' | sh",
        r"printf -- '%s' 'printf SAFE' | sh",
        r"printf '%s' 'literal \c and %n'",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}
#[test]
fn missing_origin_or_bytes_never_become_a_complete_bash_program() {
    for command in [
        r#"sh -c "printf 'printf SAFE\c; rm -rf /' | sh""#,
        r"/usr/bin/printf 'printf SAFE\c; rm -rf /' | sh",
        r"env printf 'printf SAFE\c; rm -rf /' | sh",
        r"printf '\xff' | sh",
        r"printf 'printf SAFE\0; rm -rf /' | sh",
        r"printf '\u0072\u006d -rf /' | sh",
        r#"printf "$format" | sh"#,
        r"printf $fields | sh",
        r"f=echo; printf -v f '%s' unknown-program; $f owned",
        r"printf -v 'slots[$(printf MARKER >&2)]' '%s' owned",
    ] {
        let r = check(command);
        assert_ne!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

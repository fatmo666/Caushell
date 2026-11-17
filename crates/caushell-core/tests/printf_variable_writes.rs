//! Static judge-only checks; no command under test is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("printf-variables"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/work/project")
            .with_variable_knowledge(ShellStateKnowledge::Unknown)
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
fn unknown_or_array_destinations_never_bypass_target_validation() {
    for command in [
        "printf -v 'slots[$(printf MARKER >&2)]' '%s' owned",
        "command printf -v 'slots[$(printf MARKER >&2)]' '%s' owned",
        "builtin printf -v 'slots[$(printf MARKER >&2)]' '%s' owned",
        "bash -c \"printf -v 'slots[1]' '%s' owned\"",
        "printf -v \"$destination\" '%s' owned",
        "printf \"$format\" owned",
        "printf \"operator: $format\" target",
        "printf \"operator: $format\" | sh",
        "printf -- \"$format\" | sh",
        "printf '%n' \"$destination\"",
    ] {
        let r = check(command);
        assert_ne!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}
#[test]
fn writes_retire_stale_variable_values_before_later_execution() {
    for command in [
        "target=echo; printf -v target '%s' unknown-program; $target owned",
        "target=echo; printf '%n' target; $target owned",
        "target=echo; printf -v \"$destination\" '%s' unknown-program; $target owned",
        "target=echo; printf '%s%n' a target; $target owned",
        "target=echo; printf '%*s%n' 2 a target; $target owned",
        "target=echo; declare -n ref=target; printf -v ref '%s' unknown-program; $target owned",
    ] {
        let r = check(command);
        assert_ne!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

#[test]
fn known_unset_format_is_empty_instead_of_an_unknown_writer() {
    let r = check("unset format; printf \"$format\" owned");
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
}
#[test]
fn ordinary_data_external_programs_and_boundaries_remain_usable() {
    for command in [
        "printf '%s' owned",
        "printf '%n'",
        "printf \"operator: $format\"",
        "printf -- \"$format\"",
        "printf '%s' \"$@\"",
        "printf '%%n%s' owned",
        "printf -- '-v %s' owned",
        "printf '%s' -v target",
        "printf '%(%n)T' 0",
        "printf -v target '%s' owned",
        "printf 'x%n' count",
        "env printf -v target '%s' owned",
        "/usr/bin/printf -v target '%s' owned",
        "target=echo; /usr/bin/printf -v target '%s' unknown-program; $target owned",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

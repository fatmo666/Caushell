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

#[test]
fn plain_hex_capture_is_a_data_only_printf_format() {
    for command in [
        "v=$(echo 'F% !' | xxd -p); printf $v",
        "v=$(echo 'F% !' | xxd -ps -c 2); printf $v",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.execution_semantics.iter().any(|item| {
            item.normalized_command_name == "printf" && !item.operation_semantics_unresolved
        }));
    }
}

#[test]
fn plain_hex_format_proof_does_not_escape_its_capture_or_reference() {
    for command in [
        "v=$(echo '25' | xxd -r -p); printf $v",
        "v=$(echo 'F' | xxd -p; echo literal); printf $v",
        "v=$(echo 'F' | xxd -p 2>&1); printf $v",
        "xxd() { echo literal; }; v=$(echo 'F' | xxd -p); printf $v",
        "v=$(echo 'F' | xxd -p); v=$unknown; printf $v",
        "(v=$(echo 'F' | xxd -p)); printf $v",
        "v=$(echo 'F' | xxd -p); printf -v \"$destination\" $v",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}: {:?}", result.reasons);
    }
}

#[test]
fn raw_base64_capture_is_a_data_only_printf_format() {
    for command in [
        "v=$(echo 'demo % text' | b64encode -r -); printf $v",
        "v=$(echo 'fixture' | b64encode -r fixture-output); printf \"$v\"",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|item| {
                    item.normalized_command_name == "printf"
                        && !item.operation_semantics_unresolved
                        && !item.mutates_current_shell
                })
        );
    }
}

#[test]
fn raw_base64_format_proof_requires_the_complete_capture() {
    for command in [
        "v=$(echo 'fixture' | b64encode fixture-output); printf $v",
        "v=$(echo 'fixture' | b64encode -r input.txt fixture-output); printf $v",
        "v=$(echo 'fixture' | b64encode -r - 2>&1); printf $v",
        "v=$(echo 'fixture' | b64encode -r -; echo suffix); printf $v",
        "v=$(echo 'Zg==' | b64decode -r); printf $v",
        "b64encode() { echo literal; }; v=$(echo 'fixture' | b64encode -r -); printf $v",
        "v=$(echo 'fixture' | b64encode -r -); v=$unknown; printf $v",
        "v=$(echo 'fixture' | b64encode -r -); printf -v \"$destination\" $v",
    ] {
        let result = check(command);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            result.reasons
        );
    }
}

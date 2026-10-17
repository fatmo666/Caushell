//! Static checks only: make commands, recipes and shell payloads never execute.
use caushell_core::ShellQueryCore;
use caushell_types::*;
fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("make-native"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/benchmark-user".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}
fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(request(command));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    r
}
#[test]
fn explicit_eval_needs_approval_including_print_and_question_modes() {
    for c in [
        "make -s --eval='$(file >/path/to/output-file,DATA)' .",
        "make --eval='$(shell /bin/sh 1>&0)' .",
        "make -n --eval='$(shell /bin/sh)'",
        "make -q -E'$(file >/opt/out,DATA)'",
        "make -p --eval '$(shell /bin/sh)'",
        "make -t --eval='$(shell /bin/sh)'",
        "gmake -sE '$(shell /bin/sh)'",
        "make all --eval='$(shell /bin/sh)'",
        "make --eval='X=1' -E '$(shell /bin/sh)'",
        "env make --eval='$(shell /bin/sh)'",
        "bash -c 'make --eval=\"X=1\"'",
        "find . -type d -exec make --eval='$(shell /bin/sh)' \\;",
        "cat input | xargs -r -I {} make --eval='{}'",
    ] {
        let r = check(c, Decision::NeedApproval);
        if c.contains("xargs") {
            assert!(
                r.decision_trace.decision_proposals.iter().any(|p| matches!(
                    p.rule_id,
                    RuleId::NestedPayloadExpansion | RuleId::SelectionError
                )),
                "{c}: {:?}",
                r.reasons
            );
        } else {
            assert!(
                r.decision_trace
                    .decision_proposals
                    .iter()
                    .any(|p| p.rule_id == RuleId::NestedPayloadExpansion),
                "{c}: {:?}",
                r.reasons
            );
            assert!(
                r.decision_trace
                    .execution_semantics
                    .iter()
                    .any(
                        |s| matches!(s.normalized_command_name.as_str(), "make" | "gmake")
                            && s.executes_payload
                    ),
                "{c}: {:?}",
                r.reasons
            );
        }
    }
}
#[test]
fn normal_local_builds_and_literal_assignments_keep_the_existing_policy() {
    for c in [
        "make",
        "make all",
        "gmake -j8 all",
        "make -j 8 all",
        "make --jobs=4 -l2.5 -Otarget all",
        "make --warn-undefined-variables --jobserver-style=pipe all",
        "make -e CFLAGS=-O2",
        "K_VERSION=6.0; make \"K_VERSION=$K_VERSION\"",
        "make -f local.mk all",
        "make --file=first.mk --makefile=second.mk",
        "make -- --eval=not-code",
    ] {
        check(c, Decision::Allow);
    }
}
#[test]
fn explicit_makefile_code_paths_use_the_existing_path_guard() {
    for c in [
        "make -f /opt/rules.mk",
        "make -f local.mk -f /opt/rules.mk",
        "make --makefile=\"$RULES\"",
        "env -C /opt make -f rules.mk",
    ] {
        check(c, Decision::NeedApproval);
    }
    for c in [
        "make -f /tmp/rules.mk",
        "make --makefile=/private/tmp/rules.mk",
        "env -C /tmp make",
    ] {
        check(c, Decision::Allow);
    }
}
#[test]
fn native_assignment_code_and_stdin_makefiles_are_not_plain_goals() {
    for c in [
        "make 'X!=/bin/sh'",
        "make 'X:=$(shell /bin/sh)'",
        "make 'X=$(file >/opt/out,DATA)'",
        "make -f -",
        "printf '%s\\n' 'X=1' | make -f -",
    ] {
        check(c, Decision::NeedApproval);
    }
}

#[test]
fn make_source_is_not_treated_as_bash_or_assumed_pure() {
    check(
        "make -s --eval='$(file >/dev/stdout,$(file </path/to/input-file))' .",
        Decision::NeedApproval,
    );
}
#[test]
fn unknown_options_missing_operands_and_directory_changes_do_not_silently_pass() {
    for c in [
        "make --unknown=one",
        "make --eval",
        "make -E",
        "make -f",
        "make -C sub",
        "make -C / -C etc",
        "make --directory=/opt -f rules.mk",
        "make K_VERSION=`uname -r`",
    ] {
        check(c, Decision::NeedApproval);
    }
}
#[test]
fn help_and_version_stop_make_evaluation_but_not_outer_shell_effects() {
    for c in [
        "make --help --eval='$(shell /bin/sh)'",
        "make -v --eval='$(shell /bin/sh)'",
        "make --help -f /opt/rules.mk",
    ] {
        check(c, Decision::Allow);
    }
    check(
        "make --help --eval=\"$(touch /opt/out)\"",
        Decision::NeedApproval,
    );
    check("make --help 'X:=$(shell /bin/sh)'", Decision::NeedApproval);
    check("make --version 'X!=/bin/sh'", Decision::NeedApproval);
}

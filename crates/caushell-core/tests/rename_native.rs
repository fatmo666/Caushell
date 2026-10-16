//! Static checks only: no rename, Perl or benchmark command is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("rename-native"),
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
    assert_eq!(r.decision, expected, "{command}: {r:#?}");
    r
}

#[test]
fn complete_supported_local_transforms_are_allowed() {
    for command in [
        "rename 's/^/new./' original.filename",
        "rename 's/(.*)$/new.$1/' original.filename",
        "rename 's/x/y/' x1 x2",
        "rename -v 's/\\.JPG$/.jpeg/' one.JPG",
        "rename.ul foo bar foo1 foo2",
        "file-rename -e 's/x/y/' x1 x2",
        "prename 'y/A-Z/a-z/' FOO.TXT",
        "rename --help",
        "file-rename --version",
        "rename.ul -n './' '/opt/out/' ./file",
        "rename -n 's/x/y/' /opt/x",
        "file-rename -d 's/foo/bar/' ./foo/foo.txt",
        "value=one.JPG; rename 's/\\.JPG$/.jpeg/' \"$value\"",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn destination_and_source_outside_workspace_both_require_approval() {
    for command in [
        "rename.ul './' '/opt/out/' ./file",
        "file-rename 's@^@/opt/out/@' file",
        "file-rename 's/x/../' x",
        "rename.ul x ../x x",
        "file-rename 's/foo/bar/' /opt/foo",
        "rename 's/x/y/' /opt/x",
        "rename 's/a/b/' -n /opt/a",
        "file-rename -- 's/a/b/' -n /opt/a",
    ] {
        check(command, Decision::NeedApproval);
    }
    let r = check("rename.ul './' '/opt/out/' ./file", Decision::NeedApproval);
    assert!(
        r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation)
    );
}

#[test]
fn opaque_or_unknown_perl_is_not_waived_by_dry_run_or_util_argument_count() {
    for command in [
        "rename -n 'system(\"id\")' file",
        "rename --no-act 'system(\"id\")' file",
        "file-rename -n 's/x/y/e' x",
        "file-rename -n 's/x/y/; unlink($_)' x",
        "file-rename 's/(?{system(\"id\")})/x/' x",
        "rename unlink a b",
        "rename foo bar file",
        "file-rename 's/x/$ENV{HOME}/' x",
        "file-rename -u 's/x/y/' x",
        "file-rename \"$PROGRAM\" file",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|f| f.rule_id == RuleId::NestedPayloadExpansion),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn wrappers_and_single_field_dispatch_preserve_native_target_facts() {
    for command in [
        "env rename 's/x/y/' x",
        "bash -c 'rename \"s/x/y/\" x'",
        "find . -name '*.t1' -exec rename 's/\\.t1$/.t2/' '{}' \\;",
        "find . -name '* *' -execdir file-rename 's/ /_/g' '{}' \\;",
        "find . -name '*.t1' -exec file-rename 's/\\.t1$/.t2/' '{}' +",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "env rename.ul './' '/opt/out/' ./file",
        "find . -type f -exec file-rename 's@^@/opt/out/@' '{}' \\;",
        "find . -type f -exec file-rename 's/\\.compiled$//' '{}' \\;",
        "find . -type f -exec rename 's/\\.t1$/.t2/' '{}' +",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn complete_stdin_is_filename_data_while_unknown_stdin_stays_unknown() {
    for command in [
        "printf './one x.txt\\n' | rename 's/ /_/g'",
        "printf './x.txt\\0' | file-rename -0 's/x/y/'",
        "printf './x$(id)\\n' | file-rename 's/x/y/'",
    ] {
        check(command, Decision::Allow);
    }
    for command in [
        "find . -type f | rename 's/ /_/g'",
        "printf '/opt/x\\n' | file-rename 's/x/y/'",
        "cat file-list | file-rename 's/x/y/'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn read_only_modes_do_not_waive_shell_substitution_effects() {
    for command in [
        "rename --help \"$(touch /opt/out)\"",
        "rename.ul -n foo bar \"$(touch /opt/out)\"",
    ] {
        check(command, Decision::NeedApproval);
    }
}

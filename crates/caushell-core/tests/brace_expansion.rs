//! Static checks only: none of these shell commands is executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let request = CheckRequest {
        session_id: SessionId::new("brace-expansion"),
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
    };
    let r = ShellQueryCore::new().check(request);
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    r
}

#[test]
fn known_local_expansion_reaches_existing_path_guards_and_native_forms() {
    for command in [
        "mkdir -p project/{lib/ext,bin,src,doc/{html,info,pdf},demo/stat/a}",
        "mkdir -p directory{1..3}/subdirectory{1..3}/subsubdirectory{1..2}",
        "mkdir -p path2/{a..z}",
        "touch -a UEDP0{1..5}_20120821.csv",
        "mkdir Labs/lab4a/{folder1,myfolder,foofolder}",
        "mv {,new.}original.filename",
        "touch cache/{01..03}",
        "env touch cache/{a,b}",
        "bash -c 'touch cache/{a,b}'",
        "f() { touch \"$1\" \"$2\"; }; f cache/{a,b}",
        "find . -exec touch cache/{a,b} \\;",
        "for f in cache/{a,b}; do touch \"$f\"; done",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn one_outside_alternative_is_not_hidden_by_local_alternatives() {
    for command in [
        "touch {cache/file,/opt/file}",
        "mkdir -p {cache,/opt}/dir",
        "touch cache/{ok,../../../../opt/out}",
        "mv cache/file {cache/renamed,/opt/out}",
        "env touch {cache/file,/opt/file}",
        "bash -c 'touch {cache/file,/opt/file}'",
        "find {./cache,/opt} -type d -exec touch '{}/out' \\;",
        "for f in {cache/file,/opt/file}; do touch \"$f\"; done",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn expansion_generated_options_do_not_acquire_a_readonly_waiver() {
    for command in [
        "find . -{print,delete}",
        "touch {--reference=/opt/input,/opt/out}",
        "make {--eval=,}'$(shell /bin/sh)'",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn quotes_escaped_syntax_and_native_child_argv_stay_data() {
    for command in [
        "touch 'cache/{a,b}'",
        "touch \"cache/{1..3}\"",
        "touch cache/\\{a,b\\}",
        "X='cache/{a,b}'; touch \"$X\"",
        "printf '%s\\0' 'cache/{a,b}' | xargs -0 -r touch",
    ] {
        check(command, Decision::Allow);
    }
    check("X='/opt/{a,b}'; touch \"$X\"", Decision::NeedApproval);
}

#[test]
fn huge_and_unsupported_expansions_are_bounded_not_partially_allowed() {
    for command in [
        "touch cache/{1..10000}",
        "echo {1..10000}",
        "bash -c 'echo {1..10000}'",
        "touch cache/{1..20}{1..20}",
        "touch cache/{a,b}$UNKNOWN",
    ] {
        check(command, Decision::NeedApproval);
    }
    check("sh -c 'echo {1..10000}'", Decision::Allow);
}

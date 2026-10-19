//! End-to-end policy checks for audited native Profile forms; no submitted command executes.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("profile-gap-forms"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
    })
}

fn expect(command: &str, expected: Decision) -> CheckResponse {
    let result = check(command);
    assert_eq!(result.decision, expected, "{command}: {result:#?}");
    assert!(
        !result
            .decision_trace
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::NoProfile),
        "{command}: {result:#?}"
    );
    result
}

#[test]
fn information_queries_remain_allowed_and_distinct_from_wrappers() {
    for command in [
        "sudo -l",
        "grep --help",
        "ssh -V",
        "gcc -print-search-dirs",
        "npm config get prefix",
        "git help",
        "cargo help doc",
        "brew --version",
    ] {
        expect(command, Decision::Allow);
    }

    // No environment fact proves HOMEBREW_CACHE's destination in this request.
    // Diagnose is not a child command, but its unknown configured write remains.
    let doctor = expect("brew doctor", Decision::NeedApproval);
    assert!(
        doctor
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
    );

    let sudo = expect("sudo -l", Decision::Allow);
    assert!(
        !sudo
            .decision_trace
            .execution_semantics
            .iter()
            .any(|semantics| {
                semantics.normalized_command_name == "sudo" && semantics.dispatches_child_command
            }),
        "{sudo:#?}"
    );
}

#[test]
fn external_execution_and_system_transactions_keep_approval_candidates() {
    for command in [
        "apt-get update -o APT::Update::Pre-Invoke::=/bin/sh",
        "pip config --editor '/bin/sh -s' edit",
        "rpm -Uvh https://example.test/package.rpm",
        "yum groupinstall 'Development Tools'",
        "killall -u alice dropbox",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn local_queries_and_explicit_worktree_reads_keep_their_scopes() {
    for command in [
        "java -jar program.jar",
        "git -c color.status=always status",
        "git grep '^needle' src/file.rs",
        "git whatchanged --all",
        "git symbolic-ref HEAD",
        "npm -C . i example-package",
        "ffmpeg -i input.m4a -aq 6 -vn -ac 2 output.ogg",
        "tshark -c 5 -i eth0",
        "nmap -Pn -sS -sV -p 80 192.0.2.1",
        "octave -q --eval 'disp(1)'",
        "kill -SIGINT 123",
        "aspell check text.txt",
        "hg st -R /tmp/project",
        "vagrant ssh-config --host default",
        "composer validate composer.json",
        "fd",
        "latexmk -c",
    ] {
        let response = check(command);
        assert!(
            !response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::NoProfile),
            "{command}: {response:#?}"
        );
    }
}

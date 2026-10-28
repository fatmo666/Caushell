//! Policy checks only: submitted programs and download commands never execute.
use caushell_core::ShellQueryCore;
use caushell_runner::FilesystemView;
use caushell_types::*;
use std::sync::Arc;

fn request(command: &str, sequence: u64) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
        .with_environment_observation("ENV", ShellEnvironmentValue::Absent)
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    shell.observability.variables = ShellStateKnowledge::Complete;
    shell.observability.aliases = ShellStateKnowledge::Complete;
    shell.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("file-execution-authorization"),
        sequence_no: CommandSequenceNo(sequence),
        command: command.into(),
        shell_state_before: shell,
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(command: &str, expected: Decision) {
    let result = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(result.decision, expected, "{command}: {result:#?}");
}

#[test]
fn local_file_execution_uses_one_scope_across_program_languages() {
    for command in [
        "./build/tool",
        "/workspace/build/tool",
        "/tmp/tool",
        "python3 ./main.py",
        "python3 /tmp/main.py",
        "python3 /private/tmp/main.py",
        "python3 -I -S ./main.py",
        "perl ./main.pl",
        "node ./main.js",
        "ruby ./main.rb",
        "lua ./main.lua",
        "php -f ./main.php",
        "julia ./main.jl",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn wrappers_aliases_functions_and_callbacks_keep_the_execution_file_owner() {
    for command in [
        "env python3 ./main.py",
        "timeout 5 node ./main.js",
        "command perl ./main.pl",
        "exec ruby ./main.rb",
        "bash -c 'node ./main.js'",
        "entry=./main.py; python3 \"$entry\"",
        "alias run='node ./main.js'; run",
        "run() { perl ./main.pl; }; run",
        "find . -exec node ./main.js {} \\;",
        "printf '%s\\n' arg | xargs python3 ./main.py",
        "cd /workspace/sub; lua ../main.lua",
        "cd /outside; python3 /workspace/main.py",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn outside_and_unknown_execution_locations_keep_approval() {
    for command in [
        "/outside/tool",
        "python3 /outside/main.py",
        "node ../outside/main.js",
        "perl /workspace/../outside/main.pl",
        "lua \"$UNKNOWN\"",
        "python3 \"$(cat entry.txt)\"",
        "cd /outside; ruby ./main.rb",
        "cd \"$UNKNOWN\"; node ./main.js",
        "env -C /outside python3 ./main.py",
    ] {
        expect(command, Decision::NeedApproval);
    }
    let mut req = request("python3 ./main.py", 1);
    req.workspace_root = None;
    assert_eq!(
        ShellQueryCore::new().check(req).decision,
        Decision::NeedApproval
    );
}

#[test]
fn inline_stdin_and_module_entries_are_not_file_execution_grants() {
    for command in [
        "python3 -c pass",
        "node -e '1+2'",
        "perl -e 1",
        "ruby -e 1",
        "lua -e 'x=1'",
        "python3 -m unknown_module",
        "python3 - < ./main.py",
        "python3 < ./main.py",
        "printf pass | python3",
        "python3 <<'PY'\npass\nPY",
        "python3 /dev/fd/3 3<./main.py",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn a_local_file_grant_cannot_cover_a_sibling_payload_or_risk() {
    for command in [
        "python3 ./main.py; perl -e 1",
        "node ./main.js; python3 -m unknown_module",
        "perl ./main.pl; touch /outside/result",
        "python3 ./main.py > /outside/output",
    ] {
        expect(command, Decision::NeedApproval);
    }
    for command in [
        "python3 ./main.py; rm -rf /",
        "rm -rf /; node ./main.js",
        "bash -c 'perl ./main.pl; rm -rf /'",
        "python3 ./main.py; python3 -c 'import shutil; shutil.rmtree(\"/\")'",
    ] {
        expect(command, Decision::Deny);
    }
}

#[test]
fn an_explicit_non_shell_deny_is_never_erased_by_a_file_grant() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::NonShellScriptExecution,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    for command in ["python3 ./main.py", "node /tmp/main.js", "perl -e 1"] {
        let result = ShellQueryCore::with_policy(policy.clone()).check(request(command, 1));
        assert_eq!(result.decision, Decision::Deny, "{command}: {result:#?}");
    }
}

#[test]
fn downloaded_files_keep_tainted_execution_for_every_file_entry() {
    for entry in [
        "./code",
        "python3 ./code",
        "node ./code",
        "perl ./code",
        "bash ./code",
    ] {
        let mut core = ShellQueryCore::new();
        let download = core.check(request("curl -q -o ./code https://example.test/code", 1));
        assert_eq!(download.decision, Decision::Allow, "{download:#?}");
        let result = core.check(request(entry, 2));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{entry}: {result:#?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::TaintedExecution),
            "{entry}: {result:#?}"
        );
    }
    expect(
        "curl -q -o /tmp/code https://example.test/code; node /tmp/code",
        Decision::NeedApproval,
    );
}

struct Links;
impl FilesystemView for Links {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if path == "/workspace/link" {
            FilesystemEntry::Symlink {
                target: "/outside".into(),
            }
        } else {
            FilesystemEntry::Directory
        }
    }
}

#[test]
fn file_execution_uses_the_resolved_target_not_a_workspace_prefix() {
    for command in [
        "./link/tool",
        "python3 ./link/main.py",
        "node ./link/main.js",
    ] {
        let result = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(Links))
            .check(request(command, 1));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:#?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceScriptSource)
        );
    }
}

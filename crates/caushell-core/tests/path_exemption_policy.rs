//! Static guard checks; no fixture command is executed or file read.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("path-policy"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    })
}

#[test]
fn file_execution_policy_is_language_independent_and_consumer_local() {
    for command in [
        "bash ./hello.sh",
        "python ./hello.py",
        "python /tmp/hello.py",
        "node ./app.js",
        "awk -f ./helper.awk input",
        "sed -f ./commands.sed input",
        "java -jar /tmp/app.jar",
        "env python ./hello.py",
        "bash -c 'python ./hello.py'",
        "env bash -c 'python ./hello.py'",
        "bash -c 'bash -c \"python ./hello.py\"'",
        "find . -name '*.txt' -exec python ./worker.py '{}' +",
        "find . -type f -print0 | xargs -0 python ./worker.py",
    ] {
        let r = check(command);
        assert_eq!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
    for command in [
        "bash /opt/hello.sh",
        "python /opt/hello.py",
        "node /opt/app.js",
        "awk -f /opt/helper.awk input",
        "python \"$UNKNOWN\"",
        "python /tmp-evil/hello.py",
        "python ./../opt/hello.py",
        "python ./safe.py; python /opt/other.py",
        "env python /opt/other.py",
        "find . -type f -exec python /opt/worker.py '{}' +",
        "bash -c 'python ./safe.py; python /opt/other.py'",
        "bash -c 'python ./safe.py; python -c \"print(1)\"'",
        "env bash -c 'python /opt/other.py'",
        "bash -c 'cd /opt; python ./other.py'",
        "bash -c 'bash -c \"python /opt/other.py\"'",
    ] {
        let r = check(command);
        assert_ne!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

#[test]
fn file_location_does_not_exempt_stream_code_or_other_effects() {
    for command in [
        "python -c 'print(1)'",
        "node -e 'console.log(1)'",
        "cat input | python -",
        "sed -f - input",
        "awk -f /dev/stdin input",
        "python /dev/stdin",
        "python <(printf 'print(1)')",
        "python ./safe.py; rm ./user-file",
        "python ./safe.py; python -c 'print(1)'",
        "python ./safe.py > /opt/output",
        "printf 'rm ./owned\\n' >./safe.sh; bash ./safe.sh",
    ] {
        let r = check(command);
        assert_ne!(r.decision, Decision::Allow, "{command}: {r:#?}");
    }
}

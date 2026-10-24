use caushell_core::ShellQueryCore;
use caushell_runner::FilesystemView;
use caushell_types::*;
use std::sync::Arc;

struct Files;
impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if matches!(path, "/" | "/workspace" | "/outside") {
            FilesystemEntry::Directory
        } else {
            FilesystemEntry::Missing
        }
    }
}
fn check(command: &str) -> CheckResponse {
    let mut shell = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    shell.observability.variables = ShellStateKnowledge::Complete;
    shell.observability.aliases = ShellStateKnowledge::Complete;
    shell.observability.functions = ShellStateKnowledge::Complete;
    let request = CheckRequest {
        session_id: SessionId::new("python-program"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: shell,
        shell_kind: ShellKind::Bash,
        home: None,
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    };
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(Files))
        .check(request)
}
fn proof(response: &CheckResponse) -> &PythonPayloadEvidence {
    response
        .decision_trace
        .evidence
        .iter()
        .find_map(|e| match &e.kind {
            EvidenceKind::PythonPayload(p) => Some(p),
            _ => None,
        })
        .expect("Python evidence")
}
#[test]
fn python_isolated_pure_program_has_a_language_proof_not_a_shell_parse() {
    let r = check("python3 -I -S -c 'print(1)' ");
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    assert!(proof(&r).complete);
    assert!(proof(&r).stdout_complete);
    assert_eq!(proof(&r).stdout, b"1\n");
}
#[test]
fn python_native_child_uses_existing_path_policy_and_preserves_data() {
    for (path, expected) in [
        ("/workspace/output", Decision::Allow),
        ("/outside/output", Decision::NeedApproval),
    ] {
        let r = check(&format!(
            "python3 -I -S -c 'import subprocess; subprocess.run([\"touch\",\"--\",\"{path}\"],check=True)'"
        ));
        assert_eq!(r.decision, expected, "{:?}", r.decision_trace);
        assert!(proof(&r).complete, "{:?}", proof(&r));
        assert_eq!(proof(&r).native_argv[0], ["touch", "--", path]);
        assert!(!proof(&r).stdout_complete);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "touch")
        );
    }
    let r = check(
        "python3 -I -S -c 'import subprocess; subprocess.run([\"touch\",\"--\",\"$(rm -rf /)\"])'",
    );
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    assert!(
        !r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "rm")
    );
}
#[test]
fn python_launch_forms_share_the_adapter() {
    for command in [
        "python3 -IS -c 'print(2)'",
        "python3 -I -S - <<'PY'\nprint(2)\nPY",
        "cat > /workspace/run.py <<'PY'\nprint(2)\nPY\npython3 -I -S /workspace/run.py",
        "env python3 -I -S -c 'print(2)'",
    ] {
        let r = check(command);
        assert!(proof(&r).complete, "{command}: {:?}", r.decision_trace);
        assert_eq!(proof(&r).stdout, b"2\n");
        assert_eq!(
            r.decision,
            Decision::Allow,
            "{command}: {:?}",
            r.decision_trace
        );
    }
}
#[test]
fn python_child_can_be_a_wrapper_without_chain_specific_rules() {
    let r = check(
        "python3 -I -S -c 'import subprocess; subprocess.run([\"env\",\"touch\",\"--\",\"/outside/result\"])'",
    );
    assert!(proof(&r).complete);
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.decision_trace);
    assert!(
        r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.normalized_command_name == "touch")
    );
}
#[test]
fn python_plain_startup_unsupported_code_and_missing_bytes_remain_approval() {
    for command in [
        "python3 -c 'print(1)'",
        "python3 -I -c 'print(1)'",
        "python3 -S -c 'print(1)'",
        "python2 -I -S -c 'print(1)'",
        "python3 -I -S -W anything -c 'print(1)'",
        "python3 -I -S -c 'import unknown; print(1)'",
        "python3 -I -S -c 'import subprocess; subprocess.run([\"touch\",\"x\"]); unknown()'",
        "python3 -I -S -c 'from pathlib import Path; print(Path(\"unknown\").read_bytes())'",
        "python3 -I -S /workspace/unknown.py",
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.decision_trace
        );
        assert!(!proof(&r).complete, "{command}");
    }
}
#[test]
fn python_environment_values_and_known_file_content_have_dependencies() {
    let r = check(
        "TARGET=/workspace/out python3 -I -S -c 'import os,subprocess; subprocess.run([\"touch\",\"--\",os.environ[\"TARGET\"]])'",
    );
    assert!(proof(&r).complete, "{:?}", r.decision_trace);
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    assert!(
        matches!(&proof(&r).inputs[0], PythonPayloadInputEvidence::Environment {name,value} if name=="TARGET" && value.as_deref()==Some("/workspace/out"))
    );
    let r = check(
        "printf 'hello' > /workspace/data; python3 -I -S -c 'from pathlib import Path; from urllib.parse import quote_from_bytes; print(quote_from_bytes(Path(\"data\").read_bytes(),safe=\"\"))'",
    );
    assert!(proof(&r).complete, "{:?}", r.decision_trace);
    assert_eq!(proof(&r).stdout, b"hello\n");
    assert!(proof(&r).inputs.iter().any(|i| matches!(i, PythonPayloadInputEvidence::File {path,bytes} if path=="data" && bytes==b"hello")));
}
#[test]
fn python_unknown_native_children_and_unmodeled_shell_boundaries_do_not_pass() {
    let r = check("python3 -I -S -c 'import subprocess; subprocess.run([\"rm\",\"-rf\",\"/\"])'");
    assert!(proof(&r).complete);
    assert_eq!(r.decision, Decision::Deny, "{:?}", r.decision_trace);
    for command in [
        "python3 -I -S -c 'import subprocess; subprocess.run([\"unknown-tool\"])'",
        "python3 -I -S -c 'import subprocess; subprocess.run(\"touch x\",shell=True)'",
        "python3 -I -S -c 'import subprocess; subprocess.run([\"bash\",\"-c\",\"unknown-tool\"])'",
    ] {
        let r = check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.decision_trace
        );
    }
}

#[test]
fn python_source_encoding_cwd_and_substitution_keep_their_own_boundaries() {
    let r = check(
        "cat > /workspace/code.py <<'PY'\n# coding: latin1\nprint('text')\nPY\npython3 -I -S code.py",
    );
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(proof(&r).gap.as_deref().unwrap().contains("encoding"));
    let r = check("python3 -I -S -c 'print(\"中文\")'");
    assert!(proof(&r).complete);
    assert!(!proof(&r).stdout_complete);
    let r = check(
        "echo \"$(python3 -I -S -c 'import subprocess; subprocess.run([\"touch\",\"/outside/output\"])')\"",
    );
    assert!(proof(&r).complete);
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.decision_trace);
    let r = check(
        "cd /outside && python3 -I -S -c 'import subprocess; subprocess.run([\"touch\",\"output\"])'",
    );
    assert!(proof(&r).complete, "{:?}", proof(&r));
    assert_eq!(proof(&r).cwd.as_deref(), Some("/outside"));
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.decision_trace);
}

#[test]
fn python_functions_and_native_callbacks_share_the_language_adapter() {
    let r = check(
        "run_step() { python3 -I -S -c 'import subprocess; subprocess.run([\"touch\",\"/outside/out\"])'; }; run_step",
    );
    assert!(proof(&r).complete, "{:?}", proof(&r));
    assert_eq!(r.decision, Decision::NeedApproval);
    for (program, expected) in [
        ("print(1)", Decision::Allow),
        (
            "import subprocess; subprocess.run(['touch','/outside/out'])",
            Decision::NeedApproval,
        ),
    ] {
        let action = format!("--checkpoint-action=exec=python3 -I -S -c \"{program}\"");
        let quoted = format!("'{}'", action.replace('\'', "'\\''"));
        let r = check(&format!(
            "tar -cf /workspace/a.tar --checkpoint=1 {quoted} -- /workspace/input"
        ));
        assert!(proof(&r).complete, "{:?}", r.decision_trace);
        assert_eq!(r.decision, expected, "{:?}", r.decision_trace);
    }
}

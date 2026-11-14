//! Submitted commands are analyzed, never executed.
use caushell_core::ShellQueryCore;
use caushell_runner::{FileContentRead, FilesystemView};
use caushell_types::*;
use std::sync::{Arc, Mutex};

fn request(command: &str) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    state.observability.variables = ShellStateKnowledge::Complete;
    state.observability.aliases = ShellStateKnowledge::Complete;
    state.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("script-policy"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_state_before: state,
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn script_evidence(r: &CheckResponse) -> Vec<&NonShellScriptExecutionEvidence> {
    r.decision_trace
        .evidence
        .iter()
        .filter_map(|e| match &e.kind {
            EvidenceKind::NonShellScriptExecution(script) => Some(script),
            _ => None,
        })
        .collect()
}

fn no_python_analysis(r: &CheckResponse) {
    assert!(!r.decision_trace.evidence.iter().any(|e| matches!(
        &e.kind,
        EvidenceKind::PythonPayload(_)
            | EvidenceKind::PythonStdoutField(_)
            | EvidenceKind::PythonStartup(_)
    )));
}

#[test]
fn non_shell_code_is_approval_policy_not_a_source_analysis_result() {
    for command in [
        "python3 -c pass",
        "python3 -I -S -c 'print(1)'",
        "python3 /dev/null",
        "python3 - <<< 'print(1)'",
        "python3 <<'PY'\nprint(1)\nPY",
        "printf 'print(1)' | python3",
        "python3 < ./demo.py",
        "python3 -c '$UNKNOWN'",
        "python3 -c 'not valid python !'",
        "python3 -m json.tool --help",
        "python3 -m http.server --bind 127.0.0.1",
        "python3 -m pytest tests",
        "python3 -m unknown_module",
        "perl -e 1",
        "printf 1 | perl",
        "node -e 'console.log(1)'",
        "php -r 'echo 1;'",
        "lua -e 'print(1)'",
        "Rscript -e 'print(1)'",
        "Rscript --vanilla -e 'print(1)' -e 'print(2)'",
        "Rscript -e 'print(1)' --help",
        "Rscript -e 'not valid R !'",
        "Rscript - <<< 'print(1)'",
        "printf 'print(1)' | Rscript -",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            !script_evidence(&r).is_empty(),
            "{command}: {:?}",
            r.reasons
        );
        no_python_analysis(&r);
    }
}

#[test]
fn wrappers_callbacks_functions_aliases_and_substitutions_keep_the_boundary() {
    for command in [
        "env -i python3 -c pass",
        "timeout 5 python3 -c pass",
        "bash -c 'python3 -c pass'",
        "sh -c 'perl -e 1'",
        "run() { python3 -c pass; }; run",
        "alias run='python3 -c pass'; run",
        "printf '%s\\0' pass | xargs -0 python3 -c",
        "find . -exec python3 -c pass \\;",
        "tar -cf ./out.tar --checkpoint=1 --checkpoint-action='exec=python3 -c pass' -- input",
        "printf '%s' \"$(python3 -c 'print(1)')\"",
        "cat <(python3 -c 'print(1)')",
        "env -i Rscript -e 'print(1)'",
        "timeout 5 /usr/bin/Rscript -e 'print(1)'",
        "bash -c 'Rscript -e 1'",
        "run() { Rscript -e 1; }; run",
        "alias run='Rscript -e 1'; run",
        "printf '%s' \"$(Rscript -e 1)\"",
        "cat <(Rscript -e 1)",
        "find . -exec Rscript -e 1 \\;",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(
            !script_evidence(&r).is_empty(),
            "{command}: {:?}",
            r.reasons
        );
        no_python_analysis(&r);
    }
}

#[test]
fn shell_information_and_literal_data_do_not_become_script_execution() {
    for command in [
        "python3 --help",
        "python3 --version",
        "perl -v",
        "Rscript --help",
        "Rscript --version",
        "node --version",
        "printf '%s' 'python3 -c pass'",
        "printf '%s' './demo.py'",
        "cat ./demo.py",
        "bash -c 'printf %s ok'",
        "sh -c 'echo ok'",
        "printf 'echo ok\\n' | sh",
        "cp -- source ./target",
        "touch ./demo.py",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        let expected = if command == "node --version" {
            // This information form is not currently matched by the Node
            // Profile. It remains non-script data, but now has an approval gap.
            assert!(
                r.decision_trace
                    .decision_proposals
                    .iter()
                    .any(|p| p.rule_id == RuleId::SelectionError)
            );
            Decision::NeedApproval
        } else {
            Decision::Allow
        };
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
        assert!(script_evidence(&r).is_empty(), "{command}");
        no_python_analysis(&r);
    }
}

#[test]
fn other_analysis_continues_and_deny_is_not_downgraded() {
    for command in [
        "python3 -c pass; rm -rf /",
        "rm -rf /; python3 -c pass",
        "python3 -c pass | rm -rf /",
        "python3 -c pass & rm -rf /",
        "bash -c 'python3 -c pass; rm -rf /'",
        "printf '%s' \"$(python3 -c pass)\"; rm -rf /",
        "Rscript -e 1; rm -rf /",
        "bash -c 'Rscript -e 1; rm -rf /'",
    ] {
        let r = ShellQueryCore::new().check(request(command));
        assert_eq!(r.decision, Decision::Deny, "{command}: {:?}", r.reasons);
        assert!(!script_evidence(&r).is_empty(), "{command}");
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CatastrophicFileSystemDelete),
            "{command}: {:?}",
            r.reasons
        );
    }
    let r = ShellQueryCore::new().check(request("python3 -c pass; touch /outside/target"));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
    );
}

#[test]
fn general_resolve_observe_does_not_authorize_inline_or_module_execution() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::NestedPayloadExpansion,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    policy.rule_policy.rules.insert(
        RuleId::NonShellScriptExecution,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    for command in ["python3 -I -S -c pass", "python3 -m json.tool --help"] {
        let r = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
        assert!(!script_evidence(&r).is_empty());
    }
    for command in ["python3 ./demo.py", "node ./demo.js", "perl /tmp/demo.pl"] {
        let r = ShellQueryCore::with_policy(policy.clone()).check(request(command));
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        assert!(script_evidence(&r).is_empty());
        no_python_analysis(&r);
    }
    policy.rule_policy.rules.insert(
        RuleId::NonShellScriptExecution,
        RulePolicyEntry::new(RuleAction::Deny),
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("python3 -c pass"))
            .decision,
        Decision::Deny
    );
}

#[test]
fn python_stdout_is_not_used_to_materialize_consumer_arguments() {
    let r = ShellQueryCore::new().check(request(
        "touch \"$(python3 -I -S -c 'print(\"exact-target\")')\"",
    ));
    assert_eq!(r.decision, Decision::NeedApproval);
    no_python_analysis(&r);
    assert!(
        !r.decision_trace
            .path_targets
            .iter()
            .any(|p| matches!(&p.lexical,
        PathResolution::Concrete { path } if path == "/workspace/exact-target"))
    );
    let serialized = serde_json::to_vec(&r).unwrap();
    let decoded: CheckResponse = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(script_evidence(&r), script_evidence(&decoded));
}

#[derive(Default)]
struct Files {
    reads: Mutex<Vec<String>>,
}
impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if matches!(path, "/" | "/workspace" | "/usr" | "/usr/bin") {
            FilesystemEntry::Directory
        } else if matches!(path, "/workspace/demo.py" | "/usr/bin/python3") {
            FilesystemEntry::File
        } else {
            FilesystemEntry::Missing
        }
    }
    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        self.reads.lock().unwrap().push(path.into());
        FileContentRead::failed(
            FileContentSource::SuppliedView,
            path,
            limit,
            FileContentStatus::Unavailable,
            "no body observation",
        )
    }
}

#[test]
fn file_execution_authority_does_not_require_source_or_runtime_inventory() {
    let files = Arc::new(Files::default());
    let r = ShellQueryCore::new()
        .with_filesystem_view(files.clone())
        .check(request("/usr/bin/python3 /workspace/demo.py"));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.reasons);
    assert!(script_evidence(&r).is_empty());
    assert!(
        !files
            .reads
            .lock()
            .unwrap()
            .iter()
            .any(|p| p == "/workspace/demo.py")
    );
    no_python_analysis(&r);
}

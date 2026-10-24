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
fn request(command: &str) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    shell.observability.variables = ShellStateKnowledge::Complete;
    shell.observability.aliases = ShellStateKnowledge::Complete;
    shell.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
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
    }
}
fn check(command: &str) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(Files))
        .check(request(command))
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
fn python_unknown_native_children_do_not_pass() {
    let r = check("python3 -I -S -c 'import subprocess; subprocess.run([\"rm\",\"-rf\",\"/\"])'");
    assert!(proof(&r).complete);
    assert_eq!(r.decision, Decision::Deny, "{:?}", r.decision_trace);
    for command in [
        "python3 -I -S -c 'import subprocess; subprocess.run([\"unknown-tool\"])'",
        "python3 -I -S -c 'import subprocess; subprocess.run(\"unknown-tool\",shell=True)'",
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
fn python_shell_true_uses_the_posix_shell_frontier_and_policy() {
    for (code, expected) in [
        ("touch /workspace/a; touch /workspace/b", Decision::Allow),
        ("touch /outside/a", Decision::NeedApproval),
        ("rm -rf /", Decision::Deny),
        ("touch /workspace/a; unknown-tool", Decision::NeedApproval),
    ] {
        let command =
            format!("python3 -I -S -c 'import subprocess; subprocess.run(\"{code}\",shell=True)'");
        let r = check(&command);
        assert!(proof(&r).complete, "{code}: {:?}", proof(&r));
        assert_eq!(r.decision, expected, "{code}: {:?}", r.decision_trace);
        assert_eq!(proof(&r).shell_commands, [code]);
        assert!(
            r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "sh")
        );
    }
}

#[test]
fn python_listener_and_response_use_shared_network_facts() {
    for (host, expected) in [
        ("127.0.0.2", Decision::Allow),
        ("0.0.0.0", Decision::NeedApproval),
    ] {
        let source = format!(
            "import socket\ns=socket.socket()\ns.bind((\"{host}\",19318))\ns.listen(1)\nc,_=s.accept()\nassert c.recv(64)==b\"ping\"\nc.sendall(b\"pong\")\nc.close(); s.close()"
        );
        let r = check(&format!("python3 -I -S -c '{source}'"));
        assert!(proof(&r).complete, "{:?}", proof(&r));
        assert_eq!(r.decision, expected, "{host}: {:?}", r.decision_trace);
        assert!(r.decision_trace.execution_semantics.iter().any(|s| {
            s.network_listeners.iter().any(|l| {
                matches!(l,
                NetworkListener::Internet {host:Some(h),port:Some(p),..} if h==host && p=="19318")
            })
        }));
        assert!(!proof(&r).stdout_complete);
    }
}

#[test]
fn python_response_retains_file_origins_and_unmodeled_effects_fail_closed() {
    let source = "from pathlib import Path\nimport socket\nbody=Path(\"/workspace/data\").read_bytes()\ns=socket.socket(); s.bind((\"127.0.0.1\",19319)); s.listen(1)\nc,_=s.accept(); c.sendall(body); c.close(); s.close()";
    let r = check(&format!(
        "printf 'body' > /workspace/data; python3 -I -S -c '{source}'"
    ));
    assert!(proof(&r).complete, "{:?}", proof(&r));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    assert!(proof(&r).inputs.iter().any(|i| matches!(i, PythonPayloadInputEvidence::File {path,bytes} if path=="/workspace/data" && bytes==b"body")));
    for suffix in [
        "\nunknown_call()",
        "\ns.connect((\"127.0.0.1\",1))",
        "\nif c.recv(2)==b\"x\":\n    unknown_call()",
    ] {
        let r = check(&format!(
            "printf 'body' > /workspace/data; python3 -I -S -c '{source}{suffix}'"
        ));
        assert!(!proof(&r).complete);
        assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.decision_trace);
    }
}

#[test]
fn python_exact_stdout_reaches_command_substitutions_without_becoming_code() {
    for (command, expected) in [
        (
            "touch -- \"$(python3 -I -S -c 'print(\"/workspace/out\")')\"",
            Decision::Allow,
        ),
        (
            "touch -- \"$(python3 -I -S -c 'print(\"/outside/out\")')\"",
            Decision::NeedApproval,
        ),
        (
            "touch -- \"$(python3 -I -S -c 'print(\"$(rm -rf /)\")')\"",
            Decision::Allow,
        ),
        (
            "touch -- \"$(python3 -I -S -c 'unknown_call(); print(\"/workspace/out\")')\"",
            Decision::NeedApproval,
        ),
        (
            "touch -- \"$(python3 -c 'print(\"/workspace/out\")')\"",
            Decision::NeedApproval,
        ),
    ] {
        let r = check(command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
        assert!(
            !r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "rm")
        );
    }
}

#[test]
fn python_stdout_uses_current_file_bytes_not_stale_writes() {
    for (prefix, expected) in [
        ("printf '/workspace/out' > /workspace/path", Decision::Allow),
        (
            "printf '/outside/out' > /workspace/path",
            Decision::NeedApproval,
        ),
        (
            "printf '/workspace/out' > /workspace/path; cp /workspace/unknown /workspace/path",
            Decision::NeedApproval,
        ),
    ] {
        let command = format!(
            "{prefix}; touch -- \"$(python3 -I -S -c 'from pathlib import Path; print(Path(\"/workspace/path\").read_bytes().decode())')\""
        );
        let r = check(&command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.decision_trace);
    }
}

#[test]
fn python_stdout_fields_preserve_scalar_bytes_and_shell_environment_order() {
    for (literal, value) in [
        ("$HOME/out", "$HOME/out"),
        ("", ""),
        ("a\\nb", "a\nb"),
        ("a\\n\\n", "a"),
    ] {
        let r = check(&format!(
            "printf '%s' \"$(python3 -I -S -c 'print(\"{literal}\")')\""
        ));
        let field = r
            .decision_trace
            .evidence
            .iter()
            .find_map(|e| match &e.kind {
                EvidenceKind::PythonStdoutField(p) => Some(p),
                _ => None,
            })
            .unwrap();
        assert_eq!(field.value, value);
        assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    }
    let r = check(
        "export TARGET=/outside/out; TARGET=/workspace/out touch -- \"$(python3 -I -S -c 'import os; print(os.environ[\"TARGET\"])')\"",
    );
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.decision_trace);
    assert!(r.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
        EvidenceKind::PythonStdoutField(p) if p.value=="/outside/out")));
    for command in [
        "touch -- \"$(python3 -I -S -c 'print(\"a\\0b\")')\"",
        "touch -- $(python3 -I -S -c 'print(\"/workspace/out\")')",
        "touch -- \"$(unset TARGET; python3 -I -S -c 'print(\"/workspace/out\")')\"",
        "touch -- \"$(python3 -I -S -c 'print(\"/workspace/out\")')\" \"$(unknown-tool)\"",
        "python3() { echo /outside/out; }; touch -- \"$(python3 -I -S -c 'print(\"/workspace/out\")')\"",
    ] {
        let r = check(command);
        assert!(
            !r.decision_trace
                .evidence
                .iter()
                .any(|e| matches!(e.kind, EvidenceKind::PythonStdoutField(_))),
            "{command}"
        );
        assert_ne!(
            r.decision,
            Decision::Allow,
            "{command}: {:?}",
            r.decision_trace
        );
    }
}

#[test]
fn materialized_stdout_keeps_the_source_to_consumer_provenance_slot() {
    use caushell_graph::{EdgeKind, NodeKind};
    let mut core = ShellQueryCore::new().with_filesystem_view(Arc::new(Files));
    let r=core.check(request("printf 'hello' > /workspace/body; printf '%s' \"$(python3 -I -S -c 'from pathlib import Path; print(Path(\"/workspace/body\").read_bytes().decode())')\""));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.decision_trace);
    let graph = core
        .session_graph(&SessionId::new("python-program"))
        .unwrap();
    let artifact = graph
        .nodes()
        .find(|n| {
            matches!(
                &n.kind,
                NodeKind::ProvenanceArtifact {
                    artifact: ProvenanceArtifact::CommandSubstitutionOutput { .. }
                }
            )
        })
        .unwrap();
    assert!(
        graph
            .incoming_edges(&artifact.id)
            .any(|e| e.kind == EdgeKind::Produces)
    );
    assert!(
        graph
            .incoming_edges(&artifact.id)
            .any(|e| e.kind == EdgeKind::Consumes
                && matches!(
                    &e.semantics,
                    Some(ProvenanceEdgeSemantics::Consume {
                        slot_name: Some(_),
                        ..
                    })
                ))
    );
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

#[test]
fn python_http_handlers_use_shared_listener_response_and_child_policies() {
    for (host, extra, decision) in [
        ("127.0.0.2", "pass", Decision::Allow),
        ("0.0.0.0", "pass", Decision::NeedApproval),
        (
            "127.0.0.2",
            "subprocess.run([\"touch\",\"/outside/extra\"])",
            Decision::NeedApproval,
        ),
        (
            "127.0.0.2",
            "subprocess.run([\"rm\",\"-rf\",\"/\"])",
            Decision::Deny,
        ),
    ] {
        let source = format!(
            "from http.server import HTTPServer,BaseHTTPRequestHandler\nfrom pathlib import Path\nimport subprocess\nbody=Path(\"/workspace/body\").read_bytes()\nclass Handler(BaseHTTPRequestHandler):\n    def do_GET(self):\n        if self.path != \"/item\":\n            self.send_error(404)\n            return\n        self.send_response(200)\n        self.send_header(\"Content-Length\",str(len(body)))\n        self.end_headers()\n        self.wfile.write(body)\n    def do_POST(self):\n        {extra}\n    def log_message(self,*args):\n        pass\nserver=HTTPServer((\"{host}\",19232),Handler)\nserver.timeout=3\nfor _ in range(2):\n    server.handle_request()\nserver.server_close()"
        );
        let r = check(&format!(
            "printf body > /workspace/body; python3 -I -S -c '{source}'"
        ));
        assert!(proof(&r).complete, "{source}: {:?}", proof(&r));
        assert_eq!(r.decision, decision, "{source}: {:?}", r.decision_trace);
        assert!(proof(&r).inputs.iter().any(
            |i| matches!(i,PythonPayloadInputEvidence::File {path,..} if path=="/workspace/body")
        ));
        assert!(!proof(&r).stdout_complete);
    }
}

#[test]
fn unsupported_http_dispatch_and_request_paths_never_pass_as_complete() {
    for method in [
        "    def do_GET(self):\n        if self.path == \"/hidden\":\n            unknown_call()",
        "    def do_GET(self):\n        self.wfile.write(Path(self.path).read_bytes())",
        "    def do_GET(self):\n        pass\n    def log_message(self,*args):\n        unknown_call()",
        "    def setup(self):\n        pass",
    ] {
        let source = format!(
            "from http.server import HTTPServer,BaseHTTPRequestHandler\nfrom pathlib import Path\nclass Handler(BaseHTTPRequestHandler):\n{method}\nserver=HTTPServer((\"127.0.0.1\",19233),Handler)\nserver.handle_request()\nserver.server_close()"
        );
        let r = check(&format!("python3 -I -S -c '{source}'"));
        assert!(!proof(&r).complete, "{source}: {:?}", proof(&r));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{source}: {:?}",
            r.decision_trace
        );
    }
}

#[test]
fn scalar_stdout_routes_keep_prefix_suffix_parameters_and_multiple_producers() {
    for (command, values, decision) in [
        (
            "touch -- \"/workspace/pre-$(python3 -I -S -c 'print(\"a b\")')-post\"",
            vec!["/workspace/pre-a b-post"],
            Decision::Allow,
        ),
        (
            "ROOT=/outside; touch -- \"${ROOT}/$(python3 -I -S -c 'print(\"out\")')\"",
            vec!["/outside/out"],
            Decision::NeedApproval,
        ),
        (
            "touch -- \"${ABSENT}/$(python3 -I -S -c 'print(\"file\")')\"",
            vec!["/file"],
            Decision::NeedApproval,
        ),
        (
            "ROOT=/outside; ROOT=/workspace touch -- \"${ROOT}/$(python3 -I -S -c 'print(\"out\")')\"",
            vec!["/outside/out"],
            Decision::NeedApproval,
        ),
        (
            "touch -- /workspace/\"$(python3 -I -S -c 'print(\"a\\n\")')\"'-'\"$(python3 -I -S -c 'print(\"b\")')\"",
            vec!["/workspace/a-b", "/workspace/a-b"],
            Decision::Allow,
        ),
        (
            "touch -- \"$(python3 -I -S -c 'print(\"/workspace/a\")')\" \"$(python3 -I -S -c 'print(\"/outside/b\")')\"",
            vec!["/workspace/a", "/outside/b"],
            Decision::NeedApproval,
        ),
        (
            "touch -- \"/workspace/$(python3 -I -S -c 'print(\"$HOME $(rm -rf /) `whoami`\")')\"",
            vec!["/workspace/$HOME $(rm -rf /) `whoami`"],
            Decision::Allow,
        ),
    ] {
        let r = check(command);
        let fields = r
            .decision_trace
            .evidence
            .iter()
            .filter_map(|e| match &e.kind {
                EvidenceKind::PythonStdoutField(p) => Some(p.value.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(fields, values, "{command}: {:?}", r.decision_trace);
        assert_eq!(r.decision, decision, "{command}: {:?}", r.decision_trace);
        assert!(
            !r.decision_trace
                .execution_semantics
                .iter()
                .any(|s| matches!(s.normalized_command_name.as_str(), "rm" | "whoami"))
        );
    }
}

#[test]
fn scalar_stdout_routes_require_all_sibling_producers_and_original_fields_to_be_known() {
    for command in [
        "ROOT=$(unknown-tool); touch -- \"${ROOT}/$(python3 -I -S -c 'print(\"file\")')\"",
        "touch -- \"${ROOT:=/workspace}/$(python3 -I -S -c 'print(\"file\")')\"",
        "touch -- \"$(python3 -I -S -c 'print(\"/workspace/a\")')-$(unknown-tool)\"",
        "touch -- \"$(python3 -I -S -c 'print(\"/workspace/a\")')\" <(touch /workspace/other)",
        "touch -- \"$(python3 -I -S -c 'print(\"/workspace/a\")')\" > \"$(unknown-tool)\"",
        "touch -- \"$(python3 -I -S -c 'print(\"/workspace/a\")')\" \"$(python3 -I -S -c 'import subprocess; subprocess.run([\"touch\",\"/workspace/other\"])')\"",
        "touch -- /workspace/$(python3 -I -S -c 'print(\"a b\")')",
    ] {
        let r = check(command);
        assert!(
            !r.decision_trace
                .evidence
                .iter()
                .any(|e| matches!(e.kind, EvidenceKind::PythonStdoutField(_))),
            "{command}: {:?}",
            r.decision_trace
        );
    }
}

#[test]
fn uri_encoded_stdout_reaches_the_original_endpoint_with_file_dependencies() {
    for (options, decision) in [("", Decision::NeedApproval), ("-q ", Decision::Allow)] {
        let command = format!(
            "printf 'a b' > /workspace/body; DEST=127.0.0.1; curl {options}--fail -- \"gopher://${{DEST}}:19234/_$(python3 -I -S -c 'from pathlib import Path; from urllib.parse import quote_from_bytes; print(quote_from_bytes(Path(\"/workspace/body\").read_bytes(),safe=\"\"))')\""
        );
        let r = check(&command);
        let field = r
            .decision_trace
            .evidence
            .iter()
            .find_map(|e| match &e.kind {
                EvidenceKind::PythonStdoutField(p) => Some(p),
                _ => None,
            })
            .expect("materialized endpoint");
        assert_eq!(field.value, "gopher://127.0.0.1:19234/_a%20b");
        assert!(field.inputs.iter().any(|i|matches!(i,PythonPayloadInputEvidence::File {path,bytes} if path=="/workspace/body" && bytes==b"a b")));
        assert_eq!(r.decision, decision, "{:?}", r.decision_trace);
    }
}

#[test]
fn compound_stdout_fields_do_not_borrow_bash_quote_rules_for_zsh() {
    let mut req = request("touch -- /workspace/'a''b'\"$(python3 -I -S -c 'print(\"out\")')\"");
    req.shell_kind = ShellKind::Zsh;
    let r = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(Files))
        .check(req);
    assert!(
        !r.decision_trace
            .evidence
            .iter()
            .any(|e| matches!(e.kind, EvidenceKind::PythonStdoutField(_)))
    );
}

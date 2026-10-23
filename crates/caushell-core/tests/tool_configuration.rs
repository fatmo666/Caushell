use std::collections::BTreeMap;
use std::sync::Arc;

use caushell_core::ShellQueryCore;
use caushell_runner::{FileContentRead, FilesystemView};
use caushell_types::*;

#[derive(Default)]
struct Files {
    files: BTreeMap<String, Vec<u8>>,
    unavailable: bool,
    tampered: bool,
    missing_read: bool,
}

impl Files {
    fn file(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.into(), content.as_bytes().to_vec());
        self
    }
}

impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if self.files.contains_key(path) {
            FilesystemEntry::File
        } else if ["/", "/workspace", "/home", "/home/test", "/certs"].contains(&path)
            || self
                .files
                .keys()
                .any(|p| p.starts_with(&format!("{}/", path.trim_end_matches('/'))))
        {
            FilesystemEntry::Directory
        } else {
            FilesystemEntry::Missing
        }
    }

    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        if self.missing_read {
            return FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "changed",
            );
        }
        if self.unavailable {
            return FileContentRead::failed(
                FileContentSource::Unavailable,
                path,
                limit,
                FileContentStatus::Unavailable,
                "not supplied",
            );
        }
        if let Some(bytes) = self.files.get(path) {
            let mut result = FileContentRead::complete(
                FileContentSource::SuppliedView,
                path,
                limit,
                None,
                bytes.clone(),
            );
            if self.tampered {
                result.observation.sha256 = Some("invalid".into());
            }
            result
        } else {
            FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "absent",
            )
        }
    }
}

fn check(command: &str, files: Files) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(CheckRequest {
            session_id: SessionId::new("tool-configuration"),
            sequence_no: CommandSequenceNo(1),
            command: command.into(),
            shell_kind: ShellKind::Bash,
            shell_state_before: ShellStateSnapshot::new("/workspace")
                .with_variable_knowledge(ShellStateKnowledge::Complete),
            home: Some("/home/test".into()),
            workspace_root: Some("/workspace".into()),
            runtime: RuntimeMetadata {
                runtime_name: "test".into(),
                tool_name: None,
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        })
}

fn parse(response: &CheckResponse) -> &ToolConfigParseEvidence {
    response
        .decision_trace
        .evidence
        .iter()
        .find_map(|e| match &e.kind {
            EvidenceKind::ToolConfigParse(e) => Some(e),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{response:#?}"))
}

fn tls_control(response: &CheckResponse) -> bool {
    response.decision_trace.execution_semantics.iter().any(|s| {
        s.state_operations.iter().any(|op| {
            op.domain == StateOperationDomain::ConnectionVerification
                && op.operation == StateOperationKind::Control
        })
    })
}

#[test]
fn explicit_and_implicit_inputs_reuse_the_same_effects() {
    for (content, decision, tls) in [
        ("cacert /certs/ca.pem\n", Decision::Allow, false),
        ("insecure\n", Decision::NeedApproval, true),
    ] {
        let explicit = check(
            "curl -q -K settings.rc https://example.test",
            Files::default().file("/workspace/settings.rc", content),
        );
        let implicit = check(
            "CURL_HOME=/workspace/settings curl https://example.test",
            Files::default().file("/workspace/settings/.curlrc", content),
        );
        for response in [&explicit, &implicit] {
            assert_eq!(response.decision, decision, "{response:#?}");
            assert_eq!(tls_control(response), tls, "{response:#?}");
            assert!(parse(response).complete, "{response:#?}");
            assert!(
                response
                    .decision_trace
                    .execution_semantics
                    .iter()
                    .any(|s| s.loads_tool_config && !s.operation_semantics_unresolved)
            );
        }
    }
}

#[test]
fn repeated_options_and_configuration_files_preserve_order() {
    for (arguments, decision) in [
        ("-K insecure.rc --no-insecure", Decision::Allow),
        ("--no-insecure -K insecure.rc", Decision::NeedApproval),
        ("-K insecure.rc -K secure.rc", Decision::Allow),
        ("-K secure.rc -K insecure.rc", Decision::NeedApproval),
        ("--config=insecure.rc --no-insecure", Decision::Allow),
        ("-sKinsecure.rc --no-insecure", Decision::Allow),
        ("-sK insecure.rc --no-insecure", Decision::Allow),
    ] {
        let response = check(
            &format!("curl -q {arguments} https://example.test"),
            Files::default()
                .file("/workspace/insecure.rc", "insecure\n")
                .file("/workspace/secure.rc", "no-insecure\n"),
        );
        assert_eq!(response.decision, decision, "{arguments}: {response:#?}");
        assert!(parse(&response).complete, "{response:#?}");
        assert_eq!(
            tls_control(&response),
            decision == Decision::NeedApproval,
            "{response:#?}"
        );
    }
}

#[test]
fn nested_configuration_uses_command_cwd_and_literal_values() {
    let response = check(
        "curl -q -K config/main.rc https://example.test",
        Files::default()
            .file(
                "/workspace/config/main.rc",
                "config child.rc\nno-insecure\nheader \"X-Value: $HOME; $(bad)\"\n",
            )
            .file("/workspace/child.rc", "insecure\n"),
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    let evidence = parse(&response);
    assert!(evidence.complete, "{response:#?}");
    assert_eq!(evidence.files.len(), 2);
    assert_eq!(evidence.files[1].path, "/workspace/child.rc");
    assert_eq!(
        evidence
            .options
            .iter()
            .map(|o| o.option.as_str())
            .collect::<Vec<_>>(),
        ["--config", "--insecure", "--no-insecure", "--header"]
    );
    assert!(!format!("{evidence:?}").contains("$(bad)"));
}

#[test]
fn partial_and_unknown_inputs_keep_approval_and_known_effects() {
    for content in [
        "insecure\nunknown-control x\n",
        "insecure\nnext\n",
        "insecure\nurl \"bad\n",
    ] {
        let response = check(
            "curl -q -K settings.rc https://example.test",
            Files::default().file("/workspace/settings.rc", content),
        );
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(!parse(&response).complete);
        assert!(tls_control(&response), "{response:#?}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.operation_semantics_unresolved)
        );
    }
}

#[test]
fn missing_unavailable_or_corrupt_observations_never_become_complete() {
    for files in [
        Files::default(),
        Files {
            unavailable: true,
            ..Files::default().file("/workspace/settings.rc", "insecure\n")
        },
        Files {
            tampered: true,
            ..Files::default().file("/workspace/settings.rc", "insecure\n")
        },
    ] {
        let response = check("curl -q -K settings.rc https://example.test", files);
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(!parse(&response).complete, "{response:#?}");
    }
}

#[test]
fn cycles_stdin_and_expansion_budgets_remain_explicit_gaps() {
    for (arguments, content) in [
        ("-K settings.rc", "config settings.rc\n"),
        ("-K -", ""),
        ("-K settings.rc", "insecure\n"),
    ] {
        let mut files = Files::default().file("/workspace/settings.rc", content);
        if content == "insecure\n" {
            files
                .files
                .insert("/workspace/settings.rc".into(), vec![b'x'; 65_537]);
        }
        let response = check(&format!("curl -q {arguments} https://example.test"), files);
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(!parse(&response).complete);
    }
}

#[test]
fn option_operands_and_terminators_do_not_create_config_inputs() {
    for arguments in ["--output --config", "-- -K"] {
        let response = check(
            &format!("curl -q {arguments} https://example.test"),
            Files::default(),
        );
        assert!(
            !response
                .decision_trace
                .evidence
                .iter()
                .any(|e| matches!(e.kind, EvidenceKind::ToolConfigParse(_))),
            "{response:#?}"
        );
    }
    let response = check(
        "curl -q -K -k https://example.test",
        Files::default().file("/workspace/-k", "no-insecure\n"),
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    assert!(parse(&response).complete);
    assert!(!tls_control(&response));
}

#[test]
fn known_graph_content_precedes_filesystem_bytes() {
    let response = check(
        "printf 'insecure\\n' > settings.rc; curl -q -K settings.rc https://example.test",
        Files::default().file("/workspace/settings.rc", "no-insecure\n"),
    );
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(parse(&response).complete, "{response:#?}");
    assert_eq!(parse(&response).files[0].source, FileContentSource::Graph);
    assert!(tls_control(&response));
}

#[test]
fn unknown_overwrites_and_namespace_mutations_cannot_use_stale_bytes() {
    for prefix in [
        "printf '%s' \"$(cat source.txt)\" > settings.rc;",
        "if test -f trigger; then printf 'insecure\\n' > settings.rc; fi;",
        "ln -sf target.rc settings.rc;",
    ] {
        let response = check(
            &format!("{prefix} curl -q -K settings.rc https://example.test"),
            Files::default().file("/workspace/settings.rc", "no-insecure\n"),
        );
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(!parse(&response).complete, "{response:#?}");
    }
}

#[test]
fn configuration_cannot_clear_other_incompleteness_or_mutation_policy() {
    for arguments in ["--unknown-operation", "--data SAFE"] {
        let response = check(
            &format!("curl -q -K settings.rc {arguments} https://example.test"),
            Files::default().file("/workspace/settings.rc", "no-insecure\n"),
        );
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    }
}

#[test]
fn version_sensitive_default_selection_is_not_guessed() {
    let response = check(
        "XDG_CONFIG_HOME=/workspace/settings curl https://example.test",
        Files::default().file("/workspace/settings/curlrc", "no-insecure\n"),
    );
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(!parse(&response).complete);
    let response = check(
        "CURL_HOME=/workspace/first XDG_CONFIG_HOME=/workspace/other curl https://example.test",
        Files::default()
            .file("/workspace/first/.curlrc", "no-insecure\n")
            .file("/workspace/other/curlrc", "insecure\n"),
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    assert!(parse(&response).complete);
    assert_eq!(parse(&response).files.len(), 1);
}

#[test]
fn separate_function_calls_keep_their_own_config_inputs() {
    let response = check(
        "f(){ curl -q -K \"$1\" https://example.test; }; f secure.rc; f insecure.rc",
        Files::default()
            .file("/workspace/secure.rc", "no-insecure\n")
            .file("/workspace/insecure.rc", "insecure\n"),
    );
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(tls_control(&response), "{response:#?}");
    let inputs = response
        .decision_trace
        .evidence
        .iter()
        .filter_map(|e| match &e.kind {
            EvidenceKind::ToolConfigParse(e) => Some(e),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(inputs.len(), 2, "{response:#?}");
    assert!(inputs.iter().all(|e| e.complete), "{response:#?}");
    assert_ne!(inputs[0].files[0].path, inputs[1].files[0].path);
}

#[test]
fn configured_uploads_keep_stdin_and_state_policy() {
    let response = check(
        "printf SAFE | curl -q -K settings.rc https://example.test",
        Files::default().file("/workspace/settings.rc", "data @-\n"),
    );
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(parse(&response).complete, "{response:#?}");
    assert!(
        response.decision_trace.execution_semantics.iter().any(|s| s
            .state_operations
            .iter()
            .any(|o| o.domain == StateOperationDomain::RemoteResource
                && o.operation == StateOperationKind::Mutate)),
        "{response:#?}"
    );
}

#[test]
fn runtime_argv_is_not_reparsed_before_native_operand_projection() {
    let response = check(
        "curl -q --noproxy '*' --silent --show-error --fail --connect-timeout 2 --max-time 4 -K settings.rc --output /workspace/body.txt --write-out 'VERIFY=%{ssl_verify_result}\\n' https://localhost/check",
        Files::default().file("/workspace/settings.rc", "cacert /certs/ca.pem\n"),
    );
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    assert!(parse(&response).complete);
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .all(|s| !s.operation_semantics_unresolved)
    );
}

#[test]
fn conflicting_existence_observations_cannot_prove_default_absence() {
    let files = Files {
        missing_read: true,
        ..Files::default().file("/workspace/settings/.curlrc", "insecure\n")
    };
    let response = check(
        "CURL_HOME=/workspace/settings curl https://example.test",
        files,
    );
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(!parse(&response).complete, "{response:#?}");
}

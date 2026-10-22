use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let response = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("request-modes"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/test".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    });
    assert_eq!(
        response.decision, expected,
        "{command}: {:?}",
        response.reasons
    );
    response
}

#[test]
fn implicit_and_explicit_request_mutations_share_the_same_guard() {
    for mode in [
        "--data SAFE",
        "--json '{}'",
        "-F key=value",
        "-T payload",
        "-X POST",
        "-X PUT",
    ] {
        for endpoint in ["http://127.0.0.1/ingest", "https://example.test/ingest"] {
            let response = check(
                &format!("curl -q {mode} --url {endpoint}"),
                Decision::NeedApproval,
            );
            assert!(
                response
                    .decision_trace
                    .execution_semantics
                    .iter()
                    .any(|semantics| {
                        semantics.state_operations.iter().any(|operation| {
                            operation.domain == StateOperationDomain::RemoteResource
                                && operation.operation == StateOperationKind::Mutate
                        })
                    })
            );
            assert!(
                response
                    .decision_trace
                    .decision_proposals
                    .iter()
                    .any(|proposal| {
                        proposal.rule_id == RuleId::StateMutation
                            && proposal.decision == Decision::NeedApproval
                    })
            );
        }
    }
}

#[test]
fn read_requests_and_help_do_not_inherit_mutation_effects() {
    for command in [
        "curl -q --get --data key=value --url https://example.test/",
        "curl -q --data SAFE --request GET --url http://127.0.0.1/",
        "curl -q -T payload --request GET --url http://127.0.0.1/",
        "curl -q --help --data SAFE --url https://example.test/",
        "curl -q --help -T payload --url https://example.test/",
        "wget --help -O /opt/output -o /opt/log --save-cookies=/opt/cookies https://example.test/",
    ] {
        let response = check(command, Decision::Allow);
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|semantics| { semantics.state_operations.is_empty() })
        );
    }
}

#[test]
fn npm_preview_does_not_execute_imported_package_logic() {
    let response = check(
        "npm install --dry-run https://example.test/pkg.tgz",
        Decision::Allow,
    );
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .all(|semantics| { !semantics.executes_imported_package_logic })
    );
    assert!(
        !response
            .decision_trace
            .findings
            .iter()
            .any(|finding| { finding.rule_id == RuleId::ImportedPackageExecution })
    );
}

//! Static checks for audited command entry/effect boundaries. No sample command runs.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("profile-gap-boundaries"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
    }
}

fn check(command: &str) -> CheckResponse {
    let result = ShellQueryCore::new().check(request(command));
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

fn has_state_operation(
    response: &CheckResponse,
    domain: StateOperationDomain,
    operation: StateOperationKind,
) -> bool {
    response
        .decision_trace
        .execution_semantics
        .iter()
        .flat_map(|semantics| semantics.state_operations.iter())
        .any(|state_operation| {
            state_operation.domain == domain && state_operation.operation == operation
        })
}

#[test]
fn systemctl_query_does_not_hide_a_pager_and_no_pager_does_not_approve_control() {
    for operation in ["status", "show", "list-dependencies"] {
        let response = check(&format!("systemctl {operation} example.service"));
        // Query itself is read-only, but its pager still exposes shell escape.
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::InteractiveEscapeSurface)
        );
        assert!(
            !response
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::StateControl)
        );
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::InteractiveEscapeSurface,
            RulePolicyEntry::new(RuleAction::NeedApproval),
        );
        let enforcing = ShellQueryCore::with_policy(policy)
            .check(request(&format!("systemctl {operation} example.service")));
        assert_eq!(enforcing.decision, Decision::NeedApproval, "{enforcing:#?}");
        assert_eq!(
            check(&format!("systemctl --no-pager {operation} example.service")).decision,
            Decision::Allow
        );
    }
    assert_eq!(
        check("systemctl is-active example.service").decision,
        Decision::Allow
    );
    assert_eq!(
        check("systemctl --no-pager restart example.service").decision,
        Decision::NeedApproval
    );
}

#[test]
fn chmod_reference_clusters_unknown_options_and_nested_targets_keep_approval() {
    for command in [
        "chmod -Rf u+w /path/to/git/repo/objects",
        "find . -type f | xargs -I {} chmod --reference {} ../version1/{}",
        "chmod --reference source /opt/file",
        "chmod --unsupported u+w /opt/file",
    ] {
        let response = check(command);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
    }
    for command in [
        "chmod --reference source cache/file",
        "chmod -Rf u+w cache/file",
        "chmod --help -R u+w /opt/file",
        "ssh-keygen -l -E md5 -f /etc/ssh/ssh_host_ecdsa_key.pub",
    ] {
        assert_eq!(check(command).decision, Decision::Allow, "{command}");
    }
}

#[test]
fn service_status_all_exposes_opaque_service_script_dispatch() {
    for command in [
        "service --status-all | cat",
        "service '--status-all' | wc -l",
        "env service --status-all | cat",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            has_state_operation(
                &result,
                StateOperationDomain::ServiceManager,
                StateOperationKind::Opaque,
            ),
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| {
                    semantics.form_id == "linux_list_all_status"
                        && semantics.executes_payload
                        && semantics.operation_semantics_unresolved
                }),
            "{command}"
        );
    }
}

#[test]
fn service_status_all_does_not_consume_extra_arguments_as_safe_queries() {
    for command in [
        "service --status-all --",
        "service --status-all ''",
        "service --status-all --status-all",
        "service --status-all --help",
        "service --status-all fixture status",
        "service --status-all fixture start",
        "service --status-all \"$EXTRA\"",
        "service --status-all $EXTRA",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            !result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|semantics| { semantics.form_id == "linux_list_all_status" }),
            "{command}"
        );
    }
    assert_eq!(check("service fixture status").decision, Decision::Allow);
    assert_eq!(
        check("service fixture start").decision,
        Decision::NeedApproval
    );
}

#[test]
fn service_enabled_enumeration_preserves_configuration_execution() {
    for command in ["service -e", "service '-e' | cat", "env service -e"] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            has_state_operation(
                &result,
                StateOperationDomain::ServiceManager,
                StateOperationKind::Opaque,
            ),
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|item| {
                    item.form_id == "freebsd_list_enabled_services"
                        && item.executes_payload
                        && item.operation_semantics_unresolved
                })
        );
    }
    for command in [
        "service -e -h",
        "service -e --status-all",
        "service --status-all -e",
        "service -e --",
        "service -e -e",
        "service -e fixture status",
        "service -e \"$EXTRA\"",
        "service -e $EXTRA",
        "service -- -e",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}");
        assert!(
            !result
                .decision_trace
                .execution_semantics
                .iter()
                .any(|item| { item.form_id == "freebsd_list_enabled_services" })
        );
    }
}

#[test]
fn common_entry_boundaries_keep_existing_risk_rules_independent() {
    for command in ["command", "nice"] {
        assert_eq!(check(command).decision, Decision::Allow, "{command}");
    }

    // `exec` with only a redirection mutates the shell's stream state. The shell
    // redirection owns the filesystem write; there is no child process to dispatch.
    let result = check("exec > /opt/shared/out");
    assert_eq!(result.decision, Decision::NeedApproval, "{result:#?}");
    assert!(
        !result
            .decision_trace
            .execution_semantics
            .iter()
            .any(|semantics| {
                semantics.normalized_command_name == "exec" && semantics.dispatches_child_command
            }),
        "{result:#?}"
    );

    // The supported shell script entry forms continue to be analyzed as code.
    check("printf 'echo ok\\n' | sh");
    check("ksh ./script.ksh arg");
    check("csh -c 'echo fixed' arg0 arg1");
}

#[test]
fn filesystem_effects_stay_visible_without_invented_remote_or_cloud_paths() {
    let journal = check("journalctl --vacuum-time=1d");
    assert_eq!(journal.decision, Decision::NeedApproval, "{journal:#?}");

    let archive = check("7z a /opt/shared/archive.7z /tmp/input");
    assert_eq!(archive.decision, Decision::NeedApproval, "{archive:#?}");

    // Remote commands retain remote execution semantics and never turn their
    // remote working directory into a local workspace-relative path.
    let kubectl = check("kubectl exec pod -- sh -c 'echo fixed'");
    assert!(
        kubectl
            .decision_trace
            .execution_semantics
            .iter()
            .any(|semantics| {
                semantics.normalized_command_name == "kubectl" && semantics.executes_remote_command
            }),
        "{kubectl:#?}"
    );
}

#[test]
fn dry_runs_and_terminal_protocol_data_keep_their_distinct_meanings() {
    let dry_run = check("parallel --dry-run echo ::: one two");
    assert_eq!(dry_run.decision, Decision::Allow, "{dry_run:#?}");

    let proven_jobs = check("parallel rm -rf ::: /");
    assert_eq!(proven_jobs.decision, Decision::Deny, "{proven_jobs:#?}");
    assert!(
        proven_jobs
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CatastrophicFileSystemDelete),
        "{proven_jobs:#?}"
    );

    let screen = check("screen -Rd build");
    assert_eq!(screen.decision, Decision::NeedApproval, "{screen:#?}");

    let tmux = check("tmux send-keys 'rm -rf /tmp/a'");
    assert!(tmux.decision_trace.nested_payloads.is_empty(), "{tmux:#?}");
}

#[test]
fn non_filesystem_state_domains_are_visible_without_local_path_fiction() {
    let date = check("date --set '2030-01-01 00:00:00'");
    assert!(has_state_operation(
        &date,
        StateOperationDomain::SystemClock,
        StateOperationKind::Mutate
    ));
    assert!(
        !date
            .decision_trace
            .execution_semantics
            .iter()
            .any(|semantics| {
                semantics.normalized_command_name == "date" && semantics.dispatches_child_command
            }),
        "{date:#?}"
    );

    let aws = check("aws ec2 run-instances --image-id ami-123 --instance-type t3.micro");
    assert!(has_state_operation(
        &aws,
        StateOperationDomain::CloudResource,
        StateOperationKind::Mutate
    ));
    assert_eq!(aws.decision, Decision::NeedApproval, "{aws:#?}");

    let service_query = check("systemctl --no-pager status example.service");
    assert!(has_state_operation(
        &service_query,
        StateOperationDomain::ServiceManager,
        StateOperationKind::Inspect
    ));
    assert!(!has_state_operation(
        &service_query,
        StateOperationDomain::ServiceManager,
        StateOperationKind::Control
    ));
}

#[test]
fn bash_debug_trap_registration_keeps_deferred_effects_unresolved() {
    for command in [
        "trap 'printf %s marker' DEBUG",
        "trap 'printf %s marker' DEBUG\nprintf %s body",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|effects| {
                    effects.normalized_command_name == "trap"
                        && effects.form_id == "possible_debug_handler_registration"
                        && effects.operation_semantics_unresolved
                        && !effects.executes_payload
                        && !effects.executes_hook
                        && effects.state_operations.iter().any(|effect| {
                            effect.domain == StateOperationDomain::ShellTrap
                                && effect.operation == StateOperationKind::Control
                        })
                }),
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::StateControl)
        );
        assert!(!response.reasons.iter().any(|reason|
            reason.contains("required parameter") || reason.contains("not fully modeled")
        ), "{command}: {response:#?}");
    }
}

#[test]
fn bash_debug_trap_registration_does_not_claim_other_forms() {
    for command in [
        "trap - DEBUG",
        "trap '' DEBUG",
        "trap -p DEBUG",
        "trap 'printf %s marker' EXIT",
        "trap 'printf %s marker' DEBUG RETURN",
        "env trap 'printf %s marker' DEBUG",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {response:#?}"
        );
        assert!(
            !response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|effects| effects.form_id == "possible_debug_handler_registration"),
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn bash_debug_trap_dynamic_handler_keeps_argv_and_effects_unresolved() {
    let response = ShellQueryCore::new().check(request("trap \"$handler\" DEBUG"));
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    assert!(
        response
            .decision_trace
            .execution_semantics
            .iter()
            .all(|effects| {
                effects.normalized_command_name != "trap"
                    || (effects.operation_semantics_unresolved && !effects.executes_payload)
            })
    );
}

//! End-to-end static checks; Mercurial and submitted payloads are not executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check(command: &str, expected: Decision) -> CheckResponse {
    let r = ShellQueryCore::new().check(CheckRequest {
        session_id: SessionId::new("hg-config"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: ShellStateSnapshot::new("/workspace"),
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    });
    assert_eq!(r.decision, expected, "{command}: {r:#?}");
    r
}

fn semantics(r: &CheckResponse) -> &ExecutionSemanticsFact {
    r.decision_trace
        .execution_semantics
        .iter()
        .find(|s| s.normalized_command_name == "hg")
        .unwrap()
}

#[test]
fn ordinary_queries_and_inactive_configuration_allow_without_resolve_gaps() {
    for command in [
        "hg status",
        "hg st",
        "hg log",
        "hg --config ui.color=never status",
        "hg status --config=ui.color=never",
        "hg --config 'ui.editor=touch /opt/out' log",
        "hg --config 'hooks.pre-log=touch /opt/out' status",
        "hg --config 'hooks.precommit=touch /opt/out' status",
        "hg --config 'alias.other=!touch /opt/out' status",
        "hg --config extensions.probe=!/opt/probe.py log",
        "hg --config hooks.pre-status= status",
        "hg --help --config 'hooks.pre-status=touch /opt/out' status",
        "hg status -- --config extensions.probe=/opt/probe.py",
    ] {
        let r = check(command, Decision::Allow);
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id.family() == RuleFamily::ResolveGap),
            "{command}: {r:#?}"
        );
        let s = semantics(&r);
        assert!(
            !s.executes_hook && !s.loads_in_process_code && !s.executes_payload,
            "{command}: {s:#?}"
        );
    }
}

#[test]
fn active_hooks_require_approval_and_reach_execution_semantics() {
    for (op, canonical) in [
        ("status", "status"),
        ("st", "status"),
        ("log", "log"),
        ("sum", "summary"),
        ("id", "identify"),
    ] {
        for phase in ["pre", "post", "fail"] {
            let command =
                format!("hg --config 'hooks.{phase}-{canonical}.audit=touch /opt/out' {op}");
            let r = check(&command, Decision::NeedApproval);
            let s = semantics(&r);
            assert!(s.executes_hook && s.executes_payload, "{command}: {s:#?}");
            assert!(!s.operation_semantics_unresolved, "{command}: {s:#?}");
            assert!(
                r.decision_trace
                    .decision_proposals
                    .iter()
                    .any(|f| f.rule_id == RuleId::NestedPayloadExpansion),
                "{command}: {r:#?}"
            );
        }
    }
}

#[test]
fn explicit_external_extensions_require_approval_even_with_help() {
    for tail in ["log", "status", "--help", "status --help"] {
        let command = format!("hg --config extensions.probe=/opt/probe.py {tail}");
        let r = check(&command, Decision::NeedApproval);
        assert!(semantics(&r).loads_in_process_code, "{command}: {r:#?}");
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeLoadPath),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn extension_paths_use_existing_workspace_and_temporary_code_policy() {
    for path in ["./probe.py", "/workspace/probe.py", "/tmp/probe.py"] {
        let command = format!("hg --config extensions.probe={path} log");
        let r = check(&command, Decision::Allow);
        assert!(semantics(&r).loads_in_process_code);
    }
    let r = check("hg --config extensions.probe= log", Decision::NeedApproval);
    assert!(semantics(&r).loads_in_process_code);
    for command in [
        "hg --config 'extensions.probe=$EXTENSION' log",
        "hg --config 'extensions.probe=./$EXTENSION' log",
    ] {
        let r = check(command, Decision::NeedApproval);
        assert!(semantics(&r).loads_in_process_code);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeLoadPath),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn alias_overrides_ask_via_payload_semantics_not_form_ambiguity() {
    for command in [
        "hg --config 'alias.status=!touch /opt/out' status",
        "hg --config 'alias.status=update -C' status",
        "hg --config 'alias.x=!touch /opt/out' x",
        "hg --config 'alias.status=!touch /opt/out' status --help",
        "hg --help --config 'alias.x=!touch /opt/out' x",
    ] {
        let r = check(command, Decision::NeedApproval);
        let s = semantics(&r);
        assert!(
            s.executes_payload && !s.operation_semantics_unresolved,
            "{command}: {r:#?}"
        );
        assert!(
            r.decision_trace
                .decision_proposals
                .iter()
                .any(|f| f.rule_id == RuleId::NestedPayloadExpansion)
        );
    }
}

#[test]
fn missing_or_unknown_control_surfaces_remain_approval_cases() {
    for command in [
        "hg --config",
        "hg --config \"$CONFIG\" log",
        "hg --config extensions.probe=/opt/probe.py --unknown-option log",
        "hg status --unknown-option",
        "hg update -C",
    ] {
        check(command, Decision::NeedApproval);
    }
}

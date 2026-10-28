//! Static policy checks: no submitted program or compiler command is executed.
use caushell_core::ShellQueryCore;
use caushell_runner::FilesystemView;
use caushell_types::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Namespace(Mutex<BTreeMap<String, FilesystemEntry>>);
impl FilesystemView for Namespace {
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.0
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .unwrap_or_else(|| {
                if [
                    "/workspace",
                    "/workspace/build",
                    "/tmp",
                    "/private",
                    "/private/tmp",
                    "/outside",
                ]
                .contains(&path)
                {
                    FilesystemEntry::Directory
                } else {
                    FilesystemEntry::Missing
                }
            })
    }
}

fn with_namespace() -> ShellQueryCore {
    ShellQueryCore::new().with_filesystem_view(Arc::new(Namespace::default()))
}

fn request(command: &str, sequence: u64) -> CheckRequest {
    let mut shell = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("BASH_ENV", ShellEnvironmentValue::Absent)
        .with_environment_observation("ENV", ShellEnvironmentValue::Absent);
    shell.observability.variables = ShellStateKnowledge::Complete;
    shell.observability.aliases = ShellStateKnowledge::Complete;
    shell.observability.functions = ShellStateKnowledge::Complete;
    CheckRequest {
        session_id: SessionId::new("compiler-authority"),
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
    let r = ShellQueryCore::new().check(request(command, 1));
    assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
}

#[test]
fn compiler_diagnostics_use_existing_output_authority() {
    for output in ["./build/program", "/tmp/program", "/private/tmp/program"] {
        expect(
            &format!("gcc -Wall -Wextra -pedantic source.c -o {output}"),
            Decision::Allow,
        );
    }
    expect(
        "gcc -Wall source.c -o /outside/program",
        Decision::NeedApproval,
    );
}

#[test]
fn a_pure_version_query_has_no_output_fact_or_ambient_grant() {
    let r = ShellQueryCore::new().check(request("gcc --version | head -1", 1));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.reasons);
    assert!(
        !r.decision_trace
            .path_targets
            .iter()
            .any(|p| p.operation.is_mutation())
    );
    for command in [
        "gcc --version --unknown-mode",
        "gcc --version @options",
        "gcc --version -fplugin=/outside/plugin.so",
        "gcc --version; touch /outside/result",
    ] {
        expect(command, Decision::NeedApproval);
    }
    expect("gcc --version; rm -rf /", Decision::Deny);
}

#[test]
fn compiler_unknown_options_and_code_loads_remain_approval() {
    for command in [
        "gcc -Wall --unknown-mode source.c -o build/program",
        "gcc -Wall -Wl,-Map=/outside/map source.c -o build/program",
        "gcc -Wall -fplugin=/outside/plugin.so source.c -o build/program",
        "gcc @options -o build/program",
    ] {
        expect(command, Decision::NeedApproval);
    }
    expect(
        "gcc -Wall source.c -o build/program; rm -rf /",
        Decision::Deny,
    );
}

#[test]
fn ordinary_output_scope_is_invariant_across_shell_composition() {
    for command in [
        "gcc source.c -o build/tool && ./build/tool 7",
        "cc source.c -o build/other && time ./build/other 8",
        "g++ source.cc -o /tmp/test-tool && /tmp/test-tool",
        "gcc -Wall -Wextra -pedantic source.c -o build/tool && ./build/tool",
        "gcc source.c -o build/tool && for n in 1 2; do result=$(./build/tool $n); printf '%s\\n' \"$result\"; done",
        "gcc source.c -o build/tool; ./build/tool",
        "gcc source.c -o build/tool || ./build/tool",
        "if test -f source.c; then gcc source.c -o build/tool; fi; ./build/tool",
    ] {
        let r = with_namespace().check(request(command, 1));
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        let facts: Vec<_> = r
            .decision_trace
            .path_targets
            .iter()
            .filter(|f| !f.namespace_proofs.is_empty())
            .collect();
        assert!(!facts.is_empty(), "missing proof for {command}");
        for fact in facts {
            assert!(matches!(
                fact.resolution,
                SemanticResolution::Resolved { .. }
            ));
            assert!(
                fact.observations
                    .iter()
                    .any(|o| matches!(o.entry, FilesystemEntry::Missing)),
                "must retain observed absence, not fabricate a compiled file"
            );
        }
    }
}

#[test]
fn resource_proofs_do_not_create_execution_authority() {
    let mut req = request("gcc source.c -o build/tool && ./build/tool", 1);
    req.workspace_root = None;
    let r = with_namespace().check(req);
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .any(|f| !f.namespace_proofs.is_empty())
    );
}

#[test]
fn links_parent_mutations_and_incomplete_operations_cannot_borrow_scope() {
    for command in [
        "ln -s /outside build/tool; ./build/tool",
        "ln -s /outside build; gcc source.c -o build/tool && ./build/tool",
        "mv build /outside/moved; gcc source.c -o build/tool && ./build/tool",
        "gcc --unknown-mode source.c -o build/tool && ./build/tool",
        "gcc -fplugin=./plugin.so source.c -o build/tool && ./build/tool",
        "gcc -specs=./settings source.c -o build/tool && ./build/tool",
        "gcc @options -o build/tool && ./build/tool",
    ] {
        let r = with_namespace().check(request(command, 1));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
    }
    for path in ["/workspace/build", "/workspace/build/tool"] {
        let ns = Arc::new(Namespace::default());
        ns.0.lock().unwrap().insert(
            path.into(),
            FilesystemEntry::Symlink {
                target: "/outside".into(),
            },
        );
        let r = ShellQueryCore::new()
            .with_filesystem_view(ns)
            .check(request("gcc source.c -o build/tool && ./build/tool", 1));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{path}: {:?}",
            r.reasons
        );
    }
}

#[test]
fn deletion_and_deny_remain_independent_of_namespace_proofs() {
    let command = "rm -f build/tool && gcc source.c -o build/tool && ./build/tool";
    let r = with_namespace().check(request(command, 1));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::FileDeletion)
    );
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .rules
        .insert(RuleId::FileDeletion, RulePolicyEntry::new(RuleAction::Deny));
    let r = ShellQueryCore::with_policy(policy)
        .with_filesystem_view(Arc::new(Namespace::default()))
        .check(request(command, 1));
    assert_eq!(r.decision, Decision::Deny);
    let r = with_namespace().check(request(
        "gcc source.c -o build/tool && ./build/tool; rm -rf /",
        1,
    ));
    assert_eq!(r.decision, Decision::Deny);
}

#[test]
fn downloaded_outputs_remain_tainted_after_a_namespace_proof() {
    let mut core = with_namespace();
    core.check(request(
        "curl -q -o build/tool https://example.test/tool",
        1,
    ));
    let r = core.check(request("gcc source.c -o build/tool && ./build/tool", 2));
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::TaintedExecution)
    );
}

#[test]
fn namespace_proofs_expire_across_requests_and_snapshot_restore() {
    let ns = Arc::new(Namespace::default());
    let mut core = ShellQueryCore::new().with_filesystem_view(ns.clone());
    let r = core.check(request("gcc source.c -o build/tool && ./build/tool", 1));
    assert_eq!(r.decision, Decision::Allow);
    let snapshot = core
        .session_snapshot(&SessionId::new("compiler-authority"), 1)
        .unwrap();
    let serialized = serde_json::to_vec(&snapshot).unwrap();
    let snapshot = serde_json::from_slice(&serialized).unwrap();
    let mut restored = ShellQueryCore::new().with_filesystem_view(ns.clone());
    restored.insert_session_state(
        SessionId::new("compiler-authority"),
        caushell_core::SessionState::from_snapshot(snapshot).unwrap(),
    );
    ns.0.lock().unwrap().insert(
        "/workspace/build".into(),
        FilesystemEntry::Symlink {
            target: "/outside".into(),
        },
    );
    let r = restored.check(request("./build/tool", 2));
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .all(|fact| fact.namespace_proofs.is_empty())
    );
}

#[test]
fn unavailable_namespace_and_analysis_limits_keep_approval() {
    let command = "gcc source.c -o build/tool && ./build/tool";
    let r = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem))
        .check(request(command, 1));
    assert_eq!(r.decision, Decision::NeedApproval);
    let mut policy = PolicyConfig::default();
    policy.analysis_budget.max_request_bytes = 8;
    let r = ShellQueryCore::with_policy(policy)
        .with_filesystem_view(Arc::new(Namespace::default()))
        .check(request(command, 1));
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(
        !r.decision_trace
            .analysis_usage
            .unwrap()
            .incomplete_budgets
            .is_empty()
    );
}

#[test]
fn declared_code_load_deny_cannot_become_unknown_option_ask() {
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .rules
        .insert(RuleId::CodeLoadPath, RulePolicyEntry::new(RuleAction::Deny));
    for command in [
        "gcc -Wall -fplugin=/outside/plugin.so source.c -o build/tool",
        "gcc --version -fplugin=/outside/plugin.so",
        "gcc --unknown-mode -fplugin=/outside/plugin.so source.c -o build/tool",
        "gcc -fplugin=/outside/plugin.so --unknown-mode source.c -o build/tool",
    ] {
        let r = ShellQueryCore::with_policy(policy.clone())
            .with_filesystem_view(Arc::new(Namespace::default()))
            .check(request(command, 1));
        assert_eq!(r.decision, Decision::Deny, "{command}: {:?}", r.reasons);
    }
}

#[test]
fn a_changed_producer_spelling_invalidates_its_consumers_transitively() {
    let ns = Arc::new(Namespace::default());
    ns.0.lock()
        .unwrap()
        .insert("/workspace/build/gate".into(), FilesystemEntry::Directory);
    let r = ShellQueryCore::new()
        .with_filesystem_view(ns)
        .check(request(
            "ln -s /outside build/gate; gcc source.c -o build/gate/../tool; ./build/tool",
            1,
        ));
    assert_eq!(r.decision, Decision::NeedApproval);
    let target = r
        .decision_trace
        .path_targets
        .iter()
        .find(|f| f.operation == PathTargetOperation::ExecuteFile)
        .unwrap();
    assert!(target.namespace_proofs.is_empty(), "{target:#?}");
    assert!(
        matches!(target.resolution, SemanticResolution::Unresolved { .. }),
        "{target:#?}"
    );
}

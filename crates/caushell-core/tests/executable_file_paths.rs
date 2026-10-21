use caushell_core::ShellQueryCore;
use caushell_graph::{EdgeKind, NodeKind};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("executable-file-paths"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/bench/workspace"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/bench/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(commands: &[&str], expected: Decision) {
    for command in commands {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(response.decision, expected, "{command}: {response:#?}");
        if expected == Decision::NeedApproval {
            assert!(
                response
                    .decision_trace
                    .findings
                    .iter()
                    .any(|f| { f.rule_id == RuleId::OutsideWorkspaceScriptSource }),
                "{command}: {response:#?}"
            );
        }
    }
}

#[test]
fn explicit_unmodeled_executables_use_existing_execution_scope() {
    expect(
        &[
            "/opt/shared/hello",
            "/opt/shared/hello.bin",
            "'/opt/shared/hello with spaces'",
            "~/bin/hello",
            "~other-user/hello",
            "./{../../opt/shared/hello,hello}",
            "target=/opt/shared/hello; \"$target\"",
            "bash /opt/shared/hello",
        ],
        Decision::NeedApproval,
    );
    expect(
        &[
            "./hello",
            "./hello.py",
            "/bench/workspace/build/hello",
            "/tmp/hello",
            "/private/tmp/hello",
            "'~/hello'",
            "target=./hello; \"$target\"",
            "HOME=/bench/workspace; ~/hello",
            "/usr/bin/printf SAFE",
            "unknown-tool SAFE",
        ],
        Decision::Allow,
    );
}

#[test]
fn derived_executable_paths_have_the_same_boundary() {
    expect(
        &[
            "sort --compress-program=/opt/shared/hello input",
            "find . -exec /opt/shared/hello {} \\;",
            "printf item | xargs /opt/shared/hello",
            "env /opt/shared/hello",
            "command /opt/shared/hello",
            "exec /opt/shared/hello",
            "timeout 1 /opt/shared/hello",
            "bash -c '/opt/shared/hello'",
            "cd $( ~/marker.sh go \"$@\" )",
        ],
        Decision::NeedApproval,
    );
    expect(
        &[
            "sort --compress-program=./hello input",
            "find . -exec ./hello {} \\;",
            "printf item | xargs /tmp/hello",
            "env ./hello",
            "command ./hello",
            "timeout 1 ./hello",
            "bash -c './hello'",
        ],
        Decision::Allow,
    );
}

#[test]
fn executable_scope_uses_execution_cwd_and_not_initial_cwd() {
    expect(
        &[
            "cd /opt/shared; ./hello",
            "cd /opt/shared; sort --compress-program=./hello input",
            "cd \"$unknown\"; ./hello",
            "find /opt/shared -execdir ./hello {} \\;",
        ],
        Decision::NeedApproval,
    );
    expect(
        &[
            "cd /opt/shared; /tmp/hello",
            "cd /opt/shared; cd /bench/workspace; ./hello",
            "find /bench/workspace/sub -execdir ./hello {} \\;",
        ],
        Decision::Allow,
    );
}

#[test]
fn aliases_preserve_actual_executable_words_before_lookup_normalization() {
    expect(
        &[
            "alias h='/opt/shared/hello'\nh",
            "alias h='/usr/sbin/host'\nh example.test",
            "alias h='~/hello'\nh",
        ],
        Decision::NeedApproval,
    );
    expect(
        &["alias h='./hello'\nh", "alias h='/usr/bin/printf'\nh SAFE"],
        Decision::Allow,
    );
}

#[test]
fn executable_paths_do_not_inherit_descriptor_read_exemptions() {
    expect(
        &["/dev/fd/3 3<local", "/proc/self/fd/3 3<local"],
        Decision::NeedApproval,
    );
}

#[test]
fn shell_function_bodies_own_execution_semantics() {
    expect(
        &[
            "function ./hello { printf SAFE; }; ./hello",
            "function /opt/shared/hello { printf SAFE; }; /opt/shared/hello",
            "f() { printf SAFE; }; f",
        ],
        Decision::Allow,
    );
    expect(
        &[
            "function /opt/shared/hello { printf SAFE; }; command /opt/shared/hello",
            "function /opt/shared/hello { printf SAFE; }; env /opt/shared/hello",
        ],
        Decision::NeedApproval,
    );
}

#[test]
fn native_callback_argv_is_not_expanded_as_shell_source() {
    expect(
        &[
            "sort --compress-program='./$UNKNOWN' input",
            "find . -exec '~/hello' {} \\;",
            "target='./$UNKNOWN'; \"$target\"",
        ],
        Decision::Allow,
    );
    expect(
        &["sort --compress-program='/opt/shared/$UNKNOWN' input"],
        Decision::NeedApproval,
    );
}

#[test]
fn missing_workspace_never_trusts_an_arbitrary_executable_directory() {
    let mut req = request("./hello");
    req.workspace_root = None;
    let response = ShellQueryCore::new().check(req);
    assert_eq!(response.decision, Decision::NeedApproval, "{response:#?}");
    let mut req = request("/tmp/hello");
    req.workspace_root = None;
    let response = ShellQueryCore::new().check(req);
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn existing_rule_configuration_controls_executable_file_checks() {
    for (action, expected) in [
        (RuleAction::Observe, Decision::Allow),
        (RuleAction::NeedApproval, Decision::NeedApproval),
        (RuleAction::Deny, Decision::Deny),
    ] {
        let mut policy = PolicyConfig::default();
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceScriptSource,
            RulePolicyEntry::new(action),
        );
        let response = ShellQueryCore::with_policy(policy).check(request("/opt/shared/hello"));
        assert_eq!(response.decision, expected, "{response:#?}");
    }
}

#[test]
fn executable_trust_grants_are_scoped_to_execution() {
    for (scope, expected) in [
        (PathTrustScope::Read, Decision::NeedApproval),
        (PathTrustScope::Write, Decision::NeedApproval),
        (PathTrustScope::ScriptSourceExecute, Decision::Allow),
    ] {
        let mut policy = PolicyConfig::default();
        policy.path_trust_sets.insert(
            "tools".into(),
            PathTrustSet::new(
                vec!["/opt/shared".into()],
                PathTrustGrant::Scoped {
                    scopes: [scope].into_iter().collect(),
                },
            ),
        );
        policy.rule_policy.rules.insert(
            RuleId::OutsideWorkspaceScriptSource,
            RulePolicyEntry::new(RuleAction::NeedApproval).with_trust_sets(vec!["tools".into()]),
        );
        let response = ShellQueryCore::with_policy(policy).check(request("/opt/shared/hello"));
        assert_eq!(response.decision, expected, "{response:#?}");
    }
}

#[test]
fn graph_retains_derived_executable_path_and_code_consumption() {
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::OutsideWorkspaceScriptSource,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    let mut core = ShellQueryCore::with_policy(policy);
    let response = core.check(request("sort --compress-program=/opt/shared/hello input"));
    assert_eq!(response.decision, Decision::Allow, "{response:#?}");
    let graph = core
        .session_graph(&SessionId::new("executable-file-paths"))
        .unwrap();
    let fact = graph.nodes().find(|n| matches!(&n.kind,
        NodeKind::PathFact { resolution, purpose: Some(ResolvedPathPurpose::ScriptSource), slot_name, .. }
        if slot_name == "@executable_file" && resolution.concrete_path() == Some("/opt/shared/hello")
    )).unwrap();
    let read = graph
        .edges()
        .iter()
        .find(|e| e.to == fact.id && e.kind == EdgeKind::Reads)
        .unwrap();
    assert!(
        graph
            .nodes()
            .any(|n| n.id == read.from && matches!(n.kind, NodeKind::DerivedInvocation { .. }))
    );
    assert!(graph.edges().iter().any(|e| e.from == read.from && matches!(&e.semantics,
        Some(ProvenanceEdgeSemantics::Consume { consume_kind: ProvenanceConsumeKind::ScriptSource, slot_name: Some(slot), .. })
        if slot == "@executable_file"
    )));
}

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
fn optimization_reuses_output_and_execution_authority() {
    for (tool, flags) in [
        ("gcc", "-O"),
        ("gcc", "-O0"),
        ("cc", "-O1"),
        ("gcc", "-O2 -std=c17 -Wall -Wextra"),
        ("g++", "-O3 -g"),
        ("gcc", "-Os"),
        ("gcc", "-Og -fsanitize=undefined"),
        ("gcc", "-Oz"),
        ("gcc", "-Ofast -O2"),
    ] {
        let command = format!("{tool} {flags} input.c -o build/tool && ./build/tool");
        let result = with_namespace().check(request(&command, 1));
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .path_targets
                .iter()
                .any(|p| !p.namespace_proofs.is_empty())
        );
    }
    for command in [
        "gcc -O2 input.c -o /outside/tool && /outside/tool",
        "gcc -O2 -fplugin=/outside/plugin.so input.c -o build/tool",
        "gcc -O2 -fprofile-generate input.c -o build/tool",
        "gcc -Ounknown -O2 input.c -o build/tool && ./build/tool",
    ] {
        assert_eq!(
            with_namespace().check(request(command, 1)).decision,
            Decision::NeedApproval,
            "{command}"
        );
    }
}

#[test]
fn deleting_then_compiling_stays_ask_without_an_optimization_gap() {
    for command in [
        "rm -f build/tool; gcc -O2 input.c -o build/tool && ./build/tool",
        "gcc -O2 input.c -o build/tool; rm build/tool",
    ] {
        let result = with_namespace().check(request(command, 1));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{:?}",
            result.reasons
        );
        assert!(
            result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::FileDeletion)
        );
        assert!(
            !result
                .reasons
                .iter()
                .any(|r| r.contains("UnmodeledModifier")),
            "{:?}",
            result.reasons
        );
    }
}

#[test]
fn optimization_does_not_downgrade_deny_or_incomplete_analysis() {
    for flags in ["-O2", "-Ounknown -O2"] {
        let result = with_namespace().check(request(
            &format!("printf '%s\\n' 'rm -rf /' | gcc {flags} -wrapper /bin/sh,-s input.c"),
            1,
        ));
        assert_eq!(result.decision, Decision::Deny, "{:?}", result.reasons);
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::CodeLoadPath, RulePolicyEntry::new(RuleAction::Deny));
        let result = ShellQueryCore::with_policy(policy)
            .with_filesystem_view(Arc::new(Namespace::default()))
            .check(request(
                &format!("gcc {flags} -fplugin=/outside/plugin.so input.c -o build/tool"),
                1,
            ));
        assert_eq!(result.decision, Decision::Deny, "{:?}", result.reasons);
    }
    let result = with_namespace().check(request("gcc -O2 input.c -o build/tool; rm -rf /", 1));
    assert_eq!(result.decision, Decision::Deny);
    let result = ShellQueryCore::new()
        .with_filesystem_view(Arc::new(caushell_runner::UnavailableFilesystem))
        .check(request("gcc -O2 input.c -o build/tool && ./build/tool", 1));
    assert_eq!(result.decision, Decision::NeedApproval);
}

#[test]
fn standards_reuse_existing_authority_and_require_every_value_to_be_known() {
    for tool in ["gcc", "g++", "cc"] {
        for flags in [
            "-std=c17",
            "-std=gnu17 -std=c18",
            "-std=c++20",
            "-ansi",
            "-std=c17 -g -fsanitize=address,undefined",
        ] {
            let command = format!("{tool} {flags} input.c -o build/program && ./build/program");
            let response = with_namespace().check(request(&command, 1));
            assert_eq!(
                response.decision,
                Decision::Allow,
                "{command}: {:?}",
                response.reasons
            );
        }
    }
    for flags in [
        "-std=unknown",
        "-std=unknown -std=c17",
        "-std=c17 -std=\"$UNKNOWN\"",
    ] {
        let response = with_namespace().check(request(
            &format!("gcc {flags} input.c -o build/program && ./build/program"),
            1,
        ));
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{:?}",
            response.reasons
        );
        assert!(
            response
                .decision_trace
                .path_targets
                .iter()
                .all(|p| p.namespace_proofs.is_empty())
        );
    }
    for command in [
        "gcc -std=c17 input.c -o /outside/program",
        "gcc -std=c17 input.c -o build/program; rm build/program",
    ] {
        assert_eq!(
            with_namespace().check(request(command, 1)).decision,
            Decision::NeedApproval
        );
    }
    for standard in ["c17", "unknown"] {
        let command =
            format!("printf '%s\\n' 'rm -rf /' | gcc -std={standard} -wrapper /bin/sh,-s input.c");
        assert_eq!(
            with_namespace().check(request(&command, 1)).decision,
            Decision::Deny
        );
    }
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
        "gcc source.c && ./a.out 7",
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
fn executable_spellings_stay_paired_with_their_directory_candidate() {
    // `cd` can fail: both directories are real analysis alternatives. A
    // spelling from one alternative must not be attached to the other's path.
    let r = with_namespace().check(request(
        "gcc source.c -o build/tool; cd build; value=$(./tool)",
        1,
    ));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.reasons);
    let facts: Vec<_> = r
        .decision_trace
        .path_targets
        .iter()
        .filter(|f| f.slot_name == "@executable_file")
        .collect();
    assert!(!facts.is_empty());
    for fact in facts {
        let spelling = fact.spelling.as_deref().unwrap();
        let expected = spelling.replace("/./", "/");
        assert_eq!(
            fact.lexical.concrete_path(),
            Some(expected.as_str()),
            "{fact:#?}"
        );
    }
}

#[test]
fn matching_lexical_paths_do_not_collapse_distinct_symlink_spellings() {
    let namespace = Arc::new(Namespace::default());
    namespace.0.lock().unwrap().extend([
        ("/workspace/left".into(), FilesystemEntry::Directory),
        (
            "/workspace/right".into(),
            FilesystemEntry::Symlink {
                target: "/outside/dir".into(),
            },
        ),
        ("/outside/dir".into(), FilesystemEntry::Directory),
    ]);
    let mut req = request("cd /workspace/right; value=$(../tool)", 1);
    req.shell_state_before.cwd = "/workspace/left".into();
    let r = ShellQueryCore::new()
        .with_filesystem_view(namespace)
        .check(req);
    assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
    // Both cwd alternatives normalize lexically to /workspace/tool. The
    // original right/../tool spelling must still follow the symlink first.
    assert!(r.decision_trace.path_targets.iter().any(|f|
        f.slot_name=="@executable_file" && f.spelling.as_deref()==Some("/workspace/right/../tool")
        && matches!(&f.resolution, SemanticResolution::Resolved {value} if value.concrete_path()==Some("/outside/tool"))
    ),"{r:#?}");
}

#[test]
fn successful_compound_entry_is_retained_for_every_substitution() {
    for tool in ["gcc", "cc", "g++"] {
        for body in [
            "first=$(./tool 1); second=$(./tool 2)",
            "first=$(printf x); second=$(./tool 2); third=$(./tool 3)",
        ] {
            let command =
                format!("cd build && {tool} ../source.c -o tool && for n in 1 2; do {body}; done");
            let r = with_namespace().check(request(&command, 1));
            assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
            for fact in r
                .decision_trace
                .path_targets
                .iter()
                .filter(|f| f.slot_name == "@executable_file")
            {
                assert_eq!(
                    fact.lexical.concrete_path(),
                    Some("/workspace/build/tool"),
                    "{fact:#?}"
                );
                assert!(!fact.namespace_proofs.is_empty(), "{fact:#?}");
            }
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

#[test]
fn unknown_compiler_options_do_not_erase_existing_wrapper_deny() {
    for invocation in [
        "gcc -wrapper /bin/sh,-s input.c",
        "gcc --unknown-mode -wrapper /bin/sh,-s input.c",
        "gcc -wrapper /bin/sh,-s --unknown-mode input.c",
    ] {
        let r = with_namespace().check(request(
            &format!("printf '%s\\n' 'rm -rf /' | {invocation}"),
            1,
        ));
        assert_eq!(r.decision, Decision::Deny, "{invocation}: {:?}", r.reasons);
    }
}

#[test]
fn incomplete_siblings_cannot_receive_closed_namespace_certificates() {
    for sibling in [
        "ln --unknown /outside build",
        "unmodeled-command build",
        "$unknown build",
    ] {
        let r = with_namespace().check(request(
            &format!("gcc source.c -o build/tool; {sibling}; ./build/tool"),
            1,
        ));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{sibling}: {:?}",
            r.reasons
        );
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .all(|f| f.namespace_proofs.is_empty()),
            "{sibling}"
        );
    }
    let r = with_namespace().check(request(
        "gcc source.c -o build/tool; note=ready; ./build/tool",
        1,
    ));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.reasons);
    assert!(
        r.decision_trace
            .path_targets
            .iter()
            .any(|f| !f.namespace_proofs.is_empty())
    );
}

#[test]
fn downloaded_compiler_inputs_retain_execution_provenance() {
    for flags in ["", "-O2 -g -std=c17"] {
        let mut core = with_namespace();
        core.check(request(
            "curl -q -o source.c https://example.test/source",
            1,
        ));
        let r = core.check(request(
            &format!("gcc {flags} source.c -o build/tool && ./build/tool"),
            2,
        ));
        assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::TaintedExecution)
        );
        let r = with_namespace().check(request(
            &format!("curl -q https://example.test/source | gcc {flags} -x c - -o build/tool; ./build/tool"),
            1,
        ));
        assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::TaintedExecution)
        );
    }
}

#[test]
fn instrumentation_preserves_compile_execute_path_and_authority_separation() {
    for (tool, flags, output) in [
        ("gcc", "-g -fsanitize=address,undefined", "build/checked"),
        ("g++", "-ggdb3 -fsanitize=undefined,address", "/tmp/checked"),
        (
            "cc",
            "-g0 -fsanitize=leak -fno-sanitize=leak",
            "build/checked",
        ),
        ("gcc", "-gdwarf-4 -fno-sanitize=all", "build/checked"),
    ] {
        let command = format!(
            "{tool} {flags} input.c -o {output} && {output_path}",
            output_path = if output.starts_with('/') {
                output.to_owned()
            } else {
                format!("./{output}")
            }
        );
        let r = with_namespace().check(request(&command, 1));
        assert_eq!(r.decision, Decision::Allow, "{command}: {:?}", r.reasons);
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .any(|f| !f.namespace_proofs.is_empty())
        );
    }
    let r = with_namespace().check(request(
        "gcc -g -fsanitize=address input.c -o /outside/checked && /outside/checked",
        1,
    ));
    assert_eq!(r.decision, Decision::NeedApproval);
    let mut req = request(
        "gcc -g -fsanitize=address input.c -o build/checked && ./build/checked",
        1,
    );
    req.workspace_root = None;
    assert_eq!(with_namespace().check(req).decision, Decision::NeedApproval);
}

#[test]
fn exact_instrumentation_bindings_do_not_guess_unknown_values() {
    let r = with_namespace().check(request("modes=address,undefined; gcc -fsanitize=\"$modes\" -g input.c -o build/checked && ./build/checked", 1));
    assert_eq!(r.decision, Decision::Allow, "{:?}", r.reasons);
    for flags in [
        "-fsanitize=address,unknown",
        "-fsanitize=unknown -fno-sanitize=all",
        "-fsanitize=\"$UNKNOWN\"",
        "-gsplit-dwarf -fsanitize=address",
    ] {
        let r = with_namespace().check(request(
            &format!("gcc -g {flags} input.c -o build/checked && ./build/checked"),
            1,
        ));
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{flags}: {:?}",
            r.reasons
        );
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .all(|f| f.namespace_proofs.is_empty()),
            "{flags}"
        );
    }
}

#[test]
fn instrumentation_retains_deletion_approval_and_existing_denies() {
    let command = "rm -f build/checked; gcc -g -fsanitize=address,undefined input.c -o build/checked && ./build/checked";
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
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .with_filesystem_view(Arc::new(Namespace::default()))
            .check(request(command, 1))
            .decision,
        Decision::Deny
    );
    for modes in ["address,undefined", "unknown"] {
        let r = with_namespace().check(request(
            &format!("gcc -g -fsanitize={modes} input.c -o build/checked; rm -rf /"),
            1,
        ));
        assert_eq!(r.decision, Decision::Deny);
        let r = with_namespace().check(request(
            &format!(
                "printf '%s\\n' 'rm -rf /' | gcc -g -fsanitize={modes} -wrapper /bin/sh,-s input.c"
            ),
            1,
        ));
        assert_eq!(r.decision, Decision::Deny, "{modes}: {:?}", r.reasons);
        let mut policy = PolicyConfig::default();
        policy
            .rule_policy
            .rules
            .insert(RuleId::CodeLoadPath, RulePolicyEntry::new(RuleAction::Deny));
        let r = ShellQueryCore::with_policy(policy)
            .with_filesystem_view(Arc::new(Namespace::default()))
            .check(request(
                &format!(
                    "gcc -g -fsanitize={modes} -fplugin=/outside/plugin.so input.c -o build/checked"
                ),
                1,
            ));
        assert_eq!(r.decision, Decision::Deny, "{modes}: {:?}", r.reasons);
    }
}

#[test]
fn instrumentation_values_are_revalidated_after_snapshot_restore() {
    let command = "gcc -g -fsanitize=\"$SANITIZERS\" input.c -o build/checked && ./build/checked";
    let mut core = with_namespace();
    let mut first = request(command, 1);
    first.shell_state_before = first.shell_state_before.with_exact_scalar_variable(
        "SANITIZERS",
        "address,undefined",
        false,
    );
    assert_eq!(core.check(first).decision, Decision::Allow);
    let snapshot = core
        .session_snapshot(&SessionId::new("compiler-authority"), 1)
        .unwrap();
    let snapshot = serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let mut restored = with_namespace();
    restored.insert_session_state(
        SessionId::new("compiler-authority"),
        caushell_core::SessionState::from_snapshot(snapshot).unwrap(),
    );
    for (sequence, modes, expected) in [
        (2, Some("unknown"), Decision::NeedApproval),
        (3, None, Decision::NeedApproval),
        (4, Some("undefined,address"), Decision::Allow),
    ] {
        let mut req = request(command, sequence);
        req.shell_state_before = match modes {
            Some(value) => {
                req.shell_state_before
                    .with_exact_scalar_variable("SANITIZERS", value, false)
            }
            None => {
                req.shell_state_before
                    .with_opaque_dynamic_variable("SANITIZERS", "$DYNAMIC", false)
            }
        };
        let r = restored.check(req);
        assert_eq!(r.decision, expected, "{modes:?}: {:?}", r.reasons);
        assert_eq!(
            r.decision_trace
                .path_targets
                .iter()
                .any(|p| !p.namespace_proofs.is_empty()),
            expected == Decision::Allow
        );
    }
}

#[test]
fn instrumentation_does_not_clean_downloaded_source_provenance() {
    let mut core = with_namespace();
    core.check(request("curl -q -o input.c https://example.test/source", 1));
    let r = core.check(request(
        "gcc -g3 -fsanitize=address,undefined input.c -o build/checked && ./build/checked",
        2,
    ));
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    assert!(
        r.decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::TaintedExecution)
    );
}

//! Guard checks only: none of these supplied programs are executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("execution-boundaries-loops"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/workspace/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/workspace/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(c: &str) -> CheckResponse {
    ShellQueryCore::new().check(request(c))
}
fn opaque(r: &CheckResponse) -> bool {
    r.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
        EvidenceKind::NestedPayloadUnresolved(p) if p.unresolved_execution_payload_subtype == Some(UnresolvedExecutionPayloadSubtype::OpaqueNonShell)))
}

#[test]
fn arbitrary_non_shell_code_asks_for_every_carrier() {
    for c in [
        "python -c 'print(1)'",
        "python3 -c 'open(\"/opt/file\",\"w\").write(\"data\")'",
        "node -e '1+1'",
        "node -p '1+1'",
        "node --print '1+1'",
        "node -pe '1+1'",
        "node -e 'require(\"fs\").writeFileSync(\"/opt/file\",\"data\")'",
        "perl -e 'print 1'",
        "python scripts/tool.py",
        "node scripts/tool.js",
        "python /opt/tool.py",
        "node /opt/tool.js",
        "python - <<'PY'\nprint(1)\nPY",
        "node <<'JS'\n1+1\nJS",
        "printf 'print(1)' | python -",
        "printf '1+1' | node",
        "printf '1+1' | node -",
        "node - <<'JS'\n1+1\nJS",
        "echo $(node -e '1+1')",
        "cat <(python -c 'print(1)')",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::NeedApproval, "{c}: {r:#?}");
        assert!(opaque(&r), "{c}: {r:#?}");
        if c.starts_with("node -p") || c.starts_with("node --print") {
            assert!(r.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
                EvidenceKind::NestedPayloadUnresolved(p) if p.context.source == NestedPayloadSourceEvidence::InlineString
                && matches!(&p.context.input, NestedPayloadInputEvidence::ArgumentFragments { text, .. } if text == "1+1"))), "{c}: {r:#?}");
            assert!(
                !r.decision_trace
                    .nested_payloads
                    .iter()
                    .any(|p| p.source == NestedPayloadSource::ScriptFileRef)
            );
        }
        assert!(
            r.decision_trace
                .derived_invocations
                .iter()
                .all(|i| i.command_name.as_deref() != Some("print"))
        );
    }
}

#[test]
fn known_python_contracts_and_shell_payloads_remain_semantic() {
    for c in [
        "python --version",
        "python --help",
        "python -m json.tool input.json",
        "python -m http.server --bind 127.0.0.1",
        "bash -c 'printf hello'",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::Allow, "{c}: {r:#?}");
        assert!(!opaque(&r), "{c}: {r:#?}");
    }
    let r = check("python -m http.server --bind 0.0.0.0");
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(!opaque(&r));
    let mut policy = PolicyConfig::default();
    policy
        .rule_policy
        .resolve_gap
        .unresolved_execution_payload_subtypes
        .insert(
            UnresolvedExecutionPayloadSubtype::OpaqueNonShell,
            RuleAction::Observe,
        );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("node -e '1+1'"))
            .decision,
        Decision::Allow
    );
    assert_eq!(check("node -e '1+1'; rm -rf /").decision, Decision::Deny);
}

#[test]
fn interactive_escape_defaults_to_ask_but_can_be_overridden() {
    for c in [
        "less README.md",
        "vim README.md",
        "man ls",
        "systemctl status example.service",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::NeedApproval, "{c}: {r:#?}");
        assert!(
            r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::InteractiveEscapeSurface)
        );
    }
    for c in [
        "systemctl --no-pager status example.service",
        "cat README.md",
        "tmux list-sessions",
        "tmux ls",
        "tmux -S /tmp/session.socket list-sessions",
    ] {
        assert_eq!(check(c).decision, Decision::Allow, "{c}");
    }
    for c in [
        "tmux list-sessions --future",
        "tmux list-sessions \"$ARGS\"",
        "tmux new-session",
    ] {
        assert_eq!(check(c).decision, Decision::NeedApproval, "{c}");
    }
    for c in [
        "python -m custom_module",
        "python -m \"$MODULE\"",
        "env python -m custom_module",
    ] {
        assert_eq!(check(c).decision, Decision::NeedApproval, "{c}");
    }
    let mut policy = PolicyConfig::default();
    policy.rule_policy.rules.insert(
        RuleId::InteractiveEscapeSurface,
        RulePolicyEntry::new(RuleAction::Observe),
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy.clone())
            .check(request("less README.md"))
            .decision,
        Decision::Allow
    );
    assert_eq!(
        ShellQueryCore::with_policy(policy)
            .check(request("less README.md; rm -rf /"))
            .decision,
        Decision::Deny
    );
}

#[test]
fn quoted_iteration_paths_keep_bounds_and_templates() {
    for c in [
        "for filename in ./*.jpg; do mv \"$filename\" \"prefix_$filename\"; done",
        "for f in ./a ./b; do cp \"$f\" \"${f}.bak\"; done",
        "for f in ./data/*.txt; do chmod u+w \"$f\"; done",
        "for f in ./*.jpg; do for g in \"$f\"; do cp \"$g\" ./out; done; done",
        "set -- ./a ./b; for f; do cp \"$f\" ./out; done",
        "ROOT=./a; for f in \"$ROOT\"; do chmod u+w \"$f\"; done",
        "f=./safe; (for f in /opt/*.txt; do :; done); chmod u+w \"$f\"",
        "f=./safe; for f in /opt/*.txt; do :; done & chmod u+w \"$f\"",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::Allow, "{c}: {r:#?}");
        assert!(
            !r.decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::SelectionError)
        );
    }
}

#[test]
fn uncertain_external_and_overwritten_iterations_do_not_borrow_safe_bounds() {
    for c in [
        "for f in /opt/shared/*.jpg; do mv \"$f\" ./out; done",
        "for f in ./a /opt/b; do chmod u+w \"$f\"; done",
        "f=./safe; for f in $FILES; do chmod u+w \"$f\"; done",
        "for f in $(cat list); do chmod u+w \"$f\"; done",
        "for f in ./*.jpg; do cp $f ./out; done",
        "for f in ./*.jpg; do f=/opt/file; chmod u+w \"$f\"; done",
        "for f in ./*.jpg; do read f; chmod u+w \"$f\"; done",
        "for f in ./*.jpg; do cp \"${f%.*}\" ./out; done",
        "for f in ./*.jpg; do cp \"$f$f\" ./out; done",
        "f=./safe; for f in /opt/*.txt; do :; done; chmod u+w \"$f\"",
        "for f in ./*.jpg; do cd /opt; chmod u+w \"$f\"; done",
        "for f in {/opt/a,./b}; do chmod u+w \"$f\"; done",
        "for f in ./*.jpg; do rm \"$f\"; done",
        "for f in ./*.jpg; do cp \"\\$f\" /opt/out; done",
        "for f in ./*.jpg; do env f=/opt/file bash -c 'chmod u+w \"$f\"'; done",
        "for f in ./*.jpg; do for f in /opt/*.txt; do :; done; chmod u+w \"$f\"; done",
    ] {
        let r = check(c);
        assert_eq!(r.decision, Decision::NeedApproval, "{c}: {r:#?}");
    }
}

#[test]
fn loop_bounds_enter_graph_without_concrete_filenames_or_final_values() {
    use caushell_graph::NodeKind;
    let mut core = ShellQueryCore::new();
    let r = request("for f in ./*.jpg; do cp \"$f\" \"${f}.bak\"; done");
    let id = r.session_id.clone();
    assert_eq!(core.check(r).decision, Decision::Allow);
    let graph = core.session_graph(&id).unwrap();
    assert!(graph.nodes().any(|n| matches!(&n.kind, NodeKind::PathFact {
        resolution: PathResolution::BoundedPathSet { roots, may_escape: false },
        role: ResolvedPathRole::Write, ..
    } if roots == &["/workspace/project".to_string()])));
    let mut next = request("chmod u+w \"$f\"");
    next.sequence_no = CommandSequenceNo::new(2);
    assert_eq!(core.check(next).decision, Decision::NeedApproval);
}

#[test]
fn oversized_lists_and_implicit_unknown_positionals_do_not_guess() {
    for c in [
        "for f; do chmod u+w \"$f\"; done".to_string(),
        format!(
            "for f in {}; do chmod u+w \"$f\"; done",
            (0..257)
                .map(|i| format!("./f{i}"))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    ] {
        assert_eq!(check(&c).decision, Decision::NeedApproval, "{c}");
    }
}

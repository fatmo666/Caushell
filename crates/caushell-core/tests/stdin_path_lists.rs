//! Commands are static Caushell inputs; no archive command is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{EdgeKind, NodeKind};
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("stdin-filenames"),
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
    }
}

fn check(command: &str, expected: Decision) -> ShellQueryCore {
    let mut core = ShellQueryCore::new();
    let response = core.check(request(command));
    assert_eq!(response.decision, expected, "{command}: {response:#?}");
    if expected == Decision::NeedApproval {
        assert!(
            response
                .decision_trace
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {response:#?}"
        );
    }
    core
}

#[test]
fn exact_nul_filename_lists_use_native_paths() {
    for command in [
        r"printf './cache/a\0' | cpio -oa0",
        r"printf './cache/a\0./cache/b\0' | cpio -oa0",
        r"printf './a b\0./a\nb\0' | cpio -oa0",
        r"printf './cache/a\0' | cpio --create --reset-access-time --null",
        r"printf './cache/a\0' | cpio -pa0 cache/backup",
        r"printf './literal$var*\0' | cpio -oa0",
        r"printf '~/literal\0' | cpio -oa0",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn outside_mixed_and_parent_paths_still_require_approval() {
    for command in [
        r"printf '/etc/passwd\0' | cpio -oa0",
        r"printf './cache/a\0/etc/passwd\0' | cpio -oa0",
        r"printf '../outside\0' | cpio -oa0",
        r"printf './cache/a\0' | cpio -pa0 /opt/backup",
        r"printf '/etc/passwd\0' | cpio -pa0 cache/backup",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn nul_producer_contracts_preserve_workspace_bounds() {
    for command in [
        "find . -print0 | cpio -oa0",
        "find ./src -type f -print0 | cpio -oa0",
        "find . -xdev -print0 | cpio -oa0V | gzip > backup.cpio.gz",
        "find ./src -print0 | cpio -pa0 cache/backup",
        "bash -c 'find . -print0 | cpio -oa0'",
    ] {
        check(command, Decision::Allow);
    }
}

#[test]
fn outside_and_escaping_producer_domains_remain_approval() {
    for command in [
        "find /etc -print0 | cpio -oa0",
        "find /tmp/lab -print0 | cpio -oa0",
        "find . /etc -print0 | cpio -oa0",
        "find -L . -print0 | cpio -oa0",
        "find . -print0 | cpio -oa0 <unknown-list",
    ] {
        check(command, Decision::NeedApproval);
    }
}

#[test]
fn known_newline_lists_are_separate_from_unknown_newline_streams() {
    check(
        r"printf './cache/a\n./cache/b\n' | cpio -oa",
        Decision::Allow,
    );
    check(r"cpio -oa <<<'./cache/a'", Decision::Allow);
    check(r"printf '/etc/passwd\n' | cpio -oa", Decision::NeedApproval);
    // A filename containing LF can introduce an absolute name in the consumer.
    check("find . -print | cpio -oa", Decision::NeedApproval);
    check("find . -print | cpio -oa0", Decision::NeedApproval);
    check("find . -print0 | cpio -oa", Decision::NeedApproval);
}

#[test]
fn redirects_stderr_and_transforms_do_not_borrow_a_path_domain() {
    for command in [
        "find . -print0 |& cpio -oa0",
        "find . -print0 2>&1 | cpio -oa0",
        "find . -print0 >list | cpio -oa0",
        "find . -print0 | sed -z 's|./|/etc/|' | cpio -oa0",
        "find . -print0 | cpio -oa0 <&3",
        "find . -print0 | cpio -oa0 <<<'/etc/passwd'",
        "cat unknown-list | cpio -oa0",
    ] {
        check(command, Decision::NeedApproval);
    }
    check(
        "find /etc -print0 | cpio -oa0 <<<'./local'",
        Decision::Allow,
    );
}

#[test]
fn shadowed_producers_do_not_inherit_registry_guarantees() {
    check(
        r"find() { printf '/etc/passwd\0'; }; find . -print0 | cpio -oa0",
        Decision::NeedApproval,
    );
    check(
        r"printf() { echo /etc/passwd; }; printf './cache/a\n' | cpio -oa",
        Decision::NeedApproval,
    );
    check(
        r"alias printf='echo /etc/passwd'; printf './cache/a\n' | cpio -oa",
        Decision::NeedApproval,
    );
}

#[test]
fn empty_lists_have_no_metadata_targets() {
    for command in [r"printf '' | cpio -oa0", "cpio -oa0 </dev/null"] {
        let core = check(command, Decision::Allow);
        let graph = core.session_graph(&request("").session_id).unwrap();
        assert!(
            !graph
                .edges()
                .iter()
                .any(|edge| edge.kind == EdgeKind::MutatesMetadata)
        );
    }
}

#[test]
fn source_metadata_paths_enter_the_graph_without_content_writes() {
    let core = check(r"printf './cache/a\0' | cpio -oa0", Decision::Allow);
    let graph = core.session_graph(&request("").session_id).unwrap();
    assert!(graph.nodes().any(|node| matches!(&node.kind,
        NodeKind::PathFact { resolution: PathResolution::Concrete {path}, metadata_mutation: Some(_), .. }
            if path == "/workspace/cache/a")));
    assert!(
        graph
            .edges()
            .iter()
            .any(|edge| edge.kind == EdgeKind::MutatesMetadata)
    );
    assert!(
        !graph
            .edges()
            .iter()
            .any(|edge| edge.kind == EdgeKind::Writes
                && matches!(&graph.get_node(&edge.to).unwrap().kind,
            NodeKind::PathFact { resolution: PathResolution::Concrete {path}, .. }
                if path == "/workspace/cache/a"))
    );
    let core = check("find ./src -print0 | cpio -oa0", Decision::Allow);
    let graph = core.session_graph(&request("").session_id).unwrap();
    assert!(graph.nodes().any(|node| matches!(&node.kind,
        NodeKind::PathFact { resolution: PathResolution::BoundedPathSet {roots, may_escape: false}, metadata_mutation: Some(_), .. }
            if roots == &["/workspace/src".to_string()])));
}

#[test]
fn reading_without_source_metadata_mutation_remains_allowed() {
    check(r"printf '/etc/passwd\0' | cpio -o0", Decision::Allow);
    check("cpio -ita", Decision::Allow);
}

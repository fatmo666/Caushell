//! Static checks only: no benchmark command or mutation is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::NodeKind;
use caushell_types::*;

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("pipeline-path-records"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-record-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn expect(command: &str, decision: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, decision, "{command}: {result:#?}");
}

#[test]
fn nul_path_records_reach_known_child_mutation_slots() {
    for command in [
        "find . -type f -print0 | xargs -0 chmod 644",
        "find . -type d -print0 | xargs --null chmod 755",
        "find ./src -type f -print0 | xargs -0 -n1 chmod 644",
        "find -type f -print0 | xargs -0 chmod 644",
        r"find . -name \*.py -print0 | xargs -0 sed -i '1a Line of text here'",
        "find . -type f -print0 | xargs -0 -I{} mv {} archive",
        "find . -print0 | xargs -0 -I{} mv {} {}.bak",
        "find /tmp/project/ -print0 | xargs -0 -I{} mv {} {}.bak",
        "find './space dir' -print0 | xargs -0 chmod 644",
        "find ./src /tmp/project/lib -print0 | xargs -0 chmod 644",
        "root=./src; find \"$root\" -print0 | xargs -0 chmod 644",
        "find . -print0 | tee cache.paths | xargs -0 chmod 644",
        "find . -print0 2>/dev/null | xargs -0 chmod 644",
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn bounded_domain_is_retained_in_graph_not_just_the_decision() {
    let mut core = ShellQueryCore::new();
    let response = core.check(request("find . -type f -print0 | xargs -0 chmod 644"));
    assert_eq!(response.decision, Decision::Allow);
    assert!(core.session_graph(&SessionId::new("pipeline-path-records")).unwrap().nodes().any(|node| matches!(&node.kind,
        NodeKind::PathFact { resolution, normalized_command_name: Some(name), .. } if name == "chmod" && matches!(resolution,
            PathResolution::BoundedPathSet { roots, may_escape: false } if roots == &vec!["/tmp/project".to_string()])
    )), "{:#?}", response.decision_trace);
}

#[test]
fn outside_unknown_or_escaping_roots_are_not_laundered() {
    for command in [
        "find /opt/shared -print0 | xargs -0 chmod 644",
        "find . /opt/shared -print0 | xargs -0 chmod 644",
        "find ../shared -print0 | xargs -0 chmod 644",
        "find \"$unknown\" -print0 | xargs -0 chmod 644",
        "find -L . -print0 | xargs -0 chmod 644",
        "find . -follow -print0 | xargs -0 chmod 644",
        "cd /opt/shared; find . -print0 | xargs -0 chmod 644",
        "find . -print0 | xargs -0 -I{} mv {} /opt/shared",
        "find /opt/shared -print0 | xargs -0 -I{} mv {} {}.bak",
        // The inclusive named root may itself become /tmp/project.bak;
        // unlike a root spelled with a trailing '/', this can escape.
        "find /tmp/project -print0 | xargs -0 -I{} mv {} {}.bak",
        "find -L . -print0 | xargs -0 -I{} mv {} {}.bak",
        "find \"$unknown\" -print0 | xargs -0 -I{} mv {} {}.bak",
        "find . -print0 | tee /opt/shared/paths | xargs -0 chmod 644",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn non_preserving_output_and_fd_routing_remain_unknown() {
    for command in [
        "find . -print | xargs chmod 644",
        "find . -print | xargs -I{} mv {} {}.bak",
        "find . -print0 | xargs chmod 644",
        "find . -print | xargs -0 chmod 644",
        "find . -print0 -print | xargs -0 chmod 644",
        "find . -printf '%p\\0' | xargs -0 chmod 644",
        "find . -print0 -ls | xargs -0 chmod 644",
        "find . -print0 --help | xargs -0 chmod 644",
        "find . -print0 --version | xargs -0 chmod 644",
        "find . -print0 -help | xargs -0 chmod 644",
        "find . -print0 -version | xargs -0 chmod 644",
        "find . -print0 | sed 's|./|/etc/|' | xargs -0 chmod 644",
        "find . -print0 | unknown_tool | xargs -0 chmod 644",
        "find . -print0 2>&1 | xargs -0 chmod 644",
        "find . -print0 |& xargs -0 chmod 644",
        "find . -print0 2> >(printf '/etc/passwd\\0') | xargs -0 chmod 644",
        "find . -print0 | xargs -0 chmod 644 <untrusted.paths",
        "find . -print0 | tee <untrusted.paths | xargs -0 chmod 644",
        "find . -print0 | xargs -0 -a untrusted.paths chmod 644",
        r"find . -print0 -exec printf '/etc/passwd\0' \; | xargs -0 chmod 644",
        "find . -print0 | xargs -0 -I{} sh -c '{}'",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn function_and_alias_overrides_do_not_inherit_builtin_tool_guarantees() {
    for command in [
        "find() { printf '/etc/passwd\\0'; }; find . -print0 | xargs -0 chmod 644",
        "alias find=echo; find . -print0 | xargs -0 chmod 644",
        "tee() { printf '/etc/passwd\\0'; }; find . -print0 | tee | xargs -0 chmod 644",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn exact_literal_input_and_known_risks_keep_existing_behavior() {
    expect("printf './file\\0' | xargs -0 chmod 644", Decision::Allow);
    expect(
        "printf '/opt/shared/file\\0' | xargs -0 chmod 644",
        Decision::NeedApproval,
    );
    expect(
        "find . -print0 | xargs -0 chmod 644 /opt/shared/file",
        Decision::NeedApproval,
    );
}

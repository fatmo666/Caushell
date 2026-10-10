//! Static guard/Graph checks only: sample commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, ImplicitInputSource, PathResolution,
    ResolvedPathRole, RuntimeArgumentDomain, RuntimeMetadata, SessionId, SessionSummary, ShellKind,
    ShellRuntimeCapabilities, ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("runtime-path-templates"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn expect(command: &str, decision: Decision) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, decision, "{command}: {result:#?}");
}
fn facts(
    command: &str,
) -> (
    Vec<GraphNode>,
    Vec<(ImplicitInputSource, RuntimeArgumentDomain)>,
) {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&base, &summary), &mut ctx);
    let domains = ctx
        .execution_unit_resolve_records()
        .iter()
        .flat_map(|record| &record.parsed_scope.commands[record.command_ref.command_index].tokens)
        .filter_map(|token| {
            Some((
                token.implicit_input_source?,
                token.runtime_argument_domain.clone()?,
            ))
        })
        .collect();
    let nodes = StagedSession::new(&base, ctx.request(), &summary, ctx.pending_mutations())
        .graph()
        .nodes()
        .cloned()
        .collect();
    (nodes, domains)
}
fn has_bound(nodes: &[GraphNode], role: ResolvedPathRole, expected: &str) -> bool {
    nodes.iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact {
        role: found_role, resolution: PathResolution::BoundedPathSet {roots, may_escape: false}, ..
    } if *found_role == role && roots == &[expected])
    })
}

#[test]
fn find_affixes_retain_local_write_move_and_delete_effects() {
    for command in [
        r#"find . -name '*.java' -exec cp {} {}.bk \;"#,
        r#"find folder -type f -exec gzip -9 {} \; -exec mv {}.gz {} \;"#,
        r#"find . -type f -exec sed '1s/foo/bar/' -i.bak {} \; -exec rm {}.bak \;"#,
        r#"find src/ -type d -exec mkdir -p dest/{} \; -o -type f -exec touch dest/{} \;"#,
        r#"find original -type f -exec ln -s {} new/{} \;"#,
        r#"find . -type d -exec touch '{}/index.html' \;"#,
        r#"find . -type f -exec mv '{}' '{}'.jpg \;"#,
    ] {
        expect(command, Decision::Allow);
    }
}

#[test]
fn parent_removal_respects_raw_relative_stopping_points() {
    for command in [
        r"find . -type d -empty -exec rmdir -vp --ignore-fail-on-non-empty {} +",
        r"find sub -type d -exec rmdir -p {} \;",
        "find . -type d -print0 | xargs -0 rmdir -p",
        "rmdir -p ./sub/leaf",
        "rmdir -p sub/leaf",
    ] {
        expect(command, Decision::Allow);
    }
    for command in [
        r"find /opt/shared -type d -exec rmdir -p {} \;",
        r"find /tmp/project -type d -exec rmdir -p {} \;",
        r"find -L . -type d -exec rmdir -p {} \;",
        r#"find "$UNKNOWN" -type d -execdir rmdir -p {} \;"#,
        "rmdir -p ../sub/leaf",
        "rmdir -p /tmp/project/sub/leaf",
        "rmdir -p \"$UNKNOWN\"",
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn null_delimited_xargs_reuses_the_same_template_semantics() {
    for command in [
        r#"find . -print0 | xargs -0 -I {} cp {} {}.bk"#,
        r#"find . -print0 | xargs -0 -I % touch %/index.html"#,
        r#"find sub -print0 | xargs -0 -I {} mv {} {}.bak"#,
    ] {
        expect(command, Decision::Allow);
    }
    let (nodes, domains) = facts("find . -print0 | xargs -0 -I {} cp {} {}.bk");
    assert!(has_bound(&nodes, ResolvedPathRole::Write, "/tmp/project"));
    assert!(domains.iter().any(
        |(source, domain)| matches!(domain, RuntimeArgumentDomain::PathTemplate {prefix, suffix, ..}
        if *source == ImplicitInputSource::StdinData && prefix.is_empty() && suffix == ".bk")
    ));
}

#[test]
fn graph_and_child_argv_keep_origin_without_inventing_a_filename() {
    let (nodes, domains) = facts(r#"find . -exec cp {} {}.bk \;"#);
    assert!(has_bound(&nodes, ResolvedPathRole::Write, "/tmp/project"));
    assert!(domains.contains(&(
        ImplicitInputSource::DispatchOutput,
        RuntimeArgumentDomain::PathTemplate {
            roots: vec![".".into()],
            may_escape: false,
            prefix: "".into(),
            suffix: ".bk".into(),
        }
    )));
    assert!(!nodes.iter().any(|node| matches!(
        &node.kind,
        NodeKind::PathFact {
            role: ResolvedPathRole::Write,
            resolution: PathResolution::Concrete { .. },
            ..
        }
    )));
}

#[test]
fn inclusive_roots_require_sibling_bounds_not_copied_search_roots() {
    expect(r#"find sub -exec cp {} {}.bak \;"#, Decision::Allow);
    assert!(has_bound(
        &facts(r#"find sub -exec cp {} {}.bak \;"#).0,
        ResolvedPathRole::Write,
        "/tmp/project"
    ));
    expect(
        r#"find /tmp/project -exec cp {} {}.bak \;"#,
        Decision::NeedApproval,
    );
    assert!(has_bound(
        &facts(r#"find /tmp/project -exec cp {} {}.bak \;"#).0,
        ResolvedPathRole::Write,
        "/tmp"
    ));
    expect(
        r#"find /tmp/project/ -exec cp {} {}.bak \;"#,
        Decision::Allow,
    );
    expect(
        r#"find /tmp/project -exec touch {}/index.html \;"#,
        Decision::Allow,
    );
    expect(
        "find /tmp/project/ -print0 | xargs -0 -I {} cp {} {}.bak",
        Decision::Allow,
    );
    assert!(has_bound(
        &facts(r#"find ~/ -exec cp {} {}.bak \;"#).0,
        ResolvedPathRole::Write,
        "/home/alice"
    ));
    assert!(has_bound(
        &facts("find ~/ -print0 | xargs -0 -I {} cp {} {}.bak").0,
        ResolvedPathRole::Write,
        "/home/alice"
    ));
}

#[test]
fn fixed_prefix_is_argv_concatenation_not_absolute_path_join() {
    expect(
        r#"find /opt/source -exec cp {} dest/{} \;"#,
        Decision::Allow,
    );
    assert!(has_bound(
        &facts(r#"find /opt/source -exec cp {} dest/{} \;"#).0,
        ResolvedPathRole::Write,
        "/tmp/project/dest/opt/source"
    ));
    expect(
        r#"find . -exec cp {} /opt/copies/{} \;"#,
        Decision::NeedApproval,
    );
    expect(
        r#"find . -exec cp {} ../copies/{} \;"#,
        Decision::NeedApproval,
    );
    expect(
        r#"find /../../tmp/project -exec cp {} dest/{} \;"#,
        Decision::NeedApproval,
    );
    expect(
        "find /../../tmp/project -print0 | xargs -0 -I {} cp {} dest/{}",
        Decision::NeedApproval,
    );
}

#[test]
fn unknown_followed_external_and_line_split_sources_still_require_approval() {
    for command in [
        r#"find "$dir" -exec cp {} {}.bak \;"#,
        r#"find -L . -exec cp {} {}.bak \;"#,
        r#"find /opt/shared -execdir cp {} {}.bak \;"#,
        r#"find /opt/shared -exec mv {} {}.bak \;"#,
        r#"find . -print | xargs -I {} cp {} {}.bak"#,
        r#"find . -print0 | sed 's|^|/opt/|' | xargs -0 -I {} cp {} {}.bak"#,
        r#"cd "$where"; find . -exec cp {} {}.bak \;"#,
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn traversal_repeated_inputs_and_option_like_templates_remain_unproven() {
    for command in [
        r#"find . -exec touch '{}./victim' \;"#,
        r#"find . -exec touch '{}/../../victim' \;"#,
        r#"find . -exec touch '{}{}' \;"#,
        r#"find . -exec touch '-{}' \;"#,
        r#"find . -exec touch '+{}' \;"#,
    ] {
        expect(command, Decision::NeedApproval);
    }
}

#[test]
fn literal_data_bytes_are_not_reexpanded_and_template_outputs_can_be_derived_again() {
    for command in [
        r#"find . -exec cp {} '{}.$HOME*' \;"#,
        r#"find . -exec gzip '{}.bk' \;"#,
        r#"find . -print0 | xargs -0 -I {} gzip {}.bk"#,
        r#"find . -exec env cp {} {}.bk \;"#,
    ] {
        expect(command, Decision::Allow);
    }
    assert!(has_bound(
        &facts(r#"find . -exec gzip '{}.bk' \;"#).0,
        ResolvedPathRole::Write,
        "/tmp/project"
    ));
    expect(r#"find . -exec sh -c '{}.sh' \;"#, Decision::NeedApproval);
}

#[test]
fn derived_graph_paths_survive_session_snapshot_reload() {
    let mut core = ShellQueryCore::new();
    core.check(request(r#"find . -exec cp {} {}.bk \;"#));
    let id = SessionId::new("runtime-path-templates");
    let snapshot = core.session_snapshot(&id, 1).unwrap();
    let restored = caushell_core::SessionState::from_snapshot(snapshot).unwrap();
    core.insert_session_state(id.clone(), restored);
    let nodes = core
        .session_graph(&id)
        .unwrap()
        .nodes()
        .cloned()
        .collect::<Vec<_>>();
    assert!(has_bound(&nodes, ResolvedPathRole::Write, "/tmp/project"));
}

//! Static check inputs only: no find, rm, or output action is executed.
use caushell_core::ShellQueryCore;
use caushell_graph::{NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractPathFactsPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::ProfileRegistry;
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::{
    CheckRequest, CommandSequenceNo, Decision, PathResolution, ResolvedPathRole, RuleId,
    RuntimeMetadata, SessionId, SessionSummary, ShellKind, ShellRuntimeCapabilities,
    ShellStateSnapshot,
};

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("find-completion"),
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

fn assert_allow(command: &str) {
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, Decision::Allow, "{command}: {result:?}");
    assert!(
        !result
            .decision_trace
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::SelectionError),
        "{command}: {result:?}"
    );
}

#[test]
fn interleaved_shell_redirection_keeps_child_delimiters_and_real_write_targets() {
    for command in [
        r"find . -name '*.sh' -exec grep -Hn text {} 2>/dev/null \;",
        r"find . -exec echo {} >/dev/null \; -print",
        r"find . -exec echo {} 2>&- \; -print",
    ] {
        assert_allow(command);
    }
    for command in [
        r"find . -exec echo {} >/opt/shared/log \; -print",
        r"find /opt/shared -exec rm {} 2>/dev/null \;",
        r"find . -exec rm /opt/shared/file 2>/dev/null \;",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            !result.decision_trace.derived_invocations.is_empty(),
            "{command}: {result:?}"
        );
        assert!(
            !result
                .decision_trace
                .decision_proposals
                .iter()
                .any(|p| p.rule_id == RuleId::SelectionError),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn normal_filters_no_longer_hit_selection_error_fallback() {
    for command in [
        "find . -size +100M -print",
        "find /testbed/dir1 -perm 1553",
        "find /opt/shared -mtime -60 -print",
        "find . -daystart -mmin -10 -amin +2 -cmin 5 -atime -3 -ctime +1 -print",
        "find . -user root -group staff -uid +1000 -gid 100 -inum 23 -links +1 -used 7 -print",
        "find . -regextype posix-extended -regex '.*[.]rs' -fstype ext4 -print",
        "find . -newermt '2024-01-01 00:00' -newerct '1 day ago' -print",
        "find . -newer /opt/reference -samefile /etc/reference -print",
        "find . -xtype l -lname '../*' -iwholename '*cache*' -print",
        r"find . \( -size +100M -o -mtime -7 \) -a ! -perm /u=x -print",
        r"find . \( -name '*.rs' -o -name '*.md' \) -exec echo {} +",
        "find -O2 -D tree,stat . -ignore_readdir_race -noleaf -print",
        "find . -printf '%f\\n'",
    ] {
        assert_allow(command);
    }
}

#[test]
fn predicates_do_not_hide_external_delete_or_derived_child_delete() {
    for command in [
        "find /opt/shared -mtime -7 -size +100M -perm /u=x -delete",
        r"find /opt/shared -mtime -7 -exec rm -- {} \;",
        r"find . -mtime -7 -exec rm -- /opt/shared/file \;",
        r"find . -exec printf %s -mtime -delete \; -size +1M -exec rm /opt/shared/file \;",
        r"find /opt/shared \( -size +100M -o -mtime -7 \) -exec rm {} +",
        r"find . -printf '%p\n' -exec rm /opt/shared/file \;",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:?}"
        );
        assert!(
            !result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::SelectionError),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn filters_do_not_widen_local_child_domains_with_reference_files_or_expression_operators() {
    for command in [
        r"find . -mtime -7 -size +100M -perm /u=x -exec rm {} \;",
        r"find . -newer /opt/reference -exec rm {} +",
        r"find . \( -name '*.tmp' -o -size +100M \) -exec rm {} +",
        r"find . -exec printf %s -fprint /opt/noise -mtime -delete \; -exec rm {} \;",
    ] {
        assert_allow(command);
    }
}

#[test]
fn output_actions_keep_external_write_semantics_even_without_matches() {
    for flag in ["-fprint", "-fprint0", "-fls"] {
        for command in [
            format!("find . {flag} /opt/output"),
            format!("find . -false {flag} /opt/output"),
            format!("find . -name impossible {flag} /opt/output"),
            format!("find . {flag} /opt/output {flag} ./local-output"),
        ] {
            let result = ShellQueryCore::new().check(request(&command));
            assert_eq!(
                result.decision,
                Decision::NeedApproval,
                "{command}: {result:?}"
            );
            assert!(
                result
                    .decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
                "{command}: {result:?}"
            );
            assert!(
                !result
                    .decision_trace
                    .findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::SelectionError),
                "{command}: {result:?}"
            );
        }
    }
}

#[test]
fn workspace_output_and_dev_null_use_existing_write_policy() {
    for flag in ["-fprint", "-fprint0", "-fls"] {
        assert_allow(&format!("find . -mtime -7 {flag} ./result"));
        assert_allow(&format!("find . {flag} /dev/null"));
    }
}

#[test]
fn default_cwd_is_a_real_delete_target_and_unknown_cwd_is_not_assumed_local() {
    for command in ["find -mtime -7 -delete", "find -size 0 -delete"] {
        assert_allow(command);
    }
    for command in [
        "cd /opt/shared; find -mtime -7 -delete",
        "cd /opt/shared; find -size 0 -delete",
        "cd /opt/shared; find -delete",
        "cd /opt/shared; find -delete -fprint ./result",
        "cd \"$UNKNOWN\"; find -mtime -7 -delete",
        "find \"$UNKNOWN\" -mtime -7 -delete",
        "find . /opt/shared -mtime -7 -delete",
        "find /opt/shared . -mtime -7 -delete",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn implicit_root_and_output_files_use_effective_cwd_without_widening_explicit_roots() {
    let command = "cd /opt/shared; find -mtime -7 -delete";
    let result = ShellQueryCore::new().check(request(command));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:?}");
    // NeedApproval requests are intentionally not committed to SessionGraph.
    // Inspect staged facts without bypassing the product's default policy.
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(
        ProfileRegistry::built_in().unwrap(),
    ));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    let graph = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut ctx = RunnerContext::new(request(command));
    runner.run(SessionView::new(&graph, &summary), &mut ctx);
    let staged = StagedSession::new(&graph, ctx.request(), &summary, ctx.pending_mutations());
    let paths: Vec<_> = staged
        .graph()
        .nodes()
        .filter_map(|node| match &node.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => resolution.concrete_path().map(|path| (*role, path)),
            _ => None,
        })
        .collect();
    assert!(
        paths.contains(&(ResolvedPathRole::Read, "/opt/shared")),
        "{paths:?}"
    );
    assert!(
        staged.graph().nodes().any(|node| matches!(&node.kind,
            NodeKind::PathFact { role: ResolvedPathRole::Target, resolution, .. }
                if matches!(resolution, PathResolution::BoundedPathSet { roots, may_escape: false }
                    if roots == &vec!["/opt/shared".to_string()]))),
        "default deletion must retain the traversal domain"
    );
    assert_allow("cd /opt/shared; find /tmp/project -mtime -7 -delete");
}

#[test]
fn file_output_to_block_devices_preserves_existing_hard_deny_floor() {
    for flag in ["-fprint", "-fprint0", "-fls"] {
        let command = format!("find . -false {flag} /dev/sda");
        let result = ShellQueryCore::new().check(request(&command));
        assert_eq!(result.decision, Decision::Deny, "{command}: {result:?}");
    }
}

#[test]
fn unknown_output_and_unquoted_expansion_boundaries_still_require_approval() {
    for command in [
        "find . -fprint \"$OUTPUT\"",
        "find . -fprint0 \"$OUTPUT\"",
        "find . -fls \"$OUTPUT\"",
        r"find $ROOT -mtime -7 -exec rm {} \;",
        r"find . -mtime $AGE -exec rm {} \;",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
    }
    // The bounded pattern cannot become a control word. The child deletion
    // keeps its workspace path domain; there is no blanket workspace-cleanup
    // approval policy. An outside root must still reach the mutation guard.
    assert_allow(r"find . -name *.py -exec rm {} \;");
    let result =
        ShellQueryCore::new().check(request(r"find /opt/shared -name *.py -exec rm {} \;"));
    assert_eq!(result.decision, Decision::NeedApproval, "{result:?}");
    assert!(
        result
            .decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.rule_id == RuleId::OutsideWorkspaceMutation),
        "{result:?}"
    );
}

#[test]
fn unsupported_complex_forms_and_missing_operands_are_not_silently_allowed() {
    for command in [
        "find . -fprintf /opt/output '%p'",
        "find -files0-from ./roots -delete",
        "find -f /opt/shared -delete",
        "find . -f /opt/shared -f . -delete",
        r"find . -f /opt/shared -exec rm {} \;",
        "find . -mtime",
        "find . -size",
        "find . -perm",
        "find . -printf",
        "find . -fprint",
        "find . -fprint result -fprint",
        "find . -unsupported -print",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
    }
}

#[test]
fn additional_filters_clusters_and_confirmation_actions_keep_complete_semantics() {
    for command in [
        "find . -mnewer /opt/reference -print",
        "find . ! -local -prune -o -print",
        "find -ds . -mindepth 1 -type f -print0",
        "find -EPdsx . -print",
        r"find . -ok rm {} \;",
        r"find . -okdir rm {} \;",
        r"find /opt/shared -ok ls -l {} \;",
        r"find . -okdir diff {} /opt/reference \;",
        "find /opt/shared -mmin -$((currtime + 1440)) -mmin +$((${currtime} + 1))",
    ] {
        assert_allow(command);
    }
    for command in [
        r"find /opt/shared -ok rm {} \;",
        r"find . -ok rm /opt/shared/file \;",
        r"find /opt/shared -okdir rm {} \;",
        r"find -LPds . -exec rm {} \;",
        r"find -ds /opt/shared -delete",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:?}"
        );
        assert!(
            !result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::SelectionError),
            "{command}: {result:?}"
        );
    }
}

#[test]
fn two_operand_and_legacy_output_actions_bind_only_the_actual_output_file() {
    for command in [
        "find . -fprintf ./out '-delete'",
        "find . -fprintf ./out '-exec' -fprintf ./other '-okdir'",
        "find /opt/shared -fprintf ./out '%p\\n'",
        "find . -cpio ./archive -print",
        "find . -ncpio ./archive",
    ] {
        assert_allow(command);
    }
    for command in [
        "find . -false -fprintf /opt/out '%p'",
        "find . -fprintf ./out '%p' -fprintf /opt/out '%p'",
        "find . -cpio /opt/archive",
        "find . -ncpio /opt/archive",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
        );
        assert!(
            !result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::SelectionError)
        );
    }
    for command in [
        "find . -fprintf",
        "find . -fprintf ./out",
        "find . -fprintf ./out '%p' -fprintf ./other",
        "find . -ok echo {} +",
    ] {
        assert_eq!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::NeedApproval,
            "{command}"
        );
    }
    assert_eq!(
        ShellQueryCore::new()
            .check(request("find . -fprintf /dev/sda '%p'"))
            .decision,
        Decision::Deny
    );
}

#[test]
fn xargs_replace_preserves_find_operand_position_and_single_field_width() {
    for options in [
        "-n 1 -I '{}'",
        "-I '{}' -n 1",
        "-I{}",
        "--replace",
        "-i",
        "-0i",
    ] {
        let command = format!("xargs {options} find . -type f -inum '{{}}' -print");
        assert_allow(&command);
        let command = format!("printf '123\\n' | xargs {options} find . -inum '{{}}' -print");
        assert_allow(&command);
    }
    for command in [
        "printf '/opt/out\\n' | xargs -n1 -I{} find . -fprintf '{}' '%p'",
        "xargs -n1 -I{} find . -fprintf '{}' '%p'",
        "xargs -n1 -I{} find '{}' -delete",
        "find . -type f -print0 | xargs -0i sh -c \"cat /dev/null > \\\"{}\\\"\"",
        "find . -print0 | xargs -0I{} sh -c 'echo {}'",
        "find . -print0 | xargs -0I{} cp {} ~/outside",
        "find . -print0 | xargs -0I{} mv {} ~/outside",
        "cat paths | xargs -I{} ln -s {} ~/newlinks",
        "find . -print0 | xargs -0I{} touch ~/outside-{}",
    ] {
        assert_eq!(
            ShellQueryCore::new().check(request(command)).decision,
            Decision::NeedApproval,
            "{command}"
        );
    }
    assert_allow(
        r#"find FOLDER1 -type f -print0 | xargs -0 -I % find FOLDER2 -type f -exec diff -qs --from-file="%" '{}' \+"#,
    );
}

#[test]
fn output_content_channels_keep_consumer_effects_and_are_not_file_mutations() {
    for command in [
        "find . -name '*.php' -print0 -fprint >(pv --line-mode)",
        "find . -fprintf >(cat) '%p'",
        "echo foo | tee >(sha1sum) >(md5sum)",
        "find . -fprint '>(cat)'",
    ] {
        assert_allow(command);
    }
    for command in [
        // The channel's consumer can contribute to inherited stdout too:
        // -print0 plus newline file output is not a pure NUL path stream.
        "find . -name '*.php' -print0 -fprint >(pv --line-mode) | xargs -0 chmod 755",
        "find . -fprint >(cat > /opt/output)",
        "find . -fprintf >(rm /opt/file) '%p'",
        "find . -fprint >(cat) -fprint /opt/output",
        "find . -fprint \"$UNKNOWN\"",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation)
        );
    }
    // Namespace removal cannot acquire a content-channel exemption.
    assert_eq!(
        ShellQueryCore::new().check(request("rm >(cat)")).decision,
        Decision::NeedApproval
    );
}

#[test]
fn graph_distinguishes_search_roots_reference_reads_and_output_writes() {
    let command = r"find . -mtime -7 \( -name '*.rs' -o -size +100M \) -newer /opt/reference -printf '/etc/noise\n' -fprint ./result";
    let mut core = ShellQueryCore::new();
    let result = core.check(request(command));
    assert_eq!(result.decision, Decision::Allow, "{result:?}");
    let paths: Vec<_> = core
        .session_graph(&SessionId::new("find-completion"))
        .unwrap()
        .nodes()
        .filter_map(|node| match &node.kind {
            NodeKind::PathFact {
                role, resolution, ..
            } => resolution.concrete_path().map(|path| (*role, path)),
            _ => None,
        })
        .collect();
    assert!(
        paths.contains(&(ResolvedPathRole::Read, "/tmp/project")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&(ResolvedPathRole::Read, "/opt/reference")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&(ResolvedPathRole::Write, "/tmp/project/result")),
        "{paths:?}"
    );
    assert!(
        !paths.iter().any(|(_, p)| *p == "/etc/noise"
            || *p == "/tmp/project/-7"
            || *p == "/tmp/project/+100M"
            || *p == "/tmp/project/("
            || *p == "/tmp/project/)"),
        "{paths:?}"
    );
}

#[test]
fn child_literals_do_not_create_outer_output_or_delete_effects() {
    let command = r"find /opt/shared -mtime -7 -exec printf %s -fprint /opt/noise -delete -printf /etc/noise \;";
    let mut core = ShellQueryCore::new();
    let result = core.check(request(command));
    assert_eq!(result.decision, Decision::Allow, "{result:?}");
    assert_eq!(result.decision_trace.derived_invocations.len(), 1);
    let nodes: Vec<_> = core
        .session_graph(&SessionId::new("find-completion"))
        .unwrap()
        .nodes()
        .collect();
    assert!(!nodes.iter().any(|n| matches!(
        &n.kind,
        NodeKind::PathFact {
            role: ResolvedPathRole::Write | ResolvedPathRole::Target,
            ..
        }
    )));
}

#[test]
fn formatted_output_still_preserves_independent_outer_writes_and_children() {
    for command in [
        r"find . -printf '%p\n' -exec printf %s {} \; -fprint /opt/output",
        r"find . -exec printf %s {} \; -printf '%p\n' -fls /opt/output",
    ] {
        let result = ShellQueryCore::new().check(request(command));
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {result:?}"
        );
        assert_eq!(
            result.decision_trace.derived_invocations.len(),
            1,
            "{result:?}"
        );
        assert!(
            result
                .decision_trace
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::OutsideWorkspaceMutation),
            "{command}: {result:?}"
        );
    }
}

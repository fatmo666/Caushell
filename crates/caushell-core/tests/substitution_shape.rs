//! Static guard/Graph regression. Sample shell commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

fn check_filtered_name(command: &str, omitted_tool: Option<&str>) -> CheckResponse {
    let inventory = [
        ("tr", "gnu_tr_9_1_ascii_locales"),
        ("fold", "gnu_coreutils_9_1"),
        ("head", "gnu_coreutils_9_1"),
        ("mkdir", "gnu_coreutils_9_1"),
        ("xargs", "gnu_findutils_4_9_0"),
    ]
    .into_iter()
    .filter(|(tool, _)| Some(*tool) != omitted_tool)
    .map(|(tool, identity)| (tool.into(), identity.into()))
    .collect();
    let mut req = request(command);
    req.runtime.shell_runtime_capabilities = ShellRuntimeCapabilities::request_only();
    ShellQueryCore::new()
        .try_judge_static_shell_with_native_variants(req, &inventory)
        .unwrap()
}

#[test]
fn filtered_filename_consumers_keep_empty_and_nonempty_cases() {
    let output = "printf fixture | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1";
    let bash = format!("mkdir $({output})");
    let xargs = format!("{output} | xargs mkdir");
    for (command, expected_forms) in [
        (bash.as_str(), &["create_directories"][..]),
        (xargs.as_str(), &["create_directories", "missing_operands"]),
        ("mkdir $(printf '')", &["missing_operands"]),
        ("printf '' | xargs mkdir", &["missing_operands"]),
    ] {
        let response = check_filtered_name(command, None);
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {:?}",
            response.reasons
        );
        let mut forms: Vec<_> = response
            .decision_trace
            .execution_semantics
            .iter()
            .filter(|entry| entry.normalized_command_name == "mkdir")
            .map(|entry| entry.form_id.as_str())
            .collect();
        forms.sort_unstable();
        assert_eq!(forms, expected_forms, "{command}");
    }
}

#[test]
fn filtered_filename_proof_requires_ownership_and_preserves_path_guards() {
    let output = "printf fixture | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1";
    let bash = format!("mkdir $({output})");
    let xargs = format!("{output} | xargs mkdir");
    for tool in ["tr", "fold", "head", "mkdir"] {
        for command in [&bash, &xargs] {
            assert_eq!(
                check_filtered_name(command, Some(tool)).decision,
                Decision::NeedApproval
            );
        }
    }
    assert_eq!(
        check_filtered_name(&xargs, Some("xargs")).decision,
        Decision::NeedApproval
    );
    for command in [
        format!("mkdir $({})", output.replace("a-zA-Z0-9", "A-z")),
        format!(
            "mkdir $({})",
            output.replace("fold -w 32 |", "fold -w 32 |&")
        ),
        format!("mkdir $({output}) > /outside/fixture"),
        format!("IFS=A; mkdir $({output})"),
        "printf '%s\\n' /outside/fixture | xargs mkdir".into(),
    ] {
        let response = check_filtered_name(&command, None);
        assert_eq!(
            response.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            response.reasons
        );
    }
}

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("stdout-shape-test"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "stdout-shape-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

#[test]
fn quoted_absolute_outputs_do_not_manufacture_find_controls() {
    for command in [
        "find \"$(pwd)\" -type f",
        "find \"`pwd`\" -type f",
        "find \"$(pwd -P)\" -mtime 0 -print",
        "find \"$(pwd -L)\" -type d -print",
        "find \"$(/bin/pwd -P)\" -type f",
        "find \"$(pwd)/child\" -type f",
        r#"find "$("pwd")" -type f"#,
        r#"find "$('pwd')" -type f"#,
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .any(|s| s.normalized_command_name == "pwd"),
            "producer must stay in Graph: {response:#?}"
        );
    }
}

#[test]
fn no_proof_for_unquoted_mixed_or_incomplete_output() {
    for command in [
        "find $(pwd) -type f",
        "find `pwd` -type f",
        "find \"$(pwd; printf '%s' -delete)\" -type f",
        "find \"$(if true; then pwd; fi)\" -type f",
        "find \"$(pwd | cat)\" -type f",
        "find \"$(pwd 2>&1)\" -type f",
        "find \"$(pwd --help)\" -type f",
        "find \"$(pwd --version)\" -type f",
        "find \"$(pwd --unknown)\" -type f",
        "find \"$(pwd unexpected)\" -type f",
        "find \"$(pwd $options)\" -type f",
        "find \"$(pwd)$(other)\" -type f",
        "find \"$(pwd)\"$suffix -type f",
        "find \"$(pwd)-delete\" -type f",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn stdout_shape_does_not_authorize_unknown_mutation_paths() {
    for command in [
        "find \"$(pwd)\" -delete",
        "rm -rf \"$(pwd -P)\"",
        "chmod 777 \"$(pwd)\"",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn known_shadowing_does_not_borrow_the_builtin_contract() {
    for command in [
        "pwd() { printf '%s' -delete; }; find \"$(pwd)\" -type f",
        "pwd() { printf '%s' -delete; }; env find \"$(pwd)\" -type f",
        r#"pwd() { printf '%s' -delete; }; find "$(\pwd)" -type f"#,
        r#"pwd() { printf '%s' -delete; }; find "$("pwd")" -type f"#,
        r#"pwd() { printf '%s' -delete; }; find "$('pwd')" -type f"#,
        r#"pwd() { printf '%s' -delete; }; target=pwd; find "$("$target")" -type f"#,
        r#"pwd() { printf '%s' -delete; }; env find "$("pwd")" -type f"#,
        "alias pwd='printf %s -delete'; find \"$(pwd)\" -type f",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_ne!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
    let mut input = request("find \"$(pwd)\" -type f");
    input
        .shell_state_before
        .aliases
        .push(ShellAliasSnapshot::new("pwd", "printf %s -delete"));
    assert_ne!(ShellQueryCore::new().check(input).decision, Decision::Allow);
}

#[test]
fn directory_changes_do_not_turn_a_shape_into_a_cwd_value() {
    let response = ShellQueryCore::new().check(request("cd /opt; find \"$(pwd -P)\" -delete"));
    assert_ne!(response.decision, Decision::Allow, "{response:#?}");
}

#[test]
fn nested_shell_and_dispatch_use_the_same_proof_without_stale_gaps() {
    for command in [
        "bash -c 'find \"$(pwd)\" -type f'",
        "env find \"$(pwd -P)\" -type f",
        "env env find \"$(pwd)\" -type f",
        "sh -c 'find \"$(pwd)\" -type f'",
    ] {
        let response = ShellQueryCore::new().check(request(command));
        assert_eq!(
            response.decision,
            Decision::Allow,
            "{command}: {response:#?}"
        );
    }
}

#[test]
fn snapshots_and_expansion_limits_keep_conservative_boundaries() {
    let mut input = request("find \"$(pwd)\" -type f");
    input
        .shell_state_before
        .functions
        .push(ShellFunctionSnapshot::new("pwd", "printf '%s' -delete"));
    assert_ne!(ShellQueryCore::new().check(input).decision, Decision::Allow);
    let mut policy = PolicyConfig::default();
    policy.semantic_expansion.max_nested_parse_depth = 0;
    let response = ShellQueryCore::with_policy(policy).check(request("find \"$(pwd)\" -type f"));
    assert_ne!(response.decision, Decision::Allow, "{response:#?}");
}

struct SubstitutionWorkspace(std::path::PathBuf);

impl SubstitutionWorkspace {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let fixture_id = NEXT.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "caushell-output-{}-{nonce}-{fixture_id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("logs")).unwrap();
        std::fs::write(path.join("server.log"), "fixture\n").unwrap();
        Self(path)
    }

    fn check(&self, command: &str, ifs: Option<&str>) -> CheckResponse {
        let cwd = self.0.to_str().unwrap();
        let mut input = request(command);
        input.shell_state_before = ShellStateSnapshot::new(cwd);
        input.workspace_root = Some(cwd.into());
        if let Some(value) = ifs {
            input.shell_state_before.observability.variables = ShellStateKnowledge::Complete;
            input
                .shell_state_before
                .variables
                .push(ShellVariableSnapshot::new(
                    "IFS",
                    ShellValueSnapshot::ExactScalar {
                        value: value.into(),
                    },
                    false,
                ));
        }
        ShellQueryCore::new().check(input)
    }
}

impl Drop for SubstitutionWorkspace {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn arithmetic_output_affixes_bind_one_field_and_keep_the_destination_bound() {
    let workspace = SubstitutionWorkspace::new();
    for (command, ifs, producer, root) in [
        (r#"touch "filename_$(date +%s).txt""#, None, "date", ""),
        (
            r#"touch "filename_`/bin/date +%Y%m%d%H%M%S`.txt""#,
            None,
            "date",
            "",
        ),
        (r#"touch filename_"$(date +%s)".txt"#, None, "date", ""),
        ("touch filename_`date +%s`.txt", Some(""), "date", ""),
        (
            r#"mv server.log "logs/$(date -d "today" +"%Y%m%d%H%M").log""#,
            None,
            "date",
            "logs",
        ),
        (
            r#"mv server.log logs/$(date -d "today" +"%Y%m%d%H%M").log"#,
            Some(","),
            "date",
            "logs",
        ),
        (r#"touch -- "item_$(seq 2).txt""#, None, "seq", ""),
    ] {
        let result = workspace.check(command, ifs);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(
            result.decision_trace.execution_semantics.iter().any(|s| {
                s.normalized_command_name == producer && !s.operation_semantics_unresolved
            }),
            "producer remains a checked execution: {command}"
        );
        let expected_root = if root.is_empty() {
            workspace.0.clone()
        } else {
            workspace.0.join(root)
        };
        assert!(
            result.decision_trace.path_targets.iter().any(|fact| {
                matches!(
                    &fact.resolution,
                    SemanticResolution::Resolved {
                        value: PathResolution::BoundedPathSet { roots, may_escape: false }
                    } if roots == &[expected_root.to_string_lossy().into_owned()]
                )
            }),
            "expected a resolved path family for {command}: {:?}",
            result.decision_trace.path_targets
        );
    }
    assert_eq!(
        std::fs::read_to_string(workspace.0.join("server.log")).unwrap(),
        "fixture\n"
    );
    assert_eq!(
        std::fs::read_dir(workspace.0.join("logs")).unwrap().count(),
        0
    );
}

#[test]
fn output_bounds_require_verified_field_width_and_namespace() {
    let workspace = SubstitutionWorkspace::new();
    for (command, ifs) in [
        ("touch filename_$(date +%s).txt", None),
        ("touch filename_$(date +%s).txt", Some("0")),
        ("touch filename_$(seq 2).txt", Some(" \t\n")),
        (r#"touch "filename_$(seq -s / 2).txt""#, None),
        (r#"touch "filename_$(date +%s | cat).txt""#, None),
        (
            r#"date() { printf '%s' arbitrary; }; touch "filename_$(date +%s).txt""#,
            None,
        ),
        (r#"touch "filename_$(date +%s 2>&1).txt""#, None),
        (r#"touch "filename_$(date +%s)/child""#, None),
        (r#"touch "$(date +%s)..""#, None),
        (r#"touch "../filename_$(date +%s).txt""#, None),
        (r#"touch "/outside/filename_$(date +%s).txt""#, None),
    ] {
        let result = workspace.check(command, ifs);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            workspace.0.join("server.log"),
            workspace.0.join("logs/item_1"),
        )
        .unwrap();
        let result = workspace.check(r#"touch "logs/item_$(date +%s)""#, None);
        assert_ne!(result.decision, Decision::Allow, "{:?}", result.reasons);
    }
}

#[test]
fn attached_temporal_values_preserve_binding_and_independent_effect_checks() {
    let workspace = SubstitutionWorkspace::new();
    for command in [
        r#"date --date="@$old_time""#,
        r#"touch --date="$(date --date="@$old_time")" report.txt"#,
        r#"touch -d@"$old_time" report.txt"#,
        r#"touch -d"$(date --date="@$old_time")" report.txt"#,
        r#"touch -d "2000-01-01""#,
    ] {
        let result = workspace.check(command, None);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
    for command in [
        r#"touch -d"$(date --date="@$old_time")" report.txt other.txt"#,
        r#"touch -d"$old_time" -- report.txt"#,
        r#"touch -d"$(date --date="@$old_time")" /outside/report.txt"#,
        r#"touch -r "$reference" -d "$old_time""#,
        r#"touch --date="$@" report.txt"#,
        r#"touch --date="@$old_time" /outside/report.txt"#,
        r#"date --set="@$old_time""#,
    ] {
        let result = workspace.check(command, None);
        assert_ne!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
    }
}

#[test]
fn bare_and_attached_temporal_layouts_keep_the_union_of_writes() {
    let workspace = SubstitutionWorkspace::new();
    let attached = workspace.check(r#"touch -d"$TIME" report.txt"#, None);
    assert_eq!(attached.decision, Decision::Allow, "{:?}", attached.reasons);
    let expected = workspace
        .0
        .join("report.txt")
        .to_string_lossy()
        .into_owned();
    assert!(attached.decision_trace.path_targets.iter().any(|fact| {
        fact.operation == PathTargetOperation::Write
            && fact.lexical
                == PathResolution::Concrete {
                    path: expected.clone(),
                }
    }));

    let bare = workspace.check(r#"touch -d "2000-01-01""#, None);
    assert_eq!(bare.decision, Decision::Allow, "{:?}", bare.reasons);
    assert!(
        !bare
            .decision_trace
            .path_targets
            .iter()
            .any(|fact| { fact.operation == PathTargetOperation::Write })
    );
    assert!(!workspace.0.join("report.txt").exists());
}

#[test]
fn quoted_calendar_archive_is_bounded_by_the_execution_directory() {
    let workspace = SubstitutionWorkspace::new();
    for (command, directory) in [
        (r#"zip "archive_$(date +%Y%m%d_%H%M%S).zip" server.log"#, ""),
        (r#"zip -r "archive-$(date +%Y%m%d).zip" logs"#, ""),
        (r#"cd logs && zip "archive_$(date +%Y%m%d).zip" ../server.log"#, "logs"),
    ] {
        let result = workspace.check(command, None);
        let expected = if directory.is_empty() {
            workspace.0.clone()
        } else {
            workspace.0.join(directory)
        };
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.path_targets.iter().any(|target| {
            target.slot_name == "archive_path"
                && target.operation == PathTargetOperation::Write
                && matches!(&target.resolution, SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if roots == &[expected.to_string_lossy().into_owned()])
        }), "{command}: {:?}", result.decision_trace.path_targets);
    }
}

#[test]
fn calendar_paths_keep_the_leaf_and_option_boundaries() {
    let workspace = SubstitutionWorkspace::new();
    let result = workspace.check(
        r#"cp server.log "server.log.$(date +%Y%m%d_%H%M%S).bak" && mv server.log logs/"#,
        None,
    );
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    assert!(result.decision_trace.path_targets.iter().any(|target| {
        matches!(&target.lexical, PathResolution::FileNamePrefix { prefix, .. }
            if prefix == "server.log.")
    }));
    assert_eq!(
        workspace.check(r#"mkdir -p "$(date +%Y-%m-%d)""#, None).decision,
        Decision::Allow,
    );
    assert_ne!(
        workspace.check(r#"mkdir -p "$(date +%Y/%m/%d)""#, None).decision,
        Decision::Allow,
    );
}

#[test]
fn paired_basenames_do_not_erase_unrelated_option_or_link_paths() {
    let workspace = SubstitutionWorkspace::new();
    let paired = r#"for f in *.txt; do expand -t 4 "$f" > "$f.tmp" && mv "$f.tmp" "$f"; done"#;
    let result = workspace.check(paired, None);
    assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
    let independent = r#"for f in *.txt; do for g in *.txt; do mv "$f.tmp" "$g"; done; done"#;
    assert_ne!(workspace.check(independent, None).decision, Decision::Allow);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/", workspace.0.join("linked.txt.tmp")).unwrap();
        assert_ne!(workspace.check(paired, None).decision, Decision::Allow);
    }
}

#[test]
fn calendar_archive_still_requires_a_proven_capture_and_namespace() {
    let workspace = SubstitutionWorkspace::new();
    for command in [
        r#"zip "archive_$(date +%Y/%m/%d).zip" server.log"#,
        r#"zip "archive_$(date +%Y%m%d 2>&1).zip" server.log"#,
        r#"date() { printf '%s' example; }; zip "archive_$(date +%Y%m%d).zip" server.log"#,
        r#"zip archive_$(date +%Y%m%d_%H%M%S).zip server.log"#,
        r#"zip "../archive_$(date +%Y%m%d).zip" server.log"#,
    ] {
        let result = workspace.check(command, None);
        assert_ne!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
    }

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            workspace.0.join("server.log"),
            workspace.0.join("archive_20261127_000000.zip"),
        ).unwrap();
        let result = workspace.check(r#"zip "archive_$(date +%Y%m%d_%H%M%S).zip" server.log"#, None);
        assert_ne!(result.decision, Decision::Allow, "{:?}", result.reasons);
    }
}

#[test]
fn split_calendar_output_keeps_all_touch_targets_in_the_workspace() {
    let workspace = SubstitutionWorkspace::new();
    for (command, ifs) in [
        (r#"touch report_`/bin/date +%Y%m%d%H%M`.dat"#, None),
        (r#"touch report_$(date +%Y%m%d%H%M).dat"#, Some("0-1")),
    ] {
        let result = workspace.check(command, ifs);
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.path_targets.iter().any(|target| {
            target.operation == PathTargetOperation::Write && matches!(
                &target.resolution,
                SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if roots == &[workspace.0.to_string_lossy().into_owned()]
            )
        }));
    }
}

#[test]
fn split_calendar_filenames_require_literal_anchors_and_a_stable_namespace() {
    let workspace = SubstitutionWorkspace::new();
    for command in [
        r#"touch ../report_$(date +%Y%m%d).dat"#,
        r#"touch $(date +%Y%m%d).dat"#,
        r#"touch report_$(date +%Y/%m/%d).dat"#,
        r#"touch report_$(date +%Y%m%d 2>&1).dat"#,
        r#"touch report_$(date +%Y%m%d).dat /outside/other"#,
    ] {
        let result = workspace.check(command, None);
        assert_ne!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/outside/file", workspace.0.join("report_1.dat")).unwrap();
        let result = workspace.check("touch report_$(date +%Y%m%d).dat", None);
        assert_ne!(result.decision, Decision::Allow);
    }
}

#[test]
fn split_touch_timestamp_and_pid_keep_a_bounded_write() {
    let workspace = SubstitutionWorkspace::new();
    std::fs::create_dir(workspace.0.join("bucket")).unwrap();
    for ifs in [None, Some("09")] {
        let result = workspace.check("touch -t $(date +%m%d%H%M) ./bucket/$$", ifs);
        assert_eq!(result.decision, Decision::Allow, "{:?}", result.reasons);
        assert!(result.decision_trace.path_targets.iter().any(|target| {
            target.operation == PathTargetOperation::Write
                && matches!(&target.resolution, SemanticResolution::Resolved {
                    value: PathResolution::BoundedPathSet { roots, may_escape: false },
                } if roots.len() == 2
                    && roots.contains(&workspace.0.to_string_lossy().into_owned())
                    && roots.contains(&workspace.0.join("bucket").to_string_lossy().into_owned()))
        }));
    }
    for source in [
        "touch -t $(date +%m%d%H%M) /outside/$$",
        "touch -t $(date +%m/%d) ./bucket/$$",
        "touch -t $(date +%m%d%H%M 2>&1) ./bucket/$$",
        "touch -t $(date +%m%d%H%M) ./bucket/$target",
    ] {
        assert_ne!(workspace.check(source, None).decision, Decision::Allow, "{source}");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/outside/file", workspace.0.join("bucket/123")).unwrap();
        let result = workspace.check("touch -t $(date +%m%d%H%M) ./bucket/$$", None);
        assert_ne!(result.decision, Decision::Allow);
    }
}

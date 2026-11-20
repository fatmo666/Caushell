//! Static guard/Graph regression. Sample shell commands are never executed.
use caushell_core::ShellQueryCore;
use caushell_types::*;

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

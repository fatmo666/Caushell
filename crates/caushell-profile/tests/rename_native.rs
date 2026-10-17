//! Native argv and target projection only; rename/Perl commands never execute.
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolved(command: &str) -> ResolvedInvocationArtifact {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
fn known(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == slot)
        .unwrap()
        .semantic_values()
        .filter_map(|v| match v {
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(s) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}
fn present(bound: &BoundInvocation, slot: &str) -> bool {
    !bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == slot)
        .unwrap()
        .semantic_values_are_inapplicable()
}

#[test]
fn native_read_only_branches_do_not_generate_unknown_mutation_slots() {
    for command in [
        "rename -n 's/a/b/' ./*.txt",
        "rename -n 's/a/b/' **",
        "rename.ul -n foo bar \"$UNKNOWN\"",
        "rename.ul --no-act foo bar ./*",
        "file-rename -n 's/a/b/' ./*.txt",
    ] {
        let r = resolved(command);
        for slot in [
            "rename_sources",
            "rename_destinations",
            "rename_deletes",
            "rename_executions",
        ] {
            assert!(!present(&r.bound, slot), "{command}: {r:#?}");
        }
    }
    for command in [
        "rename -n 'system(\"id\")' ./*",
        "rename -n \"$PROGRAM\" ./*",
        "file-rename -e 's/a/b/' ./* -n /opt/a",
    ] {
        let r = resolved(command);
        assert!(present(&r.bound, "rename_executions"), "{command}: {r:#?}");
    }
    let r = resolved("file-rename 's/a/b/' /opt/a");
    assert_eq!(known(&r.bound, "rename_sources"), ["/opt/a"]);
    assert_eq!(known(&r.bound, "rename_destinations"), ["/opt/b"]);
}

#[test]
fn native_inputs_are_not_joined_and_perl_filenames_are_not_util_replacements() {
    for (command, sources, destinations) in [
        (
            "rename 's/^/new./' original.filename",
            vec!["original.filename"],
            vec!["new.original.filename"],
        ),
        (
            "rename 's/(.*)$/new.$1/' original.filename",
            vec!["original.filename"],
            vec!["new.original.filename"],
        ),
        ("rename 's/x/y/' x1 x2", vec!["x1", "x2"], vec!["y1", "y2"]),
        (
            "rename.ul foo bar foo1 foo2",
            vec!["foo1", "foo2"],
            vec!["bar1", "bar2"],
        ),
        (
            "file-rename -e 's/x/y/' x1 x2",
            vec!["x1", "x2"],
            vec!["y1", "y2"],
        ),
        ("prename -v 's/x/y/' 'x one'", vec!["x one"], vec!["y one"]),
    ] {
        let r = resolved(command);
        assert_eq!(
            known(&r.bound, "rename_sources"),
            sources,
            "{command}: {r:#?}"
        );
        assert_eq!(
            known(&r.bound, "rename_destinations"),
            destinations,
            "{command}: {r:#?}"
        );
        assert!(!present(&r.bound, "rename_executions"), "{command}: {r:#?}");
    }
}

#[test]
fn actual_destination_includes_full_path_and_option_order_semantics() {
    for (command, expected) in [
        ("rename.ul './' '/opt/out/' ./file", "/opt/out/file"),
        ("file-rename 's@^@/opt/out/@' file", "/opt/out/file"),
        ("rename.ul foo bar foo/foo.txt", "foo/bar.txt"),
        ("file-rename 's/foo/bar/' foo/foo.txt", "bar/foo.txt"),
        ("file-rename -d 's/foo/bar/' foo/foo.txt", "foo/bar.txt"),
        ("rename.ul -a a b aaa", "bbb"),
        ("rename.ul -l a b aaa", "aab"),
    ] {
        let r = resolved(command);
        assert_eq!(
            known(&r.bound, "rename_destinations"),
            [expected],
            "{command}: {r:#?}"
        );
    }
    // util-linux permutes options; Perl's positional expression closes options.
    let r = resolved("rename 's/a/b/' -n /opt/a");
    assert!(
        known(&r.bound, "rename_destinations").contains(&"/opt/b".into()),
        "{r:#?}"
    );
}

#[test]
fn unsupported_or_executable_programs_never_return_safe_partial_effects() {
    for command in [
        "rename 's/x/y/e' x",
        "rename -n 's/x/y/; system(\"id\")' x",
        "file-rename -n 's/x/y/; unlink($_)' x",
        "file-rename 's/(?{system(\"id\")})/x/' x",
        "file-rename 's/x/$ENV{HOME}/' x",
        "file-rename 's/x/@ENV/' x",
        "file-rename -e 's/x/y/' -e 'system(\"id\")' x",
        "file-rename --unicode 's/x/y/' x",
    ] {
        let r = resolved(command);
        assert!(present(&r.bound, "rename_executions"), "{command}: {r:#?}");
        assert!(
            present(&r.bound, "rename_destinations"),
            "{command}: {r:#?}"
        );
    }
}

#[test]
fn complete_stdin_is_decoded_as_filename_data_and_later_unknown_input_clears_old_results() {
    let mut r = resolved("file-rename 's/x/y/'");
    assert!(present(&r.bound, "rename_destinations"));
    refresh_payload_projections(&mut r.bound, Some("./x one\n./x$(id)\n"));
    assert_eq!(known(&r.bound, "rename_sources"), ["./x one", "./x$(id)"]);
    assert_eq!(
        known(&r.bound, "rename_destinations"),
        ["./y one", "./y$(id)"]
    );
    assert!(!present(&r.bound, "rename_executions"));
    refresh_payload_projections(&mut r.bound, None);
    assert!(known(&r.bound, "rename_destinations").is_empty());
    assert!(present(&r.bound, "rename_destinations"));
    let mut r = resolved("file-rename -0 's/x/y/'");
    refresh_payload_projections(&mut r.bound, Some("x one\0x\nline\0"));
    assert!(known(&r.bound, "rename_sources").contains(&"x\nline".into()));
    // Unterminated final records retain chop/chomp implementation alternatives.
    let mut r = resolved("file-rename 's/x/y/'");
    refresh_payload_projections(&mut r.bound, Some("xx"));
    assert_eq!(known(&r.bound, "rename_destinations"), ["yx", "y"]);
}

#[test]
fn schema_rejects_native_argv_without_boundary_and_effect_contracts() {
    let yaml = include_str!("../profiles/rename.yaml");
    for invalid in [
        yaml.replace("kind: remaining_args", "kind: remaining_positionals"),
        yaml.replace("cardinality: optional_many", "cardinality: required_many"),
        yaml.replace("        moves: rename_sources\n", ""),
        yaml.replace(
            "    implicit_inputs: [{source: stdin_data, semantic: {kind: plain_value}}]\n",
            "",
        ),
        yaml.replace("        executions: rename_executions\n", ""),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn native_contract_is_opt_in_and_not_a_command_name_branch() {
    let profile = load_command_profile_from_str(
        &include_str!("../profiles/rename.yaml")
            .replace("canonical_name: rename", "canonical_name: native-tool"),
    )
    .unwrap();
    let registry = ProfileRegistry::from_profiles(vec![profile]).unwrap();
    let parsed = caushell_parse::parse_command("native-tool 's/x/y/' x", ShellKind::Bash).unwrap();
    let ResolveInvocationArtifactResult::Resolved(r) = resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) else {
        panic!("expected native projection")
    };
    assert_eq!(known(&r.bound, "rename_destinations"), ["y"]);
}

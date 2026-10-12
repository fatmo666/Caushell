//! Root-owned, command-independent regressions for opt-in native argv grammars.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const YAML: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: octal-tool}
option_scope: leading_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: args, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]
modifiers:
  - {id: loop, matcher: {kind: any_flag, flags: [-n, -p]}}
  - id: numeric
    matcher: {kind: any_flag, flags: ['-0', -l]}
    parameters: [{name: numbers, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: optional_short_octal_prefix}, cardinality: optional_many}]
  - id: code
    matcher: {kind: any_flag, flags: [-e]}
    parameters: [{name: code, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
"#;

#[test]
fn path_projection_preserves_original_file_semantics_and_argv() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: path-projector}
forms:
  - id: run
    parameters:
      - name: destination
        semantic: {kind: path, role: write, purpose: generic_operand}
        binding: {kind: next_positional}
        cardinality: required_one
        structured_projection:
          branches:
            - {matcher: {kind: regex_capture, pattern: '^.+$', group: 0}, target: {name: helper_argument, semantic: {kind: plain_value}}}
    effects: [{kind: write_path, target: {kind: slot, name: destination}}]
"#;
    let b = bind(yaml, "path-projector 'cache/a b'");
    assert_eq!(values(&b, "destination"), ["cache/a b"]);
    let original = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "destination")
        .unwrap();
    assert!(matches!(
        original.semantic,
        SemanticType::Path(PathSemantic {
            role: PathRole::Write,
            ..
        })
    ));
    assert!(matches!(
        original.semantic_values().next().unwrap(),
        SemanticValueRef::Original(_)
    ));
    let projected = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "helper_argument")
        .unwrap();
    assert!(
        matches!(projected.semantic_values().next().unwrap(), SemanticValueRef::Projected {value, ..} if value.resolution == SemanticValueResolution::Known("cache/a b".into()))
    );
    let b = bind(yaml, "path-projector \"$UNKNOWN\"");
    assert_eq!(values(&b, "destination"), ["$UNKNOWN"]);
    assert!(b.bound_parameters.iter().find(|p| p.name.as_str() == "helper_argument").unwrap().semantic_values().any(|v| matches!(v, SemanticValueRef::Projected {value, ..} if matches!(value.resolution, SemanticValueResolution::Unknown(_)))));
    assert!(
        load_command_profile_from_str(&yaml.replace("role: write", "role: cwd_anchor")).is_err()
    );
    assert!(
        load_command_profile_from_str(&yaml.replace(
            "structured_projection:",
            "value_projection: {kind: identity}\n        structured_projection:"
        ))
        .is_err()
    );
}

#[test]
fn typed_code_load_projection_is_explicit_not_extension_guessing() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: demo-loader}
forms:
  - id: load
    parameters:
      - name: source
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        cardinality: required_one
        structured_projection:
          branches:
            - {matcher: {kind: literal, value: list}, target: null}
            - {matcher: {kind: regex_capture, pattern: '^.*/.*$', group: 0}, target: {name: library, semantic: {kind: in_process_code_load, load_kind: library_path}}}
          fallback: {name: plugin, semantic: {kind: in_process_code_load, load_kind: plugin_name}}
    effects: [{kind: load_in_process_code, target: {kind: slot, name: library}}, {kind: load_in_process_code, target: {kind: slot, name: plugin}}]
"#;
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(yaml).unwrap()]).unwrap();
    for (operand, known_slot) in [
        ("cache/blob", Some("library")),
        ("named.so", Some("plugin")),
        ("list", None),
        ("\"$UNKNOWN\"", None),
    ] {
        let command = format!("demo-loader {operand}");
        let parsed = parse_command(&command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
            &SessionBindings::new(),
        ) else {
            panic!("{command}")
        };
        assert_eq!(values(&r.bound, "source"), [operand.trim_matches('"')]);
        for slot in ["library", "plugin"] {
            let p = r
                .bound
                .bound_parameters
                .iter()
                .find(|p| p.name.as_str() == slot);
            let vals: Vec<_> = p.into_iter().flat_map(|p| p.semantic_values()).collect();
            if operand.contains("UNKNOWN") {
                assert_eq!(vals.len(), 1);
                assert!(
                    matches!(vals[0], SemanticValueRef::Projected {value, ..} if matches!(value.resolution, SemanticValueResolution::Unknown(_)))
                );
            } else {
                assert_eq!(
                    vals.len(),
                    usize::from(known_slot == Some(slot)),
                    "{command}: {r:#?}"
                );
            }
        }
    }
}

fn bind(yaml: &str, command: &str) -> BoundInvocation {
    let p = load_command_profile_from_str(yaml).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&p, &projection).unwrap();
    bind_invocation(&p, &projection, &selected)
}

#[test]
fn alternate_native_spellings_share_only_the_same_source_and_semantic_slot() {
    const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: alternate-tool}
forms:
  - id: run
    parameters:
      - name: operand
        semantic: {kind: plain_value}
        binding: {kind: remaining_args}
        cardinality: optional_many
        structured_projection:
          branches:
            - {matcher: {kind: regex_capture, pattern: '^plain:(.+)$', group: 1}, target: {name: decoded, semantic: {kind: plain_value}}}
            - {matcher: {kind: regex_capture, pattern: '^\[(.+)\]$', group: 1}, target: {name: decoded, semantic: {kind: plain_value}}}
          fallback: {name: decoded, unresolved: true, semantic: {kind: plain_value}}
"#;
    for (command, expected) in [
        ("alternate-tool plain:VALUE", "VALUE"),
        ("alternate-tool '[OTHER]'", "OTHER"),
    ] {
        let b = bind(PROFILE, command);
        let slot = b
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "decoded")
            .unwrap();
        assert!(
            matches!(slot.semantic_values().next().unwrap(), SemanticValueRef::Projected {value, ..}
            if value.resolution == SemanticValueResolution::Known(expected.into())),
            "{b:#?}"
        );
        assert_eq!(slot.values.len(), 1);
    }
    let absent = bind(PROFILE, "alternate-tool");
    assert!(
        !absent
            .bound_parameters
            .iter()
            .any(|p| p.name.as_str() == "decoded"),
        "an absent optional input has no decoded semantic value: {absent:#?}"
    );
    for command in ["alternate-tool \"$UNKNOWN\"", "alternate-tool unsupported"] {
        let b = bind(PROFILE, command);
        let slot = b
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "decoded")
            .unwrap();
        assert_eq!(
            slot.values.len(),
            1,
            "unknown input has one semantic value, not one per branch: {b:#?}"
        );
        assert!(
            matches!(slot.semantic_values().next().unwrap(), SemanticValueRef::Projected {value, ..}
            if matches!(value.resolution, SemanticValueResolution::Unknown(_)))
        );
    }
    let conflict = PROFILE.replace("fallback: {name: decoded, unresolved: true, semantic: {kind: plain_value}}",
        "fallback: {name: decoded, unresolved: true, semantic: {kind: path, role: read, purpose: generic_operand}}");
    assert!(load_command_profile_from_str(&conflict).is_err());
    let different_source = format!(
        "{PROFILE}      - name: other\n        semantic: {{kind: plain_value}}\n        binding: {{kind: remaining_args}}\n        cardinality: optional_many\n        structured_projection:\n          branches: []\n          fallback: {{name: decoded, semantic: {{kind: plain_value}}}}\n"
    );
    assert!(load_command_profile_from_str(&different_source).is_err());
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn numeric_prefix_resumes_flags_and_preserves_independent_operands() {
    for (command, numbers, code) in [
        ("octal-tool -0777ne print input", vec!["777"], "print"),
        ("octal-tool -l40pe0 input", vec!["40"], "0"),
        ("octal-tool -ln0e 'print -l70' input", vec![], "print -l70"),
        (
            "octal-tool -ln007e 'print -l70' input",
            vec!["07"],
            "print -l70",
        ),
    ] {
        let b = bind(YAML, command);
        assert!(b.residuals.is_empty(), "{command}: {b:#?}");
        assert_eq!(values(&b, "numbers"), numbers, "{command}");
        assert_eq!(values(&b, "code"), [code], "{command}");
        assert_eq!(values(&b, "args"), ["input"], "{command}");
    }
}

#[test]
fn bare_numeric_option_never_owns_the_next_word_and_terminator_is_respected() {
    let b = bind(YAML, "octal-tool -0 777 -e print");
    assert!(values(&b, "numbers").is_empty());
    assert!(values(&b, "code").is_empty());
    assert_eq!(values(&b, "args"), ["777", "-e", "print"]);
    let b = bind(YAML, "octal-tool -- -0777ne print");
    assert!(b.applied_modifiers.is_empty());
    assert_eq!(values(&b, "args"), ["-0777ne", "print"]);
}

#[test]
fn unknown_switches_and_unsupported_numeric_grammar_remain_unresolved() {
    let p = load_command_profile_from_str(YAML).unwrap();
    for command in [
        "octal-tool -l89pe0 input",
        "octal-tool -l40q",
        "octal-tool -l40l70e0",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(select_invocation(&p, &projection).is_err(), "{command}");
    }
    assert!(
        load_command_profile_from_str(&YAML.replace("leading_options", "all_arguments")).is_err()
    );
    assert!(load_command_profile_from_str(&YAML.replace("['-0', -l]", "[--numeric]")).is_err());
    assert!(
        load_command_profile_from_str(&YAML.replace(
            "option_scope: leading_options",
            "option_scope: leading_options\noption_matching: exact_names"
        ))
        .is_err()
    );
}

#[test]
fn full_operand_matcher_is_opt_in_and_does_not_swallow_unknown_controls() {
    const OPERAND: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: operand-tool}
option_scope: permuted_options
option_operand_matcher: {kind: regex_pattern, pattern: '^-[0-9]+$'}
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers: [{id: recursive, matcher: {kind: any_flag, flags: [-R]}}]
"#;
    let b = bind(OPERAND, "operand-tool -R -10 -- -garbage");
    assert!(b.residuals.is_empty(), "{b:?}");
    assert_eq!(values(&b, "data"), ["-10", "-garbage"]);
    assert_eq!(b.applied_modifiers, [ModifierId::new("recursive")]);
    let p = load_command_profile_from_str(OPERAND).unwrap();
    for command in ["operand-tool -10x", "operand-tool --unknown"] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert!(
            select_invocation(
                &p,
                &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new())
            )
            .is_err()
        );
    }
    assert!(
        load_command_profile_from_str(&OPERAND.replace("permuted_options", "all_arguments"))
            .is_err()
    );
    let unanchored =
        load_command_profile_from_str(&OPERAND.replace("^-[0-9]+$", "-[0-9]+")).unwrap();
    let parsed = parse_command("operand-tool -10x", ShellKind::Bash).unwrap();
    assert!(
        select_invocation(
            &unanchored,
            &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new())
        )
        .is_err()
    );
}

#[test]
fn exact_attached_words_do_not_enable_short_clusters_or_steal_next_words() {
    const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: word-tool}
option_scope: permuted_options
option_matching: exact_names
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: files, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - id: data
    matcher: {kind: any_flag, flags: [-m, -mhe]}
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: optional_word_attached}, cardinality: optional_many}]
  - {id: query, matcher: {kind: any_flag, flags: [-so]}}
"#;
    for (command, data, files) in [
        (
            "word-tool -mhe=on -msecret -so file",
            vec!["=on", "secret"],
            vec!["file"],
        ),
        ("word-tool -m file", vec![], vec!["file"]),
        ("word-tool -- -msecret", vec![], vec!["-msecret"]),
    ] {
        let b = bind(PROFILE, command);
        assert!(b.residuals.is_empty(), "{command}: {b:#?}");
        assert_eq!(values(&b, "data"), data);
        assert_eq!(values(&b, "files"), files);
    }
    let p = load_command_profile_from_str(PROFILE).unwrap();
    let parsed = parse_command("word-tool -sox", ShellKind::Bash).unwrap();
    assert!(
        select_invocation(
            &p,
            &project_invocation(&parsed.commands[0], InvocationRuntimeContext::new())
        )
        .is_err()
    );
    assert!(
        load_command_profile_from_str(&PROFILE.replace("permuted_options", "all_arguments"))
            .is_err()
    );
    assert!(
        load_command_profile_from_str(&PROFILE.replace("exact_names", "short_clusters")).is_err()
    );
}

#[test]
fn regex_capture_projects_whole_tool_operands_once_without_reinterpreting_shell_bytes() {
    const PROFILE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: capture-tool}
forms:
  - id: run
    parameters:
      - name: operand
        semantic: {kind: plain_value}
        binding: {kind: remaining_args}
        cardinality: optional_many
        structured_projection:
          branches:
            - {matcher: {kind: regex_capture, pattern: '^name=@(.*)$', group: 1}, target: {name: file, semantic: {kind: path, role: read, purpose: generic_operand}}}
          fallback: {name: data, semantic: {kind: plain_value}}
    effects: [{kind: read_path, target: {kind: slot, name: file}}]
"#;
    for command in [
        "capture-tool 'name=@/tmp/a b'",
        "capture-tool 'name=@$LITERAL'",
    ] {
        let b = bind(PROFILE, command);
        let file = b
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "file")
            .unwrap();
        let projected: Vec<_> = file.semantic_values().collect();
        let expected = if command.contains("LITERAL") {
            "$LITERAL"
        } else {
            "/tmp/a b"
        };
        assert!(
            matches!(&projected[0], SemanticValueRef::Projected {value, ..}
            if value.resolution == SemanticValueResolution::Known(expected.into())),
            "{b:#?}"
        );
        assert_eq!(values(&b, "operand")[0], format!("name=@{expected}"));
    }
    let b = bind(PROFILE, "capture-tool 'xname=@/tmp/file'");
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    let b = bind(PROFILE, "capture-tool 'name=@'");
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    let file = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "file")
        .unwrap();
    assert!(
        matches!(file.semantic_values().next().unwrap(), SemanticValueRef::Projected {value, ..} if matches!(value.resolution, SemanticValueResolution::Unknown(_)))
    );
    assert!(load_command_profile_from_str(&PROFILE.replace("group: 1", "group: 2")).is_err());
    assert!(load_command_profile_from_str(&PROFILE.replace("^name=@(.*)$", "[")).is_err());
    let b = bind(
        &PROFILE.replace("^name=@(.*)$", "name=@(.*)"),
        "capture-tool 'xname=@/tmp/file'",
    );
    assert!(
        !b.effects.iter().any(|e| e.kind == EffectKind::ReadPath),
        "full capture required even without anchors"
    );
    let b = bind(
        &PROFILE.replace("^name=@(.*)$", "^name=@(.*)?$"),
        "capture-tool name=@",
    );
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
}

#[test]
fn explicit_unknown_projection_never_invents_a_concrete_capture_or_preferred_source() {
    let profile = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: unknown-tool}
forms:
  - id: run
    parameters:
      - name: operand
        semantic: {kind: plain_value}
        binding: {kind: remaining_args}
        cardinality: required_many
        structured_projection:
          branches: []
          fallback: {name: target, unresolved: true, semantic: {kind: path, role: read, purpose: generic_operand}}
    effects: [{kind: read_path, target: {kind: slot, name: target}}]
"#;
    let bound = bind(profile, "unknown-tool /looks/local");
    let target = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "target")
        .unwrap();
    assert!(
        matches!(target.semantic_values().next().unwrap(), SemanticValueRef::Projected {value, ..}
        if matches!(value.resolution, SemanticValueResolution::Unknown(_)))
    );
    assert!(
        load_command_profile_from_str(
            &profile.replace("unresolved: true", "unresolved: true, sources: [operand]")
        )
        .is_err()
    );
}

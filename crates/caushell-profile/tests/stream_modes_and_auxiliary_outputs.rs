//! Model argv and stream contracts; never execute the sample programs.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{DerivedPathRule, ShellKind, StreamDataDependency};

fn bind(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(
                !r.bound.operation_semantics_unresolved,
                "{command}: {:#?}",
                r.bound
            );
            r.bound
        }
        other => panic!("{command}: {other:#?}"),
    }
}
fn values(b: &BoundInvocation, name: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| p.semantic_values())
        .filter_map(
            |v| match project_semantic_value(&ValueProjection::Identity, v) {
                Some(SemanticValueResolution::Known(s)) => Some(s),
                _ => None,
            },
        )
        .collect()
}

#[test]
fn uniq_fixed_operands_preserve_input_with_dash_output() {
    let b = bind("uniq -f1 .env -");
    assert_eq!(values(&b, "input_paths"), [".env"]);
    assert!(values(&b, "output_path").is_empty());
    let s = b.stream_contract.unwrap();
    assert_eq!(s.stdin_mode, StreamInputMode::Ignored);
    assert_eq!(s.stdout_dependency, StreamDataDependency::Inputs);
    for command in [
        "uniq .env cache/out",
        "uniq .env ./-",
        "uniq .env /dev/null",
    ] {
        let b = bind(command);
        assert_eq!(values(&b, "input_paths"), [".env"]);
        assert_eq!(
            b.stream_contract.unwrap().stdout_dependency,
            StreamDataDependency::Independent
        );
    }
    for command in ["uniq", "uniq -", "uniq - -"] {
        let b = bind(command);
        assert!(values(&b, "input_paths").is_empty());
        assert!(values(&b, "output_path").is_empty());
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DataRequired
        );
    }
    let b = bind("uniq - cache/out");
    assert_eq!(values(&b, "output_path"), ["cache/out"]);
    assert_eq!(
        b.stream_contract.unwrap().stdin_mode,
        StreamInputMode::DataRequired
    );
    bind("uniq --group .env -");
    bind("uniq --all-repeated=separate .env -");
}

#[test]
fn information_forms_have_no_operational_paths() {
    for command in [
        "uniq --help .env /outside/out",
        "uniq --version .env -",
        "sort --help .env -o /outside/out -T /outside --compress-program=bash",
        "sort --version .env",
        "head --help .env",
        "head --version .env",
    ] {
        let b = bind(command);
        assert!(
            !b.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::ReadPath
                    | EffectKind::WritePath
                    | EffectKind::TransformData
                    | EffectKind::DispatchCommand
            )),
            "{command}: {b:#?}"
        );
        assert_eq!(
            b.stream_contract.unwrap().stdout_dependency,
            StreamDataDependency::Independent
        );
    }
}

#[test]
fn sort_checks_keep_only_the_correct_diagnostic_port() {
    for command in [
        "sort -C .env",
        "sort --check=quiet .env",
        "sort --check=silent .env",
        "sort --check=q .env",
    ] {
        let b = bind(command);
        assert_eq!(b.form_id.as_str(), "check_quiet");
        assert_eq!(values(&b, "input_paths"), [".env"]);
        let s = b.stream_contract.unwrap();
        assert_eq!(s.stdout_dependency, StreamDataDependency::Independent);
        assert_eq!(s.stderr_dependency, StreamDataDependency::Independent);
    }
    for command in [
        "sort -c .env",
        "sort --check .env",
        "sort --check=diagnose-first .env",
    ] {
        let b = bind(command);
        let s = b.stream_contract.unwrap();
        assert_eq!(s.stdout_dependency, StreamDataDependency::Independent);
        assert_eq!(s.stderr_dependency, StreamDataDependency::Inputs);
    }
    let b = bind("sort -c .env -T /outside --compress-program=bash");
    assert!(!b.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::WritePath | EffectKind::DispatchCommand | EffectKind::TransformData
    )));
    assert!(values(&b, "temp_directory").is_empty());
    assert_eq!(
        bind("sort -c").stream_contract.unwrap().stdin_mode,
        StreamInputMode::DataRequired
    );
}

#[test]
fn sorting_preserves_native_outputs_and_explicit_stdin_membership() {
    assert_eq!(
        bind("sort cache/in").stream_contract.unwrap().stdin_mode,
        StreamInputMode::Ignored
    );
    for command in ["sort", "sort -", "sort cache/in -"] {
        assert_eq!(
            bind(command).stream_contract.unwrap().stdin_mode,
            StreamInputMode::DataRequired
        );
    }
    let b = bind("sort -o /dev/null -T /outside --compress-program=echo cache/in");
    assert_eq!(values(&b, "output_path"), ["/dev/null"]);
    assert_eq!(values(&b, "temp_directory"), ["/outside"]);
    assert_eq!(
        b.stream_contract.unwrap().stdout_dependency,
        StreamDataDependency::Independent
    );
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::DispatchCommand)
    );
    assert_eq!(values(&bind("sort -o - cache/in"), "output_path"), ["-"]);
}

#[test]
fn wget_auxiliary_outputs_respect_activation_and_final_values() {
    let b = bind(
        "wget -O - --warc-file=/outside/capture --warc-tempdir=/outside/temp --warc-dedup=cache/index https://example.test/",
    );
    assert_eq!(values(&b, "warc_prefix"), ["/outside/capture"]);
    assert_eq!(values(&b, "warc_temp_directory"), ["/outside/temp"]);
    assert_eq!(values(&b, "warc_dedup_file"), ["cache/index"]);
    assert!(b.effects.iter().any(|e| matches!(&e.target, EffectTarget::DerivedPath(p) if p.rule == DerivedPathRule::SiblingFiles)));
    let b = bind(
        "wget -O - --warc-tempdir=/outside/temp --warc-dedup=/outside/index https://example.test/",
    );
    assert!(values(&b, "warc_temp_directory").is_empty());
    assert!(values(&b, "warc_dedup_file").is_empty());
    let b = bind("wget -O - --hsts-file=/outside/old --hsts-file=cache/new https://example.test/");
    assert_eq!(values(&b, "hsts_file"), ["cache/new"]);
    assert!(
        values(
            &bind("wget -O - --no-hsts --hsts-file=/outside/db https://example.test/"),
            "hsts_file"
        )
        .is_empty()
    );
    assert!(
        values(
            &bind("wget -O - --rejected-log=/outside/log https://example.test/"),
            "rejected_log_file"
        )
        .is_empty()
    );
    assert_eq!(
        values(
            &bind("wget -r --rejected-log=/outside/log https://example.test/"),
            "rejected_log_file"
        ),
        ["/outside/log"]
    );
    let b = bind(
        "wget --help --warc-file=/outside/a --warc-tempdir=/outside --hsts-file=/outside/db --rejected-log=/outside/log -r",
    );
    assert!(
        !b.effects.iter().any(|e| e.kind == EffectKind::WritePath),
        "{b:#?}"
    );
}

#[test]
fn wget_explicit_startup_config_is_not_sent_as_request_body() {
    let b = bind("wget -O - --no-config --config=cache/wgetrc https://example.test/");
    assert_eq!(values(&b, "config_file"), ["cache/wgetrc"]);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::LoadConfig));
    assert!(
        !b.effects
            .iter()
            .find(|e| e.kind == EffectKind::NetworkEndpoint)
            .unwrap()
            .input_scope
            .as_ref()
            .unwrap()
            .slots
            .iter()
            .any(|s| s.as_str() == "config_file")
    );
}

#[test]
fn modifier_projection_conditions_are_generic_and_validate_references() {
    let yaml = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: demo-projector}
option_scope: permuted_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters:
      - name: operand
        semantic: {kind: plain_value}
        binding: {kind: next_positional}
        cardinality: optional_one
        structured_projection:
          branches:
            - {matcher: {kind: regex_capture, pattern: '^.+$', group: 0}, requires_modifiers: [active], unless_modifiers: [quiet, disabled], target: {name: output, semantic: {kind: path, role: write, purpose: generic_operand}}}
    effects: [{kind: write_path, target: {kind: slot, name: output}}]
modifiers:
  - {id: active, matcher: {kind: any_flag, flags: [--active]}}
  - {id: quiet, matcher: {kind: any_flag, flags: [--quiet]}}
  - {id: disabled, matcher: {kind: any_flag, flags: [--disabled]}}
"#;
    for (command, generated) in [
        ("demo-projector", false),
        ("demo-projector cache/out", false),
        ("demo-projector --active cache/out", true),
        ("demo-projector --active --quiet cache/out", false),
        ("demo-projector --active --disabled \"$X\"", false),
        ("demo-projector --active \"$X\"", true),
    ] {
        let registry =
            ProfileRegistry::from_profiles(vec![load_command_profile_from_str(yaml).unwrap()])
                .unwrap();
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationResult::Resolved(r) = resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::default(),
        ) else {
            panic!("{command}")
        };
        assert_eq!(
            r.bound
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "output"),
            generated,
            "{command}: {:#?}",
            r.bound
        );
    }
    for invalid in [
        yaml.replace(
            "requires_modifiers: [active]",
            "requires_modifiers: [missing]",
        ),
        yaml.replace(
            "requires_modifiers: [active]",
            "requires_modifiers: [active, active]",
        ),
        yaml.replace(
            "unless_modifiers: [quiet, disabled]",
            "unless_modifiers: [active]",
        ),
    ] {
        assert!(load_command_profile_from_str(&invalid).is_err());
    }
}

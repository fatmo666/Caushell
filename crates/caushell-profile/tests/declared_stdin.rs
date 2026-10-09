//! Generic opt-in stream guarantees. Shell strings are parsed, never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamDataDependency};

const SOURCE: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_stream_reader}
forms:
  - id: selected
    parameters:
      - name: inputs
        semantic: {kind: plain_value}
        binding: {kind: remaining_positionals}
        cardinality: optional_many
        structured_projection:
          branches:
            - matcher: {kind: literal, value: '-'}
              target: {name: stdin_inputs, semantic: {kind: plain_value}}
          fallback: {name: file_inputs, semantic: {kind: path, role: read}}
    effects:
      - {kind: consume_stdin, target: {kind: slot, name: stdin_inputs}}
    stream_contract:
      stdin_mode: declared_effects
      stdout_mode: path_list
      stderr_mode: opaque
      stdout_dependency: inputs
      stderr_dependency: independent
"#;

fn resolve(source: &str, command: &str) -> ResolvedInvocationArtifact {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn bound_effects_select_input_without_rewriting_the_declared_contract() {
    for (command, mode) in [
        // This generic optional projection emits possible targets for a
        // missing value; the emitted stdin effect stays conservative.
        ("arbitrary_stream_reader", StreamInputMode::DataOptional),
        (
            "arbitrary_stream_reader public.txt",
            StreamInputMode::Ignored,
        ),
        ("arbitrary_stream_reader -", StreamInputMode::DataOptional),
        (
            "arbitrary_stream_reader public.txt -",
            StreamInputMode::DataOptional,
        ),
    ] {
        let r = resolve(SOURCE, command);
        assert_eq!(
            r.bound.stream_contract.unwrap().stdin_mode,
            StreamInputMode::DeclaredEffects
        );
        let effective = r.proven_stream_contract().unwrap();
        assert_eq!(effective.stdin_mode, mode, "{command}");
        assert_eq!(effective.stdout_mode, StreamOutputMode::PathList);
        assert_eq!(effective.stderr_mode, StreamOutputMode::Opaque);
        assert_eq!(effective.stdout_dependency, StreamDataDependency::Inputs);
        assert_eq!(
            effective.stderr_dependency,
            StreamDataDependency::Independent
        );
    }
}

#[test]
fn unconditional_stdin_effect_and_absent_optional_slot_are_distinct() {
    let unconditional = SOURCE.replace(
        "target: {kind: slot, name: stdin_inputs}",
        "target: {kind: none}",
    );
    assert_eq!(
        resolve(&unconditional, "arbitrary_stream_reader public.txt")
            .proven_stream_contract()
            .unwrap()
            .stdin_mode,
        StreamInputMode::DataOptional,
    );
    let absent = resolve(SOURCE, "arbitrary_stream_reader public.txt");
    assert!(
        !absent
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ConsumeStdin)
    );
    assert_eq!(
        absent.proven_stream_contract().unwrap().stdin_mode,
        StreamInputMode::Ignored
    );
}

#[test]
fn dynamic_unresolved_or_residual_arguments_cannot_prove_ignored_input() {
    let dynamic = resolve(SOURCE, "arbitrary_stream_reader \"$unknown\"");
    assert!(dynamic.proven_stream_contract().is_none());
    let mut residual = resolve(SOURCE, "arbitrary_stream_reader public.txt");
    residual.bound.residuals.push(Residual::new(
        ResidualKind::UnboundControlSurface,
        ResidualSurface::Control,
        "unmodeled control prevents a complete shape guarantee",
    ));
    assert!(residual.proven_stream_contract().is_none());
    let mut unresolved = resolve(SOURCE, "arbitrary_stream_reader public.txt");
    unresolved.bound.operation_semantics_unresolved = true;
    assert!(unresolved.proven_stream_contract().is_none());
}

#[test]
fn all_legacy_modes_keep_their_existing_meaning() {
    for (name, mode) in [
        ("ignored", StreamInputMode::Ignored),
        ("data_optional", StreamInputMode::DataOptional),
        ("data_required", StreamInputMode::DataRequired),
        ("payload_optional", StreamInputMode::PayloadOptional),
        ("payload_required", StreamInputMode::PayloadRequired),
    ] {
        let source = SOURCE.replace(
            "stdin_mode: declared_effects",
            &format!("stdin_mode: {name}"),
        );
        for command in [
            "arbitrary_stream_reader public.txt",
            "arbitrary_stream_reader -",
        ] {
            assert_eq!(
                resolve(&source, command)
                    .proven_stream_contract()
                    .unwrap()
                    .stdin_mode,
                mode
            );
        }
    }
    let mut absent = resolve(SOURCE, "arbitrary_stream_reader -");
    absent.bound.stream_contract = None;
    assert!(absent.proven_stream_contract().is_none());
}

#[test]
fn stdin_record_forwarding_requires_effective_stdin_consumption() {
    let source = format!("{SOURCE}    stdout_records:\n      projection: {{kind: stdin}}\n");
    assert!(
        resolve(&source, "arbitrary_stream_reader -")
            .proven_stdout_records()
            .is_some()
    );
    assert!(
        resolve(&source, "arbitrary_stream_reader public.txt")
            .proven_stdout_records()
            .is_none()
    );
    assert!(
        resolve(&source, "arbitrary_stream_reader \"$unknown\"")
            .proven_stdout_records()
            .is_none()
    );
}

#[test]
fn an_absent_modifier_does_not_emit_its_stdin_effect() {
    let source = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_stream_reader}
forms:
  - id: selected
    stream_contract: {stdin_mode: declared_effects, stdout_mode: data, stderr_mode: opaque}
modifiers:
  - id: use_stdin
    matcher: {kind: any_flag, flags: ['--stdin']}
    effects:
      - {kind: consume_stdin, target: {kind: none}}
"#;
    for (command, mode) in [
        ("arbitrary_stream_reader", StreamInputMode::Ignored),
        (
            "arbitrary_stream_reader --stdin",
            StreamInputMode::DataOptional,
        ),
    ] {
        assert_eq!(
            resolve(source, command)
                .proven_stream_contract()
                .unwrap()
                .stdin_mode,
            mode
        );
    }
}

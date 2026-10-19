use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StreamGrowth, StreamRecordFraming};

const PREFIX: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_prefix}
opaque_on_unresolved: true
forms:
  - id: prefix
    remaining_selector: {kind: no_positional_args}
    stream_contract: {stdin_mode: data_required, stdout_mode: data, stderr_mode: opaque, stdout_dependency: inputs}
    stdout_growth:
      kind: prefix
      default_count: 10
      default_unit: records
      counters: [{slot: bytes, unit: bytes}, {slot: records, unit: records}]
      nul_modifier: nul
modifiers:
  - id: bytes
    matcher: {kind: any_flag, flags: [--bytes, -c]}
    parameters: [{name: bytes, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
  - id: records
    matcher: {kind: any_flag, flags: [--records, -n]}
    parameters: [{name: records, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
  - {id: nul, matcher: {kind: any_flag, flags: [-z]}}
"#;

fn resolve(source: &str, command: &str) -> ResolvedInvocationArtifact {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
            .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn generic_prefix_contract_uses_owned_last_counter_and_its_unit() {
    for (args, expected) in [
        (
            "",
            Some(StreamGrowth::RecordPrefix {
                records: StreamRecordFraming::Lines,
            }),
        ),
        (
            "-n10",
            Some(StreamGrowth::RecordPrefix {
                records: StreamRecordFraming::Lines,
            }),
        ),
        (
            "-z -n10",
            Some(StreamGrowth::RecordPrefix {
                records: StreamRecordFraming::Nul,
            }),
        ),
        ("-c10", Some(StreamGrowth::Finite)),
        ("--bytes=1MiB", Some(StreamGrowth::Finite)),
        ("-n0", Some(StreamGrowth::Finite)),
        ("-n-10", None),
        ("-c-10", None),
        ("-c10 -n-10", None),
        ("-n-10 -c10", Some(StreamGrowth::Finite)),
        ("-c10 -c-10", None),
        ("-c-10 -c10", Some(StreamGrowth::Finite)),
        ("-c10 -c\"$UNKNOWN\"", None),
        ("-{c10,n-10}", None),
        ("-c10 --unsupported", None),
    ] {
        assert_eq!(
            resolve(PREFIX, &format!("arbitrary_prefix {args}")).proven_stdout_growth(),
            expected,
            "{args}"
        );
    }
}

#[test]
fn continuous_declarations_do_not_require_a_reserved_command_name() {
    let source = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: arbitrary_source}
forms:
  - id: source
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_args}, cardinality: optional_many}]
    stream_contract: {stdin_mode: ignored, stdout_mode: data, stderr_mode: opaque}
    stdout_growth: {kind: continuous, records: lines}
"#;
    assert_eq!(
        resolve(source, "arbitrary_source data").proven_stdout_growth(),
        Some(StreamGrowth::Continuous {
            records: StreamRecordFraming::Lines
        })
    );
    assert_eq!(
        resolve(source, "arbitrary_source \"$unknown\"").proven_stdout_growth(),
        Some(StreamGrowth::Continuous {
            records: StreamRecordFraming::Unknown
        })
    );
}

#[test]
fn malformed_growth_contracts_are_rejected_at_load_time() {
    for source in [PREFIX.replace("cardinality: required_many", "cardinality: optional_many"), PREFIX.replace("slot: bytes", "slot: typo"), PREFIX.replace("nul_modifier: nul", "nul_modifier: typo"),
        PREFIX.replace("{slot: records, unit: records}", "{slot: bytes, unit: records}"),
        PREFIX.replace("kind: prefix\n      default_count", "kind: typo\n      default_count"),
        PREFIX.replace("    stream_contract: {stdin_mode: data_required, stdout_mode: data, stderr_mode: opaque, stdout_dependency: inputs}\n", "")] {
        assert!(load_command_profile_from_str(&source).is_err(), "{source}");
    }
}

#[test]
fn extent_completeness_does_not_enable_global_opaque_policy() {
    let source = PREFIX.replace("opaque_on_unresolved: true\n", "");
    let r = resolve(&source, "arbitrary_prefix -c10 --unmodeled");
    assert!(!r.bound.stdout_growth_complete);
    assert!(r.proven_stdout_growth().is_none());
    assert!(!r.bound.operation_semantics_unresolved);
    assert!(r.bound.residuals.is_empty());
}

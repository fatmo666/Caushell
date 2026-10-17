//! Profile declarations are tested independently of the final guard decision.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const CONDITIONAL: &str = r#"
dsl_version: caushell.profile/v1alpha1
kind: command_profile
identity: {canonical_name: fixture}
option_scope: permuted_options
opaque_on_unresolved: true
forms:
  - id: run
    parameters: [{name: data, semantic: {kind: plain_value}, binding: {kind: remaining_positionals}, cardinality: optional_many}]
modifiers:
  - id: operation
    matcher: {kind: any_flag, flags: [-m, --mode]}
    parameters: [{name: mode, semantic: {kind: plain_value}, binding: {kind: following_matched_flag, operand_mode: next_arg}, cardinality: required_many}]
    effects_when:
      last_parameter_not_matching: {parameter: mode, matcher: {kind: regex_pattern, pattern: '^(read|inspect)$'}}
    effects: [{kind: state_operation, state_operation: {domain: remote_resource, operation: mutate}, target: {kind: none}}]
"#;

fn resolve(
    registry: &ProfileRegistry,
    command: &str,
    bindings: &SessionBindings,
) -> ResolvedInvocationArtifact {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}

#[test]
fn final_owned_parameter_controls_effects_without_command_name_logic() {
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(CONDITIONAL).unwrap()])
            .unwrap();
    for (command, mutates) in [
        ("fixture -m read", false),
        ("fixture --mode=inspect", false),
        ("fixture -mread", false),
        ("fixture -m write -m read", false),
        ("fixture -m read -m write", true),
        ("fixture -m reader", true),
        ("fixture -m \"$UNKNOWN\"", true),
        ("fixture -- --mode=write", false),
    ] {
        let r = resolve(&registry, command, &SessionBindings::new());
        assert_eq!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::StateOperation),
            mutates,
            "{command}"
        );
    }
    let mut bindings = SessionBindings::new();
    bindings.insert_exact_scalar("OPERATION", "read");
    let r = resolve(&registry, "fixture -m \"$OPERATION\"", &bindings);
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::StateOperation)
    );
}

#[test]
fn final_parameter_comparison_requires_a_declared_owned_plain_operand() {
    for yaml in [
        CONDITIONAL.replace("parameter: mode, matcher", "parameter: typo, matcher"),
        CONDITIONAL.replace("option_scope: permuted_options", "option_scope: all_arguments"),
        CONDITIONAL.replace("semantic: {kind: plain_value}, binding: {kind: following_matched_flag", "semantic: {kind: path, role: read}, binding: {kind: following_matched_flag"),
        CONDITIONAL.replace("last_parameter_not_matching:", "last_option_not_matching: {kind: literal, value: read}\n      last_parameter_not_matching:"),
    ] {
        assert!(load_command_profile_from_str(&yaml).is_err(), "{yaml}");
    }
}

#[test]
fn new_state_domains_remain_typed_and_do_not_require_filesystem_slots() {
    for domain in ["remote_resource", "print_service", "terminal_broadcast"] {
        let yaml = CONDITIONAL.replace("domain: remote_resource", &format!("domain: {domain}"));
        assert!(load_command_profile_from_str(&yaml).is_ok());
    }
}

#[test]
fn native_execution_directory_survives_subcommand_selection() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "npm -C /opt exec --call 'touch file'",
        "yarn --cwd /opt exec touch file",
    ] {
        let r = resolve(&registry, command, &SessionBindings::new());
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::SetExecutionWorkingDirectory),
            "{r:#?}"
        );
    }
}

#[test]
fn package_preview_and_no_script_modes_do_not_claim_execution() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "npm install --dry-run",
        "npm install --ignore-scripts --prefix ./env",
        "npm install --package-lock-only --prefix ./env",
    ] {
        let r = resolve(&registry, command, &SessionBindings::new());
        assert!(
            !r.bound.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::ExecuteImportedPackageLogic
                    | EffectKind::ExecuteConfigDefinedTask
                    | EffectKind::ExecutePayload
            )),
            "{command}: {:?}",
            r.bound.effects
        );
    }
    for command in [
        "pip install --dry-run .",
        "pip install --dry-run -r requirements.txt",
        "pip install --dry-run -e .",
    ] {
        let r = resolve(&registry, command, &SessionBindings::new());
        assert!(
            !r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
        assert!(
            r.bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecuteImportedPackageLogic)
        );
    }
}

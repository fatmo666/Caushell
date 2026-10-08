use caushell_parse::parse_command;
use caushell_profile::{
    InvocationRuntimeContext, StreamInputMode, bind_invocation, load_command_profile_from_str,
    project_invocation, select_invocation,
};
use caushell_profile::{
    ProfileRegistry, ResolveInvocationArtifactResult, SessionBindings,
    resolve_invocation_artifact_with_bindings,
};
use caushell_types::{ShellKind, StreamDataDependency};

fn profile(extra: &str) -> String {
    format!(
        "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {{canonical_name: arbitrary_stream_tool}}\nforms:\n  - id: selected\n    stream_contract:\n      stdin_mode: ignored\n      stdout_mode: opaque\n      stderr_mode: opaque\n{extra}"
    )
}

#[test]
fn existing_contracts_default_to_unknown_not_safe_output() {
    let profile = load_command_profile_from_str(&profile("")).unwrap();
    let contract = profile.forms[0].stream_contract.unwrap();
    assert_eq!(contract.stdout_dependency, StreamDataDependency::Unknown);
    assert_eq!(contract.stderr_dependency, StreamDataDependency::Unknown);
}

#[test]
fn arbitrary_command_retains_selected_output_contract_in_binding() {
    let profile = load_command_profile_from_str(&profile(
        "      stdout_dependency: independent\n      stderr_dependency: inputs\n",
    ))
    .unwrap();
    let parsed = parse_command("arbitrary_stream_tool", ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).unwrap();
    let bound = bind_invocation(&profile, &projection, &selection);
    let contract = bound.stream_contract.unwrap();
    assert_eq!(contract.stdin_mode, StreamInputMode::Ignored);
    assert_eq!(
        contract.stdout_dependency,
        StreamDataDependency::Independent
    );
    assert_eq!(contract.stderr_dependency, StreamDataDependency::Inputs);
}

#[test]
fn invalid_dependency_is_rejected_not_silently_ignored() {
    assert!(load_command_profile_from_str(&profile("      stdout_dependency: safe\n")).is_err());
}

#[test]
fn positive_record_contract_is_selected_and_bound_without_tool_name_logic() {
    let source = "dsl_version: caushell.profile/v1alpha1\nkind: command_profile\nidentity: {canonical_name: arbitrary_paths}\nforms:\n  - id: selected\n    parameters:\n      - name: roots\n        semantic: {kind: path, role: read}\n        binding: {kind: remaining_positionals}\n        cardinality: optional_many\n    stream_contract: {stdin_mode: ignored, stdout_mode: path_list, stderr_mode: opaque}\n    stdout_records:\n      projection: {kind: paths, roots_slot: roots, default_root: '.', separator: nul}\n      required_modifiers: [nul]\nmodifiers:\n  - id: nul\n    matcher: {kind: any_flag, flags: ['--zero']}\n";
    let registry =
        ProfileRegistry::from_profiles(vec![load_command_profile_from_str(source).unwrap()])
            .unwrap();
    for (command, proven) in [
        ("arbitrary_paths --zero ./src", true),
        ("arbitrary_paths ./src", false),
        ("arbitrary_paths --zero \"$unknown\"", false),
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let ResolveInvocationArtifactResult::Resolved(r) =
            resolve_invocation_artifact_with_bindings(
                &registry,
                &parsed.commands[0],
                InvocationRuntimeContext::new(),
                &SessionBindings::new(),
            )
        else {
            panic!("{command}")
        };
        assert_eq!(r.proven_stdout_records().is_some(), proven, "{command}");
    }
    for invalid in [
        source.replace("roots_slot: roots", "roots_slot: typo"),
        source.replace("required_modifiers: [nul]", "required_modifiers: [typo]"),
        source.replace("separator: nul", "separator: newline"),
        source.replace("stdout_mode: path_list", "stdout_mode: data"),
        source.replace(
            "required_modifiers: [nul]",
            "required_modifiers: [nul]\n      excluded_modifiers: [nul]",
        ),
    ] {
        assert!(
            load_command_profile_from_str(&invalid).is_err(),
            "{invalid}"
        );
    }
}

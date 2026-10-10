use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;
const PROFILE: &str = include_str!("../profiles/sed.yaml");
fn resolve(command: &str) -> BoundInvocation {
    static R: OnceLock<ProfileRegistry> = OnceLock::new();
    resolve_with(
        R.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        command,
        &SessionBindings::new(),
    )
}
fn resolve_with(r: &ProfileRegistry, command: &str, bindings: &SessionBindings) -> BoundInvocation {
    let p = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        r,
        &p.commands[0],
        InvocationRuntimeContext::new(),
        bindings,
    ) {
        ResolveInvocationResult::Resolved(x) => x.bound,
        other => panic!("{command}: {other:?}"),
    }
}
fn parameter<'a>(b: &'a BoundInvocation, name: &str) -> &'a BoundParameter {
    b.bound_parameters
        .iter()
        .find(|p| p.name.as_str() == name)
        .unwrap()
}
fn values(b: &BoundInvocation, name: &str) -> Vec<SemanticValueResolution> {
    parameter(b, name)
        .semantic_values()
        .map(|v| match v {
            SemanticValueRef::Projected { value, .. } => value.resolution.clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}
fn known(s: &str) -> SemanticValueResolution {
    SemanticValueResolution::Known(s.into())
}
#[test]
fn ordinary_scripts_have_absent_embedded_effects_and_no_executable_candidates() {
    for command in [
        "sed 's/e/w/g' input",
        "sed -n '/e;w/p' input",
        "sed -e 's/a/b/' -e 'p' input",
        "sed 'a w /opt/file' input",
        "sed '' input",
        "sed \"s/^$//;t;p;\" input",
    ] {
        let b = resolve(command);
        assert!(b.residuals.is_empty(), "{command}: {b:?}");
        for name in [
            "script_reads",
            "script_writes",
            "script_deletes",
            "script_executions",
        ] {
            assert!(
                parameter(&b, name).semantic_values_are_inapplicable(),
                "{command}: {name}: {b:?}"
            );
        }
        assert!(collect_recursive_payload_candidates(&b).is_empty());
    }
}
#[test]
fn reads_and_writes_are_projected_with_their_real_script_origin() {
    let b = resolve("sed -e 'r /etc/hosts' --expression='s/a/b/w /opt/output' input");
    assert_eq!(values(&b, "script_reads"), [known("/etc/hosts")]);
    assert_eq!(values(&b, "script_writes"), [known("/opt/output")]);
    let p = parameter(&b, "script_writes");
    assert_eq!(p.values, parameter(&b, "scripts").values);
    assert_eq!(p.projected_values.as_ref().unwrap()[0].source_index, 1);
    assert!(collect_recursive_payload_candidates(&b).is_empty());
}
#[test]
fn filenames_are_tool_data_and_exact_outer_bindings_are_materialized_once() {
    let r = ProfileRegistry::built_in().unwrap();
    let mut bindings = SessionBindings::new();
    bindings.insert_exact_scalar("PROGRAM", "w $INNER/$(whoami) # data");
    bindings.insert_exact_scalar("INNER", "/etc");
    let b = resolve_with(&r, "sed \"$PROGRAM\" input", &bindings);
    assert_eq!(
        values(&b, "script_writes"),
        [known("$INNER/$(whoami) # data")]
    );
}
#[test]
fn e_and_substitution_e_and_file_scripts_are_opaque_not_fake_bash() {
    for command in [
        "sed e",
        "sed '1e exec /bin/sh' input",
        "sed 's/a/b/e' input",
        "sed -f script.sed input",
        "sed -f - input",
    ] {
        let b = resolve(command);
        let candidates = collect_recursive_payload_candidates(&b);
        assert!(!candidates.is_empty(), "{command}: {b:?}");
        assert!(
            candidates
                .iter()
                .all(|c| c.language == PayloadLanguage::Opaque)
        );
    }
}
#[test]
fn script_stdin_has_no_fake_dash_path_and_file_sources_keep_their_path() {
    let b = resolve("sed -f - -f program.sed input");
    assert_eq!(values(&b, "script_paths"), [known("program.sed")]);
    let paths = parameter(&b, "script_paths");
    let index = paths.projected_values.as_ref().unwrap()[0].source_index;
    // Structured projections retain only participating original values; their
    // source index is local to that view, not the unfiltered modifier slot.
    assert_eq!(
        &paths.values[index],
        &parameter(&b, "script_files").values[1]
    );
    assert!(!collect_recursive_payload_candidates(&b).is_empty());
    let b = resolve("sed -f - input");
    assert!(
        b.bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "script_paths")
            .is_none_or(|p| p.semantic_values_are_inapplicable())
    );
    assert!(!collect_recursive_payload_candidates(&b).is_empty());
}
#[test]
fn dynamic_malformed_and_over_budget_programs_keep_unknown_targets() {
    for command in ["sed \"$SCRIPT\" input", "sed 'w local\nunknown' input"] {
        let b = resolve(command);
        assert!(matches!(
            values(&b, "script_writes").as_slice(),
            [SemanticValueResolution::Unknown(_)]
        ));
        assert!(!collect_recursive_payload_candidates(&b).is_empty());
    }
    let p = load_command_profile_from_str(
        &PROFILE.replace("max_operations: 4096", "max_operations: 1"),
    )
    .unwrap();
    let r = ProfileRegistry::from_profiles(vec![p]).unwrap();
    let b = resolve_with(&r, "sed -e p -e p input", &SessionBindings::new());
    assert_eq!(
        values(&b, "script_writes"),
        [SemanticValueResolution::Unknown(
            ProjectionUnknownReason::PayloadBudgetExceeded
        )]
    );
}
#[test]
fn repeated_expressions_are_one_ordered_program_including_text_continuations() {
    let b = resolve("sed -e 'a\\' -e 'w /opt/output' input");
    assert!(values(&b, "script_writes").is_empty());
    let b = resolve("sed -e 'w /opt/one' -e 'W /opt/two' input");
    assert_eq!(
        values(&b, "script_writes"),
        [known("/opt/one"), known("/opt/two")]
    );
    let p = parameter(&b, "script_writes");
    assert_eq!(
        p.projected_values
            .as_ref()
            .unwrap()
            .iter()
            .map(|x| x.source_index)
            .collect::<Vec<_>>(),
        [0, 1]
    );
}
#[test]
fn projection_is_opt_in_and_not_selected_by_executable_name() {
    let p = load_command_profile_from_str(&PROFILE.replace(
        "canonical_name: sed",
        "canonical_name: arbitrary-transformer",
    ))
    .unwrap();
    let r = ProfileRegistry::from_profiles(vec![p]).unwrap();
    let b = resolve_with(
        &r,
        "arbitrary-transformer 'w /opt/out' input",
        &SessionBindings::new(),
    );
    assert_eq!(values(&b, "script_writes"), [known("/opt/out")]);
}
#[test]
fn declarations_cannot_drop_the_executable_boundary_or_collide_with_source() {
    load_command_profile_from_str(PROFILE).unwrap();
    for p in [
        PROFILE.replace("executions: script_executions", ""),
        PROFILE.replace("executions: script_executions", "executions: scripts"),
        PROFILE.replace(
            "kind: execute_payload, target: {kind: slot, name: script_executions}",
            "kind: read_path, target: {kind: slot, name: script_executions}",
        ),
        PROFILE.replace("max_operations: 4096", "max_operations: 0"),
    ] {
        assert!(load_command_profile_from_str(&p).is_err(), "{p}");
    }
}

#[test]
fn unknown_optional_write_controls_keep_the_real_control_origin_without_fake_execution() {
    let b = resolve("sed -i\"$SUFFIX\" 's/a/b/' input");
    let p = parameter(&b, "script_writes");
    assert!(matches!(
        values(&b, "script_writes").as_slice(),
        [SemanticValueResolution::Unknown(_)]
    ));
    let index = p.projected_values.as_ref().unwrap()[0].source_index;
    assert_eq!(&p.values[index], &parameter(&b, "backup_suffix").values[0]);
    assert!(collect_recursive_payload_candidates(&b).is_empty());
    for command in [
        "sed -i 's/a/b/' input",
        "sed -i.bak 's/a/b/' input",
        "sed -i'' 's/a/b/' input",
    ] {
        assert!(values(&resolve(command), "script_writes").is_empty());
    }
}

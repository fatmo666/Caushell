use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, CommandProfile, EffectKind, EffectTarget,
    InvocationRuntimeContext, PathAccessKind, StreamContract, StreamInputMode, StreamOutputMode,
    bind_invocation, load_command_profile_from_str, project_invocation, select_invocation,
};
use caushell_types::ShellKind;

fn profile() -> CommandProfile {
    load_command_profile_from_str(include_str!("../profiles/gzip.yaml")).unwrap()
}

fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let profile = profile();
    let selection = select_invocation(&profile, &projection)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    let bound = bind_invocation(&profile, &projection, &selection);
    assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
    bound
}

fn values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            _ => panic!("{v:?}"),
        })
        .collect()
}

fn has(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|e| e.kind == kind)
}

fn streams(bound: &BoundInvocation) -> StreamContract {
    profile()
        .forms
        .iter()
        .find(|f| f.id == bound.form_id)
        .unwrap()
        .stream_contract
        .unwrap()
}

#[test]
fn stdin_is_data_not_a_path_or_executable_payload() {
    for command in ["gzip", "gzip -", "gzip -d", "gzip -d -", "gzip -9 - -"] {
        let b = bind(command);
        assert!(values(&b, "input_paths").is_empty(), "{command}: {b:?}");
        assert!(!has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath));
        assert!(!has(&b, EffectKind::ExecutePayload));
        assert_eq!(streams(&b).stdin_mode, StreamInputMode::DataRequired);
        assert_eq!(streams(&b).stdout_mode, StreamOutputMode::Data);
    }
}

#[test]
fn stdout_modes_preserve_files_without_derived_outputs_or_deletions() {
    for command in [
        "gzip -c /opt/shared/input",
        "gzip -dc input.gz",
        "gzip input -c9",
        "gzip --to-stdout input",
        "gzip -cS.custom input",
        "gzip -c --suffix=.custom input",
    ] {
        let b = bind(command);
        assert!(has(&b, EffectKind::ReadPath) && has(&b, EffectKind::TransformData));
        assert!(!has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath));
        assert_eq!(streams(&b).stdin_mode, StreamInputMode::Ignored);
        assert_eq!(streams(&b).stdout_mode, StreamOutputMode::Data);
        assert_eq!(
            b.effects
                .iter()
                .find(|e| e.kind == EffectKind::ReadPath)
                .unwrap()
                .path_access,
            Some(PathAccessKind::ContentOpen)
        );
    }
}

#[test]
fn named_file_modes_preserve_possible_delete_and_keep_semantics() {
    for (command, delete) in [
        ("gzip input", true),
        ("gzip -k input", false),
        ("gzip -d input.gz", true),
        ("gzip -dk input.gz", false),
    ] {
        let b = bind(command);
        assert!(has(&b, EffectKind::WritePath));
        assert_eq!(has(&b, EffectKind::DeletePath), delete, "{command}: {b:?}");
        assert_eq!(streams(&b).stdin_mode, StreamInputMode::Ignored);
        assert_eq!(streams(&b).stdout_mode, StreamOutputMode::Opaque);
    }
}

#[test]
fn mixed_stdin_files_keep_both_stream_and_file_effects() {
    for command in [
        "gzip - input",
        "gzip input -",
        "gzip -k - input",
        "gzip -d input.gz -",
        "gzip -dk - input.gz",
        "gzip -r input -",
        "gzip -kr input -",
    ] {
        let b = bind(command);
        assert_eq!(values(&b, "input_paths").len(), 1, "{command}: {b:?}");
        assert!(has(&b, EffectKind::WritePath));
        assert_eq!(streams(&b).stdin_mode, StreamInputMode::DataRequired);
        assert_eq!(streams(&b).stdout_mode, StreamOutputMode::Data);
    }
    let b = bind("gzip -dc input.gz -");
    assert_eq!(values(&b, "input_paths"), ["input.gz"]);
    assert!(!has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath));
}

#[test]
fn inspection_and_information_do_not_claim_file_mutations() {
    for command in [
        "gzip -l input.gz",
        "gzip -t input.gz",
        "gzip -tl input.gz",
        "gzip -t",
        "gzip -l input.gz -",
    ] {
        let b = bind(command);
        assert_eq!(
            has(&b, EffectKind::ReadPath),
            !values(&b, "input_paths").is_empty()
        );
        assert!(!has(&b, EffectKind::WritePath) && !has(&b, EffectKind::DeletePath));
        assert!(!has(&b, EffectKind::TransformData));
        assert_eq!(streams(&b).stdout_mode, StreamOutputMode::Opaque);
    }
    for command in [
        "gzip --help /opt/shared/input",
        "gzip -V input",
        "gzip -L input",
        "gzip -hd input",
    ] {
        assert!(bind(command).effects.is_empty(), "{command}");
    }
}

#[test]
fn option_values_and_terminator_do_not_become_input_paths_or_modes() {
    for (command, expected) in [
        ("gzip -c -S .custom file", "file"),
        ("gzip -cS.custom file", "file"),
        ("gzip --suffix=.custom -c file", "file"),
        ("gzip -c -- -d", "-d"),
        ("gzip -- -c", "-c"),
        ("gzip './a\nb'", "./a\nb"),
    ] {
        assert_eq!(
            values(&bind(command), "input_paths"),
            [expected],
            "{command}"
        );
    }
    assert!(has(&bind("gzip -- -c"), EffectKind::WritePath));
}

#[test]
fn unsupported_output_choices_remain_explicitly_unknown() {
    for command in [
        "gzip -r folder",
        "gzip -S .custom input",
        "gzip -dN input.gz",
        "gzip -S.gz -S.custom input",
        "gzip --suffix=.gz -S.custom input",
        "gzip --suffix=.gz --suffix=.custom input",
    ] {
        let b = bind(command);
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None),
            "{command}: {b:?}"
        );
    }
    for command in [
        "gzip -k -r folder",
        "gzip -kS.custom input",
        "gzip -dkN input.gz",
    ] {
        assert!(!has(&bind(command), EffectKind::DeletePath), "{command}");
    }
    assert!(profile().opaque_on_unresolved);
}

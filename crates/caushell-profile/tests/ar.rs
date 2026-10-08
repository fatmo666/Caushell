use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, StreamInputMode, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::{ShellKind, StreamDataDependency};

fn bind(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::from_profiles(vec![
        load_command_profile_from_str(include_str!("../profiles/ar.yaml")).unwrap(),
    ])
    .unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let result = resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    );
    match result {
        ResolveInvocationResult::Resolved(r) => r.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{command}: {other:?}"),
    }
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("{v:?}"),
        })
        .collect()
}

#[test]
fn insertion_and_reading_have_different_real_file_effects() {
    for operation in ["r", "rcs", "rD", "q", "qs"] {
        let b = bind(&format!("ar {operation} ./stage.a /opt/shared/input"));
        assert!(
            !b.operation_semantics_unresolved && b.residuals.is_empty(),
            "{b:?}"
        );
        assert_eq!(values(&b, "archive_path"), ["./stage.a"]);
        assert_eq!(values(&b, "input_paths"), ["/opt/shared/input"]);
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::DeletePath));
        assert_eq!(
            b.stream_contract.unwrap().stdout_dependency,
            StreamDataDependency::Independent
        );
    }
    for operation in ["p", "pv", "t", "tv", "tO"] {
        let b = bind(&format!("ar {operation} ./stage.a /not/a/disk/read"));
        assert!(
            !b.operation_semantics_unresolved && b.residuals.is_empty(),
            "{b:?}"
        );
        assert_eq!(values(&b, "member_names"), ["/not/a/disk/read"]);
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        assert_eq!(
            b.stream_contract.unwrap().stdout_dependency,
            StreamDataDependency::Inputs
        );
    }
}

#[test]
fn member_removal_and_indexing_modify_archive_not_member_paths() {
    for command in ["ar d stage.a /opt/shared/member", "ar s stage.a"] {
        let b = bind(command);
        assert!(
            !b.operation_semantics_unresolved && b.residuals.is_empty(),
            "{b:?}"
        );
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::DeletePath));
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::Ignored
        );
    }
}

#[test]
fn options_and_information_are_not_archive_operands() {
    let b = bind("ar --target=binary r stage.a input");
    assert!(
        !b.operation_semantics_unresolved && b.residuals.is_empty(),
        "{b:?}"
    );
    assert_eq!(values(&b, "archive_path"), ["stage.a"]);
    for command in ["ar --help", "ar --version"] {
        assert!(bind(command).effects.is_empty());
    }
}

#[test]
fn response_files_and_dynamic_argv_keep_unknown_file_mutations() {
    for command in [
        "ar p @args",
        "ar p stage.a @member-list",
        "ar --help @args",
        "ar p \"$unknown\"",
        "ar p stage.a \"$unknown\"",
    ] {
        let b = bind(command);
        assert!(
            b.effects.iter().any(|e| e.kind == EffectKind::WritePath
                && matches!(e.target, caushell_profile::EffectTarget::None)),
            "{command}: {b:?}"
        );
    }
}

#[test]
fn unsupported_operations_and_plugins_are_not_silently_accepted() {
    let registry = ProfileRegistry::built_in().unwrap();
    assert!(registry.lookup("ar").profile.is_some());
    for command in [
        "ar x stage.a",
        "ar -M",
        "ar arbitrary stage.a",
        "ar r",
        "ar p --plugin=/opt/lib.so stage.a",
        "ar --help /opt/shared/input",
        "ar --help --version",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        match resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) {
            ResolveInvocationResult::Resolved(r) => assert!(
                r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty(),
                "{command}: {r:?}"
            ),
            ResolveInvocationResult::SelectionError { .. } => (),
            other => panic!("{command}: {other:?}"),
        }
    }
}

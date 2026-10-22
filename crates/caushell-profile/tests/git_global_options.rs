use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext, bind_invocation,
    load_command_profile_from_str, project_invocation, select_invocation,
};
use caushell_types::ShellKind;

fn bind(command: &str) -> Result<BoundInvocation, String> {
    let profile = load_command_profile_from_str(include_str!("../profiles/git.yaml")).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).map_err(|error| error.to_string())?;
    Ok(bind_invocation(&profile, &projection, &selection))
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn disabling_optional_locks_preserves_dispatch_and_directory_binding() {
    for command in [
        "git --no-optional-locks -C /bench/workspace/repo diff -- notes.txt",
        "git -C /bench/workspace/repo --no-optional-locks diff -- notes.txt",
    ] {
        let bound = bind(command).unwrap();
        assert_eq!(bound.subcommand_path, ["diff"]);
        assert_eq!(
            values(&bound, "working_directory"),
            ["/bench/workspace/repo"]
        );
        assert_eq!(values(&bound, "pathspecs"), ["notes.txt"]);
        assert!(bound.residuals.is_empty(), "{bound:?}");
        assert!(!bound.operation_semantics_unresolved, "{bound:?}");
        assert!(
            bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::ReadPath)
        );
        assert!(
            !bound
                .effects
                .iter()
                .any(|effect| effect.kind == EffectKind::WritePath)
        );
    }
}

#[test]
fn disabling_optional_locks_does_not_suppress_restore_effects() {
    let bound =
        bind("git --no-optional-locks -C /bench/workspace/repo restore -- notes.txt").unwrap();
    assert_eq!(bound.subcommand_path, ["restore"]);
    assert_eq!(values(&bound, "pathspecs"), ["notes.txt"]);
    assert!(
        bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );
    assert!(
        bound
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::RepositoryOperation)
    );
}

#[test]
fn undeclared_global_options_are_still_unresolved() {
    for command in [
        "git --unknown-option diff -- notes.txt",
        "git --no-optional-locks=value diff -- notes.txt",
    ] {
        assert!(bind(command).is_err(), "{command}");
    }
}

#[test]
fn identical_spelling_after_terminator_is_a_path() {
    let bound = bind("git --no-optional-locks diff -- --no-optional-locks").unwrap();
    assert_eq!(values(&bound, "pathspecs"), ["--no-optional-locks"]);
    assert!(bound.residuals.is_empty(), "{bound:?}");
}

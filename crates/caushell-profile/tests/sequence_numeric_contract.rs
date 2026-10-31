use caushell_profile::*;
use caushell_types::ShellKind;

#[test]
fn numeric_stdout_requires_complete_integer_default_format_grammar() {
    let registry = ProfileRegistry::built_in().unwrap();
    for (command, expected) in [
        ("seq 4", true),
        ("seq 2 4", true),
        ("seq 2 3 14", true),
        ("seq 1.5 3.5", false),
        ("seq 1e3 1e4", false),
        ("seq -f '%g' 2 4", false),
        ("seq -f 'a[%g]' 2 4", false),
        ("seq -s payload 2 4", false),
        ("seq --unknown 2 4", false),
        ("seq 1 2 3 4", false),
        ("seq 100000000000000000000", false),
    ] {
        let parsed = caushell_parse::parse_command(command, ShellKind::Bash).unwrap();
        let result = resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &SessionBindings::new(),
        );
        assert_eq!(
            matches!(result, ResolveInvocationArtifactResult::Resolved(r) if r.proven_arithmetic_stdout()),
            expected,
            "{command}"
        );
    }
}

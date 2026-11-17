use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
#[test]
fn quoted_and_escaped_names_have_identical_full_identity() {
    let registry = ProfileRegistry::built_in().unwrap();
    for source in [
        r"\ egrep abc",
        "' egrep' abc",
        "\\\tegrep abc",
        "'\tegrep' abc",
    ] {
        let p = parse_command(source, ShellKind::Bash).unwrap();
        let result = resolve_invocation(&registry, &p.commands[0], InvocationRuntimeContext::new());
        assert!(
            matches!(result, ResolveInvocationResult::NoProfile { .. }),
            "{source:?}: {result:?}"
        );
    }
    let p = parse_command(r"\egrep abc", ShellKind::Bash).unwrap();
    assert!(matches!(
        resolve_invocation(&registry, &p.commands[0], InvocationRuntimeContext::new()),
        ResolveInvocationResult::Resolved(_)
    ));
}
#[test]
fn wrapper_argv_and_scalar_parts_keep_escaped_prefixes() {
    let registry = ProfileRegistry::built_in().unwrap();
    let p = parse_command(r"env \ egrep abc", ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) =
        resolve_invocation(&registry, &p.commands[0], InvocationRuntimeContext::new())
    else {
        panic!()
    };
    assert_eq!(
        collect_dispatch_command_candidates(&r.bound)[0]
            .command
            .text,
        " egrep"
    );
    assert_eq!(
        materialize_command_name(r"\ 'egrep'", &SessionBindings::new()).as_deref(),
        Some(" egrep")
    );
}

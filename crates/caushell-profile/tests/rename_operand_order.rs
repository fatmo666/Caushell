//! Static Profile binding; no rename command executes.
use caushell_profile::*;

#[test]
fn sequential_operands_do_not_skip_the_replacement_and_consume_the_target() {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = caushell_parse::parse_command(
        "rename.ul foo bar /opt/shared/one /opt/shared/two",
        caushell_types::ShellKind::Bash,
    )
    .unwrap();
    let ResolveInvocationResult::Resolved(resolved) = resolve_invocation_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) else {
        panic!("expected resolved invocation");
    };
    for (slot, expected) in [(
        "argv",
        vec!["foo", "bar", "/opt/shared/one", "/opt/shared/two"],
    )] {
        let parameter = resolved
            .bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == slot)
            .unwrap();
        let texts: Vec<_> = parameter
            .values
            .iter()
            .map(|v| match v {
                BoundValue::Argument { text, .. } => text.as_str(),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(texts, expected, "{slot}");
    }
    // Neither file contains 'foo': these are proven identity transforms, not
    // a missing-target parse or a write to the replacement operand.
    for slot in ["rename_sources", "rename_destinations"] {
        assert!(
            resolved
                .bound
                .bound_parameters
                .iter()
                .find(|p| p.name.as_str() == slot)
                .unwrap()
                .semantic_values_are_inapplicable()
        );
    }
}

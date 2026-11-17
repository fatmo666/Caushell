use caushell_parse::parse_command;
use caushell_profile::{argument_structure, bind_invocation, load_command_profile_from_str,
    project_invocation, select_invocation, ArgumentFieldCount, InvocationRuntimeContext};
use caushell_types::ShellKind;

fn shape(word: &str) -> caushell_profile::ArgumentStructure {
    let parsed = parse_command(&format!("echo {word}"), ShellKind::Bash).unwrap();
    let argv = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    assert_eq!(argv.args.len(), 1, "{word}: {argv:?}");
    argument_structure(&argv.args[0])
}

#[test]
fn noninitial_tildes_are_literal_parts_of_pathname_patterns() {
    for word in ["*~", "?~", "[ab]~", "dir/*~", "prefix~*", "*~suffix"] {
        let s = shape(word);
        assert_eq!(s.fields, ArgumentFieldCount::ZeroOrMore, "{word}: {s:?}");
        assert!(!s.exact);
        for control in ["-exec", "-delete", "-files0-from", ";", "--"] {
            assert!(!s.may_equal(control), "{word} lost its literal tilde: {s:?}");
        }
    }
    assert_eq!(shape("*~").static_suffix, "~");
    assert!(shape("*~").may_equal("-delete~"));
    assert!(shape("*~").may_equal("ordinary~"));
}

#[test]
fn leading_assignment_brace_and_dynamic_tilde_contexts_are_not_blessed() {
    for word in ["~/*", "~someone/*", "{,prefix}~/*", "name=~/*", "PATH=x:~/*", "$unknown~", "$(pwd)~"] {
        let s = shape(word);
        assert_eq!(s.fields, ArgumentFieldCount::Unknown, "{word}: {s:?}");
        assert!(s.may_equal("-delete"), "{word}: {s:?}");
    }
}

#[test]
fn original_find_backup_pattern_retains_declared_operand_ownership() {
    let profile = load_command_profile_from_str(include_str!("../profiles/find.yaml")).unwrap();
    let command = r"find . -name .snapshot -prune -o \( \! -name *~ -print0 \)";
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let argv = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &argv).unwrap();
    let bound = bind_invocation(&profile, &argv, &selection);
    assert!(!bound.operation_semantics_unresolved, "{bound:#?}");
    assert!(bound.residuals.is_empty(), "{bound:#?}");
}

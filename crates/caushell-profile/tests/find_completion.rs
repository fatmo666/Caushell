//! Profile binding tests; the find commands below are never executed.
use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext, PathRole,
    SemanticType, StreamOutputMode, bind_invocation, load_command_profile_from_str,
    project_invocation, select_invocation,
};
use caushell_types::ShellKind;

fn bind(command: &str) -> BoundInvocation {
    let profile = load_command_profile_from_str(include_str!("../profiles/find.yaml")).unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    let bound = bind_invocation(&profile, &projection, &selection);
    assert!(bound.residuals.is_empty(), "{command}: {bound:?}");
    assert!(
        !bound.operation_semantics_unresolved,
        "{command}: {bound:?}"
    );
    bound
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|e| {
        e.kind == kind && matches!(&e.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}

#[test]
fn every_declared_numeric_test_owns_one_operand_including_negative_values() {
    for flag in [
        "-amin", "-atime", "-cmin", "-ctime", "-mmin", "-mtime", "-Bmin", "-Btime", "-size",
        "-inum", "-links", "-uid", "-gid", "-used",
    ] {
        for operand in ["+100", "-7", "0"] {
            let command = format!("find . {flag} {operand} -print");
            let bound = bind(&command);
            assert_eq!(values(&bound, "search_roots"), ["."], "{command}");
            assert_eq!(values(&bound, "numeric_tests"), [operand], "{command}");
            assert!(
                !bound
                    .effects
                    .iter()
                    .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
            );
        }
    }
}

#[test]
fn masks_owners_and_syntax_values_are_not_files_or_modifications() {
    for (flag, operand, slot) in [
        ("-perm", "-4000", "permission_tests"),
        ("-perm", "/u=x", "permission_tests"),
        ("-flags", "-nodump", "permission_tests"),
        ("-user", "alice", "owners"),
        ("-group", "staff", "owners"),
        ("-fstype", "nfs", "filesystem_types"),
        ("-regextype", "posix-extended", "regex_syntax"),
        ("-D", "tree,stat", "debug_categories"),
        ("-xtype", "l", "alternate_file_types"),
    ] {
        let command = format!("find . {flag} {operand} -print");
        let bound = bind(&command);
        assert_eq!(values(&bound, "search_roots"), ["."], "{command}");
        assert_eq!(values(&bound, slot), [operand], "{command}");
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
        );
    }
}

#[test]
fn literal_time_and_reference_file_comparisons_have_distinct_semantics() {
    for flag in ["-newerat", "-newerBt", "-newerct", "-newermt"] {
        let bound = bind(&format!("find . {flag} '2024-01-01 12:00' -print"));
        assert_eq!(values(&bound, "search_roots"), ["."]);
        assert_eq!(values(&bound, "reference_times"), ["2024-01-01 12:00"]);
        assert!(values(&bound, "reference_files").is_empty());
        assert!(!has_effect(&bound, EffectKind::ReadPath, "reference_times"));
    }
    for flag in [
        "-newer",
        "-anewer",
        "-cnewer",
        "-Bnewer",
        "-samefile",
        "-neweraa",
        "-neweraB",
        "-newerac",
        "-neweram",
        "-newerBa",
        "-newerBB",
        "-newerBc",
        "-newerBm",
        "-newerca",
        "-newercB",
        "-newercc",
        "-newercm",
        "-newerma",
        "-newermB",
        "-newermc",
        "-newermm",
    ] {
        let bound = bind(&format!("find . {flag} /opt/reference -print"));
        assert_eq!(values(&bound, "search_roots"), ["."]);
        assert_eq!(values(&bound, "reference_files"), ["/opt/reference"]);
        assert!(has_effect(&bound, EffectKind::ReadPath, "reference_files"));
        let parameter = bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "reference_files")
            .unwrap();
        assert!(matches!(&parameter.semantic, SemanticType::Path(p) if p.role == PathRole::Read));
    }
}

#[test]
fn output_files_keep_write_effects_even_under_a_false_expression() {
    for flag in ["-fprint", "-fprint0", "-fls"] {
        let bound = bind(&format!("find . -false {flag} /opt/output"));
        assert_eq!(values(&bound, "search_roots"), ["."]);
        assert_eq!(values(&bound, "output_paths"), ["/opt/output"]);
        assert!(has_effect(&bound, EffectKind::WritePath, "output_paths"));
        let parameter = bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "output_paths")
            .unwrap();
        assert!(matches!(&parameter.semantic, SemanticType::Path(p) if p.role == PathRole::Write));
    }
}

#[test]
fn repeated_file_outputs_are_all_retained_with_real_deletion() {
    let bound = bind("find /opt/shared -fprint first -fprint0 second -fls third -delete");
    assert_eq!(values(&bound, "search_roots"), ["/opt/shared"]);
    assert_eq!(values(&bound, "output_paths"), ["first", "second", "third"]);
    assert!(has_effect(&bound, EffectKind::WritePath, "output_paths"));
    assert!(has_effect(&bound, EffectKind::DeletePath, "search_roots"));
}

#[test]
fn formatted_stdout_is_data_not_a_traversal_bounded_path_list() {
    for command in [
        "find . -printf '/etc/passwd\\n'",
        "find . -ls",
        r"find . -printf '%p\n' -exec printf %s {} \;",
        r"find . -exec printf %s {} \; -ls",
    ] {
        let bound = bind(command);
        assert_eq!(values(&bound, "search_roots"), ["."]);
        assert_eq!(
            bound.stream_contract.unwrap().stdout_mode,
            StreamOutputMode::Data,
            "{command}"
        );
        assert_eq!(
            bound.argument_regions.len(),
            usize::from(command.contains("-exec"))
        );
    }
    for command in [
        "find . -print",
        "find . -print0",
        r"find . -exec echo {} \;",
    ] {
        let bound = bind(command);
        assert_eq!(
            bound.stream_contract.unwrap().stdout_mode,
            StreamOutputMode::PathList
        );
    }
}

#[test]
fn file_outputs_suppress_unconditional_nul_stdout_guarantees() {
    let registry = caushell_profile::ProfileRegistry::built_in().unwrap();
    for action in [
        "-fprint /dev/stdout",
        "-fprint0 /proc/self/fd/1",
        "-fls ./out",
        "-fprintf /dev/fd/1 '/etc/passwd\\0'",
        "-cpio ./out",
    ] {
        let parsed = parse_command(&format!("find . {action} -print0"), ShellKind::Bash).unwrap();
        let result = caushell_profile::resolve_invocation_artifact_with_bindings(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
            &caushell_profile::SessionBindings::new(),
        );
        let caushell_profile::ResolveInvocationArtifactResult::Resolved(r) = result else {
            panic!("{action}: {result:?}");
        };
        assert!(r.proven_stdout_records().is_none(), "{action}: {r:?}");
    }
}

#[test]
fn all_pattern_aliases_own_data_not_outer_flags() {
    for flag in [
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-regex",
        "-iregex",
        "-wholename",
        "-iwholename",
        "-lname",
        "-ilname",
        "-context",
    ] {
        for operand in ["-exec", "-delete", "/etc"] {
            let bound = bind(&format!("find . {flag} '{operand}' -print"));
            assert_eq!(values(&bound, "search_roots"), ["."]);
            assert_eq!(values(&bound, "patterns"), [operand]);
            assert!(bound.argument_regions.is_empty());
            assert!(!has_effect(&bound, EffectKind::DeletePath, "search_roots"));
        }
    }
}

#[test]
fn expression_operators_and_flag_only_options_are_not_search_roots() {
    let bound = bind(r"find . \( -mtime -7 -o -size +100M \) -a ! -perm /u=x , -print");
    assert_eq!(values(&bound, "search_roots"), ["."]);
    assert_eq!(values(&bound, "numeric_tests"), ["-7", "+100M"]);
    assert_eq!(values(&bound, "permission_tests"), ["/u=x"]);
    for flag in [
        "-acl",
        "-sparse",
        "-nouser",
        "-nogroup",
        "-daystart",
        "-noleaf",
        "-ignore_readdir_race",
        "-noignore_readdir_race",
        "-warn",
        "-nowarn",
        "-O0",
        "-O1",
        "-O2",
        "-O3",
        "-E",
        "-X",
        "-s",
        "-d",
        "-x",
        "-help",
        "--help",
        "-version",
        "--version",
    ] {
        let bound = bind(&format!("find . {flag} -print"));
        assert_eq!(values(&bound, "search_roots"), ["."], "{flag}");
    }
}

#[test]
fn unsupported_bsd_flag_roots_never_claim_incomplete_mixed_domains() {
    let profile = load_command_profile_from_str(include_str!("../profiles/find.yaml")).unwrap();
    for command in [
        "find -f /opt/shared -print",
        r"find -f /opt/shared -exec rm {} \;",
        "find . -f /opt/shared -delete",
        "find . -f /opt/shared -f . -delete",
        r"find . -f /opt/shared -f . -exec rm {} \;",
        "find -f '-exec' -f '-delete' -print",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(&profile, &projection).is_err(),
            "{command}"
        );
    }
}

#[test]
fn predicate_and_output_operands_cannot_create_fake_regions_or_actions() {
    for (flag, slot) in [
        ("-printf", "output_formats"),
        ("-fprint", "output_paths"),
        ("-newer", "reference_files"),
        ("-newermt", "reference_times"),
        ("-user", "owners"),
        ("-regextype", "regex_syntax"),
    ] {
        let bound = bind(&format!("find . {flag} '-exec' -print"));
        assert_eq!(values(&bound, slot), ["-exec"]);
        assert_eq!(values(&bound, "search_roots"), ["."]);
        assert!(bound.argument_regions.is_empty());
        assert!(!has_effect(&bound, EffectKind::DeletePath, "search_roots"));
    }
}

#[test]
fn predicates_between_children_keep_both_children_and_only_real_effects() {
    let bound = bind(
        r"find /opt/shared -mtime -7 -exec printf %s -mtime -delete -fprint /etc/noise \; -perm /u=x -size +100M -exec rm {} + -fprint ./results",
    );
    assert_eq!(values(&bound, "search_roots"), ["/opt/shared"]);
    assert_eq!(values(&bound, "numeric_tests"), ["-7", "+100M"]);
    assert_eq!(values(&bound, "permission_tests"), ["/u=x"]);
    assert_eq!(values(&bound, "output_paths"), ["./results"]);
    assert_eq!(values(&bound, "exec_command"), ["printf", "rm"]);
    assert_eq!(bound.argument_regions.len(), 2);
    assert!(has_effect(&bound, EffectKind::WritePath, "output_paths"));
    assert!(!has_effect(&bound, EffectKind::DeletePath, "search_roots"));
}

#[test]
fn every_required_option_operand_is_checked_at_each_occurrence() {
    let profile = load_command_profile_from_str(include_str!("../profiles/find.yaml")).unwrap();
    for flag in [
        "-mtime",
        "-size",
        "-perm",
        "-user",
        "-group",
        "-newer",
        "-newermt",
        "-regextype",
        "-fstype",
        "-printf",
        "-fprint",
        "-fprint0",
        "-fls",
        "-xtype",
        "-D",
    ] {
        for command in [
            format!("find . {flag}"),
            format!("find . {flag} first {flag}"),
        ] {
            let parsed = parse_command(&command, ShellKind::Bash).unwrap();
            let projection =
                project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
            assert!(
                select_invocation(&profile, &projection).is_err(),
                "{command}"
            );
        }
    }
}

#[test]
fn deliberately_unmodeled_forms_remain_explicitly_unresolved() {
    let profile = load_command_profile_from_str(include_str!("../profiles/find.yaml")).unwrap();
    for command in [
        "find -files0-from roots -delete",
        "find . -unsupported",
        "find -O4 . -print",
        "find . -newertt yesterday -print",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
        assert!(
            select_invocation(&profile, &projection).is_err(),
            "{command}"
        );
    }
}

#[test]
fn two_operand_output_binding_is_command_independent_and_preserves_each_file() {
    let profile = load_command_profile_from_str(
        &include_str!("../profiles/find.yaml")
            .replace("canonical_name: find", "canonical_name: probe"),
    )
    .unwrap();
    let parsed = parse_command(
        "probe . -fprintf first '-delete' -fprintf second '-exec' -print",
        ShellKind::Bash,
    )
    .unwrap();
    let projection = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selection = select_invocation(&profile, &projection).unwrap();
    let bound = bind_invocation(&profile, &projection, &selection);
    assert!(!bound.operation_semantics_unresolved, "{bound:?}");
    assert_eq!(
        values(&bound, "formatted_output_paths"),
        ["first", "second"]
    );
    assert_eq!(values(&bound, "search_roots"), ["."]);
    assert!(bound.argument_regions.is_empty());
    assert!(!has_effect(&bound, EffectKind::DeletePath, "search_roots"));
}

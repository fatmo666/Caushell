//! Extra-Opts loads tool configuration; file bytes are not a complete argv proof.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

const TOOLS: [&str; 3] = ["check_cups", "check_memory", "check_raid"];

fn resolve(registry: &ProfileRegistry, command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let ResolveInvocationResult::Resolved(r) = resolve_invocation(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) else {
        panic!("expected an explicit Extra-Opts file form: {command}")
    };
    r.bound
}

fn paths(bound: &BoundInvocation) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == "options_file")
        .flat_map(|p| p.semantic_values())
        .map(|v| match v {
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(path) => path.clone(),
                other => panic!("expected known configuration filename: {other:?}"),
            },
            other => panic!("expected a structured config path: {other:?}"),
        })
        .collect()
}

#[test]
fn explicit_ini_inputs_are_configuration_and_keep_unknown_option_effects() {
    let registry = ProfileRegistry::built_in().unwrap();
    for tool in TOOLS {
        let bound = resolve(
            &registry,
            &format!("{tool} --extra-opts=@/work/options.ini"),
        );
        assert!(bound.operation_semantics_unresolved, "{tool}");
        assert_eq!(paths(&bound), ["/work/options.ini"]);
        let input = bound
            .bound_parameters
            .iter()
            .find(|p| p.name.as_str() == "options_file")
            .unwrap();
        assert!(
            matches!(&input.semantic, SemanticType::Path(p) if p.purpose == Some(PathPurpose::ToolConfig))
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadConfig
                    && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == "options_file")),
            "{tool}"
        );
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert!(bound.effects.iter().all(|e| !matches!(
            e.kind,
            EffectKind::ExecutePayload | EffectKind::SourceScriptIntoCurrentShell
        )));
    }
}

#[test]
fn explicit_sections_paths_and_all_repeated_files_keep_native_ownership() {
    let registry = ProfileRegistry::built_in().unwrap();
    for tool in TOOLS {
        for (tail, expected) in [
            (
                "--extra-opts=custom@/work/options.ini",
                vec!["/work/options.ini"],
            ),
            ("--extra-opts @relative.ini", vec!["relative.ini"]),
            (
                "--extra-opts=@first.ini --extra-opts=other@second.ini",
                vec!["first.ini", "second.ini"],
            ),
            (
                "--extra-opts='custom@ file with spaces.ini  '",
                vec![" file with spaces.ini"],
            ),
            ("--extra-opts='@literal@name.ini'", vec!["literal@name.ini"]),
        ] {
            let bound = resolve(&registry, &format!("{tool} {tail}"));
            assert_eq!(paths(&bound), expected, "{tool} {tail}");
            assert!(bound.operation_semantics_unresolved);
        }
    }
}

#[test]
fn help_does_not_erase_the_configuration_read_that_precedes_it() {
    let registry = ProfileRegistry::built_in().unwrap();
    for tool in TOOLS {
        for command in [
            format!("{tool} --help --extra-opts=@options.ini"),
            format!("{tool} --extra-opts=@options.ini --version"),
        ] {
            let bound = resolve(&registry, &command);
            assert_eq!(paths(&bound), ["options.ini"]);
            assert!(bound.operation_semantics_unresolved);
            assert!(
                bound
                    .effects
                    .iter()
                    .any(|e| e.kind == EffectKind::LoadConfig)
            );
        }
    }
}

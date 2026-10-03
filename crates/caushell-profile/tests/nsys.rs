use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => {
            assert!(
                resolved.bound.residuals.is_empty(),
                "{command}: {:?}",
                resolved.bound.residuals
            );
            resolved.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn semantic_values(bound: &BoundInvocation, slot: &str) -> Vec<SemanticValueResolution> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| p.semantic_values())
        .map(|v| match v {
            SemanticValueRef::Projected { value, .. } => value.resolution.clone(),
            SemanticValueRef::Original(value) => {
                project_value(&ValueProjection::Identity, value).unwrap()
            }
        })
        .collect()
}

#[test]
fn mixed_outputs_are_projected_without_rewriting_the_source_operand() {
    let bound = resolve("nsys stats --output='-,result,@rm -f /opt/example,.' report.sqlite");
    assert_eq!(
        semantic_values(&bound, "report_bases"),
        [SemanticValueResolution::Known("result".into())]
    );
    assert_eq!(
        semantic_values(&bound, "default_report_outputs"),
        [SemanticValueResolution::Known("report.sqlite".into())]
    );
    let original = bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "output")
        .unwrap();
    assert_eq!(original.values.len(), 1);
    assert!(original.projected_values.is_none());
    let projection = collect_dispatch_command_projection(&bound);
    assert!(projection.unresolved.is_empty());
    assert_eq!(projection.resolved.len(), 1);
    let child = &projection.resolved[0];
    assert_eq!(child.command.text, "rm");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["-f", "/opt/example"]
    );
    assert!(child.stdin_from_parent);
    assert!(child.argv.iter().all(|a| a.runtime_data));
}

#[test]
fn encoded_argv_does_not_become_shell_source() {
    let bound = resolve("nsys stats -o '@echo $TOKEN ; rm -f /opt/example >out' report.sqlite");
    let child = collect_dispatch_command_candidates(&bound).remove(0);
    assert_eq!(child.command.text, "echo");
    assert_eq!(
        child
            .argv
            .iter()
            .map(|a| a.text.as_str())
            .collect::<Vec<_>>(),
        ["$TOKEN", ";", "rm", "-f", "/opt/example", ">out"]
    );
    assert!(
        child
            .to_command_fact()
            .tokens
            .iter()
            .all(|t| t.runtime_data && t.command_substitutions.is_empty())
    );
}

#[test]
fn multiple_outputs_and_commands_get_distinct_dispatch_identities() {
    let bound =
        resolve("nsys analyze -o '@echo one,@cat,-' --output='@rm -f /opt/example' report.sqlite");
    let projection = collect_dispatch_command_projection(&bound);
    assert_eq!(
        projection
            .resolved
            .iter()
            .map(|c| (c.dispatch_index, c.command.text.as_str()))
            .collect::<Vec<_>>(),
        [(0, "echo"), (1, "cat"), (2, "rm")]
    );
}

#[test]
fn dynamic_output_retains_unknown_file_and_command_candidates() {
    for command in [
        "nsys stats -o \"$OUTPUT\" report.sqlite",
        "nsys stats -o \"@echo $ARG\" report.sqlite",
        "nsys stats -o '@' report.sqlite",
        "nsys stats -o 'result,,@cat' report.sqlite",
    ] {
        let bound = resolve(command);
        assert!(
            !collect_dispatch_command_projection(&bound)
                .unresolved
                .is_empty(),
            "{command}"
        );
    }
}

#[test]
fn default_output_uses_the_first_present_source_not_an_unknown_fallback() {
    let bound = resolve("nsys stats --sqlite=/opt/a.sqlite -o . report.nsys-rep");
    assert_eq!(
        semantic_values(&bound, "default_report_outputs"),
        [SemanticValueResolution::Known("/opt/a.sqlite".into())]
    );
    let bound = resolve("nsys stats --sqlite=\"$SQLITE\" -o . report.nsys-rep");
    assert!(matches!(
        semantic_values(&bound, "default_report_outputs")[0],
        SemanticValueResolution::Unknown(_)
    ));
}

#[test]
fn stdout_does_not_drop_parent_sqlite_preparation() {
    let bound = resolve("nsys stats -o - /opt/report.nsys-rep");
    assert!(
        bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    assert!(
        collect_dispatch_command_projection(&bound)
            .resolved
            .is_empty()
    );
    let bound = resolve("nsys stats -o - report.sqlite");
    assert!(
        !bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn help_suppresses_modifier_execution_and_writes() {
    let bound = resolve("nsys stats --help -o '@rm -f /opt/example' --sqlite /opt/a.sqlite");
    assert!(bound.effects.is_empty());
    assert!(
        collect_dispatch_command_projection(&bound)
            .resolved
            .is_empty()
    );
}

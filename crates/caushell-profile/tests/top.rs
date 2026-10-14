//! Native mode binding; supplied shell commands are not executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => {
            assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
            r.bound
        }
        other => panic!("{command}: {other:#?}"),
    }
}
fn values<'a>(b: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}
#[test]
fn linux_batch_clusters_and_long_options_preserve_mode_and_operands() {
    for c in [
        "top -b",
        "top -bn1",
        "top -b -n1",
        "top -bHn2",
        "top -b -n 1 -d 0.5 -p 123 -o %CPU",
        "top --batch-mode --iterations=1 --delay=0.5 --pid=123",
        "top --batch -w120 -E k",
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), "batch", "{c}");
        assert!(b.effects.is_empty());
    }
    assert_eq!(values(&resolve("top -bn1"), "count"), ["1"]);
}
#[test]
fn darwin_logging_owns_complete_words_without_short_prefix_collisions() {
    for c in [
        "top -l 1",
        "top -l1",
        "top -l0",
        "top -l 1 -s 0 -stats mem -pid 8631",
        "top -l 1 -s 0 -i 1 -stats vprvt -pid 8631",
        "top -l1 -ncols 100 -user alice -n10 -o cpu -O time",
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), "logging", "{c}");
        assert!(b.effects.is_empty());
    }
    let b = resolve("top -l1 -stats mem -pid 8631 -user alice -ncols 100");
    assert_eq!(values(&b, "stats"), ["mem"]);
    assert_eq!(values(&b, "darwin_processes"), ["8631"]);
    assert_eq!(values(&b, "darwin_user"), ["alice"]);
    assert_eq!(values(&b, "columns"), ["100"]);
    assert!(values(&b, "display_values").is_empty());
    assert!(values(&b, "processes").is_empty());
    assert!(values(&b, "count").is_empty());
}
#[test]
fn refresh_counts_and_mode_looking_option_values_are_not_noninteraction_proofs() {
    for c in [
        "top",
        "top -n1",
        "top -n 1",
        "top -o -b",
        "top -pid -l",
        "top -n -b",
        "top -l1 -L",
        "top -L -l1",
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), "interactive", "{c}");
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
    }
}
#[test]
fn help_and_version_do_not_open_interactive_surfaces() {
    for c in [
        "top -h",
        "top --help",
        "top -V",
        "top --version",
        "top --list-fields",
        "top -h -l",
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), "information");
        assert!(b.effects.is_empty());
    }
}

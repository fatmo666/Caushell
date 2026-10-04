use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(b),
            ..
        } => b,
        other => panic!("{command}: {other:?}"),
    }
}
fn clean(command: &str) -> BoundInvocation {
    let b = resolve(command);
    assert!(b.residuals.is_empty(), "{command}: {b:?}");
    assert!(!b.operation_semantics_unresolved, "{command}: {b:?}");
    b
}
fn values<'a>(b: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{other:?}"),
        })
        .collect()
}
#[test]
fn registered_profile_is_declarative_and_accounts_for_unknown_operations() {
    let registry = ProfileRegistry::built_in().unwrap();
    let p = registry.lookup("/usr/bin/pv").profile.unwrap();
    assert!(p.opaque_on_unresolved);
    assert_eq!(p.option_scope, OptionScopePolicy::PermutedOptions);
}
#[test]
fn common_display_and_transfer_options_bind_separate_inline_and_clustered_values() {
    for c in [
        "pv",
        "pv -ptebar input.bin",
        "pv -q -L 1M input.bin",
        "pv -qL1M input.bin",
        "pv --rate-limit=1M --buffer-size=4096 input.bin",
        "pv input.bin --output out.bin",
        "pv -A 16 -D 0.5 -i 0.1 -w 80 -H 25 -N input -u plain -F '%b' -x process input.bin",
        "pv -EE -Z 4K -J 64K -m 30 -s @input.bin -W -g -l -0 -8 -k -9 -v -Y -K -O -X input.bin",
    ] {
        clean(c);
    }
}
#[test]
fn stdin_sentinels_do_not_create_dash_file_reads_and_file_only_calls_do_not_consume_stdin() {
    let files = clean("pv one.bin two.bin");
    assert_eq!(values(&files, "input_files"), ["one.bin", "two.bin"]);
    assert!(
        !files
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ConsumeStdin)
    );
    for c in ["pv", "pv -", "pv one.bin - two.bin"] {
        let b = clean(c);
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ConsumeStdin));
        assert!(!values(&b, "input_files").contains(&"-"));
    }
}
#[test]
fn stdout_and_store_and_forward_dash_have_different_effects() {
    let b = clean("pv -o - input.bin");
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    let b = clean("pv -U - -o - input.bin");
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None)
    );
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath && e.target == EffectTarget::None)
    );
    assert!(values(&b, "stage_files").is_empty());
}
#[test]
fn explicit_output_staging_and_pid_files_keep_independent_mutation_candidates() {
    let b = clean("pv -o out.bin -U stage.bin -P run.pid input.bin");
    assert_eq!(values(&b, "output_files"), ["out.bin"]);
    assert_eq!(values(&b, "stage_files"), ["stage.bin"]);
    assert_eq!(values(&b, "pidfile"), ["run.pid"]);
    for kind in [
        EffectKind::ReadPath,
        EffectKind::WritePath,
        EffectKind::DeletePath,
    ] {
        assert!(b.effects.iter().any(|e| e.kind == kind));
    }
    let b = clean("pv -o /etc/a --output=b -U /etc/stage --store-and-forward=local input.bin");
    assert_eq!(values(&b, "output_files"), ["/etc/a", "b"]);
    assert_eq!(values(&b, "stage_files"), ["/etc/stage", "local"]);
}
#[test]
fn file_size_metadata_is_not_promoted_to_content_read() {
    let b = clean("pv -s @.env public.bin");
    assert_eq!(values(&b, "size"), ["@.env"]);
    assert_eq!(values(&b, "input_files"), ["public.bin"]);
}
#[test]
fn watchfd_numeric_targets_are_metadata_not_control_or_input_file_paths() {
    let b = clean("pv -d 123:3 456:4");
    assert!(b.effects.is_empty());
    assert_eq!(values(&b, "watched_processes"), ["123:3"]);
    assert_eq!(values(&b, "watched_processes_extra"), ["456:4"]);
}
#[test]
fn remote_query_unknown_and_unmodeled_watch_forms_stay_opaque() {
    for c in [
        "pv -R 123 -L 10",
        "pv -nR123 -L10",
        "pv --remote=123 --rate-limit=10",
        "pv -Q 123",
        "pv --query=123",
        "pv -d =python",
        "pv -d @processes.txt",
        "pv --future input.bin",
        "pv -o",
        "pv -U",
        "pv -P",
        "pv -M both",
        "pv -M other -- true",
        "pv -M both true",
    ] {
        assert!(
            resolve(c).operation_semantics_unresolved,
            "{c}: {:?}",
            resolve(c)
        );
    }
}
#[test]
fn monitor_owns_only_pv_options_and_dispatches_exact_child_argv() {
    for side in ["in", "out", "both", "stdin", "stdout", "0", "1", "2"] {
        let c = format!("pv -M {side} -- rm -f /etc/example");
        let b = clean(&c);
        assert_eq!(values(&b, "monitored_command"), ["rm"]);
        assert_eq!(values(&b, "monitored_args"), ["-f", "/etc/example"]);
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::DispatchCommand)
        );
        assert!(values(&b, "input_files").is_empty());
        assert!(!b.applied_modifiers.iter().any(|m| m.as_str() == "switches"));
    }
}
#[test]
fn consumed_markers_and_mode_combinations_are_not_certified_as_plain_transfer() {
    for c in [
        "pv -o -- -R 123 -L 10",
        "pv -F -- -R 123 -L 10",
        "pv -U -- -R 123",
        "pv -P -- -R 123",
        "pv -M both -U file -- true",
        "pv -M both -d 123 -- true",
        "pv -M both -M out -- true",
    ] {
        assert!(
            resolve(c).operation_semantics_unresolved,
            "{c}: {:?}",
            resolve(c)
        );
    }
}
#[test]
fn literal_child_options_and_file_operands_after_terminator_are_not_pv_controls() {
    let b = clean("pv -- -R -U -o");
    assert_eq!(values(&b, "input_files"), ["-R", "-U", "-o"]);
    let b = clean("pv -M both -- echo --remote=123 -U -");
    assert_eq!(values(&b, "monitored_args"), ["--remote=123", "-U", "-"]);
}
#[test]
fn information_early_exit_suppresses_output_effects_but_retains_unknown_accounting() {
    assert!(
        clean("pv -o /etc/out -P /etc/pid --help")
            .effects
            .is_empty()
    );
    assert!(clean("pv --version").effects.is_empty());
    assert!(resolve("pv --future --help").operation_semantics_unresolved);
}

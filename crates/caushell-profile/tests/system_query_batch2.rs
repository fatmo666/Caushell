use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
fn attempt(command: &str, domain: CommandLookupDomain) -> ResolveInvocationArtifactResult {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation_in_lookup_domain_with_stdout_proofs(
        &ProfileRegistry::built_in().unwrap(), &parsed.commands[0],
        InvocationRuntimeContext::new().with_shell_kind(ShellKind::Bash), &SessionBindings::new(), &domain, &[],
    ).into_artifact()
}
fn resolved(command: &str) -> ResolvedInvocationArtifact {
    match attempt(command, CommandLookupDomain::Shell) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
#[test]
fn queries_have_explicit_finite_native_modes_without_argv_or_output_shape_grants() {
    for command in ["umask", "umask -Sp", "ulimit -n", "ulimit -a", "ulimit -HSn",
                    "lsmem", "lsmem --json -o RANGE,SIZE", "lsblk", "lsblk -o NAME,SIZE",
                    "lshw -class cpu", "lshw -short -sanitize", "kldstat", "kldstat -m vmm", "kextstat", "kextstat -b com.apple.kernel"] {
        let r=resolved(command);
        assert!(!r.bound.operation_semantics_unresolved && r.bound.residuals.is_empty(), "{command}: {r:#?}");
        assert!(r.bound.native_argv_effect_envelope.is_none());
        assert!(r.bound.stdout_records.is_none() && r.bound.stdout_scalar.is_none());
        assert!(!r.bound.effects.iter().any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::ExecutePayload | EffectKind::DispatchCommand)));
    }
}
#[test]
fn builtin_query_contracts_are_unavailable_to_external_dispatch() {
    for text in ["umask", "ulimit -n"] {
        assert!(matches!(attempt(text,CommandLookupDomain::Builtin),ResolveInvocationArtifactResult::Resolved(_)));
        assert!(matches!(attempt(text,CommandLookupDomain::External),ResolveInvocationArtifactResult::NoProfile { .. }));
    }
}
#[test]
fn mutating_unknown_or_helper_modes_do_not_inherit_the_query_contract() {
    for text in ["umask 000", "ulimit -n unlimited", "getconf -v POSIX_V7_LP64_OFF64 LONG_BIT", "lshw -X",
                 "lshw -enable isapnp", "lsmem --sysroot=/outside/root", "lsblk --sysroot=/outside/root",
                 "lsmem $OPTIONS", "lsblk $OPTIONS", "kextstat $OPTIONS", "kldstat -load module", "getconf $OPTIONS"] {
        if let ResolveInvocationArtifactResult::Resolved(r)=attempt(text,CommandLookupDomain::Shell) {
            assert!(r.bound.operation_semantics_unresolved || !r.bound.residuals.is_empty(), "{text}: {r:#?}");
            assert!(r.bound.native_argv_effect_envelope.is_none());
        }
    }
}
#[test]
fn dump_output_is_a_real_write() {
    let r=resolved("lshw -dump report.db");
    assert!(r.bound.effects.iter().any(|e|e.kind==EffectKind::WritePath));

}

#[test]
fn sqlite_uri_dump_values_retain_writes_and_an_unresolved_grammar_gap() {
    for command in ["lshw -dump file:/etc/report.db", "lshw -dump :memory:"] {
        let r=resolved(command);
        assert!(r.bound.operation_semantics_unresolved && !r.bound.residuals.is_empty(), "{r:#?}");
        assert!(r.bound.effects.iter().any(|e|e.kind==EffectKind::WritePath));
    }
    assert!(!resolved("lshw -dump ./file:literal.db").bound.operation_semantics_unresolved);
}

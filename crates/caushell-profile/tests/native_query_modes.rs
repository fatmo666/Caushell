use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, EffectKind, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, resolve_invocation,
};
use caushell_types::ShellKind;

fn resolved(registry: &ProfileRegistry, source: &str) -> BoundInvocation {
    let parsed = parse_command(source, ShellKind::Bash).unwrap();
    match resolve_invocation(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(result) => result.bound,
        other => panic!("{source}: {other:#?}"),
    }
}

#[test]
fn information_options_are_owned_options_and_do_not_start_recording() {
    let registry = ProfileRegistry::built_in().unwrap();
    for source in [
        "script --help",
        "script -h",
        "script --version",
        "script -V",
        "script --help -c 'rm -rf /' -O /outside/log",
        "script -I /outside/log --version",
    ] {
        let bound = resolved(&registry, source);
        assert_eq!(bound.form_id.as_str(), "information", "{source}");
        assert!(bound.effects.is_empty(), "{source}: {bound:#?}");
        assert!(
            caushell_profile::collect_recursive_payload_candidates(&bound).is_empty(),
            "{source}: {bound:#?}"
        );
    }
    for source in ["script -c '--help' recording", "script -- --help"] {
        let bound = resolved(&registry, source);
        assert_ne!(bound.form_id.as_str(), "information");
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
    }
    // Without a native dialect proof, a later --help may be a child argument.
    let parsed = parse_command("script /outside/log --help", ShellKind::Bash).unwrap();
    assert!(
        !matches!(resolve_invocation(&registry, &parsed.commands[0], InvocationRuntimeContext::new()), ResolveInvocationResult::Resolved(r) if r.bound.form_id.as_str() == "information")
    );
}

#[test]
fn package_file_lists_are_database_queries_with_a_separate_pager_surface() {
    let registry = ProfileRegistry::built_in().unwrap();
    for flag in ["-L", "--listfiles"] {
        let bound = resolved(
            &registry,
            &format!("dpkg {flag} arbitrary-package:amd64 another-package"),
        );
        assert_eq!(bound.form_id.as_str(), "installed_file_listing");
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
        assert!(!bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::WritePath
                | EffectKind::ImportPackage
                | EffectKind::ExecuteImportedPackageLogic
        )));
        let plain = resolved(
            &registry,
            &format!("dpkg --no-pager {flag} arbitrary-package"),
        );
        assert!(
            !plain
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::OpenInteractiveEscapeSurface)
        );
        assert!(
            plain
                .bound_parameters
                .iter()
                .any(|p| p.name.as_str() == "packages"
                    && matches!(p.semantic, caushell_profile::SemanticType::PlainValue))
        );
    }
}

#[test]
fn git_query_flags_preserve_remote_effects_and_local_metadata_reads() {
    let registry = ProfileRegistry::built_in().unwrap();
    for flag in ["--tags", "-t", "--heads", "-h", "--refs", "--symref"] {
        let bound = resolved(
            &registry,
            &format!("git ls-remote {flag} https://example.test/arbitrary.git 'v*'"),
        );
        assert_eq!(bound.form_id.as_str(), "inspect_remote_refs");
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::NetworkEndpoint)
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadConfig)
        );
    }
    for source in [
        "git describe --tags",
        "git describe --all --always HEAD",
        "git describe --match 'release-*' --exclude '*-rc' --abbrev=12 --dirty=+local",
    ] {
        let bound = resolved(&registry, source);
        assert_eq!(bound.form_id.as_str(), "describe_revision");
        assert!(bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath)
        );
    }
    let parsed = parse_command(
        "git grep -h --open-files-in-pager=sh needle",
        ShellKind::Bash,
    )
    .unwrap();
    assert!(
        !matches!(resolve_invocation(&registry, &parsed.commands[0], InvocationRuntimeContext::new()), ResolveInvocationResult::Resolved(r) if r.bound.form_id.as_str() == "short_help_information")
    );
}

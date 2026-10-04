//! Native CLI contracts; submitted package/service commands never execute.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn result(command: &str) -> ResolveInvocationResult<'static> {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation(
        REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap()),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
}
fn resolve(command: &str) -> BoundInvocation {
    match result(command) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(r.bound.residuals.is_empty(), "{command}: {:?}", r.bound);
            assert!(!r.bound.operation_semantics_unresolved, "{command}");
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}
fn values(b: &BoundInvocation, slot: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}
fn opaque(command: &str) {
    match result(command) {
        ResolveInvocationResult::Resolved(r) => assert!(
            r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound
        ),
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(b),
            ..
        } => assert!(b.operation_semantics_unresolved, "{command}"),
        other => panic!("{command}: {other:?}"),
    }
}
fn unknown_mutation(b: &BoundInvocation, kind: EffectKind) -> bool {
    b.effects.iter().any(|e| e.kind == kind && matches!(&e.target,
        EffectTarget::ConfiguredPath(p) if p.sources.is_empty() && p.environment.is_none() && p.default_value.is_none() && p.missing == ConfiguredPathMissing::Unknown))
}

#[test]
fn registers_native_brew_with_exact_options_and_opt_in_opacity() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in [
        "brew",
        "/opt/homebrew/bin/brew",
        "/home/linuxbrew/.linuxbrew/bin/brew",
    ] {
        let p = registry.lookup(name).profile.unwrap();
        assert_eq!(p.primary_name(), "brew");
        assert_eq!(
            p.identity
                .aliases
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>(),
            ["/home/linuxbrew/.linuxbrew/bin/brew"]
        );
        assert_eq!(p.option_matching, OptionMatchingPolicy::ExactNames);
        assert_eq!(p.option_scope, OptionScopePolicy::LeadingOptions);
        assert!(p.opaque_on_unresolved);
    }
}

#[test]
fn ordinary_queries_have_no_installation_or_deletion_effects() {
    for c in [
        "brew list",
        "brew ls --versions",
        "brew list --cask --versions",
        "brew info curl",
        "brew abv --json=v2 curl",
        "brew info --json curl",
        "brew search '/ssh.*/'",
        "brew search --desc ssh",
        "brew outdated --json",
        "brew config",
        "brew formulae",
        "brew casks",
        "brew tap",
        "brew -v list",
    ] {
        let b = resolve(c);
        assert!(!unknown_mutation(&b, EffectKind::WritePath), "{c}");
        assert!(!unknown_mutation(&b, EffectKind::DeletePath), "{c}");
        assert!(
            b.effects.iter().all(|e| !matches!(
                e.kind,
                EffectKind::ImportPackage | EffectKind::ExecuteImportedPackageLogic
            )),
            "{c}"
        );
    }
}

#[test]
fn root_location_commands_are_queries_not_installation_overrides() {
    for c in [
        "brew",
        "brew -v",
        "brew --version",
        "brew --prefix",
        "brew --cache",
        "brew --cellar",
        "brew --caskroom",
        "brew --repository",
        "brew --repo",
    ] {
        assert!(resolve(c).effects.is_empty(), "{c}");
    }
    opaque("brew install --prefix /tmp/project curl");
    opaque("brew install --version curl");
}

#[test]
fn importing_transactions_keep_sources_separate_from_unknown_targets() {
    for c in [
        "brew install curl",
        "brew instal curl",
        "brew install --formula curl",
        "brew install --cask firefox",
        "brew reinstall curl",
        "brew upgrade",
        "brew upgrade curl",
        "brew install --skip-link --skip-post-install --force-bottle curl",
    ] {
        let b = resolve(c);
        assert!(unknown_mutation(&b, EffectKind::WritePath), "{c}");
        assert!(!unknown_mutation(&b, EffectKind::DeletePath), "{c}");
        for kind in [
            EffectKind::ImportPackage,
            EffectKind::ExecuteImportedPackageLogic,
        ] {
            if c != "brew upgrade" {
                assert!(b.effects.iter().any(|e| e.kind == kind), "{c}");
            }
        }
        if c != "brew upgrade" {
            assert!(b.bound_parameters.iter().any(|p| matches!(&p.semantic,
            SemanticType::PackageLocator(s) if s.manager == PackageManagerKind::Brew && !s.locator_kinds.contains(&PackageLocatorKind::LocalPath))), "{c}");
        }
    }
}

#[test]
fn removal_cleanup_and_links_do_not_fabricate_imported_sources_or_root_deletion() {
    for c in [
        "brew uninstall curl",
        "brew rm --force curl",
        "brew remove --cask --zap firefox",
        "brew uninstal curl",
        "brew autoremove",
        "brew cleanup --prune=all",
        "brew cleanup -s curl",
        "brew link --overwrite curl",
        "brew ln curl",
        "brew unlink curl",
    ] {
        let b = resolve(c);
        assert!(
            unknown_mutation(&b, EffectKind::WritePath)
                || unknown_mutation(&b, EffectKind::DeletePath),
            "{c}"
        );
        assert!(
            b.effects.iter().all(|e| !matches!(
                e.kind,
                EffectKind::ImportPackage | EffectKind::ExecuteImportedPackageLogic
            )),
            "{c}"
        );
        assert!(b.effects.iter().all(|e| !matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.default_value.is_some())), "{c}");
    }
}

#[test]
fn cask_option_operands_and_package_sources_keep_distinct_ownership() {
    let b = resolve(
        "brew install --cask --appdir=/old firefox --fontdir /fonts --appdir /new --language en,zh-CN --cc clang curl",
    );
    assert_eq!(values(&b, "appdir"), ["/old", "/new"]);
    assert_eq!(values(&b, "fontdir"), ["/fonts"]);
    assert_eq!(values(&b, "packages"), ["firefox", "curl"]);
    assert_eq!(values(&b, "install_values"), ["en,zh-CN", "clang"]);
    assert!(unknown_mutation(&b, EffectKind::WritePath));
}

#[test]
fn all_native_cask_destination_names_are_bound_as_values_not_packages() {
    for flag in [
        "--appdir",
        "--appimagedir",
        "--keyboard-layoutdir",
        "--colorpickerdir",
        "--prefpanedir",
        "--qlplugindir",
        "--mdimporterdir",
        "--dictionarydir",
        "--fontdir",
        "--servicedir",
        "--input-methoddir",
        "--internet-plugindir",
        "--audio-unit-plugindir",
        "--vst-plugindir",
        "--vst3-plugindir",
        "--screen-saverdir",
    ] {
        let c = format!("brew install --cask {flag}=/tmp/output sample");
        let b = resolve(&c);
        assert_eq!(values(&b, "packages"), ["sample"], "{c}");
        let slot = flag.trim_start_matches("--").replace('-', "_");
        assert_eq!(values(&b, &slot), ["/tmp/output"], "{c}");
    }
}

#[test]
fn bare_optional_json_does_not_swallow_the_next_package_operand() {
    for c in [
        "brew info --json curl wget",
        "brew outdated --json curl wget",
    ] {
        let b = resolve(c);
        assert_eq!(values(&b, "arguments"), ["curl", "wget"], "{c}");
        assert!(values(&b, "json_version").is_empty());
    }
    let b = resolve("brew info --json=v2 curl");
    assert_eq!(values(&b, "json_version"), ["v2"]);
}

#[test]
fn documented_nontransaction_previews_have_no_deletion_or_modification_scope() {
    for c in [
        "brew cleanup -n",
        "brew cleanup --dry-run --prune=all",
        "brew autoremove --dry-run",
        "brew link -n --overwrite curl",
        "brew unlink --dry-run curl",
    ] {
        let b = resolve(c);
        assert!(!unknown_mutation(&b, EffectKind::WritePath), "{c}");
        assert!(!unknown_mutation(&b, EffectKind::DeletePath), "{c}");
    }
    for c in [
        "brew install --dry-run curl",
        "brew upgrade -n",
        "brew reinstall --dry-run curl",
    ] {
        opaque(c);
    }
}

#[test]
fn help_does_not_create_package_or_cask_destination_effects() {
    for c in [
        "brew --help",
        "brew help",
        "brew install --help --appdir=/etc/output curl",
        "brew upgrade --help",
        "brew services --help",
    ] {
        assert!(resolve(c).effects.is_empty(), "{c}");
    }
}

#[test]
fn service_inspection_is_separate_from_control_and_startup_registration() {
    for c in [
        "brew services",
        "brew services list --json",
        "brew services ls --debug",
        "brew services info redis",
        "brew services i --all --json",
    ] {
        let b = resolve(c);
        assert!(
            b.effects.iter().all(|e| !matches!(
                e.kind,
                EffectKind::ControlProcess
                    | EffectKind::ExecutePayload
                    | EffectKind::DispatchCommand
            )),
            "{c}"
        );
    }
    for c in [
        "brew services start redis",
        "brew services stop redis",
        "brew services restart --all",
        "brew services run redis",
        "brew services kill redis",
        "brew services cleanup",
        "brew services list --file service.plist",
    ] {
        opaque(c);
    }
}

#[test]
fn unknown_options_and_unsupported_setup_or_languages_remain_opaque() {
    for c in [
        "brew info --eval-all",
        "brew search --eval-all --desc curl",
        "brew info --github curl",
        "brew custom list",
        "brew bundle",
        "brew bundle list --install",
        "brew bundle exec rm -rf /",
        "brew exec rm -rf /",
        "brew x rm -rf /",
        "brew ruby -e anything",
        "brew tap owner/repo",
        "brew untap owner/repo",
        "brew update",
        "brew pin curl",
        "brew install --with-feature curl",
        "brew list --future",
        "brew list -qZ",
        "brew install --appdir",
        "brew install --appdir /tmp/out --cc",
        "brew -q list",
        "brew services list start",
    ] {
        opaque(c);
    }
}

#[test]
fn local_definition_query_operands_are_not_admitted_as_ordinary_queries() {
    for c in [
        "brew info ./recipe",
        "brew info /tmp/recipe",
        "brew info https://example.test/recipe",
        "brew list ./recipe",
        "brew outdated ./recipe",
    ] {
        opaque(c);
    }
    resolve("brew search /etc");
}

#[test]
fn dashdash_keeps_flag_looking_package_text_as_data() {
    let b = resolve("brew install -- --appdir=/etc/output");
    assert_eq!(values(&b, "packages"), ["--appdir=/etc/output"]);
    assert!(values(&b, "appdir").is_empty());
}

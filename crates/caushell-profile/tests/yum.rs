//! Static Profile/argv contracts only; no package manager executes.
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
fn installation_writes(b: &BoundInvocation) -> usize {
    b.effects
        .iter()
        .filter(|e| {
            matches!(&e.target,
        EffectTarget::ConfiguredPath(p) if p.default_value.as_deref() == Some("/"))
        })
        .inspect(|e| assert_eq!(e.kind, EffectKind::WritePath))
        .count()
}

#[test]
fn native_yum_registers_without_dnf_aliases() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["yum", "/usr/bin/yum"] {
        let p = registry.lookup(name).profile.unwrap();
        assert_eq!(p.primary_name(), "yum");
        assert!(p.identity.aliases.is_empty());
        assert_eq!(p.option_scope, OptionScopePolicy::AllArguments);
        assert!(p.opaque_on_unresolved);
    }
    for name in ["dnf", "dnf5"] {
        assert!(registry.lookup(name).profile.is_none());
    }
}

#[test]
fn queries_and_cache_preparation_are_not_installation_transactions() {
    for c in [
        "yum list",
        "yum info curl",
        "yum search all ssh",
        "yum provides /usr/bin/cc",
        "yum whatprovides '*.so'",
        "yum check-update",
        "yum check",
        "yum deplist curl",
        "yum resolvedep libc",
        "yum repolist all",
        "yum repoinfo enabled",
        "yum version",
        "yum history",
        "yum history list",
        "yum history info 1",
        "yum history packages-list curl",
        "yum group list",
        "yum groups info 'Development Tools'",
        "yum grouplist",
        "yum groupinfo core",
        "yum makecache",
        "yum makecache fast",
    ] {
        let b = resolve(c);
        assert_eq!(installation_writes(&b), 0, "{c}");
        assert!(
            b.effects
                .iter()
                .all(|e| e.kind != EffectKind::ExecuteImportedPackageLogic),
            "{c}"
        );
        assert!(b.effects.iter().any(|e| matches!(&e.target,
            EffectTarget::ConfiguredPath(p) if p.missing == ConfiguredPathMissing::IncidentalCache)), "{c}");
    }
}

#[test]
fn help_and_version_suppress_package_and_output_effects() {
    for c in [
        "yum -h",
        "yum --version",
        "yum install curl --help --downloaddir /etc/out",
        "yum --version --installroot=/opt/root --downloaddir=/etc/out",
    ] {
        assert!(resolve(c).effects.is_empty(), "{c}");
    }
}

#[test]
fn transactions_record_modification_not_deletion_of_the_installation_root() {
    for c in [
        "yum install curl",
        "yum install-n curl",
        "yum update",
        "yum update-to curl",
        "yum update-minimal",
        "yum upgrade",
        "yum upgrade-to curl",
        "yum distro-sync",
        "yum distribution-synchronization full",
        "yum reinstall curl",
        "yum downgrade curl",
        "yum localinstall package.rpm",
        "yum localupdate ./package.rpm",
        "yum remove curl",
        "yum erase curl",
        "yum autoremove",
        "yum remove-nevra curl",
        "yum autoremove-n curl",
    ] {
        let b = resolve(c);
        assert_eq!(installation_writes(&b), 1, "{c}");
        assert!(
            b.effects.iter().all(|e| e.kind != EffectKind::DeletePath),
            "{c}"
        );
    }
}

#[test]
fn interspersed_options_short_clusters_and_inline_values_keep_ownership() {
    let b = resolve(
        "yum -qy --installroot=/old install --releasever 7 curl --installroot /new --enablerepo base --exclude bad wget",
    );
    assert_eq!(values(&b, "operation"), ["install"]);
    assert_eq!(values(&b, "installroot"), ["/old", "/new"]);
    assert_eq!(values(&b, "packages"), ["curl", "wget"]);
    assert_eq!(values(&b, "option_values"), ["7", "base", "bad"]);
}

#[test]
fn opaque_setup_is_not_mistaken_for_an_ordinary_query_or_transaction() {
    for c in [
        "yum -c config list",
        "yum --config=config install curl",
        "yum --setopt=installroot=/tmp/root list",
        "yum install curl --setopt cachedir=/etc/out",
        "yum --enableplugin anything list",
        "yum --disableplugin '*' search curl",
        "yum --noplugins --setopt=plugins=1 list",
        "yum --help -c config",
    ] {
        assert!(
            matches!(result(c), ResolveInvocationResult::SelectionError { .. }),
            "{c}"
        );
    }
}

#[test]
fn source_roles_are_declared_without_guessing_local_rpm_existence() {
    for (c, form, kinds) in [
        (
            "yum install curl",
            "repository_transaction",
            vec![
                PackageLocatorKind::RegistryRef,
                PackageLocatorKind::DirectUrl,
                PackageLocatorKind::UnknownDynamic,
            ],
        ),
        (
            "yum install package.rpm",
            "file_or_repository_transaction",
            vec![
                PackageLocatorKind::DirectUrl,
                PackageLocatorKind::UnknownDynamic,
            ],
        ),
        (
            "yum install ./package.rpm",
            "file_or_repository_transaction",
            vec![
                PackageLocatorKind::DirectUrl,
                PackageLocatorKind::UnknownDynamic,
            ],
        ),
        (
            "yum localinstall extensionless",
            "local_transaction",
            vec![
                PackageLocatorKind::LocalPath,
                PackageLocatorKind::DirectUrl,
                PackageLocatorKind::UnknownDynamic,
            ],
        ),
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), form);
        assert!(b.bound_parameters.iter().any(|p| matches!(&p.semantic,
            SemanticType::PackageLocator(s) if s.manager == PackageManagerKind::Yum && s.locator_kinds == kinds)));
    }
}

#[test]
fn download_only_has_source_and_cache_facts_without_package_execution() {
    for c in [
        "yum install --downloadonly curl",
        "yum --downloadonly --downloaddir=out localinstall ./p.rpm",
    ] {
        let b = resolve(c);
        assert_eq!(installation_writes(&b), 0, "{c}");
        assert!(
            b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ImportPackage),
            "{c}"
        );
        assert!(
            b.effects
                .iter()
                .all(|e| e.kind != EffectKind::ExecuteImportedPackageLogic),
            "{c}"
        );
    }
    assert_eq!(
        installation_writes(&resolve("yum --downloadonly update")),
        0
    );
}

#[test]
fn cacheonly_assumeno_and_nodeps_are_not_guessed_previews() {
    for c in [
        "yum -C install curl",
        "yum install --assumeno curl",
        "yum --nodeps update",
        "yum install --downloaddir out curl",
    ] {
        assert_eq!(installation_writes(&resolve(c)), 1, "{c}");
    }
}

#[test]
fn unknown_languages_and_plugin_commands_stay_unresolved() {
    for c in [
        "yum",
        "yum shell",
        "yum shell script",
        "yum load-transaction file",
        "yum history redo 1",
        "yum history rollback 1",
        "yum history new",
        "yum group install core",
        "yum groups mark install core",
        "yum updateinfo remove-pkgs-ts",
        "yum fssnapshot delete 1",
        "yum fs refilter",
        "yum config-manager --add-repo URL",
        "yum makecache anything",
        "yum FutureCommand",
        "yum clean plugins",
    ] {
        assert!(
            matches!(result(c), ResolveInvocationResult::SelectionError { .. }),
            "{c}"
        );
    }
}

#[test]
fn cache_deletion_retains_unknown_target_not_an_incidental_write_exemption() {
    for c in [
        "yum clean all",
        "yum clean packages metadata",
        "yum --installroot /tmp/root clean rpmdb",
    ] {
        let b = resolve(c);
        let deletes: Vec<_> = b
            .effects
            .iter()
            .filter(|e| e.kind == EffectKind::DeletePath)
            .collect();
        assert_eq!(deletes.len(), 1, "{c}");
        assert!(matches!(&deletes[0].target,
            EffectTarget::ConfiguredPath(p) if p.missing == ConfiguredPathMissing::Unknown && p.default_value.is_none()));
    }
}

#[test]
fn option_terminator_preserves_flag_looking_package_data() {
    let b = resolve("yum install -- --downloadonly --setopt=plugins=1");
    assert_eq!(
        values(&b, "packages"),
        ["--downloadonly", "--setopt=plugins=1"]
    );
    assert_eq!(installation_writes(&b), 1);
    assert!(values(&b, "configuration_overrides").is_empty());
}

#[test]
fn synchronization_modes_are_not_fabricated_package_sources() {
    for c in [
        "yum distro-sync full curl",
        "yum distro-sync --downloadonly different curl",
    ] {
        let b = resolve(c);
        assert_eq!(values(&b, "packages"), ["curl"], "{c}");
        assert_eq!(values(&b, "synchronization_mode").len(), 1);
    }
}

#[test]
fn downloads_retain_the_same_source_roles_as_transactions() {
    for (c, form) in [
        (
            "yum install --downloadonly package.rpm",
            "download_file_or_repository",
        ),
        (
            "yum localinstall --downloadonly package.rpm",
            "download_local",
        ),
        ("yum install --downloadonly curl", "download_packages"),
    ] {
        assert_eq!(resolve(c).form_id.as_str(), form, "{c}");
    }
}

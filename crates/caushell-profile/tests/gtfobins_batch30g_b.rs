//! Static GTFOBins 30g group B profile checks. Source recipes are never executed.
use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, InvocationRuntimeContext, ProfileRegistry,
    ResolveInvocationResult, load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    ("apt", include_str!("../profiles/apt.yaml")),
    ("aptitude", include_str!("../profiles/aptitude.yaml")),
    ("dpkg", include_str!("../profiles/dpkg.yaml")),
    ("dnf", include_str!("../profiles/dnf.yaml")),
    ("zypper", include_str!("../profiles/zypper.yaml")),
    ("rpm", include_str!("../profiles/rpm.yaml")),
    ("rpmdb", include_str!("../profiles/rpmdb.yaml")),
    ("rpmquery", include_str!("../profiles/rpmquery.yaml")),
    ("rpmverify", include_str!("../profiles/rpmverify.yaml")),
    ("pkg", include_str!("../profiles/pkg.yaml")),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|(_, source)| load_command_profile_from_str(source).unwrap())
            .collect(),
    )
    .unwrap()
}

fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let profile = registry();
    match resolve_invocation(
        &profile,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(resolved) => resolved.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound,
            error,
            ..
        } => panic!("{command}: {error:?}; partial={partial_bound:#?}"),
        other => panic!("{command}: {other:?}"),
    }
}

fn has_effect(bound: &BoundInvocation, expected: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == expected)
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("{slot}: {other:?}"),
        })
        .collect()
}

#[test]
fn all_profiles_load_as_independent_native_profiles() {
    for (name, source) in PROFILES {
        let profile =
            load_command_profile_from_str(source).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(profile.identity.canonical_name.as_str(), name);
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/source_research"),
            "{name}"
        );
        assert!(
            profile
                .extensions
                .contains_key("caushell.profile/known_limitations"),
            "{name}"
        );
    }
    let registry = registry();
    for name in [
        "apt",
        "aptitude",
        "dpkg",
        "dnf",
        "zypper",
        "rpm",
        "rpmdb",
        "rpmquery",
        "rpmverify",
        "pkg",
    ] {
        assert!(registry.lookup(name).profile.is_some(), "{name}");
    }
}

#[test]
fn mechanisms_and_benign_queries_bind_to_separate_forms() {
    for (command, form) in [
        ("apt install package-name", "install_repository_packages"),
        ("apt show package-name", "read_only_query"),
        ("apt changelog aptitude", "changelog_pager"),
        (
            "apt update -o 'APT::Update::Pre-Invoke::=cat'",
            "update_with_shell_hook",
        ),
        (
            "apt update -o 'APT::Update::Acquire::Retries=3'",
            "update_metadata",
        ),
        ("aptitude changelog aptitude", "changelog_pager"),
        ("aptitude search package-name", "list_packages"),
        ("dpkg -i ./local.deb", "install_local_packages"),
        ("dpkg -l", "package_listing"),
        ("dpkg --print-architecture", "package_metadata_query"),
        (
            "dnf install package-1.rpm --disablerepo=*",
            "install_packages",
        ),
        ("dnf list installed", "read_only_query"),
        ("dnf install ./local.rpm", "install_local_package"),
        ("zypper search package-name", "read_only_query"),
        ("zypper install ./local.rpm", "install_local_packages"),
        ("zypper x", "external_subcommand_lookup"),
        ("rpm -ivh package-1.rpm", "install_local_package"),
        ("rpm -qa", "query_installed_packages"),
        ("rpm --eval '%{lua:print(1)}'", "evaluate_rpm_macro"),
        ("rpm --pipe 'cat'", "pipe_output_to_shell"),
        ("rpmdb --eval '%{lua:print(1)}'", "evaluate_rpm_macro"),
        ("rpmdb --verifydb", "verify_database"),
        ("rpmquery -qa", "query_packages"),
        ("rpmquery --eval '%{lua:print(1)}'", "evaluate_rpm_macro"),
        ("rpmverify -a", "verify_packages"),
        ("rpmverify --eval '%{lua:print(1)}'", "evaluate_rpm_macro"),
        (
            "pkg install -y --no-repo-update ./local.txz",
            "install_local_packages",
        ),
        ("pkg info", "query_installed_packages"),
    ] {
        let bound = bind(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
    }
}

#[test]
fn imported_package_logic_is_retained_without_invented_manager_labels() {
    for command in [
        "apt install package-name",
        "apt install ./local.deb",
        "dpkg -i ./local.deb",
        "dnf install package-1.rpm --disablerepo=*",
        "rpm -ivh package-1.rpm",
        "pkg install -y --no-repo-update ./local.txz",
    ] {
        let bound = bind(command);
        assert!(
            has_effect(&bound, EffectKind::ImportPackage),
            "{command}: {bound:#?}"
        );
        assert!(
            has_effect(&bound, EffectKind::ExecuteImportedPackageLogic),
            "{command}: {bound:#?}"
        );
    }
    let dnf = bind("dnf install package-1.rpm");
    let package = dnf
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "packages")
        .unwrap();
    assert!(
        matches!(package.semantic, caushell_profile::SemanticType::PlainValue),
        "{package:#?}"
    );
    assert_eq!(
        values(&bind("pkg install ./local.txz"), "package_files"),
        ["./local.txz"]
    );
}

#[test]
fn rpm_macro_language_and_rpm_pipe_shell_remain_distinct() {
    let macro_eval = bind("rpm --eval '%(printf DATA)'");
    assert_eq!(macro_eval.form_id.as_str(), "evaluate_rpm_macro");
    assert!(has_effect(&macro_eval, EffectKind::ExecutePayload));
    let pipe = bind("rpm --pipe 'cat'");
    assert_eq!(pipe.form_id.as_str(), "pipe_output_to_shell");
    assert!(has_effect(&pipe, EffectKind::ExecutePayload));
    let payload = macro_eval
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "macro_expressions")
        .unwrap();
    assert!(
        matches!(payload.semantic, caushell_profile::SemanticType::Payload(ref p) if p.language == caushell_profile::PayloadLanguage::Opaque && p.recursive)
    );
    let external = bind("zypper x");
    assert!(has_effect(&external, EffectKind::ExecutePayload));
}

#[test]
fn apt_alias_materialization_does_not_change_apt_get() {
    let apt = load_command_profile_from_str(PROFILES[0].1).unwrap();
    assert_eq!(apt.identity.canonical_name.as_str(), "apt");
    let legacy = load_command_profile_from_str(include_str!("../profiles/apt-get.yaml"));
    assert!(legacy.is_ok());
}

//! Independent core resolution checks for GTFOBins 30g group B; all commands remain data.
use caushell_parse::parse_command;
use caushell_passes::ResolveInvocationPass;
use caushell_profile::{
    InvocationRuntimeContext, ProfileRegistry, ResolveInvocationResult,
    load_command_profile_from_str,
};
use caushell_types::ShellKind;

const PROFILES: [(&str, &str); 10] = [
    (
        "apt",
        include_str!("../../caushell-profile/profiles/apt.yaml"),
    ),
    (
        "aptitude",
        include_str!("../../caushell-profile/profiles/aptitude.yaml"),
    ),
    (
        "dpkg",
        include_str!("../../caushell-profile/profiles/dpkg.yaml"),
    ),
    (
        "dnf",
        include_str!("../../caushell-profile/profiles/dnf.yaml"),
    ),
    (
        "zypper",
        include_str!("../../caushell-profile/profiles/zypper.yaml"),
    ),
    (
        "rpm",
        include_str!("../../caushell-profile/profiles/rpm.yaml"),
    ),
    (
        "rpmdb",
        include_str!("../../caushell-profile/profiles/rpmdb.yaml"),
    ),
    (
        "rpmquery",
        include_str!("../../caushell-profile/profiles/rpmquery.yaml"),
    ),
    (
        "rpmverify",
        include_str!("../../caushell-profile/profiles/rpmverify.yaml"),
    ),
    (
        "pkg",
        include_str!("../../caushell-profile/profiles/pkg.yaml"),
    ),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|(_, s)| load_command_profile_from_str(s).unwrap())
            .collect(),
    )
    .unwrap()
}

#[test]
fn all_group_b_commands_resolve_to_native_profiles() {
    let registry = registry();
    let cases = [
        (
            "apt install package-name",
            "apt",
            "install_repository_packages",
        ),
        ("aptitude changelog aptitude", "aptitude", "changelog_pager"),
        ("dpkg -i ./local.deb", "dpkg", "install_local_packages"),
        ("dnf install package-1.rpm", "dnf", "install_packages"),
        ("zypper search package-name", "zypper", "read_only_query"),
        ("rpm --eval '%{lua:print(1)}'", "rpm", "evaluate_rpm_macro"),
        (
            "rpmdb --eval '%{lua:print(1)}'",
            "rpmdb",
            "evaluate_rpm_macro",
        ),
        (
            "rpmquery --eval '%{lua:print(1)}'",
            "rpmquery",
            "evaluate_rpm_macro",
        ),
        (
            "rpmverify --eval '%{lua:print(1)}'",
            "rpmverify",
            "evaluate_rpm_macro",
        ),
        (
            "pkg install -y --no-repo-update ./local.txz",
            "pkg",
            "install_local_packages",
        ),
    ];
    for (command, name, form) in cases {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        match caushell_profile::resolve_invocation(
            &registry,
            &parsed.commands[0],
            InvocationRuntimeContext::new(),
        ) {
            ResolveInvocationResult::Resolved(resolved) => {
                assert_eq!(resolved.bound.command_name.as_str(), name, "{command}");
                assert_eq!(resolved.bound.form_id.as_str(), form, "{command}");
            }
            other => panic!("{command}: {other:?}"),
        }
    }
}

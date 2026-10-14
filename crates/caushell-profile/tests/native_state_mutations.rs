//! Native CLI contracts only; these supplied commands are never executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{ShellKind, StateOperationDomain, StateOperationKind};

fn resolve(command: &str) -> ResolvedInvocationArtifact {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_artifact_with_bindings(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationArtifactResult::Resolved(r) => r,
        other => panic!("{command}: {other:#?}"),
    }
}
fn known(command: &str) -> ResolvedInvocationArtifact {
    let r = resolve(command);
    assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
    r
}
fn mutation(command: &str, domain: StateOperationDomain) {
    let r = known(command);
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::StateOperation
                && e.state_operation.is_some_and(
                    |s| s.domain == domain && s.operation == StateOperationKind::Mutate
                )),
        "{command}: {r:#?}"
    );
    assert!(
        !r.bound
            .effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::MetadataMutation)),
        "{command}: {r:#?}"
    );
}
fn query(command: &str) {
    let r = known(command);
    assert!(
        r.bound
            .effects
            .iter()
            .all(|e| e.kind != EffectKind::StateOperation),
        "{command}: {r:#?}"
    );
}
fn values<'a>(r: &'a ResolvedInvocationArtifact, slot: &str) -> Vec<&'a str> {
    r.bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .filter_map(|v| {
            if let BoundValue::Argument { text, .. } = v {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn interface_queries_and_configuration_tails_are_distinct() {
    for c in [
        "ifconfig",
        "ifconfig -a",
        "ifconfig -s eth0",
        "ifconfig -v eth0",
        "ifconfig -l",
        "ifconfig eth0",
        "ifconfig eth0 inet",
        "ifconfig en0 inet6",
        "ifconfig --help eth0 down",
    ] {
        query(c);
    }
    for c in [
        "ifconfig eth0 up",
        "ifconfig eth0 down",
        "ifconfig -a eth0 down",
        "ifconfig eth0 -arp",
        "ifconfig eth0 hw ether 00:80:48:ba:d1:30",
        "ifconfig eth0 192.0.2.1 netmask 255.255.255.0",
        "ifconfig en0 inet6 2001:db8::1 prefixlen 64",
        "ifconfig eth0 name renamed",
        "ifconfig eth0 mtu 1400",
        "ifconfig eth0 --help down",
    ] {
        mutation(c, StateOperationDomain::NetworkConfiguration);
    }
    let r = known("ifconfig -v eth0 -arp");
    assert_eq!(values(&r, "interface_name"), ["eth0"]);
    assert_eq!(values(&r, "interface_arguments"), ["-arp"]);
}

#[test]
fn hostname_query_options_do_not_mask_name_or_file_setting() {
    for c in [
        "hostname",
        "hostname -f",
        "hostname -s",
        "hostname -d",
        "hostname -i",
        "hostname -I",
        "hostname --all-fqdns",
        "hostname --all-ip-address",
        "hostname -y",
        "hostname --help buildbox",
        "hostname --version",
    ] {
        query(c);
    }
    for c in [
        "hostname buildbox",
        "hostname -s buildbox",
        "hostname -d buildbox",
        "hostname -y domain.test",
        "hostname -b",
        "hostname --boot fallback",
        "hostname -F ./name",
        "hostname --file=/etc/hostname",
    ] {
        mutation(c, StateOperationDomain::HostIdentity);
    }
    let r = known("hostname -F ./name");
    assert_eq!(values(&r, "name_file"), ["./name"]);
    assert!(
        r.bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    assert!(
        known("hostname --help -F /etc/hostname")
            .bound
            .effects
            .is_empty()
    );
}

#[test]
fn clock_operands_formats_and_native_option_operands_have_correct_ownership() {
    for c in [
        "date",
        "date +%Y",
        "date -u +%Y",
        "date --date=1971-01-01 +%s",
        "date -d 010100001971",
        "date -f dates.txt",
        "date --file=dates.txt +%Y",
        "date -r0 +%s",
        "date --reference=./file",
        "date -I",
        "date -Iseconds",
        "date --rfc-3339=seconds",
        "date -v+1d +%Y",
        "date -j 010100001971 +%Y",
        "date -j -f %Y%m%d 20260101 +%s",
        "date --help --set=1971-01-01",
    ] {
        query(c);
    }
    for c in [
        "date 010100001971",
        "date -u 010100001971.00",
        "date -- 010100001971",
        "date +%Y 010100001971",
        "date -f %Y%m%d 20260101 +%s",
        "date --set=1971-01-01",
        "date -s 1971-01-01 +%Y",
    ] {
        mutation(c, StateOperationDomain::SystemClock);
    }
    let query = known("date -d 010100001971 +%Y");
    assert_eq!(values(&query, "date_expression"), ["010100001971"]);
    assert_eq!(values(&query, "format_or_dates"), ["+%Y"]);
    assert!(
        !known("date -j -f %Y%m%d 20260101")
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    assert!(
        known("date -r ./file")
            .bound
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::TargetPath)
    );
}

#[test]
fn arp_mode_flag_uses_remaining_file_or_default_and_not_next_option() {
    for c in [
        "arp",
        "arp -n",
        "arp -an",
        "arp -i eth0 -n",
        "arp -H ether -A inet 192.0.2.1",
        "arp --help -f ./entries",
    ] {
        query(c);
    }
    for c in [
        "arp -f",
        "arp -f ./entries",
        "arp -f -i eth0 ./entries",
        "arp -v -f /etc/ethers",
        "arp --file ./entries",
        "arp -s 192.0.2.1 00:80:48:ba:d1:30",
        "arp -d 192.0.2.1",
        "arp -Ds 192.0.2.1 eth0 pub",
    ] {
        mutation(c, StateOperationDomain::NetworkConfiguration);
    }
    let r = known("arp -f -i eth0 ./entries");
    assert_eq!(values(&r, "entry_file"), ["./entries"]);
    assert_eq!(values(&r, "device"), ["eth0"]);
    assert!(values(&known("arp -f"), "entry_file").is_empty());
    assert!(known("arp --help -f ./entries").bound.effects.is_empty());
}

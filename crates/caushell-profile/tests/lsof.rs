use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolved(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(r.bound.residuals.is_empty(), "{command}: {:?}", r.bound);
            assert!(!r.bound.operation_semantics_unresolved, "{command}");
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
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
fn unresolved(command: &str) {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => assert!(
            r.bound.operation_semantics_unresolved,
            "{command}: {:?}",
            r.bound
        ),
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(b),
            ..
        } => assert!(b.operation_semantics_unresolved, "{command}: {b:?}"),
        other => panic!("{command}: {other:?}"),
    }
}

#[test]
fn registered_tool_explicitly_declares_both_signs_and_unknown_form_accounting() {
    let registry = ProfileRegistry::built_in().unwrap();
    let p = registry.lookup("/usr/sbin/lsof").profile.unwrap();
    assert_eq!(p.primary_name(), "lsof");
    assert_eq!(p.option_prefixes, OptionPrefixPolicy::DashAndPlus);
    assert_eq!(p.option_scope, OptionScopePolicy::LeadingOptions);
    assert!(p.opaque_on_unresolved);
}
#[test]
fn ordinary_queries_cover_common_selectors_and_display_forms() {
    for c in [
        "lsof",
        "lsof -nP",
        "lsof -i",
        "lsof -iTCP",
        "lsof -i TCP:8080",
        "lsof -nPiTCP:8080",
        "lsof -nP -i :8080 -s TCP:LISTEN",
        "lsof -a -p 123 -d cwd,txt,0-2",
        "lsof -c python -u alice,^root",
        "lsof +c 20 -c /^python/",
        "lsof -g",
        "lsof -g 123,456 -a -i",
        "lsof -F",
        "lsof -F0",
        "lsof -F pfn",
        "lsof +f -- /mnt",
        "lsof +d /etc",
        "lsof +D/etc",
        "lsof +L1",
        "lsof -o 8 -S 15",
        "lsof -r",
        "lsof +r5",
        "lsof -r5m%H:%M:%S",
        "lsof +r5c10mDcache",
        "lsof -K i -T qs -x fl",
        "lsof -h",
        "lsof -v",
        "lsof '-?'",
        "lsof -J",
        "lsof -j",
        "lsof /etc/passwd",
        "lsof +m",
        "lsof +m /tmp/mounts",
    ] {
        resolved(c);
    }
}
#[test]
fn sign_changes_do_not_conflate_query_operands() {
    let b = resolved("lsof -c python +c20 -d cwd +d/etc +D/var -p 123 -i TCP:443");
    for (slot, value) in [
        ("command_filter", "python"),
        ("command_width", "20"),
        ("descriptor_filter", "cwd"),
        ("directory_selector", "/etc"),
        ("recursive_directory_selector", "/var"),
        ("process_filter", "123"),
        ("network_filter", "TCP:443"),
    ] {
        assert_eq!(values(&b, slot), [value], "{slot}: {b:?}");
    }
}
#[test]
fn absent_optional_values_do_not_swallow_later_options() {
    let b = resolved("lsof -i -n +D /etc -F -P");
    assert!(values(&b, "network_filter").is_empty());
    assert!(values(&b, "fields").is_empty());
    assert_eq!(values(&b, "recursive_directory_selector"), ["/etc"]);
    assert!(
        b.applied_modifiers
            .contains(&ModifierId::new("numeric_hosts"))
    );
    assert!(
        b.applied_modifiers
            .contains(&ModifierId::new("numeric_ports"))
    );
}
#[test]
fn metadata_selectors_do_not_fabricate_content_reads_or_process_control() {
    let b = resolved("lsof -p 123 -i @192.0.2.1 +D /etc /etc/shadow");
    assert!(b.effects.is_empty(), "{b:?}");
    assert!(
        b.bound_parameters
            .iter()
            .all(|p| p.semantic == SemanticType::PlainValue)
    );
}
#[test]
fn actual_supplement_file_reads_are_distinct_from_selected_file_metadata() {
    assert!(resolved("lsof +m").effects.is_empty());
    let b = resolved("lsof +m/etc/mounts /etc/shadow");
    assert_eq!(b.effects.len(), 1);
    assert_eq!(b.effects[0].kind, EffectKind::ReadPath);
    assert_eq!(values(&b, "mount_supplement"), ["/etc/mounts"]);
    assert_eq!(values(&b, "file_selectors"), ["/etc/shadow"]);
}
#[test]
fn terminators_and_first_file_operand_stop_native_option_recognition() {
    for c in [
        "lsof -- -D b/etc/cache +D /etc",
        "lsof ++ -D b/etc/cache +D /etc",
        "lsof file.txt -D b/etc/cache +D /etc",
    ] {
        let b = resolved(c);
        assert!(
            !b.applied_modifiers
                .contains(&ModifierId::new("recursive_directory"))
        );
        assert!(b.effects.is_empty());
        assert!(values(&b, "file_selectors").contains(&"-D"));
    }
}
#[test]
fn unsupported_cache_unknown_options_and_missing_required_operands_are_opaque() {
    for c in [
        "lsof -D b/etc/cache",
        "lsof -Db/etc/cache",
        "lsof -nPDu/etc/cache",
        "lsof -nP --cache /tmp/cache",
        "lsof -A /tmp/afs",
        "lsof -k /tmp/kernel",
        "lsof -m /tmp/memory",
        "lsof -z zone",
        "lsof -Z label",
        "lsof +D",
        "lsof +d",
        "lsof -c",
        "lsof +c",
        "lsof -p",
        "lsof -u",
        "lsof +D -Db/etc/cache",
        "lsof -i -D b/etc/cache",
    ] {
        unresolved(c);
    }
}
#[test]
fn numeric_suffixes_cannot_hide_unmodeled_native_options() {
    for c in [
        "lsof +L1Db/etc/cache",
        "lsof -o8Db/etc/cache",
        "lsof -S15Db/etc/cache",
        "lsof -r5Db/etc/cache",
        "lsof +r5c10Db/etc/cache",
        "lsof -r D",
        "lsof +c20Db/etc/cache",
    ] {
        unresolved(c);
    }
    // After m, the same letters are format text, not native option parsing.
    assert!(!resolved("lsof -r5mDb/etc/cache").operation_semantics_unresolved);
}
#[test]
fn numeric_operand_frontier_is_checked_for_every_repeated_value() {
    unresolved("lsof -r 5 -r 6Db/etc/cache");
    unresolved("lsof +L1 +L2Db/etc/cache");
    let b = resolved("lsof -i TCP -i -n -i UDP");
    assert_eq!(values(&b, "network_filter"), ["TCP", "UDP"]);
}

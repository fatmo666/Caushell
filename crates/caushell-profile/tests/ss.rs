use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve(command: &str) -> BoundInvocation {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(r.bound.residuals.is_empty(), "{command}: {r:?}");
            r.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn raw_values<'a>(b: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
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

fn projected_values(b: &BoundInvocation, name: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| p.semantic_values())
        .map(|v| match v {
            SemanticValueRef::Projected {
                value:
                    ProjectedSemanticValue {
                        resolution: SemanticValueResolution::Known(text),
                        ..
                    },
                ..
            } => text.clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}

fn has_file_values(b: &BoundInvocation) -> bool {
    b.bound_parameters.iter().any(|p| {
        matches!(p.semantic, SemanticType::Path(_)) && p.semantic_values().next().is_some()
    })
}

#[test]
fn registers_linux_ss_without_inventing_an_alias() {
    let r = ProfileRegistry::built_in().unwrap();
    for name in ["ss", "/usr/bin/ss", "/usr/sbin/ss"] {
        let p = r.lookup(name).profile.unwrap();
        assert_eq!(p.primary_name(), "ss");
        assert!(p.identity.aliases.is_empty());
        assert_eq!(p.platform.os_families, [OsFamily::Linux]);
    }
}

#[test]
fn common_queries_and_monitoring_do_not_become_control_operations() {
    for c in [
        "ss",
        "ss -lntp",
        "ss -tunap",
        "ss -HOn -B -4 -o -e -m -i -T",
        "ss --numeric --listening --tcp --processes --no-queues",
        "ss -s",
        "ss -E -t",
        "ss --events --context --contexts --bpf --cgroup --tos",
        "ss --tipcinfo --vsock --xdp --mptcp --inet-sockopt --bpf-maps",
        "ss --udp --raw --unix --sctp --packet --ipv6",
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), "socket_query", "{c}");
        assert!(!has_file_values(&b), "{c}: {b:?}");
        assert!(b.bound_implicit_inputs.is_empty());
    }
}

#[test]
fn filters_namespace_and_map_identifiers_are_plain_not_paths_or_endpoints() {
    let b = resolve(
        "ss -f inet -A tcp,udp --socket=unix -N lab --bpf-map-id=12 --bpf-map-id 13 state established '( dport = :443 or dst 192.0.2.1 )'",
    );
    assert_eq!(raw_values(&b, "socket_family"), ["inet"]);
    assert_eq!(raw_values(&b, "socket_tables"), ["tcp,udp", "unix"]);
    assert_eq!(raw_values(&b, "network_namespace"), ["lab"]);
    assert_eq!(raw_values(&b, "bpf_map_ids"), ["12", "13"]);
    assert_eq!(
        raw_values(&b, "socket_filter"),
        ["state", "established", "( dport = :443 or dst 192.0.2.1 )"]
    );
    assert!(
        b.bound_parameters
            .iter()
            .filter(|p| p.semantic_values().next().is_some())
            .all(|p| p.semantic == SemanticType::PlainValue)
    );
    assert!(!has_file_values(&b));
    assert!(!has_file_values(&resolve("ss -x src /run/app.sock")));
}

#[test]
fn kill_has_an_explicit_unchecked_form_and_scope_annotation() {
    for c in [
        "ss -K",
        "ss --kill dst 192.0.2.1",
        "ss -Ktn state established",
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), "close_sockets_unchecked", "{c}");
        assert!(!has_file_values(&b), "{c}: {b:?}");
        assert!(b.bound_implicit_inputs.is_empty());
    }
    let r = ProfileRegistry::built_in().unwrap();
    let p = r.lookup("ss").profile.unwrap();
    for form in p
        .forms
        .iter()
        .filter(|f| f.id.as_str().contains("unchecked"))
    {
        let annotation = form.extensions["caushell.profile/risk_scope"]
            .as_str()
            .unwrap();
        assert!(annotation.contains("not read-only"));
        assert!(annotation.contains("independently checked"));
    }
}

#[test]
fn diagnostic_paths_preserve_raw_operands_and_independent_writes() {
    for c in [
        "ss -tn -D out.bin -F filters.txt",
        "ss --diag=out.bin --filter=filters.txt --kill",
        "ss -KtnDout.bin -Ffilters.txt",
    ] {
        let b = resolve(c);
        assert_eq!(raw_values(&b, "diagnostic_operand"), ["out.bin"]);
        assert_eq!(projected_values(&b, "diagnostic_paths"), ["out.bin"]);
        assert_eq!(projected_values(&b, "filter_paths"), ["filters.txt"]);
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath
            && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == "diagnostic_paths")));
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath
            && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == "filter_paths")));
    }
}

#[test]
fn dash_prefixed_output_is_stdout_but_dot_slash_dash_is_a_file() {
    for c in ["ss -t -D -", "ss --kill --diag=-anything", "ss -tD-"] {
        let b = resolve(c);
        assert!(projected_values(&b, "diagnostic_paths").is_empty(), "{c}");
        assert!(!raw_values(&b, "diagnostic_operand").is_empty());
    }
    let b = resolve("ss --diag=./-dump");
    assert_eq!(projected_values(&b, "diagnostic_paths"), ["./-dump"]);
}

#[test]
fn stdin_filter_is_data_not_shell_payload_or_a_file_named_dash() {
    for (c, form) in [
        ("ss -t -F -", "socket_query_stdin_filter"),
        ("ss --filter=-anything", "socket_query_stdin_filter"),
        ("ss -KtF-", "close_sockets_stdin_filter_unchecked"),
        (
            "ss --kill --filter=-",
            "close_sockets_stdin_filter_unchecked",
        ),
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), form, "{c}");
        assert!(projected_values(&b, "filter_paths").is_empty());
        assert_eq!(b.bound_implicit_inputs.len(), 1);
        assert_eq!(
            b.bound_implicit_inputs[0].source,
            ImplicitInputSource::StdinData
        );
        assert_eq!(
            b.bound_implicit_inputs[0].semantic,
            SemanticType::PlainValue
        );
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ConsumeStdin));
        assert!(collect_recursive_payload_candidates(&b).is_empty());
        assert!(collect_dispatch_command_candidates(&b).is_empty());
    }
    assert_eq!(
        projected_values(&resolve("ss -F ./-filter"), "filter_paths"),
        ["./-filter"]
    );
}

#[test]
fn file_filter_is_only_read_and_its_text_is_not_a_nested_command() {
    let b = resolve("ss -K -F /etc/ss-filter '( dst 192.0.2.1 )'");
    assert_eq!(b.form_id.as_str(), "close_sockets_unchecked");
    assert_eq!(projected_values(&b, "filter_paths"), ["/etc/ss-filter"]);
    assert!(b.bound_implicit_inputs.is_empty());
    assert!(!b.effects.iter().any(|e| matches!(
        e.kind,
        EffectKind::ExecutePayload | EffectKind::ControlProcess | EffectKind::ListenNetwork
    )));
    assert!(raw_values(&b, "residual_diagnostic_operand").is_empty());
    assert!(collect_recursive_payload_candidates(&b).is_empty());
}

#[test]
fn unknown_diagnostic_operand_preserves_an_unknown_write_candidate() {
    let b = resolve("ss --kill --diag=\"$OUTPUT\"");
    let paths = b
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == "diagnostic_paths")
        .unwrap();
    assert!(matches!(
        paths.semantic_values().next().unwrap(),
        SemanticValueRef::Projected {
            value: ProjectedSemanticValue {
                resolution: SemanticValueResolution::Unknown(_),
                ..
            },
            ..
        }
    ));
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
}

#[test]
fn repeated_outputs_are_conservatively_retained() {
    let b = resolve("ss -D /etc/first.bin --diag=second.bin");
    assert_eq!(
        projected_values(&b, "diagnostic_paths"),
        ["/etc/first.bin", "second.bin"]
    );
}

#[test]
fn help_suppresses_deferred_writes_but_keeps_possible_prior_filter_reads() {
    for c in [
        "ss -h",
        "ss --help",
        "ss -v",
        "ss -V",
        "ss --version",
        "ss -K -D /etc/out --help",
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), "information", "{c}");
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    }
    let b = resolve("ss -F /etc/filter --help");
    assert_eq!(projected_values(&b, "filter_paths"), ["/etc/filter"]);
}

#[test]
fn dashdash_preserves_filter_argv_without_activating_modifiers() {
    let b = resolve("ss -- -K -D /etc/not-an-output");
    assert_eq!(b.form_id.as_str(), "socket_query");
    assert_eq!(
        raw_values(&b, "socket_filter"),
        ["--", "-K", "-D", "/etc/not-an-output"]
    );
    assert!(!has_file_values(&b));
}

#[test]
fn compact_alphabetic_file_operands_do_not_disappear_as_unmatched_flags() {
    for (c, slot, value) in [
        ("ss -Ddump", "residual_diagnostic_operand", "dump"),
        ("ss -Ffilter", "residual_filter_operand", "filter"),
    ] {
        let b = resolve(c);
        assert_eq!(raw_values(&b, slot), [value], "{c}: {b:?}");
        assert!(raw_values(&b, "socket_filter").is_empty(), "{c}: {b:?}");
    }
}

#[test]
fn terminated_filter_data_keeps_real_prior_modifiers_without_compact_fallbacks() {
    for (c, form) in [
        ("ss -- -Ddump -Ffilter", "socket_query"),
        ("ss -K -- -Ddump", "close_sockets_unchecked"),
        ("ss -F - -- -Ddump", "socket_query_stdin_filter"),
        (
            "ss -K -F - -- -Ddump",
            "close_sockets_stdin_filter_unchecked",
        ),
    ] {
        let b = resolve(c);
        assert_eq!(b.form_id.as_str(), form, "{c}: {b:?}");
        assert!(!has_file_values(&b), "{c}: {b:?}");
    }
    let b = resolve("ss -K -D /etc/real-output -- -Ddump");
    assert_eq!(
        projected_values(&b, "diagnostic_paths"),
        ["/etc/real-output"]
    );
    let b = resolve("ss -Ddump -- -Dother");
    assert_eq!(raw_values(&b, "residual_diagnostic_operand"), ["dump"]);
}

use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, ResolveInvocationResult, resolve_invocation,
};
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let registry = ProfileRegistry::built_in().unwrap();
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(result) => {
            assert!(
                result.bound.residuals.is_empty(),
                "{command}: {:?}",
                result.bound.residuals
            );
            result.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .find(|p| p.name.as_str() == name)
        .map(|p| {
            p.values
                .iter()
                .map(|v| match v {
                    BoundValue::Argument { text, .. } => text.as_str(),
                    _ => panic!("expected literal argument"),
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn frequency_profiles_register_canonical_names_and_absolute_paths() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["pdftotext", "bc", "getent"] {
        for lookup_name in [name.to_string(), format!("/usr/bin/{name}")] {
            assert_eq!(
                registry
                    .lookup(&lookup_name)
                    .profile
                    .unwrap()
                    .primary_name(),
                name
            );
        }
        assert!(
            registry
                .lookup(name)
                .profile
                .unwrap()
                .identity
                .aliases
                .is_empty()
        );
    }
    println!(
        "registry_profile_count={} registry_name_count={}",
        registry.len(),
        registry
            .profiles()
            .iter()
            .map(|profile| 1 + profile.identity.aliases.len())
            .sum::<usize>()
    );
}

#[test]
fn pdftotext_explicit_file_and_stream_forms() {
    for (command, form, input, output) in [
        (
            "pdftotext input.pdf out.txt",
            "file_to_file",
            "input.pdf",
            "out.txt",
        ),
        ("pdftotext input.pdf -", "file_to_stdout", "input.pdf", ""),
        ("pdftotext - out.txt", "stdin_to_file", "", "out.txt"),
        ("pdftotext - -", "stdin_to_stdout", "", ""),
        (
            "pdftotext -layout -f 2 -l 4 -r 72 -x 1 -y 2 -W 3 -H 4 -fixed 10 -colspacing 0.7 -enc UTF-8 -eol unix -opw dummy -upw dummy input.pdf out.txt",
            "file_to_file",
            "input.pdf",
            "out.txt",
        ),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}");
        assert_eq!(
            values(&bound, "input_pdf"),
            if input.is_empty() {
                vec![]
            } else {
                vec![input]
            },
            "{command}"
        );
        assert_eq!(
            values(&bound, "output_text"),
            if output.is_empty() {
                vec![]
            } else {
                vec![output]
            },
            "{command}"
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::TransformData)
        );
        assert_eq!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            !output.is_empty()
        );
        assert_eq!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin),
            input.is_empty()
        );
    }
}

#[test]
fn pdftotext_default_output_rules_and_information_are_distinct() {
    for (command, form) in [
        ("pdftotext a.pdf", "default_pdf_text"),
        ("pdftotext a.PDF", "default_upper_pdf_text"),
        ("pdftotext a.Pdf", "default_other_text"),
        ("pdftotext a", "default_other_text"),
        ("pdftotext -htmlmeta a.pdf", "default_pdf_html"),
        ("pdftotext -bbox a.PDF", "default_upper_pdf_html"),
        ("pdftotext -bbox-layout a", "default_other_html"),
        ("pdftotext -tsv a.pdf", "default_pdf_text"),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}");
        assert_eq!(
            bound
                .effects
                .iter()
                .filter(|e| e.kind == EffectKind::WritePath)
                .count(),
            1
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| matches!(e.target, EffectTarget::DerivedPath(_)))
        );
    }
    for flag in ["-h", "-help", "--help", "-?", "-v", "-listenc"] {
        let bound = resolve(&format!("pdftotext {flag}"));
        assert_eq!(bound.form_id.as_str(), "information");
        assert!(bound.effects.is_empty());
    }
}

#[test]
fn pdftotext_missing_and_extra_operands_remain_unresolved() {
    let registry = ProfileRegistry::built_in().unwrap();
    for command in [
        "pdftotext",
        "pdftotext -",
        "pdftotext a.pdf b.txt c.txt",
        "pdftotext fd://0",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert!(
            matches!(
                resolve_invocation(
                    &registry,
                    &parsed.commands[0],
                    InvocationRuntimeContext::new()
                ),
                ResolveInvocationResult::SelectionError { .. }
            ),
            "{command}"
        );
    }
}

#[test]
fn pdftotext_protocol_inputs_preserve_outputs_without_fake_read_paths() {
    for (command, form, writes) in [
        ("pdftotext fd://0 -", "stdin_to_stdout", false),
        ("pdftotext fd://0 out.txt", "stdin_to_file", true),
        ("pdftotext fd://4 -", "protocol_to_stdout", false),
        ("pdftotext fd://4 out.txt", "protocol_to_file", true),
        (
            "pdftotext https://example.test/a.pdf -",
            "protocol_to_stdout",
            false,
        ),
        (
            "pdftotext https://example.test/a.pdf /etc/out.txt",
            "protocol_to_file",
            true,
        ),
        (
            "pdftotext https://example.test/a.pdf",
            "protocol_default_pdf_text",
            true,
        ),
        (
            "pdftotext file:///etc/a.PDF",
            "protocol_default_upper_pdf_text",
            true,
        ),
        ("pdftotext fd://4", "protocol_default_other_text", true),
        (
            "pdftotext -htmlmeta https://example.test/a.pdf",
            "protocol_default_pdf_html",
            true,
        ),
        (
            "pdftotext -bbox file:///etc/a.PDF",
            "protocol_default_upper_pdf_html",
            true,
        ),
        (
            "pdftotext -bbox-layout fd://4",
            "protocol_default_other_html",
            true,
        ),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}");
        assert!(
            !bound.effects.iter().any(|e| e.kind == EffectKind::ReadPath),
            "{command}"
        );
        assert_eq!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::WritePath),
            writes,
            "{command}"
        );
    }
}

#[test]
fn bc_preserves_files_and_stdin_without_inventing_shell_execution() {
    for (command, files) in [
        ("bc", vec![]),
        ("bc -lq math.bc", vec!["math.bc"]),
        ("bc --standard --warn a.bc b.bc", vec!["a.bc", "b.bc"]),
        ("bc -- -private.bc", vec!["-private.bc"]),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), "evaluate_expressions");
        assert_eq!(values(&bound, "input_files"), files);
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::TransformData)
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin)
        );
        assert!(!bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ExecutePayload
                | EffectKind::WritePath
                | EffectKind::OpenInteractiveEscapeSurface
        )));
    }
    for flag in ["-h", "--help", "-v", "--version"] {
        let bound = resolve(&format!("bc {flag}"));
        assert_eq!(bound.form_id.as_str(), "information");
        assert!(bound.effects.is_empty());
    }
}

#[test]
fn getent_database_and_service_keys_are_not_files() {
    for database in [
        "aliases",
        "ethers",
        "group",
        "gshadow",
        "initgroups",
        "netgroup",
        "networks",
        "passwd",
        "protocols",
        "rpc",
        "services",
        "shadow",
    ] {
        let command = format!("getent --service=files {database} key1 key2");
        let bound = resolve(&command);
        assert_eq!(bound.form_id.as_str(), "query_name_service");
        assert_eq!(values(&bound, "database"), vec![database]);
        assert_eq!(values(&bound, "lookup_keys"), vec!["key1", "key2"]);
        assert_eq!(values(&bound, "service_overrides"), vec!["files"]);
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::LoadInProcessCode)
        );
        assert!(!bound.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
        )));
    }
    let bound = resolve("getent -s files -s passwd:compat passwd");
    assert_eq!(
        values(&bound, "service_overrides"),
        vec!["files", "passwd:compat"]
    );
    assert!(values(&bound, "lookup_keys").is_empty());
    for flag in ["--help", "--usage", "--version", "-V", "'-?'"] {
        assert!(resolve(&format!("getent {flag}")).effects.is_empty());
    }
}

#[test]
fn getent_host_queries_preserve_endpoint_keys_and_ignore_stdin() {
    for database in ["hosts", "ahosts", "ahostsv4", "ahostsv6"] {
        let bound = resolve(&format!(
            "getent -i -sdns {database} example.test 127.0.0.1"
        ));
        assert_eq!(bound.form_id.as_str(), "query_hosts");
        assert_eq!(values(&bound, "database"), vec![database]);
        assert_eq!(
            values(&bound, "host_keys"),
            vec!["example.test", "127.0.0.1"]
        );
        assert!(
            bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::NetworkEndpoint)
        );
        assert!(
            !bound
                .effects
                .iter()
                .any(|e| e.kind == EffectKind::ConsumeStdin)
        );
    }
}

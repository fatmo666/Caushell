use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn registry() -> &'static ProfileRegistry {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap())
}
fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        registry(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(b),
            ..
        } => b,
        other => panic!("{command}: {other:?}"),
    }
}
fn clean(command: &str) -> BoundInvocation {
    let b = resolve(command);
    assert!(b.residuals.is_empty(), "{command}: {b:?}");
    assert!(!b.operation_semantics_unresolved, "{command}: {b:?}");
    b
}
fn values(b: &BoundInvocation, slot: &str) -> Vec<String> {
    b.bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == slot)
        .flat_map(|p| &p.values)
        .map(|v| match project_value(&ValueProjection::Identity, v) {
            Some(SemanticValueResolution::Known(text)) => text,
            other => panic!("{other:?}: {v:?}"),
        })
        .collect()
}
fn opaque(command: &str) {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let result = resolve_invocation(
        registry(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    );
    assert!(
        matches!(result, ResolveInvocationResult::SelectionError { .. })
            || matches!(&result, ResolveInvocationResult::Resolved(r) if r.bound.operation_semantics_unresolved),
        "{command}: {result:?}"
    );
}

#[test]
fn dialect_and_email_endpoint_kind_are_explicit() {
    let p = registry().lookup("/usr/bin/mail").profile.unwrap();
    assert!(p.opaque_on_unresolved);
    assert_eq!(p.option_scope, OptionScopePolicy::PermutedOptions);
    assert!(p.identity.aliases.is_empty());
    assert!(registry().lookup("mailx").profile.is_none());
    let b = clean("mail receiver@example.test");
    assert!(
        b.bound_parameters
            .iter()
            .any(|p| p.name.as_str() == "recipients"
                && p.semantic
                    == SemanticType::Endpoint(EndpointSemantic {
                        kind: EndpointKind::EmailAddress,
                        usage: EndpointUsage::UploadTarget,
                    }))
    );
}
#[test]
fn known_send_options_bind_permuted_clustered_inline_and_multiple_operands() {
    for c in [
        "mail -s fixture receiver@example.test",
        "mail receiver@example.test -s --help",
        "mail -insfixture --mime receiver@example.test",
        "mail --subject=fixture --return-address=sender@example.test receiver@example.test other@example.test",
        "mail --no-config -n --no-mime --alternative --no-alternative --skip-empty-attachments --no-skip-empty-attachments --config-verbose --debug-line-info --no-debug-line-info --debug-level=none --encoding=base64 --content-type=text/plain --content-name=fixture --content-filename=fixture receiver@example.test",
        "mail -e -H -p receiver@example.test",
    ] {
        clean(c);
    }
    let b = clean("mail -s --help receiver@example.test -r --version");
    assert_eq!(values(&b, "subjects"), ["--help"]);
    assert_eq!(values(&b, "return_addresses"), ["--version"]);
    assert_eq!(values(&b, "recipients"), ["receiver@example.test"]);
    assert!(
        !b.applied_modifiers
            .iter()
            .any(|m| ["help", "version"].contains(&m.as_str()))
    );
}
#[test]
fn local_output_recipients_keep_absolute_paths_and_are_not_addresses_or_reads() {
    let b = clean("mail /etc/output ./local receiver@example.test ../sibling other@example.test");
    assert_eq!(values(&b, "absolute_outputs"), ["/etc/output"]);
    assert_eq!(values(&b, "relative_outputs"), ["./local", "../sibling"]);
    assert_eq!(
        values(&b, "recipients"),
        ["receiver@example.test", "other@example.test"]
    );
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    let b = clean("mail '/etc/output one' receiver@example.test \"./local two\"");
    assert_eq!(values(&b, "absolute_outputs"), ["/etc/output one"]);
    assert_eq!(values(&b, "relative_outputs"), ["./local two"]);
    assert_eq!(values(&b, "recipients"), ["receiver@example.test"]);
}
#[test]
fn uppercase_attachments_retain_files_but_dash_is_stdin_data() {
    let b = clean("mail -A .env --attach=public.txt -A - receiver@example.test");
    assert_eq!(values(&b, "attachment_files"), [".env", "public.txt"]);
    assert_eq!(values(&b, "recipients"), ["receiver@example.test"]);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    for c in [
        "mail -A - receiver@example.test",
        "mail --attach-fd=0 receiver@example.test",
    ] {
        let b = clean(c);
        assert!(values(&b, "attachment_files").is_empty());
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ConsumeStdin));
        assert!(
            !b.effects
                .iter()
                .any(|e| e.kind == EffectKind::ExecutePayload)
        );
    }
}
#[test]
fn lowercase_append_is_header_metadata_not_a_bsd_attachment_alias() {
    let b = clean("mail -a .env --append='X-Trace: fixture' receiver@example.test");
    assert_eq!(values(&b, "appended_headers"), [".env", "X-Trace: fixture"]);
    assert!(values(&b, "attachment_files").is_empty());
    assert!(!b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    for header in [
        "To: secret@example.test",
        "Cc: secret@example.test",
        "bCc : secret@example.test",
    ] {
        opaque(&format!("mail -a '{header}' receiver@example.test"));
    }
}
#[test]
fn every_configuration_variant_retains_send_effects_and_separate_config_layers() {
    for (prefix, configs) in [
        ("--no-config -n", 1),
        ("--no-config", 2),
        ("-n", 2),
        ("", 3),
    ] {
        let b = clean(&format!("mail {prefix} receiver@example.test"));
        assert_eq!(
            b.effects
                .iter()
                .filter(|e| e.kind == EffectKind::LoadConfig)
                .count(),
            configs
        );
        for kind in [
            EffectKind::NetworkEndpoint,
            EffectKind::ConsumeStdin,
            EffectKind::WritePath,
            EffectKind::DeletePath,
        ] {
            assert!(b.effects.iter().any(|e| e.kind == kind));
        }
    }
    let n = clean("mail -n receiver@example.test");
    let big_n = clean("mail -N receiver@example.test");
    assert_eq!(
        n.effects
            .iter()
            .filter(|e| e.kind == EffectKind::LoadConfig)
            .count(),
        2
    );
    assert_eq!(
        big_n
            .effects
            .iter()
            .filter(|e| e.kind == EffectKind::LoadConfig)
            .count(),
        3
    );
}
#[test]
fn body_is_data_and_failure_spill_and_byname_modifications_are_not_erased() {
    let b = clean("mail --no-config -n -F receiver@example.test");
    assert!(
        b.bound_implicit_inputs
            .iter()
            .any(|i| i.source == ImplicitInputSource::StdinData
                && i.semantic == SemanticType::PlainValue)
    );
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath && e.target == EffectTarget::None)
    );
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath && e.target == EffectTarget::None)
    );
    assert!(b.effects.iter().any(|e| matches!(&e.target, EffectTarget::ConfiguredPath(p) if p.environment.as_ref().is_some_and(|v| v.name == "DEAD"))));
    assert!(
        !b.effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
    assert!(
        !b.bound_parameters
            .iter()
            .any(|p| matches!(p.semantic, SemanticType::Payload(_)))
    );
}
#[test]
fn file_switch_selects_positional_mailbox_not_the_immediately_following_flag() {
    for c in [
        "mail -f -e mbox",
        "mail -fe mbox",
        "mail --file -p mbox",
        "mail -f mbox -H",
        "mail --file=mbox --read",
    ] {
        let b = clean(c);
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
        assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
        assert!(
            !b.effects
                .iter()
                .any(|e| e.kind == EffectKind::NetworkEndpoint)
        );
        assert!(!b.effects.iter().any(|e| e.kind == EffectKind::ConsumeStdin));
    }
    let b = clean("mail -f -e mbox");
    assert_eq!(values(&b, "positional_mailbox"), ["mbox"]);
    let b = clean("mail --file=mbox -e");
    assert_eq!(values(&b, "inline_mailboxes"), ["mbox"]);
    let b = clean("mail -f -e");
    assert!(values(&b, "positional_mailbox").is_empty());
}
#[test]
fn every_configuration_variant_retains_mailbox_read_and_write_effects() {
    for prefix in ["--no-config -n", "--no-config", "-n", ""] {
        let b = clean(&format!("mail {prefix} -f mbox -H"));
        for kind in [
            EffectKind::LoadConfig,
            EffectKind::ReadPath,
            EffectKind::WritePath,
        ] {
            assert!(b.effects.iter().any(|e| e.kind == kind));
        }
    }
}
#[test]
fn mail_commands_are_retained_as_client_text_not_falsely_parsed_bash() {
    let b = resolve("mail -E 'set record=/etc/mail-record' receiver@example.test");
    assert!(b.operation_semantics_unresolved);
    assert_eq!(values(&b, "mail_commands"), ["set record=/etc/mail-record"]);
    assert!(collect_recursive_payload_candidates(&b).is_empty());
    assert!(
        !b.effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
}
#[test]
fn unknown_execution_recipient_descriptor_mailbox_and_cli_forms_remain_opaque() {
    for c in [
        "mail",
        "mail -s fixture",
        "mail -e",
        "mail -f mbox",
        "mail -t",
        "mail -u other -e",
        "mail '| cat > file'",
        "mail receiver@example.test '| cat > file'",
        "mail \"$DEST\"",
        "mail \"./$DEST\"",
        "mail -a \"$HEADER\" ./local",
        "mail -E 'shell rm -rf /' receiver@example.test",
        "mail --set=mailer.url=sendmail:///tmp/tool receiver@example.test",
        "mail --mailer=sendmail:///tmp/tool receiver@example.test",
        "mail --attach-fd=3 receiver@example.test",
        "mail --attach-fd=\"$FD\" receiver@example.test",
        "mail --config-file=config receiver@example.test",
        "mail -f imap://host/mail -e",
        "mail --file=+folder -p",
        "mail -f %other -H",
        "mail --future receiver@example.test",
        "mail -s",
        "mail -A",
        "mail -E",
        "mail -f -s subject file",
        "mail -f one two -e",
        "mail --file=mbox extra -p",
        "mail --file=public --file=.env -p",
        "mail -s --help",
    ] {
        opaque(c);
    }
}
#[test]
fn information_exits_do_not_invent_attachment_reads_or_client_execution() {
    for c in [
        "mail --help",
        "mail --version",
        "mail --usage",
        "mail --config-help",
        "mail --show-config-options",
        "mail -E 'shell rm -rf /' --help",
        "mail -A .env --help",
        "mail -F receiver@example.test --version",
    ] {
        let b = clean(c);
        assert!(b.effects.is_empty(), "{c}: {b:?}");
        assert!(b.bound_implicit_inputs.is_empty());
    }
}
#[test]
fn actual_terminator_and_owned_dashdash_values_keep_argv_roles() {
    let b = clean("mail -s -- -- receiver@example.test -E");
    assert_eq!(values(&b, "subjects"), ["--"]);
    assert_eq!(values(&b, "recipients"), ["receiver@example.test", "-E"]);
    assert!(!b.applied_modifiers.iter().any(|m| m.as_str() == "exec"));
    let b = clean("mail -A --help receiver@example.test");
    assert_eq!(values(&b, "attachment_files"), ["--help"]);
    assert!(!b.applied_modifiers.iter().any(|m| m.as_str() == "help"));
}
#[test]
fn an_opaque_client_command_does_not_erase_already_bound_attachment_reads() {
    let b = resolve("mail -A .env -E 'set record=/etc/mail' receiver@example.test");
    assert!(b.operation_semantics_unresolved);
    assert_eq!(values(&b, "attachment_files"), [".env"]);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
}

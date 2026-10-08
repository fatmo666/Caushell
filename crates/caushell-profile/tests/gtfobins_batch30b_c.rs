use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, ResolveInvocationResult, SemanticValueRef, SemanticValueResolution,
    load_command_profile_from_str, resolve_invocation,
};
use caushell_types::ShellKind;

const PROFILES: [&str; 10] = [
    include_str!("../profiles/dos2unix.yaml"),
    include_str!("../profiles/ssh-keyscan.yaml"),
    include_str!("../profiles/ab.yaml"),
    include_str!("../profiles/lwp-request.yaml"),
    include_str!("../profiles/lwp-download.yaml"),
    include_str!("../profiles/check_log.yaml"),
    include_str!("../profiles/check_statusfile.yaml"),
    include_str!("../profiles/as.yaml"),
    include_str!("../profiles/efax.yaml"),
    include_str!("../profiles/fping.yaml"),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .into_iter()
            .map(|yaml| load_command_profile_from_str(yaml).unwrap())
            .collect(),
    )
    .unwrap()
}

fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation(
        &registry(),
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    ) {
        ResolveInvocationResult::Resolved(result) => result.bound,
        ResolveInvocationResult::SelectionError {
            partial_bound: Some(bound),
            ..
        } => bound,
        other => panic!("{command}: {other:?}"),
    }
}

fn values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            other => panic!("unexpected value for {slot}: {other:?}"),
        })
        .collect()
}

fn semantic_values<'a>(bound: &'a BoundInvocation, slot: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| parameter.semantic_values())
        .map(|value| match value {
            SemanticValueRef::Original(BoundValue::Argument { text, .. }) => text.as_str(),
            SemanticValueRef::Projected { value, .. } => match &value.resolution {
                SemanticValueResolution::Known(text) => text.as_str(),
                SemanticValueResolution::Unknown(reason) => panic!("{slot}: {reason:?}"),
            },
            other => panic!("unexpected semantic value for {slot}: {other:?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind, slot: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == kind
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == slot)
    })
}

#[test]
fn dos2unix_distinguishes_stdout_paired_output_and_in_place_modes() {
    let stdout = bind("dos2unix -f -O /tmp/project/.env");
    assert_eq!(stdout.form_id.as_str(), "convert_files_to_stdout");
    assert_eq!(values(&stdout, "input_files"), ["/tmp/project/.env"]);
    assert!(has_effect(&stdout, EffectKind::ReadPath, "input_files"));
    assert_eq!(
        stdout.stream_contract.unwrap().stdout_mode,
        caushell_profile::StreamOutputMode::Data
    );

    let pair = bind("dos2unix -fn /tmp/project/source /tmp/project/converted");
    assert_eq!(pair.form_id.as_str(), "convert_newfile_pair");
    assert_eq!(values(&pair, "input_file"), ["/tmp/project/source"]);
    assert_eq!(values(&pair, "output_file"), ["/tmp/project/converted"]);
    assert!(has_effect(&pair, EffectKind::WritePath, "output_file"));

    let inplace = bind("dos2unix /tmp/project/source");
    assert_eq!(inplace.form_id.as_str(), "convert_in_place");
    assert!(has_effect(&inplace, EffectKind::ReadPath, "input_files"));
    assert!(has_effect(&inplace, EffectKind::WritePath, "input_files"));
    assert!(
        inplace
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath && effect.path_access.is_none())
    );
}

#[test]
fn ssh_keyscan_keeps_file_targets_and_network_hosts_separate() {
    let file = bind("ssh-keyscan -f /tmp/project/hosts");
    assert_eq!(values(&file, "host_file"), ["/tmp/project/hosts"]);
    assert!(has_effect(&file, EffectKind::ReadPath, "host_file_path"));
    assert!(
        file.effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint
                && effect.target == EffectTarget::None)
    );

    let host = bind("ssh-keyscan -p 2222 example.invalid");
    assert_eq!(values(&host, "hosts"), ["example.invalid"]);
    assert!(has_effect(&host, EffectKind::NetworkEndpoint, "hosts"));

    let stdin = bind("ssh-keyscan -f -");
    assert_eq!(values(&stdin, "host_file"), ["-"]);
    assert!(
        stdin
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ConsumeStdin)
    );
    assert!(
        !stdin
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );
    assert_eq!(
        stdin.stream_contract.unwrap().stdout_dependency,
        caushell_types::StreamDataDependency::Inputs
    );
}

#[test]
fn ab_binds_upload_files_separately_from_request_endpoint() {
    for (command, slot) in [
        (
            "ab -p /tmp/project/post https://example.invalid/submit",
            "post_file",
        ),
        (
            "ab -u /tmp/project/put https://example.invalid/replace",
            "put_file",
        ),
    ] {
        let bound = bind(command);
        assert_eq!(values(&bound, slot).len(), 1, "{command}: {bound:?}");
        assert!(has_effect(&bound, EffectKind::ReadPath, slot));
        assert_eq!(bound.form_id.as_str(), "upload_endpoint");
        assert_eq!(values(&bound, "endpoint").len(), 1, "{command}: {bound:?}");
        assert!(has_effect(&bound, EffectKind::NetworkEndpoint, "endpoint"));
    }

    let verbose = bind("ab -v2 https://example.invalid/");
    assert_eq!(values(&verbose, "verbosity_level"), ["2"]);
    assert_eq!(values(&verbose, "endpoint"), ["https://example.invalid/"]);
    assert_eq!(
        verbose.stream_contract.unwrap().stdout_dependency,
        caushell_types::StreamDataDependency::Unknown
    );
    let ordinary = bind("ab https://example.invalid/");
    assert!(
        ordinary
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint)
    );
}

#[test]
fn lwp_request_distinguishes_local_uri_reads_from_network_responses() {
    let local = bind("lwp-request file:///tmp/project/.env");
    assert_eq!(local.form_id.as_str(), "read_file_uri", "{local:?}");
    assert_eq!(values(&local, "file_uri"), ["file:///tmp/project/.env"]);
    assert_eq!(
        semantic_values(&local, "local_file_path"),
        ["/tmp/project/.env"]
    );
    assert!(has_effect(&local, EffectKind::ReadPath, "local_file_path"));

    let remote = bind("lwp-request -m GET https://example.invalid/data");
    assert_eq!(remote.form_id.as_str(), "request_network_url");
    assert_eq!(
        values(&remote, "endpoint"),
        ["https://example.invalid/data"]
    );
    assert!(has_effect(&remote, EffectKind::NetworkEndpoint, "endpoint"));
    assert_eq!(
        remote.stream_contract.unwrap().stdout_dependency,
        caushell_types::StreamDataDependency::Unknown
    );

    let suppressed = bind("lwp-request -d -e https://example.invalid/data");
    assert_eq!(
        suppressed.form_id.as_str(),
        "request_network_url_without_content"
    );
    assert_eq!(values(&suppressed, "endpoint").len(), 1);
    assert_eq!(
        suppressed.stream_contract.unwrap().stdout_mode,
        caushell_profile::StreamOutputMode::Opaque
    );

    let local_suppressed = bind("lwp-request -d file:///tmp/project/.env");
    assert_eq!(
        local_suppressed.form_id.as_str(),
        "read_file_uri_without_content"
    );
    assert_eq!(
        semantic_values(&local_suppressed, "local_file_path"),
        ["/tmp/project/.env"]
    );
    assert_eq!(
        local_suppressed.stream_contract.unwrap().stdout_mode,
        caushell_profile::StreamOutputMode::Opaque
    );

    let upload = bind("lwp-request -m PATCH https://example.invalid/submit");
    assert_eq!(upload.form_id.as_str(), "upload_stdin_to_network_url");
    assert_eq!(
        upload.stream_contract.unwrap().stdin_mode,
        caushell_profile::StreamInputMode::DataRequired
    );

    let unknown_method = parse_command(
        "lwp-request -m DELETE https://example.invalid/",
        ShellKind::Bash,
    )
    .unwrap();
    assert!(matches!(
        resolve_invocation(
            &registry(),
            &unknown_method.commands[0],
            InvocationRuntimeContext::new()
        ),
        ResolveInvocationResult::SelectionError { .. }
    ));

    for command in [
        "lwp-request ftp://example.invalid/data",
        "lwp-request -m POST file:///tmp/project/data",
        "lwp-request -m PATCH file:///tmp/project/data",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert!(
            matches!(
                resolve_invocation(
                    &registry(),
                    &parsed.commands[0],
                    InvocationRuntimeContext::new()
                ),
                ResolveInvocationResult::SelectionError { .. }
            ),
            "{command}"
        );
    }

    let escaped = parse_command("lwp-request file:///tmp/project/%2eenv", ShellKind::Bash).unwrap();
    assert!(matches!(
        resolve_invocation(
            &registry(),
            &escaped.commands[0],
            InvocationRuntimeContext::new()
        ),
        ResolveInvocationResult::SelectionError { .. }
    ));
}

#[test]
fn lwp_download_tracks_source_destination_and_stdout_separately() {
    let named = bind("lwp-download https://example.invalid/archive.tar /tmp/project/archive.tar");
    assert_eq!(named.form_id.as_str(), "download_network_to_named_path");
    assert_eq!(values(&named, "output_file"), ["/tmp/project/archive.tar"]);
    assert!(has_effect(&named, EffectKind::NetworkEndpoint, "endpoint"));
    assert!(has_effect(&named, EffectKind::WritePath, "output_file"));

    let derived = bind("lwp-download https://example.invalid/archive.tar");
    assert_eq!(derived.form_id.as_str(), "download_network_to_unknown_path");
    assert!(
        derived
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath
                && effect.target == EffectTarget::None)
    );

    let network_stdout = bind("lwp-download https://example.invalid/archive /dev/stdout");
    assert_eq!(
        network_stdout.form_id.as_str(),
        "download_network_to_stdout"
    );
    assert_eq!(
        network_stdout.stream_contract.unwrap().stdout_mode,
        caushell_profile::StreamOutputMode::Data
    );

    let local = bind("lwp-download file:///tmp/project/.env /dev/stdout");
    assert_eq!(local.form_id.as_str(), "read_file_uri_to_stdout");
    assert_eq!(
        semantic_values(&local, "local_source_path"),
        ["/tmp/project/.env"]
    );
    assert!(has_effect(
        &local,
        EffectKind::ReadPath,
        "local_source_path"
    ));
    assert_eq!(
        local.stream_contract.unwrap().stdout_mode,
        caushell_profile::StreamOutputMode::Data
    );

    let server_name = bind("lwp-download -s https://example.invalid/archive");
    assert_eq!(
        server_name.form_id.as_str(),
        "download_network_server_filename"
    );
    assert!(
        server_name
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath
                && effect.target == EffectTarget::None)
    );

    let server_name_explicit =
        bind("lwp-download -s https://example.invalid/archive /tmp/project/saved");
    assert_eq!(
        server_name_explicit.form_id.as_str(),
        "download_network_to_named_path"
    );
    assert_eq!(
        values(&server_name_explicit, "output_file"),
        ["/tmp/project/saved"]
    );

    let escaped = parse_command(
        "lwp-download file:///tmp/project/%2eenv /dev/stdout",
        ShellKind::Bash,
    )
    .unwrap();
    assert!(matches!(
        resolve_invocation(
            &registry(),
            &escaped.commands[0],
            InvocationRuntimeContext::new()
        ),
        ResolveInvocationResult::SelectionError { .. }
    ));
}

#[test]
fn check_log_models_oldfile_as_state_and_query_as_plain_data() {
    let bound = bind(
        "check_log -F /tmp/project/service.log -O /tmp/project/oldlog -q /tmp/query-looks-like-a-path",
    );
    assert_eq!(values(&bound, "log_file"), ["/tmp/project/service.log"]);
    assert_eq!(values(&bound, "old_file"), ["/tmp/project/oldlog"]);
    assert_eq!(values(&bound, "query"), ["/tmp/query-looks-like-a-path"]);
    assert!(has_effect(&bound, EffectKind::ReadPath, "log_file"));
    assert!(has_effect(&bound, EffectKind::ReadPath, "old_file"));
    assert!(has_effect(&bound, EffectKind::WritePath, "old_file"));

    let stdout_oldfile = bind("check_log -F /tmp/project/service.log -O /dev/stdout -q error");
    assert!(has_effect(
        &stdout_oldfile,
        EffectKind::WritePath,
        "old_file"
    ));
    assert_eq!(
        stdout_oldfile.stream_contract.unwrap().stdout_dependency,
        caushell_types::StreamDataDependency::Inputs
    );
}

#[test]
fn check_statusfile_reads_only_a_bound_positional() {
    let bound = bind("check_statusfile /tmp/project/status");
    assert_eq!(bound.form_id.as_str(), "read_status_file");
    assert_eq!(values(&bound, "status_file"), ["/tmp/project/status"]);
    assert!(has_effect(&bound, EffectKind::ReadPath, "status_file"));
    assert_eq!(
        bound.stream_contract.unwrap().stdout_dependency,
        caushell_types::StreamDataDependency::Inputs
    );
}

#[test]
fn as_response_file_is_not_bound_as_assembly_source() {
    let response = bind("as @/tmp/project/args");
    assert_eq!(response.form_id.as_str(), "response_file_arguments");
    assert_eq!(values(&response, "response_files"), ["@/tmp/project/args"]);
    assert_eq!(
        semantic_values(&response, "response_file_paths"),
        ["/tmp/project/args"]
    );
    assert!(has_effect(
        &response,
        EffectKind::ReadPath,
        "response_file_paths"
    ));

    let normal_source = bind("as /tmp/project/source.s");
    assert_ne!(normal_source.form_id.as_str(), "response_file_arguments");
    assert!(
        normal_source
            .effects
            .iter()
            .all(|effect| effect.kind != EffectKind::ReadPath)
    );
}

#[test]
fn efax_device_is_opened_for_read_and_write_with_input_dependent_diagnostics() {
    let bound = bind("efax -d /tmp/project/device");
    assert_eq!(values(&bound, "device_path"), ["/tmp/project/device"]);
    assert!(has_effect(&bound, EffectKind::ReadPath, "device_path"));
    assert!(has_effect(&bound, EffectKind::WritePath, "device_path"));
    assert_eq!(
        bound.stream_contract.unwrap().stderr_dependency,
        caushell_types::StreamDataDependency::Inputs
    );
}

#[test]
fn fping_file_input_has_dynamic_network_and_diagnostic_dependencies() {
    let file = bind("fping -f /tmp/project/hosts");
    assert_eq!(values(&file, "host_file"), ["/tmp/project/hosts"]);
    assert!(has_effect(&file, EffectKind::ReadPath, "host_file_path"));
    assert!(
        file.effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint
                && effect.target == EffectTarget::None)
    );
    assert_eq!(
        file.stream_contract.unwrap().stderr_dependency,
        caushell_types::StreamDataDependency::Inputs
    );

    let stdin = bind("fping -f -");
    assert!(
        stdin
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ConsumeStdin)
    );
    assert!(
        !stdin
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );
    assert!(
        stdin
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint
                && effect.target == EffectTarget::None)
    );
}

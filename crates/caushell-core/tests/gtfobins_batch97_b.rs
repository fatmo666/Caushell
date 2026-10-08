//! Batch 97 group B Graph coverage; native source recipes are not executed.
use caushell_graph::{GraphNode, NodeKind, SessionGraph, SessionRead};
use caushell_passes::{
    ComputeEffectiveCwdPass, ExtractEndpointProvenancePass, ExtractExecutionSemanticsPass,
    ExtractPathFactsPass, ExtractPipelineFlowPass, ParseCommandPass, ProjectTopLevelCommandsPass,
    ResolveInvocationPass,
};
use caushell_profile::{ProfileRegistry, load_command_profile_from_str};
use caushell_runner::{PassRunner, RunnerContext, SessionView, StagedSession};
use caushell_types::*;
const PROFILES: [&str; 33] = [
    include_str!("../../caushell-profile/profiles/apache2.yaml"),
    include_str!("../../caushell-profile/profiles/apache2ctl.yaml"),
    include_str!("../../caushell-profile/profiles/aws.yaml"),
    include_str!("../../caushell-profile/profiles/busctl.yaml"),
    include_str!("../../caushell-profile/profiles/ctr.yaml"),
    include_str!("../../caushell-profile/profiles/dmsetup.yaml"),
    include_str!("../../caushell-profile/profiles/dstat.yaml"),
    include_str!("../../caushell-profile/profiles/easyrsa.yaml"),
    include_str!("../../caushell-profile/profiles/fail2ban-client.yaml"),
    include_str!("../../caushell-profile/profiles/hg.yaml"),
    include_str!("../../caushell-profile/profiles/ip.yaml"),
    include_str!("../../caushell-profile/profiles/kubectl.yaml"),
    include_str!("../../caushell-profile/profiles/loginctl.yaml"),
    include_str!("../../caushell-profile/profiles/lxd.yaml"),
    include_str!("../../caushell-profile/profiles/mosh-server.yaml"),
    include_str!("../../caushell-profile/profiles/needrestart.yaml"),
    include_str!("../../caushell-profile/profiles/nginx.yaml"),
    include_str!("../../caushell-profile/profiles/opkg.yaml"),
    include_str!("../../caushell-profile/profiles/passwd.yaml"),
    include_str!("../../caushell-profile/profiles/plymouth.yaml"),
    include_str!("../../caushell-profile/profiles/podman.yaml"),
    include_str!("../../caushell-profile/profiles/procmail.yaml"),
    include_str!("../../caushell-profile/profiles/redis-cli.yaml"),
    include_str!("../../caushell-profile/profiles/rsyslogd.yaml"),
    include_str!("../../caushell-profile/profiles/service.yaml"),
    include_str!("../../caushell-profile/profiles/snap.yaml"),
    include_str!("../../caushell-profile/profiles/systemctl.yaml"),
    include_str!("../../caushell-profile/profiles/systemd-resolve.yaml"),
    include_str!("../../caushell-profile/profiles/tailscale.yaml"),
    include_str!("../../caushell-profile/profiles/timedatectl.yaml"),
    include_str!("../../caushell-profile/profiles/unsquashfs.yaml"),
    include_str!("../../caushell-profile/profiles/virsh.yaml"),
    include_str!("../../caushell-profile/profiles/wg-quick.yaml"),
];
fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        PROFILES
            .iter()
            .map(|s| load_command_profile_from_str(s).unwrap())
            .collect(),
    )
    .unwrap()
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
    let request = CheckRequest {
        session_id: SessionId::new("gtfo97-b"),
        sequence_no: CommandSequenceNo::new(1),
        command: command.into(),
        shell_state_before: ShellStateSnapshot::new("/tmp"),
        shell_kind: ShellKind::Bash,
        home: Some("/home/fixture".into()),
        workspace_root: Some("/tmp".into()),
        runtime: RuntimeMetadata {
            runtime_name: "isolated-profile-tests".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    };
    let mut context = RunnerContext::new(request);
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
fn semantic(command: &str, name: &str) -> ExecutionSemantics {
    graph(command)
        .iter()
        .find_map(|n| match &n.kind {
            NodeKind::ExecutionSemantics { semantics, .. }
                if semantics.normalized_command_name == name =>
            {
                Some(semantics.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}: {command}: {:#?}", graph(command)))
}
fn has_path(command: &str, path: &str, role: ResolvedPathRole) -> bool {
    graph(command).iter().any(|n|matches!(&n.kind,NodeKind::PathFact{role:r,resolution,..} if *r==role&&resolution.concrete_path()==Some(path)))
}
fn has_derived(command: &str, name: &str) -> bool {
    graph(command)
        .iter()
        .any(|n| matches!(&n.kind,NodeKind::DerivedInvocation{command_name:Some(x),..} if x==name))
}
#[test]
fn config_execution_and_actual_config_paths_reach_the_graph() {
    for (c, n, p) in [
        ("apache2 -f /tmp/httpd.conf", "apache2", "/tmp/httpd.conf"),
        ("easyrsa --vars /tmp/vars", "easyrsa", "/tmp/vars"),
        (
            "kubectl --kubeconfig /tmp/kubeconfig",
            "kubectl",
            "/tmp/kubeconfig",
        ),
        (
            "needrestart -c /tmp/needrestart.conf",
            "needrestart",
            "/tmp/needrestart.conf",
        ),
        ("nginx -c /tmp/nginx.conf", "nginx", "/tmp/nginx.conf"),
        ("procmail -m /tmp/procmailrc", "procmail", "/tmp/procmailrc"),
        (
            "rsyslogd -f /tmp/rsyslog.conf",
            "rsyslogd",
            "/tmp/rsyslog.conf",
        ),
    ] {
        let s = semantic(c, n);
        assert!(s.executes_payload, "{c}: {s:#?}");
        assert!(
            has_path(c, p, ResolvedPathRole::Read),
            "{c}: {:#?}",
            graph(c)
        );
    }
    let attached = "kubectl get pods --kubeconfig=/tmp/kubeconfig";
    let k = semantic(attached, "kubectl");
    assert!(k.executes_payload, "{attached}: {k:#?}");
    assert!(
        has_path(attached, "/tmp/kubeconfig", ResolvedPathRole::Read),
        "{:#?}",
        graph(attached)
    );
}
#[test]
fn busctl_address_executes_an_opaque_native_address_without_fabricated_shell_child() {
    let c = "busctl --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'";
    let s = semantic(c, "busctl");
    assert_eq!(s.form_id, "unixexec_address");
    assert!(s.executes_payload, "{s:#?}");
    assert!(!has_derived(c, "/bin/sh"), "{:#?}", graph(c));
    let p = semantic("busctl --show-machine", "busctl");
    assert_eq!(p.form_id, "pager_escape_surface");
    assert!(!p.executes_payload, "{p:#?}");
}
#[test]
fn ip_batch_and_netns_keep_native_payload_separate_from_host_shell() {
    let c = "ip -force -batch /tmp/ip.batch";
    let s = semantic(c, "ip");
    assert_eq!(s.form_id, "batch_file");
    assert!(s.executes_payload);
    assert!(has_path(c, "/tmp/ip.batch", ResolvedPathRole::Read));
    let ns = "ip netns exec foo /bin/sh";
    let n = semantic(ns, "ip");
    assert_eq!(n.form_id, "namespace_exec_child_argv");
    assert!(has_derived(ns, "/bin/sh"), "{:#?}", graph(ns));
}
#[test]
fn fail2ban_and_virsh_boundaries_include_mutation_and_explicit_local_paths() {
    let c = "fail2ban-client set x action x actionban /tmp/command";
    let s = semantic(c, "fail2ban-client");
    assert_eq!(s.form_id, "action_callback");
    assert!(!s.executes_payload);
    assert!(!s.controls_process);
    let trigger = semantic("fail2ban-client start x", "fail2ban-client");
    assert_eq!(trigger.form_id, "action_hook_trigger");
    assert!(trigger.executes_hook);
    let xml = "virsh -c qemu:///system create /tmp/domain.xml";
    let v = semantic(xml, "virsh");
    assert_eq!(v.form_id, "create_domain_from_xml");
    assert!(v.executes_payload);
    assert!(has_path(xml, "/tmp/domain.xml", ResolvedPathRole::Read));
    let upload = "virsh -c qemu:///system vol-upload --pool x /tmp/remote-output /tmp/input";
    assert!(
        has_path(upload, "/tmp/input", ResolvedPathRole::Read),
        "{:#?}",
        graph(upload)
    );
    let download = "virsh -c qemu:///system vol-download --pool x input-file /tmp/download";
    assert!(
        has_path(download, "/tmp/download", ResolvedPathRole::Write),
        "{:#?}",
        graph(download)
    );
}
#[test]
fn listener_pager_container_and_archive_boundaries_reach_graph() {
    let proxy = "kubectl proxy --address=0.0.0.0 --port=12345 --www=/tmp/www --www-prefix=/x/";
    let p = semantic(proxy, "kubectl");
    assert_eq!(p.form_id, "proxy_listener");
    assert_eq!(p.network_listeners.len(), 1);
    assert!(
        has_path(proxy, "/tmp/www", ResolvedPathRole::Read),
        "{:#?}",
        graph(proxy)
    );
    let list = semantic("systemctl", "systemctl");
    assert_eq!(list.form_id, "default_list_pager");
    assert!(list.opens_interactive_escape_surface);
    let link = "systemctl link /tmp/unit.service";
    let l = semantic(link, "systemctl");
    assert_eq!(l.form_id, "link_executable_service_unit");
    assert!(!l.executes_payload);
    assert!(has_path(link, "/tmp/unit.service", ResolvedPathRole::Read));
    let now = semantic("systemctl enable --now x.service", "systemctl");
    assert_eq!(now.form_id, "enable_start_unit");
    assert!(now.executes_hook);
    assert!(!now.controls_process);
    let container = "lxc exec x /bin/sh";
    let c = semantic(container, "lxc");
    assert_eq!(c.form_id, "container_command");
    assert!(c.executes_payload);
    assert!(
        !has_derived(container, "/bin/sh"),
        "container command must remain within its foreign runtime boundary: {:#?}",
        graph(container)
    );
    let archive = "unsquashfs -d /opt/shared/output /tmp/archive.squashfs";
    let u = semantic(archive, "unsquashfs");
    assert_eq!(u.form_id, "extract_filesystem_archive");
    assert!(has_path(
        archive,
        "/tmp/archive.squashfs",
        ResolvedPathRole::Read
    ));
    assert!(
        has_path(archive, "/opt/shared/output", ResolvedPathRole::Write),
        "{:#?}",
        graph(archive)
    );
}

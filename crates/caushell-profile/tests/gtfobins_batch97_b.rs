//! Batch 97 group B profile contracts. Recipes remain inert test strings.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{DatabaseOperationKind, ShellKind};
const PROFILES: [(&str, &str); 33] = [
    ("apache2", include_str!("../profiles/apache2.yaml")),
    ("apache2ctl", include_str!("../profiles/apache2ctl.yaml")),
    ("aws", include_str!("../profiles/aws.yaml")),
    ("busctl", include_str!("../profiles/busctl.yaml")),
    ("ctr", include_str!("../profiles/ctr.yaml")),
    ("dmsetup", include_str!("../profiles/dmsetup.yaml")),
    ("dstat", include_str!("../profiles/dstat.yaml")),
    ("easyrsa", include_str!("../profiles/easyrsa.yaml")),
    (
        "fail2ban-client",
        include_str!("../profiles/fail2ban-client.yaml"),
    ),
    ("hg", include_str!("../profiles/hg.yaml")),
    ("ip", include_str!("../profiles/ip.yaml")),
    ("kubectl", include_str!("../profiles/kubectl.yaml")),
    ("loginctl", include_str!("../profiles/loginctl.yaml")),
    ("lxd", include_str!("../profiles/lxd.yaml")),
    ("mosh-server", include_str!("../profiles/mosh-server.yaml")),
    ("needrestart", include_str!("../profiles/needrestart.yaml")),
    ("nginx", include_str!("../profiles/nginx.yaml")),
    ("opkg", include_str!("../profiles/opkg.yaml")),
    ("passwd", include_str!("../profiles/passwd.yaml")),
    ("plymouth", include_str!("../profiles/plymouth.yaml")),
    ("podman", include_str!("../profiles/podman.yaml")),
    ("procmail", include_str!("../profiles/procmail.yaml")),
    ("redis", include_str!("../profiles/redis-cli.yaml")),
    ("rsyslogd", include_str!("../profiles/rsyslogd.yaml")),
    ("service", include_str!("../profiles/service.yaml")),
    ("snap", include_str!("../profiles/snap.yaml")),
    ("systemctl", include_str!("../profiles/systemctl.yaml")),
    (
        "systemd-resolve",
        include_str!("../profiles/systemd-resolve.yaml"),
    ),
    ("tailscale", include_str!("../profiles/tailscale.yaml")),
    ("timedatectl", include_str!("../profiles/timedatectl.yaml")),
    ("unsquashfs", include_str!("../profiles/unsquashfs.yaml")),
    ("virsh", include_str!("../profiles/virsh.yaml")),
    ("wg-quick", include_str!("../profiles/wg-quick.yaml")),
];
fn source(n: &str) -> &str {
    PROFILES.iter().find(|(x, _)| *x == n).unwrap().1
}
fn bind(s: &str, c: &str) -> BoundInvocation {
    let p = load_command_profile_from_str(s).unwrap();
    let parsed = parse_command(c, ShellKind::Bash).unwrap();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let selected = select_invocation(&p, &projected).unwrap_or_else(|e| panic!("{c}: {e:?}"));
    bind_invocation(&p, &projected, &selected)
}
fn effect(b: &BoundInvocation, k: EffectKind) -> bool {
    b.effects.iter().any(|e| e.kind == k)
}
fn argument(b: &BoundInvocation, n: &str, v: &str) -> bool {
    b.bound_parameters.iter().any(|p| {
        p.name.as_str() == n
            && p.values
                .iter()
                .any(|x| matches!(x,BoundValue::Argument{text,..} if text==v))
    })
}
#[test]
fn profiles_load_with_native_names_source_references_and_unresolved_guard() {
    for (name, s) in PROFILES {
        let p = load_command_profile_from_str(s).unwrap_or_else(|e| panic!("{name}: {e}"));
        if name != "redis" {
            assert!(p.opaque_on_unresolved, "{name}");
        }
        if name != "redis" {
            assert!(
                p.extensions
                    .contains_key("caushell.profile/source_research"),
                "{name}"
            );
            assert!(
                p.extensions
                    .contains_key("caushell.profile/known_limitations"),
                "{name}"
            );
        }
    }
    for (file, actual) in [
        ("lxd", "lxc"),
        ("mosh-server", "mosh"),
        ("redis", "redis-cli"),
    ] {
        assert_eq!(
            load_command_profile_from_str(source(file))
                .unwrap()
                .identity
                .canonical_name
                .as_str(),
            actual
        );
    }
}
#[test]
fn verified_query_forms_are_information_only() {
    for (profile_name, command, expected_form) in [
        ("apache2", "apache2 -h", "information"),
        ("apache2ctl", "apache2ctl -h", "information"),
        ("aws", "aws --help", "information"),
        ("busctl", "busctl --help", "information"),
        ("ctr", "ctr --help", "information"),
        ("dmsetup", "dmsetup --help", "information"),
        ("dstat", "dstat --help", "information"),
        ("easyrsa", "easyrsa help", "information_subcommand"),
        ("fail2ban-client", "fail2ban-client --help", "information"),
        ("hg", "hg --help", "information"),
        ("ip", "ip -help", "information"),
        ("kubectl", "kubectl --help", "information"),
        ("loginctl", "loginctl --help", "information"),
        ("lxd", "lxc --help", "information"),
        ("mosh-server", "mosh --help", "information"),
        ("needrestart", "needrestart --help", "information"),
        ("nginx", "nginx -h", "information"),
        ("opkg", "opkg --help", "information"),
        ("passwd", "passwd --help", "information"),
        ("plymouth", "plymouth --help", "information"),
        ("podman", "podman --help", "information"),
        ("procmail", "procmail -v", "information"),
        ("redis", "redis-cli --help", "information"),
        ("rsyslogd", "rsyslogd -v", "information"),
        ("service", "service --help", "information"),
        ("snap", "snap help", "information_subcommand"),
        ("systemctl", "systemctl --help", "information"),
        ("systemd-resolve", "systemd-resolve --help", "information"),
        ("tailscale", "tailscale --help", "information"),
        ("timedatectl", "timedatectl --help", "information"),
        ("unsquashfs", "unsquashfs -help", "information"),
        ("virsh", "virsh --help", "information"),
        ("wg-quick", "wg-quick --help", "information"),
    ] {
        let b = bind(source(profile_name), command);
        assert_eq!(b.form_id.as_str(), expected_form, "{command}: {b:#?}");
        assert!(!effect(&b, EffectKind::ExecutePayload), "{command}: {b:#?}");
        assert!(
            !effect(&b, EffectKind::DispatchCommand),
            "{command}: {b:#?}"
        );
        let with_data = bind(
            source(profile_name),
            &format!("{command} -- malformed-data"),
        );
        assert_eq!(
            with_data.form_id.as_str(),
            expected_form,
            "help/data must stay informational: {command}: {with_data:#?}"
        );
        assert!(
            !with_data.operation_semantics_unresolved,
            "help/data tail must be consumed: {command}: {with_data:#?}"
        );
        assert!(
            !effect(&with_data, EffectKind::ExecutePayload),
            "{command}: {with_data:#?}"
        );
        assert!(
            !effect(&with_data, EffectKind::DispatchCommand),
            "{command}: {with_data:#?}"
        );
    }
}
#[test]
fn typed_config_files_have_explicit_read_load_and_execution_boundaries() {
    for (name, command, path) in [
        ("apache2", "apache2 -f /tmp/input.conf", "/tmp/input.conf"),
        ("easyrsa", "easyrsa --vars /tmp/vars", "/tmp/vars"),
        (
            "kubectl",
            "kubectl --kubeconfig /tmp/kubeconfig",
            "/tmp/kubeconfig",
        ),
        (
            "needrestart",
            "needrestart -c /tmp/needrestart.conf",
            "/tmp/needrestart.conf",
        ),
        ("nginx", "nginx -c /tmp/nginx.conf", "/tmp/nginx.conf"),
        ("procmail", "procmail -m /tmp/procmailrc", "/tmp/procmailrc"),
        (
            "rsyslogd",
            "rsyslogd -f /tmp/rsyslog.conf",
            "/tmp/rsyslog.conf",
        ),
    ] {
        let b = bind(source(name), command);
        assert!(
            b.form_id.as_str().starts_with("executable_configuration"),
            "{command}: {b:#?}"
        );
        assert!(effect(&b, EffectKind::ReadPath), "{command}: {b:#?}");
        assert!(effect(&b, EffectKind::LoadConfig), "{command}: {b:#?}");
        assert!(effect(&b, EffectKind::ExecutePayload), "{command}: {b:#?}");
        assert!(
            argument(&b, "configuration_path", path),
            "{command}: {b:#?}"
        );
    }
    let b = bind(
        source("apache2ctl"),
        "apache2ctl -c 'Include /tmp/input.conf'",
    );
    assert_eq!(b.form_id.as_str(), "executable_configuration_inline_c");
    assert!(effect(&b, EffectKind::ExecutePayload), "{b:#?}");
    assert!(!effect(&b, EffectKind::ReadPath), "{b:#?}");
}
#[test]
fn information_flags_suppress_cooccurring_executable_configuration() {
    for (name, command) in [
        ("apache2", "apache2 -h -f /tmp/input.conf"),
        ("nginx", "nginx -h -c /tmp/nginx.conf"),
        ("kubectl", "kubectl --help --kubeconfig /tmp/kubeconfig"),
    ] {
        let b = bind(source(name), command);
        assert_eq!(b.form_id.as_str(), "information", "{command}: {b:#?}");
        assert!(!effect(&b, EffectKind::ExecutePayload), "{command}: {b:#?}");
        assert!(!effect(&b, EffectKind::LoadConfig), "{command}: {b:#?}");
    }
}
#[test]
fn busctl_shell_address_is_opaque_native_payload_and_pager_is_only_a_capability() {
    let command = "busctl --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'";
    let b = bind(source("busctl"), command);
    assert_eq!(b.form_id.as_str(), "unixexec_address", "{b:#?}");
    assert!(effect(&b, EffectKind::ExecutePayload), "{b:#?}");
    assert!(!effect(&b, EffectKind::DispatchCommand), "{b:#?}");
    let separated = bind(
        source("busctl"),
        "busctl --address unixexec:path=/bin/sh,argv1=-c,argv2='id'",
    );
    assert_eq!(
        separated.form_id.as_str(),
        "unixexec_address",
        "{separated:#?}"
    );
    assert!(
        effect(&separated, EffectKind::ExecutePayload),
        "{separated:#?}"
    );
    let pager = bind(source("busctl"), "busctl --show-machine");
    assert_eq!(pager.form_id.as_str(), "pager_escape_surface");
    assert!(
        effect(&pager, EffectKind::OpenInteractiveEscapeSurface),
        "{pager:#?}"
    );
    assert!(!effect(&pager, EffectKind::ExecutePayload), "{pager:#?}");
    let systemctl_pager = bind(source("systemctl"), "systemctl");
    assert_eq!(
        systemctl_pager.form_id.as_str(),
        "default_list_pager",
        "{systemctl_pager:#?}"
    );
    assert!(
        effect(&systemctl_pager, EffectKind::OpenInteractiveEscapeSurface),
        "{systemctl_pager:#?}"
    );
    let no_pager = bind(source("systemctl"), "systemctl --no-pager");
    assert_eq!(
        no_pager.form_id.as_str(),
        "default_list_no_pager",
        "{no_pager:#?}"
    );
    assert!(
        !effect(&no_pager, EffectKind::OpenInteractiveEscapeSurface),
        "{no_pager:#?}"
    );
}
#[test]
fn ip_batch_file_and_namespace_payload_keep_real_input_boundary() {
    let batch = bind(source("ip"), "ip -force -batch /tmp/ip.batch");
    assert_eq!(batch.form_id.as_str(), "batch_file", "{batch:#?}");
    assert!(effect(&batch, EffectKind::ReadPath), "{batch:#?}");
    assert!(effect(&batch, EffectKind::ExecutePayload), "{batch:#?}");
    assert!(
        argument(&batch, "batch_path", "/tmp/ip.batch"),
        "{batch:#?}"
    );
    let ns = bind(source("ip"), "ip netns exec foo /bin/sh");
    assert_eq!(ns.form_id.as_str(), "namespace_exec_child_argv", "{ns:#?}");
    assert!(effect(&ns, EffectKind::DispatchCommand), "{ns:#?}");
    assert!(argument(&ns, "namespace_name", "foo"), "{ns:#?}");
    let privileged = bind(source("ip"), "ip netns exec foo /bin/sh -p");
    assert_eq!(
        privileged.form_id.as_str(),
        "namespace_exec_child_argv",
        "{privileged:#?}"
    );
    assert!(
        effect(&privileged, EffectKind::DispatchCommand),
        "{privileged:#?}"
    );
    assert!(argument(&privileged, "child_argv", "-p"), "{privileged:#?}");
    let link = bind(
        source("ip"),
        "ip netns exec foo /bin/ln -s /proc/1/ns/net /var/run/netns/bar",
    );
    assert_eq!(
        link.form_id.as_str(),
        "namespace_exec_child_argv",
        "{link:#?}"
    );
    assert!(argument(&link, "child_command", "/bin/ln"), "{link:#?}");
    assert!(argument(&link, "child_argv", "-s"), "{link:#?}");
    assert!(
        argument(&link, "child_argv", "/var/run/netns/bar"),
        "{link:#?}"
    );
    let shell = bind(
        source("ip"),
        "ip netns exec foo sh -c 'rm /opt/shared/victim'",
    );
    assert_eq!(
        shell.form_id.as_str(),
        "namespace_exec_child_argv",
        "{shell:#?}"
    );
    assert!(argument(&shell, "child_command", "sh"), "{shell:#?}");
    assert!(argument(&shell, "child_argv", "-c"), "{shell:#?}");
    assert!(
        argument(&shell, "child_argv", "rm /opt/shared/victim"),
        "{shell:#?}"
    );
    let add = bind(source("ip"), "ip netns add foo");
    assert_eq!(add.form_id.as_str(), "create_namespace", "{add:#?}");
    assert!(effect(&add, EffectKind::WritePath), "{add:#?}");
    assert!(!add.operation_semantics_unresolved, "{add:#?}");
    let delete = bind(source("ip"), "ip netns delete foo");
    assert_eq!(delete.form_id.as_str(), "delete_namespace", "{delete:#?}");
    assert!(!delete.operation_semantics_unresolved, "{delete:#?}");
}
#[test]
fn attached_native_options_and_management_arguments_bind_without_residuals() {
    for (name, command, form) in [
        (
            "easyrsa",
            "easyrsa --vars=/tmp/vars",
            "executable_configuration_config_vars_attached",
        ),
        (
            "kubectl",
            "kubectl get pods --kubeconfig=/tmp/kubeconfig",
            "executable_configuration_config_kubeconfig_attached",
        ),
        (
            "lxd",
            "lxc init ubuntu:16.04 x -c security.privileged=true",
            "privileged_container_setup",
        ),
        (
            "lxd",
            "lxc config device add x x disk source=/ path=/mnt/ recursive=true",
            "container_device_setup",
        ),
        ("lxd", "lxc start x", "container_start"),
        ("lxd", "lxc exec x /bin/sh", "container_command"),
        (
            "lxd",
            "lxc image import ./alpine.tar.gz --alias x",
            "image_import",
        ),
        (
            "systemctl",
            "systemctl link /tmp/temp-file.service",
            "link_executable_service_unit",
        ),
        (
            "systemctl",
            "systemctl daemon-reload",
            "daemon_reload_unit_files",
        ),
        (
            "systemctl",
            "systemctl enable --now /tmp/temp-file.service",
            "enable_start_unit",
        ),
        (
            "systemctl",
            "SYSTEMD_EDITOR=/tmp/editor systemctl edit basic.target",
            "edit_unit_via_editor",
        ),
    ] {
        let b = bind(source(name), command);
        assert_eq!(b.form_id.as_str(), form, "{command}: {b:#?}");
        assert!(!b.operation_semantics_unresolved, "{command}: {b:#?}");
    }
    let proxy = bind(
        source("kubectl"),
        "kubectl proxy --address=0.0.0.0 --port=12345 --www=/tmp/www --www-prefix=/x/",
    );
    assert_eq!(proxy.form_id.as_str(), "proxy_listener", "{proxy:#?}");
    assert!(effect(&proxy, EffectKind::ListenNetwork), "{proxy:#?}");
    assert!(effect(&proxy, EffectKind::ReadPath), "{proxy:#?}");
}
#[test]
fn fail2ban_callback_payload_and_jail_control_are_separate() {
    let callback = bind(
        source("fail2ban-client"),
        "fail2ban-client set x action x actionban /tmp/command",
    );
    assert_eq!(
        callback.form_id.as_str(),
        "action_callback",
        "{callback:#?}"
    );
    assert!(
        !effect(&callback, EffectKind::ExecutePayload),
        "setting the persistent action does not invoke it: {callback:#?}"
    );
    assert!(
        !effect(&callback, EffectKind::ControlProcess),
        "{callback:#?}"
    );
    let trigger = bind(source("fail2ban-client"), "fail2ban-client start x");
    assert_eq!(
        trigger.form_id.as_str(),
        "action_hook_trigger",
        "{trigger:#?}"
    );
    assert!(effect(&trigger, EffectKind::ExecuteHook), "{trigger:#?}");
    let change = bind(
        source("fail2ban-client"),
        "fail2ban-client banip 192.0.2.44",
    );
    assert_eq!(
        change.form_id.as_str(),
        "action_hook_trigger",
        "{change:#?}"
    );
    assert!(effect(&change, EffectKind::ExecuteHook), "{change:#?}");
    assert!(!effect(&change, EffectKind::ControlProcess), "{change:#?}");
    assert!(!effect(&change, EffectKind::ExecutePayload), "{change:#?}");
}
#[test]
fn virsh_xml_hook_boundary_and_volume_path_roles_are_distinct() {
    let xml = bind(
        source("virsh"),
        "virsh -c qemu:///system create /tmp/domain.xml",
    );
    assert_eq!(xml.form_id.as_str(), "create_domain_from_xml", "{xml:#?}");
    assert!(effect(&xml, EffectKind::ReadPath), "{xml:#?}");
    assert!(effect(&xml, EffectKind::LoadConfig), "{xml:#?}");
    assert!(effect(&xml, EffectKind::ExecutePayload), "{xml:#?}");
    let up = bind(
        source("virsh"),
        "virsh -c qemu:///system vol-upload --pool x /tmp/remote-output /tmp/input",
    );
    assert_eq!(
        up.form_id.as_str(),
        "upload_local_file_to_volume",
        "{up:#?}"
    );
    assert!(effect(&up, EffectKind::ReadPath), "{up:#?}");
    assert!(argument(&up, "local_data_path", "/tmp/input"), "{up:#?}");
    let volume_xml = bind(
        source("virsh"),
        "virsh -c qemu:///system vol-create --pool x --file /tmp/volume.xml",
    );
    assert_eq!(
        volume_xml.form_id.as_str(),
        "create_volume_from_xml",
        "{volume_xml:#?}"
    );
    assert!(effect(&volume_xml, EffectKind::ReadPath), "{volume_xml:#?}");
    assert!(
        effect(&volume_xml, EffectKind::LoadConfig),
        "{volume_xml:#?}"
    );
    assert!(
        effect(&volume_xml, EffectKind::WritePath),
        "{volume_xml:#?}"
    );
    assert!(
        !effect(&volume_xml, EffectKind::ExecutePayload),
        "volume XML defines storage, not executable content: {volume_xml:#?}"
    );
    let down = bind(
        source("virsh"),
        "virsh -c qemu:///system vol-download --pool x input-file /tmp/download",
    );
    assert_eq!(
        down.form_id.as_str(),
        "download_volume_to_local_file",
        "{down:#?}"
    );
    assert!(effect(&down, EffectKind::WritePath), "{down:#?}");
    assert!(
        argument(&down, "local_output_path", "/tmp/download"),
        "{down:#?}"
    );
}
#[test]
fn redis_inventory_label_reuses_native_cli_database_semantics() {
    fn db(command: &str, expected: DatabaseOperationKind) {
        let b = bind(source("redis"), command);
        let found = b
            .effects
            .iter()
            .filter_map(|e| e.database_operation)
            .collect::<Vec<_>>();
        assert_eq!(found, [expected], "{command}: {b:#?}");
    }
    db("redis-cli GET key", DatabaseOperationKind::Read);
    db(
        "redis-cli CONFIG SET dir /tmp",
        DatabaseOperationKind::Administration,
    );
    db("redis-cli SAVE", DatabaseOperationKind::Administration);
    db("redis-cli EVAL 'return 1' 0", DatabaseOperationKind::Opaque);
    let interactive = bind(source("redis"), "redis-cli");
    assert_eq!(
        interactive.form_id.as_str(),
        "interactive_or_command_stream"
    );
    assert!(
        effect(&interactive, EffectKind::ConsumeStdin),
        "{interactive:#?}"
    );
    let help = bind(source("redis"), "redis-cli --help");
    assert_eq!(help.form_id.as_str(), "information");
    assert!(!effect(&help, EffectKind::ConsumeStdin), "{help:#?}");
}
#[test]
fn remaining_native_mechanisms_bind_payloads_paths_hooks_and_capabilities() {
    for (name, command, form) in [
        (
            "aws",
            "aws ec2 describe-instances --filter file:///tmp/filter.json",
            "local_file_parameter",
        ),
        (
            "ctr",
            "ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t alpine x /bin/sh",
            "container_run_with_host_bind",
        ),
        ("dmsetup", "dmsetup ls --exec /bin/sh", "device_mapper_exec"),
        ("dstat", "dstat --xxx", "external_python_plugin"),
        ("hg", "hg --config alias.x='!/bin/sh' x", "executable_alias"),
        ("loginctl", "loginctl user-status", "information_subcommand"),
        ("lxd", "lxc exec x /bin/sh", "container_command"),
        (
            "mosh-server",
            "mosh --server=mosh-server localhost /bin/sh",
            "server_shell_request",
        ),
        ("passwd", "passwd", "password_change_from_stdin"),
        (
            "plymouth",
            "plymouth ask-for-password --prompt=x --command=/bin/sh",
            "password_command_callback",
        ),
        (
            "podman",
            "podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh",
            "privileged_container_execution",
        ),
        (
            "service",
            "service ../../bin/sh",
            "service_name_path_execution",
        ),
        (
            "snap",
            "snap install /tmp/x.snap --dangerous --devmode",
            "install_hook_package",
        ),
        (
            "systemctl",
            "systemctl link /tmp/temp-file.service",
            "link_executable_service_unit",
        ),
        (
            "systemctl",
            "systemctl enable --now temp-file.service",
            "enable_start_unit",
        ),
        (
            "systemctl",
            "SYSTEMD_EDITOR=/tmp/editor systemctl edit basic.target",
            "edit_unit_via_editor",
        ),
        (
            "systemd-resolve",
            "systemd-resolve --status",
            "information_subcommand",
        ),
        (
            "tailscale",
            "tailscale serve --http=12345 /tmp/input",
            "serve_local_file",
        ),
        (
            "timedatectl",
            "timedatectl list-timezones",
            "information_subcommand",
        ),
        (
            "unsquashfs",
            "unsquashfs /tmp/archive.squashfs",
            "extract_filesystem_archive",
        ),
        (
            "wg-quick",
            "wg-quick up /tmp/wg0.conf",
            "interface_up_from_executable_config",
        ),
        (
            "opkg",
            "opkg install /tmp/package.ipk",
            "install_local_package_hook",
        ),
        (
            "procmail",
            "procmail -m /tmp/procmailrc",
            "executable_configuration_config_m",
        ),
    ] {
        let b = bind(source(name), command);
        assert_eq!(b.form_id.as_str(), form, "{command}: {b:#?}");
    }
    let podman = bind(
        source("podman"),
        "podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh",
    );
    assert!(effect(&podman, EffectKind::ExecutePayload), "{podman:#?}");
    assert!(argument(&podman, "container_argv", "chroot"), "{podman:#?}");
    assert!(
        !effect(&podman, EffectKind::DispatchCommand),
        "container argv must not become a host child: {podman:#?}"
    );
    let ctr = bind(
        source("ctr"),
        "ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x",
    );
    assert_eq!(
        ctr.form_id.as_str(),
        "container_run_with_host_bind",
        "{ctr:#?}"
    );
    assert!(
        !effect(&ctr, EffectKind::DispatchCommand),
        "container entrypoint is not a host child: {ctr:#?}"
    );
    assert!(
        argument(&ctr, "container_image", "docker.io/library/alpine:latest"),
        "{ctr:#?}"
    );
    for (name, command, path) in [
        (
            "aws",
            "aws ec2 describe-instances --filter file:///tmp/filter.json",
            "/tmp/filter.json",
        ),
        (
            "tailscale",
            "tailscale serve --http=12345 /tmp/input",
            "/tmp/input",
        ),
        (
            "unsquashfs",
            "unsquashfs /tmp/archive.squashfs",
            "/tmp/archive.squashfs",
        ),
        ("opkg", "opkg install /tmp/package.ipk", "/tmp/package.ipk"),
        ("procmail", "procmail -m /tmp/procmailrc", "/tmp/procmailrc"),
    ] {
        let b = bind(source(name), command);
        assert!(
            b.effects.iter().any(|e| e.kind == EffectKind::ReadPath),
            "{command}: {b:#?}"
        );
        assert!(
            b.bound_parameters
                .iter()
                .flat_map(|p| &p.values)
                .any(|v| matches!(v,BoundValue::Argument{text,..} if text==path)),
            "{command}: {b:#?}"
        );
    }
    for (name, command) in [
        ("loginctl", "loginctl user-status"),
        ("systemd-resolve", "systemd-resolve --status"),
        ("timedatectl", "timedatectl list-timezones"),
    ] {
        assert!(
            effect(
                &bind(source(name), command),
                EffectKind::OpenInteractiveEscapeSurface
            ),
            "{command}"
        );
    }
    let extracted = bind(
        source("unsquashfs"),
        "unsquashfs -d /opt/shared/output /tmp/archive.squashfs",
    );
    assert!(effect(&extracted, EffectKind::ReadPath), "{extracted:#?}");
    assert!(effect(&extracted, EffectKind::WritePath), "{extracted:#?}");
    assert!(
        argument(&extracted, "extraction_directory", "/opt/shared/output"),
        "{extracted:#?}"
    );
    assert!(
        argument(&extracted, "squashfs_archive", "/tmp/archive.squashfs"),
        "{extracted:#?}"
    );
}

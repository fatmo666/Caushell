use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, ResolveInvocationResult, resolve_invocation,
};
use caushell_types::ShellKind;
use std::sync::OnceLock;

fn resolve_result(command: &str) -> ResolveInvocationResult<'static> {
    static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| ProfileRegistry::built_in().unwrap());
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    resolve_invocation(
        registry,
        &parsed.commands[0],
        InvocationRuntimeContext::new(),
    )
}

fn resolve(command: &str) -> BoundInvocation {
    match resolve_result(command) {
        ResolveInvocationResult::Resolved(result) => {
            assert!(result.bound.residuals.is_empty(), "{command}: {result:?}");
            result.bound
        }
        other => panic!("{command}: {other:?}"),
    }
}

fn values<'a>(bound: &'a BoundInvocation, name: &str) -> Vec<&'a str> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == name)
        .flat_map(|parameter| &parameter.values)
        .map(|value| match value {
            BoundValue::Argument { text, .. } => text.as_str(),
            _ => panic!("expected argument: {value:?}"),
        })
        .collect()
}

fn effect_slots(bound: &BoundInvocation, kind: EffectKind) -> Vec<&str> {
    bound
        .effects
        .iter()
        .filter(|effect| effect.kind == kind)
        .map(|effect| match &effect.target {
            EffectTarget::Slot(slot) => slot.as_str(),
            other => panic!("expected slot: {other:?}"),
        })
        .collect()
}

#[test]
fn nvidia_smi_registers_only_its_real_name() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in ["nvidia-smi", "/usr/bin/nvidia-smi"] {
        let profile = registry.lookup(name).profile.unwrap();
        assert_eq!(profile.primary_name(), "nvidia-smi");
        assert!(profile.identity.aliases.is_empty());
    }
    println!(
        "registry_profile_count={} registry_name_count={}",
        registry.len(),
        registry
            .profiles()
            .iter()
            .map(|p| 1 + p.identity.aliases.len())
            .sum::<usize>()
    );
}

#[test]
fn nvidia_smi_queries_bind_device_ids_and_filters_as_plain_values() {
    for command in [
        "nvidia-smi",
        "nvidia-smi -L",
        "nvidia-smi --list-excluded-gpus",
        "nvidia-smi -col",
        "nvidia-smi -q -u -x --dtd -i 0",
        "nvidia-smi --query --id=0000:01:00.0 --display=MEMORY,ECC -l",
        "nvidia-smi --query-gpu=name,power.draw --format=csv,noheader,nounits -lms 500",
        "nvidia-smi --query-compute-apps=pid,used_memory --format csv -l 2",
        "nvidia-smi --query-accounted-apps=pid --format=csv --loop-ms=1000",
        "nvidia-smi --query-supported-clocks=memory,graphics --format=csv",
        "nvidia-smi --query-retired-pages=address --format=csv",
        "nvidia-smi --query-remapped-rows=gpu_uuid --format=csv",
        "nvidia-smi -lmi",
        "nvidia-smi -gvfd",
        "nvidia-smi --get-hostname -eom",
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), "device_query", "{command}");
        assert!(bound.effects.is_empty(), "{command}: {bound:?}");
        assert!(
            bound
                .bound_parameters
                .iter()
                .all(|p| matches!(p.semantic, caushell_profile::SemanticType::PlainValue)),
            "{command}: {bound:?}"
        );
    }
    let bound =
        resolve("nvidia-smi --id=GPU-abcd --query-gpu=name,power.draw --format=csv -lms 500");
    assert_eq!(values(&bound, "gpu_ids"), ["GPU-abcd"]);
    assert_eq!(values(&bound, "query_fields"), ["name,power.draw"]);
    assert_eq!(values(&bound, "loop_milliseconds"), ["500"]);
    assert!(values(&bound, "loop_seconds").is_empty());
}

#[test]
fn nvidia_smi_approved_operations_are_explicit_forms_not_query_or_process_effects() {
    for (command, form) in [
        ("nvidia-smi -i 0 -pl 200", "set_power_limit"),
        (
            "nvidia-smi --power-limit=200.5 --scope=0 --id=GPU-abcd",
            "set_power_limit",
        ),
        ("nvidia-smi -sc 2 -pl 200", "set_power_limit"),
        ("nvidia-smi -i 0 --gpu-reset", "reset_gpu"),
        ("nvidia-smi -r", "reset_gpu"),
        ("nvidia-smi -r bus -i 0,1", "reset_gpu"),
        ("nvidia-smi --gpu-reset --id=0000:01:00.0", "reset_gpu"),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}");
        assert!(bound.effects.is_empty(), "{command}: {bound:?}");
        assert!(
            bound
                .bound_parameters
                .iter()
                .all(|p| matches!(p.semantic, caushell_profile::SemanticType::PlainValue)),
            "{command}: {bound:?}"
        );
    }
    let bound = resolve("nvidia-smi -i 0 -pl 200");
    assert_eq!(values(&bound, "power_watts"), ["200"]);
    assert_eq!(values(&bound, "gpu_ids"), ["0"]);
    assert!(values(&bound, "loop_seconds").is_empty());
}

#[test]
fn nvidia_smi_file_and_debug_outputs_are_independent_write_effects() {
    for command in [
        "nvidia-smi -q -f report.xml --debug=debug.log",
        "nvidia-smi --filename=report.xml --debug debug.log",
        "nvidia-smi -i 0 -pl 200 -f report.xml --debug=debug.log",
        "nvidia-smi --gpu-reset --filename=report.xml --debug debug.log",
    ] {
        let bound = resolve(command);
        assert_eq!(values(&bound, "query_output"), ["report.xml"]);
        assert_eq!(values(&bound, "debug_output"), ["debug.log"]);
        let mut writes = effect_slots(&bound, EffectKind::WritePath);
        writes.sort_unstable();
        assert_eq!(writes, ["debug_output", "query_output"]);
    }
}

#[test]
fn nvidia_smi_monitors_preserve_their_own_option_meanings() {
    for (command, form) in [
        ("nvidia-smi dmon", "monitor_devices"),
        (
            "nvidia-smi dmon -i 0,1 -s pucm -c 4 -d 2 -o DT --gpm-metrics 1,2 --gpm-options dm --format csv,nounit",
            "monitor_devices",
        ),
        ("nvidia-smi pmon", "monitor_processes"),
        (
            "nvidia-smi pmon -i 0 -s um -c 4 -d 2 -o DT",
            "monitor_processes",
        ),
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}");
        assert!(bound.effects.is_empty(), "{command}: {bound:?}");
        if command.contains("-c 4") {
            assert_eq!(values(&bound, "sample_count"), ["4"]);
            assert_eq!(values(&bound, "sample_seconds"), ["2"]);
            assert!(values(&bound, "display_fields").is_empty());
            assert!(values(&bound, "unmodeled_control_values").is_empty());
        }
    }
}

#[test]
fn nvidia_smi_topology_does_not_invent_paths_or_network_endpoints() {
    for command in [
        "nvidia-smi topo -m",
        "nvidia-smi topo -mp",
        "nvidia-smi topo -c 0",
        "nvidia-smi topo -n 1 -i 0",
        "nvidia-smi topo -p -i 0,1",
        "nvidia-smi topo -p2p r",
        "nvidia-smi topo -C -i 0",
        "nvidia-smi topo -M -i 0",
        "nvidia-smi topo -gnid -i 0",
        "nvidia-smi topo -nvme",
        "nvidia-smi topo -cpu",
        "nvidia-smi topo -gpu",
        "nvidia-smi topo -nic",
        "nvidia-smi topo -all",
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), "query_topology", "{command}");
        assert!(bound.effects.is_empty(), "{command}: {bound:?}");
    }
}

#[test]
fn nvidia_smi_replay_f_reads_and_r_writes_instead_of_using_root_flags() {
    let bound = resolve(
        "nvidia-smi replay -f /var/log/nvstats/log -r out.txt -s pum -i 0 -b 01:00:00 -e 02:00:00",
    );
    assert_eq!(bound.form_id.as_str(), "replay_log");
    assert_eq!(values(&bound, "replay_input"), ["/var/log/nvstats/log"]);
    assert_eq!(values(&bound, "replay_output"), ["out.txt"]);
    assert_eq!(effect_slots(&bound, EffectKind::ReadPath), ["replay_input"]);
    assert_eq!(
        effect_slots(&bound, EffectKind::WritePath),
        ["replay_output"]
    );
    for name in ["query_output", "reset_type", "unmodeled_control_values"] {
        assert!(values(&bound, name).is_empty(), "{name}: {bound:?}");
    }
}

#[test]
fn nvidia_smi_information_has_no_file_writes() {
    for command in [
        "nvidia-smi -h",
        "nvidia-smi --help",
        "nvidia-smi --version",
        "nvidia-smi --help-query-gpu",
        "nvidia-smi --help-query-remapped-rows",
        "nvidia-smi dmon -h",
        "nvidia-smi pmon -h",
        "nvidia-smi topo -h",
        "nvidia-smi replay -h",
    ] {
        let bound = resolve(command);
        assert_eq!(bound.form_id.as_str(), "information", "{command}");
        assert!(bound.effects.is_empty(), "{command}: {bound:?}");
    }
    // Mixed help/operand invocations need not be fully covered, but must not
    // invent writes which the information-only form does not perform.
    for command in [
        "nvidia-smi -h -f /etc/out",
        "nvidia-smi replay -h -r /etc/out",
    ] {
        match resolve_result(command) {
            ResolveInvocationResult::Resolved(result) => {
                assert!(result.bound.effects.is_empty(), "{command}: {result:?}")
            }
            other => panic!("{command}: {other:?}"),
        }
    }
}

#[test]
fn nvidia_smi_unapproved_controls_and_subcommands_are_not_query_forms() {
    for command in [
        "nvidia-smi -pm 1",
        "nvidia-smi --persistence-mode=1",
        "nvidia-smi -e 1",
        "nvidia-smi -c 1",
        "nvidia-smi -dm 1",
        "nvidia-smi -fdm 1",
        "nvidia-smi -lgc 1500,1500",
        "nvidia-smi -rgc",
        "nvidia-smi -rac",
        "nvidia-smi -mig 1",
        "nvidia-smi --multi-instance-gpu=1",
        "nvidia-smi -pl 200 --ecc-config=1",
        "nvidia-smi -pl 200 --gpu-reset",
        "nvidia-smi daemon",
        "nvidia-smi daemon -t",
        "nvidia-smi mig -cgi 0",
        "nvidia-smi clocks --auto-boost-default=0",
        "nvidia-smi drain -m 1",
        "nvidia-smi unexpected-subcommand",
        "nvidia-smi replay",
    ] {
        assert!(
            matches!(
                resolve_result(command),
                ResolveInvocationResult::SelectionError { .. }
            ),
            "{command}: {:?}",
            resolve_result(command)
        );
    }
}

#[test]
fn nvidia_smi_missing_required_operands_remain_visible() {
    for command in [
        "nvidia-smi -pl",
        "nvidia-smi -i",
        "nvidia-smi -f",
        "nvidia-smi --debug",
        "nvidia-smi -lms",
        "nvidia-smi dmon -c",
        "nvidia-smi replay -f",
    ] {
        if let ResolveInvocationResult::Resolved(result) = resolve_result(command) {
            assert!(!result.bound.residuals.is_empty(), "{command}: {result:?}");
        }
    }
}

#[test]
fn nvidia_smi_unknown_flags_do_not_activate_declared_operations() {
    // The existing all_arguments binder is not a CLI validity checker and
    // does not universally emit residuals for unknown flags. Do not claim a
    // new rejection policy here: verify only exact matching, not coverage.
    for command in [
        "nvidia-smi --unrecognized-control",
        "nvidia-smi -pl200",
        "nvidia-smi -i0",
    ] {
        if let ResolveInvocationResult::Resolved(result) = resolve_result(command) {
            assert!(
                result.bound.applied_modifiers.is_empty(),
                "{command}: {:?}",
                result.bound
            );
            assert!(
                result.bound.effects.is_empty(),
                "{command}: {:?}",
                result.bound
            );
        }
    }
}

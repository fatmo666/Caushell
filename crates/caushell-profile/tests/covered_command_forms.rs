//! Binding only: no media tool, network tool or PHP code is executed.
use caushell_parse::parse_command;
use caushell_profile::*;
use caushell_types::{DerivedPathRule, ShellKind};

fn resolve(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    match resolve_invocation_with_bindings(
        &ProfileRegistry::built_in().unwrap(),
        &parsed.commands[0],
        InvocationRuntimeContext::default(),
        &SessionBindings::new(),
    ) {
        ResolveInvocationResult::Resolved(r) => {
            assert!(!r.bound.operation_semantics_unresolved, "{command}: {r:#?}");
            assert!(r.bound.residuals.is_empty(), "{command}: {r:#?}");
            r.bound
        }
        r => panic!("{command}: {r:#?}"),
    }
}
fn count(bound: &BoundInvocation, name: &str) -> usize {
    bound
        .bound_parameters
        .iter()
        .filter(|p| p.name.as_str() == name)
        .map(|p| p.values.len())
        .sum()
}
fn effect(bound: &BoundInvocation, kind: EffectKind, name: &str) -> bool {
    bound
        .effects
        .iter()
        .any(|e| e.kind == kind && matches!(&e.target, EffectTarget::Slot(s) if s.as_str() == name))
}

#[test]
fn ffmpeg_binds_all_inputs_outputs_and_not_codec_values() {
    let b = resolve("ffmpeg -i a.mp4 -i b.mp4 -c:v libx264 -crf 19 first.mp4 -map 1 second.mp4");
    assert_eq!(b.form_id.as_str(), "transcode_local_media");
    assert_eq!(count(&b, "input_paths"), 2);
    assert_eq!(count(&b, "output_paths"), 2);
    assert!(effect(&b, EffectKind::ReadPath, "input_paths"));
    assert!(effect(&b, EffectKind::WritePath, "output_paths"));
    assert!(b.effects.iter().any(|e| matches!(&e.target, EffectTarget::DerivedPath(p) if p.rule == DerivedPathRule::SiblingFiles)));
}

#[test]
fn ffmpeg_stdio_is_not_a_file_named_dash() {
    let b = resolve("ffmpeg -i - -f flv -");
    assert_eq!(count(&b, "input_paths"), 0);
    assert_eq!(count(&b, "output_paths"), 0);
    assert_eq!(count(&b, "input_stream"), 1);
    assert_eq!(count(&b, "stdout_output"), 1);
    assert!(effect(&b, EffectKind::ConsumeStdin, "input_stream"));
}

#[test]
fn ffmpeg_ladspa_is_still_a_code_loading_form() {
    let b = resolve("ffmpeg -f lavfi -i anullsrc -af ladspa=file=/opt/lib.so local.wav");
    assert_eq!(b.form_id.as_str(), "lavfi_ladspa_load");
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::LoadInProcessCode)
    );
}

#[test]
fn ip_query_forms_have_no_mutation_or_dispatch_effects() {
    for command in [
        "ip addr show en0",
        "ip -j -4 route",
        "ip link show",
        "ip neighbour list",
        "ip tcp_metrics show",
        "ip route get 192.0.2.1",
        "ip -n lab addr show dev eth0",
    ] {
        let b = resolve(command);
        assert!(b.form_id.as_str().starts_with("query_"), "{command}");
        assert!(b.effects.is_empty(), "{command}: {b:#?}");
        assert_eq!(
            b.stream_contract.unwrap().stdin_mode,
            StreamInputMode::Ignored
        );
    }
}

#[test]
fn php_lint_retains_reads_without_payload_execution() {
    for command in [
        "php -l a.php",
        "php --syntax-check /opt/a.php",
        "php -n -l a.php b.php",
        "php -l",
    ] {
        let b = resolve(command);
        assert_eq!(
            b.form_id.as_str(),
            if command == "php -l" {
                "lint_stdin"
            } else {
                "lint_files"
            }
        );
        assert_eq!(
            effect(&b, EffectKind::ReadPath, "lint_paths"),
            command != "php -l"
        );
        assert!(
            !b.effects.iter().any(|e| matches!(
                e.kind,
                EffectKind::ExecutePayload
                    | EffectKind::DispatchCommand
                    | EffectKind::LoadInProcessCode
            )),
            "{command}: {b:#?}"
        );
    }
}

#[test]
fn php_information_does_not_reclassify_normal_execution() {
    for command in ["php -m", "php --modules"] {
        assert_eq!(resolve(command).form_id.as_str(), "information");
    }
    for command in ["php -i", "php --info"] {
        let b = resolve(command);
        assert_eq!(b.form_id.as_str(), "runtime_information");
        assert!(
            b.bound_implicit_inputs
                .iter()
                .any(|i| i.source == ImplicitInputSource::InheritedEnvironment)
        );
    }
    let b = resolve("php script.php -l");
    assert_eq!(b.form_id.as_str(), "script_file");
    assert!(
        b.effects
            .iter()
            .any(|e| e.kind == EffectKind::ExecutePayload)
    );
}

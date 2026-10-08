use caushell_parse::parse_command;
use caushell_profile::{
    BoundInvocation, BoundValue, EffectKind, EffectTarget, InvocationRuntimeContext,
    ProfileRegistry, SemanticValueResolution, StreamInputMode, StreamOutputMode, bind_invocation,
    load_command_profile_from_str, project_invocation, select_invocation,
};
use caushell_types::ShellKind;

const NTPDATE: &str = include_str!("../profiles/ntpdate.yaml");
const CHECK_CUPS: &str = include_str!("../profiles/check_cups.yaml");
const CHECK_MEMORY: &str = include_str!("../profiles/check_memory.yaml");
const CHECK_RAID: &str = include_str!("../profiles/check_raid.yaml");
const BBOT: &str = include_str!("../profiles/bbot.yaml");
const MOSQUITTO: &str = include_str!("../profiles/mosquitto.yaml");
const KSSHELL: &str = include_str!("../profiles/ksshell.yaml");
const TERRAFORM: &str = include_str!("../profiles/terraform.yaml");
const XMODMAP: &str = include_str!("../profiles/xmodmap.yaml");
const SEVEN_Z: &str = include_str!("../profiles/7z.yaml");

fn registry() -> ProfileRegistry {
    ProfileRegistry::from_profiles(
        [
            NTPDATE,
            CHECK_CUPS,
            CHECK_MEMORY,
            CHECK_RAID,
            BBOT,
            MOSQUITTO,
            KSSHELL,
            TERRAFORM,
            XMODMAP,
            SEVEN_Z,
        ]
        .into_iter()
        .map(|yaml| load_command_profile_from_str(yaml).unwrap())
        .collect(),
    )
    .unwrap()
}

fn bind(command: &str) -> BoundInvocation {
    let parsed = parse_command(command, ShellKind::Bash).unwrap();
    let profile = registry();
    let projected = project_invocation(&parsed.commands[0], InvocationRuntimeContext::new());
    let command_name = projected.command_name.as_deref().unwrap();
    let command_profile = profile.lookup(command_name).profile.unwrap();
    let selected = select_invocation(command_profile, &projected)
        .unwrap_or_else(|error| panic!("{command}: {error}"));
    bind_invocation(command_profile, &projected, &selected)
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

fn projected_values(bound: &BoundInvocation, slot: &str) -> Vec<String> {
    bound
        .bound_parameters
        .iter()
        .filter(|parameter| parameter.name.as_str() == slot)
        .flat_map(|parameter| parameter.projected_values.iter().flatten())
        .map(|value| match &value.resolution {
            SemanticValueResolution::Known(text) => text.clone(),
            other => panic!("unexpected projection for {slot}: {other:?}"),
        })
        .collect()
}

fn has_effect(bound: &BoundInvocation, kind: EffectKind, target: &str) -> bool {
    bound.effects.iter().any(|effect| {
        effect.kind == kind
            && matches!(&effect.target, EffectTarget::Slot(name) if name.as_str() == target)
    })
}

#[test]
fn all_ten_source_forms_select_named_semantics_and_bind_the_actual_file_operands() {
    let cases = [
        (
            "ntpdate -a x -k /opt/shared/keyfile -d localhost",
            "debug_key_file",
            "key_file_path",
            "/opt/shared/keyfile",
        ),
        (
            "check_cups --extra-opts=@/opt/shared/options.ini",
            "extra_options_file",
            "options_file",
            "/opt/shared/options.ini",
        ),
        (
            "check_memory --extra-opts=@/opt/shared/options.ini",
            "extra_options_file",
            "options_file",
            "/opt/shared/options.ini",
        ),
        (
            "check_raid --extra-opts=@/opt/shared/options.ini",
            "extra_options_file",
            "options_file",
            "/opt/shared/options.ini",
        ),
        (
            "bbot -d -cy /opt/shared/rules.yar",
            "custom_yara_rules",
            "custom_rules_file",
            "/opt/shared/rules.yar",
        ),
        (
            "mosquitto -c /opt/shared/mosquitto.conf",
            "start_broker_from_config",
            "config_path",
            "/opt/shared/mosquitto.conf",
        ),
        (
            "ksshell -i /opt/shared/kickstart.cfg",
            "load_kickstart_input",
            "input_file",
            "/opt/shared/kickstart.cfg",
        ),
        (
            "terraform console <<'EOF'\nfile(\"/opt/shared/input\")\nEOF",
            "console_expression_input",
            "",
            "",
        ),
        (
            "xmodmap -v /opt/shared/map",
            "verbose_map_file",
            "map_file",
            "/opt/shared/map",
        ),
        (
            "7z a -ttar -an -so /opt/shared/archive-input",
            "create_tar_stream",
            "input_paths",
            "/opt/shared/archive-input",
        ),
    ];
    for (command, form, path_slot, path) in cases {
        let bound = bind(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert!(
            !bound.operation_semantics_unresolved,
            "{command}: {bound:#?}"
        );
        assert!(bound.residuals.is_empty(), "{command}: {bound:#?}");
        if !path_slot.is_empty() {
            let found = if path_slot == "options_file" {
                projected_values(&bound, path_slot)
            } else {
                values(&bound, path_slot)
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            };
            assert_eq!(found, [path], "{command}: {bound:#?}");
            assert!(
                has_effect(&bound, EffectKind::ReadPath, path_slot),
                "{command}: {bound:#?}"
            );
        }
    }
}

#[test]
fn option_values_keep_their_real_roles_and_do_not_turn_into_paths() {
    let ntpdate = bind("ntpdate -a 17 -k /tmp/keyfile -d localhost");
    assert_eq!(values(&ntpdate, "key_id"), ["17"]);
    assert_eq!(values(&ntpdate, "key_file_path"), ["/tmp/keyfile"]);
    assert_eq!(values(&ntpdate, "servers"), ["localhost"]);
    assert!(!values(&ntpdate, "key_file_path").contains(&"17"));

    for command in [
        "check_cups --extra-opts=@/tmp/options.ini",
        "check_memory --extra-opts=@/tmp/options.ini",
        "check_raid --extra-opts=@/tmp/options.ini",
    ] {
        let bound = bind(command);
        assert_eq!(values(&bound, "extra_opts_value"), ["@/tmp/options.ini"]);
        assert_eq!(
            projected_values(&bound, "options_file"),
            ["/tmp/options.ini"]
        );
        assert!(!projected_values(&bound, "options_file").contains(&"@/tmp/options.ini".into()));
    }

    let bbot = bind("bbot -d -cy /tmp/rules.yar");
    assert_eq!(values(&bbot, "custom_rules_file"), ["/tmp/rules.yar"]);
    assert!(
        !bbot
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint)
    );

    let seven = bind("7z a -ttar -an -so /tmp/input.tar");
    assert_eq!(values(&seven, "input_paths"), ["/tmp/input.tar"]);
    assert!(!values(&seven, "input_paths").contains(&"-ttar"));
    assert!(!values(&seven, "input_paths").contains(&"-so"));
}

#[test]
fn compact_bbot_option_is_exact_and_c_and_y_remain_independent() {
    let compact = bind("bbot -d -cy /tmp/rules.yar");
    assert_eq!(compact.form_id.as_str(), "custom_yara_rules");
    assert_eq!(values(&compact, "custom_rules_file"), ["/tmp/rules.yar"]);

    let separate = parse_command(
        "bbot -d -c modules.excavate.custom_yara_rules=/tmp/config-value -y",
        ShellKind::Bash,
    )
    .unwrap();
    let profiles = registry();
    let profile = profiles.lookup("bbot").profile.unwrap();
    let projected = project_invocation(&separate.commands[0], InvocationRuntimeContext::new());
    assert!(select_invocation(profile, &projected).is_err());
}

#[test]
fn ntpdate_clock_mutation_requires_separate_unmodeled_invocations() {
    let debug = bind("ntpdate -a x -k /tmp/keyfile -d localhost");
    assert!(has_effect(&debug, EffectKind::ReadPath, "key_file_path"));
    assert!(has_effect(&debug, EffectKind::NetworkEndpoint, "servers"));
    assert!(
        !debug
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );

    // Without -d, the utility may step or slew the host clock and must not be
    // resolved by the source's debug-only file-read model.
    let ordinary =
        parse_command("ntpdate -a x -k /tmp/keyfile localhost", ShellKind::Bash).unwrap();
    let profiles = registry();
    let profile = profiles.lookup("ntpdate").profile.unwrap();
    let projected = project_invocation(&ordinary.commands[0], InvocationRuntimeContext::new());
    assert!(select_invocation(profile, &projected).is_err());
}

#[test]
fn stream_and_parser_boundaries_are_explicit_for_console_kickstart_mosquitto_and_7z() {
    let terraform = bind("terraform console <<'EOF'\nfile(\"/tmp/input\")\nEOF");
    let streams = terraform.stream_contract.unwrap();
    assert_eq!(streams.stdin_mode, StreamInputMode::PayloadRequired);
    assert!(
        terraform
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ConsumeStdin)
    );
    assert!(
        !terraform
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );

    for (command, form, path_slot) in [
        (
            "terraform console -var-file /tmp/vars.tfvars",
            "console_with_var_file",
            "variable_file",
        ),
        (
            "terraform console -state /tmp/terraform.tfstate",
            "console_with_state_file",
            "state_file",
        ),
    ] {
        let bound = bind(command);
        assert_eq!(bound.form_id.as_str(), form, "{command}: {bound:#?}");
        assert_eq!(
            values(&bound, path_slot),
            [if path_slot == "variable_file" {
                "/tmp/vars.tfvars"
            } else {
                "/tmp/terraform.tfstate"
            }],
            "{command}: {bound:#?}"
        );
        assert!(
            has_effect(&bound, EffectKind::ReadPath, path_slot),
            "{command}: {bound:#?}"
        );
    }

    let inline_var_file = bind("terraform console -var-file=/opt/shared/vars");
    assert_eq!(inline_var_file.form_id.as_str(), "console_expression_input");
    assert_eq!(
        values(&inline_var_file, "inline_variable_files"),
        ["/opt/shared/vars"]
    );
    assert!(has_effect(
        &inline_var_file,
        EffectKind::ReadPath,
        "inline_variable_files"
    ));

    let post_dashdash = bind("terraform console -- -var-file=/tmp/not-a-terraform-read");
    assert!(values(&post_dashdash, "inline_variable_files").is_empty());
    let empty_inline = bind("terraform console -var-file=");
    assert!(values(&empty_inline, "inline_variable_files").is_empty());
    let lookalike = bind("terraform console -var-file-extra=/tmp/not-a-var-file");
    assert!(values(&lookalike, "inline_variable_files").is_empty());

    let ksshell = bind("ksshell -i /tmp/input.cfg");
    assert_eq!(
        ksshell.stream_contract.unwrap().stdout_mode,
        StreamOutputMode::Data
    );
    assert!(
        ksshell
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ReadPath)
    );
    assert!(
        !ksshell
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::ExecutePayload)
    );
    let ksshell_output = bind("ksshell -i /tmp/input.cfg -o /tmp/output.cfg");
    assert!(has_effect(
        &ksshell_output,
        EffectKind::WritePath,
        "output_file"
    ));

    let mosquitto = bind("mosquitto -c /tmp/mosquitto.conf");
    assert!(
        mosquitto
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkEndpoint
                && effect.target == EffectTarget::None)
    );
    assert!(
        mosquitto
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );

    let create = bind("7z a -ttar -an -so /tmp/input");
    assert_eq!(
        create.stream_contract.unwrap().stdout_dependency,
        caushell_types::StreamDataDependency::Inputs
    );
    assert!(
        !create
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );
    let extract = bind("7z e -ttar -si -so");
    assert_eq!(extract.form_id.as_str(), "extract_tar_stream");
    assert_eq!(
        extract.stream_contract.unwrap().stdin_mode,
        StreamInputMode::DataRequired
    );
    assert!(
        !extract
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::WritePath)
    );
}

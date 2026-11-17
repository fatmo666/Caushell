use crate::{CommandProfile, EffectTarget, ImplicitConfigSource, NativeConfigurationSyntax};
use caushell_types::ExecutionFrameRequirements;

/// Profile-declared child-environment dependencies plus native locale inputs.
pub fn execution_frame_requirements<'a>(
    profiles: impl IntoIterator<Item = &'a CommandProfile>,
) -> ExecutionFrameRequirements {
    let mut requirements = ExecutionFrameRequirements {
        environment_series: Vec::new(),
        variable_names: Default::default(),
        environment_names: ["LC_ALL", "LC_CTYPE", "LANG"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        pathname: true,
    };
    for profile in profiles {
        if profile.native_configuration == Some(NativeConfigurationSyntax::Pip25_3Linux) {
            requirements.environment_names.extend(
                crate::PIP_CONFIGURATION_ENVIRONMENT
                    .iter()
                    .map(|s| (*s).into()),
            );
        }
        if profile.native_configuration == Some(NativeConfigurationSyntax::Git) {
            requirements.environment_names.extend(
                crate::GIT_CONFIGURATION_ENVIRONMENT
                    .iter()
                    .map(|s| (*s).into()),
            );
            requirements
                .environment_series
                .push(caushell_types::IndexedEnvironmentRequirement {
                    count_name: "GIT_CONFIG_COUNT".into(),
                    prefixes: vec!["GIT_CONFIG_KEY_".into(), "GIT_CONFIG_VALUE_".into()],
                    max_entries: 32,
                });
        }
        add_resource_inputs(&profile.forms, &profile.modifiers, &mut requirements);
        for over in &profile.dispatch_overrides {
            add_resource_inputs(&over.forms, &over.modifiers, &mut requirements);
        }
        if let Some(tree) = &profile.subcommands {
            for child in &tree.roots {
                add_subcommand_inputs(child, &mut requirements);
            }
        }
        if let Some(options) = &profile.option_environment {
            requirements.environment_names.insert(options.name.clone());
        }
        for input in &profile.environment_inputs {
            requirements
                .environment_names
                .insert(input.environment.name.clone());
        }
        for input in &profile.implicit_config_files {
            for source in &input.sources {
                if let ImplicitConfigSource::EnvironmentDirectory {
                    name,
                    unless_environment_set,
                    ..
                } = source
                {
                    requirements.environment_names.insert(name.clone());
                    requirements
                        .environment_names
                        .extend(unless_environment_set.iter().cloned());
                }
            }
        }
        for effect in &profile.selection_failure_effects {
            add_effect_inputs(effect, &mut requirements);
        }
    }
    requirements
}

fn add_subcommand_inputs(
    node: &crate::SubcommandNode,
    requirements: &mut ExecutionFrameRequirements,
) {
    add_resource_inputs(&node.forms, &node.modifiers, requirements);
    for child in &node.children {
        add_subcommand_inputs(child, requirements);
    }
}

fn add_resource_inputs(
    forms: &[crate::Form],
    modifiers: &[crate::Modifier],
    requirements: &mut ExecutionFrameRequirements,
) {
    for effect in forms
        .iter()
        .flat_map(|f| &f.effects)
        .chain(modifiers.iter().flat_map(|m| &m.effects))
    {
        add_effect_inputs(effect, requirements);
    }
}

fn add_effect_inputs(effect: &crate::Effect, requirements: &mut ExecutionFrameRequirements) {
    let names = &mut requirements.environment_names;
    names.extend(effect.resource_environment_absent.iter().cloned());
    match &effect.target {
        EffectTarget::ConfiguredPath(path) => {
            names.extend(path.environment.iter().map(|e| e.name.clone()));
            if let Some(anchor) = &path.relative_to {
                names.extend(anchor.environment.iter().map(|e| e.name.clone()));
            }
            if path.expand_user {
                names.insert("HOME".into());
            }
        }
        EffectTarget::Dispatch(dispatch) => {
            names.extend(
                dispatch
                    .unknown_environment_from
                    .iter()
                    .map(|e| e.name.clone()),
            );
        }
        EffectTarget::NetworkListener(listener) => {
            for scalar in std::iter::once(&listener.host)
                .chain(listener.port.iter())
                .chain(listener.unix_socket.iter())
                .chain(listener.inherited_fd.iter())
            {
                names.extend(scalar.environment.iter().map(|e| e.name.clone()));
            }
        }
        _ => {}
    }
}

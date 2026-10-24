use crate::CommandProfile;
use caushell_types::ExecutionFrameRequirements;

/// Profile-declared child-environment dependencies plus native locale inputs.
pub fn execution_frame_requirements<'a>(
    profiles: impl IntoIterator<Item = &'a CommandProfile>,
) -> ExecutionFrameRequirements {
    let mut requirements = ExecutionFrameRequirements {
        environment_names: ["LC_ALL", "LC_CTYPE", "LANG"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        pathname: true,
    };
    for profile in profiles {
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
        requirements
            .environment_names
            .extend(effect.resource_environment_absent.iter().cloned());
    }
}

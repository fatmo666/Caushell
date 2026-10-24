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

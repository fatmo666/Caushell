use crate::{
    CommandProfile, EnvironmentValueRef, MaterializedProjectedInvocation, ProjectedArg,
    OptionEnvironmentSyntax, ProjectedArgKind, SessionBindings, SessionValue, ValueMaterialization,
    argument_structure,
};

pub fn option_environment_observation(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    bindings: &SessionBindings,
) -> Option<(caushell_types::ShellEnvironmentSnapshot, bool)> {
    let input = profile.option_environment.as_ref()?;
    let prefix = crate::materialize_prefix_environment(command, bindings);
    Some(observe(&input.name, &prefix, bindings))
}

pub fn option_environment_observations(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    bindings: &SessionBindings,
) -> Vec<(caushell_types::ShellEnvironmentSnapshot, bool)> {
    let Some(input) = &profile.option_environment else {
        return Vec::new();
    };
    let prefix = crate::materialize_prefix_environment(command, bindings);
    input.names().map(|name| observe(name, &prefix, bindings)).collect()
}

fn observe(
    name: &str,
    prefix: &[(String, SessionValue)],
    bindings: &SessionBindings,
) -> (caushell_types::ShellEnvironmentSnapshot, bool) {
    let from_prefix = prefix.iter().rev().find(|(key, _)| key == name);
    let value = from_prefix
        .map(|(_, v)| EnvironmentValueRef::Present(v))
        .unwrap_or_else(|| bindings.environment_value(name));
    let value = match value {
        EnvironmentValueRef::Absent => caushell_types::ShellEnvironmentValue::Absent,
        EnvironmentValueRef::Present(SessionValue::ExactScalar(value))
        | EnvironmentValueRef::Present(SessionValue::RuntimeProduced { value, .. }) => {
            caushell_types::ShellEnvironmentValue::Present {
                value: value.clone(),
            }
        }
        _ => caushell_types::ShellEnvironmentValue::Unknown,
    };
    (
        caushell_types::ShellEnvironmentSnapshot {
            name: name.into(),
            value,
        },
        from_prefix.is_some(),
    )
}

pub(crate) fn prepend(
    profile: &CommandProfile,
    command: &caushell_parse::CommandFact,
    bindings: &SessionBindings,
    projection: &mut MaterializedProjectedInvocation,
) -> Result<(), String> {
    let Some(input) = &profile.option_environment else {
        return Ok(());
    };
    let prefix = crate::materialize_prefix_environment(command, bindings);
    if input.syntax == OptionEnvironmentSyntax::Bzip2 {
        let mut args = Vec::new();
        for name in input.names() {
            let (observation, _) = observe(name, &prefix, bindings);
            match observation.value {
                caushell_types::ShellEnvironmentValue::Absent => continue,
                caushell_types::ShellEnvironmentValue::Unknown => {
                    if prefix.iter().any(|(key, _)| key == name)
                        || bindings.environment_names().contains(name)
                    {
                        return Err(format!("{name} option bytes are unresolved"));
                    }
                }
                caushell_types::ShellEnvironmentValue::Present { value } => {
                    if value.len() > 65_536 || !value.is_ascii() || value.contains('\0') {
                        return Err(format!("{name} option syntax is unsupported"));
                    }
                    for word in value.split(|ch: char| ch.is_ascii_whitespace() || ch == '\x0b')
                        .filter(|word| !word.is_empty())
                    {
                        // Native bzip2 caps individual environment argument
                        // lengths. Decline all spellings near that bound.
                        if word.len() > 1000 || args.len() >= 4096 {
                            return Err(format!("{name} option syntax exceeds its budget"));
                        }
                        args.push(native_arg(word, &command.span));
                    }
                }
            }
        }
        if args.is_empty() {
            return Ok(());
        }
        let mut native_environment = projection.invocation.clone();
        native_environment.args = args;
        let ownership = crate::root_option_ownership(profile, &native_environment)
            .ok_or("bzip2 environment option grammar is unavailable")?;
        if ownership.ownership_unresolved
            || ownership.error.is_some()
            || ownership.terminator.is_some()
            || ownership.positionals.as_ref().is_some_and(|args| !args.is_empty())
            || !ownership.additional_positionals.is_empty()
        {
            return Err("bzip2 environment contains unresolved options or operands".into());
        }
        args = native_environment.args;
        if args.len() + projection.invocation.args.len() > 4096
            || args.iter().chain(&projection.invocation.args).map(|arg| arg.text.len()).sum::<usize>() > 65_536
        {
            return Err("effective option argv exceeds its budget".into());
        }
        let mut resolutions = vec![ValueMaterialization::Static; args.len()];
        args.append(&mut projection.invocation.args);
        resolutions.append(&mut projection.arg_resolutions);
        projection.invocation.args = args;
        projection.arg_resolutions = resolutions;
        return Ok(());
    }
    let value = prefix
        .iter()
        .rev()
        .find(|(name, _)| name == &input.name)
        .map(|(_, value)| EnvironmentValueRef::Present(value))
        .unwrap_or_else(|| bindings.environment_value(&input.name));
    let text = match value {
        EnvironmentValueRef::Absent | EnvironmentValueRef::Unknown => return Ok(()),
        EnvironmentValueRef::Present(SessionValue::ExactScalar(text))
        | EnvironmentValueRef::Present(SessionValue::RuntimeProduced { value: text, .. }) => text,
        _ => return Err(format!("{} option bytes are unresolved", input.name)),
    };
    let words = crate::dispatch_string::gnu_wordsplit(text).ok_or_else(|| {
        format!(
            "{} option syntax is unresolved or exceeds its budget",
            input.name
        )
    })?;
    if text.contains("$(") || text.contains('`') {
        return Err("native environment command substitution is unsupported".into());
    }
    if words.is_empty() {
        return Ok(());
    }
    let mut environment_invocation = projection.invocation.clone();
    environment_invocation.args = words
        .iter()
        .map(|text| native_arg(text, &command.span))
        .collect();
    let ownership = crate::root_option_ownership(profile, &environment_invocation)
        .ok_or("environment option grammar is not declared")?;
    if ownership.ownership_unresolved
        || ownership.error.is_some()
        || ownership.terminator.is_some()
        || ownership
            .positionals
            .as_ref()
            .is_some_and(|positions| !positions.is_empty())
        || !ownership.additional_positionals.is_empty()
    {
        return Err(format!(
            "{} has incomplete option ownership or non-option arguments",
            input.name
        ));
    }
    let argv = projection
        .invocation
        .args
        .iter()
        .map(|arg| argument_structure(arg).exact_value().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "environment options require complete explicit argv".to_string())?;
    let fields = modern_tar_fields(&argv)
        .ok_or_else(|| "old-style option ownership is unresolved".to_string())?;
    if words.len() + fields.len() > 4096
        || words
            .iter()
            .chain(argv.iter())
            .map(String::len)
            .sum::<usize>()
            > 65_536
    {
        return Err("effective option argv exceeds its budget".into());
    }
    let mut args: Vec<_> = words
        .iter()
        .map(|text| native_arg(text, &command.span))
        .collect();
    let mut resolutions: Vec<_> = words
        .into_iter()
        .map(|_| ValueMaterialization::Static)
        .collect();
    for (index, replacement) in fields {
        if let Some(flag) = replacement {
            args.push(native_arg(&flag, &projection.invocation.args[index].span));
            resolutions.push(ValueMaterialization::Static);
        } else {
            args.push(projection.invocation.args[index].clone());
            resolutions.push(projection.arg_resolutions[index].clone());
        }
    }
    projection.invocation.args = args;
    projection.arg_resolutions = resolutions;
    Ok(())
}

fn native_arg(text: &str, span: &caushell_parse::SourceSpan) -> ProjectedArg {
    ProjectedArg {
        word_context: Default::default(),
        text: text.to_owned(),
        implicit_input_source: None,
        runtime_argument_domain: None,
        runtime_data: true,
        substitution_shape: None,
        native_region_field: None,
        lexical_field_prefix: None,
        kind: if text == "--" {
            ProjectedArgKind::DashDash
        } else if text.starts_with('-') {
            ProjectedArgKind::Flag
        } else {
            ProjectedArgKind::Positional
        },
        quoted: true,
        node_kind: "environment_option_argv".into(),
        span: span.clone(),
    }
}

/// Old option letters own their following operands before environment options
/// are prepended. Other old grammars remain unproved, never positional data.
pub(crate) fn modern_tar_argv(argv: &[String]) -> Option<Vec<String>> {
    Some(
        modern_tar_fields(argv)?
            .into_iter()
            .map(|(index, replacement)| replacement.unwrap_or_else(|| argv[index].clone()))
            .collect(),
    )
}

fn modern_tar_fields(argv: &[String]) -> Option<Vec<(usize, Option<String>)>> {
    let Some(first) = argv.first() else {
        return Some(Vec::new());
    };
    if first.starts_with('-') {
        return Some((0..argv.len()).map(|index| (index, None)).collect());
    }
    if first.is_empty() || !first.bytes().all(|c| b"cxtrudAvphOPzjJSfC".contains(&c)) {
        return None;
    }
    let mut result = Vec::new();
    let mut operand = 1;
    for letter in first.chars() {
        result.push((0, Some(format!("-{letter}"))));
        if matches!(letter, 'f' | 'C') {
            argv.get(operand)?;
            result.push((operand, None));
            operand += 1;
        }
    }
    result.extend((operand..argv.len()).map(|index| (index, None)));
    Some(result)
}

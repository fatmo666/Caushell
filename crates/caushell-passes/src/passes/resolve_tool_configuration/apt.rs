//! Native APT configuration lifecycle. Selected by the profile's syntax contract,
//! not by command spelling, workspace names, benchmark labels or policy grants.
use super::*;
use caushell_profile::{
    AptConfiguration, ArgumentBindingSource, BoundValue, EnvironmentValueRef, SessionValue,
    materialize_prefix_environment,
};
use caushell_types::{
    DirectoryEntryKind, DirectoryReadLimits, DirectoryReadStatus, FilesystemEntry,
    SemanticResolution,
};

#[derive(Clone)]
struct OptionEvent {
    flag: String,
    value: Option<String>,
    span: SourceSpan,
}

// Only binding-owned options participate. Data after -- and projected hook bodies
// cannot create config switches, even if they happen to spell '-c' or '-o'.
fn events(
    bound: &BoundInvocation,
    argv: &[caushell_profile::ProjectedArg],
) -> Result<Vec<OptionEvent>, &'static str> {
    let mut found = BTreeMap::new();
    for p in bound
        .bound_parameters
        .iter()
        .filter(|p| p.structured_source.is_none())
    {
        for value in &p.values {
            if let BoundValue::Argument {
                text,
                binding_source,
                ..
            } = value
            {
                insert(&mut found, binding_source, Some(text.clone()));
            }
        }
    }
    for flag in &bound.modifier_parameter_flags {
        insert(&mut found, flag, None);
    }
    let mut ordered = Vec::new();
    for e in found.into_values() {
        let words = argv
            .iter()
            .filter(|a| {
                a.span.start_byte <= e.span.start_byte && a.span.end_byte >= e.span.end_byte
            })
            .collect::<Vec<_>>();
        if words.len() != 1 {
            return Err("APT option has ambiguous argv origin");
        }
        let word = argument_structure(words[0]);
        let word = word.exact_value().ok_or("APT option word is not exact")?;
        let offset = if word == e.flag || word.starts_with(&format!("{}=", e.flag)) {
            0
        } else if e.flag.len() == 2 && word.starts_with('-') && !word.starts_with("--") {
            word[1..]
                .find(e.flag.as_bytes()[1] as char)
                .map(|i| i + 1)
                .ok_or("APT owned short option is not in its source word")?
        } else {
            return Err("APT option ownership does not match its source word");
        };
        ordered.push((e.span.start_byte, offset, e));
    }
    ordered.sort_by_key(|(start, offset, _)| (*start, *offset));
    Ok(ordered.into_iter().map(|(_, _, e)| e).collect())
}
fn insert(
    found: &mut BTreeMap<(usize, usize, String), OptionEvent>,
    source: &ArgumentBindingSource,
    value: Option<String>,
) {
    if let ArgumentBindingSource::FollowingFlag {
        flag_name,
        flag_span,
    }
    | ArgumentBindingSource::MatchedModifierFlag {
        flag_name,
        flag_span,
        ..
    } = source
    {
        let flag = flag_name.as_str();
        if !matches!(
            flag,
            "-o" | "--option" | "-c" | "--config-file" | "-d" | "--download-only"
        ) {
            return;
        }
        let key = (flag_span.start_byte, flag_span.end_byte, flag.into());
        let e = found.entry(key).or_insert_with(|| OptionEvent {
            flag: flag.into(),
            value: None,
            span: flag_span.clone(),
        });
        if value.is_some() {
            e.value = value
        }
    }
}

pub(super) fn resolve(
    exp: &mut Expansion<'_>,
    record: ExecutionResolveRecordRef<'_>,
) -> ResolveInvocationArtifactResult {
    let mut result = record.result().clone();
    let ResolveInvocationArtifactResult::Resolved(original) = record.result() else {
        return result;
    };
    let command = record.command().unwrap();
    let bound = &original.bound;
    let options = match events(bound, &original.materialized_projection.invocation.args) {
        Ok(options) => options,
        Err(error) => {
            exp.error(error);
            return result;
        }
    };
    if bound.operation_semantics_unresolved
        && (bound.residuals.is_empty()
            || bound
                .residuals
                .iter()
                .any(|r| r.kind != ResidualKind::ConfigurationInput))
    {
        exp.error("APT operation is incomplete independently of configuration");
    }
    if original.materialized_projection.shell_expansion_unresolved
        || original
            .materialized_projection
            .invocation
            .args
            .iter()
            .any(|a| argument_structure(a).exact_value().is_none())
    {
        exp.error("APT argv is not completely materialized");
        return result;
    }
    // Help/version don't perform a package operation. Explicit configuration/hook
    // options still require inspection and retain their independent effects.
    if bound.form_id.as_str() == "information" && options.is_empty() {
        return result;
    }
    let mut config = AptConfiguration::default();
    let prefix = materialize_prefix_environment(command, record.bindings());
    let environment = prefix
        .iter()
        .rev()
        .find(|(k, _)| k == "APT_CONFIG")
        .map(|(_, v)| EnvironmentValueRef::Present(v))
        .unwrap_or_else(|| record.bindings().environment_value("APT_CONFIG"));
    match environment {
        EnvironmentValueRef::Absent => (),
        EnvironmentValueRef::Present(
            SessionValue::ExactScalar(p) | SessionValue::RuntimeProduced { value: p, .. },
        ) if !p.contains('\0') => {
            if !p.is_empty() {
                load(exp, &mut config, p, &command.span, true)
            }
        }
        _ => exp.error("APT_CONFIG presence/value is unknown in the owning execution frame"),
    }
    // Phase names are captured before loading that phase. Earlier configuration
    // may redirect the next phase; CLI overrides do not hide already-loaded files.
    if let Some(parts) = config.path("dir::etc::parts", exp.cwd.unwrap_or("")) {
        if !parts.is_empty() {
            for path in directory(exp, &parts).unwrap_or_default() {
                load(exp, &mut config, &path, &command.span, false)
            }
        }
    } else {
        exp.error("APT config parts path is unknown")
    }
    if let Some(main) = config.path("dir::etc::main", exp.cwd.unwrap_or("")) {
        if !main.is_empty() {
            load(exp, &mut config, &main, &command.span, true)
        }
    } else {
        exp.error("APT main config path is unknown")
    }
    for option in &options {
        match option.flag.as_str() {
            "-c" | "--config-file" => {
                if let Some(path) = &option.value {
                    load(exp, &mut config, path, &option.span, false)
                } else {
                    exp.error("APT config filename is unknown")
                }
            }
            "-o" | "--option" => {
                if let Some(value) = &option.value {
                    config.apply(value)
                } else {
                    config.error("APT configuration assignment is unknown")
                }
            }
            "-d" | "--download-only" => config.apply(&format!(
                "apt::get::download-only={}",
                option.value.as_deref().unwrap_or("true")
            )),
            _ => (),
        }
    }
    for observation in exp.evidence.directories.clone() {
        if exp
            .view
            .read_directory(&observation.path, observation.limits)
            .observation
            != observation
        {
            exp.error("APT configuration directory changed after loading files");
        }
    }
    for error in &config.errors {
        exp.error(error.clone())
    }
    let operation = bound
        .subcommand_path
        .first()
        .map(String::as_str)
        .unwrap_or("");
    // Do not erase any package-code effect when configuration is incomplete.
    if exp.evidence.errors.is_empty()
        && operation == "install"
        && config.download_only() == Some(true)
    {
        bound_mut(&mut result)
            .unwrap()
            .effects
            .retain(|e| e.kind != EffectKind::ExecuteImportedPackageLogic);
    }
    if matches!(operation, "download" | "update")
        || (operation == "install" && config.download_only() == Some(true))
    {
        let paths = exp
            .cwd
            .and_then(|cwd| config.package_outputs(operation, cwd));
        if let Some(paths) = paths {
            if exp.evidence.errors.is_empty() {
                let bound = bound_mut(&mut result).unwrap();
                bound.effects.retain(|e|!(e.kind==EffectKind::WritePath && matches!(&e.target,EffectTarget::ConfiguredPath(t) if t.sources.is_empty()&&t.default_value.is_none()&&t.environment.is_none()&&t.shell_variable.is_none())));
                for path in paths {
                    let mut effect = Effect::new(EffectKind::WritePath);
                    effect.target = concrete_target(path);
                    effect.namespace_effect =
                        Some(caushell_types::PathNamespaceEffect::DirectoryTreeWrite);
                    bound.effects.push(effect);
                }
            }
        } else {
            exp.error("APT output roots are unknown")
        }
    }
    if exp.evidence.errors.is_empty() {
        let bound = bound_mut(&mut result).unwrap();
        let only_configuration = !bound.residuals.is_empty()
            && bound
                .residuals
                .iter()
                .all(|r| r.kind == ResidualKind::ConfigurationInput);
        bound
            .residuals
            .retain(|r| r.kind != ResidualKind::ConfigurationInput);
        if only_configuration {
            bound.operation_semantics_unresolved = false;
        }
    }
    result
}

fn load(
    exp: &mut Expansion<'_>,
    config: &mut AptConfiguration,
    path: &str,
    span: &SourceSpan,
    missing_ok: bool,
) {
    let before = exp.tokens.len();
    exp.file(path, span, 0, missing_ok);
    let tokens = exp.tokens.split_off(before);
    for pair in tokens.chunks(2) {
        if pair.len() == 2 && pair[0].text == "-o" {
            config.apply(&pair[1].text)
        } else {
            exp.error("APT configuration token projection is incomplete")
        }
    }
}

// A stable complete listing is evidence about resources, never permission.
fn directory(exp: &mut Expansion<'_>, path: &str) -> Option<Vec<String>> {
    exp.requests += 1;
    if exp.requests > exp.request_limit {
        exp.error("APT directory observation budget exceeded");
        return None;
    }
    let mut ns = NamespaceResolver::new(exp.view.clone());
    let (resolution, observations) = ns.resolve(path, PathTargetAccess::Follow);
    exp.evidence
        .namespace_observations
        .extend(observations.clone());
    let concrete = match &resolution {
        SemanticResolution::Resolved { value } => value.concrete_path(),
        _ => None,
    };
    let Some(concrete) = concrete else {
        exp.error("APT directory namespace is unresolved");
        return None;
    };
    if touches(exp.writes, path) || touches(exp.writes, concrete) {
        exp.error("APT directory may change within this action");
        return None;
    }
    let limits = DirectoryReadLimits::default();
    let read = exp.view.read_directory(concrete, limits);
    exp.evidence.directories.push(read.observation.clone());
    let mut after_ns = NamespaceResolver::new(exp.view.clone());
    let (after, after_observations) = after_ns.resolve(path, PathTargetAccess::Follow);
    if resolution != after || observations != after_observations {
        exp.error("APT directory namespace changed during observation");
        return None;
    }
    if observations
        .iter()
        .any(|o| o.path == concrete && o.entry == FilesystemEntry::Missing)
        && read.observation.path == concrete
        && read.observation.limits == limits
        && read.observation.source != caushell_types::FilesystemObservationSource::Unavailable
        && read.observation.status == DirectoryReadStatus::Missing
    {
        return Some(Vec::new());
    }
    let Some(entries) = read.complete_entries(concrete, limits) else {
        exp.error("APT directory listing is incomplete");
        return None;
    };
    if exp.view.read_directory(concrete, limits) != read {
        exp.error("APT directory listing changed during observation");
        return None;
    }
    let mut paths = Vec::new();
    for entry in entries {
        let name = &entry.name;
        let valid = name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            && (!name.contains('.') || name.ends_with(".conf"));
        if valid
            && matches!(
                entry.kind,
                DirectoryEntryKind::File | DirectoryEntryKind::Symlink
            )
        {
            paths.push(format!("{}/{name}", concrete.trim_end_matches('/')))
        } else if valid && entry.kind == DirectoryEntryKind::Other {
            exp.error("APT config candidate is not a regular file")
        }
    }
    Some(paths)
}

fn concrete_target(path: String) -> EffectTarget {
    EffectTarget::ConfiguredPath(ConfiguredPathTarget {
        sources: vec![],
        only_when_sources_absent: false,
        environment: None,
        shell_variable: None,
        relative_to: None,
        unresolved_relative_base: false,
        expand_environment: false,
        expand_user: false,
        missing: ConfiguredPathMissing::Unknown,
        default_value: Some(path),
        fallback_parent_slots: vec![],
        fallback_parent_suffix: None,
        purpose: Some(PathPurpose::GenericOperand),
    })
}

//! Versioned Pip data discovery on the executor filesystem. Never probes Pip,
//! imports Python, evaluates an INI value, or grants resource authority.
use super::*;
use caushell_profile::{
    EnvironmentValueRef, NativeConfigurationSyntax, PipConfiguration, SessionValue,
    materialize_prefix_environment, pip_boolean,
};
use caushell_types::{PIP_25_3_LINUX_VARIANT, PipRuntimeLayout};

pub(super) fn run(registry: &ProfileRegistry, session: SessionView<'_>, ctx: &mut RunnerContext) {
    let records = graph_backed_execution_resolve_records(ctx);
    let mut updates = Vec::new();
    let mut remaining = 128usize;
    for record in &records {
        let ResolveInvocationArtifactResult::Resolved(original) = record.result() else {
            continue;
        };
        let Some(profile) = registry.lookup(&original.normalized_command_name).profile else {
            continue;
        };
        if profile.native_configuration != Some(NativeConfigurationSyntax::Pip25_3Linux) {
            continue;
        }
        if original.bound.form_id.as_str() == "information"
            || original.bound.form_id.as_str().ends_with("show_help")
        {
            continue;
        }
        let Some(command) = record.command() else {
            continue;
        };
        let cwds = record.cwd_options(&ctx.request().shell_state_before.cwd);
        let cwd = (cwds.len() == 1 && !record.static_input_cwd_unproven())
            .then(|| cwds[0])
            .flatten();
        let mut namespace = NamespaceResolver::new(ctx.filesystem_view());
        let writes = possible_writes_excluding_effects(
            ctx,
            &records,
            &mut namespace,
            record.source_node_id(),
            true,
        );
        let namespace_writes = possible_writes_excluding_effects(
            ctx,
            &records,
            &mut namespace,
            record.source_node_id(),
            false,
        );
        let content = |path: &str| known_content(session, ctx, registry, *record, &records, path);
        let mut exp = Expansion {
            profile,
            view: ctx.filesystem_view(),
            cwd,
            writes: &writes,
            namespace_writes: &namespace_writes,
            static_content: &content,
            stack: Vec::new(),
            paths: Vec::new(),
            bytes: 0,
            requests: 0,
            request_limit: remaining.min(32),
            byte_limit: 262144,
            tokens: Vec::new(),
            evidence: ToolConfigParseEvidence {
                node_id: record.source_node_id().0.clone(),
                command: original.normalized_command_name.clone(),
                complete: false,
                files: Vec::new(),
                directories: Vec::new(),
                namespace_observations: Vec::new(),
                options: Vec::new(),
                errors: Vec::new(),
            },
        };
        let mut result = record.result().clone();
        let complete_environment = matches!(
            ctx.request().shell_state_before.observability.variables,
            caushell_types::ShellStateKnowledge::Complete
                | caushell_types::ShellStateKnowledge::ExportedOnly
        );
        if let Err(error) = resolve(&mut exp, *record, &mut result, complete_environment) {
            exp.error(error);
        }
        if let Some(bound) = bound_mut(&mut result) {
            for path in &exp.paths {
                attach_file_effects(bound, path.clone());
            }
            if !exp.evidence.errors.is_empty() {
                mark_configuration_pending(bound, "Pip native configuration is incomplete");
            }
        }
        exp.evidence.complete = exp.evidence.errors.is_empty();
        remaining = remaining.saturating_sub(exp.requests);
        updates.push((record.source_node_id().clone(), result, exp.evidence));
        let _ = command;
    }
    for (node, result, evidence) in updates {
        if let Some(target) = ctx.execution_result_mut(&node) {
            *target = result;
        }
        ctx.add_evidence(Evidence {
            rule_id: RuleId::SelectionError,
            summary: if evidence.complete {
                "Pip configuration resolved"
            } else {
                "Pip configuration incomplete"
            }
            .into(),
            kind: EvidenceKind::ToolConfigParse(evidence),
        });
    }
}

fn resolve(
    exp: &mut Expansion<'_>,
    record: ExecutionResolveRecordRef<'_>,
    result: &mut ResolveInvocationArtifactResult,
    complete_environment: bool,
) -> Result<(), String> {
    let ResolveInvocationArtifactResult::Resolved(original) = record.result() else {
        return Ok(());
    };
    let bound = &original.bound;
    let command = record.command().ok_or("Pip command origin is missing")?;
    // An env/module/native-generated child may select a different interpreter.
    // A parent Shell's executable observation is not a transfer certificate.
    if record.variable_frame().is_some() {
        return Err("Pip child runtime identity is not proven in its own frame".into());
    }
    let spelling = command
        .command_name
        .as_deref()
        .ok_or("Pip executable spelling is unknown")?;
    if record.bindings().native_variant(spelling) != Some(PIP_25_3_LINUX_VARIANT) {
        return Err("Pip implementation has no current owning-frame identity".into());
    }
    let layout = exp
        .view
        .pip_runtime(spelling)
        .ok_or("private executor Pip layout is unavailable")?;
    layout.validate()?;
    if exp.view.execution_account().as_ref() != Some(&layout.account) {
        return Err("Pip runtime execution account does not match".into());
    }
    if bound.operation_semantics_unresolved
        || original.materialized_projection.shell_expansion_unresolved
    {
        return Err("Pip invocation is incomplete independently of configuration".into());
    }
    let prefix = materialize_prefix_environment(command, record.bindings());
    // Pip scans *all* PIP_* keys and normalizes case. A finite named capture
    // cannot establish that an unobserved alias (e.g. PIP_log) is absent.
    if !complete_environment || !record.bindings().environment_is_complete() {
        return Err(
            "Pip requires a complete executor environment, not only named observations".into(),
        );
    }
    for name in record
        .bindings()
        .environment_names()
        .into_iter()
        .chain(prefix.iter().map(|(k, _)| k.clone()))
    {
        if name.starts_with("PIP_")
            && !caushell_profile::PIP_CONFIGURATION_ENVIRONMENT.contains(&name.as_str())
        {
            let present = prefix.iter().any(|(key, _)| key == &name)
                || !matches!(
                    record.bindings().environment_value(&name),
                    EnvironmentValueRef::Absent
                );
            if present {
                return Err(format!(
                    "unmodeled or noncanonical Pip environment key {name}"
                ));
            }
        }
    }
    for (key, value) in &prefix {
        if key == "PATH"
            || key.starts_with("LD_")
            || key.starts_with("DYLD_")
            || matches!(key.as_str(), "GCONV_PATH" | "GLIBC_TUNABLES")
        {
            return Err("Pip prefix changes its native lookup/loader contract".into());
        }
        if key.starts_with("PYTHON")
            && !matches!(key.as_str(), "PYTHONDONTWRITEBYTECODE")
            && !matches!(value,SessionValue::ExactScalar(v) if v.is_empty())
        {
            return Err("Pip prefix changes interpreter startup".into());
        }
    }
    let env = |name: &str| -> Result<Option<String>, String> {
        let value = prefix
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| EnvironmentValueRef::Present(v))
            .unwrap_or_else(|| record.bindings().environment_value(name));
        match value {
            EnvironmentValueRef::Absent => Ok(None),
            EnvironmentValueRef::Present(
                SessionValue::ExactScalar(s) | SessionValue::RuntimeProduced { value: s, .. },
            ) if s.len() <= 8192 && !s.contains('\0') => Ok(Some(s.clone())),
            _ => Err(format!("{name} is not observed in the owning Pip frame")),
        }
    };
    for name in [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONPYCACHEPREFIX",
        "PYTHONEXECUTABLE",
        "__PYVENV_LAUNCHER__",
        "PYTHONBREAKPOINT",
        "PIP_PYTHON",
        "PYTHONWARNINGS",
        "PYTHONPLATLIBDIR",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
        "PIP_AUTO_COMPLETE",
    ] {
        if env(name)?.is_some_and(|v| !v.is_empty()) {
            return Err(format!("{name} changes the attested Pip runtime"));
        }
    }
    // This also excludes unmodeled import-cache writes from an otherwise read-only query.
    if env("PYTHONDONTWRITEBYTECODE")?.as_deref() != Some("1") {
        return Err("Pip startup bytecode writes are not disabled by observed evidence".into());
    }
    let mut cli = owned_options(bound);
    let operation = bound
        .subcommand_path
        .first()
        .ok_or("Pip operation is unknown")?;
    // Pip 25.3's bootstrap also uses literal argv membership/removal. A data
    // operand with these spellings can change bootstrap dispatch independently
    // of optparse ownership. Keep that boundary unknown rather than rescan data.
    if bound
        .bound_parameters
        .iter()
        .flat_map(|p| &p.values)
        .any(|value| {
            matches!(value,caushell_profile::BoundValue::Argument{text,binding_source,..}
                if text=="--isolated" || matches!(binding_source,caushell_profile::ArgumentBindingSource::FollowingFlag{..}|
                    caushell_profile::ArgumentBindingSource::MatchedModifierFlag{..}) && text==operation)
        })
    {
        return Err("Pip bootstrap argv/option-operand ambiguity is unsupported".into());
    }
    if env("PIP_ISOLATED")?.is_some_and(|v| !v.is_empty()) {
        return Err("Pip environment-selected isolated startup is not modeled".into());
    }
    let isolated = cli.contains_key("--isolated");
    let home = match env("HOME")? {
        Some(v) if v.is_empty() => {
            return Err("empty HOME has unsupported native user expansion".into());
        }
        Some(v) => v,
        None => layout.account_home.clone(),
    };
    absolute(&home)?;
    let directories = if let Some(v) = env("XDG_CONFIG_DIRS")?.filter(|v| !v.is_empty()) {
        if v.trim() != v {
            return Err("whitespace-normalized XDG config search is unsupported".into());
        }
        let parts = v.split(':').map(String::from).collect::<Vec<_>>();
        if parts.len() > 16 {
            return Err("Pip config directory budget exceeded".into());
        }
        for p in &parts {
            if p.trim() != p {
                return Err("whitespace-normalized XDG config directory is unsupported".into());
            }
            absolute(p)?;
        }
        parts
    } else {
        vec!["/etc/xdg".into()]
    };
    let config_home = env("XDG_CONFIG_HOME")?
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| join(&home, ".config"));
    if config_home.trim() != config_home {
        return Err("whitespace-normalized XDG config home is unsupported".into());
    }
    absolute(&config_home)?;
    let mut global = directories
        .iter()
        .map(|p| join(p, "pip/pip.conf"))
        .collect::<Vec<_>>();
    global.push("/etc/pip.conf".into());
    let user = vec![
        join(&home, ".pip/pip.conf"),
        join(&config_home, "pip/pip.conf"),
    ];
    let site = join(&layout.prefix, "pip.conf");
    let explicit = env("PIP_CONFIG_FILE")?;
    let disabled = explicit.as_deref() == Some("/dev/null");
    let explicit_exists = if let Some(p) = explicit.as_ref().filter(|p| !p.is_empty() && !disabled)
    {
        Some(observe(exp, p)?.is_some())
    } else {
        None
    };
    let mut config = PipConfiguration::default();
    if !disabled {
        for path in &global {
            load(exp, &mut config, path)?;
        }
        if !isolated && explicit_exists != Some(true) {
            for path in &user {
                load(exp, &mut config, path)?;
            }
        }
        load(exp, &mut config, &site)?;
        if let Some(p) = explicit.as_ref().filter(|p| !p.is_empty()) {
            load(exp, &mut config, p)?;
        }
    }
    for error in &config.errors {
        exp.error(error);
    }
    let mut options = config.effective(operation);
    if !isolated {
        for (key, name) in [
            ("log", "PIP_LOG"),
            ("cache-dir", "PIP_CACHE_DIR"),
            ("disable-pip-version-check", "PIP_DISABLE_PIP_VERSION_CHECK"),
            ("no-cache-dir", "PIP_NO_CACHE_DIR"),
            ("user", "PIP_USER"),
            ("global", "PIP_GLOBAL"),
            ("site", "PIP_SITE"),
            ("editor", "PIP_EDITOR"),
            ("debug", "PIP_DEBUG"),
            ("verbose", "PIP_VERBOSE"),
            ("quiet", "PIP_QUIET"),
        ] {
            if let Some(v) = env(name)?.filter(|v| !v.is_empty()) {
                options.insert(key.into(), v);
            }
        }
        for name in [
            "PIP_REQUIREMENT",
            "PIP_CERT",
            "PIP_CLIENT_CERT",
            "PIP_PROXY",
            "PIP_KEYRING_PROVIDER",
        ] {
            if env(name)?.is_some_and(|v| !v.is_empty()) {
                exp.error(format!("{name} native effects are not yet modeled"));
            }
        }
    }
    for (flag, value) in &cli {
        if let Some(key) = flag.strip_prefix("--") {
            if matches!(
                key,
                "log"
                    | "cache-dir"
                    | "disable-pip-version-check"
                    | "no-cache-dir"
                    | "user"
                    | "global"
                    | "site"
                    | "editor"
                    | "debug"
                    | "quiet"
                    | "verbose"
            ) {
                options.insert(key.into(), value.clone().unwrap_or_else(|| "true".into()));
            }
        }
    }
    // A deliberately bounded option semantics set. Unsupported effective data
    // never turns a parsed prefix into proof that configuration has no effects.
    for key in options.keys() {
        if !matches!(
            key.as_str(),
            "log"
                | "cache-dir"
                | "disable-pip-version-check"
                | "no-cache-dir"
                | "user"
                | "global"
                | "site"
                | "editor"
                | "debug"
                | "quiet"
                | "verbose"
                | "no-color"
                | "no-input"
                | "timeout"
                | "retries"
                | "format"
                | "local"
                | "all"
                | "files"
                | "editable"
                | "exclude-editable"
                | "include-editable"
                | "not-required"
                | "require-virtualenv"
                | "require-venv"
                | "root-user-action"
        ) {
            exp.error(format!("Pip configuration option {key} is unsupported"));
        }
    }
    if operation == "freeze" {
        exp.error("Pip freeze may dispatch native VCS tools for editable distributions");
    }
    if operation == "config" && bound.subcommand_path.get(1).is_some_and(|v| v == "edit") {
        exp.error("Pip config edit composes a native shell/editor command; that composition is not closed");
    }
    let query = matches!(operation.as_str(), "list" | "show" | "check")
        || operation == "config"
            && bound
                .subcommand_path
                .get(1)
                .is_some_and(|v| matches!(v.as_str(), "list" | "debug" | "get"));
    let rewrite = operation == "config"
        && bound
            .subcommand_path
            .get(1)
            .is_some_and(|v| matches!(v.as_str(), "set" | "unset" | "edit"));
    let mut additions = Vec::new();
    if let Some(path) = options.get("log") {
        additions.push(path_effect(EffectKind::WritePath, relative(exp, path)?));
    }
    let disable_version = bool_option(&options, "disable-pip-version-check")?.unwrap_or(false);
    let version_effect = operation == "list" && !disable_version;
    if version_effect || !query && operation != "config" {
        let cache = options.get("cache-dir").cloned().unwrap_or_else(|| {
            env("XDG_CACHE_HOME")
                .ok()
                .flatten()
                .filter(|v| !v.is_empty())
                .map(|v| join(&v, "pip"))
                .unwrap_or_else(|| join(&home, ".cache/pip"))
        });
        // Unknown XDG_CACHE_HOME cannot silently choose HOME's default.
        if !options.contains_key("cache-dir") {
            env("XDG_CACHE_HOME")?;
        }
        if cache.trim() != cache {
            return Err("whitespace-normalized XDG cache home is unsupported".into());
        }
        additions.push(path_effect(EffectKind::WritePath, relative(exp, &cache)?));
    }
    for key in [
        "no-cache-dir",
        "user",
        "global",
        "site",
        "debug",
        "no-color",
        "no-input",
        "local",
        "all",
        "files",
        "editable",
        "exclude-editable",
        "include-editable",
        "not-required",
        "require-virtualenv",
        "require-venv",
    ] {
        bool_option(&options, key)?;
    }
    if rewrite {
        if disabled {
            return Err(
                "Pip configuration modification has no loaded parser under /dev/null".into(),
            );
        }
        let target = edit_target(exp, &layout, &global, &user, &site, &options)?;
        additions.push(path_effect(EffectKind::WritePath, target));
    }
    // Recheck the private runtime/lease and every observed file, including
    // absences, before removing any unknown lifecycle effect.
    if exp.view.pip_runtime(spelling).as_ref() != Some(&layout)
        || exp.view.execution_account().as_ref() != Some(&layout.account)
    {
        exp.error("Pip runtime/configuration lease changed during analysis");
    }
    let paths = exp
        .evidence
        .files
        .iter()
        .map(|f| f.path.clone())
        .collect::<BTreeSet<_>>();
    for path in paths {
        observe(exp, &path)?;
    }
    let complete = exp.evidence.errors.is_empty();
    if let Some(bound) = bound_mut(result) {
        // Only closed query/config-rewrite lifecycle effects are replaced.
        // Imported package/backend execution and package temporary writes stay.
        if complete && (query || rewrite) {
            // Native option precedence selects a single effective log/cache
            // value. Replace only the owned option slots we resolved above;
            // shell redirections and other output effects remain independent.
            let slots=bound.bound_parameters.iter().filter(|parameter| {
                !parameter.values.is_empty() && parameter.values.iter().all(|value| {
                    let caushell_profile::BoundValue::Argument{binding_source,..}=value else {return false};
                    use caushell_profile::ArgumentBindingSource as S;
                    matches!(binding_source,S::FollowingFlag{flag_name,..}|S::MatchedModifierFlag{flag_name,..}
                        if matches!(flag_name.as_str(),"--log"|"--cache-dir"))
                })
            }).map(|p|p.name.clone()).collect::<BTreeSet<_>>();
            bound.effects.retain(|e| {
                !(e.target == EffectTarget::None
                    && matches!(e.kind, EffectKind::LoadConfig | EffectKind::WritePath))
                    && !(e.kind == EffectKind::WritePath
                        && matches!(&e.target,EffectTarget::Slot(slot) if slots.contains(slot)))
            });
            if query && !version_effect {
                bound.effects.retain(|e| {
                    !(e.kind == EffectKind::NetworkEndpoint && e.target == EffectTarget::None)
                });
            }
        }
        for effect in additions {
            if !bound.effects.contains(&effect) {
                bound.effects.push(effect);
            }
        }
    }
    cli.clear();
    Ok(())
}

fn absolute(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.len() > 4096 || path.contains(['\0', '\n', '\r']) {
        return Err("Pip path is not bounded and absolute".into());
    }
    Ok(())
}
fn join(base: &str, leaf: &str) -> String {
    format!("{}/{leaf}", base.trim_end_matches('/'))
}
fn relative(exp: &Expansion<'_>, path: &str) -> Result<String, String> {
    if path.is_empty()
        || path.starts_with('~')
        || path.contains(['\0', '\n', '\r'])
        || path.len() > 4096
    {
        return Err("Pip configured path is invalid or requires unmodeled user expansion".into());
    }
    if path.starts_with('/') {
        Ok(path.into())
    } else {
        exp.cwd
            .map(|cwd| join(cwd, path))
            .ok_or_else(|| "Pip configured path has an unknown cwd".into())
    }
}
fn bool_option(values: &BTreeMap<String, String>, name: &str) -> Result<Option<bool>, String> {
    values
        .get(name)
        .map(|s| pip_boolean(s).ok_or_else(|| format!("Pip boolean {name} is not modeled")))
        .transpose()
}
fn owned_options(bound: &BoundInvocation) -> BTreeMap<String, Option<String>> {
    let mut rows = BTreeMap::new();
    let mut insert = |source: &caushell_profile::ArgumentBindingSource, value: Option<String>| {
        use caushell_profile::ArgumentBindingSource as S;
        if let S::FollowingFlag {
            flag_name,
            flag_span,
        }
        | S::MatchedModifierFlag {
            flag_name,
            flag_span,
            ..
        } = source
        {
            let key = (flag_span.start_byte, flag_name.as_str().to_owned());
            if value.is_some() || !rows.contains_key(&key) {
                rows.insert(key, value);
            }
        }
    };
    for parameter in &bound.bound_parameters {
        for value in &parameter.values {
            if let caushell_profile::BoundValue::Argument {
                text,
                binding_source,
                ..
            } = value
            {
                insert(binding_source, Some(text.clone()));
            }
        }
    }
    for source in bound
        .modifier_parameter_flags
        .iter()
        .chain(&bound.owned_option_flags)
    {
        insert(source, None);
    }
    rows.into_iter()
        .map(|((_, flag), value)| (flag, value))
        .collect()
}
fn observe(exp: &mut Expansion<'_>, path: &str) -> Result<Option<Vec<u8>>, String> {
    exp.requests += 1;
    if exp.requests > exp.request_limit || exp.bytes >= exp.byte_limit {
        return Err("Pip configuration observation budget exceeded".into());
    }
    let path = relative(exp, path)?;
    let (read, concrete) = exp.read(&path);
    let source = read.observation.source;
    let trusted = matches!(
        (exp.view.source(), source),
        (
            caushell_types::FilesystemObservationSource::CurrentProcess,
            FileContentSource::CurrentProcess
        ) | (
            caushell_types::FilesystemObservationSource::SuppliedView,
            FileContentSource::SuppliedView
        )
    ) || source == FileContentSource::Graph;
    let status = read.observation.status;
    if status == FileContentStatus::Complete
        && source != FileContentSource::Graph
        && read.observation.identity.is_none()
    {
        return Err("Pip regular-file identity is missing".into());
    }
    let bytes = read
        .complete_bytes(&concrete, MAX_FILE_CONTENT_BYTES)
        .map(<[u8]>::to_vec);
    if exp
        .evidence
        .files
        .iter()
        .any(|old| old.path == read.observation.path && old != &read.observation)
    {
        return Err("Pip configuration identity/content/existence changed during analysis".into());
    }
    exp.evidence.files.push(read.observation);
    if !trusted {
        return Err("Pip configuration did not come from the trusted execution filesystem".into());
    }
    if status == FileContentStatus::Missing {
        return Ok(None);
    }
    exp.paths.push(Some(concrete));
    let bytes = bytes.ok_or_else(|| format!("Pip configuration observation is {status:?}"))?;
    exp.bytes += bytes.len();
    if exp.bytes > exp.byte_limit {
        return Err("Pip configuration byte budget exceeded".into());
    }
    Ok(Some(bytes))
}
fn load(exp: &mut Expansion<'_>, config: &mut PipConfiguration, path: &str) -> Result<(), String> {
    if let Some(bytes) = observe(exp, path)? {
        let parsed = PipConfiguration::parse(&bytes);
        for (section, values) in &parsed.sections {
            for (key, value) in values {
                exp.evidence.options.push(ToolConfigOptionEvidence {
                    path: path.into(),
                    line: 0,
                    order: exp.evidence.options.len(),
                    option: format!("{section}.{key}"),
                    argument_sha256: Some(content_sha256(value.as_bytes())),
                });
            }
        }
        config.merge(parsed);
    }
    Ok(())
}
fn edit_target(
    exp: &mut Expansion<'_>,
    _layout: &PipRuntimeLayout,
    global: &[String],
    user: &[String],
    site: &str,
    options: &BTreeMap<String, String>,
) -> Result<String, String> {
    let scopes = ["user", "global", "site"]
        .into_iter()
        .filter_map(|k| match bool_option(options, k) {
            Ok(Some(true)) => Some(Ok(k)),
            Err(e) => Some(Err(e)),
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    if scopes.len() > 1 {
        return Err("Pip config file selection has conflicting scopes".into());
    }
    let scope = if let Some(scope) = scopes.first() {
        *scope
    } else if observe(exp, site)?.is_some() {
        "site"
    } else {
        "user"
    };
    Ok(match scope {
        "site" => site.to_owned(),
        "global" => global.last().unwrap().clone(),
        _ => user.last().unwrap().clone(),
    })
}
fn path_effect(kind: EffectKind, path: String) -> Effect {
    let mut temp = BoundInvocation::new(
        caushell_profile::CommandName::new("pip"),
        caushell_profile::FormId::new("data"),
    );
    attach_file_effects(&mut temp, Some(path));
    let mut effect = temp.effects.remove(0);
    effect.kind = kind;
    effect
}

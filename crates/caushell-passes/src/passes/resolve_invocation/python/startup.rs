use super::*;
use crate::path::namespace::NamespaceResolver;
use caushell_types::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod contract;
mod frame;
mod imports;
mod observer;

use contract::valid_contract;
use frame::{ancestors_stable, readonly_scope};
use imports::{check_hook, module_file};
use observer::Observer;

pub(super) fn prove(
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    bindings: &SessionBindings,
    cwd: &str,
    argv0: &str,
    imports: &[String],
    output_body: Option<&str>,
    ancestor_records: &[ExecutionUnitResolveRecord],
    ctx: &mut RunnerContext,
) -> Result<(), String> {
    let view = ctx.filesystem_view();
    let mut observer = Observer {
        namespace: NamespaceResolver::new(view.clone()),
        view,
        entries: BTreeMap::new(),
        listings: BTreeMap::new(),
        digests: BTreeMap::new(),
        proof: PythonStartupEvidence {
            node_id: entry.source_node_id.0.clone(),
            complete: false,
            contract_sha256: None,
            executable: None,
            executable_lookup: None,
            version: None,
            account: None,
            environment: BTreeMap::new(),
            search_paths: Vec::new(),
            modules: BTreeMap::new(),
            namespace: Vec::new(),
            directories: Vec::new(),
            files: Vec::new(),
            gap: None,
        },
    };
    let result = ancestors_stable(entry, request, ancestor_records).and_then(|_| {
        verify(
            &mut observer,
            registry,
            request,
            entry,
            context,
            resolved,
            bindings,
            cwd,
            argv0,
            imports,
            output_body,
        )
    });
    match &result {
        Ok(()) => observer.proof.complete = true,
        Err(gap) => observer.proof.gap = Some(gap.clone()),
    }
    observer.proof.namespace = observer.entries.into_values().collect();
    ctx.add_evidence(Evidence {
        rule_id: RuleId::NestedPayloadExpansion,
        summary: if result.is_ok() {
            "Python startup origins verified".into()
        } else {
            "Python startup origins incomplete".into()
        },
        kind: EvidenceKind::PythonStartup(observer.proof),
    });
    result
}

fn verify(
    o: &mut Observer,
    registry: &ProfileRegistry,
    request: &CheckRequest,
    entry: &ExpandedFrontierEntry,
    context: &ProgramSourceContext,
    resolved: &caushell_profile::ResolvedInvocationArtifact,
    bindings: &SessionBindings,
    cwd: &str,
    argv0: &str,
    imports: &[String],
    output_body: Option<&str>,
) -> Result<(), String> {
    let c = o
        .view
        .python_runtime_contract()
        .ok_or("Python runtime contract is not registered")?;
    valid_contract(&c)?;
    o.proof.contract_sha256 = Some(caushell_runner::content_sha256(
        &serde_json::to_vec(c.as_ref())
            .map_err(|_| "Python runtime contract serialization failed")?,
    ));
    o.proof.version = Some(c.version);
    o.proof.account = o.view.execution_account();
    if o.proof.account.as_ref() != Some(&c.account) {
        return Err("Python runtime execution account is unproven".into());
    }
    readonly_scope(
        registry,
        request,
        &entry.parsed_scope,
        program_command_index(entry),
        program_scope_bindings(entry),
        output_body,
    )?;
    for scope in &context.source_scopes {
        readonly_scope(
            registry,
            request,
            &scope.parsed,
            scope.before_command_index,
            &scope.bindings,
            Some(&entry.rendered_command_text),
        )?;
    }
    let options = caushell_profile::python_startup_options(resolved)?;
    let launch = resolved
        .materialized_projection
        .invocation
        .command_name
        .as_deref()
        .ok_or("Python executable is unknown")?;
    let selected = if launch.starts_with('/') {
        launch.to_owned()
    } else {
        let value = o.env(bindings, "PATH")?;
        let path = value.map_or(ShellEnvironmentValue::Absent, |value| {
            ShellEnvironmentValue::Present { value }
        });
        let lookup = o
            .view
            .shell_executable(launch, cwd, entry.shell_kind, &path)
            .ok_or("Python shell executable lookup is not observed")?;
        if lookup.command != launch
            || lookup.cwd != cwd
            || lookup.shell_kind != entry.shell_kind
            || lookup.path_environment != path
            || lookup.source != o.view.source()
            || !lookup.executable.starts_with('/')
        {
            return Err("Python shell executable lookup does not match its frame".into());
        }
        let executable = lookup.executable.clone();
        o.proof.executable_lookup = Some(lookup);
        executable
    };
    let executable = o.resolve(&selected)?;
    o.proof.executable = Some(executable.clone());
    if executable != c.executable {
        return Err("Python executable does not match the registered runtime".into());
    }
    o.digest(&executable, &c.files[&executable])?;
    if o.digests[&executable].executable != Some(true) {
        return Err("Python interpreter execute permission is not proven".into());
    }
    if !bindings.environment_is_complete() {
        return Err("Python startup environment inventory is incomplete".into());
    }
    for name in bindings.environment_names().into_iter().filter(|n| {
        n.starts_with("LD_")
            || n.starts_with("DYLD_")
            || n == "GCONV_PATH"
            || n == "__PYVENV_LAUNCHER__"
            || n.starts_with("PYTHON")
    }) {
        if options.ignore_environment && name.starts_with("PYTHON") {
            continue;
        }
        if matches!(
            name.as_str(),
            "PYTHONPATH"
                | "PYTHONUSERBASE"
                | "PYTHONNOUSERSITE"
                | "PYTHONSAFEPATH"
                | "PYTHONDONTWRITEBYTECODE"
        ) {
            continue;
        }
        if o.env(bindings, &name)?.is_some_and(|v| !v.is_empty()) {
            return Err(format!(
                "unsupported Python startup environment control: {name}"
            ));
        }
    }
    let mut guards = c.absent_configuration.clone();
    for executable_path in [selected.as_str(), &executable] {
        let directory = std::path::Path::new(executable_path)
            .parent()
            .ok_or("Python executable has no parent")?
            .to_string_lossy();
        guards.push(format!("{directory}/pyvenv.cfg"));
        guards.push(
            format!(
                "{}/pyvenv.cfg",
                std::path::Path::new(directory.as_ref())
                    .parent()
                    .unwrap_or(std::path::Path::new("/"))
                    .display()
            )
            .replace("//", "/"),
        );
        guards.push(format!("{executable_path}._pth"));
        guards.push(format!("{directory}/pybuilddir.txt"));
    }
    guards.sort();
    guards.dedup();
    for path in guards {
        o.missing(&path)?;
    }
    for (path, target) in &c.symlinks {
        let entry = o.view.entry(path);
        o.entries.insert(
            path.clone(),
            FilesystemObservation {
                source: o.view.source(),
                path: path.clone(),
                entry: entry.clone(),
            },
        );
        if entry
            != (FilesystemEntry::Symlink {
                target: target.clone(),
            })
        {
            return Err(format!("Python runtime link changed: {path}"));
        }
        let target = o.resolve(path)?;
        if !c.files.contains_key(&target) {
            return Err("Python runtime link target is not inventoried".into());
        }
    }
    for (path, expected) in &c.directories {
        let Some((resolved, actual)) = o.directory(path)? else {
            return Err(format!("Python runtime directory is missing: {path}"));
        };
        if &resolved != path
            || actual.len() != expected.len()
            || actual
                .iter()
                .zip(expected)
                .any(|(a, b)| a.name != b.name || a.kind != b.kind)
        {
            return Err(format!("Python runtime directory changed: {path}"));
        }
    }
    for (path, expected) in &c.files {
        if !o.digests.contains_key(path) {
            o.digest(path, expected)?;
        }
    }
    let mut paths = Vec::new();
    let safe_path = options.safe_path
        || (!options.ignore_environment
            && o.env(bindings, "PYTHONSAFEPATH")?
                .is_some_and(|s| !s.is_empty()));
    if !safe_path {
        paths.push(if matches!(argv0, "-c" | "-") {
            cwd.into()
        } else {
            let source = o.resolve(&resolve_conventional_path(cwd, argv0))?;
            std::path::Path::new(&source)
                .parent()
                .ok_or("Python script directory is unknown")?
                .to_string_lossy()
                .into_owned()
        });
    }
    if !options.ignore_environment
        && let Some(value) = o.env(bindings, "PYTHONPATH")?
    {
        for path in value.split(':') {
            paths.push(resolve_conventional_path(cwd, path));
        }
    }
    paths.extend(c.search_paths.iter().cloned());
    let mut user_site = false;
    if !options.no_site {
        user_site = !options.no_user_site
            && (options.ignore_environment
                || o.env(bindings, "PYTHONNOUSERSITE")?
                    .is_none_or(|s| s.is_empty()));
        if user_site {
            let base = o.env(bindings, "PYTHONUSERBASE")?.filter(|s| !s.is_empty());
            let base = match base {
                Some(base) if base.starts_with('/') => base,
                Some(_) => return Err("relative Python user base is unsupported".into()),
                None => {
                    let home = o
                        .env(bindings, "HOME")?
                        .unwrap_or_else(|| c.account_home.clone());
                    if !home.starts_with('/') {
                        return Err("Python account home is unresolved".into());
                    }
                    format!("{home}/.local")
                }
            };
            paths.push(format!("{base}/lib/python3.11/site-packages"));
        }
        paths.extend(c.site_directories.iter().cloned());
    }
    let mut seen = BTreeSet::new();
    let mut search = Vec::new();
    for path in paths {
        if c.absent_configuration.contains(&path) {
            continue;
        }
        let Some((path, entries)) = o.directory(&path)? else {
            continue;
        };
        if seen.insert(path.clone()) {
            search.push((path, entries));
        }
        if search.len() > 64 {
            return Err("Python search path budget exceeded".into());
        }
    }
    o.proof.search_paths = search.iter().map(|(p, _)| p.clone()).collect();
    if search.len() > 64 {
        return Err("Python search path budget exceeded".into());
    }
    let shadow_names = c
        .stdlib_names
        .iter()
        .filter(|name| !c.builtin_modules.contains(name) && !c.frozen_modules.contains(name))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for (path, entries) in &search {
        if !options.no_site && entries.iter().any(|e| e.name.ends_with(".pth")) {
            return Err(format!("unmodeled Python site path configuration: {path}"));
        }
        if !c.directories.contains_key(path) {
            for candidate in entries {
                let names = std::iter::once(Some(candidate.name.as_str())).chain(
                    [".py", ".pyc"]
                        .into_iter()
                        .chain(c.extension_suffixes.iter().map(String::as_str))
                        .map(|suffix| candidate.name.strip_suffix(suffix)),
                );
                if let Some(name) = names.flatten().find(|name| shadow_names.contains(name)) {
                    return Err(format!(
                        "Python standard module may be shadowed: {path}/{name}"
                    ));
                }
            }
        }
    }
    if !options.no_site {
        for hook in ["sitecustomize", "usercustomize"] {
            if hook == "usercustomize" && !user_site {
                continue;
            }
            check_hook(o, &c, &search, hook)?;
        }
    }
    for name in imports {
        let origin = c
            .modules
            .get(name)
            .ok_or_else(|| format!("Python module origin is not registered: {name}"))?;
        match origin {
            PythonModuleOrigin::Builtin if c.builtin_modules.contains(name) => {}
            PythonModuleOrigin::Frozen if c.frozen_modules.contains(name) => {}
            PythonModuleOrigin::File { path } if c.files.contains_key(path) => {
                let actual = module_file(o, &search, name, &c.extension_suffixes)?;
                if &actual != path {
                    return Err(format!("Python module resolves to another file: {name}"));
                }
            }
            _ => return Err(format!("Python module origin contract is invalid: {name}")),
        }
        o.proof.modules.insert(name.clone(), origin.clone());
    }
    Ok(())
}

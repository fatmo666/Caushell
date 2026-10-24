use super::*;

fn has_module(entries: &[DirectoryEntry], name: &str, suffixes: &[String]) -> bool {
    entries.iter().any(|e| {
        e.name == name
            || e.name == format!("{name}.py")
            || e.name == format!("{name}.pyc")
            || suffixes.iter().any(|s| e.name == format!("{name}{s}"))
    })
}

pub(super) fn check_hook(
    o: &mut Observer,
    c: &PythonRuntimeContract,
    search: &[(String, Vec<DirectoryEntry>)],
    name: &str,
) -> Result<(), String> {
    if c.builtin_modules.contains(&name.to_owned()) || c.frozen_modules.contains(&name.to_owned()) {
        return Err("unsupported Python startup hook origin".into());
    }
    for (directory, entries) in search {
        if !has_module(entries, name, &c.extension_suffixes) {
            continue;
        }
        let spelling = format!("{directory}/{name}.py");
        let path = o.resolve(&spelling)?;
        if !c.files.contains_key(&path) {
            return Err(format!(
                "Python startup customization is not registered: {name}"
            ));
        }
        if entries.iter().any(|e| {
            e.name == name
                || e.name == format!("{name}.pyc")
                || c.extension_suffixes
                    .iter()
                    .any(|s| e.name == format!("{name}{s}"))
        }) {
            return Err(format!("unsupported Python startup loader: {name}"));
        }
        let read = o.view.read_file(&path, 65_536);
        if !matches!(
            (o.view.source(), read.observation.source),
            (
                FilesystemObservationSource::CurrentProcess,
                FileContentSource::CurrentProcess
            ) | (
                FilesystemObservationSource::SuppliedView,
                FileContentSource::SuppliedView
            )
        ) {
            return Err("Python startup source is not a fresh namespace observation".into());
        }
        let bytes = read
            .complete_bytes(&path, 65_536)
            .ok_or("Python startup source bytes are not observed")?;
        if read.observation.sha256.as_ref() != Some(&c.files[&path].sha256) {
            return Err("Python startup source changed".into());
        }
        let source =
            std::str::from_utf8(bytes).map_err(|_| "Python startup source is not UTF-8")?;
        for missing in caushell_profile::python_startup_missing_imports(source)? {
            if c.builtin_modules.contains(&missing)
                || c.frozen_modules.contains(&missing)
                || search
                    .iter()
                    .any(|(_, entries)| has_module(entries, &missing, &c.extension_suffixes))
            {
                return Err(format!(
                    "Python startup optional import is not absent: {missing}"
                ));
            }
        }
        return Ok(());
    }
    Ok(())
}

pub(super) fn module_file(
    o: &mut Observer,
    search: &[(String, Vec<DirectoryEntry>)],
    name: &str,
    suffixes: &[String],
) -> Result<String, String> {
    let mut paths = search.to_vec();
    let mut result = None;
    let components = name.split('.').collect::<Vec<_>>();
    let suffixes = suffixes
        .iter()
        .map(String::as_str)
        .chain([".py", ".pyc"])
        .collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        if !caushell_profile::shell_identifier(component) {
            return Err("unsupported Python module name".into());
        }
        let mut selected = None;
        for (directory, entries) in &paths {
            if entries.iter().any(|e| e.name == *component) {
                let package = format!("{directory}/{component}");
                let Some((package, children)) = o.directory(&package)? else {
                    return Err("Python package is missing".into());
                };
                if let Some(suffix) = suffixes.iter().find(|suffix| {
                    children
                        .iter()
                        .any(|e| e.name == format!("__init__{suffix}"))
                }) {
                    selected = Some((
                        o.resolve(&format!("{package}/__init__{suffix}"))?,
                        Some((package, children)),
                    ));
                    break;
                }
                return Err("Python namespace packages are unsupported".into());
            }
            if let Some(suffix) = suffixes.iter().find(|suffix| {
                entries
                    .iter()
                    .any(|e| e.name == format!("{component}{suffix}"))
            }) {
                selected = Some((
                    o.resolve(&format!("{directory}/{component}{suffix}"))?,
                    None,
                ));
                break;
            }
        }
        let (file, package) =
            selected.ok_or_else(|| format!("Python module is not found: {name}"))?;
        result = Some(file);
        if index + 1 < components.len() {
            paths = vec![package.ok_or("Python module parent is not a package")?];
        }
    }
    result.ok_or("empty Python module name".into())
}

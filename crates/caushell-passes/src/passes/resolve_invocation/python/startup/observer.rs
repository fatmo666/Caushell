use super::*;

pub(super) struct Observer {
    pub(super) view: Arc<dyn caushell_runner::FilesystemView>,
    pub(super) namespace: NamespaceResolver,
    pub(super) proof: PythonStartupEvidence,
    pub(super) entries: BTreeMap<String, FilesystemObservation>,
    pub(super) listings: BTreeMap<String, Vec<DirectoryEntry>>,
    pub(super) digests: BTreeMap<String, RuntimeFileObservation>,
}

impl Observer {
    pub(super) fn resolve(&mut self, path: &str) -> Result<String, String> {
        let (resolution, observations) = self.namespace.resolve(path, PathTargetAccess::Follow);
        for o in observations {
            self.entries.insert(o.path.clone(), o);
        }
        match resolution {
            SemanticResolution::Resolved {
                value: PathResolution::Concrete { path },
            } => Ok(path),
            _ => Err(format!("Python runtime namespace is unresolved: {path}")),
        }
    }
    pub(super) fn entry(&mut self, path: &str) -> Result<(String, FilesystemEntry), String> {
        let path = self.resolve(path)?;
        let entry = self.view.entry(&path);
        self.entries.insert(
            path.clone(),
            FilesystemObservation {
                source: self.view.source(),
                path: path.clone(),
                entry: entry.clone(),
            },
        );
        Ok((path, entry))
    }
    pub(super) fn missing(&mut self, path: &str) -> Result<(), String> {
        let (_, entry) = self.entry(path)?;
        if entry == FilesystemEntry::Missing {
            Ok(())
        } else {
            Err(format!("unmodeled Python startup configuration: {path}"))
        }
    }
    pub(super) fn directory(
        &mut self,
        path: &str,
    ) -> Result<Option<(String, Vec<DirectoryEntry>)>, String> {
        let (path, entry) = self.entry(path)?;
        if entry == FilesystemEntry::Missing {
            return Ok(None);
        }
        if entry != FilesystemEntry::Directory {
            return Err(format!("Python search path is not a directory: {path}"));
        }
        if let Some(entries) = self.listings.get(&path) {
            return Ok(Some((path.clone(), entries.clone())));
        }
        if self.listings.len() >= 512 {
            return Err("Python runtime directory budget exceeded".into());
        }
        let limits = DirectoryReadLimits::default();
        let read = self.view.read_directory(&path, limits);
        self.proof.directories.push(read.observation.clone());
        let entries = read
            .complete_entries(&path, limits)
            .filter(|_| read.observation.source == self.view.source())
            .ok_or_else(|| format!("Python directory entries are incomplete: {path}"))?
            .to_vec();
        self.listings.insert(path.clone(), entries.clone());
        Ok(Some((path, entries)))
    }
    pub(super) fn digest(&mut self, path: &str, expected: &RuntimeFile) -> Result<(), String> {
        let resolved = self.resolve(path)?;
        if resolved != path {
            return Err(format!("Python runtime identity path changed: {path}"));
        }
        let read = self.view.runtime_file(path);
        self.proof.files.push(read.clone());
        let same_source = matches!(
            (self.view.source(), read.content.source),
            (
                FilesystemObservationSource::CurrentProcess,
                FileContentSource::CurrentProcess
            ) | (
                FilesystemObservationSource::SuppliedView,
                FileContentSource::SuppliedView
            )
        );
        if !same_source || !caushell_runner::runtime_file_matches(&read, path, expected) {
            return Err(format!("Python runtime file changed or unobserved: {path}"));
        }
        self.digests.insert(path.into(), read);
        Ok(())
    }
    pub(super) fn env(
        &mut self,
        bindings: &SessionBindings,
        name: &str,
    ) -> Result<Option<String>, String> {
        let value = match bindings.environment_value(name) {
            caushell_profile::EnvironmentValueRef::Absent => ShellEnvironmentValue::Absent,
            caushell_profile::EnvironmentValueRef::Present(
                caushell_profile::SessionValue::ExactScalar(value),
            ) => ShellEnvironmentValue::Present {
                value: value.clone(),
            },
            _ => ShellEnvironmentValue::Unknown,
        };
        self.proof.environment.insert(name.into(), value.clone());
        match value {
            ShellEnvironmentValue::Absent => Ok(None),
            ShellEnvironmentValue::Present { value } => Ok(Some(value)),
            ShellEnvironmentValue::Unknown => {
                Err(format!("Python startup environment is unobserved: {name}"))
            }
        }
    }
}

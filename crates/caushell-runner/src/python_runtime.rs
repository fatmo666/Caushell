use crate::{DirectoryRead, FileContentRead, FilesystemView};
use caushell_types::*;
use std::sync::Arc;

pub struct PythonRuntimeFilesystem {
    inner: Arc<dyn FilesystemView>,
    contract: Arc<PythonRuntimeContract>,
}

impl PythonRuntimeFilesystem {
    pub fn new(inner: Arc<dyn FilesystemView>, contract: PythonRuntimeContract) -> Self {
        Self {
            inner,
            contract: Arc::new(contract),
        }
    }
}

impl FilesystemView for PythonRuntimeFilesystem {
    fn shell_executable(
        &self,
        command: &str,
        cwd: &str,
        shell: ShellKind,
        path: &ShellEnvironmentValue,
    ) -> Option<ShellExecutableObservation> {
        self.inner.shell_executable(command, cwd, shell, path)
    }
    fn source(&self) -> FilesystemObservationSource {
        self.inner.source()
    }
    fn entry(&self, path: &str) -> FilesystemEntry {
        self.inner.entry(path)
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        self.inner.read_directory(path, limits)
    }
    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        self.inner.read_file(path, limit)
    }
    fn runtime_file(&self, path: &str) -> RuntimeFileObservation {
        self.inner.runtime_file(path)
    }
    fn execution_account(&self) -> Option<RuntimeAccount> {
        self.inner.execution_account()
    }
    fn python_runtime_contract(&self) -> Option<Arc<PythonRuntimeContract>> {
        Some(self.contract.clone())
    }
}

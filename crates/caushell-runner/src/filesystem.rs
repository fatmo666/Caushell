use caushell_types::FilesystemEntry;

#[derive(Clone, Default)]
pub(crate) struct FilesystemViewHandle(Option<std::sync::Arc<dyn FilesystemView>>);

impl FilesystemViewHandle {
    pub fn new(view: std::sync::Arc<dyn FilesystemView>) -> Self {
        Self(Some(view))
    }
    pub fn view(&self) -> std::sync::Arc<dyn FilesystemView> {
        self.0
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(UnavailableFilesystem))
    }
}

impl std::fmt::Debug for FilesystemViewHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilesystemViewHandle")
            .field("available", &self.0.is_some())
            .finish()
    }
}
impl PartialEq for FilesystemViewHandle {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(left), Some(right)) => std::sync::Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}
impl Eq for FilesystemViewHandle {}

pub trait FilesystemView: Send + Sync {
    /// Entries must describe the execution namespace; Missing means observed absence.
    fn source(&self) -> caushell_types::FilesystemObservationSource {
        caushell_types::FilesystemObservationSource::SuppliedView
    }
    fn entry(&self, path: &str) -> FilesystemEntry;
    fn read_directory(
        &self,
        path: &str,
        limits: caushell_types::DirectoryReadLimits,
    ) -> crate::DirectoryRead {
        crate::DirectoryRead::failed(
            self.source(),
            path,
            limits,
            caushell_types::DirectoryReadStatus::Unavailable,
            "directory entries are not supplied by this filesystem view",
        )
    }
    /// Read a namespace-resolved regular file; metadata-only views remain valid.
    fn read_file(&self, path: &str, byte_limit: usize) -> crate::FileContentRead {
        crate::FileContentRead::failed(
            caushell_types::FileContentSource::Unavailable,
            path,
            byte_limit,
            caushell_types::FileContentStatus::Unavailable,
            "file contents are not supplied by this filesystem view",
        )
    }
}

pub struct UnavailableFilesystem;

impl FilesystemView for UnavailableFilesystem {
    fn source(&self) -> caushell_types::FilesystemObservationSource {
        caushell_types::FilesystemObservationSource::Unavailable
    }
    fn entry(&self, _path: &str) -> FilesystemEntry {
        FilesystemEntry::Unavailable {
            reason: "no filesystem view supplied".into(),
        }
    }
}

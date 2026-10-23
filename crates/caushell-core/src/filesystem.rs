use caushell_runner::FilesystemView;
use caushell_types::FilesystemEntry;

pub struct LocalFilesystem;

impl FilesystemView for LocalFilesystem {
    fn read_directory(
        &self,
        path: &str,
        limits: caushell_types::DirectoryReadLimits,
    ) -> caushell_runner::DirectoryRead {
        crate::directory::read(path, limits)
    }
    fn read_file(&self, path: &str, byte_limit: usize) -> caushell_runner::FileContentRead {
        crate::file_content::read(path, byte_limit)
    }
    fn source(&self) -> caushell_types::FilesystemObservationSource {
        caushell_types::FilesystemObservationSource::CurrentProcess
    }
    fn entry(&self, path: &str) -> FilesystemEntry {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => match std::fs::read_link(path) {
                Ok(target) => match target.to_str() {
                    Some(target) => FilesystemEntry::Symlink {
                        target: target.into(),
                    },
                    None => FilesystemEntry::Unavailable {
                        reason: "non-UTF-8 link target".into(),
                    },
                },
                Err(error) => FilesystemEntry::Unavailable {
                    reason: error.to_string(),
                },
            },
            Ok(metadata) if metadata.is_dir() => FilesystemEntry::Directory,
            Ok(_) => FilesystemEntry::File,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => FilesystemEntry::Missing,
            Err(error) => FilesystemEntry::Unavailable {
                reason: error.to_string(),
            },
        }
    }
}

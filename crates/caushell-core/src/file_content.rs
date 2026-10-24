use caushell_runner::{FileContentRead, MAX_FILE_CONTENT_BYTES};
use caushell_types::{FileContentIdentity, FileContentSource, FileContentStatus};

pub(crate) fn read(path: &str, limit: usize) -> FileContentRead {
    let failed = |status, detail| {
        FileContentRead::failed(
            FileContentSource::CurrentProcess,
            path,
            limit,
            status,
            detail,
        )
    };
    if limit > MAX_FILE_CONTENT_BYTES || path.len() > 16_384 {
        return failed(
            FileContentStatus::TooLarge,
            "content observation budget exceeded".into(),
        );
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut file = match open_regular_path(path) {
            Ok(file) => file,
            Err(error) => {
                let status = if error.kind() == std::io::ErrorKind::NotFound {
                    FileContentStatus::Missing
                } else if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                    FileContentStatus::NonRegular
                } else {
                    FileContentStatus::Unreadable
                };
                return failed(status, error.to_string());
            }
        };
        let before = match file.metadata() {
            Ok(metadata) if metadata.is_file() => identity(&metadata),
            Ok(_) => return failed(FileContentStatus::NonRegular, "not a regular file".into()),
            Err(error) => return failed(FileContentStatus::Unreadable, error.to_string()),
        };
        if before.size > limit as u64 {
            let mut result = failed(
                FileContentStatus::TooLarge,
                "file exceeds the content observation budget".into(),
            );
            result.observation.identity = Some(before);
            return result;
        }
        let mut bytes = Vec::new();
        if let Err(error) = (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes) {
            return failed(FileContentStatus::Unreadable, error.to_string());
        }
        if bytes.len() > limit {
            return failed(
                FileContentStatus::TooLarge,
                "file grew beyond the content observation budget".into(),
            );
        }
        let stable = file
            .metadata()
            .ok()
            .filter(|m| m.is_file())
            .is_some_and(|m| identity(&m) == before)
            && std::fs::symlink_metadata(path)
                .ok()
                .filter(|m| m.is_file())
                .is_some_and(|m| identity(&m) == before)
            && bytes.len() as u64 == before.size;
        if !stable {
            return failed(
                FileContentStatus::Changed,
                "file identity or contents changed during observation".into(),
            );
        }
        FileContentRead::complete(
            FileContentSource::CurrentProcess,
            path,
            limit,
            Some(before),
            bytes,
        )
    }
    #[cfg(not(unix))]
    failed(
        FileContentStatus::Unavailable,
        "regular-file observation is unavailable on this platform".into(),
    )
}

#[cfg(unix)]
pub(crate) fn identity(metadata: &std::fs::Metadata) -> FileContentIdentity {
    use std::os::unix::fs::MetadataExt;
    FileContentIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    }
}

#[cfg(unix)]
pub(crate) fn open_regular_path(path: &str) -> std::io::Result<std::fs::File> {
    open_path(path, false)
}

#[cfg(unix)]
pub(crate) fn open_directory_path(path: &str) -> std::io::Result<std::fs::File> {
    open_path(path, true)
}

#[cfg(unix)]
fn open_path(path: &str, is_directory: bool) -> std::io::Result<std::fs::File> {
    use std::{
        ffi::CString,
        fs::File,
        os::fd::{AsRawFd, FromRawFd},
        os::unix::fs::OpenOptionsExt,
        path::Component,
    };
    let components = std::path::Path::new(path).components().collect::<Vec<_>>();
    if components.first() != Some(&Component::RootDir)
        || (!is_directory && components.len() < 2)
        || components.len() > 256
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected a bounded absolute resolved path",
        ));
    }
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    if components.len() == 1 {
        return Ok(directory);
    }
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is not namespace-resolved",
            ));
        };
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
        let last = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if last && !is_directory {
                0
            } else {
                libc::O_DIRECTORY
            };
        // Each descriptor is owned before the next component is opened.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        if last {
            return Ok(opened);
        }
        directory = opened;
    }
    unreachable!()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn directory() -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "caushell-content-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        directory.canonicalize().unwrap()
    }

    #[test]
    fn regular_file_observation_is_bounded_and_identified() {
        let root = directory();
        let path = root.join("settings");
        fs::write(&path, b"insecure\n").unwrap();
        let path = path.to_str().unwrap();
        let result = read(path, 32);
        assert_eq!(result.complete_bytes(path, 32), Some(&b"insecure\n"[..]));
        assert!(result.observation.identity.is_some());
        assert_eq!(
            read(path, 2).observation.status,
            FileContentStatus::TooLarge
        );
        assert_eq!(
            read(root.join("missing").to_str().unwrap(), 32)
                .observation
                .status,
            FileContentStatus::Missing
        );
        assert_eq!(
            read(root.to_str().unwrap(), 32).observation.status,
            FileContentStatus::NonRegular
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinks_and_fifos_never_supply_file_content() {
        use std::{ffi::CString, os::unix::fs::symlink};
        let root = directory();
        fs::write(root.join("settings"), b"insecure\n").unwrap();
        symlink(root.join("settings"), root.join("link")).unwrap();
        symlink(&root, root.join("parent-link")).unwrap();
        let fifo = CString::new(root.join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        for path in [
            root.join("link"),
            root.join("parent-link/settings"),
            root.join("fifo"),
        ] {
            let read = read(path.to_str().unwrap(), 32);
            assert_ne!(read.observation.status, FileContentStatus::Complete);
            assert!(read.complete_bytes(path.to_str().unwrap(), 32).is_none());
        }
        fs::remove_dir_all(root).unwrap();
    }
}

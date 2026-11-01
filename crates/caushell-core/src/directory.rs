use caushell_runner::{DirectoryRead, directory_path_is_resolved};
use caushell_types::{DirectoryReadLimits, DirectoryReadStatus, FilesystemObservationSource};

pub(crate) fn read(path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
    read_with(path, limits, || {})
}

fn read_with(path: &str, limits: DirectoryReadLimits, after_scan: impl FnOnce()) -> DirectoryRead {
    let failed = |status, detail: String| {
        DirectoryRead::failed(
            FilesystemObservationSource::CurrentProcess,
            path,
            limits,
            status,
            detail,
        )
    };
    if !limits.is_valid() {
        return failed(
            DirectoryReadStatus::TooLarge,
            "directory budget is invalid".into(),
        );
    }
    if !directory_path_is_resolved(path) {
        return failed(
            DirectoryReadStatus::InvalidPath,
            "expected a resolved absolute directory".into(),
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use caushell_types::DirectoryEntry;
        use std::{
            ffi::{CStr, CString},
            os::fd::{AsRawFd, IntoRawFd},
        };

        let directory = match crate::file_content::open_directory_path(path) {
            Ok(file) => file,
            Err(error) => return failed(io_status(&error), error.to_string()),
        };
        let before = match directory.metadata() {
            Ok(metadata) if metadata.is_dir() => crate::file_content::identity(&metadata),
            Ok(_) => return failed(DirectoryReadStatus::NotDirectory, "not a directory".into()),
            Err(error) => return failed(DirectoryReadStatus::Unreadable, error.to_string()),
        };
        let duplicate = match directory.try_clone() {
            Ok(file) => file,
            Err(error) => return failed(DirectoryReadStatus::Unreadable, error.to_string()),
        };
        let fd = duplicate.into_raw_fd();
        // fdopendir owns the duplicate on success; the original pins the namespace.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return failed(DirectoryReadStatus::Unreadable, error.to_string());
        }
        let stream = DirectoryStream(stream);
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        loop {
            unsafe { *errno() = 0 };
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if unsafe { *errno() } != 0 {
                    return failed(
                        DirectoryReadStatus::Unreadable,
                        std::io::Error::last_os_error().to_string(),
                    );
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let text = match entry_name(name) {
                Ok(Some(text)) => text,
                Ok(None) => continue,
                Err(status) => return failed(status, "directory name is not UTF-8".into()),
            };
            bytes = match bytes.checked_add(text.len()) {
                Some(n) if n <= limits.max_name_bytes => n,
                _ => {
                    return failed(
                        DirectoryReadStatus::TooLarge,
                        "directory name budget exceeded".into(),
                    );
                }
            };
            if entries.len() >= limits.max_entries {
                return failed(
                    DirectoryReadStatus::TooLarge,
                    "directory entry budget exceeded".into(),
                );
            }
            let (kind, identity) = match entry_identity(directory.as_raw_fd(), name) {
                Ok(entry) => entry,
                Err(error) => return failed(DirectoryReadStatus::Changed, error.to_string()),
            };
            entries.push(DirectoryEntry {
                name: text.into(),
                kind,
                identity,
            });
        }
        after_scan();
        for entry in &entries {
            let name = CString::new(entry.name.as_bytes()).expect("native name contains no NUL");
            if entry_identity(directory.as_raw_fd(), &name).ok()
                != Some((entry.kind, entry.identity.clone()))
            {
                return failed(
                    DirectoryReadStatus::Changed,
                    "directory entry changed during observation".into(),
                );
            }
        }
        let stable = directory
            .metadata()
            .ok()
            .is_some_and(|metadata| crate::file_content::identity(&metadata) == before)
            && crate::file_content::open_directory_path(path)
                .ok()
                .and_then(|file| file.metadata().ok())
                .is_some_and(|metadata| crate::file_content::identity(&metadata) == before);
        if !stable {
            return failed(
                DirectoryReadStatus::Changed,
                "directory identity changed during observation".into(),
            );
        }
        DirectoryRead::complete(
            FilesystemObservationSource::CurrentProcess,
            path,
            limits,
            before,
            entries,
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = after_scan;
        failed(
            DirectoryReadStatus::Unavailable,
            "directory observation is unavailable on this platform".into(),
        )
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn entry_name(name: &std::ffi::CStr) -> Result<Option<&str>, DirectoryReadStatus> {
    if matches!(name.to_bytes(), b"." | b"..") {
        return Ok(None);
    }
    name.to_str()
        .map(Some)
        .map_err(|_| DirectoryReadStatus::NonUtf8)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn io_status(error: &std::io::Error) -> DirectoryReadStatus {
    if error.kind() == std::io::ErrorKind::NotFound {
        DirectoryReadStatus::Missing
    } else if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        DirectoryReadStatus::NotDirectory
    } else {
        DirectoryReadStatus::Unreadable
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct DirectoryStream(*mut libc::DIR);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(target_os = "linux")]
unsafe fn errno() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
unsafe fn errno() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn entry_identity(
    fd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
) -> std::io::Result<(
    caushell_types::DirectoryEntryKind,
    caushell_types::FileContentIdentity,
)> {
    use caushell_types::{DirectoryEntryKind as Kind, FileContentIdentity};
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    let kind = match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => Kind::File,
        libc::S_IFDIR => Kind::Directory,
        libc::S_IFLNK => Kind::Symlink,
        _ => Kind::Other,
    };
    Ok((
        kind,
        FileContentIdentity {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            size: stat.st_size as u64,
            modified_seconds: stat.st_mtime as i64,
            modified_nanos: stat.st_mtime_nsec as i64,
            changed_seconds: stat.st_ctime as i64,
            changed_nanos: stat.st_ctime_nsec as i64,
        },
    ))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use caushell_types::DirectoryEntryKind;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "caushell-directory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn empty_and_nonempty_directories_preserve_native_names_and_kinds() {
        let root = Fixture::new();
        let limits = DirectoryReadLimits::default();
        assert_eq!(
            read(root.path(), limits).complete_entries(root.path(), limits),
            Some(&[][..])
        );
        for name in ["line\nbreak", "a b", "--control='value'", ".hidden"] {
            fs::write(root.join(name), b"data").unwrap();
        }
        fs::create_dir(root.join("directory")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("link")).unwrap();
        let result = read(root.path(), limits);
        let entries = result.complete_entries(root.path(), limits).unwrap();
        assert_eq!(entries.len(), 6);
        assert!(
            entries
                .iter()
                .any(|e| e.name == "line\nbreak" && e.kind == DirectoryEntryKind::File)
        );
        assert!(
            entries
                .iter()
                .any(|e| e.name == "directory" && e.kind == DirectoryEntryKind::Directory)
        );
        assert!(
            entries
                .iter()
                .any(|e| e.name == "link" && e.kind == DirectoryEntryKind::Symlink)
        );
        assert_eq!(read(root.path(), limits), result);
    }

    #[test]
    fn missing_files_symlinks_and_unresolved_paths_do_not_become_empty_sets() {
        let root = Fixture::new();
        fs::write(root.join("file"), b"data").unwrap();
        std::os::unix::fs::symlink(root.path(), root.join("alias")).unwrap();
        for (path, expected) in [
            (root.join("missing"), DirectoryReadStatus::Missing),
            (root.join("file"), DirectoryReadStatus::NotDirectory),
            (root.join("alias"), DirectoryReadStatus::NotDirectory),
            (root.join("alias/file"), DirectoryReadStatus::NotDirectory),
            (root.join("../other"), DirectoryReadStatus::InvalidPath),
            (
                Path::new("relative").to_path_buf(),
                DirectoryReadStatus::InvalidPath,
            ),
        ] {
            let path = path.to_str().unwrap();
            let r = read(path, DirectoryReadLimits::default());
            assert_eq!(r.observation.status, expected, "{path}: {r:?}");
            assert!(
                r.complete_entries(path, DirectoryReadLimits::default())
                    .is_none()
            );
        }
    }

    #[test]
    fn non_utf8_names_are_reported_without_lossy_replacement() {
        // Exercise the exact native-name boundary even on filesystems that
        // reject these bytes at creation time. No lossy replacement or empty
        // complete enumeration may stand in for NonUtf8.
        let raw = std::ffi::CStr::from_bytes_with_nul(b"a\xff\0").unwrap();
        assert_eq!(entry_name(raw), Err(DirectoryReadStatus::NonUtf8));
        assert_eq!(entry_name(c"a b"), Ok(Some("a b")));
        assert_eq!(entry_name(c"."), Ok(None));
        assert_eq!(entry_name(c".."), Ok(None));
    }

    #[test]
    fn native_filesystem_preserves_or_rejects_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt;
        let root = Fixture::new();
        let created = fs::write(
            root.0.join(std::ffi::OsString::from_vec(vec![b'a', 0xff])),
            b"data",
        );
        if let Err(error) = created {
            // macOS native filesystems may reject invalid Unicode at open(2),
            // before readdir can supply any name. Unexpected errors still fail.
            assert!(cfg!(target_os = "macos"), "{error}");
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
            return;
        }
        assert_eq!(
            read(root.path(), DirectoryReadLimits::default())
                .observation
                .status,
            DirectoryReadStatus::NonUtf8
        );
    }

    #[test]
    fn native_entry_and_name_limits_are_enforced() {
        let root = Fixture::new();
        fs::write(root.join("data"), b"bytes").unwrap();
        let limits = DirectoryReadLimits {
            max_entries: 1,
            max_name_bytes: 4,
        };
        assert!(
            read(root.path(), limits)
                .complete_entries(root.path(), limits)
                .is_some()
        );
        assert_eq!(
            read(
                root.path(),
                DirectoryReadLimits {
                    max_name_bytes: 3,
                    ..limits
                }
            )
            .observation
            .status,
            DirectoryReadStatus::TooLarge
        );
        fs::write(root.join("other"), b"bytes").unwrap();
        assert_eq!(
            read(root.path(), limits).observation.status,
            DirectoryReadStatus::TooLarge
        );
    }

    #[test]
    fn changed_entry_and_replaced_directory_are_not_complete() {
        let root = Fixture::new();
        fs::create_dir(root.join("child")).unwrap();
        fs::write(root.join("child/file"), b"before").unwrap();
        let child = root.join("child");
        let path = child.to_str().unwrap();
        let result = read_with(path, DirectoryReadLimits::default(), || {
            fs::write(root.join("child/file"), b"changed content").unwrap();
        });
        assert_eq!(result.observation.status, DirectoryReadStatus::Changed);
        let result = read_with(path, DirectoryReadLimits::default(), || {
            fs::rename(&child, root.join("old")).unwrap();
            fs::create_dir(&child).unwrap();
        });
        assert_eq!(result.observation.status, DirectoryReadStatus::Changed);
    }
}

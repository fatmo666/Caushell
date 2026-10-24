use caushell_runner::MAX_RUNTIME_FILE_BYTES;
use caushell_types::*;

pub(crate) fn read(path: &str) -> RuntimeFileObservation {
    let failed = |status, reason: String| RuntimeFileObservation {
        content: caushell_runner::FileContentRead::failed(
            FileContentSource::CurrentProcess,
            path,
            MAX_RUNTIME_FILE_BYTES,
            status,
            reason,
        )
        .observation,
        executable: None,
    };
    #[cfg(unix)]
    {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        if !caushell_runner::directory_path_is_resolved(path) {
            return failed(
                FileContentStatus::NonRegular,
                "unresolved runtime path".into(),
            );
        }
        let mut file = match crate::file_content::open_regular_path(path) {
            Ok(file) => file,
            Err(error) => {
                return failed(
                    if error.kind() == std::io::ErrorKind::NotFound {
                        FileContentStatus::Missing
                    } else {
                        FileContentStatus::Unreadable
                    },
                    error.to_string(),
                );
            }
        };
        let before = match file.metadata() {
            Ok(meta) if meta.is_file() => crate::file_content::identity(&meta),
            _ => {
                return failed(
                    FileContentStatus::NonRegular,
                    "runtime entry is not a regular file".into(),
                );
            }
        };
        if before.size > MAX_RUNTIME_FILE_BYTES as u64 {
            return failed(
                FileContentStatus::TooLarge,
                "runtime file digest budget exceeded".into(),
            );
        }
        let mut buffer = [0u8; 32768];
        let mut hash = Sha256::new();
        let mut bytes = 0;
        loop {
            let n = match file.read(&mut buffer) {
                Ok(n) => n,
                Err(e) => return failed(FileContentStatus::Unreadable, e.to_string()),
            };
            if n == 0 {
                break;
            }
            bytes += n;
            if bytes > MAX_RUNTIME_FILE_BYTES {
                return failed(
                    FileContentStatus::TooLarge,
                    "runtime file grew beyond budget".into(),
                );
            }
            hash.update(&buffer[..n]);
        }
        let Ok(name) = std::ffi::CString::new(path) else {
            return failed(FileContentStatus::NonRegular, "NUL in runtime path".into());
        };
        // The caller supplies the execution namespace. Permission is queried
        // for that process's effective IDs, after opening without symlinks.
        let executable = unsafe {
            libc::faccessat(libc::AT_FDCWD, name.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0
        };
        let stable = file
            .metadata()
            .ok()
            .filter(|m| m.is_file())
            .is_some_and(|m| crate::file_content::identity(&m) == before)
            && std::fs::symlink_metadata(path)
                .ok()
                .filter(|m| m.is_file())
                .is_some_and(|m| crate::file_content::identity(&m) == before)
            && bytes as u64 == before.size;
        if !stable {
            return failed(
                FileContentStatus::Changed,
                "runtime file changed during observation".into(),
            );
        }
        RuntimeFileObservation {
            content: FileContentObservation {
                source: FileContentSource::CurrentProcess,
                path: path.into(),
                status: FileContentStatus::Complete,
                byte_limit: MAX_RUNTIME_FILE_BYTES,
                bytes_observed: bytes,
                sha256: Some(format!("{:x}", hash.finalize())),
                identity: Some(before),
                detail: None,
            },
            executable: Some(executable),
        }
    }
    #[cfg(not(unix))]
    failed(
        FileContentStatus::Unavailable,
        "runtime digests are unavailable".into(),
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    };

    #[test]
    fn local_digest_rejects_links_special_files_and_over_budget_content() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "caushell-runtime-digest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("python");
        std::fs::write(&file, b"abc").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
        let observed = read(file.to_str().unwrap());
        assert_eq!(observed.content.status, FileContentStatus::Complete);
        assert_eq!(observed.executable, Some(true));
        assert_eq!(
            observed.content.sha256.as_deref(),
            Some(caushell_runner::content_sha256(b"abc").as_str())
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(file.to_str().unwrap()).executable, Some(false));
        let link = root.join("link");
        symlink(&file, &link).unwrap();
        assert_ne!(
            read(link.to_str().unwrap()).content.status,
            FileContentStatus::Complete
        );
        let fifo = root.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_ne!(
            read(fifo.to_str().unwrap()).content.status,
            FileContentStatus::Complete
        );
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_len(MAX_RUNTIME_FILE_BYTES as u64 + 1)
            .unwrap();
        assert_eq!(
            read(file.to_str().unwrap()).content.status,
            FileContentStatus::TooLarge
        );
        assert_eq!(
            read(root.join("missing").to_str().unwrap()).content.status,
            FileContentStatus::Missing
        );
        for path in [fifo, link, file] {
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }
}

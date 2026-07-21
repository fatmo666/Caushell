use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;

#[cfg(unix)]
pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
pub const PRIVATE_FILE_MODE: u32 = 0o600;

static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn private_directory_is_usable(path: &Path) -> bool {
    require_private_directory(path).is_ok()
}

pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    let path = absolute_lexical_path(path)?;
    let mut current = PathBuf::new();
    let components = path.components().collect::<Vec<_>>();

    for (index, component) in components.iter().enumerate() {
        push_component(&mut current, *component)?;
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }

        let is_target = index + 1 == components.len();
        ensure_directory_component(&current, is_target)?;
    }

    require_private_directory(&path)
}

pub fn ensure_private_directory_tree(root: &Path, target: &Path) -> io::Result<()> {
    let root = absolute_lexical_path(root)?;
    let target = absolute_lexical_path(target)?;
    if !target.starts_with(&root) {
        return Err(invalid_input(format!(
            "runtime path {} is outside private root {}",
            target.display(),
            root.display()
        )));
    }

    ensure_private_directory(&root)?;
    let mut current = root;
    for component in target
        .strip_prefix(&current)
        .map_err(|_| {
            invalid_input(format!(
                "runtime path {} is outside private root {}",
                target.display(),
                current.display()
            ))
        })?
        .components()
    {
        match component {
            Component::Normal(value) => current.push(value),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_input(format!(
                    "invalid private runtime path component in {}",
                    target.display()
                )));
            }
        }
        ensure_private_directory(&current)?;
    }
    Ok(())
}

pub fn require_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(invalid_input(format!(
            "runtime path is not a real directory: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        require_current_owner(&metadata, path)?;
        if metadata.permissions().mode() & 0o777 != PRIVATE_DIRECTORY_MODE {
            return Err(permission_denied(format!(
                "runtime directory must have mode 0700: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

pub fn harden_private_tree(root: &Path) -> io::Result<()> {
    ensure_private_directory(root)?;
    harden_private_tree_inner(root)
}

pub fn open_private_append(path: &Path) -> io::Result<File> {
    let mut options = private_open_options();
    options.create(true).append(true);
    open_private_file(path, &mut options)
}

pub fn open_private_read_write(path: &Path) -> io::Result<File> {
    let mut options = private_open_options();
    options.create(true).read(true).write(true);
    open_private_file(path, &mut options)
}

pub fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let mut options = private_open_options();
    options.create(true).write(true).truncate(true);
    let mut file = open_private_file(path, &mut options)?;
    file.write_all(contents.as_ref())?;
    file.flush()
}

pub fn write_private_file_atomic(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input(format!("runtime file has no parent: {}", path.display())))?;
    require_private_directory(parent)?;

    let (temp_path, mut temp_file) = create_private_atomic_temp_file(path)?;
    let result = (|| {
        temp_file.write_all(contents.as_ref())?;
        temp_file.sync_all()?;
        drop(temp_file);
        fs::rename(&temp_path, path)?;

        let metadata = fs::symlink_metadata(path)?;
        validate_private_regular_metadata(&metadata, path)?;
        #[cfg(unix)]
        {
            set_mode_if_needed(path, &metadata, PRIVATE_FILE_MODE)?;
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

pub fn write_private_file_atomic_new(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input(format!("runtime file has no parent: {}", path.display())))?;
    require_private_directory(parent)?;

    let (temp_path, mut temp_file) = create_private_atomic_temp_file(path)?;
    let mut target_created = false;
    let result = (|| {
        temp_file.write_all(contents.as_ref())?;
        temp_file.sync_all()?;
        drop(temp_file);
        fs::hard_link(&temp_path, path)?;
        target_created = true;
        if let Err(error) = fs::remove_file(&temp_path) {
            let _ = fs::remove_file(path);
            return Err(error);
        }

        let metadata = fs::symlink_metadata(path)?;
        validate_private_regular_metadata(&metadata, path)?;
        #[cfg(unix)]
        {
            set_mode_if_needed(path, &metadata, PRIVATE_FILE_MODE)?;
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
        if target_created {
            let _ = fs::remove_file(path);
        }
    }
    result
}

pub fn read_private_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = private_open_options();
    options.read(true);
    let mut file = open_private_file(path, &mut options)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

pub fn read_private_file_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match read_private_file(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn read_private_to_string_optional(path: &Path) -> io::Result<Option<String>> {
    let Some(contents) = read_private_file_optional(path)? else {
        return Ok(None);
    };
    String::from_utf8(contents)
        .map(Some)
        .map_err(|error| invalid_data(format!("private runtime file is not UTF-8: {error}")))
}

pub fn wait_for_process_start_marker(pid: u32, timeout: Duration) -> Option<u64> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(marker) = process_start_marker(pid) {
            return Some(marker);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

pub fn process_identity_matches(
    pid: u32,
    expected_start_marker: u64,
    expected_executable: &Path,
) -> bool {
    if process_start_marker(pid) != Some(expected_start_marker) {
        return false;
    }
    let executable_matches = process_executable_path(pid)
        .is_some_and(|actual_executable| same_file(&actual_executable, expected_executable));
    executable_matches && process_start_marker(pid) == Some(expected_start_marker)
}

#[cfg(target_os = "linux")]
pub fn process_start_marker(pid: u32) -> Option<u64> {
    let contents = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = contents.rfind(')')?;
    let rest = contents.get(end + 2..)?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    fields.get(19)?.parse::<u64>().ok()
}

#[cfg(target_os = "macos")]
pub fn process_start_marker(pid: u32) -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let bytes_written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if bytes_written != size as libc::c_int {
        return None;
    }

    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid {
        return None;
    }
    info.pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_start_marker(_pid: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn process_executable_path(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
fn process_executable_path(pid: u32) -> Option<PathBuf> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let bytes_written = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if bytes_written <= 0 {
        return None;
    }

    let bytes = &buffer[..bytes_written as usize];
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end])))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_executable_path(_pid: u32) -> Option<PathBuf> {
    None
}

#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> bool {
    let (Ok(left), Ok(right)) = (fs::metadata(left), fs::metadata(right)) else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

pub fn remove_private_file_if_exists(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    validate_private_regular_metadata(&metadata, path)?;
    fs::remove_file(path)
}

#[cfg(unix)]
pub fn secure_unix_socket(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(invalid_input(format!(
            "runtime socket path is not a socket: {}",
            path.display()
        )));
    }
    require_current_owner(&metadata, path)?;
    harden_unix_socket_access(path, &metadata)?;
    require_private_unix_socket(path)
}

#[cfg(unix)]
pub fn require_private_unix_socket(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(invalid_input(format!(
            "runtime socket path is not a socket: {}",
            path.display()
        )));
    }
    require_current_owner(&metadata, path)?;
    require_unix_socket_access(path, &metadata)
}

#[cfg(unix)]
pub fn remove_private_unix_socket_if_exists(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(invalid_input(format!(
            "refusing to remove non-socket runtime path: {}",
            path.display()
        )));
    }
    require_current_owner(&metadata, path)?;
    fs::remove_file(path)
}

#[cfg(not(unix))]
pub fn remove_private_unix_socket_if_exists(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix runtime sockets are unsupported on this platform",
    ))
}

#[cfg(unix)]
pub fn verify_same_user_peer(stream: &UnixStream) -> io::Result<()> {
    let actual_uid = peer_effective_uid(stream)?;
    let expected_uid = unsafe { libc::geteuid() };
    if actual_uid != expected_uid {
        return Err(permission_denied(format!(
            "runtime socket peer uid {actual_uid} does not match effective uid {expected_uid}"
        )));
    }
    Ok(())
}

fn harden_private_tree_inner(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let entry_path = entry.path();
        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };

        if metadata.file_type().is_symlink() {
            return Err(invalid_input(format!(
                "runtime tree contains a symlink: {}",
                entry_path.display()
            )));
        }

        #[cfg(unix)]
        require_current_owner(&metadata, &entry_path)?;

        if metadata.file_type().is_dir() {
            #[cfg(unix)]
            set_mode_if_needed(&entry_path, &metadata, PRIVATE_DIRECTORY_MODE)?;
            harden_private_tree_inner(&entry_path)?;
        } else if metadata.file_type().is_file() {
            validate_private_regular_metadata(&metadata, &entry_path)?;
            #[cfg(unix)]
            set_mode_if_needed(&entry_path, &metadata, PRIVATE_FILE_MODE)?;
        } else {
            #[cfg(unix)]
            if metadata.file_type().is_socket() {
                harden_unix_socket_access(&entry_path, &metadata)?;
                continue;
            }
            return Err(invalid_input(format!(
                "runtime tree contains an unsupported file type: {}",
                entry_path.display()
            )));
        }
    }
    Ok(())
}

fn ensure_directory_component(path: &Path, is_target: bool) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(PRIVATE_DIRECTORY_MODE);
            match builder.create(path) {
                Ok(()) => fs::symlink_metadata(path)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::symlink_metadata(path)?
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(invalid_input(format!(
            "runtime path component is not a real directory: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        require_safe_directory_owner(&metadata, path, is_target)?;
        if is_target {
            set_mode_if_needed(path, &metadata, PRIVATE_DIRECTORY_MODE)?;
        }
    }
    Ok(())
}

fn open_private_file(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input(format!("runtime file has no parent: {}", path.display())))?;
    require_private_directory(parent)?;
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    validate_private_regular_metadata(&metadata, path)?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE {
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    }
    Ok(file)
}

fn private_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        options
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
}

fn create_private_atomic_temp_file(path: &Path) -> io::Result<(PathBuf, File)> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_input(format!("runtime file has no parent: {}", path.display())))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| invalid_input(format!("runtime file has no name: {}", path.display())))?;

    for _ in 0..128 {
        let counter = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(file_name);
        temp_name.push(format!(".{}.{}.tmp", std::process::id(), counter));
        let temp_path = parent.join(temp_name);
        let mut options = private_open_options();
        options.create_new(true).write(true);
        match open_private_file(&temp_path, &mut options) {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "failed to allocate private temporary file next to {}",
            path.display()
        ),
    ))
}

fn validate_private_regular_metadata(metadata: &fs::Metadata, path: &Path) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(invalid_input(format!(
            "runtime path is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        require_current_owner(metadata, path)?;
        if metadata.nlink() != 1 {
            return Err(permission_denied(format!(
                "runtime file must not have hard links: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_current_owner(metadata: &fs::Metadata, path: &Path) -> io::Result<()> {
    let expected_uid = unsafe { libc::geteuid() };
    if metadata.uid() != expected_uid {
        return Err(permission_denied(format!(
            "runtime path {} is owned by uid {}, expected {}",
            path.display(),
            metadata.uid(),
            expected_uid
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn require_safe_directory_owner(
    metadata: &fs::Metadata,
    path: &Path,
    is_target: bool,
) -> io::Result<()> {
    let expected_uid = unsafe { libc::geteuid() };
    let actual_uid = metadata.uid();
    if actual_uid == expected_uid || (!is_target && actual_uid == 0) {
        return Ok(());
    }
    Err(permission_denied(format!(
        "runtime path component {} is owned by uid {}, expected {}{}",
        path.display(),
        actual_uid,
        expected_uid,
        if is_target { "" } else { " or root" }
    )))
}

#[cfg(unix)]
fn set_mode_if_needed(path: &Path, metadata: &fs::Metadata, mode: u32) -> io::Result<()> {
    if metadata.permissions().mode() & 0o777 != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let actual = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
    if actual != mode {
        return Err(permission_denied(format!(
            "runtime path {} has mode {actual:04o}, expected {mode:04o}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn harden_unix_socket_access(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    set_mode_if_needed(path, metadata, PRIVATE_FILE_MODE)
}

#[cfg(target_os = "macos")]
fn harden_unix_socket_access(path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    require_private_socket_parent(path)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn require_unix_socket_access(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE {
        return Err(permission_denied(format!(
            "runtime socket must have mode 0600: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_unix_socket_access(path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    require_private_socket_parent(path)
}

#[cfg(target_os = "macos")]
fn require_private_socket_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        invalid_input(format!(
            "runtime socket has no parent directory: {}",
            path.display()
        ))
    })?;
    require_private_directory(parent)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_effective_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(credentials.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn peer_effective_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
fn peer_effective_uid(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix peer credential checks are unsupported on this platform",
    ))
}

fn absolute_lexical_path(path: &Path) -> io::Result<PathBuf> {
    let source = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in source.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(invalid_input(format!(
                        "runtime path escapes filesystem root: {}",
                        path.display()
                    )));
                }
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    Ok(normalized)
}

fn push_component(path: &mut PathBuf, component: Component<'_>) -> io::Result<()> {
    match component {
        Component::Prefix(prefix) => path.push(prefix.as_os_str()),
        Component::RootDir => path.push(Path::new("/")),
        Component::CurDir => {}
        Component::ParentDir => {
            return Err(invalid_input("unexpected parent component in runtime path"));
        }
        Component::Normal(value) => path.push(value),
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn permission_denied(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir()
            .canonicalize()
            .expect("temporary directory should resolve to a real directory");
        temp_dir.join(format!("crs-{:x}-{unique:x}", std::process::id()))
    }

    #[test]
    fn harden_private_tree_migrates_directory_and_file_modes() {
        let root = temp_root();
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("metadata.json"), b"{}\n").unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            nested.join("metadata.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        harden_private_tree(&root).unwrap();

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(nested.join("metadata.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn harden_private_tree_secures_socket_access() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        let socket_path = root.join("runtime.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        #[cfg(not(target_os = "macos"))]
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o755)).unwrap();

        #[cfg(target_os = "macos")]
        assert!(require_private_unix_socket(&socket_path).is_err());

        harden_private_tree(&root).unwrap();

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );

        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            fs::symlink_metadata(&socket_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        require_private_unix_socket(&socket_path).unwrap();

        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_file_helpers_reject_symlinks_and_hard_links() {
        let root = temp_root();
        ensure_private_directory(&root).unwrap();
        let target = root.join("target");
        write_private_file(&target, b"secret").unwrap();

        let symlink_path = root.join("symlink");
        symlink(&target, &symlink_path).unwrap();
        assert!(read_private_file(&symlink_path).is_err());

        let hardlink_path = root.join("hardlink");
        fs::hard_link(&target, &hardlink_path).unwrap();
        assert!(read_private_file(&target).is_err());
        assert!(read_private_file(&hardlink_path).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_private_write_replaces_contents_without_weakening_permissions() {
        let root = temp_root();
        ensure_private_directory(&root).unwrap();
        let target = root.join("config.yaml");
        write_private_file(&target, b"old").unwrap();

        write_private_file_atomic(&target, b"new contents").unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new contents");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            PRIVATE_FILE_MODE
        );
        assert_eq!(
            fs::read_dir(&root).unwrap().filter_map(Result::ok).count(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_private_new_write_does_not_replace_existing_file() {
        let root = temp_root();
        ensure_private_directory(&root).unwrap();
        let target = root.join("config.yaml");
        write_private_file(&target, b"original").unwrap();

        let error = write_private_file_atomic_new(&target, b"replacement").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert_eq!(
            fs::read_dir(&root).unwrap().filter_map(Result::ok).count(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_directory_rejects_symlink_targets() {
        let root = temp_root();
        let real = root.join("real");
        let linked = root.join("linked");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, &linked).unwrap();

        let error = ensure_private_directory(&linked)
            .expect_err("expected private runtime directory symlink to be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_user_unix_socket_peer_is_accepted() {
        let root = temp_root();
        ensure_private_directory(&root).unwrap();
        let socket_path = root.join("runtime.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        secure_unix_socket(&socket_path).unwrap();

        let client = UnixStream::connect(&socket_path).unwrap();
        let (server, _) = listener.accept().unwrap();
        verify_same_user_peer(&client).unwrap();
        verify_same_user_peer(&server).unwrap();

        drop(client);
        drop(server);
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_identity_requires_matching_start_marker_and_executable() {
        let pid = std::process::id();
        let marker =
            process_start_marker(pid).expect("current process should expose a start marker");
        let executable = std::env::current_exe().expect("current executable should be known");

        assert!(process_identity_matches(pid, marker, &executable));
        assert!(!process_identity_matches(
            pid,
            marker.wrapping_add(1),
            &executable
        ));
        assert!(!process_identity_matches(
            pid,
            marker,
            Path::new("/definitely/not/the/current/executable")
        ));
    }

    #[test]
    fn waiting_for_process_start_marker_returns_current_process_identity() {
        assert_eq!(
            wait_for_process_start_marker(std::process::id(), Duration::from_millis(100)),
            process_start_marker(std::process::id())
        );
    }
}

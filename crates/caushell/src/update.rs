use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use caushell::CliError;
use serde::{Deserialize, Serialize};

const DEFAULT_REPOSITORY: &str = "fatmo666/Caushell";
const RELEASE_BINARIES: &[&str] = &[
    "caushell",
    "caushell-adapter-codex",
    "caushell-codex-hook",
    "caushell-adapter-claude",
    "caushell-claude-hook",
];
const CODEX_PLUGIN_ID: &str = "caushell-codex@caushell";
const CLAUDE_PLUGIN_ID: &str = "caushell-claude@caushell";

const CAUSHELL_VERSION: &str = env!("CARGO_PKG_VERSION");
const CAUSHELL_BUILD_COMMIT: &str = env!("CAUSHELL_BUILD_COMMIT");
const CAUSHELL_RELEASE_TAG: &str = env!("CAUSHELL_RELEASE_TAG");
const CAUSHELL_BUILD_TARGET: &str = env!("CAUSHELL_BUILD_TARGET");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BuildInfo {
    pub name: String,
    pub version: String,
    pub commit: String,
    pub release: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateOptions {
    help: bool,
    check_only: bool,
    runtime_only: bool,
    version: Option<String>,
}

#[derive(Debug, Clone)]
struct Package {
    package_dir: PathBuf,
    candidate_info: BuildInfo,
}

#[derive(Debug, Clone)]
struct UpdateWorkspace {
    path: PathBuf,
}

impl Drop for UpdateWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct UpdateLock {
    _file: File,
}

#[derive(Debug, Clone)]
struct InstalledAgent {
    name: AgentName,
    scope: Option<String>,
    enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentName {
    Codex,
    Claude,
}

impl AgentName {
    fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Claude => "Claude Code",
        }
    }
}

#[derive(Debug, Deserialize)]
struct CodexPluginList {
    #[serde(default)]
    installed: Vec<CodexPluginEntry>,
}

#[derive(Debug, Deserialize)]
struct CodexPluginEntry {
    #[serde(rename = "pluginId")]
    plugin_id: String,
    #[serde(default)]
    installed: bool,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ClaudePluginEntry {
    id: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

pub(crate) fn current_build_info() -> BuildInfo {
    BuildInfo {
        name: "caushell".to_string(),
        version: CAUSHELL_VERSION.to_string(),
        commit: CAUSHELL_BUILD_COMMIT.to_string(),
        release: CAUSHELL_RELEASE_TAG.to_string(),
        target: CAUSHELL_BUILD_TARGET.to_string(),
    }
}

pub(crate) fn run_build_info(mut args: impl Iterator<Item = String>) -> Result<(), CliError> {
    if let Some(argument) = args.next() {
        return Err(invalid_update_argument(format!(
            "unexpected build-info argument: {argument}"
        )));
    }
    serde_json::to_writer_pretty(std::io::stdout().lock(), &current_build_info())
        .map_err(CliError::InvalidResponse)?;
    println!();
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), CliError> {
    let options = parse_update_options(&mut args)?;
    if options.help {
        return Ok(());
    }
    let target = release_target()?;
    let install_dir = update_install_dir()?;
    let _lock = if options.check_only {
        None
    } else {
        Some(acquire_update_lock(&install_dir)?)
    };
    let workspace = create_update_workspace(&install_dir, options.check_only)?;
    let repository = env::var("CAUSHELL_REPO").unwrap_or_else(|_| DEFAULT_REPOSITORY.to_string());

    println!("Caushell update");
    println!("  install_dir={}", install_dir.display());
    println!("  target={target}");

    let package =
        download_and_stage_package(&workspace, &repository, &target, options.version.as_deref())?;
    let current = current_build_info();
    println!(
        "  current={}/{}",
        current.release,
        short_commit(&current.commit)
    );
    println!(
        "  available={}/{}",
        package.candidate_info.release,
        short_commit(&package.candidate_info.commit)
    );

    let runtime_changed = !same_build(&current, &package.candidate_info);
    if runtime_changed {
        if options.check_only {
            println!("[ok] update is available (check only; nothing was changed)");
            return Ok(());
        }

        replace_runtime_binaries(&install_dir, &package.package_dir)?;
        println!("[ok] runtime binaries updated");
    } else {
        println!("[ok] runtime binaries are already up to date");
        if options.check_only || options.runtime_only {
            return Ok(());
        }
    }

    let agents = if options.runtime_only {
        Vec::new()
    } else {
        match refresh_installed_plugins(&repository) {
            Ok(agents) => agents,
            Err(error) => {
                let state = if runtime_changed {
                    "runtime updated"
                } else {
                    "runtime is current"
                };
                return Err(io::Error::other(format!(
                    "{state}, but an installed agent plugin could not be refreshed: {error}"
                ))
                .into());
            }
        }
    };
    run_post_update_doctor(&install_dir, &agents)?;

    if runtime_changed || !agents.is_empty() {
        println!(
            "[ok] update complete; restart Codex or Claude Code to load the updated runtime/plugin"
        );
    } else {
        println!("[ok] update complete; no runtime or enabled plugin changes were needed");
    }
    Ok(())
}

fn parse_update_options(
    args: &mut impl Iterator<Item = String>,
) -> Result<UpdateOptions, CliError> {
    let mut check_only = false;
    let mut runtime_only = false;
    let mut version = None;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--check" => check_only = true,
            "--runtime-only" | "--no-plugins" => runtime_only = true,
            "--version" => {
                let Some(value) = args.next() else {
                    return Err(invalid_update_argument(
                        "caushell update --version requires a release tag",
                    ));
                };
                if value.trim().is_empty() {
                    return Err(invalid_update_argument(
                        "caushell update --version requires a non-empty release tag",
                    ));
                }
                validate_release_tag(&value)?;
                version = Some(value);
            }
            "--help" | "-h" => {
                print_update_usage();
                return Ok(UpdateOptions {
                    help: true,
                    check_only: true,
                    runtime_only: true,
                    version: None,
                });
            }
            other => {
                return Err(invalid_update_argument(format!(
                    "unexpected update argument: {other}"
                )));
            }
        }
    }

    Ok(UpdateOptions {
        help: false,
        check_only,
        runtime_only,
        version,
    })
}

fn invalid_update_argument(message: impl Into<String>) -> CliError {
    CliError::InvalidArguments(message.into())
}

fn validate_release_tag(value: &str) -> Result<(), CliError> {
    if !value.is_empty()
        && (value == "latest"
            || value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            }))
    {
        Ok(())
    } else {
        Err(invalid_update_argument(format!(
            "invalid release tag {value:?}; use letters, numbers, '.', '_' or '-'"
        )))
    }
}

fn print_update_usage() {
    eprintln!(
        "usage: caushell update [--check] [--runtime-only] [--version <release-tag>]\n       caushell --update [--check] [--runtime-only] [--version <release-tag>]\n\nupdates the Caushell runtime and already-installed, enabled agent plugins\n--check verifies and reports the available build without changing files\n--runtime-only updates runtime binaries without touching agent plugins\n--no-plugins is an alias for --runtime-only\n--version pins a GitHub release tag; default is the GitHub latest release"
    );
}

fn release_target() -> Result<&'static str, CliError> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Ok("x86_64-unknown-linux-musl");
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Ok("x86_64-apple-darwin");
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Ok("aarch64-apple-darwin");
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        Err(CliError::UnsupportedPlatform("caushell update"))
    }
}

fn update_install_dir() -> Result<PathBuf, CliError> {
    if let Some(path) = env_path("CAUSHELL_UPDATE_INSTALL_DIR") {
        return Ok(path);
    }
    if let Some(path) = env_path("CAUSHELL_INSTALL_DIR") {
        return Ok(path);
    }
    let executable = env::current_exe()?;
    executable.parent().map(Path::to_path_buf).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "caushell executable has no parent directory",
        )
        .into()
    })
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn acquire_update_lock(install_dir: &Path) -> Result<UpdateLock, CliError> {
    fs::create_dir_all(install_dir)?;
    let path = install_dir.join(".caushell-update.lock");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to use symlinked update lock {}", path.display()),
            )
            .into());
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "another Caushell update is already running ({})",
                        path.display()
                    ),
                )
                .into());
            }
            return Err(error.into());
        }
    }

    Ok(UpdateLock { _file: file })
}

fn create_update_workspace(
    install_dir: &Path,
    check_only: bool,
) -> Result<UpdateWorkspace, CliError> {
    let parent = if check_only {
        env::temp_dir()
    } else {
        install_dir
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };
    fs::create_dir_all(&parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = parent.join(format!(".caushell-update-{}-{stamp}", std::process::id()));
    fs::create_dir(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(UpdateWorkspace { path })
}

fn download_and_stage_package(
    workspace: &UpdateWorkspace,
    repository: &str,
    target: &str,
    requested_version: Option<&str>,
) -> Result<Package, CliError> {
    let version = requested_version
        .map(str::to_owned)
        .or_else(|| env::var("CAUSHELL_UPDATE_VERSION").ok())
        .or_else(|| env::var("CAUSHELL_VERSION").ok())
        .unwrap_or_else(|| "latest".to_string());
    validate_release_tag(&version)?;
    let asset = format!("caushell-{target}.tar.gz");
    let archive_path = workspace.path.join(&asset);
    let checksum_path = workspace.path.join(format!("{asset}.sha256"));
    let package_url = release_asset_url(repository, &version, &asset);
    let checksum_url = format!("{package_url}.sha256");

    println!("[info] downloading {package_url}");
    download_file(&package_url, &archive_path)?;
    download_file(&checksum_url, &checksum_path)?;
    verify_checksum(&archive_path, &checksum_path)?;
    println!("[ok] release checksum verified");

    validate_archive_layout(&archive_path, &format!("caushell-{target}"))?;
    extract_archive(&archive_path, &workspace.path)?;
    let package_dir = workspace.path.join(format!("caushell-{target}"));
    let candidate_info = validate_package(&package_dir, target)?;
    Ok(Package {
        package_dir,
        candidate_info,
    })
}

fn validate_archive_layout(archive: &Path, package_name: &str) -> Result<(), CliError> {
    let output = Command::new("tar").args(["-tzf"]).arg(archive).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format_command_failure("list archive", &output)).into());
    }
    for entry in String::from_utf8_lossy(&output.stdout).lines() {
        let entry = entry.trim_end_matches('/');
        let safe_prefix = format!("{package_name}/");
        let safe = (entry == package_name || entry.starts_with(&safe_prefix))
            && !Path::new(entry)
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir));
        if !safe {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("release archive contains an unsafe path: {entry}"),
            )
            .into());
        }
    }

    let verbose = Command::new("tar").args(["-tvzf"]).arg(archive).output()?;
    if !verbose.status.success() {
        return Err(
            io::Error::other(format_command_failure("inspect archive entries", &verbose)).into(),
        );
    }
    for entry in String::from_utf8_lossy(&verbose.stdout).lines() {
        let Some(kind) = entry.as_bytes().first().copied() else {
            continue;
        };
        if !matches!(kind, b'-' | b'd') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("release archive contains a non-file entry: {entry}"),
            )
            .into());
        }
    }
    Ok(())
}

fn release_asset_url(repository: &str, version: &str, asset: &str) -> String {
    if let Some(base) = env::var("CAUSHELL_UPDATE_BASE_URL")
        .ok()
        .or_else(|| env::var("CAUSHELL_DOWNLOAD_BASE_URL").ok())
    {
        return format!("{}/{asset}", base.trim_end_matches('/'));
    }
    if version == "latest" {
        format!("https://github.com/{repository}/releases/latest/download/{asset}")
    } else {
        format!("https://github.com/{repository}/releases/download/{version}/{asset}")
    }
}

fn download_file(url: &str, destination: &Path) -> Result<(), CliError> {
    let output = if executable_on_path("curl") {
        Command::new("curl")
            .args(["-fsSL", "--retry", "3", "--connect-timeout", "15", "-o"])
            .arg(destination)
            .arg(url)
            .output()?
    } else if executable_on_path("wget") {
        Command::new("wget")
            .args(["-q", "-O"])
            .arg(destination)
            .arg(url)
            .output()?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "caushell update requires curl or wget",
        )
        .into());
    };
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format_command_failure("download", &output)).into())
}

fn verify_checksum(archive: &Path, checksum: &Path) -> Result<(), CliError> {
    let file_name = archive
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "release archive has no UTF-8 file name",
            )
        })?;
    let checksum_payload = fs::read_to_string(checksum)?;
    let expected = parse_checksum_file(&checksum_payload, file_name)?;
    let output = if executable_on_path("sha256sum") {
        Command::new("sha256sum").arg(archive).output()?
    } else if executable_on_path("shasum") {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(archive)
            .output()?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "caushell update requires sha256sum or shasum",
        )
        .into());
    };
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "checksum calculation failed for {file_name}: {}",
            format_command_failure("checksum", &output)
        ))
        .into());
    }
    let actual = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "checksum command returned no digest",
            )
        })?;
    if actual.len() != 64
        || !actual
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checksum command returned an invalid SHA-256 digest",
        )
        .into());
    }
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checksum mismatch for {file_name}: expected {expected}, got {actual}"),
        )
        .into())
    }
}

fn parse_checksum_file(payload: &str, expected_file_name: &str) -> Result<String, CliError> {
    let mut lines = payload.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "release checksum file is empty")
    })?;
    if lines.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "release checksum file must contain exactly one entry",
        )
        .into());
    }

    let mut fields = line.split_whitespace();
    let digest = fields.next().unwrap_or_default().to_ascii_lowercase();
    if digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "release checksum file does not contain a valid SHA-256 digest",
        )
        .into());
    }
    if let Some(file_name) = fields.next() {
        let file_name = file_name.strip_prefix('*').unwrap_or(file_name);
        if file_name != expected_file_name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("release checksum names {file_name:?}, expected {expected_file_name:?}"),
            )
            .into());
        }
    }
    if fields.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "release checksum entry contains unexpected fields",
        )
        .into());
    }
    Ok(digest)
}

fn extract_archive(archive: &Path, destination: &Path) -> Result<(), CliError> {
    let output = Command::new("tar")
        .args(["-xzf"])
        .arg(archive)
        .args(["-C"])
        .arg(destination)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format_command_failure("extract", &output)).into())
}

fn validate_package(package_dir: &Path, target: &str) -> Result<BuildInfo, CliError> {
    if !package_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("release package is missing {}", package_dir.display()),
        )
        .into());
    }
    for binary in RELEASE_BINARIES {
        let path = package_dir.join("bin").join(binary);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("release package is missing {binary}: {error}"),
            )
        })?;
        if !metadata.file_type().is_file() || !is_executable(&path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "release package binary is not executable: {}",
                    path.display()
                ),
            )
            .into());
        }
    }
    let info = read_build_info(&package_dir.join("bin/caushell")).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "release binary does not expose build-info; install a current release before updating: {error}"
            ),
        )
    })?;
    if info.name != "caushell"
        || info.version.trim().is_empty()
        || info.commit.trim().is_empty()
        || info.release.trim().is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "release binary returned incomplete or invalid build identity",
        )
        .into());
    }
    if info.target != "unknown" && info.target != target {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "release target mismatch: package={} host={target}",
                info.target
            ),
        )
        .into());
    }
    let update_help = Command::new(package_dir.join("bin/caushell"))
        .args(["update", "--help"])
        .output()?;
    if !update_help.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "release binary does not support built-in updates: {}",
                format_command_failure("update --help", &update_help)
            ),
        )
        .into());
    }
    Ok(info)
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn read_build_info(path: &Path) -> Result<BuildInfo, CliError> {
    let output = Command::new(path).args(["build-info"]).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format_command_failure("build-info", &output)).into());
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("release binary returned invalid build-info JSON: {error}"),
        )
        .into()
    })
}

fn replace_runtime_binaries(install_dir: &Path, package_dir: &Path) -> Result<(), CliError> {
    fs::create_dir_all(install_dir)?;
    for binary in RELEASE_BINARIES {
        let destination = install_dir.join(binary);
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to update symlinked binary {}; install into a real directory",
                        destination.display()
                    ),
                )
                .into());
            }
        }
    }

    let transaction = format!("{}-{}", std::process::id(), current_time_nanos());
    let mut changes = Vec::new();
    for binary in RELEASE_BINARIES {
        let destination = install_dir.join(binary);
        let candidate = package_dir.join("bin").join(binary);
        let backup = install_dir.join(format!(".{binary}.caushell-backup-{transaction}"));
        let had_existing = destination.exists();
        if had_existing {
            if let Err(error) = fs::rename(&destination, &backup) {
                rollback_replacements(&changes);
                return Err(error.into());
            }
        }
        if let Err(error) = fs::rename(&candidate, &destination) {
            if had_existing {
                let _ = fs::rename(&backup, &destination);
            }
            rollback_replacements(&changes);
            return Err(error.into());
        }
        changes.push((destination, backup, had_existing));
    }

    for (_, backup, had_existing) in &changes {
        if *had_existing {
            let _ = fs::remove_file(backup);
        }
    }
    Ok(())
}

fn rollback_replacements(changes: &[(PathBuf, PathBuf, bool)]) {
    for (destination, backup, had_existing) in changes.iter().rev() {
        let _ = fs::remove_file(destination);
        if *had_existing {
            let _ = fs::rename(backup, destination);
        }
    }
}

fn refresh_installed_plugins(repository: &str) -> Result<Vec<InstalledAgent>, CliError> {
    let mut agents = Vec::new();
    let mut errors = Vec::new();
    if executable_on_path("codex") {
        match installed_codex_plugin() {
            Ok(Some(agent)) => {
                if agent.enabled {
                    println!("[info] refreshing {} plugin", agent.name.label());
                    match refresh_codex_plugin(repository) {
                        Ok(()) => agents.push(agent),
                        Err(error) => {
                            eprintln!("[warn] Codex plugin refresh failed: {error}");
                            errors.push(format!("Codex: {error}"));
                        }
                    }
                } else {
                    println!("[skip] Codex plugin is installed but disabled; leaving it disabled");
                }
            }
            Ok(None) => println!("[skip] Codex plugin is not installed"),
            Err(error) => {
                eprintln!("[warn] could not inspect Codex plugins: {error}");
                errors.push(format!("Codex inspection: {error}"));
            }
        }
    } else {
        println!("[skip] Codex CLI is not on PATH");
    }
    if executable_on_path("claude") {
        match installed_claude_plugin() {
            Ok(Some(agent)) => {
                if agent.enabled {
                    println!("[info] refreshing {} plugin", agent.name.label());
                    match refresh_claude_plugin(&agent, repository) {
                        Ok(()) => agents.push(agent),
                        Err(error) => {
                            eprintln!("[warn] Claude Code plugin refresh failed: {error}");
                            errors.push(format!("Claude Code: {error}"));
                        }
                    }
                } else {
                    println!(
                        "[skip] Claude Code plugin is installed but disabled; leaving it disabled"
                    );
                }
            }
            Ok(None) => println!("[skip] Claude Code plugin is not installed"),
            Err(error) => {
                eprintln!("[warn] could not inspect Claude Code plugins: {error}");
                errors.push(format!("Claude Code inspection: {error}"));
            }
        }
    } else {
        println!("[skip] Claude Code CLI is not on PATH");
    }
    if errors.is_empty() {
        Ok(agents)
    } else {
        Err(io::Error::other(errors.join("; ")).into())
    }
}

fn installed_codex_plugin() -> Result<Option<InstalledAgent>, CliError> {
    let output = run_command("codex", ["plugin", "list", "--json"])?;
    if !output.status.success() {
        return Err(command_error("codex plugin list", &output));
    }
    parse_codex_plugin_list(&output.stdout)
}

fn parse_codex_plugin_list(payload: &[u8]) -> Result<Option<InstalledAgent>, CliError> {
    let list: CodexPluginList = serde_json::from_slice(payload).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Codex plugin list JSON: {error}"),
        )
    })?;
    Ok(list
        .installed
        .into_iter()
        .find(|entry| entry.plugin_id == CODEX_PLUGIN_ID && entry.installed)
        .map(|entry| InstalledAgent {
            name: AgentName::Codex,
            scope: None,
            enabled: entry.enabled,
        }))
}

fn installed_claude_plugin() -> Result<Option<InstalledAgent>, CliError> {
    let output = run_command("claude", ["plugin", "list", "--json"])?;
    if !output.status.success() {
        return Err(command_error("claude plugin list", &output));
    }
    parse_claude_plugin_list(&output.stdout)
}

fn parse_claude_plugin_list(payload: &[u8]) -> Result<Option<InstalledAgent>, CliError> {
    let list: Vec<ClaudePluginEntry> = serde_json::from_slice(payload).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Claude plugin list JSON: {error}"),
        )
    })?;
    Ok(list
        .into_iter()
        .find(|entry| entry.id == CLAUDE_PLUGIN_ID)
        .map(|entry| InstalledAgent {
            name: AgentName::Claude,
            scope: entry.scope,
            enabled: entry.enabled,
        }))
}

fn refresh_codex_plugin(repository: &str) -> Result<(), CliError> {
    run_checked("codex", ["plugin", "marketplace", "add", repository])?;
    run_checked("codex", ["plugin", "marketplace", "upgrade", "caushell"])?;
    let first_attempt = run_checked("codex", ["plugin", "add", CODEX_PLUGIN_ID]);
    match first_attempt {
        Ok(()) => Ok(()),
        Err(first_error) => {
            eprintln!("[warn] Codex plugin add failed; retrying once");
            let retry = run_checked("codex", ["plugin", "add", CODEX_PLUGIN_ID]);
            retry.map_err(|retry_error| {
                io::Error::other(format!(
                    "initial add failed: {first_error}; retry failed: {retry_error}"
                ))
                .into()
            })
        }
    }
}

fn refresh_claude_plugin(agent: &InstalledAgent, repository: &str) -> Result<(), CliError> {
    run_checked("claude", ["plugin", "marketplace", "add", repository])?;
    run_checked("claude", ["plugin", "marketplace", "update", "caushell"])?;
    let scope = agent.scope.as_deref().unwrap_or("user");
    run_checked(
        "claude",
        ["plugin", "update", CLAUDE_PLUGIN_ID, "--scope", scope],
    )?;
    Ok(())
}

fn run_post_update_doctor(install_dir: &Path, agents: &[InstalledAgent]) -> Result<(), CliError> {
    let runtime = install_dir.join("caushell");
    let updated_path = path_with_install_dir(install_dir);
    let mut failures = Vec::new();
    for agent in agents {
        let target = match agent.name {
            AgentName::Codex => "codex",
            AgentName::Claude => "claude",
        };
        let mut command = Command::new(&runtime);
        command.args(["doctor", target]);
        if let Some(path) = &updated_path {
            command.env("PATH", path);
        }
        match command.output() {
            Ok(output) if output.status.success() => {
                println!("[ok] {} doctor passed", agent.name.label());
            }
            Ok(output) => {
                eprintln!(
                    "[warn] {} doctor failed: {}",
                    agent.name.label(),
                    format_command_failure("doctor", &output)
                );
                failures.push(agent.name.label());
            }
            Err(error) => {
                eprintln!(
                    "[warn] could not run {} doctor: {error}",
                    agent.name.label()
                );
                failures.push(agent.name.label());
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "updated runtime/plugin, but post-update doctor failed for {}",
            failures.join(", ")
        ))
        .into())
    }
}

fn path_with_install_dir(install_dir: &Path) -> Option<OsString> {
    let mut paths = vec![install_dir.to_path_buf()];
    if let Some(existing) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing));
    }
    env::join_paths(paths).ok()
}

fn same_build(current: &BuildInfo, candidate: &BuildInfo) -> bool {
    current.commit != "unknown"
        && candidate.commit != "unknown"
        && current.commit == candidate.commit
        && (current.target == candidate.target
            || current.target == "unknown"
            || candidate.target == "unknown")
}

fn short_commit(commit: &str) -> &str {
    commit.get(..commit.len().min(7)).unwrap_or(commit)
}

fn current_time_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn executable_on_path(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|directory| {
        let candidate = directory.join(name);
        candidate.is_file() && is_executable(&candidate)
    })
}

fn run_command<I, S>(program: &str, args: I) -> Result<std::process::Output, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(program).args(args).output()?)
}

fn run_checked<I, S>(program: &str, args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<std::ffi::OsStr> + Clone,
{
    let output = run_command(program, args.clone())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, &output))
    }
}

fn command_error(program: &str, output: &std::process::Output) -> CliError {
    io::Error::other(format_command_failure(program, output)).into()
}

fn format_command_failure(program: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stderr.is_empty() {
        format!(
            "{program} exited with {}{}",
            output.status,
            if stdout.is_empty() {
                String::new()
            } else {
                format!(": {stdout}")
            }
        )
    } else {
        format!("{program} exited with {}: {stderr}", output.status)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentName, UpdateOptions, acquire_update_lock, parse_checksum_file,
        parse_claude_plugin_list, parse_codex_plugin_list, parse_update_options, same_build,
    };

    #[test]
    fn update_options_parse_check_and_version() {
        let mut args = [
            "--check".to_string(),
            "--runtime-only".to_string(),
            "--version".to_string(),
            "v0.0.1".to_string(),
        ]
        .into_iter();
        assert_eq!(
            parse_update_options(&mut args).expect("options should parse"),
            UpdateOptions {
                help: false,
                check_only: true,
                runtime_only: true,
                version: Some("v0.0.1".to_string())
            }
        );
    }

    #[test]
    fn same_build_requires_known_commit() {
        let current = super::BuildInfo {
            name: "caushell".to_string(),
            version: "0.0.1".to_string(),
            commit: "unknown".to_string(),
            release: "source".to_string(),
            target: "x86_64-unknown-linux-musl".to_string(),
        };
        let candidate = super::BuildInfo {
            commit: "unknown".to_string(),
            ..current.clone()
        };
        assert!(!same_build(&current, &candidate));
    }

    #[test]
    fn same_build_rejects_a_different_target() {
        let current = super::BuildInfo {
            name: "caushell".to_string(),
            version: "0.0.1".to_string(),
            commit: "same-commit".to_string(),
            release: "source".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
        };
        let candidate = super::BuildInfo {
            target: "x86_64-unknown-linux-musl".to_string(),
            ..current.clone()
        };
        assert!(!same_build(&current, &candidate));
    }

    #[test]
    fn checksum_file_must_name_only_the_expected_asset() {
        let digest = "a".repeat(64);
        assert_eq!(
            parse_checksum_file(
                &format!("{digest}  caushell-x86_64-unknown-linux-musl.tar.gz\n"),
                "caushell-x86_64-unknown-linux-musl.tar.gz",
            )
            .expect("release checksum should parse"),
            digest
        );

        let error = parse_checksum_file(
            &format!("{digest}  ../../etc/shadow\n"),
            "caushell-x86_64-unknown-linux-musl.tar.gz",
        )
        .expect_err("checksum must not name another path");
        assert!(error.to_string().contains("expected"));
    }

    #[cfg(unix)]
    #[test]
    fn update_lock_blocks_a_concurrent_updater() {
        let install_dir = std::env::temp_dir().join(format!(
            "caushell-update-lock-{}-{}",
            std::process::id(),
            super::current_time_nanos()
        ));
        let first = acquire_update_lock(&install_dir).expect("first update lock should succeed");
        let error = acquire_update_lock(&install_dir)
            .err()
            .expect("second update lock should be blocked");
        assert!(error.to_string().contains("already running"));

        drop(first);
        acquire_update_lock(&install_dir).expect("lock should be reusable after the first closes");
        std::fs::remove_dir_all(install_dir).expect("test install directory should be removable");
    }

    #[test]
    fn installed_agent_plugin_shapes_are_detected() {
        let codex = parse_codex_plugin_list(
            br#"{"installed":[{"pluginId":"caushell-codex@caushell","installed":true,"enabled":false}]}"#,
        )
        .expect("Codex plugin JSON should parse")
        .expect("Codex plugin should be found");
        assert_eq!(codex.name, AgentName::Codex);
        assert!(!codex.enabled);

        let claude = parse_claude_plugin_list(
            br#"[{"id":"caushell-claude@caushell","scope":"project","enabled":true}]"#,
        )
        .expect("Claude plugin JSON should parse")
        .expect("Claude plugin should be found");
        assert_eq!(claude.name, AgentName::Claude);
        assert_eq!(claude.scope.as_deref(), Some("project"));
    }
}

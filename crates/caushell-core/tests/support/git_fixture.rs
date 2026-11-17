//! These dispatch tests start with a controlled, already initialized repository.
//! Absence is an explicit executor observation, never inferred from no view.
use caushell_core::ShellQueryCore;
use caushell_runner::{FileContentRead, FilesystemView};
use caushell_types::*;
use std::sync::Arc;
struct CleanGit;
impl FilesystemView for CleanGit {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if [
            "/",
            "/bench",
            "/bench/workspace",
            "/tmp",
            "/tmp/repo",
            "/home",
            "/home/benchmark-user",
        ]
        .contains(&path)
            || ["/bench/workspace/.git", "/tmp/.git", "/tmp/repo/.git"].contains(&path)
        {
            FilesystemEntry::Directory
        } else if [
            "/bench/workspace/.git/config",
            "/tmp/.git/config",
            "/tmp/repo/.git/config",
        ]
        .contains(&path)
        {
            FilesystemEntry::File
        } else {
            FilesystemEntry::Missing
        }
    }
    fn read_file(&self, path: &str, limit: usize) -> FileContentRead {
        if self.entry(path) == FilesystemEntry::File {
            FileContentRead::complete(
                FileContentSource::SuppliedView,
                path,
                limit,
                None,
                Vec::new(),
            )
        } else {
            FileContentRead::failed(
                FileContentSource::SuppliedView,
                path,
                limit,
                FileContentStatus::Missing,
                "controlled fixture absence",
            )
        }
    }
}
pub fn core() -> ShellQueryCore {
    ShellQueryCore::new().with_filesystem_view(Arc::new(CleanGit))
}

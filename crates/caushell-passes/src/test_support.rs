use caushell_runner::{FilesystemView, RunnerContext};
use caushell_types::FilesystemEntry;

struct DirectoryFilesystem;
impl FilesystemView for DirectoryFilesystem {
    fn entry(&self, _path: &str) -> FilesystemEntry {
        FilesystemEntry::Directory
    }
}

pub(crate) fn supply_filesystem(ctx: &mut RunnerContext) {
    ctx.set_filesystem_view(std::sync::Arc::new(DirectoryFilesystem));
}

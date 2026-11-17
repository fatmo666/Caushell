//! Evidence-valued discovery. Failure to prove absence is never NotRepository.
use super::*;
use caushell_types::FilesystemEntry;

#[derive(Clone, Debug)]
pub(super) enum Repository {
    WorkTree(String),
    Bare(String),
    Absent,
    Unknown,
}
pub(super) fn discover(inputs: &mut Inputs<'_>, cwd: &str) -> Repository {
    let mut path = cwd.to_owned();
    // Searching past a native ceiling/mount is a conservative superset. Only
    // absence through the filesystem root is a negative certificate. Symlinks
    // and same-action namespace changes pass through Inputs::entry.
    for _ in 0..32 {
        let dot = crate::path::join_shell_path(&path, ".git");
        match inputs.entry(&dot) {
            FilesystemEntry::Directory | FilesystemEntry::File => {
                return Repository::WorkTree(path);
            }
            FilesystemEntry::Missing => (),
            _ => return Repository::Unknown,
        }
        // Bare repositories do not have a .git marker. A missing HEAD rules
        // them out independently of object-directory environment overrides.
        match inputs.entry(&crate::path::join_shell_path(&path, "HEAD")) {
            FilesystemEntry::Missing => (),
            FilesystemEntry::File => {
                if inputs.entry(&crate::path::join_shell_path(&path, "objects"))
                    == FilesystemEntry::Directory
                    && inputs.entry(&crate::path::join_shell_path(&path, "refs"))
                        == FilesystemEntry::Directory
                {
                    return Repository::Bare(path);
                }
                return Repository::Unknown;
            }
            _ => return Repository::Unknown,
        }
        if path == "/" {
            return Repository::Absent;
        }
        path = path
            .rsplit_once('/')
            .map_or("/", |(p, _)| if p.is_empty() { "/" } else { p })
            .into();
    }
    Repository::Unknown
}

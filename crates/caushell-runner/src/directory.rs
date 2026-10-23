use caushell_types::{
    DirectoryEntry, DirectoryEntryKind, DirectoryObservation, DirectoryReadLimits,
    DirectoryReadStatus, FileContentIdentity, FilesystemObservationSource, MAX_DIRECTORY_DEPTH,
    MAX_DIRECTORY_OBSERVATIONS,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryRead {
    pub observation: DirectoryObservation,
    entries: Option<Vec<DirectoryEntry>>,
}

impl DirectoryRead {
    pub fn complete(
        source: FilesystemObservationSource,
        path: &str,
        limits: DirectoryReadLimits,
        identity: FileContentIdentity,
        mut entries: Vec<DirectoryEntry>,
    ) -> Self {
        let failed = |status, detail| Self::failed(source, path, limits, status, detail);
        if !directory_path_is_resolved(path) {
            return failed(
                DirectoryReadStatus::InvalidPath,
                "expected a resolved absolute directory",
            );
        }
        if source == FilesystemObservationSource::Unavailable {
            return failed(
                DirectoryReadStatus::Unavailable,
                "directory source is unavailable",
            );
        }
        if !limits.is_valid() || entries.len() > limits.max_entries {
            return failed(
                DirectoryReadStatus::TooLarge,
                "directory entry budget exceeded",
            );
        }
        let Some(bytes) = name_bytes(&entries).filter(|n| *n <= limits.max_name_bytes) else {
            return failed(
                DirectoryReadStatus::TooLarge,
                "directory name budget exceeded",
            );
        };
        if entries.iter().any(|e| !valid_name(&e.name)) {
            return failed(DirectoryReadStatus::Changed, "invalid directory entry name");
        }
        // Canonical set representation, not a claim about native traversal order.
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        if entries.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return failed(DirectoryReadStatus::Changed, "duplicate directory entries");
        }
        Self {
            observation: DirectoryObservation {
                source,
                path: path.into(),
                status: DirectoryReadStatus::Complete,
                limits,
                entries_observed: entries.len(),
                name_bytes_observed: bytes,
                sha256: Some(entries_sha256(&identity, &entries)),
                identity: Some(identity),
                detail: None,
            },
            entries: Some(entries),
        }
    }

    pub fn failed(
        source: FilesystemObservationSource,
        path: &str,
        limits: DirectoryReadLimits,
        status: DirectoryReadStatus,
        detail: impl Into<String>,
    ) -> Self {
        assert_ne!(status, DirectoryReadStatus::Complete);
        Self {
            observation: DirectoryObservation {
                source,
                path: path.into(),
                status,
                limits,
                entries_observed: 0,
                name_bytes_observed: 0,
                sha256: None,
                identity: None,
                detail: Some(detail.into()),
            },
            entries: None,
        }
    }

    /// A complete set of direct children; its slice order is not tool output order.
    pub fn complete_entries(
        &self,
        path: &str,
        limits: DirectoryReadLimits,
    ) -> Option<&[DirectoryEntry]> {
        let entries = self.entries.as_deref()?;
        let o = &self.observation;
        (o.status == DirectoryReadStatus::Complete
            && o.source != FilesystemObservationSource::Unavailable
            && o.path == path
            && directory_path_is_resolved(path)
            && o.limits == limits
            && limits.is_valid()
            && o.identity.is_some()
            && o.entries_observed == entries.len()
            && entries.len() <= limits.max_entries
            && name_bytes(entries) == Some(o.name_bytes_observed)
            && o.name_bytes_observed <= limits.max_name_bytes
            && entries.iter().all(|e| valid_name(&e.name))
            && entries
                .windows(2)
                .all(|p| p[0].name.as_bytes() < p[1].name.as_bytes())
            && o.sha256.as_deref() == Some(entries_sha256(o.identity.as_ref()?, entries).as_str()))
        .then_some(entries)
    }
}

pub fn directory_path_is_resolved(path: &str) -> bool {
    path == "/"
        || (path.starts_with('/')
            && path.len() <= 16_384
            && !path.contains('\0')
            && path
                .split('/')
                .skip(1)
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && path.split('/').count() <= 256)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

fn name_bytes(entries: &[DirectoryEntry]) -> Option<usize> {
    entries
        .iter()
        .try_fold(0usize, |sum, e| sum.checked_add(e.name.len()))
}

fn entries_sha256(identity: &FileContentIdentity, entries: &[DirectoryEntry]) -> String {
    let mut hash = Sha256::new();
    hash_identity(&mut hash, identity);
    for entry in entries {
        hash.update((entry.name.len() as u64).to_le_bytes());
        hash.update(entry.name.as_bytes());
        hash.update([match entry.kind {
            DirectoryEntryKind::File => 0,
            DirectoryEntryKind::Directory => 1,
            DirectoryEntryKind::Symlink => 2,
            DirectoryEntryKind::Other => 3,
        }]);
        hash_identity(&mut hash, &entry.identity);
    }
    format!("{:x}", hash.finalize())
}

fn hash_identity(hash: &mut Sha256, id: &FileContentIdentity) {
    for value in [id.device, id.inode, id.size] {
        hash.update(value.to_le_bytes());
    }
    for value in [
        id.modified_seconds,
        id.modified_nanos,
        id.changed_seconds,
        id.changed_nanos,
    ] {
        hash.update(value.to_le_bytes());
    }
}

#[derive(Debug, Clone)]
pub struct DirectoryReadBudget {
    limits: DirectoryReadLimits,
    max_depth: usize,
    max_observations: usize,
    observations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PartialEq for DirectoryReadBudget {
    fn eq(&self, other: &Self) -> bool {
        use std::sync::atomic::Ordering;
        self.limits == other.limits
            && self.max_depth == other.max_depth
            && self.max_observations == other.max_observations
            && self.observations.load(Ordering::Relaxed)
                == other.observations.load(Ordering::Relaxed)
    }
}

impl Eq for DirectoryReadBudget {}

impl Default for DirectoryReadBudget {
    fn default() -> Self {
        Self::new(
            DirectoryReadLimits::default(),
            MAX_DIRECTORY_DEPTH,
            MAX_DIRECTORY_OBSERVATIONS,
        )
    }
}

impl DirectoryReadBudget {
    pub fn new(limits: DirectoryReadLimits, max_depth: usize, max_observations: usize) -> Self {
        Self {
            limits,
            max_depth,
            max_observations,
            observations: Default::default(),
        }
    }

    pub fn read(
        &mut self,
        view: &dyn crate::FilesystemView,
        path: &str,
        depth: usize,
    ) -> DirectoryRead {
        if !self.limits.is_valid()
            || self.max_depth > MAX_DIRECTORY_DEPTH
            || depth > self.max_depth
            || self.max_observations > MAX_DIRECTORY_OBSERVATIONS
        {
            return DirectoryRead::failed(
                view.source(),
                path,
                self.limits,
                DirectoryReadStatus::TooLarge,
                "directory observation budget exceeded",
            );
        }
        if !directory_path_is_resolved(path) {
            return DirectoryRead::failed(
                view.source(),
                path,
                self.limits,
                DirectoryReadStatus::InvalidPath,
                "expected a resolved absolute directory",
            );
        }
        use std::sync::atomic::Ordering;
        // Cloned request contexts consume the same capacity.
        if self
            .observations
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < self.max_observations).then(|| used + 1)
            })
            .is_err()
        {
            return DirectoryRead::failed(
                view.source(),
                path,
                self.limits,
                DirectoryReadStatus::TooLarge,
                "directory observation budget exceeded",
            );
        }
        let read = view.read_directory(path, self.limits);
        if read.observation.status == DirectoryReadStatus::Complete
            && (read.observation.source != view.source()
                || read.complete_entries(path, self.limits).is_none())
        {
            return DirectoryRead::failed(
                view.source(),
                path,
                self.limits,
                DirectoryReadStatus::Changed,
                "directory observation does not match its request",
            );
        }
        read
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FilesystemView, UnavailableFilesystem};
    use caushell_types::FilesystemEntry;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn identity(inode: u64) -> FileContentIdentity {
        FileContentIdentity {
            device: 1,
            inode,
            size: 0,
            modified_seconds: 1,
            modified_nanos: 0,
            changed_seconds: 1,
            changed_nanos: 0,
        }
    }

    fn entry(name: &str) -> DirectoryEntry {
        DirectoryEntry {
            name: name.into(),
            kind: DirectoryEntryKind::File,
            identity: identity(2),
        }
    }

    fn complete(names: &[&str]) -> DirectoryRead {
        DirectoryRead::complete(
            FilesystemObservationSource::SuppliedView,
            "/work",
            DirectoryReadLimits::default(),
            identity(1),
            names.iter().map(|n| entry(n)).collect(),
        )
    }

    #[test]
    fn empty_complete_set_is_distinct_from_every_failure() {
        let limits = DirectoryReadLimits::default();
        assert_eq!(
            complete(&[]).complete_entries("/work", limits),
            Some(&[][..])
        );
        for status in [
            DirectoryReadStatus::Missing,
            DirectoryReadStatus::InvalidPath,
            DirectoryReadStatus::NotDirectory,
            DirectoryReadStatus::Unreadable,
            DirectoryReadStatus::NonUtf8,
            DirectoryReadStatus::TooLarge,
            DirectoryReadStatus::Changed,
            DirectoryReadStatus::Unavailable,
        ] {
            let read = DirectoryRead::failed(
                FilesystemObservationSource::SuppliedView,
                "/work",
                limits,
                status,
                "not complete",
            );
            assert!(read.complete_entries("/work", limits).is_none());
        }
        assert!(
            UnavailableFilesystem
                .read_directory("/work", limits)
                .complete_entries("/work", limits)
                .is_none()
        );
    }

    #[test]
    fn names_are_preserved_and_canonical_set_hash_is_order_independent() {
        let a = complete(&["z\n/x", "a"]);
        assert_eq!(a.observation.status, DirectoryReadStatus::Changed);
        let a = complete(&["z\nname", "--flag='value'", "a"]);
        let b = complete(&["a", "z\nname", "--flag='value'"]);
        assert_eq!(a, b);
        assert_eq!(
            a.complete_entries("/work", DirectoryReadLimits::default())
                .unwrap()[2]
                .name,
            "z\nname"
        );
        assert_eq!(
            complete(&["same", "same"]).observation.status,
            DirectoryReadStatus::Changed
        );
        for name in ["", ".", "..", "a/b", "bad\0name"] {
            assert!(
                complete(&[name])
                    .complete_entries("/work", DirectoryReadLimits::default())
                    .is_none()
            );
        }
    }

    #[test]
    fn payload_is_bound_to_path_limits_source_identity_counts_and_digest() {
        let limits = DirectoryReadLimits::default();
        let read = complete(&["data"]);
        assert!(read.complete_entries("/other", limits).is_none());
        assert!(
            read.complete_entries(
                "/work",
                DirectoryReadLimits {
                    max_entries: 1,
                    ..limits
                }
            )
            .is_none()
        );
        for index in 0..7 {
            let mut bad = read.clone();
            match index {
                0 => bad.observation.sha256 = Some("bad".into()),
                1 => bad.observation.entries_observed += 1,
                2 => bad.observation.name_bytes_observed += 1,
                3 => bad.observation.source = FilesystemObservationSource::Unavailable,
                4 => bad.observation.identity = None,
                5 => bad.observation.identity.as_mut().unwrap().inode += 1,
                _ => bad.entries.as_mut().unwrap()[0].identity.inode += 1,
            }
            assert!(bad.complete_entries("/work", limits).is_none());
        }
    }

    #[test]
    fn zero_and_excessive_limits_are_not_unlimited() {
        for limits in [
            DirectoryReadLimits {
                max_entries: 0,
                max_name_bytes: 10,
            },
            DirectoryReadLimits {
                max_entries: 10,
                max_name_bytes: 0,
            },
            DirectoryReadLimits {
                max_entries: usize::MAX,
                max_name_bytes: 10,
            },
        ] {
            let read = DirectoryRead::complete(
                FilesystemObservationSource::SuppliedView,
                "/work",
                limits,
                identity(1),
                vec![],
            );
            assert_eq!(read.observation.status, DirectoryReadStatus::TooLarge);
        }
        let limits = DirectoryReadLimits {
            max_entries: 1,
            max_name_bytes: 1,
        };
        assert!(
            DirectoryRead::complete(
                FilesystemObservationSource::SuppliedView,
                "/work",
                limits,
                identity(1),
                vec![entry("x")]
            )
            .complete_entries("/work", limits)
            .is_some()
        );
        for entries in [vec![entry("xx")], vec![entry("x"), entry("y")]] {
            assert_eq!(
                DirectoryRead::complete(
                    FilesystemObservationSource::SuppliedView,
                    "/work",
                    limits,
                    identity(1),
                    entries
                )
                .observation
                .status,
                DirectoryReadStatus::TooLarge
            );
        }
    }

    #[derive(Default)]
    struct View {
        calls: AtomicUsize,
        wrong_path: bool,
    }
    impl FilesystemView for View {
        fn entry(&self, _: &str) -> FilesystemEntry {
            FilesystemEntry::Directory
        }
        fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
            self.calls.fetch_add(1, Ordering::SeqCst);
            DirectoryRead::complete(
                self.source(),
                if self.wrong_path { "/other" } else { path },
                limits,
                identity(1),
                vec![],
            )
        }
    }

    #[test]
    fn observation_and_depth_budgets_precede_provider_calls() {
        let view = View::default();
        let mut budget = DirectoryReadBudget::new(DirectoryReadLimits::default(), 1, 2);
        assert_eq!(
            budget.read(&view, "/work", 2).observation.status,
            DirectoryReadStatus::TooLarge
        );
        assert!(
            budget
                .read(&view, "/work", 0)
                .complete_entries("/work", DirectoryReadLimits::default())
                .is_some()
        );
        assert!(
            budget
                .read(&view, "/work", 1)
                .complete_entries("/work", DirectoryReadLimits::default())
                .is_some()
        );
        assert_eq!(
            budget.read(&view, "/work", 0).observation.status,
            DirectoryReadStatus::TooLarge
        );
        assert_eq!(view.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            DirectoryReadBudget::new(DirectoryReadLimits::default(), 1, 0)
                .read(&view, "/work", 0)
                .observation
                .status,
            DirectoryReadStatus::TooLarge
        );
    }

    #[test]
    fn wrong_provider_identity_and_unresolved_paths_are_not_complete() {
        let mut budget = DirectoryReadBudget::default();
        let view = View {
            wrong_path: true,
            ..View::default()
        };
        assert_eq!(
            budget.read(&view, "/work", 0).observation.status,
            DirectoryReadStatus::Changed
        );
        for path in [
            "relative",
            "/work/../other",
            "/work/./other",
            "/work//other",
            "/work/",
            "",
            "/bad\0path",
        ] {
            assert_eq!(
                budget.read(&view, path, 0).observation.status,
                DirectoryReadStatus::InvalidPath
            );
        }
        assert_eq!(view.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cloned_contexts_share_the_observation_capacity() {
        let view = View::default();
        let mut original = DirectoryReadBudget::new(DirectoryReadLimits::default(), 1, 1);
        let mut cloned = original.clone();
        assert_eq!(
            original.read(&view, "/work", 0).observation.status,
            DirectoryReadStatus::Complete
        );
        assert_eq!(
            cloned.read(&view, "/work", 0).observation.status,
            DirectoryReadStatus::TooLarge
        );
        assert_eq!(view.calls.load(Ordering::SeqCst), 1);
    }
}

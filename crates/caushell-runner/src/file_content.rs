use caushell_types::{
    FileContentIdentity, FileContentObservation, FileContentSource, FileContentStatus,
};
use sha2::{Digest, Sha256};

pub const MAX_FILE_CONTENT_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContentRead {
    pub observation: FileContentObservation,
    bytes: Option<Vec<u8>>,
}

impl FileContentRead {
    pub fn complete(
        source: FileContentSource,
        path: &str,
        limit: usize,
        identity: Option<FileContentIdentity>,
        bytes: Vec<u8>,
    ) -> Self {
        if limit > MAX_FILE_CONTENT_BYTES || bytes.len() > limit {
            return Self::failed(
                source,
                path,
                limit,
                FileContentStatus::TooLarge,
                "file exceeds the content observation budget",
            );
        }
        Self {
            observation: FileContentObservation {
                source,
                path: path.into(),
                status: FileContentStatus::Complete,
                byte_limit: limit,
                bytes_observed: bytes.len(),
                sha256: Some(content_sha256(&bytes)),
                identity,
                detail: None,
            },
            bytes: Some(bytes),
        }
    }

    pub fn failed(
        source: FileContentSource,
        path: &str,
        limit: usize,
        status: FileContentStatus,
        detail: impl Into<String>,
    ) -> Self {
        assert_ne!(status, FileContentStatus::Complete);
        Self {
            observation: FileContentObservation {
                source,
                path: path.into(),
                status,
                byte_limit: limit,
                bytes_observed: 0,
                sha256: None,
                identity: None,
                detail: Some(detail.into()),
            },
            bytes: None,
        }
    }

    pub fn complete_bytes(&self, path: &str, limit: usize) -> Option<&[u8]> {
        let bytes = self.bytes.as_deref()?;
        let observation = &self.observation;
        (observation.status == FileContentStatus::Complete
            && observation.source != FileContentSource::Unavailable
            && observation.path == path
            && observation.byte_limit == limit
            && limit <= MAX_FILE_CONTENT_BYTES
            && bytes.len() <= limit
            && observation.bytes_observed == bytes.len()
            && observation.sha256.as_deref() == Some(content_sha256(bytes).as_str()))
        .then_some(bytes)
    }
}

pub fn content_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_observations_bind_bytes_to_path_limit_and_digest() {
        let mut read = FileContentRead::complete(
            FileContentSource::SuppliedView,
            "/config",
            20,
            None,
            b"insecure\n".to_vec(),
        );
        assert_eq!(read.complete_bytes("/config", 20), Some(&b"insecure\n"[..]));
        assert!(read.complete_bytes("/other", 20).is_none());
        assert!(read.complete_bytes("/config", 19).is_none());
        read.observation.sha256 = Some("invalid".into());
        assert!(read.complete_bytes("/config", 20).is_none());
    }

    #[test]
    fn failures_and_budget_exhaustion_cannot_supply_complete_bytes() {
        for status in [
            FileContentStatus::Missing,
            FileContentStatus::Unreadable,
            FileContentStatus::NonRegular,
            FileContentStatus::Changed,
            FileContentStatus::Unavailable,
        ] {
            assert!(
                FileContentRead::failed(
                    FileContentSource::SuppliedView,
                    "/config",
                    20,
                    status,
                    "not complete"
                )
                .complete_bytes("/config", 20)
                .is_none()
            );
        }
        let read = FileContentRead::complete(
            FileContentSource::SuppliedView,
            "/config",
            2,
            None,
            b"insecure\n".to_vec(),
        );
        assert_eq!(read.observation.status, FileContentStatus::TooLarge);
        assert!(read.complete_bytes("/config", 2).is_none());
        assert_eq!(
            content_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

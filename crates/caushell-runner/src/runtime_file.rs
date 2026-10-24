use caushell_types::{FileContentSource, FileContentStatus, RuntimeFileObservation};

pub const MAX_RUNTIME_FILE_BYTES: usize = 33_554_432;

pub fn runtime_file_matches(
    observation: &RuntimeFileObservation,
    path: &str,
    expected: &caushell_types::RuntimeFile,
) -> bool {
    let o = &observation.content;
    matches!(
        o.source,
        FileContentSource::CurrentProcess | FileContentSource::SuppliedView
    ) && o.status == FileContentStatus::Complete
        && o.path == path
        && o.byte_limit == MAX_RUNTIME_FILE_BYTES
        && o.identity
            .as_ref()
            .is_some_and(|id| id.size == expected.size)
        && o.bytes_observed as u64 == expected.size
        && o.bytes_observed <= MAX_RUNTIME_FILE_BYTES
        && o.sha256.as_deref() == Some(expected.sha256.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use caushell_types::*;

    #[test]
    fn runtime_digests_require_fresh_complete_path_identity_and_budget() {
        let expected = RuntimeFile {
            sha256: crate::content_sha256(b"abc"),
            size: 3,
        };
        let valid = RuntimeFileObservation {
            content: FileContentObservation {
                source: FileContentSource::SuppliedView,
                path: "/runtime/python".into(),
                status: FileContentStatus::Complete,
                byte_limit: MAX_RUNTIME_FILE_BYTES,
                bytes_observed: 3,
                sha256: Some(expected.sha256.clone()),
                identity: Some(FileContentIdentity {
                    device: 1,
                    inode: 2,
                    size: 3,
                    modified_seconds: 1,
                    modified_nanos: 0,
                    changed_seconds: 1,
                    changed_nanos: 0,
                }),
                detail: None,
            },
            executable: Some(true),
        };
        assert!(runtime_file_matches(&valid, "/runtime/python", &expected));
        for change in 0..8 {
            let mut invalid = valid.clone();
            match change {
                0 => invalid.content.source = FileContentSource::Graph,
                1 => invalid.content.status = FileContentStatus::Changed,
                2 => invalid.content.path = "/another".into(),
                3 => invalid.content.byte_limit -= 1,
                4 => invalid.content.bytes_observed -= 1,
                5 => invalid.content.identity = None,
                6 => invalid.content.identity.as_mut().unwrap().size = 4,
                7 => invalid.content.sha256 = Some("wrong".into()),
                _ => unreachable!(),
            }
            assert!(
                !runtime_file_matches(&invalid, "/runtime/python", &expected),
                "{change}"
            );
        }
    }
}

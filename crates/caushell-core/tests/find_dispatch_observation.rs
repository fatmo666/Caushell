//! Exercise dispatch reasoning with a synthetic filesystem; no shell is run.
use caushell_core::ShellQueryCore;
use caushell_runner::{DirectoryRead, FilesystemView};
use caushell_types::*;
use std::sync::Arc;

struct DirectoryFixture {
    with_file: bool,
}

impl FilesystemView for DirectoryFixture {
    fn entry(&self, path: &str) -> FilesystemEntry {
        match path {
            "/" | "/fixture" => FilesystemEntry::Directory,
            "/fixture/ordinary.txt" if self.with_file => FilesystemEntry::File,
            _ => FilesystemEntry::Missing,
        }
    }

    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        assert_eq!(path, "/fixture");
        DirectoryRead::complete(
            self.source(),
            path,
            limits,
            FileContentIdentity {
                device: 1,
                inode: 1,
                size: 0,
                modified_seconds: 0,
                modified_nanos: 0,
                changed_seconds: 0,
                changed_nanos: 0,
            },
            if self.with_file {
                vec![DirectoryEntry {
                    name: "ordinary.txt".into(),
                    kind: DirectoryEntryKind::File,
                    identity: FileContentIdentity {
                        device: 1,
                        inode: 2,
                        size: 0,
                        modified_seconds: 0,
                        modified_nanos: 0,
                        changed_seconds: 0,
                        changed_nanos: 0,
                    },
                }]
            } else {
                Vec::new()
            },
        )
    }
}

fn check(command: &str) -> CheckResponse {
    check_with_directory(command, false)
}

fn check_with_directory(command: &str, with_file: bool) -> CheckResponse {
    check_with_view(command, Arc::new(DirectoryFixture { with_file }))
}

fn check_with_view(command: &str, view: Arc<dyn FilesystemView>) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(view)
        .check(dispatch_request(command))
}

fn dispatch_request(command: &str) -> CheckRequest {
    CheckRequest {
        session_id: SessionId::new("empty-observation"),
        sequence_no: CommandSequenceNo(1),
        command: command.to_owned(),
        shell_state_before: ShellStateSnapshot::new("/fixture"),
        shell_kind: ShellKind::Bash,
        home: None,
        workspace_root: Some("/fixture".into()),
        runtime: RuntimeMetadata {
            runtime_name: "static-test".into(),
            tool_name: Some("Bash".into()),
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    }
}

#[test]
fn empty_directory_keeps_possible_native_dispatches() {
    for command in [
        "find . -type f -print0 | xargs -0 -I{} rm -v {}",
        "find . -type f -print0 | xargs -0 -r cp -t /outside",
        "find . -type f -print0 | xargs -0 cp -t /outside",
        "find . -type f -print0 | tee | xargs -0 -I{} rm -v {}",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::NeedApproval, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.derived_invocations.iter()
            .any(|child| matches!(child.command_name.as_deref(), Some("rm" | "cp"))),
            "{command}: possible child disappeared");
    }
}

#[test]
fn empty_observation_keeps_readers_and_proved_unreachable_dispatches() {
    for command in [
        "find . -type f -print0 | xargs -0 cat --",
        "find . -false -print0 | xargs -0 -r chmod 600",
        "find . -false -print0 | tee | xargs -0 -r chmod 600",
    ] {
        let result = check(command);
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.evidence.iter().any(|e|
            matches!(&e.kind, EvidenceKind::StdoutRecords(r) if r.complete && r.records.is_empty())
        ), "{command}: complete empty output was lost");
    }
}


#[test]
fn current_text_records_do_not_authorize_metadata_dispatch() {
    for command in [
        "find . -type f | xargs chmod 644",
        "find . -type f | tee | xargs -I{} chmod -v 644 {}",
    ] {
        let result = check_with_directory(command, true);
        assert_eq!(
            result.decision,
            Decision::NeedApproval,
            "{command}: {:?}", result.reasons
        );
        assert!(result.decision_trace.evidence.iter().any(|e|
            matches!(&e.kind, EvidenceKind::NativeInputDecode(d) if !d.complete)
        ));
    }
}

#[test]
fn native_nul_records_and_independently_proved_readers_keep_their_effects() {
    for command in [
        "find . -type f -print0 | xargs -0 chmod 644",
        "find . -type f | xargs cat --",
    ] {
        let result = check_with_directory(command, true);
        assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
        assert!(result.decision_trace.evidence.iter().any(|e|
            matches!(&e.kind, EvidenceKind::NativeInputDecode(d) if d.complete)
        ), "{command}: complete input proof was lost");
    }
}

#[test]
fn external_printf_reader_does_not_inherit_shell_variable_writes() {
    use caushell_profile::{
        CommandLookupDomain, ProfileRegistry, native_effect_contract_is_closed_in_domain,
    };
    let registry = ProfileRegistry::built_in().unwrap();
    let profile = registry.lookup("printf").profile.unwrap();
    for domain in [CommandLookupDomain::Shell, CommandLookupDomain::Builtin, CommandLookupDomain::Unknown] {
        assert!(!native_effect_contract_is_closed_in_domain(
            profile, NativeArgvEffectEnvelope::ContentRead, &domain,
        ));
    }

    let command = r#"find . | xargs -I{} printf "%s%s\n" {} {}"#;
    let result = check_with_directory(command, true);
    assert_eq!(result.decision, Decision::Allow, "{command}: {:?}", result.reasons);
    assert!(result.decision_trace.evidence.iter().any(|e|
        matches!(&e.kind, EvidenceKind::NativeInputDecode(d) if d.complete)
    ), "{command}: external data-only dispatch lost its input proof");
}

struct MountFixture;

impl FilesystemView for MountFixture {
    fn entry(&self, path: &str) -> FilesystemEntry {
        match path {
            "/" | "/fixture" | "/fixture/cross" => FilesystemEntry::Directory,
            "/fixture/same" | "/fixture/cross/other" => FilesystemEntry::File,
            _ => FilesystemEntry::Missing,
        }
    }

    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        let identity = |device, inode| FileContentIdentity {
            device,
            inode,
            size: 0,
            modified_seconds: 0,
            modified_nanos: 0,
            changed_seconds: 0,
            changed_nanos: 0,
        };
        let (directory, entries) = match path {
            "/fixture" => (
                identity(1, 1),
                vec![
                    DirectoryEntry {
                        name: "same".into(),
                        kind: DirectoryEntryKind::File,
                        identity: identity(1, 2),
                    },
                    DirectoryEntry {
                        name: "cross".into(),
                        kind: DirectoryEntryKind::Directory,
                        identity: identity(2, 1),
                    },
                ],
            ),
            "/fixture/cross" => (
                identity(2, 1),
                vec![DirectoryEntry {
                    name: "other".into(),
                    kind: DirectoryEntryKind::File,
                    identity: identity(2, 2),
                }],
            ),
            _ => panic!("unexpected directory {path}"),
        };
        DirectoryRead::complete(self.source(), path, limits, directory, entries)
    }
}

#[test]
fn device_constraint_emits_the_boundary_and_uses_each_starting_point() {
    for (expression, expected, reads_cross_device) in [
        (". -print0", vec![".", "./cross", "./cross/other", "./same"], true),
        (". -xdev -print0", vec![".", "./cross", "./same"], false),
        (". -mount -print0", vec![".", "./cross", "./same"], false),
        (r". \( -name unmatched -a -xdev \) -o -print0", vec![".", "./cross", "./same"], false),
        (
            ". ./cross -xdev -print0",
            vec![".", "./cross", "./cross", "./cross/other", "./same"],
            true,
        ),
    ] {
        let command = format!("find {expression} | wc -c");
        let response = check_with_view(&command, Arc::new(MountFixture));
        let records = response.decision_trace.evidence.iter().find_map(|e| match &e.kind {
            EvidenceKind::StdoutRecords(records) => Some(records),
            _ => None,
        }).expect("find producer evidence");
        assert!(records.complete, "{command}: {:?}", records.gap);
        assert_eq!(records.order, StreamRecordOrder::Unspecified, "{command}");
        let mut names = records.records.iter().map(|entry| entry.path_spelling.as_str()).collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, expected, "{command}");
        assert_eq!(
            records.directory_observations.iter().any(|directory| directory.path == "/fixture/cross"),
            reads_cross_device,
            "{command}"
        );
    }
}

#[test]
fn leading_x_requires_a_current_apple_find_variant() {
    let forms = [
        (
            "find -x . -print0 | wc -c",
            Some("apple_find"),
            Some(vec![".", "./cross", "./same"]),
        ),
        (
            "find -P -x . ./cross -print0 | wc -c",
            Some("apple_find"),
            Some(vec![".", "./cross", "./cross", "./cross/other", "./same"]),
        ),
        ("find -x . -print0 | wc -c", None, None),
        ("find -x . -print0 | wc -c", Some("gnu_findutils"), None),
        (
            "PATH=/elsewhere find -x . -print0 | wc -c",
            Some("apple_find"),
            None,
        ),
        ("find . -x -print0 | wc -c", Some("apple_find"), None),
        ("find -x -print0 | wc -c", Some("apple_find"), None),
        (
            r#"find -x . -printf '%p\0' | wc -c"#,
            Some("apple_find"),
            None,
        ),
        ("find . -name -x -print0 | wc -c", None, Some(Vec::new())),
    ];
    for (command, variant, expected) in forms {
        let mut request = dispatch_request(command);
        if let Some(variant) = variant {
            request.shell_state_before.execution_frame = Some(ExecutionFrameObservation {
                binding: ExecutionFrameBinding::for_request(&request, "owner"),
                environment: Vec::new(),
                pathname: None,
                variables: Vec::new(),
                variable_values: Vec::new(),
                integer_variables: Default::default(),
                native_variants: [("find".into(), variant.into())].into(),
            });
        }
        let result = ShellQueryCore::new()
            .with_filesystem_view(Arc::new(MountFixture))
            .check(request);
        let evidence = result
            .decision_trace
            .evidence
            .iter()
            .find_map(|entry| {
                if let EvidenceKind::StdoutRecords(records) = &entry.kind {
                    Some(records)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("{command}: no find producer evidence"));
        if let Some(expected) = expected {
            assert!(evidence.complete, "{command}: {:?}", evidence.gap);
            let mut names = evidence
                .records
                .iter()
                .map(|entry| entry.path_spelling.as_str())
                .collect::<Vec<_>>();
            names.sort_unstable();
            assert_eq!(names, expected, "{command}");
        } else {
            assert!(
                !evidence.complete && evidence.records.is_empty(),
                "{command}"
            );
        }
    }
}

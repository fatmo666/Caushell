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
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(DirectoryFixture { with_file }))
        .check(CheckRequest {
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
        })
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

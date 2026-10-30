//! Abstract file-kind/path invariants; no sed, scripts or submitted commands run.
use caushell_core::ShellQueryCore;
use caushell_runner::FilesystemView;
use caushell_types::*;
use std::{collections::BTreeMap, sync::Arc};
struct Namespace(BTreeMap<String, FilesystemEntry>);
impl FilesystemView for Namespace {
    fn entry(&self, p: &str) -> FilesystemEntry {
        self.0.get(p).cloned().unwrap_or(FilesystemEntry::Missing)
    }
}
fn namespace() -> BTreeMap<String, FilesystemEntry> {
    let mut m = BTreeMap::new();
    for p in [
        "/",
        "/workspace",
        "/workspace/src",
        "/tmp",
        "/outside",
        "/private",
        "/private/tmp",
    ] {
        m.insert(p.into(), FilesystemEntry::Directory);
    }
    for p in ["/workspace/src/a.c", "/workspace/src/b.c"] {
        m.insert(p.into(), FilesystemEntry::File);
    }
    m
}
fn check(cmd: &str, fs: BTreeMap<String, FilesystemEntry>) -> CheckResponse {
    let shell = ShellStateSnapshot::new("/workspace");
    let req = CheckRequest {
        session_id: SessionId::new("atomic-file-scope"),
        sequence_no: CommandSequenceNo(1),
        command: cmd.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: shell,
        home: Some("/home/user".into()),
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "offline-test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
        },
    };
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(Namespace(fs)))
        .check(req)
}
#[test]
fn atomic_replacements_preserve_scope_without_inventing_result_contents() {
    for cmd in [
        "sed -i 's/first/second/' src/a.c && sed -i 's/third/fourth/' src/a.c",
        "sed -i -e 's/old/new/' src/a.c src/b.c; sed -i 's/x/y/' src/a.c",
    ] {
        let r = check(cmd, namespace());
        assert_eq!(r.decision, Decision::Allow, "{cmd}: {:?}", r.reasons);
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .any(|p| !p.namespace_proofs.is_empty())
        );
    }
}
#[test]
fn links_outside_targets_and_unknown_siblings_never_gain_authority() {
    for cmd in [
        "sed -i 's/a/b/' /outside/data",
        "sed -i 's/a/b/' src/link.c; sed -i 's/x/y/' src/link.c",
        "sed --unknown 's/x/y/' src/a.c; sed -i 's/a/b/' src/a.c",
        "sed -i 's/a/b/' $(grep -rl old src)",
        "git clone --depth 2 --branch dev https://example.org/repo.git /workspace/repo; python3 /workspace/repo/setup.py",
    ] {
        let mut m = namespace();
        m.insert(
            "/workspace/src/link.c".into(),
            FilesystemEntry::Symlink {
                target: "/outside/data".into(),
            },
        );
        let r = check(cmd, m);
        assert_eq!(r.decision, Decision::NeedApproval, "{cmd}: {:?}", r.reasons);
    }
}
#[test]
fn deletion_and_independent_deny_remain_effective() {
    assert_eq!(
        check("sed -i 's/a/b/' src/a.c; rm src/b.c", namespace()).decision,
        Decision::NeedApproval
    );
    assert_eq!(
        check("sed -i 's/a/b/' src/a.c; rm -rf /", namespace()).decision,
        Decision::Deny
    );
    assert_eq!(
        check("sed -i 's/a/b/' src/a.c; python3 -c pass", namespace()).decision,
        Decision::NeedApproval
    );
}

#[test]
fn native_configuration_uncertainty_is_not_removed_by_cli_option_coverage() {
    for command in [
        "R CMD config BLAS_LIBS",
        "git clone --depth 2 --branch dev https://example.org/repo.git /workspace/repo",
    ] {
        assert_eq!(
            check(command, namespace()).decision,
            Decision::NeedApproval,
            "{command}"
        );
    }
}

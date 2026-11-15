//! Judge-only checks. Configuration bytes and monitored programs never execute.
use caushell_core::ShellQueryCore;
use caushell_types::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const TOOLS: [&str; 3] = ["check_cups", "check_memory", "check_raid"];

struct Fixture {
    root: PathBuf,
    work: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "caushell-extra-opts-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let work = root.join("workspace");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir(root.join("external")).unwrap();
        fs::write(work.join("options.ini"), "[check_raid]\nsudoers=\n").unwrap();
        fs::write(
            root.join("external/options.ini"),
            "[custom]\nplugin=unknown\n",
        )
        .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("external/options.ini"), work.join("link.ini"))
            .unwrap();
        Self { root, work }
    }
    fn request(&self, command: String) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new(format!(
                "extra-opts-{}",
                NEXT.fetch_add(1, Ordering::Relaxed)
            )),
            sequence_no: CommandSequenceNo::new(1),
            command,
            shell_state_before: ShellStateSnapshot::new(self.work.to_string_lossy().as_ref()),
            shell_kind: ShellKind::Bash,
            home: Some("/home/auditor".into()),
            workspace_root: Some(self.work.to_string_lossy().into_owned()),
            runtime: RuntimeMetadata {
                runtime_name: "extra-opts-local-test".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn unexpanded_config_options_require_approval_inside_outside_or_through_links() {
    let f = Fixture::new();
    let mut core = ShellQueryCore::new();
    for tool in TOOLS {
        for value in [
            "@options.ini".to_string(),
            "custom@options.ini".into(),
            format!("@{}", f.root.join("external/options.ini").display()),
            "@link.ini".into(),
        ] {
            let response = core.check(f.request(format!("{tool} --extra-opts='{value}'")));
            assert_eq!(
                response.decision,
                Decision::NeedApproval,
                "{tool} {value}: {response:#?}"
            );
            assert!(
                response
                    .decision_trace
                    .execution_semantics
                    .iter()
                    .any(|s| s.normalized_command_name == tool && s.loads_tool_config),
                "{response:#?}"
            );
            // path_targets is a mutation-target trace, not a read-input list.
            // Exact file dependencies are checked by the profile-layer tests.
            assert!(response.decision_trace.execution_semantics.iter().any(|s| {
                s.normalized_command_name == tool && s.operation_semantics_unresolved
            }));
            assert!(
                response
                    .decision_trace
                    .execution_semantics
                    .iter()
                    .all(|s| s.normalized_command_name == tool)
            );
        }
    }
}

#[test]
fn configuration_read_precedes_help_and_default_or_dynamic_inputs_stay_conservative() {
    let f = Fixture::new();
    let mut core = ShellQueryCore::new();
    for tool in TOOLS {
        for tail in [
            "--help --extra-opts=@options.ini",
            "--extra-opts=@options.ini --version",
            "--extra-opts",
            "--extra-opts=custom",
            "--extra-opts=@",
            "--extra-opts=\"$UNKNOWN\"",
            "--extra-opts=@options.ini --extra-opts=default_section",
        ] {
            let response = core.check(f.request(format!("{tool} {tail}")));
            assert_eq!(
                response.decision,
                Decision::NeedApproval,
                "{tool} {tail}: {response:#?}"
            );
        }
    }
}

#[test]
fn config_filenames_are_data_and_independent_deny_is_retained() {
    let f = Fixture::new();
    let mut core = ShellQueryCore::new();
    for tool in TOOLS {
        let response = core.check(f.request(format!(
            "{tool} --extra-opts='@literal$(printf marker).ini'"
        )));
        assert_eq!(response.decision, Decision::NeedApproval);
        assert!(
            response
                .decision_trace
                .execution_semantics
                .iter()
                .all(|s| s.normalized_command_name == tool)
        );
        let denied = core.check(f.request(format!("{tool} --extra-opts=@options.ini; rm -rf /")));
        assert_eq!(denied.decision, Decision::Deny, "{denied:#?}");
    }
}

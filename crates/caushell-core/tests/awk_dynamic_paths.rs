use caushell_core::ShellQueryCore;
use caushell_types::*;
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "caushell-awk-bounds-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::create_dir(p.join("out")).unwrap();
        fs::write(p.join("input"), "marker\ndata\n").unwrap();
        Self(p)
    }
    fn request(&self, command: &str) -> CheckRequest {
        CheckRequest {
            session_id: SessionId::new("awk-components"),
            sequence_no: CommandSequenceNo(1),
            command: command.into(),
            shell_kind: ShellKind::Bash,
            shell_state_before: ShellStateSnapshot::new(self.0.to_str().unwrap()),
            home: None,
            workspace_root: Some(self.0.to_str().unwrap().into()),
            runtime: RuntimeMetadata {
                runtime_name: "awk-test".into(),
                tool_name: Some("Bash".into()),
                shell_runtime_capabilities: ShellRuntimeCapabilities::request_only(),
            },
        }
    }
    fn check(&self, command: &str) -> CheckResponse {
        ShellQueryCore::new().check(self.request(command))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn complete_numeric_state_has_a_path_family_not_an_invented_filename() {
    let f = Fixture::new();
    for program in [
        r#"/marker/{counter++;next}{print > "out/item_" counter ".dat"}"#,
        r#"{counter+=2; print > ("out/part_" counter ".txt")}"#,
        r#"BEGIN{counter=3}{print > "out/row_" (counter+7) ".txt"}"#,
    ] {
        let r = f.check(&format!("awk '{program}' input"));
        assert_eq!(r.decision, Decision::Allow, "{program}: {:?}", r.reasons);
        assert!(
            r.decision_trace
                .path_targets
                .iter()
                .any(|t| t.slot_name == "program_writes"
                    && matches!(
                        &t.lexical,
                        PathResolution::BoundedPathSet {
                            may_escape: false,
                            ..
                        }
                    )),
            "{r:#?}"
        );
    }
    assert!(fs::read_dir(f.0.join("out")).unwrap().next().is_none());
}
#[test]
fn fields_reassignments_external_variables_and_number_formats_remain_unknown() {
    let f = Fixture::new();
    for command in [
        r#"awk '{n++;n=$1;print > "out/item_" n ".txt"}' input"#,
        r#"awk '{n=$1;print > "out/item_" n++ ".txt"}' input"#,
        r#"awk '{n++;if(NR>2)n=$1;print > "out/item_" n ".txt"}' input"#,
        r#"awk '{n++;print > "out/item_" n ".txt"} END{getline n < "input"}' input"#,
        r#"awk '{n++;gsub(/x/,"../",n);print > "out/item_" n ".txt"}' input"#,
        r#"awk 'function change(){n=$0} {n++;change();print > "out/item_" n ".txt"}' input"#,
        r#"awk -v n=../outside '{n++;print > "out/item_" n ".txt"}' input"#,
        r#"awk '{n++;print > "out/item_" n ".txt"}' n=../outside input"#,
        r#"awk 'BEGIN{CONVFMT="../../%g"}{n++;print > "out/item_" n ".txt"}' input"#,
        r#"awk '{n++;SYMTAB["n"]=$1;print > "out/item_" n ".txt"}' input"#,
        r#"awk 'BEGIN{ARGV[2]="n=../escape"}/marker/{n++;next}{print > "out/item_" n ".txt"}' input input"#,
        r#"awk '{print > "out/" $1 ".txt"}' input"#,
        r#"awk '{n++;print > "out/" n "/../other"}' input"#,
    ] {
        let r = f.check(command);
        assert_eq!(
            r.decision,
            Decision::NeedApproval,
            "{command}: {:?}",
            r.reasons
        );
    }
}
#[test]
fn numeric_path_facts_do_not_authorize_symlink_escape_or_other_effects() {
    let f = Fixture::new();
    std::os::unix::fs::symlink("/opt", f.0.join("out/item_1.txt")).unwrap();
    let r = f.check(r#"awk '{n++;print > "out/item_" n ".txt"}' input"#);
    assert_eq!(r.decision, Decision::NeedApproval, "{:?}", r.reasons);
    for (command, expected) in [
        (
            r#"awk '{n++;print > "/opt/item_" n ".txt"}' input"#,
            Decision::NeedApproval,
        ),
        (
            r#"awk '{n++;print > "out/item_" n ".txt"}' input; rm input"#,
            Decision::NeedApproval,
        ),
        (
            r#"awk '{n++;print > "out/item_" n ".txt"}' input; rm -rf /"#,
            Decision::Deny,
        ),
        (r#"awk '{broken' input; rm -rf /"#, Decision::Deny),
        (
            r#"awk '{n++;print > "out/item_" n ".txt";system($0)}' input"#,
            Decision::NeedApproval,
        ),
    ] {
        let r = f.check(command);
        assert_eq!(r.decision, expected, "{command}: {:?}", r.reasons);
    }
}

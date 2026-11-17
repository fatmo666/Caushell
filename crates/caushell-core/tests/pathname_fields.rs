use caushell_core::ShellQueryCore;
use caushell_runner::{DirectoryRead, FilesystemView};
use caushell_types::*;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn identity(inode: u64) -> FileContentIdentity {
    FileContentIdentity {
        device: 1,
        inode,
        size: 0,
        modified_seconds: 0,
        modified_nanos: 0,
        changed_seconds: 0,
        changed_nanos: 0,
    }
}

struct Files {
    dirs: BTreeMap<String, Vec<DirectoryEntry>>,
    failure: Option<DirectoryReadStatus>,
    changed: bool,
    calls: AtomicUsize,
}
impl Files {
    fn new(names: &[&str]) -> Self {
        let entries = |names: &[&str]| {
            names
                .iter()
                .enumerate()
                .map(|(i, n)| DirectoryEntry {
                    name: (*n).into(),
                    kind: if *n == "sub" {
                        DirectoryEntryKind::Directory
                    } else {
                        DirectoryEntryKind::File
                    },
                    identity: identity(i as u64 + 10),
                })
                .collect()
        };
        Self {
            dirs: BTreeMap::from([
                ("/workspace".into(), entries(names)),
                ("/workspace/sub".into(), entries(&["inner"])),
            ]),
            failure: None,
            changed: false,
            calls: AtomicUsize::new(0),
        }
    }
}
impl FilesystemView for Files {
    fn entry(&self, path: &str) -> FilesystemEntry {
        if path == "/" || self.dirs.contains_key(path) {
            return FilesystemEntry::Directory;
        }
        for (parent, names) in &self.dirs {
            if let Some(entry) = names
                .iter()
                .find(|e| format!("{parent}/{}", e.name) == path)
            {
                return match entry.kind {
                    DirectoryEntryKind::Directory => FilesystemEntry::Directory,
                    _ => FilesystemEntry::File,
                };
            }
        }
        FilesystemEntry::Missing
    }
    fn read_directory(&self, path: &str, limits: DirectoryReadLimits) -> DirectoryRead {
        if let Some(status) = self.failure {
            return DirectoryRead::failed(self.source(), path, limits, status, "fixture failure");
        }
        let Some(entries) = self.dirs.get(path) else {
            return DirectoryRead::failed(
                self.source(),
                path,
                limits,
                DirectoryReadStatus::Missing,
                "absent",
            );
        };
        let changed = self.changed && self.calls.fetch_add(1, Ordering::Relaxed) > 0;
        DirectoryRead::complete(
            self.source(),
            path,
            limits,
            identity(if changed { 2 } else { 1 }),
            entries.clone(),
        )
    }
}

fn options() -> ShellPathnameSnapshot {
    ShellPathnameSnapshot {
        noglob: false,
        nullglob: false,
        failglob: false,
        dotglob: false,
        nocaseglob: false,
        globstar: false,
        extglob: false,
        globskipdots: true,
        globignore: ShellEnvironmentValue::Absent,
        lc_all: ShellEnvironmentValue::Present { value: "C".into() },
        lc_collate: ShellEnvironmentValue::Absent,
        lc_ctype: ShellEnvironmentValue::Absent,
        lang: ShellEnvironmentValue::Absent,
    }
}
fn request(command: &str) -> CheckRequest {
    let mut state = ShellStateSnapshot::new("/workspace")
        .with_environment_observation("TAR_OPTIONS", ShellEnvironmentValue::Absent);
    state.pathname = Some(options());
    CheckRequest {
        session_id: SessionId::new("pathname"),
        sequence_no: CommandSequenceNo(1),
        command: command.into(),
        shell_kind: ShellKind::Bash,
        shell_state_before: state,
        home: None,
        workspace_root: Some("/workspace".into()),
        runtime: RuntimeMetadata {
            runtime_name: "test".into(),
            tool_name: None,
            shell_runtime_capabilities: ShellRuntimeCapabilities::persistent_shell(),
        },
    }
}
fn check(r: CheckRequest, files: Files) -> CheckResponse {
    ShellQueryCore::new()
        .with_filesystem_view(Arc::new(files))
        .check(r)
}
fn proofs(r: &CheckResponse) -> Vec<&PathnameFieldsEvidence> {
    r.decision_trace
        .evidence
        .iter()
        .filter_map(|e| match &e.kind {
            EvidenceKind::PathnameFields(p) => Some(p),
            _ => None,
        })
        .collect()
}
fn has_command(r: &CheckResponse, name: &str) -> bool {
    r.decision_trace
        .execution_semantics
        .iter()
        .any(|s| s.normalized_command_name == name)
}

#[test]
fn native_fields_keep_byte_order_and_do_not_reparse_shell_text() {
    let names = [
        "z",
        "two words",
        "line\nbreak",
        ".hidden",
        "$(touch injected)",
        "a*?",
    ];
    let r = check(request("tar -cf output.tar -- *"), Files::new(&names));
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
    let p = proofs(&r)[0];
    assert!(p.complete, "{p:#?}");
    assert_eq!(
        p.fields,
        ["$(touch injected)", "a*?", "line\nbreak", "two words", "z"]
    );
    assert!(!has_command(&r, "touch"));
}

#[test]
fn generated_control_options_enter_the_existing_callback_dispatch() {
    let filename = "--checkpoint-action=exec=python3 .post.py";
    let r = check(
        request("tar -cf output.tar --checkpoint=1 *"),
        Files::new(&[filename, "input", ".post.py"]),
    );
    assert!(proofs(&r)[0].complete, "{r:#?}");
    assert!(has_command(&r, "python3"), "{r:#?}");
    assert_eq!(r.decision, Decision::NeedApproval, "{r:#?}");
    assert!(
        !r.decision_trace
            .decision_proposals
            .iter()
            .any(|p| p.reason.contains("argument region ownership is unresolved")),
        "{r:#?}"
    );
    let r = check(
        request("tar -cf output.tar --checkpoint=1 -- *"),
        Files::new(&[filename, "input"]),
    );
    assert!(proofs(&r)[0].complete);
    assert!(!has_command(&r, "python3"), "{r:#?}");
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
}

#[test]
fn quoted_and_native_literal_stars_do_not_request_directory_expansion() {
    for word in ["'*'", "\"*\"", "\\*"] {
        let r = check(
            request(&format!("tar -cf output.tar -- {word}")),
            Files::new(&["input"]),
        );
        assert!(proofs(&r).is_empty(), "{r:#?}");
        assert_eq!(r.decision, Decision::Allow, "{r:#?}");
    }
    let mut r = request("tar -cf output.tar *");
    r.shell_state_before.pathname.as_mut().unwrap().noglob = true;
    let r = check(
        r,
        Files::new(&["--checkpoint-action=exec=python3 .post.py"]),
    );
    assert_eq!(proofs(&r)[0].fields, ["*"]);
    assert!(!has_command(&r, "python3"));
}

#[test]
fn unmatched_fields_obey_nullglob_and_failglob() {
    for (nullglob, failglob, fields, complete) in [
        (false, false, vec!["missing*"], true),
        (true, false, vec![], true),
        (false, true, vec![], false),
        (true, true, vec![], false),
    ] {
        let mut r = request("tar -cf output.tar -- missing*");
        let o = r.shell_state_before.pathname.as_mut().unwrap();
        o.nullglob = nullglob;
        o.failglob = failglob;
        let r = check(r, Files::new(&["input"]));
        let p = proofs(&r)[0];
        assert_eq!(p.complete, complete, "{p:#?}");
        assert_eq!(p.fields, fields);
        if failglob {
            assert_eq!(r.decision, Decision::NeedApproval);
        }
    }
}

#[test]
fn dotfiles_case_and_character_width_follow_observed_shell_state() {
    let mut r = request("tar -cf output.tar -- *.txt");
    r.shell_state_before.pathname.as_mut().unwrap().nocaseglob = true;
    r.shell_state_before.pathname.as_mut().unwrap().dotglob = true;
    let r = check(r, Files::new(&["A.TXT", ".x.txt", "other"]));
    assert_eq!(proofs(&r)[0].fields, [".x.txt", "A.TXT"]);
    for (locale, expected) in [("C", Vec::<&str>::new()), ("C.UTF-8", vec!["é"])] {
        let mut r = request("tar -cf output.tar -- ?");
        r.shell_state_before.pathname.as_mut().unwrap().lc_all = ShellEnvironmentValue::Present {
            value: locale.into(),
        };
        r.shell_state_before.pathname.as_mut().unwrap().nullglob = true;
        let r = check(r, Files::new(&["é"]));
        assert_eq!(proofs(&r)[0].fields, expected);
    }
}

#[test]
fn tool_chdir_does_not_replace_the_shell_expansion_directory() {
    for command in [
        "tar -C sub -cf output.tar -- *",
        "env -C sub tar -cf output.tar -- *",
    ] {
        let r = check(request(command), Files::new(&["outer", "sub"]));
        let p = proofs(&r);
        assert_eq!(p.len(), 1, "{r:#?}");
        assert!(p[0].complete, "{p:#?}");
        assert_eq!(p[0].cwd.as_deref(), Some("/workspace"));
        assert_eq!(p[0].fields, ["outer", "sub"]);
    }
    let r = check(
        request("cd /workspace/sub && tar -cf output.tar -- *"),
        Files::new(&["outer", "sub"]),
    );
    let p = proofs(&r)[0];
    assert!(p.complete, "{r:#?}");
    assert_eq!(p.cwd.as_deref(), Some("/workspace/sub"));
    assert_eq!(p.fields, ["inner"]);
}

#[test]
fn missing_shell_and_environment_inputs_are_separate_gaps() {
    for (pathname, environment) in [(true, true), (true, false), (false, true), (false, false)] {
        let mut r = request("tar -cf output.tar *");
        if !pathname {
            r.shell_state_before.pathname = None;
        }
        if !environment {
            r.shell_state_before.environment.clear();
        }
        let r = check(r, Files::new(&["input"]));
        assert_eq!(proofs(&r)[0].complete, pathname);
        assert_eq!(
            r.decision == Decision::Allow,
            pathname && environment,
            "{r:#?}"
        );
        let env = r
            .decision_trace
            .evidence
            .iter()
            .find_map(|e| match &e.kind {
                EvidenceKind::ToolOptionEnvironment(v) => Some(v),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            env.value,
            if environment {
                ShellEnvironmentValue::Absent
            } else {
                ShellEnvironmentValue::Unknown
            }
        );
    }
}

#[test]
fn changing_failed_or_oversized_directory_evidence_never_completes() {
    for status in [
        DirectoryReadStatus::Unavailable,
        DirectoryReadStatus::Unreadable,
        DirectoryReadStatus::NonUtf8,
        DirectoryReadStatus::TooLarge,
        DirectoryReadStatus::Changed,
    ] {
        let mut files = Files::new(&["input"]);
        files.failure = Some(status);
        let r = check(request("tar -cf output.tar *"), files);
        assert!(!proofs(&r)[0].complete);
        assert_eq!(r.decision, Decision::NeedApproval);
    }
    let mut files = Files::new(&["input"]);
    files.changed = true;
    let r = check(request("tar -cf output.tar *"), files);
    assert!(!proofs(&r)[0].complete);
    assert_eq!(r.decision, Decision::NeedApproval);
}

#[test]
fn unsupported_inputs_and_in_action_state_changes_keep_explicit_gaps() {
    for command in [
        "touch new; tar -cf output.tar *",
        "shopt -s nullglob; tar -cf output.tar *",
        "set -f; tar -cf output.tar *",
        "GLOBIGNORE=x; tar -cf output.tar *",
        "tar -cf output.tar [[:alpha:]]*",
        "tar -cf output.tar $dir/*",
    ] {
        let r = check(request(command), Files::new(&["input"]));
        assert_eq!(r.decision, Decision::NeedApproval, "{command}: {r:#?}");
        assert!(
            proofs(&r).iter().any(|p| !p.complete && p.gap.is_some()),
            "{command}: {r:#?}"
        );
    }
    for change in ["locale", "ignore", "recursive"] {
        let mut r = request("tar -cf output.tar **");
        let o = r.shell_state_before.pathname.as_mut().unwrap();
        match change {
            "locale" => o.lc_all = ShellEnvironmentValue::Unknown,
            "ignore" => o.globignore = ShellEnvironmentValue::Unknown,
            _ => o.globstar = true,
        }
        let r = check(r, Files::new(&["input"]));
        assert!(!proofs(&r)[0].complete);
        assert_eq!(r.decision, Decision::NeedApproval);
    }
}

#[test]
fn environment_callbacks_use_native_ownership_and_keep_their_origin() {
    let mut r = request("tar -cf output.tar -- input");
    r.shell_state_before.environment.clear();
    r.shell_state_before = r.shell_state_before.with_environment_observation(
        "TAR_OPTIONS",
        ShellEnvironmentValue::Present {
            value: "--checkpoint=1 --checkpoint-action='exec=python3 .post.py'".into(),
        },
    );
    let r = check(r, Files::new(&["input", ".post.py"]));
    assert!(has_command(&r, "python3"), "{r:#?}");
    assert_eq!(r.decision, Decision::NeedApproval);
    let r = check(
        request("TAR_OPTIONS=--verbose tar -cf output.tar -- input"),
        Files::new(&["input"]),
    );
    assert!(
        r.decision_trace.evidence.iter().any(|e| matches!(&e.kind,
        EvidenceKind::ToolOptionEnvironment(v) if v.from_prefix_assignment && matches!(&v.value,
            ShellEnvironmentValue::Present { value } if value == "--verbose"))),
        "{r:#?}"
    );
    for value in [
        "--directory",
        "--unknown-control",
        "--checkpoint-action='unterminated",
    ] {
        let mut r = request("tar -cf output.tar -- input");
        r.shell_state_before.environment.clear();
        r.shell_state_before = r.shell_state_before.with_environment_observation(
            "TAR_OPTIONS",
            ShellEnvironmentValue::Present {
                value: value.into(),
            },
        );
        assert_eq!(
            check(r, Files::new(&["input"])).decision,
            Decision::NeedApproval
        );
    }
}

#[test]
fn declared_callback_coverage_not_filename_location_controls_completeness() {
    for (callback, expected) in [
        ("touch output", Decision::Allow),
        ("python3 .post.py", Decision::NeedApproval),
        ("unmodeled_program input", Decision::NeedApproval),
    ] {
        for source in [
            format!(
                "tar -cf output.tar --checkpoint=1 '--checkpoint-action=exec={callback}' input"
            ),
            "tar -cf output.tar --checkpoint=1 *".into(),
        ] {
            let name = format!("--checkpoint-action=exec={callback}");
            let r = check(request(&source), Files::new(&[&name, "input", ".post.py"]));
            assert_eq!(r.decision, expected, "{source}: {r:#?}");
        }
    }
}

#[test]
fn conflicting_shell_variable_observations_are_not_silently_reconciled() {
    let mut r = request("tar -cf output.tar *");
    r.shell_state_before
        .variables
        .push(ShellVariableSnapshot::new(
            "LC_ALL",
            ShellValueSnapshot::ExactScalar {
                value: "other".into(),
            },
            false,
        ));
    let r = check(r, Files::new(&["input"]));
    assert!(!proofs(&r)[0].complete);
    assert_eq!(r.decision, Decision::NeedApproval);
}

#[test]
fn native_bash_agrees_on_fields_without_executing_sample_commands() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "caushell-pathname-oracle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let names = [
        "z",
        "two words",
        "line\nbreak",
        ".hidden",
        "$(touch injected)",
        "a*?",
        "A.TXT",
        "é",
    ];
    for name in names {
        std::fs::write(root.join(name), b"fixture").unwrap();
    }
    for (word, settings, nullglob, dotglob, nocase, noglob, skipdots, locale) in [
        ("*", "", false, false, false, false, true, "C"),
        (
            "*",
            "shopt -s dotglob",
            false,
            true,
            false,
            false,
            true,
            "C",
        ),
        (
            "*.txt",
            "shopt -s nocaseglob",
            false,
            false,
            true,
            false,
            true,
            "C",
        ),
        ("missing*", "", false, false, false, false, true, "C"),
        (
            "missing*",
            "shopt -s nullglob",
            true,
            false,
            false,
            false,
            true,
            "C",
        ),
        ("*", "set -f", false, false, false, true, true, "C"),
        ("a'*'?*", "", false, false, false, false, true, "C"),
        (".[^.]*", "", false, false, false, false, true, "C"),
        ("[a-z]*", "", false, false, false, false, true, "C"),
        ("[^a]*", "", false, false, false, false, true, "C"),
        (
            ".*",
            "shopt -u globskipdots",
            false,
            false,
            false,
            false,
            false,
            "C",
        ),
        ("?", "", false, false, false, false, true, "C"),
        ("?", "", false, false, false, false, true, "C.UTF-8"),
    ] {
        let source = format!(
            "set +f; unset GLOBIGNORE; shopt -u nullglob failglob dotglob nocaseglob globstar extglob; shopt -s globskipdots; export LC_ALL={locale}; {settings}\n/usr/bin/python3 -I -S -c 'import sys; b=sys.stdout.buffer; b.write(str(len(sys.argv)-1).encode()+b\"\\n\"); b.write(b\"\\0\".join(v.encode() for v in sys.argv[1:]))' {word}"
        );
        let native = std::process::Command::new("/bin/bash")
            .args(["--noprofile", "--norc", "-c", &source])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            native.status.success(),
            "{}",
            String::from_utf8(native.stderr).unwrap()
        );
        let output = String::from_utf8(native.stdout).unwrap();
        let (count, body) = output.split_once('\n').unwrap();
        let count = count.parse::<usize>().unwrap();
        let expected = if count == 0 {
            Vec::new()
        } else {
            body.split('\0').map(str::to_owned).collect::<Vec<_>>()
        };
        assert_eq!(expected.len(), count);
        let mut r = request(&format!("tar -cf output.tar -- {word}"));
        let o = r.shell_state_before.pathname.as_mut().unwrap();
        o.nullglob = nullglob;
        o.dotglob = dotglob;
        o.nocaseglob = nocase;
        o.noglob = noglob;
        o.globskipdots = skipdots;
        o.lc_all = ShellEnvironmentValue::Present {
            value: locale.into(),
        };
        let r = check(r, Files::new(&names));
        let p = proofs(&r)[0];
        assert!(p.complete, "{source}: {p:#?}");
        assert_eq!(p.fields, expected, "{source}");
    }
    assert!(!root.join("injected").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn aggregate_argv_budget_does_not_accept_partial_materialization() {
    let names = (0..1000).map(|i| format!("file{i:04}")).collect::<Vec<_>>();
    let names = names.iter().map(String::as_str).collect::<Vec<_>>();
    let r = check(
        request("tar -cf output.tar -- f* f* f* f* f*"),
        Files::new(&names),
    );
    assert_eq!(r.decision, Decision::NeedApproval);
    assert!(proofs(&r).iter().all(|p| !p.complete
        && p.fields.is_empty()
        && p.gap.as_deref() == Some("pathname argv budget exceeded")));
}

#[test]
fn an_existing_bounded_proof_does_not_become_fabricated_exact_fields() {
    let mut r = request("tar -cf output.tar -- *");
    r.shell_state_before.pathname = None;
    let r = check(r, Files::new(&["input"]));
    let p = proofs(&r)[0];
    assert!(!p.complete && !p.exact_fields_required && p.fields.is_empty());
    assert_eq!(r.decision, Decision::Allow, "{r:#?}");
    assert!(
        !r.decision_trace
            .execution_semantics
            .iter()
            .any(|s| s.operation_semantics_unresolved)
    );
}

fn without_pathname_options(command: &str) -> CheckRequest {
    let mut request = request(command);
    request.shell_state_before.pathname = None;
    request
}

#[test]
fn no_match_keeps_literal_targets_and_native_defaults_without_claiming_exact_argv() {
    let response = check(
        without_pathname_options("find */201111 -name '*.jpg'"),
        Files::new(&["ordinary"]),
    );
    assert_eq!(response.decision, Decision::Allow, "{:?}", response.reasons);
    let proof = proofs(&response)[0];
    assert_eq!(proof.unmatched_literal.as_deref(), Some("*/201111"));
    assert!(proof.gap.is_none(), "{proof:?}");
    assert!(!proof.complete && proof.fields.is_empty());
    assert!(
        response.decision_trace.path_targets.iter().any(|fact| {
            let SemanticResolution::Resolved { value } = &fact.resolution else {
                return false;
            };
            matches!(value, PathResolution::BoundedPathSet { roots, .. }
                if roots == &["/workspace"])
                || value.concrete_path() == Some("/workspace")
        }),
        "{:?}",
        response.decision_trace.path_targets
    );
}

#[test]
fn no_match_does_not_hide_other_pipeline_stages_or_new_native_roles() {
    let simple_pipeline = check(
        without_pathname_options("file *.php | grep UTF"),
        Files::new(&["ordinary"]),
    );
    assert_eq!(
        simple_pipeline.decision,
        Decision::Allow,
        "{:?}",
        simple_pipeline.reasons
    );
    assert!(has_command(&simple_pipeline, "grep"));
    let outcome = check(
        without_pathname_options("file *.php | python3 -"),
        Files::new(&["ordinary"]),
    );
    assert_ne!(outcome.decision, Decision::Allow);
    assert!(has_command(&outcome, "python3"));
    let changed = check(
        without_pathname_options("file -m *.missing local"),
        Files::new(&["local"]),
    );
    assert_ne!(changed.decision, Decision::Allow, "{:?}", changed.reasons);
    assert!(proofs(&changed)[0].gap.is_some());
}

#[test]
fn possible_matches_and_stale_directory_observations_cannot_close_the_bound() {
    for names in [&[".HIDDEN.PHP"][..], &["é"][..]] {
        let outcome = check(without_pathname_options("file *.php"), Files::new(names));
        assert!(proofs(&outcome)[0].unmatched_literal.is_none());
    }
    let mut files = Files::new(&["ordinary"]);
    files.changed = true;
    let outcome = check(without_pathname_options("file *.php"), files);
    assert!(proofs(&outcome)[0].gap.is_some());
    assert_ne!(outcome.decision, Decision::Allow);
}

#[test]
fn no_match_joins_the_same_operands_across_layouts() {
    for command in ["chmod +x *.sh", "find . name *foo", "find *-name hi.dat"] {
        let result = check(without_pathname_options(command), Files::new(&["ordinary"]));
        assert_eq!(
            result.decision,
            Decision::Allow,
            "{command}: {:?}",
            result.reasons
        );
        assert!(proofs(&result)[0].gap.is_none());
    }
    let outside = check(
        without_pathname_options("chmod +x /outside/*.sh"),
        Files::new(&["ordinary"]),
    );
    assert_ne!(outside.decision, Decision::Allow, "{:?}", outside.reasons);
}

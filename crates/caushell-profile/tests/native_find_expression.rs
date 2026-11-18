//! Read-only differential controls against the pinned local GNU find runtime.
#![cfg(target_os = "linux")]
use caushell_profile::NativePathOutputPlan;
use caushell_types::DirectoryEntryKind;
use std::{collections::VecDeque, fs, path::Path, process::Command};

fn observed(plan: &NativePathOutputPlan, root: &Path) -> Vec<u8> {
    let mut queue = VecDeque::from([("input".to_owned(), String::new(), 0usize)]);
    let mut bytes = Vec::new();
    while let Some((spelling, relative, depth)) = queue.pop_front() {
        let native = root.join(&spelling);
        let metadata = fs::symlink_metadata(&native).unwrap();
        let kind = if metadata.file_type().is_symlink() {
            DirectoryEntryKind::Symlink
        } else if metadata.is_dir() {
            DirectoryEntryKind::Directory
        } else {
            DirectoryEntryKind::File
        };
        let name = spelling.rsplit('/').next().unwrap();
        let result = plan
            .evaluate(&spelling, &relative, name, kind, depth)
            .unwrap();
        bytes.extend(result.bytes);
        if kind == DirectoryEntryKind::Directory
            && !result.prune
            && plan.max_depth.is_none_or(|max| depth < max)
        {
            for child in fs::read_dir(native).unwrap() {
                let name = child.unwrap().file_name().into_string().unwrap();
                queue.push_back((
                    format!("{spelling}/{name}"),
                    if relative.is_empty() {
                        name.clone()
                    } else {
                        format!("{relative}/{name}")
                    },
                    depth + 1,
                ));
            }
        }
    }
    bytes
}
fn nul_records(bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    assert_eq!(bytes.last(), Some(&0));
    let mut records = bytes[..bytes.len() - 1]
        .split(|b| *b == 0)
        .map(Vec::from)
        .collect::<Vec<_>>();
    records.sort();
    records
}

#[test]
fn expression_outputs_and_pruned_traversal_match_native_find() {
    let version = Command::new("/usr/bin/find")
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).contains("GNU findutils")
    );
    println!(
        "NATIVE_FIND_VERSION {}",
        String::from_utf8_lossy(&version.stdout)
    );
    let root =
        std::env::temp_dir().join(format!("caushell-find-expression-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    for dir in ["input", "input/sub", "input/skip", "input/skip/deeper"] {
        fs::create_dir(root.join(dir)).unwrap();
    }
    for file in [
        "input/a",
        "input/b",
        "input/a.tmp",
        "input/line\nbreak",
        "input/-exec",
        "input/sub/a",
        "input/sub/c",
        "input/skip/a",
        "input/skip/deeper/b",
    ] {
        fs::write(root.join(file), b"owned fixture\n").unwrap();
    }
    std::os::unix::fs::symlink("../skip", root.join("input/sub/link")).unwrap();
    let atoms = [
        vec!["-true"],
        vec!["-false"],
        vec!["-name", "a"],
        vec!["-type", "d"],
        vec!["-name", "skip", "-prune"],
    ];
    let mut cases = Vec::new();
    for a in &atoms {
        for b in &atoms {
            for operator in ["-a", "-and", "-o"] {
                let mut args = vec!["input", "("];
                args.extend(a.iter().copied());
                args.push(operator);
                args.extend(b.iter().copied());
                args.extend([")", "-print0"]);
                cases.push(args);
            }
        }
    }
    cases.extend([
        vec!["input", "!", "-name", "*.tmp", "-print0"],
        vec!["input", "-name", "skip", "-prune", "-o", "-print0"],
        vec![
            "input", "-name", "a", "-print0", "-o", "-name", "b", "-print0",
        ],
        vec!["input", "-print0", "-false"],
        vec!["input", "-true", "-o", "-print0"],
        vec!["input", "-false", "-printf", "", "-o", "-true"],
        vec!["input", "-mindepth", "1", "-prune", "-print0"],
        vec!["input", "-false", "-a", "-maxdepth", "1", "-o", "-print0"],
        vec!["input", "-print0", "-maxdepth", "1"],
        vec![
            "input", "-name", "skip", "-o", "-name", "sub", "-prune", "-o", "-print0",
        ],
        vec![
            "input", "-not", "(", "-name", "a", "-or", "-name", "skip", ")", "-print0",
        ],
        vec!["input", "-iwholename", "*SUB*", "-print0"],
        vec!["input", "-wholename", "*skip*", "-prune", "-o", "-print0"],
        vec!["input", "-prune", "-name", "never-matches", "-cmin", "+60"],
        vec!["input", "-false", "-size", "+1M", "-print0"],
        vec!["input", "-true", "-o", "-mtime", "+5", "-print0"],
    ]);
    for args in &cases {
        let plan =
            NativePathOutputPlan::find(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let expected = observed(&plan, &root);
        let native = Command::new("/usr/bin/find")
            .current_dir(&root)
            .env("LC_ALL", "C")
            .args(args)
            .output()
            .unwrap();
        assert!(native.status.success(), "{args:?}: {:?}", native.stderr);
        assert_eq!(
            nul_records(&expected),
            nul_records(&native.stdout),
            "{args:?}"
        );
        println!("FIND_ORACLE {args:?} bytes={:?}", native.stdout);
    }
    // Implicit newline print is distinct from the NUL controls above.
    for args in [
        vec!["input", "-prune"],
        vec!["input", "!", "-prune"],
        vec![
            "input",
            "-maxdepth",
            "0",
            "-printf",
            r"A%p\0",
            "-a",
            "-printf",
            r"B%p\0",
        ],
    ] {
        let plan =
            NativePathOutputPlan::find(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let native = Command::new("/usr/bin/find")
            .current_dir(&root)
            .env("LC_ALL", "C")
            .args(&args)
            .output()
            .unwrap();
        assert!(native.status.success());
        assert_eq!(observed(&plan, &root), native.stdout, "{args:?}");
        println!("FIND_ORACLE {args:?} bytes={:?}", native.stdout);
    }
    fs::remove_dir_all(&root).unwrap();
    println!("FIND_ORACLE_CASES {}", cases.len() + 3);
}

#[test]
fn numeric_metadata_requires_observation_when_evaluated_and_valid_syntax_everywhere() {
    fn plan(args: &[&str]) -> Result<NativePathOutputPlan, &'static str> {
        NativePathOutputPlan::find(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
    }
    for args in [
        &["-amin", "1"][..],
        &["-atime", "+1"],
        &["-cmin", "+60"],
        &["-ctime", "-1"],
        &["-mmin", "0"],
        &["-mtime", "+5"],
        &["-size", "+1M"],
        &["-not", "-size", "-1k"],
        &["-print0", "-mtime", "+5"],
        &["-size", "1", "-false"],
    ] {
        let result = plan(args)
            .unwrap()
            .evaluate(".", "", ".", DirectoryEntryKind::Directory, 0);
        assert_eq!(
            result,
            Err("native numeric metadata predicate is unobserved")
        );
    }
    for args in [
        &["-false", "-cmin"][..],
        &["-false", "-cmin", "+1M"],
        &["-false", "-mtime", "++1"],
        &["-false", "-size", "+M"],
        &["-false", "-size", "1MB"],
        &["-false", "-size", "1b"],
        &["-false", "-size", "1w"],
        &["-false", "-size", "4294967296c"],
        &["-false", "-size", "-print"],
        &["-false", "-depth"],
    ] {
        assert!(plan(args).is_err(), "{args:?}");
    }
}

#[test]
fn unknown_case_folding_only_matters_when_a_test_is_reached() {
    let plan = |args: &[&str]| {
        caushell_profile::NativePathOutputPlan::find(
            &args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap()
    };
    let skipped = plan(&["-type", "f", "-iname", "*.txt", "-print0"]);
    assert!(
        !skipped
            .evaluate_with_case_fold(".", "", ".", DirectoryEntryKind::Directory, 0, false)
            .unwrap()
            .emitted
    );
    assert_eq!(
        skipped.evaluate_with_case_fold(
            "./A.TXT",
            "A.TXT",
            "A.TXT",
            DirectoryEntryKind::File,
            1,
            false
        ),
        Err("native case folding locale is unobserved or unsupported"),
    );
    assert!(
        skipped
            .evaluate_with_case_fold(
                "./A.TXT",
                "A.TXT",
                "A.TXT",
                DirectoryEntryKind::File,
                1,
                true
            )
            .unwrap()
            .emitted
    );
    let disjunction = plan(&[
        "-type", "d", "-print0", "-o", "-ipath", "*/A.TXT", "-print0",
    ]);
    assert!(
        disjunction
            .evaluate_with_case_fold(".", "", ".", DirectoryEntryKind::Directory, 0, false)
            .unwrap()
            .emitted
    );
}

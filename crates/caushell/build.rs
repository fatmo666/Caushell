use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    for variable in [
        "CAUSHELL_BUILD_COMMIT",
        "CAUSHELL_RELEASE_TAG",
        "GITHUB_SHA",
        "GITHUB_REF_NAME",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    emit_git_rerun_paths();

    let commit = env::var("CAUSHELL_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            env::var("GITHUB_SHA")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(git_commit)
        .unwrap_or_else(|| "unknown".to_string());
    let commit = commit.trim().to_string();

    let release = env::var("CAUSHELL_RELEASE_TAG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(inferred_release)
        .unwrap_or_else(|| "source".to_string());

    println!("cargo:rustc-env=CAUSHELL_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=CAUSHELL_RELEASE_TAG={}", release.trim());
    println!(
        "cargo:rustc-env=CAUSHELL_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );
}

fn emit_git_rerun_paths() {
    let git_dir = Path::new("../../.git");
    let head = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head.display());
    println!(
        "cargo:rerun-if-changed={}",
        git_dir.join("packed-refs").display()
    );
    if let Ok(contents) = fs::read_to_string(&head)
        && let Some(reference) = contents.trim().strip_prefix("ref: ")
    {
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join(reference).display()
        );
    }
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn inferred_release() -> Option<String> {
    let ref_name = env::var("GITHUB_REF_NAME").ok()?;
    if ref_name.starts_with('v') {
        return Some(ref_name);
    }
    None
}

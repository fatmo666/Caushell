use std::process::Command;

#[test]
fn version_reports_the_release_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .arg("--version")
        .output()
        .expect("caushell must start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output must be UTF-8"),
        format!("caushell {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn unknown_command_returns_failure() {
    let output = Command::new(env!("CARGO_BIN_EXE_caushell"))
        .arg("does-not-exist")
        .output()
        .expect("caushell must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("error output must be UTF-8"),
        "invalid caushell arguments: unknown command: does-not-exist\n"
    );
}

//! Architecture regressions: configuration consumers cannot accept entry snapshots.
use std::path::Path;

fn production(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[test]
fn configuration_consumers_require_execution_environment_not_requests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in ["support/implicit_startup.rs", "support/git_hooks.rs"] {
        let text = production(&root.join(name));
        for forbidden in [
            "CheckRequest",
            "ShellStateSnapshot",
            ".exported_variable(",
            ".variable_binding(",
        ] {
            assert!(
                !text.contains(forbidden),
                "{name} bypasses execution context through {forbidden}"
            );
        }
    }
    let git = production(&root.join("support/git_hooks.rs"));
    assert!(git.contains("environment:&ExecutionEnvironment"));
    assert!(
        production(&root.join("passes/discover_tool_config_inputs.rs"))
            .contains("record.environment()")
    );
}

#[test]
fn no_pass_reads_entry_environment_values_directly() {
    fn walk(path: &Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path);
                continue;
            }
            if path.extension().is_none_or(|s| s != "rs") {
                continue;
            }
            let text = production(&path);
            for forbidden in [
                ".exported_variable(",
                ".shell_state_before.variables",
                ".shell_state_before.variable_binding(",
                ".shell_state_before.exported_variables(",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{} reads entry state: {forbidden}",
                    path.display()
                );
            }
        }
    }
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
}

#[test]
fn dispatch_resolution_carries_the_complete_lookup_domain() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    // This module has test-only imports before its production implementation.
    // Splitting at the first cfg(test) would skip the entire dispatch boundary.
    let source: String = std::fs::read_to_string(root.join("src/passes/resolve_invocation.rs"))
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(!source.contains("resolve_invocation_in_namespace"));
    assert!(source.contains("resolve_invocation_in_lookup_domain_with_stdout_proofs("));
    let profile = root.join("../caushell-profile/src");
    for file in ["bind.rs", "types.rs"] {
        let source = production(&profile.join(file));
        assert!(
            !source.contains("pubmodule_runtime:Option<String>"),
            "{file}"
        );
    }
}

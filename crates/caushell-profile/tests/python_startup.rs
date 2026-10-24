use caushell_profile::python_startup_missing_imports as inspect;

#[test]
fn startup_noop_and_absent_import_handlers_have_explicit_dependencies() {
    assert_eq!(
        inspect("# comment\npass\n'constant'\n").unwrap(),
        Vec::<String>::new()
    );
    let source = "try:\n    import optional_hook\nexcept ImportError:\n    pass\nelse:\n    optional_hook.install()\n";
    assert_eq!(inspect(source).unwrap(), ["optional_hook"]);
    assert_eq!(
        inspect(&source.replace("ImportError", "ModuleNotFoundError")).unwrap(),
        ["optional_hook"]
    );
}

#[test]
fn startup_actions_are_not_inferred_from_a_familiar_filename() {
    for source in [
        "unknown_call()",
        "import optional_hook",
        "try:\n    import optional_hook\nexcept ImportError:\n    unknown_call()",
        "try:\n    import optional_hook\nexcept Exception:\n    pass",
        "try:\n    import optional_hook\nexcept ImportError:\n    pass\nfinally:\n    unknown_call()",
        "try:\n    import optional_hook\n    unknown_call()\nexcept ImportError:\n    pass",
        "try:\n    import package.hook\nexcept ImportError:\n    pass",
        "try:\n    import optional_hook as hook\nexcept ImportError:\n    pass",
    ] {
        assert!(inspect(source).is_err(), "{source}");
    }
}

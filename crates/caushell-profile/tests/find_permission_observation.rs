use caushell_profile::NativePathOutputPlan;
use caushell_types::DirectoryEntryKind;

fn plan(tokens: &[&str]) -> Result<NativePathOutputPlan, &'static str> {
    NativePathOutputPlan::find(&tokens.iter().map(|word| (*word).into()).collect::<Vec<_>>())
}

#[test]
fn supported_permission_tests_depend_on_observed_mode_bits() {
    for mode in ["640", "-0640", "u=rw,g=r", "-a+x"] {
        let lookup =
            plan(&["input", "-perm", mode, "-print0"]).expect("recognized permission test");
        assert!(lookup.contains_metadata_test());
        assert_eq!(
            lookup.evaluate("input/notes", "notes", "notes", DirectoryEntryKind::File, 1),
            Err("native permission bits are unobserved")
        );

        let skipped =
            plan(&["input", "-false", "-a", "-perm", mode, "-print0"]).expect("known expression");
        assert!(skipped.output_is_unreachable());
        assert!(
            !skipped
                .evaluate("input/notes", "notes", "notes", DirectoryEntryKind::File, 1)
                .unwrap()
                .emitted
        );
    }
}

#[test]
fn gnu_permission_syntax_and_invalid_operands_cannot_certify_output() {
    for mode in ["/g=r", "/040"] {
        let result = plan(&["input", "-true", "-o", "-perm", mode, "-print0"]);
        assert_eq!(
            result.err(),
            Some("native permission mode requires a GNU find dialect proof")
        );
    }
    for mode in ["", "988", "--exec", "u=rr,garbage"] {
        assert!(plan(&["input", "-perm", mode, "-print0"]).is_err());
    }
}

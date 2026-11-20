use caushell_profile::NativePathOutputPlan;
use caushell_types::DirectoryEntryKind;

fn plan(expression: &[&str]) -> Result<NativePathOutputPlan, &'static str> {
    let mut argv = vec![".".into()];
    argv.extend(expression.iter().map(|word| (*word).into()));
    NativePathOutputPlan::find(&argv)
}

const LOWER: &str = "2014-04-30 08:00:00";
const UPPER: &str = "2014-04-30 09:00:00";

#[test]
fn modification_time_window_requires_metadata_and_timezone_evidence() {
    let window = plan(&["-newermt", LOWER, "-not", "-newermt", UPPER])
        .expect("recognize both civil-time comparisons");
    assert!(window.contains_metadata_test());
    assert_eq!(
        window.evaluate("./input", "input", "input", DirectoryEntryKind::File, 1),
        Err("native modification time and reference timezone are unobserved")
    );
}

#[test]
fn skipped_date_comparison_does_not_supply_positive_output_evidence() {
    let never = plan(&["-false", "-a", "-newermt", LOWER, "-print0"])
        .expect("recognize the unreachable expression");
    assert!(never.output_is_unreachable());
    assert!(
        !never
            .evaluate("./input", "input", "input", DirectoryEntryKind::File, 1)
            .unwrap()
            .emitted
    );

    let emits = plan(&["-true", "-o", "-newermt", LOWER]).unwrap();
    assert_eq!(
        emits.evaluate("./input", "input", "input", DirectoryEntryKind::File, 1),
        Err("native reference date parsing is unproved")
    );
    assert_eq!(
        plan(&["-false", "-a", "-newermt", "-print0"]),
        Err("unsupported native modification-time date spelling")
    );
}

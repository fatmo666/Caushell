use caushell_parse::command_success_required_before;

#[test]
fn success_conditions_follow_and_lists_and_if_arms() {
    for source in [
        "source env && target",
        "source env && true && target",
        "test -f flag && source env && target",
        "if source env; then target; fi",
        "if source env && true; then target; fi",
        "if test -f flag; then source env && target; fi",
        "! source env || target",
    ] {
        assert!(
            command_success_required_before(
                source,
                source.find("source").unwrap(),
                source.find("target").unwrap()
            ),
            "{source}"
        );
    }
}

#[test]
fn joins_failure_paths_and_other_statuses_do_not_prove_success() {
    for source in [
        "source env; target",
        "source env || target",
        "source env && true; target",
        "if source env; then :; else target; fi",
        "if source env; true; then target; fi",
        "source env || true && target",
        "source env | cat && target",
        "(source env) && target",
        "while source env; do target; done",
        "source env && echo target; actual",
    ] {
        let target = if source.ends_with("actual") {
            source.find("actual")
        } else {
            source.find("target")
        }
        .unwrap();
        assert!(
            !command_success_required_before(source, source.find("source").unwrap(), target),
            "{source}"
        );
    }
}

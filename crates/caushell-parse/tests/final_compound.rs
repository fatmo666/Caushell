use caushell_parse::{ParseStatus, parse_command};
use caushell_types::ShellKind;

#[test]
fn final_subshell_can_directly_precede_a_closing_brace() {
    for command in [
        "{ (printf '%s' fixture) }",
        "{ (printf '%s' fixture)}",
        "work() { (printf '%s' fixture) }\nwork",
        "work() { (while read -r value; do printf '%s' \"$value\"; done < input.txt) }\nwork",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{command}: {:?}",
            parsed.diagnostics
        );
    }
}

#[test]
fn closed_compounds_can_end_a_bash_loop_body() {
    for command in [
        "while false; do if true; then :; fi done",
        "while false; do :; if true; then :; fi done",
        "while false; do case v in v) :;; esac done",
        "while false; do (printf fixture) done",
        "while false; do { :; } done",
        "while false; do until true; do :; done done",
        "for item in fixture; do if true; then :; fi done",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{command}: {:?}",
            parsed.diagnostics
        );
        assert_eq!(parsed.raw_command, command);
    }
}

#[test]
fn a_loop_tail_still_requires_a_complete_non_redirected_compound() {
    for command in [
        "while false; do printf x done",
        "while false; do (printf x) >out done",
        "while false; do (printf x) | cat done",
        "while false; do if true; then :; done",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{command}");
    }
    let sh = parse_command("while false; do if true; then :; fi done", ShellKind::Sh).unwrap();
    assert_eq!(sh.status, ParseStatus::Partial);
}

#[test]
fn a_closed_compound_can_finish_a_bash_condition() {
    for command in [
        "if (false) then printf yes; fi",
        "if :; (false) then printf yes; fi",
        "if (printf fixture | cat) then printf yes; fi;",
        "if { false; } then printf yes; fi",
        "if case x in x) :;; esac then printf yes; fi",
        "if while false; do :; done then printf yes; fi",
        "if false; then :; elif (true) then printf yes; fi",
        "while (false) do printf yes; done",
        "until (true) do printf yes; done",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Complete,
            "{command}: {:?}",
            parsed.diagnostics
        );
        assert_eq!(parsed.raw_command, command);
        let original_span = &parsed.commands.last().unwrap().span;
        assert_eq!(
            &command[original_span.start_byte..original_span.end_byte],
            "printf yes"
        );
    }
}

#[test]
fn incomplete_or_non_compound_conditions_still_need_a_separator() {
    for command in [
        "if printf x then printf yes; fi",
        "if (false) >out then printf yes; fi",
        "if (false) | cat then printf yes; fi",
        "if (false then printf yes; fi",
        "if (false) then printf yes",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert_eq!(parsed.status, ParseStatus::Partial, "{command}");
    }
    let sh = parse_command("if (false) then printf yes; fi", ShellKind::Sh).unwrap();
    assert_eq!(sh.status, ParseStatus::Partial);
}

#[test]
fn real_missing_terminators_and_delimiters_remain_partial() {
    for command in [
        "{ printf '%s' fixture }",
        "{ (printf '%s' fixture) > output.txt }",
        "{ (printf '%s' fixture) | cat }",
        "{ (printf '%s' fixture)",
        "{ (printf '%s fixture) }",
    ] {
        let parsed = parse_command(command, ShellKind::Bash).unwrap();
        assert_eq!(
            parsed.status,
            ParseStatus::Partial,
            "{command}: {:?}",
            parsed.diagnostics
        );
    }
}

#[test]
fn omitted_separator_recovery_is_bash_only() {
    let sh = parse_command("{ (printf fixture) }", ShellKind::Sh).unwrap();
    assert_eq!(sh.status, ParseStatus::Partial);
    let bash = parse_command("{ (printf fixture) & }", ShellKind::Bash).unwrap();
    assert_eq!(bash.status, ParseStatus::Complete);
}

use super::{
    XargsDispatchMode as D, XargsItemMode as I, XargsStaticExpansionConfig, observed_xargs_groups,
};
use caushell_types::*;

fn output(blocks: &[&str], order: StreamRecordOrder) -> StdoutRecordsEvidence {
    StdoutRecordsEvidence {
        producer_contract_sha256: None,
        node_id: "producer".into(),
        producer_node_id: "producer".into(),
        session_id: "s".into(),
        sequence_no: CommandSequenceNo(1),
        cwd: Some("/work".into()),
        complete: true,
        order,
        encoding: Some(StreamRecordEncoding::NativeFormat),
        records: blocks
            .iter()
            .map(|b| ObservedStreamRecord {
                path_spelling: String::new(),
                bytes: b.as_bytes().to_vec(),
            })
            .collect(),
        namespace_observations: vec![],
        missing_starting_point_observations: vec![],
        directory_observations: vec![],
        environment_observations: vec![],
        forwarded_by: vec![],
        gap: None,
    }
}

fn config(item_mode: I, dispatch_mode: D, run_if_empty: bool) -> XargsStaticExpansionConfig {
    XargsStaticExpansionConfig {
        item_mode,
        dispatch_mode,
        run_if_empty,
        requires_confirmation: false,
        eof_marker: None,
        insert_batch_token: None,
    }
}

#[test]
fn exact_groups_preserve_order_repeats_and_short_final_batch() {
    let p = output(&["b a b c d\n"], StreamRecordOrder::Exact);
    let c = config(I::WhitespaceSeparated, D::MaxArgs { max_args: 2 }, true);
    assert_eq!(
        observed_xargs_groups(&p, &c).unwrap(),
        vec![vec!["b", "a"], vec!["b", "c"], vec!["d"]]
    );
    let c = config(I::WhitespaceSeparated, D::MaxArgs { max_args: 1 }, true);
    assert_eq!(observed_xargs_groups(&p, &c).unwrap().len(), 5);
}

#[test]
fn unordered_records_cover_all_native_batch_positions() {
    let p = output(&["a\n", "b\n", "c\n"], StreamRecordOrder::Unspecified);
    let c = config(I::WhitespaceSeparated, D::MaxArgs { max_args: 2 }, false);
    let groups = observed_xargs_groups(&p, &c).unwrap();
    for a in ["a", "b", "c"] {
        assert!(groups.contains(&vec![a.to_string()]));
        for b in ["a", "b", "c"] {
            if a != b {
                assert!(groups.contains(&vec![a.to_string(), b.to_string()]));
            }
        }
    }
    assert_eq!(groups.len(), 9);
}

#[test]
fn partial_malformed_and_over_budget_records_are_not_empty_input() {
    let c = config(I::WhitespaceSeparated, D::AppendAll, false);
    for text in ["\"unterminated\n", "trailing\\", "embedded\0nul"] {
        assert!(observed_xargs_groups(&output(&[text], StreamRecordOrder::Exact), &c).is_err());
    }
    let mut p = output(&[], StreamRecordOrder::Exact);
    assert!(observed_xargs_groups(&p, &c).unwrap().is_empty());
    p.complete = false;
    assert!(observed_xargs_groups(&p, &c).is_err());
    let p = output(
        &["a\n", "b\n", "c\n", "d\n", "e\n", "f\n"],
        StreamRecordOrder::Unspecified,
    );
    assert!(observed_xargs_groups(&p, &c).is_err());
    let c = config(I::WhitespaceSeparated, D::MaxArgs { max_args: 1 }, false);
    assert_eq!(observed_xargs_groups(&p, &c).unwrap().len(), 6);
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_native_xargs_confirms_decoder_grouping_and_empty_input() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let cases = [
        (
            "one \"two words\" back\\\\slash\n",
            vec!["-n2"],
            config(I::WhitespaceSeparated, D::MaxArgs { max_args: 2 }, true),
        ),
        (
            "a b\0line\nbreak\0quote'\\\0",
            vec!["-0", "-n2"],
            config(I::NullSeparated, D::MaxArgs { max_args: 2 }, true),
        ),
        (
            "a b|quote'|back\\slash|",
            vec!["-d", "|", "-n1"],
            config(
                I::Delimited {
                    delimiter: "|".into(),
                },
                D::MaxArgs { max_args: 1 },
                true,
            ),
        ),
        (
            "a b\nc d\ne f\n",
            vec!["-L2"],
            config(I::WhitespaceSeparated, D::MaxLines { max_lines: 2 }, true),
        ),
        (
            " one two\nthree\\\\four\n",
            vec!["-I@"],
            config(
                I::NewlineSeparated,
                D::ReplaceToken { token: "@".into() },
                true,
            ),
        ),
        (
            "",
            vec!["-n1"],
            config(I::WhitespaceSeparated, D::MaxArgs { max_args: 1 }, true),
        ),
        (
            "",
            vec!["-r", "-n1"],
            config(I::WhitespaceSeparated, D::MaxArgs { max_args: 1 }, false),
        ),
        (
            "",
            vec!["-I@"],
            config(
                I::NewlineSeparated,
                D::ReplaceToken { token: "@".into() },
                true,
            ),
        ),
    ];
    for (text, flags, c) in cases {
        let mut command = Command::new("xargs");
        command.args(&flags).args([
            "python3",
            "-c",
            "import json,sys; print(json.dumps(sys.argv[1:]))",
        ]);
        if matches!(c.dispatch_mode, D::ReplaceToken { .. }) {
            command.arg("@");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "{flags:?}: {:?}", result.stderr);
        let actual: Vec<Vec<String>> = String::from_utf8(result.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            observed_xargs_groups(&output(&[text], StreamRecordOrder::Exact), &c).unwrap(),
            actual,
            "{flags:?} {text:?}"
        );
    }
}

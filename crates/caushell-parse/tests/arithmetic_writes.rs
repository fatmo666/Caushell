use caushell_parse::{ArithmeticReference as R, parse_arithmetic_references};

#[test]
fn prefix_and_postfix_updates_are_writes_not_just_reads() {
    for source in ["slot++", "++slot", "slot--", "--slot"] {
        assert_eq!(
            parse_arithmetic_references(source).unwrap(),
            vec![R::Assignment {
                name: "slot".into(),
                reads_previous: true,
                value: Vec::new()
            }],
            "{source}"
        );
    }
}

#[test]
fn array_updates_keep_both_the_value_read_and_the_write() {
    let refs = parse_arithmetic_references("items[0]++").unwrap();
    assert!(
        refs.iter()
            .any(|r| matches!(r, R::Array { name, read_value: true, .. } if name == "items"))
    );
    assert!(
        refs.iter()
            .any(|r| matches!(r, R::Array { name, read_value: false, .. } if name == "items"))
    );
}

#[test]
fn array_entries_keep_keys_and_ignore_comments() {
    let entries =
        caushell_parse::array_assignment_entries("(#comment\n [2]='a b' [7]=value)").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0.as_deref(), Some("2"));
    assert_eq!(entries[0].1.text, "a b");
    assert_eq!(entries[1].0.as_deref(), Some("7"));
}

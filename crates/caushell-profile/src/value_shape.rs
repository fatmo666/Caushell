use caushell_types::OwnerGroupSpec;

pub fn parse_owner_group_spec(text: &str) -> Option<OwnerGroupSpec> {
    if text.is_empty() {
        return None;
    }

    let colon_count = text.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return None;
    }

    if colon_count == 0 {
        return Some(OwnerGroupSpec {
            owner: Some(text.to_string()),
            group: None,
            trailing_colon: false,
        });
    }

    let (owner, group) = text.split_once(':')?;
    if owner.is_empty() && group.is_empty() {
        return None;
    }

    Some(OwnerGroupSpec {
        owner: (!owner.is_empty()).then(|| owner.to_string()),
        group: (!group.is_empty()).then(|| group.to_string()),
        trailing_colon: group.is_empty(),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_owner_group_spec;
    use caushell_types::OwnerGroupSpec;

    #[test]
    fn parse_owner_group_spec_accepts_supported_shapes() {
        assert_eq!(
            parse_owner_group_spec("root"),
            Some(OwnerGroupSpec {
                owner: Some("root".to_string()),
                group: None,
                trailing_colon: false,
            })
        );
        assert_eq!(
            parse_owner_group_spec("root:staff"),
            Some(OwnerGroupSpec {
                owner: Some("root".to_string()),
                group: Some("staff".to_string()),
                trailing_colon: false,
            })
        );
        assert_eq!(
            parse_owner_group_spec(":staff"),
            Some(OwnerGroupSpec {
                owner: None,
                group: Some("staff".to_string()),
                trailing_colon: false,
            })
        );
        assert_eq!(
            parse_owner_group_spec("root:"),
            Some(OwnerGroupSpec {
                owner: Some("root".to_string()),
                group: None,
                trailing_colon: true,
            })
        );
    }

    #[test]
    fn parse_owner_group_spec_rejects_empty_and_unsupported_shapes() {
        assert_eq!(parse_owner_group_spec(""), None);
        assert_eq!(parse_owner_group_spec(":"), None);
        assert_eq!(parse_owner_group_spec("root:staff:wheel"), None);
    }
}

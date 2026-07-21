use caushell_profile::parse_owner_group_spec;
use caushell_types::OwnerGroupSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataMutationKind {
    WorldWritable,
    AllUsersRwx,
    RootOwnership,
}

pub(crate) fn classify_metadata_mutation(
    raw_operand: Option<&str>,
    command_name: &str,
) -> Option<MetadataMutationKind> {
    match command_name {
        "chmod" => raw_operand.and_then(classify_permission_mode),
        "chown" => raw_operand.and_then(classify_owner_group_spec),
        "chgrp" => raw_operand.and_then(classify_group_operand),
        _ => None,
    }
}

fn classify_permission_mode(mode_text: &str) -> Option<MetadataMutationKind> {
    let normalized = mode_text.trim();

    match normalized {
        "777" | "0777" => return Some(MetadataMutationKind::AllUsersRwx),
        "a+rwx" | "ugo+rwx" => return Some(MetadataMutationKind::AllUsersRwx),
        "a+w" | "o+w" | "go+w" => return Some(MetadataMutationKind::WorldWritable),
        _ => {}
    }

    None
}

fn classify_owner_group_spec(spec_text: &str) -> Option<MetadataMutationKind> {
    let spec = parse_owner_group_spec(spec_text.trim())?;
    classify_owner_group(&spec)
}

fn classify_group_operand(group_text: &str) -> Option<MetadataMutationKind> {
    (group_text.trim() == "root").then_some(MetadataMutationKind::RootOwnership)
}

fn classify_owner_group(spec: &OwnerGroupSpec) -> Option<MetadataMutationKind> {
    if spec.owner.as_deref() == Some("root") || spec.group.as_deref() == Some("root") {
        return Some(MetadataMutationKind::RootOwnership);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{MetadataMutationKind, classify_metadata_mutation};

    #[test]
    fn classify_metadata_mutation_detects_catastrophic_permission_modes() {
        assert_eq!(
            classify_metadata_mutation(Some("777"), "chmod"),
            Some(MetadataMutationKind::AllUsersRwx)
        );
        assert_eq!(
            classify_metadata_mutation(Some("o+w"), "chmod"),
            Some(MetadataMutationKind::WorldWritable)
        );
    }

    #[test]
    fn classify_metadata_mutation_detects_root_ownership_changes() {
        assert_eq!(
            classify_metadata_mutation(Some("root:root"), "chown"),
            Some(MetadataMutationKind::RootOwnership)
        );
        assert_eq!(
            classify_metadata_mutation(Some("root:"), "chown"),
            Some(MetadataMutationKind::RootOwnership)
        );
        assert_eq!(
            classify_metadata_mutation(Some(":root"), "chown"),
            Some(MetadataMutationKind::RootOwnership)
        );
        assert_eq!(
            classify_metadata_mutation(Some("root"), "chgrp"),
            Some(MetadataMutationKind::RootOwnership)
        );
    }

    #[test]
    fn classify_metadata_mutation_ignores_non_catastrophic_operands() {
        assert_eq!(classify_metadata_mutation(Some("+x"), "chmod"), None);
        assert_eq!(classify_metadata_mutation(Some("staff"), "chgrp"), None);
        assert_eq!(
            classify_metadata_mutation(Some("fatmo:staff"), "chown"),
            None
        );
    }
}

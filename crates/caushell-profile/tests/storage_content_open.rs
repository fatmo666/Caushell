use caushell_profile::{EffectKind, EffectTarget, PathAccessKind, ProfileRegistry};

#[test]
fn reviewed_native_targets_are_content_opens_and_generic_frontends_stay_distinct() {
    let registry = ProfileRegistry::built_in().unwrap();
    for name in [
        "mke2fs",
        "mkfs.ext2",
        "mkfs.ext3",
        "mkfs.ext4",
        "wipefs",
        "sfdisk",
    ] {
        let profile = registry.lookup(name).profile.unwrap();
        for effect in profile.forms.iter().flat_map(|f| &f.effects) {
            if matches!(&effect.target, EffectTarget::Slot(slot) if matches!(slot.as_str(), "target"|"device_paths"))
                && matches!(effect.kind, EffectKind::ReadPath | EffectKind::WritePath)
            {
                assert_eq!(
                    effect.path_access,
                    Some(PathAccessKind::ContentOpen),
                    "{name}: {effect:?}"
                );
            }
        }
    }
    for name in ["mkfs", "mkfs.xfs", "mkfs.unreviewed"] {
        let profile = registry.lookup(name).profile.unwrap();
        assert_eq!(profile.primary_name(), "mkfs");
        assert!(
            profile
                .forms
                .iter()
                .flat_map(|f| &f.effects)
                .all(|e| e.path_access.is_none())
        );
    }
}

#[test]
fn automatic_and_generated_outputs_do_not_inherit_the_main_open_contract() {
    let registry = ProfileRegistry::built_in().unwrap();
    let mke2fs = registry.lookup("mkfs.ext4").profile.unwrap();
    for name in [
        "inspect_layout",
        "create_filesystem",
        "create_filesystem_with_external_check",
    ] {
        let form = mke2fs.forms.iter().find(|f| f.id.as_str() == name).unwrap();
        assert!(
            form.effects.iter().any(|e| e.kind == EffectKind::WritePath
                && matches!(e.target, EffectTarget::ConfiguredPath(_))
                && e.path_access.is_none()),
            "{name}"
        );
    }
    assert!(
        mke2fs
            .forms
            .iter()
            .find(|f| f.id.as_str() == "create_filesystem_with_external_check")
            .unwrap()
            .operation_semantics_unresolved
    );
    let sfdisk = registry.lookup("sfdisk").profile.unwrap();
    let backup = sfdisk
        .forms
        .iter()
        .find(|f| f.id.as_str() == "backup_partition_table")
        .unwrap();
    assert!(
        backup
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath
                && matches!(e.target, EffectTarget::ConfiguredPath(_))
                && e.path_access.is_none())
    );
    assert!(
        backup
            .effects
            .iter()
            .filter(|e| e.kind == EffectKind::WritePath)
            .all(|e| !matches!(e.target, EffectTarget::Slot(_)))
    );
    let wipefs = registry.lookup("wipefs").profile.unwrap();
    let backup = wipefs
        .modifiers
        .iter()
        .find(|m| m.id.as_str() == "backup")
        .unwrap();
    assert!(
        backup
            .effects
            .iter()
            .any(|e| e.kind == EffectKind::WritePath
                && matches!(e.target, EffectTarget::ConfiguredPath(_))
                && e.path_access.is_none())
    );
}

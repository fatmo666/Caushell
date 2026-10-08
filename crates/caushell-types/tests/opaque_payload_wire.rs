use caushell_types::{
    NestedPayloadLanguage, NestedPayloadLanguageEvidence, RuleAction, RulePolicy,
    UnresolvedExecutionPayloadSubtype,
};

#[test]
fn opaque_language_and_subtype_are_stable_serialized_values() {
    assert_eq!(
        serde_json::to_string(&NestedPayloadLanguage::Opaque).unwrap(),
        "\"opaque\""
    );
    assert_eq!(
        serde_json::from_str::<NestedPayloadLanguage>("\"opaque\"").unwrap(),
        NestedPayloadLanguage::Opaque
    );
    assert_eq!(
        serde_json::from_str::<NestedPayloadLanguageEvidence>("\"opaque\"").unwrap(),
        NestedPayloadLanguageEvidence::Opaque
    );
    assert_eq!(
        serde_json::from_str::<UnresolvedExecutionPayloadSubtype>("\"opaque_non_shell\"").unwrap(),
        UnresolvedExecutionPayloadSubtype::OpaqueNonShell
    );
    assert_eq!(
        NestedPayloadLanguage::from_storage("opaque").unwrap(),
        NestedPayloadLanguage::Opaque
    );
}

#[test]
fn opaque_policy_defaults_and_overrides_roundtrip_without_changing_old_literals() {
    let mut policy = RulePolicy::default();
    assert_eq!(
        policy.action_for_unresolved_execution_payload_subtype(
            UnresolvedExecutionPayloadSubtype::OpaqueNonShell
        ),
        RuleAction::NeedApproval
    );
    assert_eq!(
        policy.action_for_unresolved_execution_payload_subtype(
            UnresolvedExecutionPayloadSubtype::StaticInlineLiteral
        ),
        RuleAction::Observe
    );
    policy
        .resolve_gap
        .unresolved_execution_payload_subtypes
        .insert(
            UnresolvedExecutionPayloadSubtype::OpaqueNonShell,
            RuleAction::Deny,
        );
    let decoded: RulePolicy =
        serde_json::from_str(&serde_json::to_string(&policy).unwrap()).unwrap();
    assert_eq!(policy, decoded);
    assert_eq!(
        decoded.action_for_unresolved_execution_payload_subtype(
            UnresolvedExecutionPayloadSubtype::OpaqueNonShell
        ),
        RuleAction::Deny
    );
}

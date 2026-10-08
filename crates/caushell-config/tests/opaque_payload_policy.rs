use caushell_config::load_config_from_str;
use caushell_types::{RuleAction, UnresolvedExecutionPayloadSubtype};

#[test]
fn explicit_opaque_payload_policy_uses_the_existing_yaml_override_interface() {
    for (action, expected) in [
        ("allow", RuleAction::Observe),
        ("need_approval", RuleAction::NeedApproval),
        ("deny", RuleAction::Deny),
    ] {
        let c = load_config_from_str(&format!(
            "policy:\n  unresolved_payloads:\n    opaque_non_shell: {action}\n"
        ))
        .unwrap();
        assert_eq!(
            c.policy
                .rule_policy
                .action_for_unresolved_execution_payload_subtype(
                    UnresolvedExecutionPayloadSubtype::OpaqueNonShell
                ),
            expected
        );
        assert_eq!(
            c.policy
                .rule_policy
                .action_for_unresolved_execution_payload_subtype(
                    UnresolvedExecutionPayloadSubtype::StaticInlineLiteral
                ),
            RuleAction::Observe
        );
    }
}

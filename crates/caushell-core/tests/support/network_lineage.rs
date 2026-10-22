use caushell_types::{PolicyConfig, RuleAction, RuleId, RulePolicyEntry};

pub fn policy() -> PolicyConfig {
    let mut policy = PolicyConfig::default();
    for rule in [RuleId::NetworkUpload, RuleId::StateMutation] {
        policy
            .rule_policy
            .rules
            .insert(rule, RulePolicyEntry::new(RuleAction::Observe));
    }
    policy
}

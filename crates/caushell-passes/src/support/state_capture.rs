//! Transient output of the existing ordered replay. Graph facts remain the
//! source of history; this recorder is discarded after producing mutations.
use std::collections::{BTreeMap, BTreeSet};

use caushell_profile::{EnvironmentValueRef, SessionBindings, VariablePresence};
use caushell_types::{
    AnalysisBudgetKind, AnalysisBudgetPolicy, SafetyStateKind as K, SafetyStateValue as V,
};

#[derive(Debug, Clone)]
pub(crate) struct StateObservation {
    pub kind: K,
    pub name: String,
    pub value: V,
    pub source_end: usize,
}

pub(crate) struct StateCapture {
    pub observations: Vec<StateObservation>,
    pub incomplete: BTreeSet<AnalysisBudgetKind>,
    limits: AnalysisBudgetPolicy,
    // Distinct value and whether a write (rather than only entry state) owns it.
    retained: BTreeMap<(K, String), Vec<(V, bool)>>,
    bytes: usize,
    work: usize,
}

impl StateCapture {
    pub fn new(limits: AnalysisBudgetPolicy) -> Self {
        Self {
            observations: Vec::new(),
            incomplete: BTreeSet::new(),
            limits,
            retained: BTreeMap::new(),
            bytes: 0,
            work: 0,
        }
    }

    pub fn observe(&mut self, kind: K, name: &str, mut value: V, source_end: usize) {
        if self.work >= self.limits.max_history_nodes {
            self.incomplete.insert(AnalysisBudgetKind::Search);
            return;
        }
        self.work += 1;
        if name.len() > self.limits.max_state_value_bytes {
            self.incomplete.insert(AnalysisBudgetKind::StateValueBytes);
            return;
        }
        if name.len().saturating_add(value.retained_bytes()) > self.limits.max_state_value_bytes {
            self.incomplete.insert(AnalysisBudgetKind::StateValueBytes);
            value = V::Unknown;
        }
        let key = (kind, name.to_owned());
        let prior = self
            .retained
            .get(&key)
            .and_then(|values| values.iter().position(|(candidate, _)| candidate == &value));
        let repeated = prior.is_some();
        if prior.is_some_and(|index| source_end == 0 || self.retained[&key][index].1) {
            return;
        }
        if !self.retained.contains_key(&key) && self.retained.len() >= self.limits.max_state_objects
        {
            self.incomplete.insert(AnalysisBudgetKind::StateObjects);
            return;
        }
        if !repeated
            && self.retained.get(&key).map_or(0, Vec::len) >= self.limits.max_candidates_per_object
        {
            self.incomplete.insert(AnalysisBudgetKind::StateCandidates);
            return;
        }
        let bytes = name.len().saturating_add(value.retained_bytes());
        if self.bytes.saturating_add(bytes) >= self.limits.max_state_history_bytes {
            self.incomplete
                .insert(AnalysisBudgetKind::StateHistoryBytes);
            return;
        }
        if self.observations.len() >= self.limits.max_history_nodes {
            self.incomplete.insert(AnalysisBudgetKind::HistoryNodes);
            return;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        let values = self.retained.entry(key).or_default();
        if let Some(index) = prior {
            values[index].1 |= source_end > 0;
        } else {
            values.push((value.clone(), source_end > 0));
        }
        self.observations.push(StateObservation {
            kind,
            name: name.to_owned(),
            value,
            source_end,
        });
    }

    pub fn variable(
        &mut self,
        entry: &SessionBindings,
        bindings: &SessionBindings,
        name: &str,
        end: usize,
    ) {
        // Keep a known entry value before its first replacement. Unknown
        // pre-session bytes are not invented as a concrete candidate.
        if !self.retained.contains_key(&(K::Variable, name.to_owned())) {
            if let Some(value) = variable_value(entry, name) {
                self.observe(K::Variable, name, value, 0);
            }
        }
        self.observe(
            K::Variable,
            name,
            variable_value(bindings, name).unwrap_or(V::Unknown),
            end,
        );
    }

    pub fn function(
        &mut self,
        entry: &SessionBindings,
        bindings: &SessionBindings,
        name: &str,
        end: usize,
    ) {
        if !self.retained.contains_key(&(K::Function, name.to_owned())) {
            if let Some(binding) = entry.retained_function_binding(name) {
                self.observe(
                    K::Function,
                    name,
                    V::Definition {
                        body: binding.body.clone(),
                        uncertainty: binding.uncertainty.clone(),
                    },
                    0,
                );
            }
        }
        let value = if bindings.shell_state_uncertainty().is_some() {
            V::Unknown
        } else {
            bindings
                .retained_function_binding(name)
                .map_or(V::Absent, |binding| V::Definition {
                    body: binding.body.clone(),
                    uncertainty: binding.uncertainty.clone(),
                })
        };
        self.observe(K::Function, name, value, end);
    }

    pub fn merge(&mut self, observations: impl IntoIterator<Item = StateObservation>) {
        for observation in observations {
            self.observe(
                observation.kind,
                &observation.name,
                observation.value,
                observation.source_end,
            );
        }
    }

    pub fn positionals(&mut self, entry: &SessionBindings, bindings: &SessionBindings, end: usize) {
        if !self.retained.contains_key(&(K::Positionals, "@".into()))
            && entry.positional_parameters_are_complete()
        {
            self.observe(
                K::Positionals,
                "@",
                V::Positionals(
                    entry
                        .positional_parameters()
                        .iter()
                        .map(caushell_profile::SessionValue::to_session_variable_value)
                        .collect(),
                ),
                0,
            );
        }
        let value = if bindings.positional_parameters_are_complete() {
            V::Positionals(
                bindings
                    .positional_parameters()
                    .iter()
                    .map(caushell_profile::SessionValue::to_session_variable_value)
                    .collect(),
            )
        } else {
            V::Unknown
        };
        self.observe(K::Positionals, "@", value, end);
    }
}

fn variable_value(bindings: &SessionBindings, name: &str) -> Option<V> {
    if bindings.runtime_variable_target_is_unresolved(name) {
        return Some(V::Unknown);
    }
    bindings
        .get(name)
        .map(|binding| V::Variable {
            value: binding.value.to_session_variable_value(),
            exported: matches!(
                bindings.environment_value(name),
                EnvironmentValueRef::Present(_)
            ),
        })
        .or_else(|| {
            (bindings.variable_presence(name) == VariablePresence::Absent).then_some(V::Absent)
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn incomplete_function_state_is_unknown_not_absent() {
        let mut bindings = caushell_profile::SessionBindings::new();
        bindings.upsert_function_binding(caushell_types::SessionFunctionBinding::new(
            "f",
            "printf SAFE;",
            caushell_types::CommandSequenceNo::new(1),
        ));
        let entry = bindings.clone();
        bindings.mark_shell_state_uncertain("incomplete source");
        let mut capture = super::StateCapture::new(caushell_types::AnalysisBudgetPolicy::default());
        capture.function(&entry, &bindings, "f", 10);
        assert!(matches!(
            capture.observations.last().unwrap().value,
            caushell_types::SafetyStateValue::Unknown
        ));
        assert!(
            !capture
                .observations
                .iter()
                .any(|observation| observation.value == caushell_types::SafetyStateValue::Absent)
        );
    }

    use super::*;

    fn value(text: &str) -> V {
        V::Variable {
            value: caushell_types::SessionVariableValue::exact_scalar(text),
            exported: false,
        }
    }

    #[test]
    fn repeated_values_are_not_copied_again_or_used_to_evict_the_first_value() {
        let mut capture = StateCapture::new(AnalysisBudgetPolicy::default());
        for n in 1..=200 {
            capture.observe(
                K::Variable,
                "DEST",
                value(if n % 2 == 1 { "/outside" } else { "safe" }),
                n,
            );
        }
        assert_eq!(capture.observations.len(), 2);
        assert_eq!(capture.observations[0].value, value("/outside"));
        assert_eq!(capture.observations[0].source_end, 1);
        assert!(capture.incomplete.is_empty());
    }

    #[test]
    fn entry_and_first_write_have_separate_witnesses_but_one_distinct_value() {
        let mut capture = StateCapture::new(AnalysisBudgetPolicy::default());
        capture.observe(K::Variable, "DEST", value("/outside"), 0);
        for end in 1..200 {
            capture.observe(K::Variable, "DEST", value("/outside"), end);
        }
        assert_eq!(capture.observations.len(), 2);
        assert_eq!(capture.observations[0].source_end, 0);
        assert_eq!(capture.observations[1].source_end, 1);
        assert_eq!(capture.retained[&(K::Variable, "DEST".into())].len(), 1);
        assert!(capture.incomplete.is_empty());
    }

    #[test]
    fn total_payload_budget_stops_retention_without_erasing_the_first_value() {
        let mut limits = AnalysisBudgetPolicy::default();
        limits.max_state_history_bytes = 100;
        let mut capture = StateCapture::new(limits);
        capture.observe(K::Variable, "DEST", value("/outside"), 0);
        capture.observe(K::Variable, "DEST", value("safe"), 1);
        assert!(
            capture
                .incomplete
                .contains(&AnalysisBudgetKind::StateHistoryBytes)
        );
        assert_eq!(capture.observations.len(), 1);
        assert_eq!(capture.observations[0].value, value("/outside"));
    }

    #[test]
    fn zero_candidate_capacity_and_oversized_values_remain_incomplete() {
        let mut limits = AnalysisBudgetPolicy::default();
        limits.max_candidates_per_object = 0;
        let mut capture = StateCapture::new(limits);
        capture.observe(K::Variable, "DEST", value("/outside"), 0);
        assert!(capture.observations.is_empty());
        assert!(
            capture
                .incomplete
                .contains(&AnalysisBudgetKind::StateCandidates)
        );
        let mut limits = AnalysisBudgetPolicy::default();
        limits.max_state_value_bytes = 16;
        let mut capture = StateCapture::new(limits);
        capture.observe(K::Variable, "DEST", value("/outside"), 0);
        assert!(
            capture
                .incomplete
                .contains(&AnalysisBudgetKind::StateValueBytes)
        );
        assert_eq!(capture.observations[0].value, V::Unknown);
    }
}

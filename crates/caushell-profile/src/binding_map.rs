use std::collections::BTreeMap;
use std::sync::Arc;

/// An immutable entry frame and request-local writes. Cloning a replay frame
/// copies its writes, not every binding accumulated by earlier requests.
#[derive(Debug, Clone)]
pub(crate) struct BindingMap<V> {
    base: Arc<BTreeMap<String, V>>,
    writes: BTreeMap<String, Option<V>>,
}

impl<V> Default for BindingMap<V> {
    fn default() -> Self {
        Self {
            base: Arc::default(),
            writes: BTreeMap::new(),
        }
    }
}

impl<V: PartialEq> PartialEq for BindingMap<V> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl<V: Eq> Eq for BindingMap<V> {}

impl<V> BindingMap<V> {
    pub fn get(&self, name: &str) -> Option<&V> {
        match self.writes.get(name) {
            Some(value) => value.as_ref(),
            None => self.base.get(name),
        }
    }

    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn overrides(&self, name: &str) -> bool {
        self.writes.contains_key(name) || self.base.contains_key(name)
    }

    pub fn insert(&mut self, name: String, value: V) {
        self.writes.insert(name, Some(value));
    }

    pub fn remove(&mut self, name: &str) {
        self.writes.insert(name.into(), None);
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        let mut base = self.base.iter().peekable();
        let mut writes = self.writes.iter().peekable();
        std::iter::from_fn(move || {
            loop {
                match (base.peek(), writes.peek()) {
                    (Some((left, _)), Some((right, _))) if left < right => return base.next(),
                    (Some((left, _)), Some((right, _))) if left == right => {
                        base.next();
                    }
                    (Some(_), None) => return base.next(),
                    (None, None) => return None,
                    _ => {}
                }
                if let Some((key, Some(value))) = writes.next() {
                    return Some((key, value));
                }
            }
        })
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.iter().map(|(key, _)| key)
    }
}

impl<V: Clone> BindingMap<V> {
    pub fn freeze(&mut self) {
        let removed = self
            .writes
            .iter()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| (key.clone(), None))
            .collect();
        if self.base.is_empty() {
            self.base = Arc::new(
                std::mem::take(&mut self.writes)
                    .into_iter()
                    .filter_map(|(key, value)| value.map(|value| (key, value)))
                    .collect(),
            );
        } else if !self.writes.is_empty() {
            self.base = Arc::new(
                self.iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            );
        }
        self.writes = removed;
    }
}

impl<V> FromIterator<(String, V)> for BindingMap<V> {
    fn from_iter<T: IntoIterator<Item = (String, V)>>(values: T) -> Self {
        Self {
            base: Arc::new(values.into_iter().collect()),
            writes: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_writes_are_isolated_ordered_and_preserve_absence() {
        let base: BindingMap<_> = [("a".into(), 1), ("c".into(), 3)].into_iter().collect();
        let mut fork = base.clone();
        assert!(Arc::ptr_eq(&base.base, &fork.base));
        fork.insert("a".into(), 2);
        fork.insert("b".into(), 4);
        fork.remove("c");
        fork.remove("missing");
        assert_eq!(
            fork.iter()
                .map(|(k, v)| (k.as_str(), *v))
                .collect::<Vec<_>>(),
            vec![("a", 2), ("b", 4)]
        );
        assert_eq!(base.get("a"), Some(&1));
        assert_eq!(base.get("c"), Some(&3));
        let prior = fork.clone();
        fork.freeze();
        assert_eq!(fork, prior);
        assert!(fork.writes.values().all(Option::is_none));
        assert!(fork.overrides("c") && fork.overrides("missing"));
        fork.remove("a");
        assert_eq!(
            fork.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["b"]
        );
        fork.clear();
        assert_eq!(fork, BindingMap::default());
        assert_eq!(prior.get("a"), Some(&2));
    }

    #[test]
    fn ordered_overlay_matches_a_flat_map_across_mutations() {
        let mut flat: BTreeMap<_, _> = (0..200).map(|i| (format!("key{i:03}"), i)).collect();
        let mut overlay: BindingMap<_> = flat.clone().into_iter().collect();
        for i in 0..500 {
            let key = format!("key{:03}", (i * 17) % 251);
            if i % 3 == 0 {
                flat.remove(&key);
                overlay.remove(&key);
            } else {
                flat.insert(key.clone(), i);
                overlay.insert(key, i);
            }
            assert!(overlay.iter().eq(flat.iter()));
            if i % 71 == 0 {
                overlay.freeze();
            }
        }
    }
}

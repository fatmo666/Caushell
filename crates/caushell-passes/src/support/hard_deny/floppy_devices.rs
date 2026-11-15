//! Conventional raw-storage names, never a probe of actual devices. A decimal
//! unit is a name component, not a claim that a controller or node is present.
use crate::path::shell_pattern_witness;
use std::{collections::BTreeMap, sync::LazyLock};

// Linux v6.12 Documentation/admin-guide/devices.txt, block major 2.
const LINUX_FORMATS: &[&str] = &[
    "d360", "h360", "h410", "h420", "h720", "h880", "h1200", "h1440", "h1476", "h1494", "h1600",
    "u360", "u720", "u800", "u820", "u830", "u1040", "u1120", "u1440", "u1600", "u1680", "u1722",
    "u1743", "u1760", "u1840", "u1920", "u2880", "u3200", "u3520", "u3840", "CompaQ",
];

#[derive(Default)]
struct SuffixNode {
    next: BTreeMap<u8, usize>,
    terminal: bool,
}
struct DeviceFamily {
    prefix: &'static str,
    suffixes: Vec<SuffixNode>,
}

impl DeviceFamily {
    fn new(prefix: &'static str, linux_formats: bool) -> Self {
        let mut family = Self {
            prefix,
            suffixes: vec![SuffixNode::default()],
        };
        family.insert("");
        // NetBSD raw/block views and OpenBSD fdc(4) partition/geometry names.
        for partition in b'a'..=b'p' {
            family.insert(&(partition as char).to_string());
            for geometry in b'B'..=b'H' {
                family.insert(&format!("{}{}", geometry as char, partition as char));
            }
        }
        if linux_formats {
            for suffix in LINUX_FORMATS {
                family.insert(suffix);
            }
        }
        family
    }
    fn insert(&mut self, text: &str) {
        let mut node = 0;
        for byte in text.bytes() {
            node = match self.suffixes[node].next.get(&byte) {
                Some(next) => *next,
                None => {
                    let next = self.suffixes.len();
                    self.suffixes.push(SuffixNode::default());
                    self.suffixes[node].next.insert(byte, next);
                    next
                }
            };
        }
        self.suffixes[node].terminal = true;
    }
    fn step(&self, state: usize, byte: u8) -> Option<usize> {
        let size = self.prefix.len();
        if state < size {
            return (self.prefix.as_bytes()[state] == byte).then_some(state + 1);
        }
        if state == size {
            return match byte {
                b'0' => Some(size + 1),
                b'1'..=b'9' => Some(size + 2),
                _ => None,
            };
        }
        if state == size + 1 || state == size + 2 {
            if state == size + 2 && byte.is_ascii_digit() {
                return Some(state);
            }
            return self.suffixes[0].next.get(&byte).map(|next| size + 3 + next);
        }
        self.suffixes
            .get(state - size - 3)?
            .next
            .get(&byte)
            .map(|next| size + 3 + next)
    }
    fn accepting(&self, state: usize) -> bool {
        let size = self.prefix.len();
        if state == size + 1 || state == size + 2 {
            return self.suffixes[0].terminal;
        }
        state
            .checked_sub(size + 3)
            .and_then(|node| self.suffixes.get(node))
            .is_some_and(|node| node.terminal)
    }
    fn matches(&self, path: &str) -> bool {
        path.bytes()
            .try_fold(0, |state, byte| self.step(state, byte))
            .is_some_and(|state| self.accepting(state))
    }
}

static FAMILIES: LazyLock<[DeviceFamily; 2]> = LazyLock::new(|| {
    [
        DeviceFamily::new("/dev/fd", true),
        DeviceFamily::new("/dev/rfd", false),
    ]
});

pub(super) fn is_floppy_device_path(path: &str) -> bool {
    FAMILIES.iter().any(|family| family.matches(path))
}

pub(super) fn floppy_device_pattern_witness(pattern: &str) -> Option<String> {
    let mut budget = 32_768;
    FAMILIES.iter().find_map(|family| {
        shell_pattern_witness(
            pattern,
            0,
            |state, byte| family.step(state, byte),
            |state| family.accepting(state),
            &mut budget,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::shell_pattern_matches_path;

    #[test]
    fn pattern_witnesses_are_complete_members_not_sampled_device_ids() {
        for pattern in [
            "/dev/fd[4-7]",
            "/dev/fd1234567",
            "/dev/rfd[5-9]a",
            "/dev/fd?Cp",
            "/dev/fd[2-6]u14[0-9]0",
            "/d?v/[r]fd2*",
            "/dev/fd[!0-3]",
        ] {
            let witness = floppy_device_pattern_witness(pattern).unwrap();
            assert!(is_floppy_device_path(&witness), "{pattern}: {witness}");
            assert!(
                shell_pattern_matches_path(pattern, &witness),
                "{pattern}: {witness}"
            );
        }
    }

    #[test]
    fn unsupported_or_exhausted_pattern_proofs_do_not_invent_a_device() {
        let family = &FAMILIES[0];
        let mut budget = 1;
        assert!(
            shell_pattern_witness(
                "/dev/fd*",
                0,
                |s, b| family.step(s, b),
                |s| family.accepting(s),
                &mut budget
            )
            .is_none()
        );
        assert!(floppy_device_pattern_witness(&format!("/dev/fd{}", "?".repeat(4096))).is_none());
        for pattern in [
            "/dev/fd/*",
            "/dev/fd0.img*",
            "/dev/rfd0.backup*",
            "/dev/fd00*",
            "/dev/fd0u999?",
        ] {
            assert!(
                floppy_device_pattern_witness(pattern).is_none(),
                "{pattern}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn generated_witnesses_match_native_bash_pathname_expansion() {
        // Only regular files in an owned temporary fixture are created. The
        // device-looking names are arguments to compgen, never commands to run.
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "caushell-device-glob-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("dev")).unwrap();
        for pattern in [
            "/dev/fd[4-7]",
            "/dev/fd1234567",
            "/dev/rfd[5-9]a",
            "/dev/fd?Cp",
            "/dev/fd[2-6]u14[0-9]0",
            "/d?v/[r]fd2*",
            "/dev/fd[!0-3]",
            "/dev/fd[^0-3]",
            "/dev/fd[0246]",
            "/dev/fd*CompaQ",
            "/dev/fd?B[a-p]",
            "/dev/*fd?",
        ] {
            let witness = floppy_device_pattern_witness(pattern).unwrap();
            let fixture = root.join(witness.strip_prefix('/').unwrap());
            std::fs::write(&fixture, b"ordinary fixture file\n").unwrap();
            let output = std::process::Command::new("/bin/bash")
                .args([
                    "--noprofile",
                    "--norc",
                    "-c",
                    "compgen -G \"$1\"",
                    "fixture",
                ])
                .arg(format!("{}{pattern}", root.display()))
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            assert!(output.status.success(), "{pattern}: {witness}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .lines()
                    .any(|path| path == fixture.to_str().unwrap()),
                "{pattern}: {witness}"
            );
            std::fs::remove_file(fixture).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

use caushell_types::*;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Stdio},
};

/// A paused executor fixture: the candidate command is never sent to Bash.
pub struct OwnedBashFrame {
    child: Child,
    values: BTreeMap<String, ShellEnvironmentValue>,
    options: ShellPathnameSnapshot,
}

impl OwnedBashFrame {
    pub fn start(cwd: &Path, requirements: &ExecutionFrameRequirements) -> Self {
        let script = r#"
emit_value() {
    local declaration
    declaration=$(builtin declare -p "$1" 2>/dev/null) || {
        builtin printf 'absent\0\0'; return
    }
    if [[ $2 == environment && ! $declaration =~ ^declare\ -[^\ ]*x[^\ ]*\  ]]; then
        builtin printf 'absent\0\0'
    elif [[ $declaration =~ ^declare\ -[^\ ]*[aAn][^\ ]*\  ]]; then
        builtin printf 'unknown\0\0'
    else
        builtin printf 'present\0%s\0' "${!1}"
    fi
}
if [[ $- == *f* ]]; then builtin printf '1\0'; else builtin printf '0\0'; fi
for option in nullglob failglob dotglob nocaseglob globstar extglob globskipdots; do
    if builtin shopt -q "$option"; then builtin printf '1\0'; else builtin printf '0\0'; fi
done
for name in GLOBIGNORE LC_ALL LC_COLLATE LC_CTYPE LANG; do emit_value "$name" shell; done
for name; do builtin printf '%s\0' "$name"; emit_value "$name" environment; done
builtin printf 'END\0\n'
if IFS= builtin read -r unused; then builtin eval -- "$unused"; fi
"#;
        let mut child = Command::new("/bin/bash")
            .args(["--noprofile", "--norc", "-c", script, "frame-observer"])
            .args(&requirements.environment_names)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut raw = Vec::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_until(b'\n', &mut raw)
            .unwrap();
        assert_eq!(raw.pop(), Some(b'\n'));
        let fields = raw
            .split(|b| *b == 0)
            .map(|p| std::str::from_utf8(p).unwrap().to_owned())
            .collect::<Vec<_>>();
        let mut fields = fields.into_iter();
        let flags = (0..8)
            .map(|_| fields.next().unwrap() == "1")
            .collect::<Vec<_>>();
        let value = |fields: &mut std::vec::IntoIter<String>| {
            let kind = fields.next().unwrap();
            let value = fields.next().unwrap();
            match kind.as_str() {
                "present" => ShellEnvironmentValue::Present { value },
                "absent" => ShellEnvironmentValue::Absent,
                "unknown" => ShellEnvironmentValue::Unknown,
                _ => panic!("invalid observation tag"),
            }
        };
        let options = ShellPathnameSnapshot {
            noglob: flags[0],
            nullglob: flags[1],
            failglob: flags[2],
            dotglob: flags[3],
            nocaseglob: flags[4],
            globstar: flags[5],
            extglob: flags[6],
            globskipdots: flags[7],
            globignore: value(&mut fields),
            lc_all: value(&mut fields),
            lc_collate: value(&mut fields),
            lc_ctype: value(&mut fields),
            lang: value(&mut fields),
        };
        let mut values = BTreeMap::new();
        loop {
            let name = fields.next().unwrap();
            if name == "END" {
                break;
            }
            values.insert(name, value(&mut fields));
        }
        Self {
            child,
            values,
            options,
        }
    }
    pub fn instance_id(&self) -> String {
        format!("owned-bash-{}", self.child.id())
    }
    #[allow(dead_code)]
    pub fn execute(&mut self, command: &str) -> std::process::ExitStatus {
        assert!(!command.contains('\n'));
        let mut input = self.child.stdin.take().unwrap();
        writeln!(input, "{command}").unwrap();
        drop(input);
        self.child.wait().unwrap()
    }
}
impl ExecutionFrameObserver for OwnedBashFrame {
    fn environment(&self, name: &str) -> ShellEnvironmentValue {
        self.values
            .get(name)
            .cloned()
            .unwrap_or(ShellEnvironmentValue::Unknown)
    }
    fn pathname(&self) -> Option<ShellPathnameSnapshot> {
        Some(self.options.clone())
    }
}
impl Drop for OwnedBashFrame {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        assert!(self.child.wait().unwrap().success());
    }
}

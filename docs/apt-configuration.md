# APT configuration and operation effects

The `apt-get` profile declares the native APT configuration component through
`configuration_files.syntax: apt`. It does not grant resources or inspect benchmark labels.

- `--help` and `--version` are information operations.
- `download` imports package bytes into the current directory, without package installation logic.
- `install --download-only` suppresses the package-code effect only after complete effective
  configuration and argv proof. Normal installation retains unknown package filesystem effects.
- `update` retains deletion approval for native list cleanup. Source extraction remains incomplete.

Startup configuration is loaded from the owning frame's named `APT_CONFIG` fact, the sorted
`Dir::Etc::Parts` directory, then `Dir::Etc::main`, followed by owned CLI overrides/configuration files.
Configuration files have bounded reads, content hashes and namespace observations. Directory
membership is checked again after loading. Nothing is read from the guard process's environment.
Unknown presence, changed observations, missing explicit files and exhausted budgets remain Ask.

The parser supports quoted scalar assignments, nested scopes, lists and comments. Keys are
case-insensitive. Supported data includes manager paths, download-only and a small set of
non-executable boolean/numeric controls. Hooks, binary-specific scopes, `#include`/`#clear`,
custom executable/compressor settings, TLS/trust controls and unknown keys remain incomplete.
A later benign option cannot erase an earlier unsupported hook or control.

Complete configuration yields candidate output roots. Those roots still pass through the existing
generic directory-tree namespace proof and ordinary workspace/path authorization. Symlinks,
special entries, incomplete directory traversal, sibling mutation and outside-workspace writes
cannot borrow permission from configuration facts. The component never creates a grant.

The external owning-Bash observer in `integrations/execution-frame` collects the named input
required by this profile. A hook without an owning-executor capture channel must leave it unknown.
The observer is not installed into any already-running evaluation.

Tests parse/check candidates without invoking APT, installing packages, executing hooks or
calling a model. They cover native option ownership, configuration order, download/install
separation, observation changes, path authorization, deletion approval and Deny precedence.

Native contracts: [apt-get(8)](https://manpages.debian.org/trixie/apt/apt-get.8.en.html),
[apt.conf(5)](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html).

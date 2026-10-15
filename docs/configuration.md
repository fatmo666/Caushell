# Caushell Configuration

This document describes Caushell's configuration file location, configuration management commands, and currently supported user configuration fields.

## Configuration file location

Caushell looks for the configuration file in this order:

1. `$CAUSHELL_CONFIG_PATH`
2. `$XDG_CONFIG_HOME/caushell/config.yaml`
3. `~/.config/caushell/config.yaml`

If `$CAUSHELL_CONFIG_PATH` is set, it must be an absolute path.

Show the current configuration file path:

```bash
caushell config path
```

## Initialize, show, and validate

Initialize a new configuration file:

```bash
caushell config init
```

This creates the default configuration file in the configuration directory. If the file already exists, the command returns an error and does not overwrite it.

Show the current configuration file content:

```bash
caushell config show
```

This command outputs JSON containing:

- the resolved configuration path
- whether the configuration file exists
- the original configuration content from the file

Validate whether the configuration is usable:

```bash
caushell config validate
```

If the configuration file does not exist, `validate` still succeeds because Caushell uses built-in defaults.

## Current configuration fields

### Mutation path exemptions

`mutation_path_exemptions` exempts selected operations from the existing
outside-workspace mutation rule. Defaults:

```yaml
mutation_path_exemptions:
  - root: /tmp
    operations: [write, permission_metadata]
  - root: /private/tmp
    operations: [write, permission_metadata]
```

`write` covers declared file/directory writes and shell output redirections.
`permission_metadata` covers modeled mode, owner and group changes, including
setuid/setgid and reference-derived modes. It does not suppress unresolved
argument/control checks or exempt generic attributes such as immutable.
The narrower `ordinary_metadata` remains available with its original behavior:
it excludes special/reference/unknown permission modes. Delete and move-source
operations cannot be granted here. Other risk rules keep their configured behavior;
these roots do not become trusted script/startup locations or workspace roots.

Entries require absolute roots and a nonempty operation list. Paths are checked
with normalized directory boundaries, not substring matching. Unknown targets,
unknown relative cwd, and escaping/empty path bounds are not exempt. No filesystem
or process lookup is added. The existing path facts remain unchanged.

An explicit list replaces the defaults; `mutation_path_exemptions: []` disables
all exemptions. For example, to permit only writes in a custom scratch directory:

```yaml
mutation_path_exemptions:
  - root: /opt/scratch
    operations: [write]
```

Without a supplied `TMPDIR`, a default-template `mktemp` invocation retains an
unknown creation location and requires approval. An explicit `/tmp` template
or a supplied, known `TMPDIR` is checked against these roots normally.

| Field | Values | Default | Purpose |
| --- | --- | --- | --- |
| `failure_action` | `allow` / `need_approval` / `deny` | `need_approval` | Fallback behavior when Caushell cannot complete analysis |
| `codex.need_approval_mode` | `block` / `observe` | `block` | How Codex handles `NeedApproval` decisions |
| `policy.rules.process_control` | `allow` / `need_approval` / `deny` | `need_approval` | Signals or resumes a process/job through a declared control effect |
| `policy.rules.privilege_boundary` | `allow` / `need_approval` / `deny` | `need_approval` | Declared execution-identity or privilege changes |
| `policy.rules.network_upload` | `allow` / `need_approval` / `deny` | `need_approval` | Declared outbound data transfers not statically confined to loopback |
| `policy.rules.file_deletion` | `allow` / `need_approval` / `deny` | `need_approval` | Declared filesystem deletion, irrespective of workspace or temporary-path location |

The upload guard consumes existing `upload_target` endpoint declarations,
including nested and partial calls. It does not require a sensitive source.
Ordinary fetch/query endpoints and dry-run forms are not reclassified as
uploads. An explicit request-byte scope that carries local file content also
requires approval, even for a GET query or request header. Literal query fields
and authentication/TLS files not sent as request bytes remain distinct. This
lineage query uses the existing node/hop budgets; incomplete budget-limited
analysis requires approval.
Only an explicit loopback IP or `localhost` destination is exempt; unresolved
destinations require approval. Recipient email domains do not establish local
SMTP transport. `allow` disables only this rule's proposal, not sensitive-data,
filesystem or hard-deny rules. No DNS lookup or connection probe is performed.
An explicit nonlocal/unresolved `transport_target` (proxy or address override)
prevents a loopback URL from certifying local transmission. Ordinary proxied
queries remain queries. Unresolved native routing specifications do not gain
a local-route exemption merely because the logical URL says `localhost`.

Filesystem deletion uses the existing `delete_path` effects, including nested
calls and tools that remove their input files. Moves/renames declared as
`move_path` are not deletion; their existing source/destination path rules remain
independent. Explicitly empty payload-projection deletion slots do not trigger
the rule. Unknown deletion targets still require approval. `allow` disables this
rule's proposal, not outside-workspace or hard-deny rules; catastrophic deletion
retains its existing hard-deny floor. No filesystem inspection is performed.

The privilege-boundary guard consumes existing `privilege_modifier` effects on
current graph-backed invocations, including nested calls. It requires approval
independently of whether the child is read-only or targets the workspace. User,
group and security-context changes are covered when declared by a Profile;
query forms such as `sudo -l` have no such effect. With no candidate effect the
Pass returns before graph queries. No identity lookup or new Harness input is
needed. `allow` preserves findings but disables only this rule's proposal;
other rules and hard-deny floors remain independent. The rule belongs to the
existing `host_safety` family, with per-rule overrides taking precedence.

The process-control guard reads resolved `control_process` effects, including
nested invocations, without looking up live processes or requiring known action
metadata. `allow` preserves findings but removes this rule's approval; it does
not override other rules. Zero-signal probes and signal-list forms have no
control effect. The built-in control profiles mark unsupported forms opaque,
so the existing resolve policy requests approval; allowing `process_control`
does not turn an unparsed operation into a known safe one. No critical-PID
lookup or special protection is claimed.

```yaml
policy:
  rules:
    process_control: allow
```

### Declared opaque executable input

Profiles opting into `language: opaque` with `recursive: true` use the existing unresolved-payload policy. `opaque_non_shell` defaults to `need_approval`, including literal AWK/HCL input; it does not alter other unsupported-language literal defaults. Override it explicitly when needed:

```yaml
policy:
  unresolved_payloads:
    opaque_non_shell: need_approval  # allow / need_approval / deny
```

`allow` retains the analysis evidence and cannot bypass independent mutation or hard-deny rules. No live process lookup, code execution or new Harness field is required.

### `failure_action`

This field defines how Caushell handles a shell action when analysis cannot be completed.

- `allow`: allow the action when analysis fails
- `need_approval`: require confirmation when analysis fails
- `deny`: block the action when analysis fails

Show the current value:

```bash
caushell config get failure_action
```

Change it:

```bash
caushell config set failure_action need_approval
```

### `codex.need_approval_mode`

This field only affects the Codex integration.

Codex hooks currently cannot request user confirmation directly. They can only return allow or reject, so Caushell maps `NeedApproval` to one of two modes:

- `block`: block execution when the decision is `NeedApproval`
- `observe`: allow Codex to continue while preserving Caushell's decision and reason record

Show the current value:

```bash
caushell config get codex.need_approval_mode
```

Change it:

```bash
caushell config set codex.need_approval_mode observe
```

`Deny` decisions are always blocked and are not affected by this setting.

## Expansion depth

`analysis.max_nested_parse_depth` defaults to 8. The top-level command is depth 0, and nested dispatch or shell payload execution increments the depth. A command with no further child at the limit is judged normally; pending child execution beyond the limit requires approval by default (`policy.rules.execution_expansion_limit`). This is not the adapter's `failure_action`, and it does not change the handling of unsupported non-Bash literals.

Existing explicit depth values remain effective; configuration validation still requires at least 3 for the hard-deny analysis floor. Raising the default does not rewrite existing configuration files.

```yaml
analysis:
  max_nested_parse_depth: 8
```

## Minimal example

This is a minimal configuration:

```yaml
version: 1
failure_action: need_approval
codex:
  need_approval_mode: block
```

The default configuration uses `need_approval` and `block`.

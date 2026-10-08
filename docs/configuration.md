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

| Field | Values | Default | Purpose |
| --- | --- | --- | --- |
| `failure_action` | `allow` / `need_approval` / `deny` | `need_approval` | Fallback behavior when Caushell cannot complete analysis |
| `codex.need_approval_mode` | `block` / `observe` | `block` | How Codex handles `NeedApproval` decisions |
| `policy.rules.process_control` | `allow` / `need_approval` / `deny` | `need_approval` | Signals or resumes a process/job through a declared control effect |

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

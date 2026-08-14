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

## Minimal example

This is a minimal configuration:

```yaml
version: 1
failure_action: need_approval
codex:
  need_approval_mode: block
```

The default configuration uses `need_approval` and `block`.


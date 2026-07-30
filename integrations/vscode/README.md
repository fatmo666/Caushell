# Caushell VS Code Extension

## Features

- Provides a native VS Code TreeView sidebar for Caushell sessions.
- Shows a best-effort process summary for Codex, Claude, and Caushell runtime processes.
- Groups loaded sessions into running sessions backed by active-session heartbeats, historical sessions, and collapsed other-workspace history.
- Prioritizes sessions that match the current VS Code workspace.
- Shows runtime labels such as `Claude` and `Codex`, latest decisions, and check counts on session rows.
- Opens a session detail tab with summary metrics, a command stream, and an active command inspection pane.
- Shows command details in the same session tab; selecting a command updates the right-hand inspection pane.
- Renders findings, evidence, decision proposals, execution units, flows, nested payloads, and execution semantics as readable audit records.
- Uses `caushell query-stdio --store <storeRoot>` internally; no extra server is required.

## Settings

- `caushell.storeRoot`: optional single-store override for debugging. If unset, the extension reads the canonical Caushell Claude and Codex stores.
- `caushell.cliPath`: path or executable name for `caushell`. If omitted, the extension checks the same runtime env vars used by Caushell hooks, then `PATH`, then repo-local `target/debug`.

## Development

Open this folder in VS Code and run the extension host.

The extension is plain JavaScript and intentionally has no build step.

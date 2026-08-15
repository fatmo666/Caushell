# Caushell for DeepSeek Harness

This integration guards the ordinary DSH `bash` tool at `tools/pre-execute`.
It sends each command to a long-lived `caushell-adapter-dsh` process, which
keeps one Caushell runtime and session store for the DSH process.

The first version intentionally supports only the default non-persistent Bash
composition:

- `@deepseek-ai/dsh-bash-local`
- `@deepseek-ai/dsh-tool-bash`

Do not compose it with `@deepseek-ai/dsh-tool-bash-persistent`. Persistent Bash
uses the same tool name but has a different shell-state contract that is not
exposed at `tools/pre-execute`. The plugin checks the ordinary Bash invocation
contract and denies a `bash` call when that contract is absent; it never falls
back to analyzing Persistent Bash as a fresh shell.

## Install from a source checkout

Build the adapter from the Caushell repository:

```bash
cargo build -p caushell-adapter-dsh
```

The integration package can be installed into a DSH profile from the checkout.
Because the package declares a DSH bundle patch, installation also adds the
plugin to the profile composition:

```bash
dsh plugin --profile <profile> add /absolute/path/to/Caushell/integrations/deepseek-harness
```

Unless the debug adapter is already on `PATH`, configure the source checkout
with its absolute path:

```yaml
- id: caushell-dsh-bash
  config:
    adapterPath: /absolute/path/to/Caushell/target/debug/caushell-adapter-dsh
```

For a released Caushell runtime, install the matching package asset directly:

```bash
dsh plugin --profile <profile> add https://github.com/fatmo666/Caushell/releases/latest/download/caushell-dsh-bash.tgz
```

The profile must already provide ordinary DSH Bash. To configure the installed
plugin, add an id-targeted entry to the profile's `cordis.patch.yml`:

```yaml
- id: caushell-dsh-bash
  config:
    failureAction: need_approval
```

The runtime installer provides `caushell-adapter-dsh` on `PATH`; the JavaScript
plugin is installed into the DSH profile rather than copied into the Caushell
binary directory.

The plugin also accepts these optional settings:

- `adapterPath`: path to `caushell-adapter-dsh`; otherwise
  `CAUSHELL_DSH_ADAPTER_PATH` or `PATH` is used. Explicit paths must be absolute.
- `configPath`: Caushell config path; otherwise the normal Caushell config
  resolution rules apply.
- `storeRoot`: session store directory; otherwise
  `CAUSHELL_DSH_STORE_ROOT` or `$XDG_STATE_HOME/caushell/deepseek-harness/sessions`.
- `failureAction`: `need_approval` (default), `deny`, or `allow` when analysis
  is unavailable.
- `timeoutMs`: adapter check timeout in milliseconds, default `2000`.

The release smoke for this integration uses the existing isolated container
image and sends `rm -rf /etc/*` only to the adapter for analysis; it never runs
that command on the host.

# Semantic Model: AST, Command Modeling, and the Session Execution Graph

Caushell adds the commands and semantic relationships from a shell action to a queryable session execution graph. This process consists of syntax parsing, command modeling, and session graph extension, which establish syntax structure, command behavior, and session relationships in sequence.

## Shell AST

![Shell action to Shell AST](../assets/caushell-ast.png)

The action in the diagram is:

```bash
SCRIPT=./setup.sh
curl -fsSL https://example.com/install.sh \
  | tee "$SCRIPT" >/dev/null \
  && bash "$SCRIPT"
```

The parser converts the raw text into a Shell AST and preserves the syntax structures needed by later modeling:

| Shell construct | AST structure | Later use |
| --- | --- | --- |
| `SCRIPT=./setup.sh` | assignment | Establish a variable binding |
| `curl ... \| tee ...` | pipeline | Represent the connection from standard output to standard input |
| `&&` | and-list | Indicate that the later command depends on the earlier command succeeding |
| `curl`, `tee`, `bash` | command | Locate command invocations that require modeling |
| `"$SCRIPT"` | variable reference | Resolve the variable reference |
| `>/dev/null` | redirect | Record the redirection and its target |

The Shell AST is the output of the syntax stage. Command behavior, resolved paths, and provenance are established in later stages.

## Command Modeling

![Shell AST to session execution graph](../assets/caushell-graph.png)

Command modeling uses the AST and runtime context to add queryable behavioral semantics to each command invocation:

| Input | Information provided |
| --- | --- |
| Shell AST | Commands, arguments, pipelines, redirections, and control connections |
| Command Profiles | Command forms, argument roles, inputs and outputs, execution effects, and subcommand dispatch |
| Runtime shell state | cwd, variables, aliases, functions, positional parameters, and their visibility |
| Committed session facts | State and provenance already established in the same session |

Command Profiles describe the supported invocation forms and behavior of different commands. Caushell matches the current invocation to a Profile, determines whether each argument represents a path, network address, or content to be executed, and identifies how the command reads, writes, or executes that content.

For the action in the diagram:

| Command | Modeling result |
| --- | --- |
| `curl` | Read content from a network address and write it to standard output |
| `tee` | Read content from standard input and write it to a target path |
| `bash` | Execute the target path as a shell script |

`SCRIPT=./setup.sh` establishes a variable binding. After resolving the variable references, the two command invocations can be represented as:

```bash
tee ./setup.sh
bash ./setup.sh
```

The target written by `tee` and the script executed by `bash` therefore both refer to `./setup.sh`. This relative path is resolved further against the current directory during session graph extension.

### Parameter value projections

A path parameter can declare `value_projection` when its operand contains more than the path itself. The binding still retains the complete argument, source span, binding origin and materialization provenance. Path analysis uses a separate semantic view; command dispatch and execution arguments are not rewritten.

```yaml
- name: test_paths
  semantic: {kind: path, role: read, purpose: generic_operand}
  binding: {kind: remaining_positionals}
  cardinality: optional_many
  value_projection:
    kind: prefix_before
    delimiter: "::"
    if_absent: original

- name: cache_path
  semantic: {kind: path, role: write, purpose: generic_operand}
  binding: {kind: following_flag, flag: "--override", operand_mode: next_arg}
  cardinality: optional_many
  value_projection:
    kind: key_value
    separator: "="
    key: cache_dir
```

`prefix_before` selects text before the first delimiter: `tests/test_api.py::test_login` contributes `tests/test_api.py` to path analysis. Without a delimiter, `if_absent: original` (the default) retains the operand; `if_absent: unknown` leaves it unresolved. `key_value` matches the complete key before the first separator: `cache_dir=/etc/pytest-cache` contributes `/etc/pytest-cache`, whereas `console_output_style=classic` contributes no cache path. Additional separators in the value are retained.

Unknown and inapplicable are distinct. Empty projected paths, malformed keyed operands, unresolved values and implicit runtime operands remain unknown. A known nonmatching key produces no path and no mutation fallback. An unresolved unquoted expansion can introduce additional argv fields, so a static prefix does not establish applicability or a complete path. For a fully double-quoted argument, a completed static delimiter can establish a path prefix or a nonmatching key even if the suffix is unknown. Exact materialized values and decoded literal data are not expanded a second time. Runtime bounds on a whole operand are not reused as bounds on its substring.

Path facts, path-content provenance, mutation targets, derived paths and catastrophic target classification consume the same semantic view. An unknown projected root remains unknown rather than erasing a derived effect. Existing guards decide approval or denial; projection adds no risk pass or command-name special case. Each bound operand is projected independently, without imposing a command-specific repeated-option precedence rule.

The declaration currently supports filesystem `path` semantics except `cwd_anchor`, not command references or payloads. Omitting it preserves the existing identity view without allocating projected values. Projection alone does not activate a Profile or discover configuration. The built-in pytest Profile combines projections with the configured-path declaration below.

### Structured operands and encoded argv

`structured_projection` declares a tool-owned grammar on a plain-value parameter: an optional separator, ordered literal/prefix branches, and a fallback. Prefix matching consumes the prefix; a branch without a target proves that no associated effect applies. Targets emit distinct virtual slots with declared semantics without rewriting argv. Source spans and materialization provenance are retained. Ordered `sources` select the first present original slot, never replacing an explicit unknown with a later default. Separators, references and name collisions are validated at load time.

```yaml
structured_projection:
  separator: ','
  branches:
    - matcher: {kind: literal, value: '-'}
    - matcher: {kind: prefix, value: '@'}
      target:
        name: child_commands
        semantic: {kind: command_ref, dispatch: wrapper_command}
  fallback:
    name: output_bases
    semantic: {kind: plain_value}
```

`command_whitespace_argv: child_commands` dispatches each semantic value as executable/argv split on whitespace, not Bash source. Executables and arguments retain their argv-data status: dollar signs, quotes, pipes and semicolons are not interpreted again. Unresolved entries remain child-call gaps, and unknown writes remain mutation candidates. Existing scalar `value_projection` is unchanged. Only declared operands are structurally decoded.

`stdin_from_parent: true` declares delivery of generated tool data to child stdin. Existing dispatch, execution-context and stream-provenance machinery retain the opaque input, including wrapper dispatch; `@bash` therefore requires approval. Unresolved calls inside wrappers reach the existing approval fallback. No new risk pass, dynamic probing or Harness field is involved.

The first built-in user is `nsys stats/analyze --output`, distinguishing console output, file basenames, default basenames and `@command`. `sibling_files` produces a `BoundedPathSet` under the known output directory instead of inventing a concrete file named after the basename; only its directory is normalized before appending report filenames. Potential SQLite creation from `.nsys-rep` and explicit `--sqlite` targets remain separate effects. Help does not trigger them.

This scope does not cover persistent collection sessions, profile/start/launch/stop, callbacks or report templates. Listed built-in reports/rules and formats are statically accepted; other code references, report/format arguments and custom directories require approval. List alignment and execution counts are not replayed exactly: all output candidates are retained, potentially increasing approvals. Report content and process state are not dynamically inspected.

Reference: [NVIDIA CLI documentation](https://docs.nvidia.com/nsight-systems/UserGuide/index.html#cli-stats-command-switch-options).

### Opaque argument files and Ruff effects

Profiles may opt into whole-argv argument-file recognition:

```yaml
argument_files:
  - prefix: '@'
    possible_effects: [read_path, write_path, delete_path]
```

Recognition runs on materialized argv before tool option binding, including option values and arguments after `--`. Unknown argv retains the possibility of expansion. Declared filesystem effects have unknown targets; the existing mutation guard requests approval for writes/deletions. Neither file contents nor the filesystem are queried. An existing literal `@path` fallback is therefore conservatively ambiguous. Profiles without this declaration do not scan argv for argument files. Empty prefixes, empty effect lists and non-filesystem effects are rejected during loading.

Effects retained in a partial binding remain subject to the mutation guard even if form selection fails. A path parameter's base role is not exclusive: a declared write effect on a read parameter also contributes a write PathFact to the Graph. These are command-independent preservation rules, not new policies or passes.

The Ruff Profile covers direct `check`, `format`, `clean` and information queries. A normal `check` retains potential source writes because uninspected configuration can enable `fix` or `fix-only`. `--no-fix` alone is insufficient to prove read-only operation. `--diff`, inspection modes, or both `--no-fix --no-fix-only` without conflicting fixing/suppression switches remove source writes. `format --check/--diff` does likewise. Default source selection is cwd. `--stdin-filename` supplies stdin identity, not a disk output target; check watch/suppression modes retain file-processing effects.

Ruff rejects `--diff` combined with `--add-noqa/--add-ignore`; the Profile conservatively retains source-write candidates for conflicting fixing/suppression combinations rather than treating them as valid read-only forms. Inspection modes return before suppression processing. Source read-only modes do not remove independent check report writes. Explicit cache/report destinations use configured paths; implicit unknown cache writes retain the agreed incidental-cache exemption. Cache clearing is an unknown deletion, not exempt incidental writing. Environment uncertainty is not absence: without sufficient shell-state observability, an optional `RUFF_OUTPUT_FILE` may still exist and require approval. A CLI output destination takes precedence.

`toml_string` is an opt-in value projection for a top-level TOML string key, for example `{kind: toml_string, key: cache-dir}`. It parses TOML rather than stripping quotes, preserving escaped characters and unknown malformed/dynamic values. Ruff's `--config` may denote either a file or inline TOML, with an existing file taking precedence. Without probing existence, an assignment-shaped operand contributes a potential inline cache destination; file contents and their hidden settings remain uninspected. No extension-based classification is used. `analyze`, `server`, Python-module entrypoints and arbitrary config/code behavior are not claimed as covered.

References: [Ruff configuration](https://docs.astral.sh/ruff/configuration/), [settings](https://docs.astral.sh/ruff/settings/), [pinned CLI implementation](https://github.com/astral-sh/ruff/tree/127e77ef8bee49f21c0e7c2ff1e38ccf27fb522a/crates/ruff/src).

### Configured paths and incidental cache writes

An effect may declare `configured_path` when its destination comes from multiple options or keyed configuration overrides. Sources are checked in declaration order; the first applicable source wins, and its last applicable argv value wins within that source. An explicit unknown value does not fall back to a lower-priority source or an implicit default. Raw operands and their ownership and materialization metadata remain unchanged.

```yaml
kind: write_path
target:
  kind: configured_path
  sources:
    - slot: overrides
      projection: {kind: key_value, separator: "=", key: cache_dir}
  relative_to:
    slot: rootdir
    expand_environment: true
    fallback_parent_slot: config_file
  expand_environment: true
  expand_user: true
  missing: incidental_cache
  purpose: incidental_cache
```

Absolute destinations do not depend on the anchor. Relative destinations use the declared anchor, or the parent of the fallback config-file operand if the primary anchor is absent. An unknown primary anchor is not treated as absent. Without a declared anchor, relative paths use cwd; a required but unavailable anchor remains unknown. Tool-level environment expansion is opt-in and unresolved environment references remain unknown instead of consulting the guard's environment. Home expansion uses the supplied home and does not look up named users.

`missing: skip` means no applicable source produces no target. `missing: unknown` retains an unresolved target for ordinary guard checking. `missing: incidental_cache` retains an unknown cache-write fact in the Graph, but the existing outside-workspace mutation guard does not request approval for that implicit write. This fallback is validated at Profile load time: it is allowed only for `write_path` with `purpose: incidental_cache`. An explicit source, even an empty or unknown one, never receives this exemption; cache purpose alone does not grant it. A fixed `default_value` can supply a literal convention such as `pytestdebug.log`, but cannot be combined with an unknown fallback. Source and anchor slots must be declared.

The direct pytest/py.test Profile covers test selectors, configuration and plugin loading boundaries, cache overrides and clearing, JUnit reports, log files, and explicit base-temporary-directory cleanup. Its built-in CLI semantics were checked against [pytest 9.0.2 cache handling](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/cacheprovider.py), [root-directory selection](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/config/findpaths.py), [JUnit output](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/junitxml.py), [logging](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/logging.py), and [temporary-directory handling](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/tmpdir.py). In particular, cache paths are relative to rootdir, while initial CLI/ini log output and JUnit reports use cwd. Repeated overrides retain the last matching key; a CLI log path takes precedence over an ini override.

With cwd and workspace both `/workspace`, default `pytest tests/` allows the implicit unknown cache write. Explicit `-o cache_dir=/etc/cache`, unknown explicit outputs, `--cache-clear` with an unknown target, and outside-workspace report/log/basetemp destinations require approval. Workspace-local explicit destinations allow when their required anchors are known. Shell redirections, deletion and other commands remain independently checked; no new pass or pytest-name branch is added.

Configuration contents, environment-injected options, test/plugin Python code, and runtime filesystem discovery are not interpreted here. Undiscovered configuration may redirect an implicit cache outside the workspace; allowing that unknown incidental write is the selected policy tradeoff, not proof of a local destination. Non-cache writes hidden in configuration or Python code are not claimed as covered by these CLI declarations. Python `-m pytest` module dispatch remains separate.

### Conda environment targets

The direct Conda Profile models environment creation, package installation/update/removal, the corresponding `env` operations, queries and explicit exports. Transactions declare possible writes and deletions through `configured_path`, using the last explicit `-p/--prefix` value. A name, the active environment, or a target supplied inside an unread definition/config file does not establish a filesystem path: the target remains unknown and the existing outside-workspace mutation guard requests approval. Known prefixes use the ordinary workspace check. No runtime discovery, new Harness field or Conda-specific risk pass is added. Prefix selection was checked against [Conda 26.7.0 CLI helpers](https://github.com/conda/conda/blob/26.7.0/conda/cli/helpers.py).

Standard transaction previews omit environment mutations and imported-package execution, but do not exempt shell redirections or neighboring commands. Download-only install/update does not link packages into the environment; create still declares possible prefix deletion because it can remove an existing environment before transaction handling. See [create](https://github.com/conda/conda/blob/26.7.0/conda/cli/main_create.py) and [transaction handling](https://github.com/conda/conda/blob/26.7.0/conda/cli/install.py). Definition-file operands are inputs, not environment destinations. Queries and stdout exports do not invent environment writes; `export -f` supplies a separate output path, with no tool-level home/environment expansion, matching [the exporter](https://github.com/conda/conda/blob/26.7.0/conda/cli/main_export.py).

This is a CLI transaction-target scope, not complete Conda execution modeling. Configuration content, solver results, transitive packages, cache/registry paths, plugin code and link/activation-script bodies are not inspected. `run/activate/deactivate`, `config/clean/init/rename`, environment-variable configuration and Python module dispatch remain separate work. In particular, [Conda run](https://github.com/conda/conda/blob/26.7.0/conda/cli/main_run.py) activates an environment before launching the child; it is not declared a transparent wrapper.

### Package-source roles instead of filename guesses

Package provenance uses the bound parameter's `package_locator.locator_kinds` together with a statically resolved argv value. It does not infer a definition file from `.txt`, `.in`, `.lock`, or the word `requirements` in a filename.

The shared classifier first obtains the semantic argv value, preserving the distinction between unresolved shell expansion and literal data. It then checks explicit local-path, HTTP(S) and VCS URL syntax against the kinds declared by the Profile. A definition-file parameter with one declared local role retains `requirement_file` for extensionless, relative and absolute filenames. Ordinary package parameters can retain `registry_ref`; the existing manager-specific precedence for slash-bearing package references is unchanged. Conflicting local roles, unsupported URI forms and unresolved arguments produce `unknown_dynamic` rather than disappearing or becoming a registry package by fallback. Unknown is an analysis result even if a Profile lists only concrete input kinds.

For example, `pip install requests.txt` treats the operand as a registry reference, `pip install -r requests.txt` as a definition file, and `pip install -e requests.txt` as a local source. `pip install -r input` and `conda env create -p env -f environment.yml` likewise identify definition files without inspecting their contents or testing filesystem existence. The pip `-r` declaration permits a local definition file or a direct URL, consistent with the [official option contract](https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-r).

Known local inputs retain path-content provenance and known URLs retain network-source provenance. Literal `$` characters in a quoted or already materialized filename are not re-expanded. Simple shell `~/` expansion can use the request's supplied home; named-user lookup and host-state probing are not performed. Source classification does not itself grant approval: existing guards and policy configuration still decide the action. This contract does not claim complete package-manager locator grammars or interpretation of definition-file contents.

The existing imported-package execution guard checks every source consumed by the current invocation, not just its first package. Its trigger is the existing `executes_imported_package_logic` fact; calls without that fact skip source-edge traversal. Only `Consumes` edges labeled `ImportedPackageLogic` to imported-package artifacts participate. Each distinct invocation/artifact pair receives its own evidence and existing source policy, and ordinary decision assembly retains `Deny > NeedApproval > Allow`. Repeated operands or slots consuming the same artifact do not duplicate findings, while separate invocations and distinct source kinds remain separate. Pure downloads, previews and queries are not package execution merely because their Graph contains package artifacts. This adds no pass, Profile-name special case or full-session graph scan.

## Session Graph Extension

Each session maintains a continuously updated execution graph. When analyzing the current action, Caushell first layers its new commands, state, and provenance relationships onto the existing graph to form the view used for this analysis.

This analysis view consists of two parts:

- Session facts already committed to the session execution graph.
- Nodes and edges produced by the current action that have not yet been committed.

The diagram above shows the portion relevant to the example after the current action has been added to the analysis view. The entities represent the following facts:

| Graph entity | Fact represented |
| --- | --- |
| Command Invocation | A command invocation in the current action or session history |
| Variable Binding | A value bound to a variable in the current action or an earlier action |
| Runtime State | Runtime state such as the current directory |
| Resolved Path | A concrete path resolved from variables and the current directory |
| Network Endpoint | A network source or destination accessed by a command |
| Payload Artifact | Data obtained from a network source, file, or other input |
| Path Content | File content associated with a path |
| Execution Sink | A script, interpreter, or other execution target |

### Variable Bindings and Path Resolution

After `SCRIPT=./setup.sh` establishes the variable binding, `tee "$SCRIPT"` and `bash "$SCRIPT"` resolve to the same relative path. The Runtime State node shows that the current directory is `/workspace`, so the path resolves to `/workspace/setup.sh`.

The file write performed by `tee` and the script read performed by `bash` both point to the same Resolved Path. The graph therefore associates the content written by `tee` and the content read by `bash` with the same file.

Variables or paths that cannot be determined remain unknown in the graph. Later analysis considers both known relationships and this unresolved information.

### Provenance

Provenance records where data originated, which steps it passed through, and how it was ultimately used. The action in the diagram creates the following relationships:

1. `curl` obtains content from a network address.
2. The pipeline passes the output of `curl` to `tee`.
3. `tee` writes the content to `/workspace/setup.sh`.
4. `bash` reads that path and sends its content to the shell for execution.

This relationship chain connects the network source, downloaded payload, file content, and script execution. Analysis modules can trace backward through the graph to produce a reviewable evidence chain.

### Nested dispatch and runtime arguments

Profiles for leading-option command grammars can opt into `option_scope: leading_options` at the command root or an individual subcommand node. The shared binder parses declared options and their operands before stopping at the first non-option operand or an option terminator (`--`). This same ownership boundary governs modifier matching, form selectors, and parameter binding. For example, in `sshpass -e ssh -p 2222 host`, `-p 2222` belongs to `ssh`, not to `sshpass`. A flag-like option value is still a value, and the child's argv (including its own `--`) is preserved for normal nested dispatch. Positional parameters still span the invocation: `env` can consume environment assignments and `timeout` can consume its duration before selecting the child.

The default remains `all_arguments`; ordinary profiles can still describe options after operands. Leading-option profiles declare option arity through modifier/form flag bindings. Unknown option arity is reported as a selection gap, retaining already established modifier effects rather than guessing a child boundary. This does not change the configured resolve-gap action or nested-expansion limit.

Option name matching is a separate declaration: `option_matching: exact_names` matches complete declared names such as NVIDIA's `-pl` and `-nic`, without interpreting their letters as short-option clusters or guessing attached short operands. Long inline values such as `--power-limit=200` still follow the declared operand binding. Omission defaults to `short_clusters`, preserving existing matching behaviour. Subcommand nodes inherit their enclosing node's mode unless they explicitly override it; inheritance is resolved when the Profile is loaded. The selected mode governs modifier matching and constraints, form/remaining selectors, parameter binding, leading-option scanning and partial binding after selection failures. It does not change Bash parsing, add a risk pass or determine the decision action.

For example, a Profile with `option_matching: exact_names` can declare `flags: ["-pl", "--power-limit"]` and bind the following value to a plain `power_watts` parameter. `-pl 200` binds that value without activating `-p` or `-l`; `-pl200` does not infer an attached operand. This mode is not a universal CLI validity or coverage check: the existing `all_arguments` binder does not report every unknown flag as a residual. Known unsupported forms and configured resolve-gap actions remain distinct from successfully modelled calls.

Command Profiles describe where a command can dispatch execution and how its arguments are bound. The dispatch layer carries each argument as a typed value: literal argv data, a runtime-produced value, or an implicit input with a conservative domain. Consumers may use a bounded path domain to classify possible locations, but it is not a claim that any listed root is the concrete file actually acted on. Unknown input and known-empty input remain distinct.

The `find -exec`/`-execdir` and `xargs` profiles feed the same dispatch and execution-graph machinery. `find` arguments may carry a bounded search-root domain; symlink-following, unresolved roots, and `-execdir` context that cannot be established widen that domain or leave it unknown. `xargs` static input is used only when its source is known complete; partial fragments are advisory, not a proven argv prefix, and incomplete or runtime-generated input leaves arguments unknown. Explicit stdin redirection takes precedence over pipeline input.

Known argv data is never parsed again as shell source. A shell `-c` operand is the intentional exception at the payload boundary: it is parsed once as code, while its positional arguments remain typed data and are bound separately. Recursive inline execution uses the canonical execution frontier so graph expansion is bounded by the configured depth and preserves source relationships. This models common cases conservatively; it is not a complete shell, `find`, or `xargs` interpreter.

The default expansion depth is 8; the top-level command is depth 0. Reaching depth 8 is not itself a risk: a fully analysed leaf uses the normal decision rules. If child execution remains beyond the budget, expansion stops and the existing resolve-policy pass proposes `NeedApproval` under `execution_expansion_limit`. The decision trace retains the truncation evidence, depth budget and pending candidate count. This applies to both the canonical execution frontier and nested-payload truncation; a parsed ancestor or the default Observe action for unsupported static literals does not hide an incomplete expansion. Existing `Deny` findings still take precedence.

## Session Graph Lifecycle

| Point in time | Graph state |
| --- | --- |
| Before a check begins | The session execution graph contains previously committed session facts |
| During the current check | The analysis view includes nodes and edges produced by the current action |
| Decision is `Allow` | The current action's graph changes are committed to the session execution graph |
| Decision is `NeedApproval` or `Deny` | The request is recorded, but the new nodes and edges are not added to the session execution graph |

Runtime shell state also indicates whether information such as cwd, variables, aliases, and functions is visible and whether it persists across actions. Information supplied by the Harness and confirmed by the runtime can participate in command modeling for later actions; information that cannot be confirmed is recorded as unknown.

## Network listeners and Uvicorn

`listen_network` is distinct from an outbound `network_endpoint`. A Profile
declares a `network_listener` target whose host, port, UNIX socket and inherited
FD settings each select the last CLI slot value, then a declared environment
default, then a literal default. An unresolved higher-priority value never falls
back to a known lower-priority value. The generic `configured_path` target also
accepts an `environment: {name: ..., empty_is_unset: true}` fallback so socket
creation and cleanup retain the same path semantics.

The extracted `ExecutionSemantics.network_listeners` facts are available through
the semantic Query, decision trace and session snapshot. The independent
`network_listener_guard` applies `network_listener_exposure` (family
`network_safety`, default `NeedApproval`):

- Numeric loopback IPv4/IPv6 addresses, including IPv4-mapped loopback, are exempt
  from this rule. LAN addresses, machine-owned non-loopback addresses and wildcard
  binds are not local for this policy.
- Hostnames (including `localhost`), dynamic addresses, unavailable environment
  facts and inherited sockets with unknown scope require approval. No DNS,
  process/socket discovery, host environment or new Harness field is used.
- A known filesystem UNIX socket is checked by existing filesystem mutation
  rules. A local listener never exempts redirections or other effects.

The pass first checks already-extracted current-request facts. If no non-local or
unknown listener candidate exists it returns without querying the graph. When
needed, the semantic Query uses the current sequence's indexed window, not the
entire history. Historical listener facts alone do not retrigger later actions.

The first built-in consumer is `uvicorn`, including declarative
`python[3] -m uvicorn` dispatch. Its Profile preserves application code loading,
`--host`/`--port`, `--uds` creation and cleanup, `--fd`, configuration inputs,
certificate reads and ordinary option arities. `--app-dir` is a search path, not
a cwd change; `--root-path` is an HTTP prefix, not a filesystem target. Uvicorn's
CLI defaults use `UVICORN_*` environment variables; `--env-file` is an application
input and is not scanned for server settings. When FD and UDS settings coexist,
startup-mode-dependent precedence is conservatively reviewed and the UDS cleanup
effects remain present.

The existing shell-state snapshot supplies environment observability and export
attributes. Complete/exported-only snapshots can prove a variable absent;
unavailable facts cannot. Child-environment facts are kept separate from shell
locals. Prefix assignments, exports, unset, and declared wrapper environment
reset/removal are propagated without command-name cases in the listener code.
`env` declares `clear_environment_when: [ignore_environment]` and
`unset_environment: [unset_names]` on its dispatch target. Conditional or isolated
exports and unsupported export-mode changes retain uncertainty. A child shell
does not inherit unexported locals; exported session values keep their Graph
provenance.

This is static listener admission, not application-code analysis, firewall
reachability analysis or live process tracking. Other server commands need their
own Profile declarations; generic endpoint effects are not silently reclassified.
Source: [Uvicorn CLI](https://github.com/Kludex/uvicorn/blob/724f82fdba1765fe5f821a3ebed6da5c1ddcb386/uvicorn/main.py),
[server startup](https://github.com/Kludex/uvicorn/blob/724f82fdba1765fe5f821a3ebed6da5c1ddcb386/uvicorn/server.py),
[socket binding](https://github.com/Kludex/uvicorn/blob/724f82fdba1765fe5f821a3ebed6da5c1ddcb386/uvicorn/config.py).

## Environment preparation and `uv`

The `uv` Profile retains both wrapper preparation and child execution. `uv run`
can create or replace a project environment before launching the child; even
`--no-sync` can create a missing environment. `--locked` and `--frozen` prevent
lockfile updates, not environment changes. `--with*` overlays and opaque PEP 723
script metadata may prepare additional environments. Real environment mutations
use the existing filesystem guard; they are not incidental-cache exemptions.

Supported entrypoints are external-command/module/local-script/stdin/URL `run`,
`sync`, `venv`, direct `pip install/sync/uninstall` and query forms, `lock`,
`add/remove` and help. Known CLI targets and absolute `UV_PROJECT_ENVIRONMENT`
values are preserved. Project discovery can select a parent directory, so a
default or relative project environment and an undiscovered lockfile remain
unknown rather than being placed beneath the request cwd. Preview forms omit
their transaction effects; independently declared option effects remain present.
Sources use the shared package-locator classifier and keep their complete text.
Relative local package artifacts also include their resolved source path in the
node identity, preventing identical argv spellings in different cwd contexts from
merging. Absolute and network/registry identities stay cwd-independent.

The shared DSL provides three additive mechanisms, with no `uv`-specific branch
in the risk passes:

- `set_execution_working_directory` with a `configured_path` target changes a
  process and its execution descendants, not the caller shell. `--directory` and
  `UV_WORKING_DIR` use this declaration; `--project` does not change child cwd.
  Shell expansions and outer redirections use the shell-entry cwd. Paths, package
  sources, repository scopes and nested shell redirections retain known branches
  or unknown cwd facts consistently with mutation decisions.
- `configured_path.unresolved_relative_base: true` keeps a relative target
  unresolved when its base needs filesystem discovery. It cannot coexist with
  `relative_to`. Empty `sources` are allowed with an environment/default source or
  `missing: unknown`; an empty incidental-cache-only declaration is invalid.
- Dispatch targets accept exactly one of `command` (a slot), `command_literal`
  (fixed executable), or `command_whitespace_argv` (encoded argv as described above).
  The first two forms accept optional `argv_prefix` data. For example,
  `{kind: dispatch, command_literal: python, argv_prefix: ['-m'], argv: [module, args]}`
  produces a typed interpreter call, not shell source. `unknown_environment_when`
  (modifier IDs) and `unknown_environment_from` (declared environment sources)
  invalidate inherited child environment certainty when an opaque env file may
  replace values. Explicit later environment transforms still apply normally.

This scope does not inspect project/config/requirements/script contents or discover
installed interpreters. Automatic Python acquisition, `uv tool/python` management,
build/publish and the other unsupported administration commands are not claimed
as covered; interpreter downloads may introduce additional destinations. The
Profile's limitations are explicit rather than a claim of full `uv` CLI coverage.
No dynamic probing, new Harness facts, risk pass or approval-policy changes are
introduced.
Source: [uv CLI](https://docs.astral.sh/uv/reference/cli/),
[run implementation](https://github.com/astral-sh/uv/blob/a75d26a6abb614d60cdf1947dfaa13d7b9bb2978/crates/uv/src/commands/project/run.rs),
[project environment preparation](https://github.com/astral-sh/uv/blob/a75d26a6abb614d60cdf1947dfaa13d7b9bb2978/crates/uv/src/commands/project/mod.rs).

## Further Reading

- [How Caushell works](how-it-works.md)
- [Security model: risk analysis, decisions, and the execution boundary](security-model.md)
- [Configuration](configuration.md)

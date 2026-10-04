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

For a complete Bash double-quoted string, token text is the exact source between the outer quotes. Newlines, whitespace, escapes and expansion spelling are retained, together with the original source span and independently collected substitution facts. The parser does not evaluate this text or reconstruct it by concatenating AST children. Existing argv decoding and value materialization establish the operand value; incomplete quotes remain a partial parse.

Before parsing a recursive inline payload, its outer-shell operands must become complete argv values. Recursive materialization reuses the quote-aware lexical decoder for literals and the existing exact-scalar resolution for bindings. Decoded literals, resolved scalars and runtime argv data are not expanded again; original quote metadata and spans remain available. Static prefixes, unsupported expansions and incomplete values remain unresolved and use the existing approval fallback. Canonical inline-shell expansion and nested payload records share this materialization path. Already-complete program text from stdin, files or configuration is not subjected to another outer-quote decode.

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

### Structured patch data and modification targets

A form may opt into `payload_projections`. This decodes a complete tool-owned data protocol, not Bash or another executable language. An undeclared form is not scanned. The first format is `codex_apply_patch`; the Profile, not the generic binder, selects it:

```yaml
payload_projections:
  - format: codex_apply_patch
    source: {kind: slot, name: patch}
    reads: patch_reads
    writes: patch_writes
    deletes: patch_deletes
    max_bytes: 1048576
    max_operations: 4096
effects:
  - {kind: read_path, target: {kind: slot, name: patch_reads}}
  - {kind: write_path, target: {kind: slot, name: patch_writes}}
  - {kind: delete_path, target: {kind: slot, name: patch_deletes}}
```

The source must be an unprojected plain-value parameter. Alternatively, `source: {kind: stdin}` requires a plain `stdin_data` declaration. Output slot names must be distinct, must not collide with existing slots, and must have matching effects in that form. Omitted budgets default to 1 MiB and 4096 operations; both must be positive. `no_arguments` distinguishes no arguments from flags and `--`, unlike `no_positional_args`.

The built-in `apply_patch`/`applypatch` Profile accepts exactly one patch argument, or effective stdin with no arguments. Add emits write; update emits read and write; delete emits deletion; update with move emits source read/deletion and destination write. Multiple operations retain all targets. Empty patches and proven absent effect classes have explicit empty semantic views, not unknown mutations. The existing workspace and catastrophic guards decide the action; no new risk pass or Harness request field is added.

The decoder validates the whole envelope, operation headers and update chunks, without applying the patch or interpreting inserted/context lines as commands. It preserves literal path bytes, Unicode and spaces; filenames are not shell-expanded a second time. Materialization of the *outer* shell argument still precedes projection. Truncated, malformed, dynamic, over-budget or environment-tagged payloads retain unknown writes/deletions rather than proving a safe prefix. The pure decoder is linear and copies original source metadata once per effect class, not once per file.

Canonical execution resolution supplies stdin only when existing static evidence proves the complete stream. Explicit redirections override pipes, and the last stdin redirection wins. Ambient input, missing file contents, partial fragments and opaque dispatcher output stay unknown, including through wrapper chains. No host file or process is probed. File application success, exact resulting file contents and native non-Shell editor tools are outside this scope. Any limitations in upstream shell argument materialization remain conservative unknowns.

Protocol reference: [pinned Codex apply-patch parser](https://github.com/openai/codex/tree/f6fd7f17ed2ef4bf28e5b320789d764350ce4529/codex-rs/apply-patch/src). This is a pinned implementation contract, not a claim about every future version.

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

### SQLite CLI and opaque executable input

The `sqlite3` Profile models database operands, potential main-file and `-journal`/`-wal`/`-shm` writes, inline SQL/dot-command input, stdin, `-cmd`, startup configuration and VFS code loading. `:memory:` and a missing database operand do not become filesystem paths. URI databases remain opaque rather than being fabricated as cwd-relative `file:` paths. File/script dispatch and database contents are not probed; the first operand is a potential database, not a confirmed database file. Further script-selected targets remain unknown.

`sqlite_cli` is a payload-language metadata value preserved in the Graph, evidence and queries. It denotes SQL plus SQLite dot-commands, not Bash: it does not enable a SQL interpreter or create shell subcalls from `.shell` text. Inline input ignores stdin; stdin forms retain executable-input provenance. `--noinit` suppresses both default and explicit init loading. Otherwise an explicit init path is retained, or the XDG/home startup location remains unknown. Compound/unrecognized options are captured across unconsumed argv as opaque client syntax; flag-shaped values, exact option names and `--` ownership use the shared binder.

All SQL/client execution retains an unknown write candidate and therefore requests approval under the existing mutation guard, including apparent `SELECT`, `--readonly`, `:memory:` and `--safe --noinit` calls. This is an explicit opaque-execution boundary, not a claim that every query writes. Readonly protects the ordinary main database, not arbitrary dot-command/function effects; WAL sidecars and auto-detected ZIP backends also prevent a whole-call read-only proof. Database and sidecar effects remain separately visible even when unknown client effects require approval.

Native safe mode is not a workspace-confinement exemption: startup runs before it is enabled, `-cmd` ordering and nonce can bypass restrictions, and even `--safe --noinit` permits an external `temp_store_directory` pragma. No SQL-body filtering is used to pretend these inputs have been analyzed. Clean `--noinit --help/--version` calls without database operands, early/value-taking or unrecognized options are informational. No risk pass, command-name special case, dynamic probing, new dependency or Harness request field is added.

References: [SQLite CLI](https://sqlite.org/cli.html), [pinned SQLite 3.53.4 CLI source](https://github.com/sqlite/sqlite/blob/b09c88c14082339b66c7b7158d609a771e64ca69/src/shell.c.in).

### Database operation classes and Redis CLI

A Profile may declare `{kind: database_operation, database_operation: read|write|administration|opaque, target: {kind: none}}`. Database keys are plain values, not filesystem paths. These operation classes are preserved in `ExecutionSemantics.database_operations`, decision traces, snapshots and the existing execution-semantics Query. The additional field defaults to empty when reading older data and is omitted when empty; no Harness request field is required.

The independent `database_operation_guard` consumes already-resolved current-request invocations, including explicitly declared partial bindings. It returns before canonical-source collection when there is no non-read database effect, does not traverse session history and does not probe servers. Reads add no decision. `database_state_mutation`, `database_administration` and `database_opaque_execution` default to `NeedApproval` and belong to the configurable `database_safety` family. Explicit rule configuration takes precedence over a family action. Existing filesystem and other rules remain independent.

The `redis-cli` Profile admits a fixed set of explicit queries, including `GET`, `EXISTS`, `DBSIZE` and `CONFIG GET`. Data writes such as `SET`, `DEL`, `GETDEL` and `FLUSHALL`, and administration such as `CONFIG SET` and `SHUTDOWN`, require approval by default. Localhost or a workspace Unix socket does not establish database ownership. Lua, functions, interactive/RESP streams, stdin argv substitution (`-x`/`-X`), quoted-input reinterpretation and unknown commands are opaque and require approval; none is parsed as Bash. `--rdb`/`--functions-rdb` retain database-read and independent local-file-output effects; `-` is stdout rather than a filename, and shell redirections retain their own mutation checks.

Leading options stop at the command: `redis-cli -a --help GET key` uses `--help` as a password value, while `redis-cli GET --eval missing.lua` sends the later words as command data. Special modes before the command cannot be hidden by an apparent `GET`. Information forms add no database operation. Unsupported or incomplete options retain this Profile's explicitly declared opaque selection-failure effect; they do not depend on a global resolve-gap policy change. Mixed modes are conservatively classified rather than replaying every native option precedence. Custom command renaming, module commands, data confidentiality, implicit server state and exact server validity are not certified by query admission.

References: [Redis CLI](https://redis.io/docs/latest/develop/tools/cli/), [pinned Redis 8.2.3 CLI source](https://github.com/redis/redis/blob/8.2.3/src/redis-cli.c).

### Terminal-session operations and GNU Screen

A Profile may declare `{kind: terminal_session_operation, terminal_session_operation: inspect|create|attach|control|opaque, target: {kind: none}}`. These are static operation classes, not statements about a live session or its ownership. They are deduplicated per invocation and preserved in `ExecutionSemantics.terminal_session_operations`, traces, snapshots and the existing execution-semantics Query. Old data defaults to an empty list, which is omitted on serialization. Session/window identifiers and protocol text remain ordinary values rather than filesystem targets.

The existing `interactive_escape_guard` consumes these classes from its already-indexed current-request semantics query; no new Pass, history traversal or runtime probing is added. Inspect adds no finding or decision. The new `terminal_session_operation` rule defaults to NeedApproval for Create, Attach, Control and Opaque. It uses the existing `interactive_control` family and rule/family configuration precedence. The older `interactive_escape_surface` default remains Observe, and unrelated tools retain their previous policy. An empty terminal-operation list adds no secondary traversal or allocation; this is not a measured latency claim.

The `screen` Profile admits `-v`, `-ls`/`-list` with zero or one trailing pattern, and argumentless, case-sensitive `-Q windows|info|lastmsg|number|title` queries. Other query syntax, option gaps, unknown options and undeclared compact spellings are opaque; explicit selection-failure effects keep approval independent of the default resolve-gap Observe policy. Mixed list/control flags and options after a list pattern are conservative rather than relying on an optional-operand scanner extension. Query admission is a logical operation policy, not a whole-program zero-side-effect proof: native socket-registry setup may perform housekeeping even on list/query calls.

New sessions/windows (including STY-based launches), attachment/takeover, detachment, `-wipe`, and `-X` control/input injection require approval by default. Child argv, default shells, `stuff`, `eval`, `source`, `screen` and other Screen protocol commands are not parsed as Bash or child dispatches. Potential fresh-launch configuration sources retain LoadConfig candidates, but an existing server's configuration or liveness is not certified. Logfile templates and protocol-selected outputs stay opaque instead of inventing precise writes. Shell redirections are still independently checked. Turning the terminal rule to Observe does not provide precise analysis of these deferred effects.

Caller cwd can be transmitted in ordinary new-window messages, whereas environment and remote control context can differ. No existing window is assigned the caller's shell state; no session scan, dynamic process facts, new dependency or Harness field is introduced. This is a static control boundary, not complete Screen protocol analysis.

Inspect admission requires simple fixed session/window/list operands. Dynamic references, glob expressions, whitespace-containing and repeated `-S`/`-p` operands are conservatively opaque rather than proving runtime argv cardinality. This restriction lives in the Profile; the shared option scanner is unchanged.

References: [GNU Screen invocation](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html), [startup files](https://www.gnu.org/software/screen/manual/html_node/Startup-Files.html), [pinned Screen 5.0.1 source](https://ftp.gnu.org/gnu/screen/screen-5.0.1.tar.gz).

### Socket inspection and deferred socket-closure policy

The Linux iproute2 `ss` Profile separates socket queries from explicit `close_sockets_unchecked` forms for `-K/--kill`. Socket closure currently does not trigger approval; this is a deliberate product risk-scope choice, not a read-only classification. No socket-control effect, process-kill surrogate, new pass or runtime socket discovery is introduced. The form and its risk-scope annotation remain explicit in the Profile, and the Graph retains the form ID. The shared short-option matcher preserves declared flag-only prefixes before operand-taking options, including compact `-KtF-` and numeric members such as `-4`. It stops at the operand boundary rather than interpreting parameter text as later flags; exact-name profiles and `--` keep their existing semantics.

`-D/--diag` independently contributes file writes, including on closure forms; external or unknown destinations still require approval. `-F/--filter` contributes file reads or plain stdin filter data, never a Bash payload or nested command. Upstream checks the first operand byte: dash-prefixed diagnostic destinations use stdout and dash-prefixed filter sources use stdin; `./-name` remains a real path. Structured projection preserves raw operands and unknown path candidates. Compact operands that the legacy cluster matcher leaves unmatched use an opt-in scoped prefix binding (described below). Unknown filter operands retain an unknown read target; the concrete file-versus-stdin choice is not claimed resolved.

Socket-selection expressions, family/table names, namespace names and BPF map IDs are plain values: matching a UNIX socket path is not a filesystem write, and selecting a remote address does not itself upload to that address. `-p` displays process information and `-E` observes destruction events; neither becomes process control. Help/version suppress deferred diagnostic output, but independently composed shell writes/deletions remain guarded. Repeated diagnostic destinations are retained conservatively, not replayed with exact last-option precedence. Resolver internals, filter grammar validation, abbreviated options, build-specific availability and every invalid combination are not covered.

References: [ss manual](https://man7.org/linux/man-pages/man8/ss.8.html), [pinned upstream implementation](https://github.com/iproute2/iproute2/blob/e11870d5b9414b2e0770463bd6fc2399744dc734/misc/ss.c).

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

### Homebrew: queries, package transactions and opaque control entrypoints

The `brew` Profile uses independent `manager: brew`, based on the
[pinned Homebrew source](https://github.com/Homebrew/brew/tree/570982948a8a194f0f42f43f4a5bce2d1c9f64cb)
and [official manual](https://docs.brew.sh/Manpage). Ordinary list/info/search/outdated,
installation information, shellenv and services list/info are separate from transactions.
Explicit local-definition/URL query operands, `--eval-all`, unknown options and unsupported
forms remain opaque. Shellenv prints code; it does not execute it. Queries retain implicit
configuration reads and incidental cache/API writes, not a whole-program zero-side-effect
guarantee. A known absent cache override uses the existing incidental cache policy;
explicit `HOMEBREW_CACHE` is checked normally. Unknown environment facts are not invented
as absence and retain the existing unknown-mutation approval boundary.

Install/reinstall/upgrade retain unknown modification scope, package provenance and
imported logic execution. Uninstall/autoremove/cleanup retain unknown deletion scope;
link/unlink retain modification scope. No root deletion, universal `/opt/homebrew` target
or fictitious installed-package source is created. Package and qualified tap references
are registry sources; URLs, dynamic values and explicit local spellings are independently
classified without `.rb` suffix guessing. Existing source and workspace guards stay independent.

The native launcher derives prefix from the executable/filesystem and overwrites
`HOMEBREW_PREFIX`; caller environment is not proof of an installation root. Casks can
operate outside that prefix. Sixteen explicit Cask destination categories are bound
independently with last-value precedence per option. Unknown/empty/escaping destinations
retain normal path checks; they supplement, never replace, the unknown overall scope.
Neither those paths nor `--appdir` sandbox installer code. Root `brew --prefix` is a query,
not an install destination override.

Service control, Brewfile/Ruby/external execution, tap setup and unknown entrypoints use
`opaque_on_unresolved` with the existing resolve-gap approval policy, not fabricated PIDs
or Bash children. Installation dry runs remain opaque due to unbounded bootstrap,
auto-update and definition evaluation. Documented cleanup/autoremove/link/unlink previews
omit modeled transaction modifications/deletions. Bare `--json` does not consume the next
package; existing form-prefix binding retains `--json=value`, respecting `--` data boundaries.
The binder, dispatcher and risk Passes are unchanged. This adds a Profile and manager
identity, no dynamic probes, Harness fields or dependencies, and runs no host package or
service operation. Hidden configuration/Ruby bodies, dependency closures and custom
installation layouts are outside this static CLI scope.

### Package-source roles instead of filename guesses

Package provenance uses the bound parameter's `package_locator.locator_kinds` together with a statically resolved argv value. It does not infer a definition file from `.txt`, `.in`, `.lock`, or the word `requirements` in a filename.

The shared classifier first obtains the semantic argv value, preserving the distinction between unresolved shell expansion and literal data. It then checks explicit local-path, HTTP(S) and VCS URL syntax against the kinds declared by the Profile. A definition-file parameter with one declared local role retains `requirement_file` for extensionless, relative and absolute filenames. Ordinary package parameters can retain `registry_ref`; the existing manager-specific precedence for slash-bearing package references is unchanged. Conflicting local roles, unsupported URI forms and unresolved arguments produce `unknown_dynamic` rather than disappearing or becoming a registry package by fallback. Unknown is an analysis result even if a Profile lists only concrete input kinds.

For example, `pip install requests.txt` treats the operand as a registry reference, `pip install -r requests.txt` as a definition file, and `pip install -e requests.txt` as a local source. `pip install -r input` and `conda env create -p env -f environment.yml` likewise identify definition files without inspecting their contents or testing filesystem existence. The pip `-r` declaration permits a local definition file or a direct URL, consistent with the [official option contract](https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-r).

Known local inputs retain path-content provenance and known URLs retain network-source provenance. Literal `$` characters in a quoted or already materialized filename are not re-expanded. Simple shell `~/` expansion can use the request's supplied home; named-user lookup and host-state probing are not performed. Source classification does not itself grant approval: existing guards and policy configuration still decide the action. This contract does not claim complete package-manager locator grammars or interpretation of definition-file contents.

The existing imported-package execution guard checks every source consumed by the current invocation, not just its first package. Its trigger is the existing `executes_imported_package_logic` fact; calls without that fact skip source-edge traversal. Only `Consumes` edges labeled `ImportedPackageLogic` to imported-package artifacts participate. Each distinct invocation/artifact pair receives its own evidence and existing source policy, and ordinary decision assembly retains `Deny > NeedApproval > Allow`. Repeated operands or slots consuming the same artifact do not duplicate findings, while separate invocations and distinct source kinds remain separate. Pure downloads, previews and queries are not package execution merely because their Graph contains package artifacts. This adds no pass, Profile-name special case or full-session graph scan.

### Opt-in unresolved operation semantics

A Profile may declare `opaque_on_unresolved: true` (default `false`). Failed or ambiguous
form selection, unknown subcommands, binding residuals, unconsumed arguments, partially
modeled short-option clusters and missing option operands then retain an
`operation_semantics_unresolved` fact. Option values and data beyond a declared option
boundary are not reclassified as options. Known effects and operands are retained;
uncertainty does not erase resolved path or package-source semantics.

The existing `ResolvePolicyPass` handles the `opaque_invocation` resolve-gap category,
defaulting to `NeedApproval`. Profiles declare uncertainty, not policy actions. Its action
can be configured through `policy.resolve_gaps.opaque_invocation` (`allow`, `need_approval`,
`deny`); observing uncertainty does not disable other guards. The fact survives Graph,
snapshot, decision trace and execution-semantics queries. Old stored facts without this
field read as `false`; false is omitted from JSON. Profiles without the declaration keep
the previous selection/binding policy. There is no new Pass or command-name exception;
whole-argv accounting runs only for opted-in Profiles.

### Yum: independent package sources and installation targets

The Yum Profile declares `manager: yum`, not Apt or an alias for DNF/DNF5.
The pinned [official source](https://github.com/rpm-software-management/yum/tree/4ed25525ee4781907bd204018c27f44948ed83fe)
permits options before and after commands. Install/update/reinstall/synchronization/removal
declare `write_path` on the installation directory, defaulting to `/`; the last explicit
`--installroot` wins. Unknown, empty and relative roots do not fall back to `/`.
This represents directory-level modification, including RPM DB updates during uninstall,
not deletion of the root or an enumeration of package files. Existing workspace and
package-source guards independently check destinations and executable sources.

Queries keep configuration-selected incidental cache writes, not installation transactions.
Explicit `--downloaddir` is checked normally: even repository setup for a query may create it
([setup](https://github.com/rpm-software-management/yum/blob/4ed25525ee4781907bd204018c27f44948ed83fe/yum/repos.py#L152),
[directory setter](https://github.com/rpm-software-management/yum/blob/4ed25525ee4781907bd204018c27f44948ed83fe/yum/yumRepo.py#L777)).
`--downloadonly` retains sources and outputs without modeled installation logic;
`--cacheonly`, `--assumeno` and `--nodeps` are not inferred to be transaction-free.
Cache deletion keeps an unknown actual target and requires approval, not a cache-write exemption.

Ordinary install selects a local `.rpm` only if it exists or is remote
([native branch](https://github.com/rpm-software-management/yum/blob/4ed25525ee4781907bd204018c27f44948ed83fe/cli.py#L1013)).
The unresolved local/registry alternative remains `unknown_dynamic`, not a suffix-guessed
local classification. `localinstall/localupdate` instead declare an explicit local role;
URLs remain separately classified. Synchronization modes `full/different` are not package
sources; whole-environment updates and dependencies do not fabricate concrete package nodes.

Explicit config, arbitrary setopts, plugin selection, unsupported commands, group transactions,
history replay and Yum's own shell/transaction language use the opt-in
`opaque_on_unresolved` declaration and existing resolve-gap approval,
not Bash parsing. No new Pass, dynamic probing, request field or command-name exception is added.
Opaque configuration, RPM macros, package scriptlets/triggers, GPG key setup, preinstalled plugins
and filesystem aliases are outside this static CLI scope; installroot is not a sandbox proof.
This validates traditional Yum, not distribution-specific DNF implementations of a yum entrypoint.

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

`option_scope: permuted_options` opts into the same declaration-driven ownership scan but continues past non-option operands until the real terminator. Original argv order, spans and provenance are preserved; no argv is physically permuted. `pv input -F --help -o out` binds `--help` as format data, not a help modifier. A required option may own a literal `--`; only a subsequent unowned terminator ends scanning. Attached values remain data even if they repeat option letters, and root/subcommand modifier occurrences retain their own scope. Unknown arity stops certification: established effects before the gap survive, but trailing option-looking tokens are not invented as confirmed controls. Legacy `all_arguments` and `leading_options` defaults remain unchanged.

Profiles may opt into `selection_failure_effects` to preserve operand-independent effects when form selection fails. Each effect uses normal validation and must have `target: {kind: none}`; no unbound operand is fabricated. Omission leaves existing Profiles unchanged. The effects enter the partial binding and their ordinary analysis rules, rather than overriding the global resolve-gap action. Redis uses an opaque database operation for this fallback.

`matcher: {kind: ascii_case_insensitive_literals, values: [GET, MGET]}` matches complete ASCII-case-insensitive values without compiling a regex. `gEt` matches, but `GETDEL` does not; regex metacharacters are literal and no Unicode case folding is applied. Empty sets and empty entries are rejected. Existing literal and regex matchers retain their behavior.

Option name matching is a separate declaration: `option_matching: exact_names` matches complete declared names such as NVIDIA's `-pl` and `-nic`, without interpreting their letters as short-option clusters or guessing attached short operands. Long inline values such as `--power-limit=200` still follow the declared operand binding. Omission defaults to `short_clusters`, preserving existing matching behaviour. Subcommand nodes inherit their enclosing node's mode unless they explicitly override it; inheritance is resolved when the Profile is loaded. The selected mode governs modifier matching and constraints, form/remaining selectors, parameter binding, leading-option scanning and partial binding after selection failures. It does not change Bash parsing, add a risk pass or determine the decision action.

For example, a Profile with `option_matching: exact_names` can declare `flags: ["-pl", "--power-limit"]` and bind the following value to a plain `power_watts` parameter. `-pl 200` binds that value without activating `-p` or `-l`; `-pl200` does not infer an attached operand. This mode is not a universal CLI validity or coverage check: the existing `all_arguments` binder does not report every unknown flag as a residual. Known unsupported forms and configured resolve-gap actions remain distinct from successfully modelled calls.

A command Profile may opt into `option_prefixes: dash_and_plus`. Its materialized CLI arguments then recognize both signs without conflating them: `+c` and `-c` can have different modifiers and operands, and both `++` and `--` terminate option parsing. Short clusters and attached operands retain their sign. This root-level grammar also applies to the Profile's subcommands, not to separately dispatched tools. With `leading_options`, option ownership still stops at the first non-option operand; a declared option's value is not reinterpreted as another option or terminator. The default is `dash_only`, so values such as `date +%F` and `chmod +x` remain data. The declaration does not change Bash tokenization, argument text/spans/provenance, risk rules or the Harness protocol. The default projection fast path returns without scanning or cloning argv.

`operand_mode: optional_next_arg` is an additive flag binding mode: an attached short or inline long value binds first; otherwise only the immediate non-option argument may bind. A following option/terminator stays available to its own parser, using the selected Profile's prefix grammar. Absence is accepted for `optional_one`/`optional_many`; required cardinality still reports a missing operand. An explicitly present empty value is not absence, and a present value rejected by constraints remains an unresolved operand even with optional cardinality. Older operand modes are unchanged. For example, `lsof -i`, `lsof -i :8080`, and `lsof -i -n` bind respectively no selection, `:8080`, and no selection plus a separate `-n` option.

The lsof Profile treats file/directory, PID, descriptor and socket selectors as metadata query values, not selected-file content reads, process control or listener creation. The actual `+m file` mount-supplement read is distinct; bare `+m` has no fabricated file output. Native `-D` cache operations and unsupported dialect forms use `opaque_on_unresolved` and existing approval. Numeric options that can re-enter native option parsing admit modeled complete numeric/repeat specifications rather than swallowing arbitrary suffixes as data. Outer shell redirections and dispatched children retain their independent semantics. This scope does not replay every version/build-specific selector or resolver/implicit-cache implementation.

Prefix bindings can optionally declare `binding: {kind: args_with_prefix, prefix: '-D', before_dash_dash: true}`. This binds only unconsumed prefix arguments before the option terminator. Declared option operands are consumed first, so a literal `--` used as an option value is not mistaken for the delimiter; an actual later `--` still ends the binding. The binding does not consume the delimiter or trailing data. Omitting the declaration, or setting it to `false`, preserves legacy prefix binding across the whole scope. Thus `ss -Ddump -- state established` retains the `dump` write, whereas `ss -- -Ddump` does not invent a write from filter data. This is a command-independent, opt-in binding declaration, not a new risk rule.

Command Profiles describe where a command can dispatch execution and how its arguments are bound. The dispatch layer carries each argument as a typed value: literal argv data, a runtime-produced value, or an implicit input with a conservative domain. Consumers may use a bounded path domain to classify possible locations, but it is not a claim that any listed root is the concrete file actually acted on. Unknown input and known-empty input remain distinct.

A dispatch target can opt into `stdout_to_parent: true`. The existing stream-provenance pass records a child `Produces` edge and parent `Consumes` edge through a `dispatch_stdout` artifact. Its bytes remain unknown, while the child's modeled inputs retain their origin. Parent pipelines, output redirections and explicitly declared wrapper chains can then trace that origin. This is independent of `stdin_from_parent`; a control/dispatch edge alone does not imply output inheritance. Each direct dispatch uses its own declaration rather than inheriting an outer wrapper's flag, and omission defaults to false. Canonical nested Bash command-string scopes supply pipeline node identities so these edges do not connect only to legacy duplicate nodes. No new risk pass, dynamic file/process probe or Harness protocol field is introduced. This does not infer arbitrary interpreter internals or replay all FD redirection semantics.

The pv Profile models ordinary file/stdin transfer, explicit output and staging files, PID-file replacement/removal, numeric descriptor progress queries and typed monitor child dispatch. `-o -` means stdout; `-U -` generates temporary storage and retains unknown write/delete targets. Cursor lock storage is also unknown. Remote reconfiguration, query IPC (which can write control files and signal a process), name/list-file watch selectors and unsupported forms use existing unresolved-operation approval. Repeated explicit targets are retained conservatively; no implicit-cache exemption or native execution replay is claimed. Env declares child stdout inheritance too; other dispatch profiles must explicitly declare it before gaining this data-flow bridge. Curl's missing `@file` content-read modeling is a separate coverage gap: pv staging provenance tests use an explicitly modeled file reader, not an unmodeled curl file input.

The `find -exec`/`-execdir` and `xargs` profiles feed the same dispatch and execution-graph machinery. `find` arguments may carry a bounded search-root domain; symlink-following, unresolved roots, and `-execdir` context that cannot be established widen that domain or leave it unknown. `xargs` static input is used only when its source is known complete; partial fragments are advisory, not a proven argv prefix, and incomplete or runtime-generated input leaves arguments unknown. Explicit stdin redirection takes precedence over pipeline input.

Known argv data is never parsed again as shell source. A shell `-c` operand is the intentional exception at the payload boundary: it is parsed once as code, while its positional arguments remain typed data and are bound separately. Recursive inline execution uses the canonical execution frontier so graph expansion is bounded by the configured depth and preserves source relationships. This models common cases conservatively; it is not a complete shell, `find`, or `xargs` interpreter.

The default expansion depth is 8; the top-level command is depth 0. Reaching depth 8 is not itself a risk: a fully analysed leaf uses the normal decision rules. If child execution remains beyond the budget, expansion stops and the existing resolve-policy pass proposes `NeedApproval` under `execution_expansion_limit`. The decision trace retains the truncation evidence, depth budget and pending candidate count. This applies to both the canonical execution frontier and nested-payload truncation; a parsed ancestor or the default Observe action for unsupported static literals does not hide an incomplete expansion. Existing `Deny` findings still take precedence.

## Optional inline operands and matching positional arguments

`operand_mode: optional_inline_only` accepts either a bare option or a long
`--option=value`. A bare option never consumes the next argv token, including
positionals, other options and terminators. Optional cardinality accepts absence;
required cardinality still requires a value. An explicit empty inline value is
present, and a value rejected by constraints remains unresolved. Short attached
values are not part of this mode. Existing operand modes keep their behavior.

`binding: {kind: positionals_matching, matcher: {kind: regex_pattern, pattern: '^[/.]'}}`
selects matching, unconsumed positional arguments throughout the owned scope,
not just a contiguous prefix. It matches the decoded literal semantic value but
retains the original argument, quote state, node kind, span and binding source.
Known runtime argv data is not expanded again; unknown dynamic values are not
guessed from a visible prefix. Declared option operands cannot be reclassified as
positionals. Unmatched arguments stay available to later bindings. Regex matching
compiles once per binding; unselected profiles do not execute this binding.
Legacy `args_with_prefix` still extracts the payload after its prefix.

## GNU Mailutils mail

The `mail` Profile models GNU Mailutils 3.21, not BSD mail/mailx or s-nail.
Nonterminal body and attachments are data; `-A` attaches a file while GNU `-a`
adds header metadata. Email/local-alias recipients are lexical `email_address`
endpoints with `upload_target` usage, not URLs. Filesystem recipients starting
with `/` or `.` retain full paths. Leading `|`, Mail-language `-E`, header-derived
or unresolved destinations and unsupported client controls use existing opaque
approval rather than pretending the entire value is Bash code.

GNU `-f` is a switch selecting the first positional mailbox; optional inline
`--file=mbox` and bare `--file` retain their distinct argv ownership. Mailbox
queries keep real read/write effects because native open/scan can create mailboxes
or update UID headers. `--no-config`, system mailrc and `MAILRC` are separate
layers; `-n` only disables system mailrc. Explicit output recipients, failure
`DEAD` storage and genuinely unknown compose-spill/byname targets keep mutation
effects. Ordinary sending is therefore not promised approval-free. No dynamic
config interpretation, Mail interpreter or automatic dialect discovery is added.

The existing tainted-execution analysis currently overapproximates all network
endpoints as inputs, including upload destinations on commands loading startup
configuration. This independent precision limitation remains unchanged. Graph-only
tests explicitly isolate it and unknown-spill policy; default-policy diagnostics
and sensitive-data/opaque-command checks remain separate.

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

## MySQL opaque client protocol

The `mysql` Profile targets the official MySQL 8.4.6 client, not MariaDB.
SQL, initialization SQL and stdin/interactive client input declare an opaque
database operation and use the existing database guard. `SELECT`, safe-updates,
binary-mode and disabled client commands are not whole-call safety proofs.
`mysql_cli` is language metadata for mixed SQL/local client commands, not a SQL
interpreter or a Bash parser. Outer Bash substitutions and redirections remain
independently checked.

Explicit configuration, TLS/plugin paths, tee outputs and host/socket endpoints
remain independent facts. Database names are plain values, not filesystem paths;
localhost or a workspace socket does not establish database ownership. Required
operands retain native option ownership, including flag-shaped values. Optional
long values use only `--option=value`, never the following word. Path projections
retain decoded semantic paths alongside the original quoted argument.

Defaults load before help/version processing. `--tee` opens its append target
during option parsing, before final batch-mode suppression, so batch/help and a
later disabling flag do not erase that potential write. This version does not
replay the exact order of native callbacks. Only a pure information call whose
first two semantic argv words are `--no-defaults --no-login-paths` omits opaque
startup approval; other declared modifiers, positional data, malformed/unknown
forms or an unproven prefix retain it. A whitelist-completeness regression
requires every future modifier to undergo explicit information-admission review.
Bare `-p` does not consume the following database; `-pVALUE` and `--password=VALUE`
are optional attached/inline operands, not safety exemptions. These are bounded
CLI contracts, not a claim of full client coverage.

Two additive DSL declarations express these contracts without command-name
branches. `operand_mode: optional_inline_or_short_attached` accepts a long-inline
or short-attached value, never the next argv word after a bare occurrence;
cardinality, constraints, option scope and residual audits still apply.
`{kind: has_argument_at_matching, index: 0, matcher: {kind: literal, value: --no-defaults}}`
matches a known semantic value at its original zero-based tool argv position,
excluding the executable but including subcommands, flags, operands and
terminators. Consumption and a remaining selector do not reindex it. Only
referenced positions are projected; argv/source metadata is not rewritten.
Literal quoting is decoded, already materialized runtime data is not re-expanded,
empty literal words remain data, and missing/unknown values do not match.
As with other Boolean matchers, a negated non-match is not proof of absence;
security admission should use positive known-value predicates. Direct shape
selection can supply known indexed values through `with_argument_at`.

Potential interactive history retains `MYSQL_HISTFILE` or `~/.mysql_history`;
its derived temporary target is unknown rather than fabricated. Batch, quick
and inline-execution forms omit that possible history write. No configuration
contents, TTY, filesystem, process or database state are dynamically inspected.
No new risk pass, policy default, dependency or Harness field is added.
Sources: [client options](https://dev.mysql.com/doc/refman/8.4/en/mysql-command-options.html),
[client commands](https://dev.mysql.com/doc/refman/8.4/en/mysql-commands.html),
[pinned client implementation](https://github.com/mysql/mysql-server/blob/3f821bcb4ee93cd90c0ffa0f8e17bb9677502acf/client/mysql.cc).

## Further Reading

- [How Caushell works](how-it-works.md)
- [Security model: risk analysis, decisions, and the execution boundary](security-model.md)
- [Configuration](configuration.md)

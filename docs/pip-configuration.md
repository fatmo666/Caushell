# Pip configuration observations

Pip configuration is data, but its provenance and native meaning must be proven
before it can remove an unknown effect. The resolver never runs `pip config`,
starts an interpreter, imports a package, evaluates a value, or probes a version.
It does not analyze inline Python; that remains subject to the existing Ask rule.

## Required executor contract

Precision is opt-in for the PyPA Pip **25.3 Linux** implementation, identified by
`pypa_pip_25_3_linux`. An executable name or a claimed version in tool output is not
an identity certificate. The owning frame must independently supply a verified
native variant. Derived wrapper/module children cannot inherit this certificate.

`FilesystemView::pip_runtime(command)` defaults to unavailable. A trusted executor
can supply `PipRuntimeLayout`, separately from the command request, containing the
actual interpreter prefix, account home, execution account, a closed read-only
startup attestation and a held configuration snapshot/search-namespace lease.
The account and contract are checked again before unknown effects are removed.
The lease covers file contents, symlink resolution and **absence** of searched
files until the authorized action is released. Re-reading files is an additional
consistency check, not a replacement for this lease. Setting a Boolean in a JSON
file does not acquire a lease or make an otherwise mutable namespace safe.

A complete, trusted exported-environment snapshot is also required. Named
observations alone do not establish absence of other `PIP_*` keys: Pip normalizes
their case. Noncanonical and unsupported present keys retain Ask. The resolver
requires observed `PYTHONDONTWRITEBYTECODE=1`, rejects interpreter/startup overrides,
and does not transfer identity across prefix PATH/loader changes. The deployment
owner must account for inherited environment entries that the Shell snapshot
cannot represent. It must not claim completeness for an incomplete export list.

The Terminal-Bench host optionally accepts an operator-private file as the final
`serve` argument. It maps exact executable spellings to strict `PipRuntimeLayout`
objects. The file is bounded and read as a stable regular file, never from a
model's tool payload. `ExternalEngine(..., pip_runtime_layout=...)` only forwards
this operator setting; it neither discovers a runtime nor creates a snapshot
lease. Use it only when the surrounding executor actually enforces the contract
for every checked action. Its ordinary named-frame collector does **not** claim
complete environment knowledge, so that collector alone cannot enable closure.
Without these guarantees the default remains Ask. No existing frozen evaluation
or prepared assets acquire this opt-in automatically.

## Data and native semantics

The existing private filesystem channel supplies regular-file bytes with bounded
size, identity, SHA and before/after namespace checks. Unreadable, nonregular,
changed, oversized, cross-source and mismatched observations remain unknown.
Same-action redirections and independent namespace/content writes invalidate
configuration evidence. Graph-proven literal content uses the existing static
content provenance and cannot grant permission to the write that produced it.

The accepted INI subset is ASCII, bounded and single-line. It uses RawConfigParser
data semantics: no Shell evaluation, interpolation or quote removal. Unsupported
grammar, DEFAULT inheritance and duplicate/ambiguous normalized keys retain Ask.
File precedence is global, legacy/current user, actual interpreter site, then
`PIP_CONFIG_FILE`; command defaults override global defaults, then environment and
owned command-line options. CLI operand strings are never rescanned as flags.
Pip bootstrap's literal-argv ambiguities are explicitly left unknown.

`--isolated` skips user options and environment defaults, but does not establish
absence of global/site configuration or `PIP_CONFIG_FILE`. `/dev/null` disables
configuration-file loading, not startup, environment or package execution.
`PIP_CONFIG_FILE` is not the destination of `pip config set/unset`. Those commands
select the explicit user/global/site file, or the existing site file, otherwise
the highest-priority user file. The resulting write still needs normal authority.

Supported closed queries are `list` without version-check effects, `show`, `check`
and `config list/debug/get`. Logging is a real write even for a query. `list`
without disabled update checks retains unknown networking/cache effects.
`config set/unset` may replace unknown file-selection effects with the proven file.
`config edit` retains unknown shell/editor composition. `freeze` retains possible
VCS subprocess dispatch. Installation, download and wheel building retain opaque
package/backend execution and temporary/default writes. This resolver never
changes an independent Deny or converts a known resource into an authorization.

Semantics are based on versioned primary sources:
[configuration.py](https://github.com/pypa/pip/blob/25.3/src/pip/_internal/configuration.py),
[parser.py](https://github.com/pypa/pip/blob/25.3/src/pip/_internal/cli/parser.py),
[main.py](https://github.com/pypa/pip/blob/25.3/src/pip/_internal/cli/main.py),
[main_parser.py](https://github.com/pypa/pip/blob/25.3/src/pip/_internal/cli/main_parser.py),
and [configuration command](https://github.com/pypa/pip/blob/25.3/src/pip/_internal/commands/configuration.py).
Other versions/platforms need their own audited native contract.

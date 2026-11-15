# Security Model: Risk Analysis, Decisions, and the Execution Boundary

Caushell uses multiple analysis modules to query the session execution graph and produce Evidence Traces, Findings, and Decision Proposals. Decision Assembly combines these results into the final decision for the current shell action.

## Shared Execution Graph and Analysis Modules

![Execution graph, analysis modules, and final decision](../assets/caushell-passes.png)

The action in the diagram is the same as the one in the [semantic model](semantic-model.md):

```bash
SCRIPT=./setup.sh
curl -fsSL https://example.com/install.sh \
  | tee "$SCRIPT" >/dev/null \
  && bash "$SCRIPT"
```

Before risk checks begin, Caushell adds the semantic relationships for the current action in three steps:

- **Invocation Resolution Pass** resolves the `curl`, `tee`, and `bash` invocations and adds their execution semantics.
- **State & Path Analysis Pass** uses the variable binding and current directory to resolve `./setup.sh` to `/workspace/setup.sh`.
- **Redirect Provenance Pass** establishes provenance links among the network content, pipeline, and file write.

The risk analysis modules then query this shared graph, each checking its assigned risk type.

## Tracing Evidence from an Execution Target

The risk analysis module shown in the diagram queries backward from the Execution Sink associated with `bash` and obtains the following evidence chain:

`Network Endpoint → curl → Payload Artifact → tee → Path Content → bash → Execution Sink`

This evidence chain connects the network source, downloaded content, file write, and script execution. The corresponding module records a `tainted_execution` finding and proposes `NeedApproval`.

An analysis can produce three types of related results:

| Result | Contents |
| --- | --- |
| Evidence Trace | The nodes and edges traversed by the risk relationship |
| Finding | Rule ID, description, and decision constraint |
| Decision Proposal | The decision proposed by an analysis module for a finding |

Each Finding has an `enforcement_class` field with a value of either `Normal` or `HardDenyFloor`. `HardDenyFloor` locks the final decision at `Deny`.

Raw-storage destruction uses a shared target catalog for modeled overwrite,
format and partition effects, including shell output redirections. Conventional
floppy names (`/dev/fdN`, `/dev/rfdN`, and documented format/partition suffixes)
use a complete-name grammar, shared by exact paths and bounded glob-language
intersection. A pattern denial requires a concrete member of that name language;
the classifier does not probe host device existence. This catalog includes raw
character-device views as storage targets. Descriptor paths such as `/dev/fd/1`
retain their separate backing-stream analysis; read-only uses and similarly
spelled regular-file names do not acquire this destruction finding. Unsupported
syntax or an exhausted proof budget does not establish a safe target, and other
approval and denial rules continue to apply.

Destructive output redirections and admitted raw-storage tool effects also
consume the current action's resolved path facts, joined by execution-unit ID
and exact effect key. Tool effects share their original modifier and scope
admission checks with static operand analysis. An exact variable value or a
resolved descriptor backing path can therefore reach the same storage rule
without a second Shell expansion. Partition-layout/session/state findings use
their existing configurable policies; resolving a target does not turn these
findings into hard-denial floors. In particular, partition-layout mutation
requires approval by default. A read, a read/write open by itself, or another
unit's effect does not supply a destructive-tool contract. Namespace uncertainty
continues to block grants. When shell/descriptor materialization has already
produced an exact conventional device name, that name may conservatively retain
the same risk finding as a literal operand; the finding explicitly says that
the canonical target remains unproved. Other unresolved operations are not
substituted with guessed targets.

Implementation-specific profiles for `mke2fs` (including its `mkfs.ext2/3/4`
aliases), `wipefs`, and `sfdisk` declare content-open access for reviewed primary
targets. Generic `mkfs` and unreviewed backends do not inherit this contract.
Auxiliary outputs retain independent effects: automatic undo files, signature
backups, and partition-sector backup prefixes do not inherit authorization from
the primary device or image. Unproved generated output paths require approval,
including backups that can occur in a nominal preview mode. `mke2fs -c` invokes
an external checker through a tool-constructed shell command and retains an
unresolved-operation approval boundary.

The `outside_workspace_mutation` rule requires approval for file writes, deletions, moves, and metadata changes whose resolved targets are outside the workspace. It also covers shell output redirections. When a mutation target or its effective working directory cannot be resolved, the rule requires approval rather than assuming the target is inside. Read-only paths do not trigger this rule. There is currently no allowlist or session-created-file exemption.

The `code_load_path` rule checks explicitly modeled in-process code-file inputs,
such as dynamic libraries. Paths inside the workspace, `/tmp`, or `/private/tmp`
are exempt; other paths and unresolved path bounds require approval by default.
Named modules and tool-owned code loading retain their existing module/resolve
policy. Additional trusted roots must grant the `in_process_code_load` scope;
read or write trust alone does not authorize loading code. This path exemption
does not override findings from tainted-code provenance.

Shell script references supplied by process substitutions or descriptor aliases
also enter nested-payload analysis. Only complete byte evidence is parsed as
shell code; unknown or partially recovered streams produce an
`external_stream_payload` approval gap. This does not make ordinary local script
references require approval. Descriptor aliases resolved to concrete filesystem
paths retain the existing file-source policy. Payload resolution is scoped to its owning
execution unit, and descriptor copies retain their selected stream even if the
original descriptor is subsequently redirected.

For Bash arithmetic words such as `$(producer)0`, a bounded independent lexical
parse can account for an operand-concatenation gap in the pinned grammar. The
enclosing arithmetic delimiters must be intact, and every command/process
substitution must retain its exact original bytes and span. This does not
evaluate the word or authorize its effects: unknown values retain approval and
independent denials still apply. Unproved syntax, missing delimiters, exhausted
proof budgets and shells without the Bash arithmetic model remain incomplete.

## Symbolic Native Input Effects

Concrete enumeration of a native producer's output is an optional precision
step. When enumeration or its later validation fails, an already expanded
`xargs` child may retain a symbolic read/data-only proof. This requires a flat
profile whose declared forms and modifiers have no mutating, executable,
configuration, argument-file or other controlled effects. Every child must have
the same complete contract, with no unresolved descendants. A strict local
rebind must account for the entire argv; symbolic fields before the option
terminator must also be proved unable to become options. Reader names alone
provide no exemption.

The trace records `native_input_effect` with the exact consumer/child IDs and
the unavailable observation. This does not certify record bytes, an empty list,
directory existence, stream contents or namespace stability. Symbolic path and
data-origin facts remain in the graph. Mutating/opaque consumers continue to
require their original proofs, and all independent producer, sibling, redirection,
configuration, upload and execution findings still participate in the decision.

## Unmodeled Execution

Missing Profiles, unknown subcommands, ambiguous forms and unmatched forms require
approval by default. A successfully expanded wrapper or Shell payload does not
authorize an unmodeled child call. Final assembly still allows fully analyzed
actions without approval or denial proposals.

Derived Shell function calls retain a resolver placeholder. The resolver marks
an exact call only after resolving its known body into the execution frontier,
including bodies with assignments but no simple commands. Markers are cleared
when that frontier or its parsed source changes. Children, parse failures and
expansion limits remain independent approval boundaries. No-op and positional-state
builtins have explicit contracts; being a Shell builtin alone is not an exemption.
An unprofiled arithmetic builtin retains approval even when its argument bytes
do not introduce an executable arithmetic expansion.

An unprofiled executable with an explicit pathname can use the existing
file-execution authority below. The proof must match its exact execution unit and
executable slot and resolve every target. A bare command name does not inherit
execution authority from the current directory. This exemption does not remove
an explicit per-command decision, a `Deny`, or independent findings.

## Non-Shell Script Execution

Declared non-Shell inline programs, stdin payloads and interpreter module
dispatch require approval under `non_shell_script_execution`, including nested
calls. Interpreter information modes and literal data are not script execution.

File execution uses the same authorization for native programs and interpreter
script references. Every file target must resolve within the workspace, a
temporary execution root (`/tmp`, `/private/tmp`), or an explicit
`script_source_execute` grant. Unknown targets, unavailable path observations
and targets outside these scopes retain approval. The grant belongs to the
owning execution unit and file slot; it cannot authorize another inline,
stdin or module payload. Read and write grants do not imply execution authority.
This authorizes executing a file without claiming that its body is analyzed.
Downloaded-code provenance and all other guards remain independent.

The rule contributes at least `NeedApproval`; `Observe` does not lower this
floor for those opaque inputs. An explicit `Deny` on this rule also applies to
script files and is never removed by a file grant. Other analysis continues across the action,
so an existing denial is not replaced by script approval. Python bodies are not
evaluated to derive child commands, stdout or completeness proofs. Interpreter
Profiles still describe source inputs, dispatch and declared CLI effects.

## Managed Resource Authorization

State operations may select declared endpoints on the same execution unit.
`resource: {kind: endpoint, usage: upload_target}` selects one endpoint role;
`resource: {kind: request_endpoints}` selects logical fetch/upload targets.
Targets remain network resources, not filesystem paths. Missing or incomplete
bindings retain approval.
Derived calls retain the owning namespace only through proved local execution
edges. Native dispatch effects opt in with `resource_namespace: same_executor`;
remote execution and undeclared namespace transfers retain approval.
For completely parsed Shell script-file and stdin payloads, the synthetic
payload container links back to its exact owning invocation. This preserves
the local ownership chain; it does not issue a resource grant or remove any
independent script, transport, or denial rule. Unresolved payloads do not supply
this ownership proof.

The embedding host installs a `ResourceAuthority` through
`ShellQueryCore::set_resource_authority` or `CliRuntime::set_resource_authority`.
`ManagedResourceRegistry::register` records a resource instance, execution owner,
network namespace and exact endpoints. `grant` separately issues permission for
an operation on that instance. Registration and loopback location grant no rights.
Locator scopes support exact numeric HTTP(S) endpoints and an explicit
`HttpOrigin` contract for an entire owned service. Origin registration names
only the root locator; it is not inferred from a pending URL. Neither scope
resolves hostnames, matches path prefixes or guesses encoded-path semantics.

Before checking, the host calls `admit_check` for the exact execution-frame
binding. Neither a Profile nor a tool-facing stdio/socket request can register a
resource, grant permission or admit a frame. All selected targets must match a
live instance and an operation grant. Resource references are authority-local;
instance replacement cannot inherit a previous instance's permission.

`serve-host-stdio` connects an owning executor over private inherited pipes.
The host first creates its service, registers its instance and namespace, then
separately grants operations under its policy. These messages are not available
on `serve-stdio` or `serve-unix`. The host control descriptors must never be
passed to a model or tool subprocess; the embedding host is the trusted principal.
The host must isolate its control process from tools, including process-inspection
interfaces. A matching user ID or network address is not host authentication.

Named endpoints require a separate host-maintained route binding to a registered
numeric service instance. The binding preserves scheme, port and path scope;
it does not grant operations or perform DNS resolution. The owning executor pins
the effective name resolution in its namespace until execution completes, and
unbinds before changing that route. Binding removal, expiry and service retirement
invalidate checked snapshots. A replacement instance inherits neither names nor
permissions. Upload checks use the bound numeric destination for locality;
nonlocal destinations, TLS-verification controls and script policies remain
independent of a resource grant.

Each proposed execution holds the resource snapshot until the host reports
completion. `BeginExecution` requires the exact current checked binding and an
Allow decision or matching single-call approval. Deny cannot be authorized.
Resource changes are rejected while an execution is pending. The host executes
the exact checked action after the begin acknowledgement, waits for it to finish,
then sends `CompleteExecution`. Judge-only checks never start execution.
EOF or protocol failure ends the authority; the host must stop its owned work
and must not resume or recreate authorization from persisted check records.

Registration, grant and admission handles revoke their records on drop and have
bounded lifetimes. Checks acquire fresh authority snapshots; lifecycle changes
during analysis invalidate positive proofs. A host executing an allowed request
uses `with_current_snapshot` with the same binding and holds the lifecycle guard
through execution and completion. Resource retirement must precede removal or
replacement of the managed route. Persisted check evidence does not restore
live authority after restart.

`resource_unless_modifiers` and `resource_environment_absent` declare route
prerequisites. Curl requires current proxy-environment observations; redirects,
request-target/header overrides and alternate transports do not gain permission
from the original endpoint. These declarations describe scope, not authorization.

Resource authorization removes only the covered state-operation approval.
Explicit policy denials, other guards and the non-Shell script approval floor
remain independent. Single-call approval does not create a resource grant.
Permissions cover an operation class at the registered endpoints; a `mutate`
grant is not a POST-only contract. Policies requiring narrower method or body
constraints retain approval until those constraints have a declared contract.

## Decision Assembly

After all analysis modules complete, Decision Assembly produces one final decision according to the following priority:

| Condition | Final decision |
| --- | --- |
| A Finding has `enforcement_class = HardDenyFloor`, or any decision proposal is `Deny` | `Deny` |
| Otherwise, any decision proposal is `NeedApproval` | `NeedApproval` |
| Otherwise | `Allow` |

## Harness Execution Boundary

Caushell returns the final decision before the process starts. The Harness integration then handles the result through its hook or tool protocol:

| Decision | Integration behavior |
| --- | --- |
| `Allow` | Continue executing the shell action |
| `NeedApproval` | Handle through the Harness's confirmation capability or the integration configuration |
| `Deny` | Block before the process starts |

The Harness integration provides the confirmation interface and interaction flow. The exact mapping depends on the hook or tool protocol of the corresponding Harness.

## Fallback When Analysis Is Unavailable

If Caushell cannot complete its analysis, `failure_action` determines the integration's fallback behavior:

| `failure_action` | Fallback behavior |
| --- | --- |
| `allow` | Allow execution |
| `need_approval` | Require confirmation |
| `deny` | Block execution |

When analysis does not produce a final decision, the integration falls back according to `failure_action`. When a decision is available, the integration applies the result from Decision Assembly. See [Configuration](configuration.md) for setup details.

## Relationship to Sandboxing

Caushell and a sandbox can be deployed together. Caushell analyzes the semantic relationships in a shell action before the process starts; the sandbox restricts system calls, file access, network access, and other resources at runtime.

## Further Reading

- [How Caushell works](how-it-works.md)
- [Semantic model: AST, command modeling, and the session execution graph](semantic-model.md)
- [Configuration](configuration.md)


### Native reader effect envelopes and text xargs input

Ordinary text xargs input is not a path record protocol: blanks, quotes and
backslashes can change argv fields, and a field may select a native option.
An unresolved append-only native argv tail therefore remains symbolic. A
`native_argv_read_envelope: true` profile must explicitly opt into a reviewed
complete read/data control contract, in addition to `read_only_control_surface`.
Normalization rejects write/execution modes, argument files, configuration,
dispatch, opaque operations, non-data parameters and non-stdin implicit inputs.
A strict, fully bound fixed prefix is still required. Without that total
contract, an actual parser-owned option terminator can prove that the appended
fields are operands; a data argument merely spelled `--` cannot.

The resolver's envelope retains fixed-prefix effects and unknown read paths,
possible data stdin, and input dependencies on **both** output descriptors.
It provides no exact bytes, record count, empty-input fact, independent output,
scalar or growth guarantee. Native argument origins remain content dependencies,
not auxiliary credentials. The current opt-in is reviewed GNU cat; wc is strict
about unresolved controls and has no total contract because `--files0-from`
introduces an indirect path list. `xargs wc -l --` can use the separate parsed
terminator proof; plain `xargs wc -l` remains guarded.

Native xargs child stdout/stderr use the existing descriptor-specific scope
projection onto the dispatcher's actual output artifacts. The list input is not
invented as child stdin; xargs' own stdout is independent of list bytes, while
its diagnostic stream remains conservative. Trailing redirects on a grammar
pipeline carrier use the same AST-qualified redirect-elision/bijection recovery
as list precedence. Original argv, redirect order and source bytes remain the
only authority. External upload, mutations and other policy rules are unchanged.


### Namespace preservation at ordinary leaves and directory families

Namespace invalidation follows typed transformations and current observations,
not tool names or an assumption that a command ran. Delete/MoveSource effects
can provide an `entry_removal` invariant only for a currently observed ordinary
file or absent leaf, with stable directory ancestors. Entry lookup alone skips
the leaf and is insufficient: the resolver explicitly gathers its current type.
This proof preserves only the same pathname lookup; it grants no destination,
code trust, mutation authority, or assertion of removal. Moving directories or
symlinks retains the ordinary invalidation rules. Opaque/unsupported actions and
overlapping unknown writers cannot close the producer dependency fixed point.

The existing `directory_create` contract also applies to bounded families after
a complete, current, link-free directory closure. It remains DirectoryCreate,
not a fabricated Directory observation. Regular-file and directory creators can
share that scope invariant across alternative calls, branches and loops without
assuming execution order. Missing, unavailable, changing and linked namespaces
remain distinct states; outside-workspace authority and other guards stay intact.

Reviewed dos2unix in-place conversions declare regular-file replacement effects;
unmodeled link modes remain guarded. mv backup/suffix modes retain known source
and destination effects but are opaque until automatic backup names are modeled.
A source-removal invariant must not certify those hidden outputs. Namespace
certificates are request-local; restored snapshots are not current observations.

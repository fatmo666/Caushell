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

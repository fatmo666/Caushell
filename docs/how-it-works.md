# How Caushell Works

Caushell completes its analysis after a Harness initiates a shell action and before the process starts, then returns `Allow`, `NeedApproval`, or `Deny`.

![Caushell analysis flow from a Harness shell action to the final decision](../assets/caushell-overall-flow.png)

## From Input to Decision

The Harness integration sends the pending shell action, together with the shell and workspace state visible before execution, to the Caushell runtime. The runtime processes the request in the following order:

| Stage | Processing | Output |
| --- | --- | --- |
| Intake | Read the raw shell action and pre-execution context | Runtime request |
| Syntax parsing | Parse the shell text into a Shell AST | Structured syntax |
| Command modeling | Use Command Profiles and available shell state to determine the role of each argument and the behavior of each command | Command behavior model |
| Session graph extension | Connect the current action's commands, paths, state, and provenance to existing session relationships | Execution graph used for the current analysis |
| Risk analysis | Run multiple analysis modules to inspect risk signals in the graph | Findings and Decision Proposals |
| Decision assembly | Merge all proposals in Decision Assembly | `Allow`, `NeedApproval`, or `Deny` |

Syntax parsing identifies the shell structure. Command modeling adds argument roles and execution behavior to the commands in the AST. Caushell then connects the commands, paths, state, and provenance produced by the current action to existing session relationships, allowing each analysis module to identify risks and propose a decision.

## A Running Example

The following action contains a variable assignment, a network read, a pipeline, file redirection, and a `bash` command:

```bash
SCRIPT=./setup.sh
curl -fsSL https://example.com/install.sh \
  | tee "$SCRIPT" >/dev/null \
  && bash "$SCRIPT"
```

Caushell processes this action as follows:

1. **Intake**: The runtime receives the raw shell text together with the current directory, workspace, and visible shell state.
2. **Syntax parsing**: The Shell AST records the variable assignment, the `curl`, `tee`, and `bash` commands, the pipeline, the `&&` connector, variable expansion, and output redirection.
3. **Command modeling**: Using Command Profiles, Caushell identifies `curl` as reading from the network, `tee` as reading from standard input and writing to a file, and `bash` as executing a script. The same action first binds `SCRIPT` to `./setup.sh`, and the two later variable references resolve to that path.
4. **Session graph extension**: Caushell connects the current action's commands and semantic relationships to the session execution graph. After accounting for the current directory, the graph contains a relationship chain from the network address, downloaded content, pipeline, and target path to script execution.
5. **Risk analysis**: The relevant analysis modules detect that remote content is written to a script file and then executed by a shell, so they propose `NeedApproval`.
6. **Decision assembly**: Decision Assembly combines all findings and proposals and produces the final decision under the active policy.

For command modeling, the execution graph, variable bindings, and provenance, see the [semantic model](semantic-model.md). For risk analysis, decision assembly, and the execution boundary, see the [security model](security-model.md).

## The Three Decisions

| Decision | Meaning |
| --- | --- |
| `Allow` | The current policy allows execution. |
| `NeedApproval` | The current policy requires user confirmation before execution. |
| `Deny` | Block before execution. |

The Harness integration translates the final decision into the corresponding hook or tool behavior. The available confirmation mechanisms vary between integrations; see the [security model](security-model.md) for the execution boundary.

## Further Reading

- [Semantic model: AST, command modeling, and the session execution graph](semantic-model.md)
- [Security model: risk analysis, decisions, and the execution boundary](security-model.md)
- [Configuration](configuration.md)

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

## Session Graph Lifecycle

| Point in time | Graph state |
| --- | --- |
| Before a check begins | The session execution graph contains previously committed session facts |
| During the current check | The analysis view includes nodes and edges produced by the current action |
| Decision is `Allow` | The current action's graph changes are committed to the session execution graph |
| Decision is `NeedApproval` or `Deny` | The request is recorded, but the new nodes and edges are not added to the session execution graph |

Runtime shell state also indicates whether information such as cwd, variables, aliases, and functions is visible and whether it persists across actions. Information supplied by the Harness and confirmed by the runtime can participate in command modeling for later actions; information that cannot be confirmed is recorded as unknown.

## Further Reading

- [How Caushell works](how-it-works.md)
- [Security model: risk analysis, decisions, and the execution boundary](security-model.md)
- [Configuration](configuration.md)

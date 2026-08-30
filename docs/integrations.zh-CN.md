# Harness 集成与执行行为

Caushell 通过 Harness 提供的执行前接口接收 shell action，并返回 `Allow`、`NeedApproval` 或 `Deny`。Harness 再把这个结果转换为继续执行、请求确认或阻断。

Caushell 返回 `Allow` 后，控制权交回 Harness。Harness 继续处理其余权限检查；进程启动后，沙箱和内核限制其实际能力。

```text
shell action
  → Harness 执行前接口
  → Caushell 分析与决策
  → Harness 权限与确认流程
  → 进程启动
  → 沙箱与内核权限
```

## 三种 Harness 集成

| Harness | Caushell 接入点 | `NeedApproval` 的处理 | 能否显示人工确认 | 跨 action shell 状态 |
| --- | --- | --- | --- | --- |
| Claude Code | `PreToolUse`，匹配 `Bash` | 返回 `permissionDecision: ask` | 交互模式显示确认 | 当前 cwd 可跨 action 延续；变量、alias 和函数从当前 action 分析 |
| Codex | `PreToolUse` 与 `PermissionRequest`，匹配 `Bash` | 默认在执行前阻断；`observe` 模式只记录并继续 | 默认阻断；`observe` 模式交回 Codex 原生权限流程 | 每条 action 使用独立状态和本次请求提供的 cwd |
| DeepSeek Harness | 普通 Bash 的 `tools/pre-execute` | 映射为 `ask` | Web 与 ACP 提供确认；Headless 没有通道时拒绝 | 普通 Bash 每次启动独立 shell；当前集成不支持 Persistent Bash |

## Claude Code

Claude Code 在 Bash action 执行前触发 `PreToolUse`。Caushell 从事件中读取完整命令、session id、当前 cwd 和 workspace，并返回对应的 hook 结果。

| Caushell 决策 | Claude Code 中的行为 |
| --- | --- |
| `Allow` | 控制权交回 Claude Code，继续其权限流程 |
| `NeedApproval` | 返回 `permissionDecision: ask` 和分析原因 |
| `Deny` | 返回 `permissionDecision: deny`，进程不启动 |

交互模式将 `ask` 显示为用户确认。非交互模式下，Caushell 仍返回 `ask`，后续由 Claude Code 的权限流程处理。

Claude Code 会把当前 action 的 cwd 交给 Caushell。跨 action 可用的 shell 状态目前只有 cwd；变量、alias 和函数根据当前 action 的内容分析。

## Codex

Codex 集成同时监听 Bash 的 `PreToolUse` 和 `PermissionRequest`。前者在工具执行前运行，后者覆盖 Codex 自身准备请求权限的路径。

Codex hook 协议提供通过和拒绝两种返回方式。因此 `NeedApproval` 有两种映射方式：

| 模式 | `NeedApproval` 的行为 |
| --- | --- |
| `block`，默认值 | 转换为 `deny`，在执行前阻断并显示 Caushell 原因 |
| `observe` | 保留 Caushell 决策记录，并将控制权交回 Codex |

`Allow` 将控制权交给 Codex，继续原生权限判断并按需请求确认。`Deny` 在两种模式下都会阻断。

Codex 每次向 Caushell 提供当前 action 的 cwd 和 workspace。每条 Bash action 使用独立状态；变量、alias 和函数根据当前 action 的内容分析。

## DeepSeek Harness

DeepSeek Harness 集成注册在普通 Bash 的 `tools/pre-execute`，位于工具主体和进程启动之前。插件使用一个长生命周期的 adapter 保存 Caushell runtime 与 session store。

| Caushell 决策 | DSH 中的行为 |
| --- | --- |
| `Allow` | 调用 `next()`，继续执行后续 pre-execute listener、guard 和工具主体 |
| `NeedApproval` | 返回 `ask`，由 DSH 的审批服务处理 |
| `Deny` | 返回 `deny`，并通过 monotonic guard 保持拒绝结果 |

Web host 将 `ask` 发送到前端，ACP 将其转发给客户端。Headless profile 没有交互审批通道时，`ask` 最终会拒绝执行。DSH 的 `approval=never` 会把所有 `ask` 映射为拒绝。

普通 Bash 每次 action 启动一个独立 shell。插件保留稳定的 session identity 和 Caushell 会话图；新 action 使用本次请求提供的 cwd，变量和其他 shell 进程状态重新开始。

Persistent Bash 会跨 action 保存真实 shell 状态，而 `tools/pre-execute` 只提供新命令和 session 信息。当前集成检查普通 Bash 的参数契约，并拒绝不符合该契约的调用。

## Caushell、Harness 与沙箱

| 层 | 生效时点 | 负责的内容 |
| --- | --- | --- |
| Caushell | 进程启动前 | 解析 shell action，结合可见上下文分析命令、路径、变量、数据流和状态，返回三态决策 |
| Harness | 工具调用和权限处理阶段 | 提供 hook 或工具接口，映射 Caushell 决策，管理权限模式、确认通道和工具生命周期 |
| 沙箱与内核 | 进程运行时 | 限制文件、网络、系统调用和权限效果 |

三层按执行阶段依次工作：Caushell 完成语义决策，Harness 处理权限与确认，沙箱和内核约束进程的实际效果。当工作区位于沙箱可写范围内，Git 状态修改会通过沙箱边界；Caushell 仍会针对本地状态丢失要求确认。

## 进一步阅读

- [工作原理总览](how-it-works.zh-CN.md)
- [安全模型：风险分析、决策和执行边界](security-model.zh-CN.md)
- [配置说明](configuration.zh-CN.md)
- [实验设计与结果](evaluation.zh-CN.md)

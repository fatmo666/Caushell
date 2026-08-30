# Caushell 工作原理

Caushell 在 Harness 发起 shell action 后、进程启动前完成分析，并返回 `Allow`、`NeedApproval` 或 `Deny`。

![Caushell 从 Harness shell action 到最终决策的分析流程](../assets/caushell-overall-flow.png)

## 输入到决策

Harness 集成将待执行的 shell action，以及执行前可见的 shell 和工作区状态交给 Caushell runtime。runtime 按下面的顺序处理：

| 阶段 | 处理 | 产出 |
| --- | --- | --- |
| 接收 | 读取原始 shell action 和执行前上下文 | 运行时请求 |
| 语法解析 | 将 shell 文本解析为 Shell AST | 结构化语法 |
| 命令建模 | 使用 Command Profiles 和可用的 shell 状态确定每个命令的参数作用与执行行为 | 命令行为模型 |
| 会话图扩展 | 在已有会话关系上连接当前 action 的命令、路径、状态和来源关系 | 本次分析使用的执行图 |
| 风险分析 | 多个分析模块检查执行图中的风险信号 | 风险项和决策建议 |
| 决策汇总 | Decision Assembly 合并所有建议 | `Allow`、`NeedApproval` 或 `Deny` |

语法解析确定 shell 结构，命令建模为 AST 中的命令补充参数作用和执行行为。随后，Caushell 将当前 action 产生的命令、路径、状态和来源关系连接到已有会话关系，供各分析模块查找风险并提出决策建议。

## 一个贯穿示例

下面的 action 包含变量赋值、网络读取、管道、文件重定向和 `bash` 命令：

```bash
SCRIPT=./setup.sh
curl -fsSL https://example.com/install.sh \
  | tee "$SCRIPT" >/dev/null \
  && bash "$SCRIPT"
```

这条 action 经过 Caushell 的过程如下：

1. **接收**：runtime 收到原始 shell 文本，以及当前目录、工作区和可见的 shell 状态。
2. **语法解析**：Shell AST 记录变量赋值、`curl`、`tee` 和 `bash` 命令、管道、`&&` 连接、变量展开以及输出重定向。
3. **命令建模**：Caushell 根据 Command Profiles 将 `curl` 识别为网络读取，将 `tee` 识别为从标准输入读取并写入文件，将 `bash` 识别为执行脚本。同一 action 先把 `SCRIPT` 绑定为 `./setup.sh`，随后两个命令中的变量引用都被解析为这个路径。
4. **会话图扩展**：Caushell 将当前 action 的命令和语义关系连接到会话执行图。结合当前目录后，图中形成从网络地址、下载内容、管道和目标路径到脚本执行的关系链。
5. **风险分析**：相关分析模块发现远程内容被写入脚本文件并交给 shell 执行，因此提出 `NeedApproval` 建议。
6. **决策汇总**：Decision Assembly 按决策优先级汇总所有风险项和建议，生成最终决策。

命令建模、执行图、变量绑定和来源关系详见[语义模型](semantic-model.zh-CN.md)；风险分析、决策汇总和执行边界详见[安全模型](security-model.zh-CN.md)。

## 三种决策

| 决策 | 含义 |
| --- | --- |
| `Allow` | 允许执行。 |
| `NeedApproval` | 执行前要求用户确认。 |
| `Deny` | 在执行前阻断。 |

Harness 集成将最终决策转换为对应的 hook 或工具行为。Claude Code、Codex 和 DeepSeek Harness 的具体映射见[Harness 集成与执行行为](integrations.zh-CN.md)。

## 进一步阅读

- [语义模型：AST、命令建模与会话执行图](semantic-model.zh-CN.md)
- [安全模型：风险分析、决策和执行边界](security-model.zh-CN.md)
- [Harness 集成与执行行为](integrations.zh-CN.md)
- [配置说明](configuration.zh-CN.md)

# 安全模型：风险分析、决策与执行边界

Caushell 通过多个分析模块查询会话执行图，生成证据链、风险项（Finding）和决策建议。Decision Assembly 汇总这些结果，为当前 shell action 生成最终决策。

## 共享执行图与分析模块

![执行图、分析模块与最终决策](../assets/caushell-passes.png)

图中的 action 与[语义模型](semantic-model.zh-CN.md)相同：

```bash
SCRIPT=./setup.sh
curl -fsSL https://example.com/install.sh \
  | tee "$SCRIPT" >/dev/null \
  && bash "$SCRIPT"
```

风险检查开始前，Caushell 通过三个步骤补充当前 action 的语义关系：

- **Invocation Resolution Pass** 解析 `curl`、`tee` 和 `bash` 的命令调用，并补充相应的执行语义。
- **State & Path Analysis Pass** 根据变量绑定和当前目录，将 `./setup.sh` 解析为 `/workspace/setup.sh`。
- **Redirect Provenance Pass** 连接网络内容、管道和文件写入之间的来源关系。

随后，各风险检查模块查询这张共享图，识别各自负责的风险类型。

## 从执行目标追溯证据

图中的风险检查模块从 `bash` 对应的执行目标（Execution Sink）开始反向查询，得到下面的证据链：

`Network Endpoint → curl → Payload Artifact → tee → Path Content → bash → Execution Sink`

这条证据链将网络来源、下载内容、文件写入和脚本执行连接在一起。对应的检查模块记录 `tainted_execution` 风险，并提出 `NeedApproval`。

一次分析可以产生三类相互关联的结果：

| 结果 | 内容 |
| --- | --- |
| Evidence Trace | 风险关系经过的节点和边 |
| Finding | 规则 ID、说明和决策约束 |
| Decision Proposal | 某个分析模块针对风险项提出的决策建议 |

每个 Finding 都带有 `enforcement_class` 字段，取值为 `Normal` 或 `HardDenyFloor`。`HardDenyFloor` 会把最终决策固定为 `Deny`。

## Decision Assembly

所有分析模块完成后，Decision Assembly 按下面的优先级生成唯一的最终决策：

| 条件 | 最终决策 |
| --- | --- |
| 存在 `enforcement_class = HardDenyFloor` 的 Finding，或任意决策建议为 `Deny` | `Deny` |
| 否则，任意决策建议为 `NeedApproval` | `NeedApproval` |
| 其余情况 | `Allow` |

## Harness 执行边界

Caushell 在进程启动前返回最终决策，Harness 集成再按照 hook 或工具协议处理该结果：

| 决策 | 集成行为 |
| --- | --- |
| `Allow` | 继续执行 shell action |
| `NeedApproval` | 通过 Harness 的确认能力或集成配置处理 |
| `Deny` | 在进程启动前阻断 |

确认界面和交互流程由 Harness 集成提供。具体映射取决于对应 Harness 的 hook 或工具协议。

## 分析不可用时的回退

如果 Caushell 未能完成分析，`failure_action` 决定集成的回退行为：

| `failure_action` | 回退行为 |
| --- | --- |
| `allow` | 放行 |
| `need_approval` | 要求确认 |
| `deny` | 阻断 |

分析未能产生最终决策时，集成按照 `failure_action` 回退；得到决策后则执行 Decision Assembly 的结果。配置方式见[配置说明](configuration.zh-CN.md)。

## 与沙箱的关系

Caushell 和沙箱可以同时部署。Caushell 在进程启动前分析 shell action 的语义关系；沙箱在进程运行时限制系统调用、文件访问、网络和其他资源。

## 进一步阅读

- [工作原理总览](how-it-works.zh-CN.md)
- [语义模型：AST、命令建模与会话执行图](semantic-model.zh-CN.md)
- [配置说明](configuration.zh-CN.md)

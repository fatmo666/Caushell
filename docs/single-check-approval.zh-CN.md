# 单次审批接口和实现状态

本分支实现检查与单次审批的关联、待批计划恢复、仅判断模式和持久日志确认。保守历史目前只有有界候选数据结构，尚未接入安全消费者；本分支不能作为完整的风险消除保护发布，也不能据此重跑正式 RQ2。

## 检查和授权

沿用现有 `check` 消息，不增加第二套检查器。请求的 `intent` 默认为 `propose_for_execution`；`judge_only` 不提交当前命令效果，也不生成可授权的计划。观察序号和请求带入的已有 Shell 状态仍可更新。

| 判断 | 拟执行模式 | 仅判断模式 |
| --- | --- | --- |
| Allow | 立即接受推定效果 | 不接受当前命令效果 |
| NeedApproval | 保存原检查计划并返回回执 | 不保存待批计划 |
| Deny | 不接受效果，不提供审批入口 | 不接受当前命令效果 |

NeedApproval 回应在原判断字段之外返回 `check_receipt`：

```json
{
  "kind": "check",
  "payload": {
    "decision": "need_approval",
    "reasons": ["..."],
    "decision_trace": {},
    "check_receipt": {
      "check_id": {"session_id": "example-session", "sequence_no": 7},
      "state_revision": 9
    }
  }
}
```

上例为省略详细追踪字段的结构示意，实际回应使用完整 CheckResponse。可信控制器使用原回执发送授权，不重新提交命令：

```json
{
  "kind": "authorize",
  "payload": {
    "check_id": {"session_id": "example-session", "sequence_no": 7},
    "state_revision": 9,
    "approved": true,
    "authority": "simulated_user"
  }
}
```

`approved: false` 表示拒绝；`authority` 可为 `user`、`host`、`simulated_user`。该字段记录来源，不是身份认证凭据；提交通道必须由可信 Harness 或实验控制器掌握，不能把模型输出或工具 stdout 当授权。

审批引用保存的完整请求、原候选变更和原政策。会话状态或政策改变后，原计划失效；审批不能改写原 NeedApproval 判断，也不能覆盖 Deny。获批只表示接受推定效果，不表示 Bash 实际执行成功。

重复的相同授权返回已记录回应，不重复应用；同一检查的冲突授权被拒绝。保留最近 256 个授权重试回执，更早的 ID 过期后报错，不会再次应用。待批计划和授权记录随快照和事件流恢复。

## 能力协商和客户端

`ping` 回应的 `approval_protocol: 1` 同时声明单次审批与仅判断支持。旧回应没有此字段，新控制器必须拒绝降级，不能试发 `judge_only` 给旧服务。

Rust 客户端新增 `check_with_receipt_unix_socket` 和 `authorize_unix_socket`。前者先验证能力再检查。旧 `check_unix_socket` 保留原默认调用方式，但传入仅判断意图时也必须先验证能力。stdio 控制器应先发 ping 并核对协议，再发送 check 或 authorize。

独立持久 Shell 应使用独立 session ID。本阶段没有跨 Shell 状态流的共享绑定协议。Claude、Codex 和 DSH 的现有适配器仍保留原宿主行为，未把 PostToolUse、退出码或出现执行结果追认为用户审批；自动关联宿主批准事件尚未接入。

## 持久化失败

有 store 的运行时在事件写入并同步日志后才返回接受成功，SQLite 物化和检查点仍异步完成。待批检查和授权分别落盘，恢复不需要重新推理。

内存分析先于日志确认。若写入或确认失败，该运行时停止接受后续请求，不返回成功；当前请求可能已经部分写入，必须从持久日志核对，不能自动重发未知工作。此阶段采用失败后停止的保护，不声称内存和磁盘已实现可回滚的事务提交。

## 后续实现范围

有界历史按变量、alias、函数、工作目录和位置参数保存候选，单对象最多四个候选、最多 512 个对象；超限保留未知而非丢旧风险。该结构尚未参与当前决定。

完整保护还需将同一安全视图贯通有序变量与定义解析、当前 action 的 staged overlay、完整快照、路径和文件来源，以及所有风险消费者。只有完成这些路径及相应回归后，才能宣称安全覆盖、unset 或清理不会解除风险。原始结果、冻结输入、旧监控和已安装程序均不由本分支修改。

## 提交和回滚

工作分支为 `conservative-history-approval-20261021`，基点为 `5000ae43df0c9a6e7f21f03a03d42560ee91ac85`。阶段提交保持独立，可按相反顺序使用 git revert 回滚；不要重置或删除用户的未提交改动。本分支尚未合入原工作分支，也没有推送。

针对性测试覆盖未批不提交、批准恰好一次、拒绝、过期和跨会话授权、政策变化、快照恢复、运行时重启、日志 ACK、写入失败停止、旧服务拒绝降级，以及候选合并与超限扩大。静态分析测试不执行示例中的 Shell 命令。

代码阶段 `b673722` 的 289 项针对性测试全部通过。全仓库测试在核心单元测试处停止，150 项通过、7 项失败；这 7 项在原始基点以独立离线构建目录逐条复现，因此不能声称全仓库已全绿，也没有改动这些政策断言。具体命令和失败用例见 [验证记录](single-check-approval-tests.json)。

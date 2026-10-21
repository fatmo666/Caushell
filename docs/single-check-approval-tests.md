# 单次审批和保守历史验证记录

最新保守历史阶段代码为 `58ffdbc`，较早单次审批阶段为 `b673722`，共同基点为 `5000ae43df0c9a6e7f21f03a03d42560ee91ac85`。所有测试在无网络、源码和依赖只读的本任务容器中运行。

## 保守历史阶段验证

2026 年 10 月 22 日最终相关回归如下，重复运行的用例不重复计入合计：

| 测试范围 | 通过 | 本组排除的既有失败 |
| --- | ---: | ---: |
| 核心集成测试 approval 与 analysis_budget 与 state_capture | 15 | 0 |
| 核心单元测试 | 150 | 7 |
| caushell 运行时单元测试 | 70 | 0 |
| 查询库单元测试 | 132 | 0 |
| 配置单元测试 | 31 | 0 |
| Graph 单元测试 | 18 | 0 |
| Runner 单元测试 | 64 | 0 |
| 类型单元测试 | 189 | 0 |
| 分析 pass 单元测试 | 846 | 1 |
| 合计 | 1515 | 8 |

命令均使用 `--offline --locked`，覆盖 `caushell-core` 的三个集成测试目标，以及上表各 crate 的 `--lib` 测试。核心单元组用 `--skip` 排除下节已在基点复现的七项；pass 单元组仅排除 `passes::catastrophic_delete_guard::tests::catastrophic_delete_guard_denies_block_device_patterns_in_default_mode`。

新增的 pass 排除项也在原始基点的只读归档副本、独立构建目录中，以完整名称加 `--exact` 复测：`shred /dev/mapper/*` 得到 Allow、预期 Deny，0 项通过、1 项失败，退出码 101。本轮不改动该测试或规则。

新增验证覆盖中间赋值、重复覆盖、unset、定义替换、批准前不提交、批准幂等、快照和真实事件流恢复、函数中间全局写入与局部隔离、调用作用域、源位置过滤、索引和全图查询一致性、派生计数恢复，以及候选填充和载荷容量耗尽后的强制 Ask。原测试中依赖 finding 列表位置和旧快照节点数的断言改为验证规则 ID 与新增候选节点，并保留原有判断、节点和边检查。

`cargo check --offline --locked --workspace --quiet`、本轮修改源码的 rustfmt 检查和 `git diff --check` 均通过。这不是全工作区测试全绿：其他集成测试未全量重跑，`cargo test --workspace --no-run` 的一次尝试在链接阶段被中止，不计为通过。

候选记录和预算保护不代表历史候选风险判断已贯通，剩余范围见 [接口说明](single-check-approval.zh-CN.md)。该阶段验证没有部署程序或运行正式实验；用户随后授权合入 `profile-coverage-option-matching-20261002`，不包含远端推送或部署。

## 单次审批阶段针对性测试

| 测试范围 | 通过 | 失败 |
| --- | ---: | ---: |
| caushell 运行时单元测试 | 68 | 0 |
| caushell-types 单元测试 | 189 | 0 |
| caushell-types 集成测试 | 12 | 0 |
| 核心单次审批集成测试 | 4 | 0 |
| caushell-store 单元测试 | 16 | 0 |
| 合计 | 289 | 0 |

命令均使用 `--offline --locked`：

```text
cargo test --offline --locked -p caushell --lib --quiet
cargo test --offline --locked -p caushell-types --quiet
cargo test --offline --locked -p caushell-core --test approval --quiet
cargo test --offline --locked -p caushell-store --lib --quiet
```

## 全仓库回归和基点复测

`cargo test --offline --locked --workspace --quiet` 在核心单元测试处以 101 退出，核心单元测试 150 项通过、7 项失败。全仓库没有全绿，也未运行到后续全部测试组。

将原始基点仓库只读挂载，并使用独立构建目录，逐条以 `cargo test --offline --locked -p caushell-core --lib <test> -- --exact` 复测，以下七项均在原始基点复现相同失败：

- `core::tests::core_allows_non_dispatch_execution_wrapper_modes`
- `core::tests::core_default_runner_commits_real_world_icp_pipeline_graph`
- `core::tests::core_default_runner_commits_wrapper_pipeline_flow_into_session_graph`
- `core::tests::core_default_runner_observes_pip_local_path_import`
- `core::tests::core_default_runner_observes_pip_requirement_file_import`
- `core::tests::core_default_runner_requires_approval_for_npm_direct_url_install`
- `core::tests::core_default_runner_requires_approval_for_python_m_pip_direct_url_import`

本轮保留这些既有政策断言，不以降低拦截要求或改写预期来消除失败。

## 实现范围

已验证的内容是检查与单次授权、幂等、拒绝及过期处理、快照和事件流恢复、日志确认、故障时保全日志、旧服务拒绝降级、Graph 候选记录、派生索引和预算耗尽保护。历史候选风险消费者、完整安全视图、宿主审批关联以及新 RQ2 控制器仍未完成，具体边界见 [接口说明](single-check-approval.zh-CN.md)。

上述验证完成时，原工作分支仍在基点且工作区干净。原有实验结果和已安装程序均未修改。

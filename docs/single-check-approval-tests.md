# 单次审批阶段验证记录

代码提交为 `b673722`，基点为 `5000ae43df0c9a6e7f21f03a03d42560ee91ac85`。所有测试在无网络、源码和依赖只读的本任务容器中运行。

## 针对性测试

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

已验证的内容是检查与单次授权、幂等、拒绝及过期处理、快照恢复、日志确认、故障时保全日志、旧服务拒绝降级和有界历史类型。完整安全视图、宿主审批关联以及新 RQ2 控制器仍未完成，具体边界见 [接口说明](single-check-approval.zh-CN.md)。

原始工作分支仍在基点且工作区干净。本轮没有替换已安装程序、推送分支、启动付费实验或修改旧实验结果。

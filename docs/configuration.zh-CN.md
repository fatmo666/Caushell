# Caushell 配置说明

本文介绍 Caushell 的配置文件位置、配置管理命令和当前支持的用户配置项。

## 配置文件位置

Caushell 按下面顺序寻找配置文件：

1. `$CAUSHELL_CONFIG_PATH`
2. `$XDG_CONFIG_HOME/caushell/config.yaml`
3. `~/.config/caushell/config.yaml`

如果设置了 `$CAUSHELL_CONFIG_PATH`，它必须是绝对路径。

查看当前配置文件位置：

```bash
caushell config path
```

## 初始化、查看和校验

初始化一个新的配置文件：

```bash
caushell config init
```

这会在配置目录里创建默认配置文件；如果文件已存在，会返回错误，不会覆盖。

查看当前配置文件内容：

```bash
caushell config show
```

这个命令会输出一段 JSON，包含：

- 解析后的配置路径
- 配置文件是否已存在
- 配置文件中的原始配置内容

校验配置是否可用：

```bash
caushell config validate
```

如果配置文件不存在，`validate` 仍然通过，因为这时 Caushell 会使用内置默认值。

## 当前可配置项

| 字段 | 可选值 | 默认值 | 作用 |
| --- | --- | --- | --- |
| `failure_action` | `allow` / `need_approval` / `deny` | `need_approval` | Caushell 无法完成分析时的回退行为 |
| `codex.need_approval_mode` | `block` / `observe` | `block` | Codex 遇到 `NeedApproval` 时的处理方式 |
| `policy.rules.process_control` | `allow` / `need_approval` / `deny` | `need_approval` | 对已解析的发信号或恢复进程/作业的命令是否要求审批 |

`allow` 会保留风险发现，但不要求审批。当前不会把目标解析为操作系统中的具体进程，因此未知目标也使用同一配置；此规则不会识别或特别保护关键 PID。

本规则消费已解析的 `control_process` 效果，包括嵌套调用和 `fg`/`bg` 恢复作业。已覆盖的零信号探测与信号列表形式不产生此效果。未覆盖的选项或调用形式仍由现有解析缺口策略处理（`form_selection_unmatched` 默认放行并观察），不能视为本规则确认安全；`allow` 也不会覆盖其他规则的审批或拒绝。

```yaml
policy:
  rules:
    process_control: allow
```

### `failure_action`

这个字段定义 Caushell 无法完成某条 shell action 分析时的处理方式。

- `allow`：分析失败时放行
- `need_approval`：分析失败时要求确认
- `deny`：分析失败时直接阻断

查看当前值：

```bash
caushell config get failure_action
```

修改它：

```bash
caushell config set failure_action need_approval
```

### `codex.need_approval_mode`

这个字段只影响 Codex 集成。

Codex hook 当前无法直接请求用户确认，只能返回通过或拒绝，因此 Caushell 将 `NeedApproval` 映射为两个模式：

- `block`：遇到 `NeedApproval` 时阻断执行
- `observe`：允许 Codex 继续执行，同时保留 Caushell 的判断和原因记录

查看当前值：

```bash
caushell config get codex.need_approval_mode
```

修改它：

```bash
caushell config set codex.need_approval_mode observe
```

`Deny` 决策始终会被阻断，不受这个开关影响。

## 最小示例

这是一个最小配置：

```yaml
version: 1
failure_action: need_approval
codex:
  need_approval_mode: block
```

默认配置使用 `need_approval` 和 `block`。

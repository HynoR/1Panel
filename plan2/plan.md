# 1Panel 防火墙统一化设计

## 设计目标

围绕以下业务目标重构防火墙模块：

- 数据库保存统一规则快照
- 重启后可按模式恢复快照或校验快照
- `iptables / nftables` 场景下由 1Panel 全权管理
- `ufw / firewalld` 场景下 1Panel 作为可视化面板与快照备份/恢复中心
- 不因 1Panel 错误持久化导致服务器失联
- 不因错误持久化导致不该开放的端口被重新开放
- 统一数据表和状态管理
- 从旧版本迁移到新版本时尽量平滑，允许部分数据变化，但不能大规模失效

## 核心设计结论

最终采用双模式架构。

### 模式 A：Panel Managed

适用条件：

- 系统不存在 `ufw`
- 系统不存在 `firewalld`
- 由 1Panel 全权代理 `iptables`，并为 `nftables` 预留同级能力

特征：

- 1Panel 是规则真源
- 数据库快照是权威状态
- 系统规则由 1Panel 负责下发、恢复、校验
- 开机恢复以 1Panel 快照为准

### 模式 B：Panel Visualized

适用条件：

- 系统存在 `ufw` 或 `firewalld`

特征：

- `ufw / firewalld` 仍是系统实际防火墙主体
- 1Panel 不直接替代其原生持久化
- 1Panel 保存统一快照，用于展示、比对、备份、还原辅助
- 开机时以系统防火墙真实状态为准，1Panel 负责同步与校验

## 统一领域模型

### FirewallMode

- `panel_managed`
- `panel_visualized`

### FirewallProvider

- `iptables`
- `nftables`
- `ufw`
- `firewalld`

### FirewallRuntimeState

用于表达当前系统真实状态：

- 当前模式
- 当前 provider
- provider 是否安装
- provider 是否运行
- 当前 profile 状态
- 当前规则摘要
- 与数据库快照是否一致
- 最近一次同步/恢复结果

### FirewallSnapshot

数据库中的统一快照对象，应至少包含：

- `mode`
- `provider`
- `version`
- `profiles`
- `rules`
- `system_policy`
- `source`
- `snapshot_version`
- `created_at`
- `updated_at`

说明：

- `source` 表示快照是来自“系统读取”还是“用户操作后生成”
- `snapshot_version` 用于后续迁移和兼容

### FirewallRule

统一规则结构：

- `scope`: `inbound | outbound | forward | system`
- `kind`: `port | address | forward | filter`
- `action`: `accept | drop | reject`
- `protocol`
- `family`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `target_ip`
- `target_port`
- `interface`
- `description`
- `managed_by`
- `fingerprint`
- `provider_meta`

### FirewallProfile

统一 profile：

- `baseline`
- `forwarding`
- `directional_filter`

`iptables` 下的 `1PANEL_*` 链只是这些 profile 的内部实现。

## 数据主从关系

### Panel Managed

主从关系：

- 数据库快照是主
- 系统实际规则是从

行为：

- 用户在 1Panel 中修改规则后，先写数据库快照，再安全下发到系统
- 开机或重启后，由 1Panel 依据快照恢复系统规则
- 恢复后回读系统状态，生成校验结果

### Panel Visualized

主从关系：

- 系统真实规则是主
- 数据库快照是观测与备份副本

行为：

- 1Panel 操作 `ufw / firewalld` 时，调用其原生接口完成变更
- 变更成功后立即刷新系统状态并更新快照
- 开机时先读取系统状态，再更新数据库快照
- 还原操作必须显式确认，且通过 provider 原生方式恢复，不绕过其持久化体系

## 安全原则

### 1. 不允许错误快照直接覆盖系统

尤其在 `panel_visualized` 模式：

- 不允许因为数据库里有旧快照，开机时强行覆盖 `ufw / firewalld`
- 默认行为是“比对并告警”，不是“自动强推恢复”

### 2. 恢复操作必须有安全门槛

对于可能导致失联的操作，必须具备：

- 恢复预检查
- 最小保底白名单
- 操作回读验证
- 失败回滚或中止

### 3. 系统保底规则必须独立建模

无论哪个模式，都需要定义保底访问集：

- 当前 SSH 端口
- 当前 1Panel 端口
- 必要时 `80/443`

在 `panel_managed` 模式下，这些可作为 `baseline` profile 的保底规则。

在 `panel_visualized` 模式下，这些仅用于风险检测和操作前提示，不默认偷偷改写系统。

### 4. 默认不因错误快照开放额外端口

恢复策略必须遵守“宁可不恢复新增开放，也不能误开放不该开放端口”的原则。

实现上要求：

- 快照恢复时严格按规则指纹和 scope 处理
- 对来源不明、格式不兼容、无法映射的旧规则，不自动恢复开放动作
- 对删除型或禁止型规则，可优先保守处理为“待确认”

## Provider 责任边界

### IptablesDriver

职责：

- 负责 `panel_managed` 模式下的完整规则管理
- 持久化和恢复 OnePanel 自己的规则集
- 将 profile 翻译成具体 iptables 链和规则

要求：

- `1PANEL_*` 链只允许存在于 driver 内部
- controller、service、前端都不再直接引用链名

### NftablesDriver

本轮先预留接口，不要求完整实现。

要求：

- 与 `IptablesDriver` 处于同等地位
- 能接入 `panel_managed` 模式
- 复用统一快照和统一规则模型

### UfwDriver / FirewalldDriver

职责：

- 作为 `panel_visualized` 模式的 provider 适配器
- 负责系统状态读取、规则翻译、原生命令调用
- 负责快照同步和显式恢复

要求：

- 不替代原生持久化机制
- 不把 1Panel 的内部持久化强加到系统启动流程

## 统一数据表设计

建议拆成三类表。

### 1. 防火墙主状态表

例如 `firewall_runtime`

字段建议：

- `mode`
- `provider`
- `provider_version`
- `is_active`
- `is_consistent`
- `last_sync_at`
- `last_restore_at`
- `last_error`

### 2. 防火墙快照表

例如 `firewall_snapshot`

字段建议：

- `id`
- `mode`
- `provider`
- `snapshot_version`
- `content_json`
- `source`
- `checksum`
- `created_at`
- `updated_at`

说明：

- `content_json` 保存结构化快照
- `checksum` 用于完整性校验

### 3. 规则元数据表

例如 `firewall_rule_meta`

字段建议：

- `fingerprint`
- `description`
- `tags`
- `managed_by`
- `profile`

说明：

- 只存 OnePanel 附加信息
- 不再让一张旧表兼任快照、描述、规则镜像三种职责

## 启动、重启、备份、还原流程

### 启动

#### Panel Managed

1. 检测 provider 为 `iptables` 或 `nftables`
2. 读取最新有效快照
3. 做快照完整性与兼容性检查
4. 生成恢复计划
5. 注入保底规则
6. 应用规则
7. 回读系统状态
8. 标记一致或异常

#### Panel Visualized

1. 检测 provider 为 `ufw` 或 `firewalld`
2. 读取系统真实状态
3. 转换成统一规则模型
4. 更新数据库快照
5. 对比上次快照
6. 若差异异常则记录告警，但不自动覆盖系统

### 重启

行为与启动一致，禁止新增另一套特殊逻辑。

### 备份

备份内容至少包括：

- 当前模式
- 当前 provider
- 最新快照
- profile 状态
- 规则元数据
- 最近一次状态一致性信息

### 还原

#### Panel Managed

- 可按快照直接还原
- 还原前必须自动注入保底规则
- 还原后必须做可达性校验

#### Panel Visualized

- 必须是显式操作
- 调用 provider 原生方式还原
- 不允许后台静默覆盖当前系统规则

## API 与服务层重构

建议统一成以下服务能力：

- `GetRuntimeState`
- `GetCapabilities`
- `SearchRules`
- `ApplyRule`
- `BatchApplyRules`
- `CreateSnapshot`
- `SyncSnapshotFromSystem`
- `RestoreSnapshot`
- `ValidateConsistency`
- `ListProfiles`
- `ApplyProfile`

旧的：

- `/hosts/firewall/port`
- `/hosts/firewall/ip`
- `/hosts/firewall/forward`
- `/hosts/firewall/filter/*`

短期保留，内部转调新服务。

## 旧版本迁移策略

原则：

- 兼容读取旧数据
- 不要求旧数据 100% 无损映射
- 不能大规模失效
- 对无法精确迁移的规则做“保守迁移”

迁移步骤：

1. 保留旧表读取能力
2. 建立旧字段到统一规则模型的映射器
3. 尽量生成规则指纹
4. 迁移描述信息和基础规则属性
5. 对无法映射的项标记为 `legacy_incomplete`
6. 首次升级后执行一次系统实际状态同步，修正快照

迁移容忍策略：

- 允许部分历史描述丢失精确绑定
- 允许部分无法识别的旧规则进入“待确认”
- 不允许因迁移错误自动新增开放端口
- 不允许因迁移错误直接覆盖现有 `ufw / firewalld`

## 前端目标形态

防火墙前端应改成统一工作台，而不是按实现拆分。

建议结构：

- 总览
- 入站规则
- 转发规则
- 高级过滤
- 快照与一致性
- 系统策略

显示逻辑依据：

- `mode`
- `provider`
- `capabilities`
- `consistency status`

而不是依据：

- `fireName === 'iptables'`
- `currentTab === 'advance'`

## 实施优先级

### 第一阶段

- 建立双模式模型
- 建立统一快照模型
- 修复现有 repo 与状态逻辑缺陷
- 保留旧接口

### 第二阶段

- 引入统一 driver 与 registry
- 把 iptables 私有链收回 driver 内部
- 建立启动/重启/同步/恢复统一流程

### 第三阶段

- 完成新数据表迁移
- 前端统一工作台
- 增加一致性展示和风险提示

### 第四阶段

- 清理旧补丁逻辑
- 预留 nftables 驱动接入点

## 设计结论

这次重构的关键，不是把 `firewalld / ufw / iptables` 再抽一个公共接口，而是先承认系统实际存在两种不同的业务模式：

1. 1Panel 全权代理防火墙
2. 1Panel 介入已有防火墙做可视化与状态管理

只有先把这两种模式分清，再把快照、恢复、状态一致性和迁移统一建模，防火墙模块才能真正从“到处写死和补丁判断”变成“可维护、可恢复、可迁移、可扩展到 nftables”的系统。

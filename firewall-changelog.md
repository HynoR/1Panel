# 1Panel 防火墙重构 CHANGELOG（feat/dev2）

> 生成日期：2026-07-02
> 范围：`feat/dev2` 相对 `dev-v2` 的防火墙模块重构（PR-1 ~ PR-8 + 2026-06-29 后续修复与 T1-T7 收尾；T8 合并 `dev-v2` 尚未执行）
> 事实基准：三点 diff `dev-v2...feat/dev2` + `de23d7259..bed2c75ab` 后续提交谱系，逐 commit 校读源码；issue 号取自同目录 `firewall-refactor-report.md`，设计对照取自 `firewall-refactor-design.md`
> 性质：双读者文档 —— 上半部分（一~四节）面向用户/发布说明，下半部分（五~九节）面向工程交接与代码评审

---

## ⚠️ 0. 升级须知（发布公告草稿）

1. **拒绝规则现在优先于保底端口生效。** 旧版中部分拒绝规则因为排在保底放行之后，可能长期处于“看起来存在但实际未生效”的休眠状态；升级到新链顺序后，拒绝规则会在保底端口前求值。升级迁移会自动隔离“广源且覆盖 SSH/面板等保底端口”的危险旧拒绝规则，并在概览页显示 degraded 横幅与“查看被隔离规则”入口。
2. **原 iptables 默认拒绝语义在界面中显示为「白名单模式」。** 这是命名统一：只有已列入放行规则的端口可访问，其余入站默认拒绝。语义不变，名称从“默认拒绝/严格”调整为更直观的“白名单模式”。
3. **看到 degraded 横幅时不要忽略。** 若提示 quarantined，可打开“查看被隔离规则”抽屉审阅原始规则；确认不需要恢复后点“清除全部”隐藏提示。若提示 baseline verify / strict-suspended / failed，请先确认 SSH、面板端口仍可达，再按横幅信息修复配置或回滚快照。
4. **失联自救命令。** 通过云厂商 VNC / 串口登录后执行 `1pctl firewall rescue --restore-latest` 可用最近快照恢复 1Panel 防火墙链；这是末路自救路径，可能覆盖窗口期第三方规则。

## 0A. 2026-07-02 状态修订

- 2026-06-29 文档中的若干“未完成/高风险”结论已被后续提交修复：`a93f72862` 修复迁移 fail-open、80/443 归类和危险旧 DENY 隔离；`319ce2b22` + `d379b1702` 落地 external 锁外保护与真实 caller IP；`7985a75b2` + `6b680d4a8` 修复批量错误聚合与会话状态机；`5c3a8e4b2`、`d75ca6c08`、`bed2c75ab` 补齐/本地化前端 i18n。
- 评审编号 **B1-B9/B12/B13** 在后续修复批次中已处理；仍需要 Linux 真机完成 S1-S10、S6 升级演练和锁外演练，不能把本地编译/单元测试视为发布门禁。
- 本任务书状态：T1-T6 已完成并分别提交；T7 为本文档更新；T8（merge `dev-v2`）仍是最后一个待执行高风险步骤。

## ⚠️ 0B. 合并前置阻断（最高优先，必须先读）

`feat/dev2` 当前**落后 `dev-v2` 共 14 个 commit**（PR #13045 ~ #13071：MCP Server `protocolVersion`、website_ssl 证书同步、runtime 容器配置、alert 调整、image 同步等）。这带来一个会误导 changelog 与合并操作的陷阱：

| diff 方式 | 命令 | 结果 | 是否可信 |
|---|---|---|---|
| 两点 diff | `git diff dev-v2..feat/dev2` | 把 dev-v2 上的 14 个上游 PR 新增**误显示为删除**（mcp_server.go −393、website_ssl.go −131、runtime/tensorrt_llm、8 语言 i18n 大量删除、frontend/package.json、go.mod/go.sum 变更） | ❌ 严重误导 |
| 三点 diff | `git diff dev-v2...feat/dev2` | 48 文件 +4447/−314，**仅防火墙重构产物** | ✅ 本文唯一采信口径 |

**合并/发布前硬性要求：**
1. 生成 changelog 必须仅采信三点 diff（本文已遵循）。
2. 合并前必须先 `rebase` 或 `merge dev-v2`，否则快进合并会**回退掉这 14 个上游 PR**（package.json/go.mod 依赖回退、MCP/SSL/runtime 功能丢失）。
3. rebase 后必须验证：无冲突、不回退上游 PR、防火墙改动完整保留。

---

# 第一部分 · 用户可见 Changelog

## 1. 一句话总览

本次重构把 1Panel 的防火墙从「白名单压制一切、容易把自己锁在外面、对 Docker/IPv6 形同虚设」的旧模型，升级为**四层安全栈兜底 + 黑名单可压过放行 + Docker 端口纳管 + IPv6 镜像 + 提交-确认窗口**的新模型，并消灭了 core 直接 shell 调防火墙的「双写者」隐患。

## 2. 修复的上游诟病（直接对应 issue）

| Issue | 诟病 | 本次如何修复 |
|---|---|---|
| #12897、#12372、#3894 | IP/端口黑名单被 BEFORE 链的无条件白名单绕过，被扫描/DDoS 时加黑名单无效 | 新链布局把黑名单链 `DENY` 排到保底链 `BASELINE` **之前**，黑名单现在可以压过端口放行（含 SSH/面板/80-443），真正生效 |
| #12476、#5852、#3274 | 链顺序错乱导致 SSH 实时断连、误删端口把自己锁在服务器外 | 五链按固定序号绑定 + 回读断言（`assertBaseOrder`）保证顺序；新增**提交-确认窗口**（60 秒未确认自动整体回滚）+ **caller-IP 紧急自救通道** + `1pctl firewall rescue` 命令行自救 |
| #726、#12471、#12932 | Docker 映射端口绕过防火墙，「防火墙形同虚设」 | 新增 Docker 端口防护：检测到 `DOCKER-USER` 即建 `1PANEL_DOCKER` 链，IP 黑名单/端口封禁可同步拦截容器发布端口（用 conntrack 还原 DNAT 前端口） |
| #12997、#3799、#5042 | IPv6 完全不受管控，删端口后 v6 照常可达 | managed 模式下端口规则默认双栈，`both/ipv6` 规则镜像写 `ip6tables` 同名五链 |
| #6734 | ufw + firewalld 共存时整个防火墙页瘫痪 | 仅当两者**都在运行**才报冲突，且基础信息页仍正常返回（携带冲突提示），不再整页瘫痪 |
| #8388 | 防火墙页面 CPU 飙升 | provider 探测改为 60 秒 TTL 进程内缓存，不再每次请求都现场探测 |
| —（C2/C3 内部矛盾） | core 改面板端口直接 shell 调防火墙造成「开新失败+删旧成功」双失联；`cleanUnUsedData` 静默删用户规则描述 | core 改为委托 agent「只增不删」放行新端口；删除 `cleanUnUsedData` 自动行为，改为用户显式触发清理 |

> 说明：#12007（nftables 系统兼容）按设计属 Stage 3，本期**不实现**，仅预留常量占位，非本期承诺项。

## 3. 行为变更点（用户可感知）

1. **黑名单现在能压过端口放行**：旧版「白名单优先级最高」的隐含哲学被有意反转。你加的 IP/端口黑名单会先于 SSH/面板/80-443 的放行求值，因此**可以封掉 SSH 爆破源**——但也意味着误封自己 IP 会真生效（有四层安全栈兜底）。
2. **80/443 从硬编码保底改为「可关闭」**：80/tcp、443/tcp、443/udp（含 HTTP/3）成为端口白名单的**默认值**而非不可删保底。SSH 端口与面板端口仍是不可移除的保底集。
3. **Docker 端口纳管**：IP/端口对话框新增「同时拦截 Docker 端口流量」勾选（检测到 Docker 时默认勾选）。仅 IPv4。
4. **IPv6 支持**：managed 模式端口规则默认双栈；删端口后 v4/v6 均不可达。存量规则保持 ipv4 不自动补 v6；NAT/端口转发仍仅 IPv4。
5. **提交-确认窗口（commit-confirm）**：降低可达性的变更（加黑名单、删放行等）会立即应用，但默认 **60 秒内需在面板点「确认保留」**，否则自动整体回滚（超时或 agent 重启都会触发）。纯放行类变更直接生效、不进确认窗口。
6. **改面板端口为「单写者只增不删」**：core 不再直接调 ufw/firewall-cmd，改由 agent 放行新端口；旧端口不会被立即删除（用新端口登录后由白名单同步或手动关闭）。
7. **ufw + firewalld 共存不再瘫痪**：基础信息页可看、操作被拦并给出冲突处置提示。

## 4. 升级 / 自救 / 降级

### 4.1 升级时会发生什么

- 存量机**首次启动新版本**会触发一次性「活体链迁移」：旧 `1PANEL_BASIC*` 三链布局转换为新的 `GUARD / DENY / BASELINE / ALLOW / AFTER` 五链布局。
- 旧链文件不会删除，而是**重命名为 `.bak`** 保留。
- 数据库执行 additive 迁移（新增 `firewall_rule_meta`、`firewall_state` 两表，从旧 `firewalls` 表保守回填描述），**旧表保留不删**，迁移幂等。
- 规则描述改为「按指纹关联」，升级后不再静默丢失可指纹化的描述。

### 4.2 出问题如何自救

- **面板内**：误操作后 60 秒内会弹出确认卡片，点「立即撤销」即回滚；不点则到期自动回滚。
- **caller-IP 紧急通道**：任何变更型请求都会给你的来源 IP 临时插一条 10 分钟放行（直插裸 INPUT，链解绑/回滚后仍存活）。
- **命令行兜底**：通过云厂商 VNC / 串口登录后执行
  - `1pctl firewall rescue`：解绑全部 `1PANEL_*` 链（`--clean-new-chains` 额外清理含 DOCKER-USER 的新链）
  - `1pctl firewall rescue --restore-latest`：用最近快照恢复（**注意**：此路径为全表 `iptables-restore`，会覆盖窗口期 Docker/fail2ban 等第三方规则，仅作末路自救）

### 4.3 如何降级（⚠️ 重要限制）

设计稿宣称的「旧代码开机重放 `.bak` 即自动恢复」**在当前代码下不成立**：
- 旧版本开机只读原文件名（`1panel_basic.rules`），**不识别 `.bak`**；
- 没有任何逻辑在降级时把 `.bak` 改名回原名。

因此降级到旧版本需要**人工干预**：手动把 `.bak` 文件改回原名后再启动旧版本。建议在文档/发布说明中明确告知此限制。

---

# 第二部分 · 技术 Changelog（按 PR 分组）

> 文件路径均为仓库相对路径；行号取自 `feat/dev2` 当前状态。每组标注「设计对照」=与 `firewall-refactor-design.md` 的吻合/偏离情况。

## PR-1 · 驱动能力层 / 模式探测 / 共存降级

**核心改动**

| 文件 | 改动 |
|---|---|
| `agent/utils/firewall/driver.go` | 新增 `Mode`(managed/external) + `Capabilities` + `ConflictState` + `Provider` struct；`Detect()` 带 60s TTL 进程内缓存探测，`detect()` 模式判定 + 共存降级；`InvalidateProbe()` 主动失效 |
| `agent/utils/firewall/client.go` | `NewFirewallClient()` 操作入口，冲突时拒绝（`Detect()` 永不因冲突 error） |
| `agent/utils/firewall/fingerprint.go` | 规则指纹规范化 sha256（见 PR-4） |

**模式判定**：`cmd.Which` 判存在性 —— 有 firewalld/ufw → `ModeExternal`；否则有 iptables → `ModeManaged`；都无 → `ErrNoFirewall`。

**共存降级**：仅当 firewalld + ufw **都在 running** 才标 `ConflictState`；只 ufw running 选 ufw；都不 running 选 firewalld（保留旧优先级）。`LoadBaseInfo` 走 `Detect()`（冲突时仍可看），写操作走 `NewFirewallClient()`（冲突时拒绝）。

**设计对照**
- ✅ 与设计 §3.1 高度一致：显式双模式、共存按 running 选 provider、冲突降级为数据而非 error、探测缓存 60s + 主动失效（修 C11/C12）。这是本次重构**兑现得最好的部分**。
- ❌ **严重偏离 §3.2**：设计要求废弃扁平接口、拆成 `RuleDriver/ServiceDriver/ForwardDriver/FilterDriver/BaselineDriver` 能力接口组合。实际仍是单一扁平 `FirewallClient` 接口（`client.go:15-33`，正是设计要废弃的那个），`Capabilities` 只是挂在 `Provider` 上的数据字段，无任何接口分解。
- ❌ `ProviderNftables` 仅是 `driver.go:30` 的一个常量，`detect()` 从不产出、无 `NftablesDriver`、无探测分支。**设计稿「nftables 零改动接入」的留缝验收标准在当前代码下不成立**（详见第六节）。

## PR-2 · 四层锁外安全栈（L1 红线 / L2 紧急放行 / L3 提交-确认 / L4 开机+rescue）

**核心改动**

| 文件 | 层 | 改动 |
|---|---|---|
| `agent/app/service/firewall.go:957-995` | L1 | `precheckPortRule`/`precheckAddressRule` 红线预检（I1 无条件 DROP / I2 抢救端口） |
| `agent/middleware/firewall_emergency.go` | L2 | 变更型 API 给 `RemoteAddr` 插 10 分钟临时 ACCEPT（刻意不信 X-Forwarded-For） |
| `agent/utils/firewall/emergency.go` | L2/L4 | `EnsureCallerAccept` / `CleanExpiredEmergency` janitor / `EnsureInputPolicySafe`（敌对 INPUT policy=DROP 时注入直连保底） |
| `agent/utils/firewall/session.go` | L3 | 提交-确认会话引擎：`BeginSession`/`armTimerLocked`(time.AfterFunc 60s)/`ConfirmSession`/`RevertSession`/`ReclaimSession`(重启回收) |
| `agent/utils/firewall/snapshot.go` | L3 | `TakeSnapshot` 全量留底 + `RestoreSnapshot` 限定 `1PANEL_*` 链与纯 jump 的 scoped 恢复（不做全表 restore，跳过 `1PANEL_DOCKER`） |
| `agent/init/firewall/firewall.go` | L4 | 开机重放 + 敌对 policy 双杀防护 + 保底注入 + 回读校验 |
| `core/cmd/server/cmd/firewall.go` | L4 | `1pctl firewall rescue` 命令（纯 shell，不依赖 agent/DB） |

**已实现且比设计更稳健**
- ✅ L3 服务端计时器（与前端存活无关）+ marker 持久化 + 重启回收。
- ✅ scoped 快照恢复（限定 1PANEL 链、跳过 DOCKER、纯 jump 往返），部分还原失败 fail-fast + 不落盘 + 保留 marker 重试（评审 P1/P2，比设计更细）。
- ✅ L2 紧急 ACCEPT 直插裸 INPUT，revert/解绑后仍存活；TTL 编码进 comment，无需 DB。

**偏离/缺失（详见第七节）**
- ❌ **「确认前不落盘」被破坏**：`client.Port`/`RichRules` 每次操作即时 `SaveRulesToFile`（`iptables.go:184,283`），会话窗口内规则已写盘，安全完全依赖 `ReclaimSession` 还原成功。
- ✅ **2026-07-02 修订：external 锁外保护已实现。** external 模式不走 commit-confirm，而是在降低可达性且触及保底端口/调用方 IP 时直接拒绝高风险操作；core 经受信 unix socket 注入真实 caller IP，agent 仅在 unix socket 场景采信该内部头，恢复 L2 临时放行与单 IP 自锁检测（`319ce2b22` + `d379b1702`）。
- ❌ I1/I2 是单笔请求浅检查，非设计要求的「会话最终状态静态求值」；I2 分级表未实现且偏严。

## PR-3 · iptables 链布局重写（最高风险点）

**核心改动**

| 文件 | 改动 |
|---|---|
| `agent/utils/firewall/client/iptables/common.go:34-38` | 新链常量 `Chain1PanelGuard/Deny/Baseline/Allow/After` + `Chain1PanelDocker` + `ClearConntrack` |
| `agent/app/service/iptables.go` | `baseChainOrder` 定义五段顺序、`bindBaseChainsInOrder`（先全解绑再按序 -I）+ `assertBaseOrder` 回读断言；白名单/保底渲染；v6 镜像编排 |
| `agent/utils/firewall/client/iptables.go:149-155,219-225` | drop/reject→`DENY`、accept→`ALLOW` 路由；family 双写；conntrack 清连接 |
| `agent/init/firewall/migrate.go` | 存量 BASIC→新链文件一次性迁移（幂等、留 .bak） |

**新链布局（INPUT）**

```
filter/INPUT 固定五段（按序号 1..5 绑定 + 回读断言）：
  1. -j 1PANEL_GUARD     # lo + RELATED,ESTABLISHED（v6 含 ipv6-icmp/NDP）
  2. -j 1PANEL_DENY      # 黑名单 drop/reject —— 排在 BASELINE 之前（根治 #12897）
  3. -j 1PANEL_BASELINE  # SSH + 面板端口 不可删保底
  4. -j 1PANEL_ALLOW     # 80/443 默认白名单 + 用户放行（可删）
  5. -j 1PANEL_AFTER     # 严格模式兜底 DROP（实为 DROP tcp + DROP udp）
  ?. -j 1PANEL_INPUT     # 高级过滤，可绑/可解绑，插在 AFTER 之前（非固定基础段）
```

**设计对照**
- ✅ 五链全部存在，DENY 真正排在 BASELINE 之前且黑名单可压过 SSH/面板/80-443（根治 #12897）；固定序号绑定 + 回读断言（根治 #12476）；80/443 改为可删白名单默认值；`conntrack -D -s` 清连接；ip6tables 镜像链。
- ⚠️ 设计稿写「6 段固定」，代码把高级过滤做成**可绑/可解绑的 `1PANEL_INPUT`**（非固定基础段）—— 语义等价但措辞与实现不符。
- ⚠️ 严格模式 AFTER 为「DROP tcp + DROP udp」而非设计 §3.4 的「DROP all」（ICMP/SCTP 仍放行）。
- ✅ **2026-07-02 修订：80/443 迁移归类已修复。** `a93f72862` 将旧 `BASIC_BEFORE` 中精确匹配的 80/443 ACCEPT 归入可编辑 ALLOW，而非只读 BASELINE。
- ✅ **2026-07-02 修订：迁移 fail-open 已加固。** 预迁移快照失败会中止迁移；广源且覆盖保底端口的旧 DENY 规则写入 `deny.quarantine` 且不加载；BASELINE 回读失败时会清空 AFTER 暂停严格布局并记录 degraded。

## PR-4 · 数据层（指纹 + 两张新表 + 删除 cleanUnUsedData）

**核心改动**

| 项 | 内容 |
|---|---|
| 新增表 | `firewall_rule_meta`（指纹关联描述/source/family，fingerprint uniqueIndex）、`firewall_state`（单行 id=1 开机自检状态） |
| 新增模型 | `agent/app/model/firewall_meta.go`：`FirewallRuleMeta` + `FirewallState` |
| 新增迁移 | `AddFirewallMetaTables`（`init.go:1032`），已注册进 `migrate.go:89-90`，AutoMigrate 建表 + 从旧表保守回填 |
| 指纹算法 | `fingerprint.go`：`sha256(family\|scope\|kind\|action\|protocol\|srcIP\|srcPort\|dstIP\|dstPort\|targetIP\|targetPort\|interface)[:16]` hex，字段先规范化（CIDR/端口区间/协议/空值统一） |
| 删除项 | `cleanUnUsedData` 自动删除行为彻底移除（全仓仅剩注释），改为用户显式触发 `CleanOrphanFirewallRecords`（keep-set 一次性删，只清 port/address，跳过 advance/forward） |
| 设置默认值 | `constant.FirewallPortWhiteListValue = "80/tcp,443/tcp,443/udp"`（含 UDP 443 / HTTP/3） |

**设计对照**
- ✅ 两表确实建出（非悬空模型）、指纹算法与 §3.3 逐字段一致、`cleanUnUsedData` 替代修掉 C3 索引 bug、required 保底集 vs 可编辑白名单区分清晰 —— 与设计 §3.8 高度吻合。
- ❌ **`FirewallProvider` 预留设置项完全未实现**：设计 §3.8/§3.9 要求作为设置键预留（默认空=iptables，Stage 3 切 nftables），但 constant/agent/core/frontend 全仓 grep `FirewallProvider` 无匹配。Provider 仅是 `firewall_state` 的运行时检测字段，缺 Stage 3 切换占位。
- ❌ **回填 source 恒为 "panel"**：`legacyFirewallRuleKey` 的 default 分支也返回 `known=true`（`init.go:1094`），导致 `source=legacy` 成为死代码，设计「算不出指纹标 legacy」从未触发。
- ❌ **`firewall_state.Consistent` 偏离语义**：设计要求是 DB/文件 vs 系统的一致性校验结果，代码里只是 `strings.HasPrefix(status,"ok")` 的布尔镜像（`firewall.go:169`），无真实比对。
- ⚠️ 回填 family 硬编码 `"ipv4"`（`init.go:1060`），历史 IPv6 规则指纹 family 维度会失配。

## PR-5 · IPv6 镜像（managed 模式）

**核心改动**

| 文件 | 改动 |
|---|---|
| `agent/utils/firewall/client/iptables/ipv6.go` | `HasIP6tables()` sync.Once 缓存探测；v6 链增删/规则/绑定；`.v6` 持久化与重放；v6 链读取 |
| `agent/app/service/iptables.go:479-548` | `setupBaseChains6` 建 v6 五链、`renderGuardAfter6`（v6 GUARD 含 lo+ipv6-icmp/NDP+ESTABLISHED、AFTER DROP tcp/udp）、`bindBaseChainsInOrder6` |

**DTO/设置**：`PortRuleOperate`/`AddrRuleOperate` 新增 `Family`(ipv4/ipv6/both)；BASELINE/ALLOW 端口规则镜像写 `ip6tables` 同名链，删白名单同步清 v6 镜像。

**设计对照**
- ✅ ip6tables 镜像五链含 BASELINE6（SSH/面板）、GUARD6（NDP）、AFTER6；端口规则默认双栈；删端口 v4/v6 均不可达（修 #12997）；ip6tables 缺失则优雅降级（`capabilities.IPv6Rules=false`）。
- ❌ **v6 链顺序无回读断言**：`bindBaseChainsInOrder6()` 只 Unbind+Insert 后即返回，无 v6 版 `assertBaseOrder`（low）。
- ❌ **开机面板端口保底「再注入」与回读校验均为 IPv4-only**（`firewall.go:106-131`）：v6 BASELINE 面板端口完全依赖 `.v6` 文件重放，文件缺失/损坏时重启后 v6 无保底放行且无 degraded 告警（low）。
- ⚠️ **能力声明与实现落差**：external 模式 `IPv6Rules` 一律硬编码 `true`（`driver.go:171`），但 ufw 驱动 `ListPort` 主动跳过 `(v6)` 端口行（`ufw.go:227-229`），纯端口场景前端 v6 选项可能名不副实（low）。

## PR-6 · Docker 端口防护（1PANEL_DOCKER）

**核心改动**

| 文件 | 改动 |
|---|---|
| `agent/utils/firewall/docker.go` | `EnsureDockerChain`（DOCKER-USER 首条 jump 到 `1PANEL_DOCKER`，重断言）、`ApplyDockerPortRule`（conntrack `--ctorigdstport <port> --ctdir ORIGINAL -j DROP`）、`ApplyDockerIPRule`（-s ip -j DROP + ClearConntrack）、`LoadDockerRules`/`ReconcileDockerChain`/`DockerProtectionAvailable`；`dockerMu` 串行化、`dockerReplayPending` 处理 Docker 晚启动 |

**生命周期**：jump 在 boot / 每分钟巡检（经 `StartEmergencyJanitor`）/ 每次操作三处重断言（Docker 重启会重建 DOCKER-USER）。

**设计对照**
- ✅ 与 §3.6 一致且生命周期到位；conntrack 正确还原 DNAT 前端口；remove 即使 Docker 停机仍清理内核链 + 持久化文件避免陈旧 DROP 复活（P2）；`dockerReplayPending` 修「Docker 晚于 agent 启动→规则丢失」（P1）。
- ⚠️ **仅 IPv4**。
- ⚠️ **有意偏离设计 §3.5**：commit-confirm/快照回滚不再回滚 Docker 封禁规则（commit `385c3d558` 将 `1PANEL_DOCKER` 与会话/快照彻底解耦，`persistManagedChains` 不纳管 `1panel_docker.rules`）。设计字面要求 scoped 恢复「限定 1PANEL_* 链」，开发中发现纳入会导致开机空内容覆盖文件的 P1，遂主动解耦。属合理工程偏离（Docker 规则只增加拦截不会锁外），但需在 changelog 注明。
- ⚠️ **纯端口黑名单不清已建连接**：`ClearConntrack` 仅在 RichRules(带 address) 与 `ApplyDockerIPRule` 调用；纯端口 `client.Port(drop)` 与 `ApplyDockerPortRule` 均不调 `conntrack -D`，故「封某端口」对该端口现存连接不立即生效，UI 无「需重连」提示（low）。

## PR-7 · 前端 capabilities 驱动渲染 + 提交-确认卡片

**核心改动**

| 文件 | 改动 |
|---|---|
| `frontend/src/views/host/firewall/session-confirm.vue` | 全局提交-确认卡片（el-alert + 60s 倒计时 + 变更明细 + 确认保留/立即撤销 + 3s 轮询 `/session/status`） |
| `frontend/src/views/host/firewall/status/index.vue` | mode 徽章 + tooltip、ufw+firewalld 冲突横幅、开机自检 degraded 横幅 |
| `frontend/src/views/host/firewall/status/snapshot/index.vue` | 快照抽屉（列表 + 经提交-确认流恢复，含 IPv6 标签） |
| `frontend/src/views/host/firewall/{port,ip}/operate/index.vue` | applyToDocker 勾选（检测到 Docker 默认勾选）；port 对话框 family 选择器（仅 `mode==='managed' && capabilities.ipv6Rules`） |

**设计对照**
- ✅ 落地了「安全栈接入 + 字段管线打通」：commit-confirm 卡片、mode 徽章、冲突/开机横幅、快照抽屉、Docker 勾选、port family 选择器、capabilities 部分驱动渲染（`advance.filter`/`forward.forwardImpl`）。
- ✅ **2026-07-02 修订：核心交互层已补齐到可验收状态。** 后续前端提交重做概览四区仪表盘、入站评估顺序可视化、风险预检、初始化向导、保底/可编辑端口区分、未激活态 CTA、隔离规则抽屉与安全提示文案。快照 diff 预览仍未做，留作后续增强。
- ❌ `fireName` 硬判断**残留 30 处**（设计目标 0-2），`fireName!=='-'` 仍是「防火墙是否就绪」的事实判断主力，未改为读 capabilities。
- ❌ **Bug**：`status/index.vue` 的 `onInit()` switch 缺 `break`，存在 fall-through —— `chainName` 永远落为 `'1PANEL_INPUT'`、msg 永远是 advance 文案（`status/index.vue:281-294`）。
- ❌ **「清理失效描述」按钮被移除**（commit `5078e20af` 删了前端 API 绑定），但后端 `/firewall/clean` 端点仍保留 —— 当前用户**无 UI 入口触发清理**，与设计 §9.4 要求不符。
- ⚠️ 存在两套 Docker 探测接口：状态头用 `container.loadDockerStatus`，对话框用 `firewall.loadFireDockerStatus`。
- ⚠️ IP 规则对话框**缺 family 选择器**（`RuleIP` 接口有 `family?` 字段但 UI 不暴露），与 port 对话框不一致；双栈机封 IP 可能只封 v4。

## PR-8 · core 单写者委托（删除双写者）

**核心改动**

| 文件 | 改动 |
|---|---|
| `core/utils/firewall/firewall.go` | **整包删除**（−51，目录不存在、core 内零 import），消灭 core 直接 shell 调 ufw/firewall-cmd 的双写者（修 C2） |
| `core/app/service/setting.go:312-345` | `UpdatePort` 改为经 unix-socket（`proxy_local`）委托 agent `POST /api/v2/hosts/firewall/panel-port`，agent 失败则整体失败（先开新再切换） |
| `agent/app/service/firewall.go:749-786` | `UpdatePanelPort`「只增不删」：iptables 未初始化 no-op、已初始化向 `1PANEL_BASELINE` 追加 ACCEPT + 持久化（含 ip6tables 双栈）；external 防火墙未运行跳过、运行时原生放行 + reload |

**设计对照**
- ✅ 与 §3.9 完全符合：整包删除、委托只增不删、消灭「开新失败+删旧成功」双失联窗口（修 C2）。
- ❌ **`/firewall/operate`（start/stop/restart 防火墙）未挂 L2 中间件**，与 §3.10「既有变更型端点全部挂 L2」不符；`/firewall/panel-port` 由 core loopback 委托可接受（中间件对 loopback 本就跳过），但 `operate stop` 是真实变更型操作（low）。

---

## 5. 新增/变更 API 端点汇总

| 端点 | 方法 | 语义 | 文件 |
|---|---|---|---|
| `/hosts/firewall/session/status` | POST | 提交-确认会话状态 | `firewall.go:LoadFirewallSession` |
| `/hosts/firewall/session/confirm` | POST | 确认保留变更 | `ConfirmFirewallSession` |
| `/hosts/firewall/session/revert` | POST | 立即撤销变更 | `RevertFirewallSession` |
| `/hosts/firewall/snapshot/list` | POST | 快照列表 | `ListFirewallSnapshot` |
| `/hosts/firewall/snapshot/restore` | POST | 恢复快照（进会话） | `RestoreFirewallSnapshot` |
| `/hosts/firewall/docker/status` | POST | DOCKER-USER 可用性 + 纳管规则 | `LoadFirewallDockerStatus` |
| `/hosts/firewall/quarantine` | GET | 查看升级迁移隔离的旧 DENY 原文规则 | `ListFirewallQuarantine` |
| `/hosts/firewall/quarantine/clean` | POST | 清除隔离文件并在 quarantined 状态下恢复 boot status | `CleanFirewallQuarantine` |
| `/hosts/firewall/panel-port` | POST | core 委托单写者改面板端口 | `UpdateFirewallPanelPort` |
| `/hosts/firewall/clean` | POST | 显式清理失效描述（替代 cleanUnUsedData，前端无入口） | `CleanOrphanFirewallRecords` |
| `/hosts/firewall/filter/rule/{search,operate,batch}` `/filter/operate` `/filter/chain/status` | POST | iptables 高级 filter 规则 | `firewall.go` |

**DTO 新增字段**：`PortRuleOperate`/`AddrRuleOperate` 加 `Family`(ipv4/ipv6/both) + `ApplyToDocker`；`ForwardRuleOperate` 加 `ForceDelete`；`FirewallBaseInfo` 加 `Mode`/`Capabilities`/`Conflict`/`BootStatus`/`Consistent`；新增 `PanelPortUpdate`/`FirewallSessionInfo`/`FirewallSnapshot`/`FirewallDockerStatus`/`FirewallCapabilities`/`FirewallConflict`。

**L2 中间件挂载**：`FirewallEmergency` 挂在 port/forward/ip/batch/update/filter/snapshot-restore 端点；**未挂** `/firewall/operate` 与 `/firewall/panel-port`。

## 6. 新增表 / 设置项 / 删除项

| 类别 | 项 |
|---|---|
| 新增表 | `firewall_rule_meta`、`firewall_state` |
| 新增设置默认值 | `FirewallPortWhiteList` 默认 `80/tcp,443/tcp,443/udp` |
| **未实现的设置项** | `FirewallProvider`（设计要求预留，全仓无此键） |
| 删除（后端） | `core/utils/firewall` 整包、`cleanUnUsedData` 自动行为 |
| 删除（前端） | 「清理失效描述」按钮 API 绑定（后端端点仍在） |

## 7. i18n 变化

- **2026-07-02 修订：前端 10 个语言包 key 集合已补齐。** `5c3a8e4b2` 回填 `es-ES/ja/ko/ms/pt-BR/ru/tr/zh-Hant` 的防火墙 key；T4/T5 新增文案同步写入全部 10 个前端语言包；T6 将 `zh-Hant` firewall 命名空间英文占位手工繁化。
- **后端 agent i18n 新 key 已按 10 个 yaml 补齐。** 批量错误聚合、会话状态机等后端错误文案在 `en/zh/zh-Hant/es-ES/ja/ko/ms/pt-BR/ru/tr` 均有 key，非中英文语言目前以英文占位为主。

---

# 第三部分 · 破坏性变更与迁移注意

## ⚠️ BREAKING / Behavior Change（按风险排序）

### B1（critical）· 存量机升级触发一次性活体链迁移
- 旧 `BASIC*` 三链 → 新五链布局，旧文件存为 `.bak`。
- commit `bc75d3f6d` 通过 `legacyMigrationPending` 修复了「旧布局未迁移时因 `/run` 引导标记跳过重放导致防火墙失效直到重启」的 P1。
- commit `a93f72862` 后迁移 fail-open 加固：预迁移快照失败直接中止；任一新链文件写失败不会改名旧文件；广源且覆盖保底端口的旧 DENY 隔离到 `deny.quarantine`；80/443 ACCEPT 归入可编辑 ALLOW。
- **剩余风险**：设计 §3.4 step5 的“失败时自动整体 RestoreSnapshot”仍未实现，开机重放失败主要依赖 `failed:`/`degraded:` 状态与 fail-open 分支提示；必须通过 S6 升级演练确认存量机语义。
- **必须做 S6 升级演练**，禁止仅凭编译上线。

### B2（high）· 黑名单语义反转：DENY 先于 BASELINE
- 黑名单现在可压过 SSH/面板/80-443 的放行（根治 #12897），是对「白名单压制一切」哲学的有意反转。
- 用户升级后黑名单行为改变；误封自己 IP 会真生效（有四层安全栈兜底）。

### B3（high）· 80/443 从硬编码保底改为可关闭
- 新装机器：80/443 是可删白名单默认值。
- ✅ **2026-07-02 修订：升级归类 bug 已修。** `a93f72862` 将旧 80/443 ACCEPT 归入可编辑 ALLOW；仍需 S6 升级演练确认存量机实际规则语义。

### B4（high）· 提交-确认窗口改变操作流
- 降低可达性的变更默认 60 秒内不确认即自动回滚。用户需理解「应用后要点确认」。

### B5（medium）· external 模式采用“拒绝高风险操作”而非 commit-confirm
- external（ufw/firewalld）不做 60 秒 commit-confirm；`319ce2b22` 改为在高风险降低可达性操作命中保底端口或当前 caller IP 时直接拒绝，避免进入不可自动回滚的状态。
- `d379b1702` 修复 unix socket 代理下 caller IP 丢失问题，L2 临时放行和单 IP 自锁检测可拿到真实浏览器 IP。external 仍建议在云控制台保留备用登录路径。

### B6（medium）· 改面板端口语义变为「只增不删」
- 旧端口不会被立即删除，需用新端口登录后由白名单同步或手动关闭。

### B7（medium）· 降级 .bak 不自动恢复
- 旧版本不识别 `.bak`，降级需人工把 `.bak` 改回原名（见 4.3）。

## 8. 升级迁移检查清单（合并/发布前必验）

| # | 检查项 | 关联 |
|---|---|---|
| 1 | rebase `dev-v2` 后无冲突、不回退 14 个上游 PR、防火墙改动完整 | 第 0 节 |
| 2 | 从带黑名单+白名单+严格模式+转发+高级规则+中文描述的 v2.x 存量机升级（S6）：逐条语义等价、SSH/面板可达、无新增开放端口、描述保留率 | B1 |
| 3 | 80/443 升级后应归入可编辑 ALLOW，不能落入不可删 BASELINE | B3 |
| 4 | 锁外演练 S1-S10（force 红线、60s 自动回滚、坏链文件重启、敌对 `iptables -P DROP`、S9③ 即时落盘断电重启复活路径） | B1/B2 |
| 5 | Docker 重启后 `1PANEL_DOCKER` jump 自动恢复 + 容器端口封禁生效 | PR-6 |
| 6 | ip6tables 缺失机优雅降级 | PR-5 |
| 7 | 四种 provider 环境改面板端口：新端口可达、旧端口不立即删 | PR-8 |

## 9. 已知缺口与未交付项（发布门禁）

| 缺口 | 严重度 | 说明 |
|---|---|---|
| nftables「零改动接入」留缝不成立 | high | service 大量 `Name()=="iptables"` 硬分支 + 直接引用 `iptables.Chain*` 链常量，接入 nftables 必然要改 `detect()` 与 service（详见第六节理由） |
| 迁移/重放失败不自动整体还原（§3.4 step5） | medium | `a93f72862` 已做 fail-open 与隔离，但 `runBootReplay` 失败仍不自动 `RestoreSnapshot`，需真机门禁验证 |
| `1pctl firewall doctor` 未实现 | low | 设计 §6/§7.2 建议项，仅 `rescue` 存在 |
| 测试矩阵 S1-S10 + 测试工具（probe/seed/比对器） + 自动化测试 | high | 完全未交付；整个 firewall 子系统无任何 `*_test.go`；commit message 反复声明「compiles but NOT release-ready」 |
| 真机升级/锁外演练未完成 | high | S1-S10、S6 升级演练、Docker 重启、ip6tables 缺失机等仍需 Linux/VNC 环境验证 |
| 快照 diff 预览未实现 | low | 快照列表/恢复已有，恢复前 diff 预览仍是后续增强 |
| 非 zh/en/zh-Hant 语言多为英文占位 | low | key 已补齐，不再暴露 i18n key；高质量本地化可后续逐语种完善 |
| `cleanUnUsedData` 替代物前端无入口 | low | 后端 `/firewall/clean` 保留，前端按钮被移除 |

---

## 附录 A · 设计承诺 vs 代码现实（一句话裁决）

> 本次重构最重要的结论：**能力模型落到了「数据标注」层面，但没落到「接口/留缝」层面。**

设计稿 §3.2 把「nftables Stage 3 接入时只需新增一个 driver、service/前端零改动」列为留缝验收标准。当前代码：
1. 仍是设计明令废弃的**单一扁平 `FirewallClient` 接口**（`client.go:15-33`），无 `RuleDriver/ServiceDriver/ForwardDriver/FilterDriver/BaselineDriver` 分解；
2. service 层仍有 **5+ 处 `client.Name()=="iptables"/"ufw"` 字符串分支**（`firewall.go:307/352/530/684/758/866` 等）；
3. **`1PANEL_*` 链名泄漏到 service 层与 init 层**（直接引用 `iptables.Chain1PanelAllow/Deny/Baseline` 等常量）；
4. `ProviderNftables` 仅是一个 `detect()` 从不产出的常量。

因此即便将来新增 nftables driver，`detect()` 要改、service 里 `Name()=="iptables"` 分支不会命中、直接引用的 `iptables.Chain*` 是 iptables 专属 —— **接入 nftables 必然要动 service**。「留缝」目前只留了一个 `Mode/Capabilities` 的数据外壳，没留接口缝。

**建议加一个「反向」回归门禁**：grep service 层不得出现 `iptables.Chain1Panel*` 引用与 `client.Name()=="..."` 分支（当前会失败），作为 nftables 零改动接入的守线。

## 附录 B · commit 谱系（feat/dev2 相对 dev-v2，三点 diff）

| commit | PR/性质 |
|---|---|
| `9137a7d6b` | PR-1 驱动/capabilities + 探测缓存 + 共存降级 |
| `0db4511f6` | PR-2 安全栈 L1/L2/L3/L4 |
| `d9bdf42e1` | PR-3 链重写 GUARD/DENY/BASELINE/ALLOW/AFTER + 存量迁移 |
| `af3f966d6` | PR-4 数据层 指纹 + meta/state 表 + 删 cleanUnUsedData |
| `a74fa631c` | PR-5 IPv6 managed v6 镜像链 + family |
| `09507441c` | PR-6 Docker 防护 1PANEL_DOCKER |
| `50fb849dc` | PR-7 前端 capabilities 驱动渲染 + status tab |
| `efb984ec6` | PR-8 单写者 core 委托 panel-port |
| `385c3d558` | 修复：Docker/恢复 stale-rule 缺口；Docker 与 commit-confirm 解耦 |
| `bc75d3f6d` | 修复：升级首启重放 + IPv6/UFW/Docker 评审缺口 |
| `6e5918d97` | 重构：链管理 + conntrack 处理（引入 baseChainOrder） |
| `5078e20af` | 重构：移除冗余 mode 变量 + 清理 API（删前端 clean 按钮） |
| `11d78ad68` | 修复：Docker 规则管理 + 快照恢复加固 |
| `ddb10ac8d` | 修复：会话 revert/reclaim 错误处理 |
| `5d2e62354` | 文档：firewall-refactor-design.md + report.md（开发依据，非交付物，合并前考虑移除） |
| `108a3b39f` | 后续：代理目标、路由与语言支持整理 |
| `54387f90e` | 后续：端口/IP 规则确认逻辑、UI 提示与翻译增强 |
| `9e6d861f` | 后续：严格/白名单模式引入 |
| `f6ca9e95` | 后续：旧链迁移与 session revert 加固 |
| `76b1fa63` | 后续：规则管理与 Docker 集成增强 |
| `4a723767` | 后续：入站/转发规则 UI 与翻译增强 |
| `923f0ffd` | 后续：概览页重构为四区运维仪表盘 |
| `80e81d4f` | 后续：Phase B 前端清理完成 |
| `319ce2b2` | 修复：external 模式锁外检查加固 |
| `5c3a8e4` | 修复：前端 8 个非 zh/en 语言包防火墙 key 回填 |
| `a93f7286` | 核心修复：迁移隔离、开机 fail-open、80/443 归类 |
| `d379b170` | 核心修复：unix socket 受信 caller IP 通道 |
| `7985a75` | 核心修复：批量操作逐条错误聚合 |
| `6b680d4` | 核心修复：提交确认会话状态机加固 |
| `5f79db8` | T1：概览页待确认横幅去重 |
| `54a4069` | T2：后端小修（IPv6 日志、迁移源判定、保护链清单等） |
| `a90a993` | T3：死代码与孤儿 i18n 清理 |
| `2b3a43e` | T4：隔离规则 quarantine 最小 UI 闭环 |
| `d75ca6c` | T5：防火墙安全 UX 文案与 CTA 增强 |
| `bed2c75` | T6：zh-Hant firewall 命名空间手工繁化 |
| 本提交 | T7：更新 changelog 与升级公告；T8 merge `dev-v2` 待执行 |

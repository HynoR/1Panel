# 1Panel 防火墙重构方案（最终设计稿）

> 版本：v1.0 草案，2026-06-12
> 性质：供核心开发者（ssongliu 等）评审；评审通过后本文档即为施工依据，每个 PR 的改动范围、验收标准均已写明，agent/开发者可直接照此开工。
> 基线：基于当前 `dev-v2` 重新实现。`feat/firewall-safety-stage1` 分支与 `plan2/plan.md` 仅作参考，可复用的代码会在文中标注，但不做分支合并。
> 背景调研：见同目录 `firewall-refactor-report.md`（上游 ~130 条 issue 的诟病全景）。

---

## 0. 重构目标（已与负责人对齐）

1. iptables 模式与 Docker 网络共存且能管住 Docker 暴露的端口（DOCKER-USER 纳入管理）。
2. 为未来 nftables 接入预留干净的驱动边界（本期**不实现** nftables，重构内测无误后作为 Stage 3 接入）。
3. 模式边界明确：对 **ufw / firewalld 只管理、不介入**其持久化与规则体系；对 **iptables（及未来 nft）全权管理**。
4. 清理各 provider 适配中自相矛盾、互相打架的逻辑（详见 §2 矛盾清单）。
5. **任何路径下用户不能把自己锁在外面**——这是硬性验收项。
6. 保底策略：SSH 端口 + 1Panel 面板端口为不可移除保底；80/443 为默认保底但**允许用户关闭**。
7. 升级迁移平滑：存量用户默认行为不变；不允许迁移错误导致误开放端口或规则大规模失效。

---

## 1. 现状盘点（dev-v2，文件级）

### 1.1 代码分布

| 位置 | 内容 |
|---|---|
| `agent/utils/firewall/client.go` | `NewFirewallClient()`：每次调用现场探测，优先级 firewalld > ufw > iptables；两者并存直接报错 |
| `agent/utils/firewall/client/{firewalld,ufw,iptables}.go` | 三个 driver 实现同一个扁平 `FirewallClient` 接口 |
| `agent/utils/firewall/client/iptables/` | iptables 原语：链管理、规则读写、按链持久化到文件、forward/filter |
| `agent/app/service/firewall.go` | 端口/IP/转发规则服务，`client.Name()` 分支散落 5 处；`cleanUnUsedData` 异步删描述记录 |
| `agent/app/service/iptables.go` | "高级"子系统：BASIC 三链 init/bind/unbind、1PANEL_INPUT/OUTPUT 过滤、端口白名单同步 |
| `agent/app/service/firewall_setting.go` | 端口白名单（#12912）：`FirewallPortWhiteList` 设置 + 强制含面板/SSH 的 required 集 |
| `agent/init/firewall/firewall.go` | 开机重放各链文件（`/run/1panel_boot_mark` 防重入） |
| `agent/app/model/firewall.go` | `Firewall` 表：按 (type, port, protocol, strategy, srcIP) 元组与活动规则相等匹配的"镜像+描述"表 |
| `core/utils/firewall/firewall.go` | core 改面板端口时**直接 shell 调 ufw/firewall-cmd**（`core/app/service/setting.go:325`） |
| `frontend/src/views/host/firewall/` | status/port/forward/ip/advance 五个 tab，43 处 `fireName` 写死判断 |

### 1.2 当前 iptables 链布局

```
filter/INPUT:
  1. -j 1PANEL_BASIC_BEFORE   # lo、ESTABLISHED、SSH/面板/白名单端口 无条件 ACCEPT
  2. -j 1PANEL_BASIC          # 用户端口/IP 规则（ACCEPT 与 DROP 混在一条链）
  3. -j 1PANEL_BASIC_AFTER    # 严格模式时的兜底 DROP
  ?. -j 1PANEL_INPUT          # 高级过滤，序号由 loadBindNumber 动态计算
filter/OUTPUT:  -j 1PANEL_OUTPUT
filter/FORWARD: -j 1PANEL_FORWARD
nat/PREROUTING: -j 1PANEL_PREROUTING   nat/POSTROUTING: -j 1PANEL_POSTROUTING
持久化: 每链一个文件，存于 FirewallDir，开机逐链重放
```

---

## 2. 矛盾与缺陷清单（重构要逐条消灭的"技术累赘"）

| # | 矛盾/缺陷 | 位置 | 后果（关联 issue） |
|---|---|---|---|
| C1 | ufw 模式下转发功能偷偷用 iptables NAT 链实现，名义上"ufw 管理"实则混合体 | `client/ufw.go:206-216` | 用户认知混乱；ufw reload 与 1Panel NAT 链互相影响（#10345） |
| C2 | 双写者：core 改面板端口直接 shell 调 ufw/firewall-cmd，绕过 agent | `core/utils/firewall/firewall.go` | 删旧端口与 reload 竞态可造成双失联；agent 侧白名单/记录全不知情 |
| C3 | DB `firewalls` 表靠元组相等匹配活动规则，`cleanUnUsedData` 异步删除"漂移"记录 | `service/firewall.go:159,560` | 用户描述静默丢失；循环内删元素的索引 bug |
| C4 | `LoadBaseInfo` 不分 provider 一律调 `iptables.LoadInitStatus` | `service/firewall.go:66` | firewalld/ufw 场景下返回无意义的 init/bind 状态 |
| C5 | 端口白名单只在 iptables 模式生效，ufw/firewalld 下无保底概念 | `service/iptables.go:392+` | 同一功能跨 provider 语义不一致 |
| C6 | BASIC_BEFORE 无条件放行 22/80/443/面板端口，黑名单写在其后的 BASIC | 链布局 | **黑名单对这些端口完全失效**（#12897、#12372） |
| C7 | 仅写 IPv4，从不碰 ip6tables | 全部 | 删了端口 IPv6 照常可达（#12997 仍 OPEN） |
| C8 | 不管理 DOCKER-USER，INPUT 规则管不到容器转发流量 | 全部 | "防火墙形同虚设"最大来源（#726、#12471） |
| C9 | `BindChain` 固定序号 1/2/3 插入 + advance 链动态序号，互相挤位 | `service/iptables.go:156+` | 链顺序错乱，AFTER 的 DROP 跑到 BEFORE 之前，SSH 实时断连（#12476 仍 OPEN） |
| C10 | 开机重放无预校验、无保底注入、无回读验证；坏文件可让 DROP 链半挂载 | `init/firewall/firewall.go` | 重启失联类 issue（#11553、#11121） |
| C11 | ufw+firewalld 并存时 `NewFirewallClient` 直接 error，整个防火墙页面瘫痪 | `client.go` | #6734 |
| C12 | 每次 API 调用都现场 `cmd.Which` 探测 provider | `client.go` | 页面 CPU 飙升类问题的帮凶（#8388） |

---

## 3. 总体设计

### 3.1 双模式模型（显式化）

```
FirewallMode:
  managed   — 系统无 ufw/firewalld。1Panel 是规则真源，全权管理 iptables（未来 nft）。
  external  — 系统有 ufw 或 firewalld。1Panel 只通过原生命令读写，不注入自有链到
              filter 主路径，不替代原生持久化（"管理而不介入"）。
```

判定规则（替换现行 `NewFirewallClient` 逻辑，修 C11/C12）：

1. 探测结果进程内缓存（TTL 60s + 防火墙启停操作后主动失效），不再每请求探测。
2. firewalld 与 ufw 并存：选**正在运行**的那个为 provider；都没运行选 firewalld（保持现有优先级）；**都在运行**才报错，且错误只影响操作接口，`/firewall/base` 仍正常返回并携带 `conflictState` 供前端展示处置指引（卸载其一）。
3. 都不存在 → managed 模式，provider=iptables（本期）；`FirewallProvider` 设置项预留 nftables（Stage 3）。

例外（经论证后保留的"介入"，要在 UI 明示）：

- **端口转发**：ufw 无原生转发能力，external+ufw 下转发仍由 1Panel 的 NAT 链实现（现状 C1），但 UI 标注"由 1Panel 通过 iptables NAT 实现，与 ufw 无关"；firewalld 用原生 `--add-forward-port`（现状保持）。NAT 表不在 ufw 的管理范围内，不构成对 ufw 的介入。
- **Docker 防护（DOCKER-USER）**：与防火墙模式正交，只要检测到 Docker 的 iptables 集成就可用（见 §3.6）。
- **紧急自救规则**（caller-IP 临时放行）：external 模式下仍以 best-effort 方式插 INPUT 顶部，ufw/firewalld reload 会清掉它——接受，因为它只是兜底而非功能。

### 3.2 驱动层重构（为 nftables 留缝）

废弃单一扁平接口 + `client.Name()` 字符串分支，改为能力接口组合：

```go
// agent/utils/firewall/driver.go
type Provider interface {
    Name() string                  // iptables | ufw | firewalld | (nftables)
    Mode() Mode                    // managed | external
    Probe() (ProviderStatus, error) // installed / running / version
    Capabilities() Capabilities
}

type Capabilities struct {
    Rules        bool // 端口/IP 规则
    Forward      bool
    ForwardImpl  string // native | panel-nat
    Filter       bool // 高级过滤（仅 managed）
    Baseline     bool // 保底集注入（仅 managed；external 为操作前检查）
    Snapshot     string // panel | native-export
    IPv6Rules    bool
    DefaultDrop  bool // 严格模式
}

type RuleDriver interface {
    ListRules(q RuleQuery) ([]Rule, error)
    ApplyRules(ops []RuleOp) error   // 单条也走批量入口，便于事务化
}
type ServiceDriver interface { Start, Stop, Restart, Reload; Status() }
type ForwardDriver interface { ListForward; ApplyForward }
type FilterDriver interface { ... }                  // 仅 IptablesDriver 实现
type BaselineDriver interface {                      // 仅 managed 实现
    EnsureBaseline(b Baseline) error
    VerifyBaseline(b Baseline) error                 // 回读校验，含顺序断言
}
```

硬性要求：

- `1PANEL_*` 链名只允许出现在 `agent/utils/firewall/client/iptables/` 包内部；service 层、API、前端一律不引用链名（替代现行 `req.Chain` 透传，修 C4 的同类问题）。
- service 层用 `Capabilities()` 分支，禁止再出现 `client.Name() == "ufw"` 类判断。
- 前端用 `/firewall/base` 返回的 capabilities 渲染，删除全部 43 处 `fireName` 判断。
- nftables Stage 3 接入时只需新增一个实现 managed 系列接口的 driver，service/前端零改动——这是"留缝"的验收标准。

### 3.3 统一规则模型与指纹

```go
type Rule struct {
    Fingerprint string // 见下
    Family      string // ipv4 | ipv6 | both
    Scope       string // input | output | forward | docker
    Kind        string // port | address | forward | filter
    Action      string // accept | drop | reject
    Protocol, SrcIP, SrcPort, DstIP, DstPort, TargetIP, TargetPort, Interface string
    Description string // 来自 meta 表 join
    Source      string // panel | system | legacy
}
```

**指纹** = `sha256(family|scope|kind|action|protocol|srcIP|srcPort|dstIP|dstPort|targetIP|targetPort|interface)` 取前 16 字节 hex，字段先规范化（CIDR 标准化、端口区间统一 `a-b`、协议小写、空值统一 `*`）。同一条语义规则在重启前后、在 DB 与系统间指纹恒定。这是修 C3 的基础：**描述按指纹关联，不再按元组裸匹配，更不自动删除**。

### 3.4 managed 模式链布局（核心变更，修 C6/C9）

```
filter/INPUT 固定 6 个 jump，序号即真理，每次 bind 后回读断言顺序：
  1. -j 1PANEL_GUARD     # lo ACCEPT；ESTABLISHED,RELATED ACCEPT；caller-IP 紧急放行(TTL)
  2. -j 1PANEL_DENY      # 用户全部 drop/reject 规则（IP 黑名单、端口封禁）
  3. -j 1PANEL_BASELINE  # 保底集：SSH 端口 + 面板端口 ACCEPT（不可移除）
  4. -j 1PANEL_ALLOW     # 用户 accept 规则 + 端口白名单（80/443 默认在此，可删）
  5. -j 1PANEL_INPUT     # 高级过滤（可选 bind，位置固定在 ALLOW 与 AFTER 之间）
  6. -j 1PANEL_AFTER     # 严格模式时 DROP all
其余链（OUTPUT/FORWARD/NAT 三链）布局不变；新增 1PANEL_DOCKER（见 §3.6）。
```

设计取舍说明（评审重点）：

- **DENY 在 BASELINE 之前**：黑名单对所有端口生效，包括 SSH/面板——封禁 SSH 爆破源这一核心诉求成立，#12897 类问题根治（80/443 在 DENY 之后的 ALLOW）。
- 由此带来的"封自己 IP 锁外"风险用四层兜底（§3.5），而不是用"无条件放行端口"这种破坏黑名单语义的方式兜底——这是对现行设计哲学的**有意反转**：失联保护从"静态白名单压制一切"改为"动态自救通道 + 操作守门"。
- **ESTABLISHED 保留在 GUARD 最前**（性能：每包都过这条）。代价是已建立连接不受新黑名单影响——补偿措施：添加 deny 规则时若系统存在 `conntrack` 工具，自动 `conntrack -D -s <ip>` 清掉该源的现存连接，使封禁立即生效；无 conntrack 时 UI 提示"对已建立连接需重启连接方生效"。
- 80/443 不再硬编码：作为 `FirewallPortWhiteList` 的**默认初始值**写入（升级时若用户从未改过该设置则保持 80/443 在列），用户可在白名单设置里删除——满足"允许用户关掉保底"。SSH/面板端口沿用现有 required 集概念（`loadRequiredFirewallPortWhiteList`），渲染进 BASELINE 链，UI 只读展示。

**存量链迁移**（升级时一次性，幂等）：

1. 全量快照（§3.5 的快照机制）。
2. 读取 BASIC/BASIC_BEFORE/BASIC_AFTER 活动规则：BEFORE 中的预置项 → GUARD/BASELINE/白名单；BASIC 中 ACCEPT → ALLOW、DROP/REJECT → DENY；AFTER → AFTER。
3. 新链建好后原子换绑（先插新 jump 再删旧 jump，任何时刻 SSH/面板放行规则至少存在于一处）。
4. 回读验证 6-jump 顺序 + BASELINE 规则存在。
5. **任何一步失败 → 从快照整体还原旧链布局，模块进入只读告警态**，绝不留半成品、绝不放开本应封锁的端口。
6. 旧链文件保留为 `.bak`，两个版本后清理。

### 3.5 防锁外安全栈（修 C9/C10，吸收旧分支可复用代码）

四层防御，全部为 managed 模式完整实现，external 模式实现到标注的层级：

| 层 | 机制 | external 模式 | 复用来源 |
|---|---|---|---|
| L1 事前 | 操作预检，分两级：**红线（硬拒绝，force 也不行，见 §3.5.2）**——无条件 DROP、同时阻断 SSH 与面板；**风险（force + 强制走 L3 事务）**——deny 匹配调用方 IP、全局封 SSH、关闭 80/443 白名单等 | ✅ 同样适用 | 新写 |
| L2 事中 | 变更型 API 中间件给调用方 RemoteAddr 插 10 分钟临时 ACCEPT（managed 写入 GUARD 链；external best-effort 插 INPUT 顶）；后台每分钟清过期 | ✅ best-effort | 旧分支 `emergency.go`/`firewall_emergency.go` 基本可直接移植 |
| L3 事后 | **提交-确认事务（本方案默认交互，详见 §3.5.1）**：可能降低可达性的变更立即应用 + 自动拍快照 + 武装服务端确认窗口；窗口内无人确认（被锁外的人点不到确认按钮）则自动整体还原 | ✅ 以逆操作日志实现（§3.5.1） | 快照恢复改造自旧分支 `snapshot.go`：恢复范围必须**限定 1PANEL_* 链与 jump 位置**，不做全表 iptables-restore（避免回滚掉窗口期内 Docker 新增的 NAT 规则——旧分支此处注释的声称是错的） |
| L4 灾备 | ① 开机流程：staging 链预校验文件 → 重放 → 注入 BASELINE → 回读验证内容**与顺序** → 全部通过才 bind；任何失败不 bind 并记录状态供 UI 横幅展示。**"不 bind 保命"依赖 INPUT 默认策略为 ACCEPT——若检测到 policy 已被外部置为 DROP，则中止前先向 INPUT 直接注入 SSH/面板紧急 ACCEPT**，杜绝"坏文件 + 敌对 policy"双杀。② 新增 `1pctl firewall rescue` 命令：解绑全部 1PANEL 链或恢复最近快照，供用户从云厂商 VNC/串口自救（回应 #5852 用户被迫重装） | ✅ rescue 对 external 提供"停用 ufw/firewalld"指引 | 开机流程复用旧分支 `init/firewall` 改造；staging 校验复用 `persistence.go` 改动；rescue 新写 |

快照规格：`iptables-save` 全量留底（文件 `<FirewallDir>/backup/<utc-ts>_<tag>.v4|.v6`，保留 10 份），但**恢复时只提取并重建 1PANEL_* 链及其 jump**。external 模式快照 = `ufw status numbered` / `firewall-cmd --list-all-zones` 导出，仅用于展示比对与"逐条原生命令重放"式还原（显式确认，不绕过原生持久化）。

### 3.5.1 提交-确认事务模型（commit-confirm，默认交互）

防火墙变更的标准时序，等同 Juniper `commit confirmed` / MikroTik Safe Mode 的面板化：

```
用户点"保存" → 立即应用到系统 → 前端进入约 2s 的"应用中"过渡态（见下第 7 条）
   → 服务端武装确认窗口(默认 60s，可配 30-300s)，前端转入确认倒计时
   → 用户在面板点"确认保留"（这个 HTTP 请求本身就是可达性证明：能点到=没锁外）
       → 变更落定，写持久化文件
   → 窗口超时无确认（锁外的人物理上点不到）
       → 自动整体还原到会话前（上一已确认版本）状态
```

定死的设计细节：

1. **立即应用，而不是"保存后延迟应用"**。必须先生效，用户才能在当前连接上实际验证没把自己锁外；延迟到确认时才应用，等于把危险时刻推到无人值守的未来，确认机制反而失去意义。"延迟"体现在**持久化**上：确认前不写规则文件，所以即使 agent 在窗口期崩溃、机器断电重启，开机重放的也是会话前的规则——多一层免费兜底。
2. **适用范围按"可达性方向"分类**，避免确认疲劳和意外回退：
   - **降低可达性**的操作（加 deny/reject、删 accept、开严格模式、删白名单项、删转发、快照恢复、解绑链）→ 强制走事务；
   - **纯增加可达性**的操作（加 accept、删 deny）→ 直接生效不进事务。它们不可能锁外，而"用户加完放行规则就走开 → 60 秒后良性规则被静默撤销"才是真正的事故。
3. **会话语义**：窗口内的后续变更并入同一会话并刷新计时器；确认/回退都是整体的（还原点 = 会话第一笔变更前的快照）。单节点同时只有一个会话；多管理员的变更并入同一会话，确认卡片显示累计变更明细。
4. **计时器在 agent 服务端**，与前端存活无关——被锁外恰恰意味着前端已经死了。agent 启动时（含开机 init）检查到存在未确认会话 → 视同超时立即还原，堵死"变更后 agent 崩溃/重启"的逃逸路径。
5. **回退实现按模式分流**：managed = 限定 1PANEL 链的快照恢复；external = 逆操作日志（每笔 ufw/firewall-cmd 操作在执行前记录其逆命令，回退时倒序重放）——不碰原生持久化体系，仍守"不介入"承诺。
6. **与 L2 的关系互补不冲突**：caller-IP 自救通道让"误封自己"的人大概率仍能打开面板——此时他看到确认卡片，自己决定"立即撤销"还是"确认保留"；L3 自动回退兜底的是连面板都摸不到的情形（换 IP 路径、NAT 出口变化、封了面板端口本身）。
7. **前端 2s"应用中"过渡态**：保存后规则虽已下发，但前端锁定操作约 2 秒并显示"应用中"，期间禁止下一笔提交与确认点击。作用：① 给 iptables/原生命令的实际落地留缓冲，避免用户在规则尚未完全生效时误判"没生效"而重复提交；② 物理上阻止"保存后 0 秒手滑点确认"——确认必须发生在用户有机会感知变更效果之后，可达性证明才有意义。过渡态结束后转入 60s 确认倒计时。

### 3.5.2 锁外硬性不变量（红线，force 也不可逾越）

针对两个已知的高频锁外向量，定义两条任何代码路径都不得违反的不变量。红线校验在**会话最终状态**上做静态求值（基于统一规则模型模拟一个任意远端源的包在求值顺序中的命运），不依赖具体链布局，因此 PR-2 即可实现、PR-3 换链后继续生效。

**I1 默认策略红线——1Panel 永不制造无条件 DROP：**

- managed 模式：任何代码路径禁止执行 `iptables -P INPUT/OUTPUT/FORWARD DROP`；"严格模式"只通过 `1PANEL_AFTER` 链内规则实现（链可解绑、可被 rescue 清除，policy 改了则什么都救不了）。
- 用户提交的规则中，匹配条件为空（无源/目的/端口/协议限定）的 drop/reject：INPUT 方向 → 拒绝并引导走"严格模式"开关（它自带 BASELINE 保护）；OUTPUT 方向 → 直接拒绝（无正当场景，且 OUTPUT 无条件 DROP 同样锁外——SSH 回包走不出去）。
- external 模式：1Panel 永不代发 `ufw default deny` / firewalld target 变更类命令；通过面板**开启** ufw/firewalld 前，先确保 SSH/面板端口已放行（将现有 `addPortsBeforeStart` 形式化为开启流程的强制前置步骤）。
- 开机流程对"外部已置 DROP"的敌对环境的处理见 L4 ①。

**I2 抢救通道红线——SSH 与面板至少一个可达，SSH 优先：**

对会话最终状态模拟求值"远端访问 SSH 端口"与"远端访问面板端口"两个包的命运：

| 求值结果 | 处置 |
|---|---|
| 两者均被阻断 | **硬拒绝，force 不可逾越**。文案："该变更将同时阻断 SSH 与 1Panel，已拒绝执行" |
| 仅 SSH 被全局阻断 | force + 强制 L3 事务，文案建议优先保 SSH（"SSH 是最后的抢救通道"） |
| 仅面板被全局阻断 | 正常 L3 事务流程（用户有意只暴露 SSH 是合理场景） |
| 按源 IP 的定向封禁 | 不触发 I2（不是全局阻断），但匹配调用方 IP 时走 L1 风险级 |

- managed 模式下 BASELINE 链已结构性保证两端口 ACCEPT 存在，I2 的实际检查对象是 DENY 链与高级过滤（含 1PANEL_OUTPUT 的出向规则）的叠加效果。
- external 模式：执行删除/封禁类原生命令前，查询当前 ufw/firewalld 规则集做同样的两包求值（在 default deny 策略下删掉 SSH 放行且面板也无放行 → 硬拒绝）。
- 快照恢复、批量导入、迁移器同样过 I1/I2 校验——"恢复一个会锁外的快照"和"手动制造锁外"没有区别。

### 3.6 Docker 防护模块（修 C8，plan2 未覆盖的新增设计）

与防火墙模式正交的独立子模块，启用条件：检测到 `DOCKER-USER` 链存在（即 Docker iptables 集成开启）。

实现：

1. 建 `1PANEL_DOCKER` 链，确保 `DOCKER-USER` 第一条为 `-j 1PANEL_DOCKER`；开机、Docker 服务事件（复用现有 docker 状态监测）、每次模块操作时重新断言该 jump（Docker 重启会重建 DOCKER-USER）。
2. 规则形态（DOCKER-USER 中流量已经过 DNAT，必须用 conntrack 还原原始目的端口）：
   - IP 封禁：`-s <ip> -j DROP`
   - 端口防护：`-p tcp -m conntrack --ctorigdstport <port> --ctdir ORIGINAL -j DROP`（可叠加 `-s` 白名单例外）
3. 入口（KISS，不另开页面）：
   - IP 规则对话框新增勾选"同时拦截 Docker 端口流量"，检测到 Docker 时**默认勾选**——用户加黑名单的预期就是"封掉这个 IP"，不应该因为业务跑在容器里就失效。
   - 端口规则列表为 Docker 发布的端口加标识（复用 #12961 的端口占用数据），其 drop 规则提供同款勾选。
4. 持久化：独立文件 + 开机重放（走 §3.5 L4 同一校验流程）；指纹与描述同样进 meta 表（scope=docker）。

### 3.7 IPv6（修 C7）

- 规则模型带 `family`；端口规则默认 `both`，IP 规则按地址族自动判定。
- IptablesDriver 对 `both/ipv6` 规则镜像写 ip6tables 同名链（GUARD/DENY/BASELINE/ALLOW/AFTER 全镜像；BASELINE v6 必须有，旧分支 `iptables/ipv6.go` 可复用）。`ip6tables` 不存在时 capabilities.IPv6Rules=false，UI 降级提示。
- 转发 NAT 本期仍 v4-only（文档与 UI 注明）；external 模式 ufw/firewalld 原生已双栈，不动。
- 升级兼容：存量规则视为 `ipv4`，不自动补 v6（避免"迁移误开放"）；新增规则默认 both。

### 3.8 数据层（修 C3）

```sql
-- 替换 firewalls 表的职责
CREATE TABLE firewall_rule_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,            -- port | address | forward | filter | docker
    family TEXT NOT NULL DEFAULT 'ipv4',
    description TEXT,
    source TEXT NOT NULL DEFAULT 'panel',  -- panel | system | legacy
    created_at DATETIME, updated_at DATETIME
);
CREATE TABLE firewall_state (      -- 单行状态表
    id INTEGER PRIMARY KEY,
    mode TEXT, provider TEXT,
    last_boot_status TEXT,         -- ok | degraded:<原因> | failed:<原因>
    last_boot_at DATETIME,
    consistent INTEGER,            -- 最近一次校验 DB 描述/文件与系统是否一致
    last_check_at DATETIME
);
```

- 旧 `firewalls` 表迁移：逐行计算指纹写入 meta；算不出指纹的（含 Deprecated 字段行）标 `source=legacy` 保留，不删。迁移后旧表保留两个版本再清理。
- 删除 `cleanUnUsedData`（连同其索引 bug）。失效描述的清理改为：列表接口标记"无对应活动规则"，用户在 UI 主动点"清理失效描述"。
- 设置项：沿用 `FirewallPortWhiteList`（默认值含 80/443）、`IptablesStatus` 等；`FirewallProvider` 预留（默认空=iptables，Stage 3 启用 nftables 值）。

### 3.9 单写者（修 C2）

`core/app/service/setting.go:325` 改面板端口时，不再调 `core/utils/firewall.UpdatePort` 直接 shell，改为通过现有 core→agent 内部通道调 agent 的端口规则接口（带"面板端口变更"语义）：agent 负责按当前 mode 放行新端口、更新 required 保底集、**只增不删**——旧端口的关闭由用户用新端口成功登录后在 UI 显式确认（或 24h 后台自动清理），消灭"开新失败+删旧成功"的双失联窗口。`core/utils/firewall/` 整包删除。

### 3.10 API 与前端

API（保持旧端点不动，前端零断裂；新增以下）：

```
POST /hosts/firewall/base            # 扩展返回: mode/provider/capabilities/conflictState/
                                     #   bootStatus/consistent/baseline(含 80/443 开关态)
POST /hosts/firewall/snapshot/list
POST /hosts/firewall/snapshot/restore    # 高危，过 L2 中间件，进入提交-确认会话
POST /hosts/firewall/session/status      # 未确认会话: {changes[], remainSeconds, since}
POST /hosts/firewall/session/confirm     # 确认保留（请求本身即可达性证明）
POST /hosts/firewall/session/revert      # 立即撤销，整体还原到会话前
POST /hosts/firewall/docker/status       # DOCKER-USER 可用性 + 已纳管规则
```

既有变更型端点全部挂 L2 中间件；请求 dto 增加可选 `applyToDocker`、`family` 字段（不传保持旧语义）。

前端（保持五 tab 结构不动，KISS）：

- 全部 `fireName` 判断改读 capabilities；advance tab 仅 `capabilities.filter` 时显示（修 C4 的前端面）。
- status tab：模式徽章（"1Panel 全权管理" / "管理 ufw（不介入）"）、开机状态/一致性横幅、快照抽屉（旧分支 `snapshot-drawer.vue` 可改造复用）、ufw+firewalld 冲突处置指引。
- 新增全局确认卡片：倒计时 + 累计变更明细 + 确认/撤销，轮询 session/status（§3.5.1）。
- IP/端口规则对话框：风险预检提示（L1 返回的 risk 字段）、Docker 勾选、IPv6 family 选择。
- 白名单设置页：required（SSH/面板，只读）与可编辑列表（含默认 80/443）分区展示，删除 80/443 时走 L1 风险确认。

---

## 4. 实施计划

Stage 1+2 合为一个发布列车（同一 minor 版本），按以下 PR 顺序施工；**每个 PR 独立可合、可回退，合并后存量行为不变**（行为变更集中在 PR-3，有迁移护栏）。

| PR | 内容 | 主要改动文件 | 验收标准 |
|---|---|---|---|
| PR-1 基建 | 驱动层拆分 + Capabilities + mode 显式化 + 探测缓存 + 并存降级（C1 标注/C4/C11/C12） | `agent/utils/firewall/*`（重组）、`service/firewall.go` 去 Name() 分支、`/firewall/base` 扩展 | 纯重构：四种环境（ufw/firewalld/iptables/裸机）下所有现有 API 回归通过；ufw+firewalld 并存时页面可打开 |
| PR-2 安全栈 | L2 中间件、L3 提交-确认会话引擎(§3.5.1：限定 1PANEL 链快照恢复 + external 逆操作日志 + 确认前不落盘 + agent 重启回收未确认会话)、L4 开机流程重写(staging 校验+保底注入+顺序断言)+`1pctl firewall rescue`、L1 预检、前端确认卡片 | `agent/utils/firewall/{emergency,snapshot,session}.go`(部分移植旧分支)、`agent/middleware/`、`agent/init/firewall/`、`agent/router/ro_host.go`、`cmd/`(1pctl)、前端确认卡片组件 | 锁外演练全过（§5 场景 S1-S5、S9、S10）；坏持久化文件重启后主机可达且 UI 有横幅 |
| PR-3 链重构 | GUARD/DENY/BASELINE/ALLOW/AFTER 布局 + 存量链迁移 + 白名单 80/443 可删 + conntrack 清除 + 固定 bind 顺序（C6/C9 根治） | `client/iptables/` 链定义与迁移器、`service/iptables.go` 白名单渲染目标改链、`service/firewall_setting.go` | 升级前后规则语义等价（自动化对比 iptables-save 规范化输出）；黑名单对 80/443 生效；S6 演练过；迁移失败自动还原验证 |
| PR-4 数据层 | 指纹 + meta 表 + state 表 + 旧表迁移 + 删 cleanUnUsedData（C3） | `model/`、`repo/`、`migration/`、`service/firewall.go` 列表 join 改指纹 | 规则增删改后描述不丢；升级后旧描述保留率 100%（可指纹化的）+ legacy 兜底 |
| PR-5 IPv6 | managed 模式 v6 镜像链 + family 字段 + BASELINE v6（C7） | `client/iptables/ipv6.go`(复用旧分支)、dto/前端 family | 双栈机上删端口后 v4/v6 均不可达；纯 v4 机无 ip6tables 时优雅降级 |
| PR-6 Docker | 1PANEL_DOCKER 模块全量（C8） | `agent/utils/firewall/docker.go`(新)、docker 事件挂钩、dto `applyToDocker`、前端勾选+徽章 | 容器发布端口場景：IP 封禁后该 IP 访问容器端口不通；Docker 重启后防护自动恢复 |
| PR-7 前端收尾 | capabilities 全面接管渲染，删 43 处 fireName；status tab 信息化 | `frontend/src/views/host/firewall/**` | `grep fireName` 仅余 status 展示用 0-2 处；四 provider 环境 UI 正确降级 |
| PR-8 单写者 | core 委托 agent，删 `core/utils/firewall`（C2） | `core/app/service/setting.go`、core→agent 调用、agent 端口变更语义 | 改面板端口在四种环境下新端口可达且旧端口按"确认后关闭"流程走 |

**Stage 3（独立后续版本，重构内测无误后）**：nftables driver——实现 §3.2 managed 系列接口（inet 表天然双栈），`FirewallProvider` 切换 API + 回退路径。旧分支 `client/nftables*` 约 1200 行可作底子，但需按新驱动接口重排。本期唯一为它做的事：接口边界（§3.2 验收标准）+ 设置项占位。

---

## 5. 测试矩阵与锁外演练（发布门禁）

环境矩阵：{Debian 11/12、Ubuntu 22.04/24.04、Rocky 9} × {ufw 活动、firewalld 活动、iptables managed、全裸} × {Docker 有/无} × {全新安装、从 v2.x 升级}。

必过演练场景：

- **S1** 添加 deny 规则封禁自己当前 IP（force 通过 L1）→ 60s 不确认 → 自动还原，SSH 恢复。
- **S2** 开启严格模式且白名单为空 → L1 阻断提示；force 后心跳还原可用。
- **S3** 手工损坏一个持久化链文件 → 重启 → 主机可达、链未 bind、UI 横幅、rescue 命令可恢复。
- **S4** 开机重放过程中 kill agent → 再次启动幂等收敛，无半挂载链。
- **S5** 改面板端口且新端口被占用/防火墙放行失败 → 旧端口仍可用（PR-8）。
- **S6** 升级迁移：含黑名单+白名单+严格模式+转发+高级规则的存量机 → 升级后逐条语义等价、SSH/面板可达、无新增开放端口。
- **S7** 黑名单 IP 访问 80/443 与 Docker 发布端口 → 全部不通（PR-3+PR-6）；删除该黑名单后恢复。
- **S8** ufw 模式全量回归：1Panel 操作均通过 ufw 原生命令落地，`ufw reload` 后规则不漂移（external 不介入验证）；external 模式下的提交-确认回退（逆操作日志倒序重放）正确。
- **S9** 提交-确认事务专项：① 加 deny 规则后不确认 → 60s 自动还原；② 窗口期内连续 3 笔变更 → 确认/回退均整体生效；③ 变更后立即 `kill -9` agent → agent 重启后未确认会话被回收还原，且因确认前未落盘，直接断电重启后开机重放的也是会话前规则；④ 纯放行类变更不进事务、立即落定。
- **S10** 红线专项（§3.5.2）：① 提交无条件 DROP 规则（INPUT 与 OUTPUT 各一）→ 硬拒绝；② 构造同时阻断 SSH+面板的组合变更（含跨多笔会话累积达成的）→ 硬拒绝；③ 全局封 SSH 但面板放行 → 要求 force+事务；④ 手工 `iptables -P INPUT DROP` 后损坏链文件并重启 → 开机注入直连紧急 ACCEPT，主机可达；⑤ external 模式 ufw default deny 下删除 SSH 放行且无面板放行 → 硬拒绝；⑥ 恢复一个会锁外的历史快照 → 被 I2 拦截。

发布节奏：PR-1~8 合入 → beta 版本 → 社区内测一个版本周期（重点征集 #12476/#12897/#12997 原 issue 用户回访）→ 稳定版。Stage 3 nftables 另起一轮。

---

## 6. 实现难度自评（诚实版）

总体判断：**写代码不是瓶颈，验证才是**。设计本身没有未知技术（全是 iptables 原语 + Go 工程），但防火墙模块的特殊性在于"错一次就是用户失联"，所以难度集中在迁移正确性和环境组合上。

| PR | 难度 | 风险 | 说明 |
|---|---|---|---|
| PR-1 基建 | 中高（量大） | 低 | 纯重构但 diff 面大（~2-3k 行触及）。最大风险是重构中悄悄改了行为——用"金标对比测试"防（重构前录制四种环境下全部 API 响应，重构后逐字节比对） |
| PR-2 安全栈 | 中 | 中 | 旧分支约 600 行可移植（emergency/middleware/snapshot 骨架）。**真正难的是"限定 1PANEL 链的快照恢复"**：要解析 iptables-save、只重建自有链、按记录位置重插 jump——这是全新代码，边界 case 多（链不存在、jump 重复、位置漂移），需要最重的单测 |
| PR-3 链重构+迁移 | **高（全计划之最）** | **高** | 在数百万台异构存量机上做活体链迁移。BEFORE 链里预置规则和用户规则的分类判定、原子换绑、失败还原，每一步都要幂等。这个 PR 的代码量不大但要消耗整个计划 1/3 以上的测试精力。安全栈先行合入（PR-2 在前）就是为了给它兜底 |
| PR-4 数据层 | 中低 | 低 | 指纹规范化的边界 case（CIDR、端口区间、空值）是细活但可纯单测覆盖；迁移是机械工作 |
| PR-5 IPv6 | 中 | 中 | 镜像链让验证面翻倍；旧分支 ipv6.go 可复用。风险在各发行版 ip6tables 存在性/行为差异 |
| PR-6 Docker | 中 | 中 | iptables 部分很小；工作量在生命周期上——Docker 重启重建 DOCKER-USER 后的 jump 重断言、`--ctorigdstport` 在不同内核/conntrack 版本上的行为验证 |
| PR-7 前端 | 中低 | 低 | 面广但机械；43 处 fireName 替换 + 新组件 |
| PR-8 单写者 | 低中 | 低 | 取决于 core→agent 通道现状（拍板点 3） |

工期粗估（一名熟悉本仓库的后端 + 半个前端，或 agent 辅助开发 + 人工评审）：编码 4-6 周，但**测试与内测周期至少同等长度**，总体一个季度量级到稳定版。最危险的 20%：PR-3 迁移器、PR-2 限定恢复、开机流程——这三块建议人工逐行评审。

---

## 7. 测试作战手册（基于"手头有各种服务器"）

### 7.1 分层结构

```
L0 单测（无环境要求，CI 跑）
    指纹规范化、iptables-save 解析、迁移分类器、白名单解析——全部表驱动
L1 单机集成（本地 VM 批量刷矩阵）
    multipass/libvirt 起 Debian 11/12、Ubuntu 22/24、Rocky 9 官方 cloud image，
    每场景跑完回滚 VM 快照。矩阵的大头在这层消化，便宜且可重复
L2 双机真机（关键层：防火墙必须从外面验证）
    目标机 + 探针机。探针机跑断言脚本：nc/nmap 扫端口开闭矩阵、ssh 可达性、
    curl 面板、ping6/nc -6 验 IPv6。所有"规则生效与否"以探针机视角为准，
    目标机自查 iptables -S 只作辅助
L3 锁外演练（必须用带 VNC/串口的云服务器或 IPMI 物理机）
    S1-S5 场景故意把自己锁外，验证自救链路。这是真机不可替代的部分
L4 浸泡（1-2 台长期机）
    cron 每小时随机增删规则 + 每天重启一次，跑一周，比对规则集无漂移、
    描述无丢失、无重复规则累积
```

### 7.2 关键工具（建议随 PR 一起交付，放 `ci/` 或测试仓库）

1. **探针断言脚本** `firewall-probe.sh <target> <expect-file>`：表驱动（端口/族/预期通断），输出 diff。L2/L3 的核心。
2. **存量机模拟器** `seed-legacy-rules.sh`：在旧版本上批量制造代表性规则集（黑名单 50 条、白名单、严格模式、转发 10 条、高级规则、带中文描述的记录），用于升级测试的"考前布题"。
3. **语义等价比对器**：升级前后各取 `iptables-save`，规范化（排序、去 counter、链名映射旧→新）后做集合 diff；同时比对 DB 描述保留率。S6 的判分器。
4. **`1pctl firewall doctor`**（建议纳入 PR-2 交付）：一条命令输出 mode/provider/开机状态/6-jump 顺序断言/保底规则存在性/conntrack 可用性/最近快照。既是测试工具，也是 beta 期间让用户贴 issue 的诊断神器，能砍掉一半来回问环境的支持成本。

### 7.3 真机分配建议

- 各发行版 VM 矩阵跑 L1（功能 + 迁移）。
- 2 台带云控制台的服务器专跑 L3 锁外演练（每次演练后用控制台救回来，不用重装）。
- 1 台 Docker 重负载机（跑十几个容器、compose 应用）专测 PR-6 + S7。
- 1 台真实从老版本一路升上来的"脏机"（规则手工改过、有第三方 fail2ban 之类）——最接近真实用户，S6 的终极考场。
- 留 1 台 ufw 机和 1 台 firewalld 机做 external 模式全程回归（S8），验证"不介入"承诺。

---

## 8. Beta 发布与用户沟通

### 8.1 发布节奏

```
beta.1 (公告+定向邀请) → 2 周收敛 → beta.2/rc → 2 周静默期(无新增 P1) → 稳定版
```

- 走现有 beta/dev 升级通道，**绝不自动推送到稳定通道**；稳定版的 go/no-go 标准：迁移失败率可观测且全部落在只读告警态（零失联报告）、S1-S8 在社区环境复验通过。
- **定向邀请**：到 #12476、#12897、#12997、#12007、#726 原 issue 下回帖邀请受影响用户测 beta——他们动机最强、且环境正是要验的环境。这是开源项目独有的测试资源。

### 8.2 告知用户（三个触点）

1. **发布前**：GitHub 置顶 Discussion + 论坛(bbs.fit2cloud.com)/公众号长文（中英），结构：哪些诟病被修了（直接列 issue 号）→ 行为变更点（黑名单现在能压过端口放行、80/443 可关）→ 升级时会发生什么（自动迁移+自动快照）→ 万一出问题怎么自救（`1pctl firewall rescue`、云控制台路径）→ 怎么回退旧版本。
2. **升级时**：升级对话框 changelog 高亮"防火墙模块重构"，链接长文。
3. **升级后首次进入防火墙页**：一次性展示**迁移报告卡片**（N 条规则重新归类、M 条描述保留、X 条标记为 legacy 待确认；失败则显示"已还原旧布局"+引导）。迁移透明化能直接消灭大量恐慌性 issue（纳入 PR-3 后端生成 + PR-7 前端展示）。

### 8.3 降级路径（必须在发布说明里写清）

迁移时旧链文件保留为 `.bak`；用户降级回旧版本后，旧代码开机重放 `.bak` 即恢复旧布局（迁移器须保证 `.bak` 与迁移前逐字节一致）。新链 `1PANEL_GUARD` 等在旧版本下是无人引用的孤儿链，提供 `1pctl firewall rescue --clean-new-chains` 清理。降级流程要进 S6 测试。

### 8.4 beta 期间支持预案

- issue 模板加防火墙专项：要求贴 `1pctl firewall doctor` 输出。
- 每个 beta 版本固定负责人盯防火墙标签 issue，48h 响应；出现任何疑似失联报告立即停灌 beta 并出 hotfix。

---

## 9. 前端交互设计（用户"舒服明了"的具体方案）

设计原则：消灭两种用户痛苦——"**我加的规则为什么没生效**"（理解成本）和"**我不敢点，怕把自己锁外面**"（恐惧成本）。保留五 tab 骨架不动（KISS + 老用户肌肉记忆），在其内做四件事：

### 9.1 状态页：把模式和保底说成人话

顶部三卡片：

```
┌─ 防火墙状态 ─────────┐ ┌─ 保底通道 ──────────────┐ ┌─ 快照 ─────────────┐
│ ● 运行中  iptables   │ │ SSH :22 ✓   面板 :9999 ✓ │ │ 最近: 2分钟前       │
│ [1Panel 全权管理] ⓘ  │ │ 80/443 ✓ (可关闭)        │ │ 共 8 份  [管理]     │
│ 开机自检: 通过 ✓     │ │ [管理白名单]              │ │                    │
└─────────────────────┘ └─────────────────────────┘ └────────────────────┘
```

- 模式徽章 tooltip 用人话："1Panel 全权管理 iptables 规则" / "ufw 由系统管理，1Panel 代为操作、不修改其启动行为"。
- 开机自检异常/迁移失败/ufw+firewalld 冲突 → 页面级横幅 + 处置指引按钮。

### 9.2 规则生效顺序可视化（性价比最高的一个改动）

端口/IP 列表页顶部加一条静态"数据包流向"指示条（div+icon 即可，不要画布库）：

```
入站流量 → [自救通道] → [黑名单 ✕] → [保底 SSH/面板] → [放行规则 ✓] → [默认策略: 宽松/严格]
```

每段可点击 → 过滤列表只看该层规则；规则列表加"生效层级"彩色 tag（黑名单=红、保底=灰锁、放行=绿）并默认按真实求值顺序排序。这一条直接回答 #12897 类"为什么没生效"的灵魂拷问，把链布局变成用户心智模型。

### 9.3 危险操作：从"恐惧"到"有保险"

- **风险预检对话框**（L1 返回 risk 时）：不说"确定吗"，说后果+保险："此规则将拦截你当前的 IP (1.2.3.4)，应用后若失联，60 秒内未确认将自动撤销。" 勾选确认才放行。
- **红线拒绝**（§3.5.2）与风险确认在视觉上必须可区分：红线是错误态（红色 alert，无任何继续按钮），文案直说原因和替代路径——"该操作会同时阻断 SSH 与 1Panel 面板，已拒绝。如需默认拒绝入站，请使用「严格模式」开关"。不给用户"再点一次就能过"的错觉。
- **确认卡片（commit-confirm 的前端面，§3.5.1）**：保存后卡片先呈现约 2s 的"应用中…"过渡态（spinner，确认/撤销按钮禁用），随后切换为倒计时态：`3 处变更已生效，0:58 后自动撤销 [明细] [确认保留] [立即撤销]`。这是 OS 改分辨率"保留设置？"模型，零学习成本；会话内继续改规则，卡片累计计数并刷新倒计时。纯放行类变更直接生效不弹卡片，避免确认疲劳。
- **快照恢复**：恢复前展示 diff 预览（"将恢复 12 条规则：新增放行 2、移除放行 1、新增封禁 3"），建立信任后才让点确认。

### 9.4 其他落点

- **Docker 可见性**：端口列表中 Docker 发布的端口加容器图标徽章（数据复用 #12961）；IP 黑名单对话框在检测到 Docker 时显示已勾选的"同时拦截容器端口流量"。回应"防火墙形同虚设"的认知问题——让用户看见容器端口的防护状态。
- **初始化向导**：替换现在语义不明的 init-base 按钮——三步：确认 SSH/面板端口 → 选默认策略（宽松/严格，配后果说明）→ 应用并自检（探针式自查+绿勾）。
- **失效描述**：列表中"无对应活动规则"灰色 tag + 工具栏"清理失效描述"按钮（替代被删除的 cleanUnUsedData 自动行为）。
- **移动端**：心跳确认卡片和风险对话框必须在窄屏可用——失联场景下用户很可能正拿手机抢救。
- 全部新文案进 i18n 9 语言（zh/en 先行，其余可机翻后人工校 zh-Hant/ja）。

---

## 10. 评审中需要核心开发者拍板的点

1. **§3.4 DENY 在 BASELINE 之前**（黑名单可封 SSH 爆破源，锁外风险转由安全栈兜底）——这是对现行"白名单压制一切"哲学的反转，是本方案最大的行为变更，需要 ssongliu 确认。
2. conntrack-tools 非默认安装，"封禁立即生效"在无 conntrack 机器上降级为提示——是否接受，还是把 conntrack 加入 1Panel 推荐依赖。
3. core→agent 内部调用通道的具体形式（PR-8），需确认现有 core 调 agent 的机制可承载。
4. 迁移失败进入"只读告警态"的 UX 文案与恢复引导。
5. Docker 勾选默认开（检测到 Docker 时 IP 封禁默认同步到 DOCKER-USER）——默认值是否符合预期。
6. 提交-确认事务（§3.5.1）：确认窗口默认 60s 是否合适（可配 30-300s）；"纯放行类变更直接生效、不进事务"的分类边界是否认可（备选：一切变更都进事务，代价是确认疲劳 + 用户走开后良性规则被意外撤销）。

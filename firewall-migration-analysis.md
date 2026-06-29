# 1Panel 防火墙重构 — 迁移分析报告（风险点 / 迁移点 / 健壮性）

> 版本：v1.0，2026-06-29
> 性质：归档分析报告，供核心开发者评审与上线决策。基于 `feat/dev2` 分支实际代码逐文件复核，与《firewall-refactor-design.md》（下称"设计稿"）逐条对照。
> 基线对照：设计稿 §3.4（存量链迁移六步）、§3.8（数据层）、§8.3（降级路径）、§5（测试矩阵）。
> 方法：所有结论均带 `file:line` 证据；凡代码与设计稿不一致处均明确点明，并标注严重度与 `isHandled`。

---

## 0. 文档定位：本报告回答三个问题

| 问题 | 回答位置 | 一句话结论 |
|---|---|---|
| **风险点在哪？** | §3 风险点清单 | 三个 high/critical 真空缺口集中在"崩溃/部分失败"对抗路径：迁移非原子、失败无自动回滚、崩溃后被 boot mark 阻止重试。 |
| **迁移点在哪？** | §2 流程拆解 + §4 迁移点清单 | 两类场景：①外部卸载 ufw/firewalld 切 managed；②老版本(2.x) 升级。迁移动作集中在 **agent 侧** `runBootReplay→migrateLegacyChains`，core 侧无任何 firewall 专属迁移项。 |
| **是否够健壮？** | §6 健壮性结论 | `yes-with-fixes`：正常路径幂等收敛、数据层 additive 无丢失；但 critical/high 项落地前**不建议广泛 GA**。 |

---

## 1. 摘要 + 健壮性裁决

### 1.1 摘要

防火墙迁移子系统由**四条独立路径**组成，彼此正交：

```
┌─────────────────────────────────────────────────────────────────────┐
│  迁移子系统四条路径                                                     │
├──────────────────┬──────────────────────────────────────────────────┤
│ (1) 链文件迁移    │ migrateLegacyChains: 旧 BASIC_* 文件 → 新           │
│                  │ GUARD/DENY/BASELINE/ALLOW/AFTER 文件，旧文件留 .bak │
│ (2) DB schema    │ AddFirewallMetaTables: additive 新增 meta/state     │
│                  │ 两表 + 按指纹回填，旧 firewalls 表保留不删           │
│ (3) provider 探测 │ Detect/detect: cmd.Which 三连探测 + 60s TTL 缓存    │
│                  │ + InvalidateProbe（仅 start/stop/restart 调用）     │
│ (4) 降级回滚      │ .bak 经 os.Rename 生成；rescue 命令人工自救          │
└──────────────────┴──────────────────────────────────────────────────┘
```

四条路径的**正常路径（无崩溃、磁盘有空间）骨架已落地**：升级首启窗口被正确堵住、DB 迁移不丢数据、commit-confirm 崩溃兜底扎实、开机有敌对 policy 双杀防护，且 `1pctl firewall rescue` 自救命令确实存在并可用。

但与设计稿对照，**最有价值的产出是几处实质性偏离/真空缺口**，且多落在设计稿 §5 测试矩阵 S6/S10 明确要求的场景上。详见 §3 / §5。

### 1.2 对 phase-1 事实的一处重要校正

> phase-1 迁移分析曾断言 `1pctl firewall rescue --restore-latest / --clean-new-chains` 命令"在代码库中根本不存在"，并据此给出 high 缺口。**该结论错误，应予撤销。**

实测：该命令完整实现于 `core/cmd/server/cmd/firewall.go`（`firewallCmd` / `firewallRescueCmd`，含 `--restore-latest` 与 `--clean-new-chains` 两个 flag，纯 shell、不依赖 agent/DB，agent 崩溃也可用）。phase-1 只 grep 了 `agent/cmd` 与 `cmd/`，**漏看 `core/cmd`**。

- 仍然成立：`doctor` 命令确实不存在（grep 无匹配）。
- 仍然成立：`rescue --restore-latest` 用**全表 `iptables-restore`**（`firewall.go:19` 帮助文本明写 "full iptables-restore"），与 agent 内 `RestoreSnapshot` 的"限定 1PANEL_* 链"恢复哲学相反，会覆盖窗口期 Docker/第三方规则——末路自救可接受，但两条恢复路径不一致，应在文档/UI 说明。

### 1.3 健壮性裁决

| 维度 | 裁决 |
|---|---|
| **readyForMigration** | **yes-with-fixes** |
| 正常升级路径 | ✅ 安全（幂等收敛、数据无丢失、有崩溃兜底与开机双杀防护） |
| 崩溃/部分失败对抗路径 | ❌ 不够健壮（迁移非原子、失败不回滚、崩溃后被 boot mark 阻止重试、失败态不强制只读） |
| 上线建议 | rankedGaps 中 **critical/high 共 4 项须作为广泛滚动升级前的强制前置条件**；当前迁移子系统**零自动化测试覆盖** |

**一句话结论**：架构方向正确、缺口可定点修复（无需重构），但因设计自评迁移为"全计划之最"高风险、当前失败无自动回滚且零测试，故为 `yes-with-fixes` 而非 `yes`。

---

## 2. 两类迁移场景的完整流程拆解

### 2a. 场景一：用户卸载 ufw/firewalld → 切换 iptables(managed)

**触发前提**：用户在 1Panel 之外（SSH 里 `apt remove ufw` / `dnf remove firewalld`），1Panel 完全不知情。

#### 状态机（时间轴）

```
T0  external 模式稳定运行
    probeCache = external（provider=ufw/firewalld）
    │
T0  ┌─ 用户 apt remove ufw（1Panel 之外，不经过 OperateFirewall）
    │  系统通常 disable ufw 并清掉其注入的内核规则
    │  ★ 无任何缓存失效钩子（InvalidateProbe 仅在 start/stop/restart 调用）
    ▼
T0~T0+60s   【错误模式窗口】
    probeCache 仍为 external（未过 TTL）
    /firewall/base 与所有写路径 isManagedMode()=false
    → 仍展示 ufw 操作入口、BeginSession 提交-确认事务不生效
    │
    ▼
≤T0+60s   probeTTL(60s) 过期 → 下一次 Detect 调 detect()
    cmd.Which("iptables") 命中 → 改判 managed（被动、非事件触发）
    │
    ▼
【保护真空】★★ 切判 managed 后，新链与保底集并不在运行期重建
    GUARD/DENY/BASELINE/ALLOW/AFTER 与 SSH/面板保底注入
    只在开机 runBootReplay 内执行，而 runBootReplay 被
    needInit() && legacyMigrationPending() 双门控跳过：
      · 该主机无旧 BASIC 文件 → legacyMigrationPending 恒 false
      · 进程未重启 → needInit 也为 false
    → 运行期根本不建链/不注保底
    │
    ▼
【真空持续】到下一次【整机重启】
    /run 清空 → needInit=true → runBootReplay 才执行：
      迁移(空)→EnsureInputPolicySafe→建链→注面板端口到 BASELINE→回读
```

#### 关键事实与证据

| 阶段 | 行为 | 证据 |
|---|---|---|
| 卸载无钩子 | `InvalidateProbe` 仅 3 处调用 | `agent/app/service/firewall.go:258/268/274`（OperateFirewall start/stop/restart） |
| 探测被动 | 60s TTL 缓存，无文件监听/inotify | `agent/utils/firewall/driver.go:79`(probeTTL=60s), `:88-101`(Detect 命中缓存直接返回) |
| 切判 managed | 仅 `cmd.Which("iptables")` | `agent/utils/firewall/driver.go:145` |
| 不自举 | 早退条件跳过 runBootReplay | `agent/init/firewall/firewall.go:30` `if !needInit() && !legacyMigrationPending() { return }` |
| 不继承 ufw 规则 | detect 切 managed 仅 `client.NewIptables()`，无导入逻辑 | `agent/utils/firewall/driver.go:146` |

**空窗期安全性**：INPUT 默认 policy=ACCEPT 时，真空=fail-open（不锁外，但保护语义完全丢失）；若外部已将 INPUT policy 置 DROP，则空窗期可能锁外。运行期 detect 翻转后 `firewall_state.Provider/Mode` 不刷新（仅 `recordBootStatus` 在 boot 时写），横幅展示的仍是上次开机（external）的自检结果，前端 mode（实时）与横幅（开机快照）可能矛盾。

### 2b. 场景二：老版本(2.x) → 新防火墙 升级

#### 状态机（升级首启）

```
升级 = 替换二进制 + 进程重启（注意：通常非主机重启）
    │ /run/1panel_boot_mark 仍在 → needInit()=false
    ▼
Init()  agent/init/firewall/firewall.go:19
    ├─ StartEmergencyJanitor()           # L2 清过期紧急放行
    ├─ ReclaimSession()                  # L3 回收未确认会话（唯一无条件兜底）
    └─ if !needInit() && !legacyMigrationPending() { return }
            │ legacyMigrationPending()=true（有旧 BASIC 文件、无 guard 文件）
            │ ★ 短路保证升级首启仍强制触发一次迁移+重放（评审 P1，设计意图正确）
            ▼
       runBootReplay()  firewall.go:38
            ├─ Detect() provider
            ├─ LoadDockerRules()                          # Docker 防护正交
            ├─ migrateLegacyChains()  firewall.go:79      # ★ 链文件转换（见下）
            ├─ EnsureInputPolicySafe(LoadBaselinePorts()) # L4① 敌对 policy 双杀防护
            ├─ 逐链 LoadRulesFromFile(+v6)                # GUARD/DENY/BASELINE/ALLOW/AFTER
            ├─ AddRule 面板端口 ACCEPT → BASELINE (v4 only) firewall.go:112
            ├─ bind-base-without-init  (bindBaseChainsInOrder + assertBaseOrder)
            ├─ CheckRuleExist 回读面板端口 (v4 only)        firewall.go:127
            └─ return ok | degraded:... | failed:...
            ▼
       recordBootStatus(status) → 写 firewall_state 单行表（仅供横幅展示）
```

#### 链文件转换内部（migrateLegacyChains, migrate.go:23）

```
GuardFileName 已存在? ──是──▶ 跳过（幂等，:26）
        │否
无任何旧 BASIC 文件? ──是──▶ 全新安装，直接返回（:30-34）
        │否
TakeSnapshot("pre-migration")  ★ 失败仅 Warnf 续跑（:37-39，best-effort）
        │
classifyLegacyFile × 3：逐条 -A <oldChain> 行分类
   BASIC_BEFORE: lo/ESTABLISHED → GUARD；其余(含 80/443 ACCEPT) → BASELINE  (:95-101)
   BASIC:        ACCEPT → ALLOW；DROP/REJECT → DENY                          (:102-107)
   BASIC_AFTER:  → AFTER                                                     (:108-109)
        │
writeChainRules × 5  ★ 任一失败仅 Errorf 续跑、不中止不回滚（:54-58）
        │
旧文件 os.Rename 为 .bak  ★ 无条件执行（:60-66）
```

#### 求值顺序反转对存量的影响

升级后 `baseChainOrder` 固定为 `GUARD(1)→DENY(2)→BASELINE(3)→ALLOW(4)→AFTER(5)`，**DENY 恒先于 BASELINE/ALLOW 求值**（设计稿 §3.4，根治 #12897）。对存量机的实质影响：

1. 旧布局中黑名单(DROP)与白名单(ACCEPT)的相对顺序由旧链决定；升级后所有 DROP→DENY(序2)、ACCEPT→ALLOW(序4)，黑名单**开始压过**白名单。这是**有意的行为反转**，但迁移即生效、无 dry-run/diff 报告，用户无感知。
2. 旧 `BASIC_BEFORE` 的 80/443 被一律归入**不可删的 BASELINE**（见 §3 风险点），升级用户反而删不掉 80/443，与全新安装体验不一致。

#### 失败还原与 .bak 降级

- **失败还原**：设计稿 §3.4 step5 要求"任一步失败→从快照整体还原"。**实际未实现**——`runBootReplay` 任何失败只 `return "failed:..."`，全程无 `RestoreSnapshot` 调用（firewall.go:38-156）；`migrate.go:37` 的 pre-migration 快照永不被用于回滚。
- **.bak 降级**：`.bak` 经 `os.Rename` 生成（与迁移前逐字节一致，符合 §8.3 字节级要求），但**全仓无任何代码读取 `.bak`**。旧版本开机只认原文件名（如 `1panel_basic.rules`，已被改名移走），且新建的 `1PANEL_GUARD` 等孤儿链旧版本不识别。因此 §8.3"旧代码开机重放 .bak 即恢复"**不自动成立，需人工** `mv *.rules.bak` 回原名 + `1pctl firewall rescue --clean-new-chains` 清孤儿链。

---

## 3. 风险点清单（按严重度排序）

> isHandled 取值：handled（已妥善处理）/ partial（有部分兜底）/ unhandled（无兜底）。

### 3.1 Critical / High

| # | 场景 | 证据 file:line | 影响 | 现有兜底 | isHandled |
|---|---|---|---|---|---|
| R1 | **迁移非原子且非自愈**：部分写失败被密封为"已完成"，崩溃后被 boot mark 阻止重试，全程无快照回滚 | `migrate.go:54-58`(写失败续跑)、`:61-66`(无条件 rename .bak)、`:134`(guard 存在即 pending=false)；`firewall.go:178`(O_EXCL boot mark)、`:30`(早退)、`:38-156`(failed 从不 RestoreSnapshot) | 单次 IO 故障即可把主机带入"新布局不完整+旧文件已移走+迁移永久视为完成"的半坏态，只能等整机重启或人工 rescue | rescue 人工自救；INPUT=ACCEPT 时真空 fail-open | **unhandled** (critical) |
| R2 | **迁移/重放失败不强制只读告警态**：用户在脏布局上继续叠加规则 | `firewall.go:160-175`(recordBootStatus 仅写表)；`service/firewall.go:69-70`(仅横幅消费)；OperatePortRule 等无 bootStatus 拦截 | 失败后写操作仍放行，加剧不一致 | UI 横幅提示 | **partial** (high) |
| R3 | **最高风险子系统零自动化测试** | `agent/utils/firewall/*`、`agent/init/firewall/*` 下 0 个 `*_test.go`（实测）；设计 §5 + `migrate.go:21-22` 自身均要求且明示禁止仅凭编译上线 | 分类边界/指纹恒定/iptables-save 解析无回归门禁 | 人工 S6 演练 | **unhandled** (high) |
| R4 | **降级回滚非自动成立**：旧版本不读 .bak、无改名回写逻辑 | `migrate.go:64`(rename .bak)；全仓无读 .bak 代码（实测）；旧版本读原文件名 | 回滚旧版本后旧布局不恢复，孤儿链残留 | rescue `--clean-new-chains` 清孤儿链；人工 mv | **partial** (high) |
| R5 | **切回 managed 后新链与保底集不在运行期重建，必须整机重启** | `firewall.go:30`(早退)、`:78-156`(建链全在 runBootReplay)；`migrate.go:132-140`(ex-external 主机 pending 恒 false) | 卸载 ufw 到重启之间 1Panel 防护真空；新增端口规则可能落空链 | 无（下次重启才建链） | **unhandled** (high，场景2a) |

### 3.2 Medium

| # | 场景 | 证据 file:line | 影响 | isHandled |
|---|---|---|---|---|
| R6 | **升级把旧 80/443 错归入不可删 BASELINE**（确定性，影响绝大多数升级用户） | `migrate.go:95-101`(BASIC_BEFORE 非 lo/ESTABLISHED 一律→BASELINE)；叠加 `constant/common.go:11` 默认白名单→ALLOW 造成双重放行 | 升级用户删不掉 80/443，违反 §3.4/目标6"80/443 可关" | **unhandled** |
| R7 | **DB 回填 source 恒为 panel（legacy 死代码）** | `init.go:1083-1095` legacyFirewallRuleKey 所有分支(含 default)返回 known=true → `:1049` !known 永假 | legacy 兜底分类从未触发（不丢数据，但诊断/清理判定失真） | **unhandled** |
| R8 | **快照恢复/迁移不过 I1/I2 锁外红线** | `service/firewall.go:822-827`(RestoreSnapshot 仅 BeginSession 不 precheck)；migrate.go 既不 precheck 也不进会话 | 恢复锁外快照仅靠 60s 兜底；迁移路径连自动回退都没有（§3.5.2 未实现） | **unhandled** |
| R9 | **非原子换绑留 INPUT 真空窗口** | `service/iptables.go:394-401`(先 unbindBaseChains 全解绑再 1..5 逐条 -I)，与设计"先插新再删旧"相反；运行期 API bind 路径不调 EnsureInputPolicySafe | INPUT=ACCEPT 时 fail-open；外部置 policy=DROP 时真空=真锁外 | **partial** |
| R10 | **运行期 external→managed 无失效钩子**（场景2a 核心） | `driver.go` probeTTL=60s；`service/firewall.go:258/268/274` 仅 3 处 InvalidateProbe | 最多 60s 仍按旧 provider 判定 | **partial** |
| R11 | **external 模式 commit-confirm 与逆操作日志整体缺失** | `service/firewall.go:318/541`(BeginSession 被 isManagedMode 门控)；§3.5.1 第5点零实现 | external 误封无 L3 自动回退，锁外保护弱于 managed | **unhandled** |
| R12 | **firewall_state.Consistent 偏离语义** | `firewall.go:169` `Consistent = strings.HasPrefix(status,"ok")` | 仅是 boot 状态镜像，非真实 DB-vs-系统一致性比对 | **partial** |

### 3.3 Low

| # | 场景 | 证据 file:line | isHandled |
|---|---|---|---|
| R13 | 回填 family 硬编码 ipv4，历史 IPv6 规则指纹失配→描述丢失（规则仍生效） | `init.go:1060,1086,1088,1094` | unhandled |
| R14 | 开机面板端口保底再注入/回读为 IPv4-only；v6 链顺序无断言 | `firewall.go:106-131`；`service/iptables.go:514-527`(无 v6 assert) | unhandled |
| R15 | 迁移期内无 I1/I2 校验，安全全依赖随后的 runBootReplay | `migrate.go:23-68` 无 precheck 调用 | partial |
| R16 | EnsureInputPolicySafe 注入的 raw-INPUT 紧急 ACCEPT 无 comment/TTL，永不清理（累积污染 INPUT） | `emergency.go:81` 注入无 comment，`:46` janitor 识别不到 | partial |
| R17 | nftables 未接入；纯 nftables 主机 ErrNoFirewall（设计标 Stage 3，可接受） | `driver.go:30`(ProviderNftables 死常量)、`:145`(仅 cmd.Which iptables) | unhandled（按计划推迟） |
| R18 | rescue `--restore-latest` 用全表 iptables-restore，与限定恢复哲学不一致（会覆盖窗口期 Docker/第三方规则） | `core/cmd/server/cmd/firewall.go:19,81-114` | partial |

---

## 4. 迁移点清单（运维实际会经历的关键步骤/状态变化）

> 标注 ⚠ 的为需要人工确认或可能踩坑的点。

| 序 | 迁移点 | 状态变化 | 人工确认 |
|---|---|---|---|
| 1 | **升级首启（进程重启）** | `/run/1panel_boot_mark` 仍在(needInit=false)，靠 legacyMigrationPending 强制触发重放 | — |
| 2 | **拍 pre-migration 快照** | best-effort，失败仅 Warn 续跑（`migrate.go:37`） | ⚠ 快照失败时无强约束 |
| 3 | **链文件转换** | BASIC_*→GUARD/DENY/BASELINE/ALLOW/AFTER，旧文件→.bak | ⚠ 写失败不回滚、旧文件仍被移走 |
| 4 | **活体加载** | EnsureInputPolicySafe→逐链重放(+v6)→面板端口注入 BASELINE→回读校验 | — |
| 5 | **DB schema 迁移** | InitFirewallPortWhiteList(默认 80/tcp,443/tcp,443/udp) → AddFirewallMetaTables(新增 2 表+回填) | — |
| 6 | **白名单语义变化** | 80/443 从硬编码保底变为可编辑白名单默认值；SSH+面板为不可删 required | ⚠ 存量机旧 80/443 被误归 BASELINE 不可删 |
| 7 | **求值顺序反转** | DENY(序2) 恒先于 BASELINE/ALLOW，黑名单可压过 SSH/面板/80-443 | ⚠ 有意反转，但无 diff 报告 |
| 8 | **provider 切换** | 运行期靠 60s TTL 被动判定；外部卸载无事件钩子 | ⚠ 切 managed 后建链要等重启 |
| 9 | **崩溃兜底** | ReclaimSession 回收未确认会话视同超时还原；失败 fail-fast 保留 marker 重试 | — |
| 10 | **迁移/重放失败处置** | 仅写 firewall_state=failed/degraded 供横幅，不自动还原、不强制只读 | ⚠ 需人工经 1pctl rescue 自救 |
| 11 | **降级回滚** | .bak 逐字节保留但无自动重放 | ⚠ 需 mv *.rules.bak 回名 + rescue --clean-new-chains |

**运维自救通道（确认可用）**：

```
1pctl firewall rescue                    # 解绑全部 1PANEL_* jump（默认，仅解绑不删）
1pctl firewall rescue --clean-new-chains # 再 -F/-X 删除 1PANEL_* 链（清孤儿链）
1pctl firewall rescue --restore-latest   # 全表 iptables-restore 最近快照（会覆盖第三方规则）
```
纯 shell、不依赖 agent/DB，agent 崩溃也可用（`core/cmd/server/cmd/firewall.go`）。⚠ `doctor` 诊断命令未实现。

---

## 5. 设计稿承诺 vs 代码现实 对照

### 5.1 §3.4 存量链迁移六步

| 步骤 | 设计稿承诺 | 代码现实 | 裁决 |
|---|---|---|---|
| 1 全量快照 | 迁移前拍快照 | `migrate.go:37` TakeSnapshot，但失败仅 Warn 续跑（best-effort，无强约束） | ⚠ 部分 |
| 2 读取分类 | BEFORE→GUARD/BASELINE/白名单；BASIC ACCEPT→ALLOW、DROP→DENY；AFTER→AFTER | `migrate.go:92-113` 已实现，但 **BEFORE 从不路由到 ALLOW/白名单**，80/443 误入 BASELINE | ⚠ 偏离 |
| 3 **原子换绑** | 先插新 jump 再删旧 jump，任何时刻 SSH/面板至少存在一处 | `iptables.go:394-401` **先全解绑再逐条插入**，与设计相反，留真空窗口；且换绑在 runBootReplay 而非迁移函数内 | ❌ 偏离 |
| 4 **回读验证** | 回读 6-jump 顺序 + BASELINE 存在 | `assertBaseOrder`(v4) 校验相对顺序；回读仅 v4 面板端口存在性，**v6 无断言**；迁移函数本身不回读 | ⚠ 部分 |
| 5 **失败整体还原** | 任一步失败→从快照整体还原+进入只读告警态 | **未实现**：runBootReplay 失败只 `return failed`，从不 RestoreSnapshot；只读态仅写表无拦截 | ❌ 未实现 |
| 6 旧文件留 .bak | 保留两版本后清理 | `migrate.go:60-66` os.Rename .bak（逐字节一致），但写失败时无条件执行可留半成品 | ⚠ 部分 |

**核心结论**：设计稿把"换绑/回读/失败还原"绑定在迁移期内完成；实际 `migrateLegacyChains` **只做文件转换**，把这些动作推迟到 `runBootReplay`，且 runBootReplay 不具备整体还原能力。迁移函数本身**不换绑、不回读、不失败还原**。

### 5.2 §3.8 数据层

| 承诺 | 代码现实 | 裁决 |
|---|---|---|
| additive 新增 meta/state 两表，旧 firewalls 表保留不删 | `init.go:1032-1068` AutoMigrate 新表+回填，不触碰旧表；model.Firewall Port/Address 仅标 Deprecated | ✅ 符合 |
| 指纹 sha256(12 字段)[:16] + 规范化 | `fingerprint.go` 逐字段对齐设计 §3.3，真正用于描述关联与迁移（非空壳） | ✅ 符合 |
| cleanUnUsedData 删除，改手动清理 | 已删，替换为 `CleanOrphanFirewallRecords`(firewall.go:829+)，keep-set 一次性删、只清 port/address、修掉 C3 索引 bug | ✅ 符合 |
| 算不出指纹的标 source=legacy 保留 | **死代码**：`init.go:1083-1095` 所有分支返回 known=true，source 恒为 panel | ❌ 偏离 |
| FirewallProvider 设置项预留（Stage 3 切 nftables） | **完全未实现**：无此 constant、无此设置键，Provider 仅是 firewall_state 运行时检测字段 | ❌ 偏离 |
| firewall_state.Consistent = DB/文件 vs 系统一致性 | 仅 `strings.HasPrefix(status,"ok")` 布尔镜像，无真实比对 | ❌ 偏离 |

### 5.3 §8.3 降级路径

| 承诺 | 代码现实 | 裁决 |
|---|---|---|
| 迁移时旧链文件留 .bak，逐字节一致 | `migrate.go:64` os.Rename 保证逐字节一致 | ✅ 符合 |
| 旧代码开机重放 .bak 即恢复 | **不成立**：旧版本不读 .bak、无降级改名回写逻辑，需人工 | ❌ 偏离 |
| 1pctl firewall rescue --clean-new-chains 清孤儿链 | ✅ 存在且可用（`core/cmd/server/cmd/firewall.go`，纠正 phase-1 误判） | ✅ 符合 |

### 5.4 §5 测试矩阵

| 承诺 | 代码现实 | 裁决 |
|---|---|---|
| classifyLegacyRule / Fingerprint / parseSave 表驱动单测 | **全部缺失**：agent/utils/firewall 与 agent/init/firewall 下 0 个 `*_test.go` | ❌ 未实现 |

---

## 6. 健壮性结论与按优先级排序的修复建议

### 6.1 结论

正常升级路径安全；**对抗路径（崩溃/部分失败/降级）不够健壮**。核心反例链（三处缺口叠成，全部实测确认）：

```
单次 IO 故障 (writeChainRules 失败)
   │ 仅 Errorf 续跑，不中止（migrate.go:54-58）
   ▼
guard 文件可能已先写出（Go map 迭代随机序）
   │ legacyMigrationPending() 恒 false（migrate.go:134）
   ▼
旧文件无条件 rename .bak（migrate.go:61-66）
   │ → 新布局不完整 + 旧文件已移走
   ▼
进程重启：/run boot mark 仍在 → needInit=false
   │ firewall.go:30 早退条件为真 → runBootReplay 整段跳过
   ▼
半坏态无法自愈，只能等【整机重启】或人工 rescue
   （ReclaimSession 只认 session.lock，对 boot 重放无能为力）
```

### 6.2 按优先级排序的修复建议

| 优先级 | 缺口 | 修复建议 | 落点 |
|---|---|---|---|
| **critical** | R1 迁移非原子+崩溃阻止重试+无回滚 | ①新链文件先写临时名+fsync，全部成功后才原子改名并移旧文件；任一失败则中止（不写 guard、不移旧文件）使下次重试。②runBootReplay 失败前调 `RestoreSnapshot(pre-migration)`。③用写在 FirewallDir、仅 runBootReplay 返回 ok 后落地的持久化 replay-complete 标记替代纯 /run 防重入；或 firewall.go:30 早退前加链一致性回读 | `migrate.go`、`firewall.go` |
| **high** | R2 失败态不强制只读 | OperatePortRule/OperateAddressRule/Batch/RestoreSnapshot 入口读 firewall_state.LastBootStatus，非 ok 时拒绝或 force | `service/firewall.go` |
| **high** | R3 零测试 | 新增 `migrate_test.go`(classifyLegacyRule，覆盖 BASIC_BEFORE 80/443、lo/ESTABLISHED)、`fingerprint_test.go`(CIDR/端口区间/空值/IPv6 family 指纹恒定)、`snapshot_test.go`(parseSave) | agent/init/firewall、agent/utils/firewall |
| **high** | R4 降级非自动 | core 增 `rescue --downgrade-restore`(把 .bak 改回原名+清 1PANEL_* 孤儿链)，或降级文档明确手工步骤 | `core/cmd/server/cmd/firewall.go` |
| **medium** | R6 80/443 误归 BASELINE | classifyLegacyRule 对 BASIC_BEFORE 中带 `--dport 80/443` 的 ACCEPT 路由到 ALLOW，仅 SSH/面板与 lo/ESTABLISHED 进 GUARD/BASELINE | `migrate.go:95-101` |
| **medium** | R8 快照/迁移不过 I1/I2 | RestoreSnapshot 与迁移落地前对最终链状态做 I1/I2 静态求值（至少校验 SSH/面板可达） | `service/firewall.go` |
| **medium** | R9 非原子换绑 | 改为先按序插入新 jump 再删旧 jump；或所有 bind 路径前统一调 EnsureInputPolicySafe | `service/iptables.go` |
| **medium** | R7/R13 source 死代码 + family 硬编码 | default 分支返回 known=false 标 legacy；按 SrcIP/DstIP 含冒号推断 family 或回填双份指纹 | `init.go` |
| **low** | R14 v6 保底/断言缺失 | 面板端口注入+回读镜像到 ip6tables；bindBaseChainsInOrder6 后补 v6 顺序断言 | `firewall.go`、`iptables.go` |
| **low** | R17 nftables | 至少探测后端类型(iptables-nft/legacy)并日志标注；完整支持按 Stage 3 推迟 | `driver.go` |

### 6.3 已落地的健壮性亮点（保留勿动）

- ✅ **升级首启窗口被正确堵住**：`legacyMigrationPending`(migrate.go:132-140) 在 boot mark 仍在的进程重启场景仍强制触发迁移+重放（firewall.go:30 短路保证首启仍创建 mark）。
- ✅ **DB additive 迁移无丢失**：AddFirewallMetaTables 仅新增表+指纹回填，绝不改/删旧表；core/init/migration 无 firewall 删除项。
- ✅ **commit-confirm 崩溃兜底扎实**：ReclaimSession/RevertSession 在 RestoreSnapshot 部分失败时 fail-fast、保留 marker、绝不持久化半还原态（session.go:190-209）。
- ✅ **EnsureInputPolicySafe 防开机双杀**：检测 INPUT policy=DROP 即注入 SSH/面板直连 ACCEPT（emergency.go + firewall.go:82）。
- ✅ **单写者落地**：core/utils/firewall 整包删除，UpdatePort 走 agent panel-port 内部通道只增不删（setting.go:313-345）。
- ✅ **rescue 自救命令存在可用**：核心逃生口（纠正 phase-1 误判）。

---

## 7. 上线前必做的迁移演练（指向 §5 测试矩阵）

| 演练 | 对应设计场景 | 验收点 | 当前预期 |
|---|---|---|---|
| **S6 升级演练** | §5 S6 / PR-3 | 升级前后规则语义等价（iptables-save 规范化对比）；黑名单对 80/443 生效；**迁移失败自动还原** | ⚠ "失败自动还原"预期**失败**（R1/R5），须先修 critical |
| **S3 坏文件重启** | §5 S3 | 手工损坏一个持久化链文件→重启→主机可达、链未 bind、UI 横幅、rescue 可恢复 | 部分通过（无 staging 预校验，单条坏行静默跳过） |
| **S9③ 断电重启** | §5 S9 | 变更后立即断电重启，开机重放的应是会话前规则 | ⚠ 预期**失败**：client.Port 即时落盘，安全全依赖 ReclaimSession 还原成功 |
| **S10② 跨多笔会话累积阻断** | §5 S10 | 多笔会话累积达成的阻断应被红线拦截 | ⚠ 预期**失败**：precheck 为单请求浅检查 |
| **S10⑤ external 删 SSH 放行** | §5 S10 | default-deny 下删 SSH 放行且无面板放行→硬拒绝 | ⚠ 预期**失败**：precheck 不分流模式、remove+accept 不触发红线 |
| **S10⑥ 恢复锁外快照** | §5 S10 | 恢复会锁外的历史快照应被 I2 拦截 | ⚠ 预期**失败**：RestoreSnapshot 不过 I1/I2（R8） |
| **降级演练** | §8.3 | 降级旧版本后旧布局恢复 | ⚠ 需人工干预（R4），须文档明确步骤 |
| **共存矩阵** | §3.1 | firewalld+ufw × {都 running/仅 ufw/仅 firewalld/都停} 断言 provider 选择与冲突态 | 共存降级实现干净，建议补单测 |

**结论**：S6/S9③/S10②/S10⑤/S10⑥/降级 六项演练当前预期失败，对应 §6.2 的 critical/high 修复项；这些演练通过应作为广泛 GA 的硬性门槛。

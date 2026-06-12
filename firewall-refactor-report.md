# 1Panel 防火墙重构调查报告

> 调查日期：2026-06-12
> 范围：上游 issue 诟病全景、plan2/plan.md 设计草案、feat/firewall-safety-stage1 已实现代码、与 dev-v2 的合并风险、上线路线建议

---

## 一、用户诟病全景（来自上游 ~130 条 issue）

按严重度排序的五大痛点：

### P1. Docker 端口绕过防火墙（结构性，10+ issue，贯穿项目史）
- 代表 issue：#726、#12471（曾标 P0）、#12932、#1846、#4741
- Docker 通过 FORWARD/DOCKER 链直接放行映射端口，面板的 INPUT 链规则、ufw、firewalld 全部拦不住。
- 官方立场：`not supported`，建议绑 127.0.0.1 或手动操作 DOCKER-USER 链——但面板 UI 不支持管理 DOCKER-USER，用户明确指出这个矛盾。
- **plan2 草案完全没有覆盖这一点。这是最高频的"防火墙形同虚设"诟病来源。**

### P2. IP 黑名单被 BEFORE 链白名单绕过（设计妥协，#12897、#12372、#3894）
- `1PANEL_BASIC_BEFORE` 预置 22/80/443/面板端口的无条件 ACCEPT + ESTABLISHED 放行，使 `1PANEL_BASIC` 里的黑名单对这些端口完全失效。
- 用户被扫描/DDoS 时加黑名单无效、磁盘 I/O 被日志打满。
- 官方承认是"防失联"的刻意设计；v2.2.1 加了端口白名单功能（#12912），但根本矛盾未解决（用户 djx30103 在 issue 中明确反馈）。
- ⚠️ **feat 分支的 EmergencyAccepts 把 80/443 也加进了保底集，会延续甚至固化这个诟病**（见第五节问题 1）。

### P3. IPv6 完全不受管控（#12997 仍 OPEN、#3799、#5042、#9524）
- iptables 模式只写 v4 规则，删除端口后 IPv6 照常可达；双栈服务器上防火墙形同虚设。
- 官方 2026-06-10 最新回应仍是"建议用云厂商安全组"。
- feat 分支只解决了紧急保底规则的 v6（EnsureIPv6EmergencyAccepts），普通用户规则仍然只写 v4。nftables 驱动用 inet 族天然双栈，是真正的解法。

### P4. nftables 系统不兼容（#12007 仍 OPEN、#7177、#11116）
- Debian 12+/Ubuntu 24.04 默认 nftables，1Panel 调 iptables 报 "No chain/target/match by that name"，端口转发、OpenResty 安装连锁失效。
- HynoR 在 #12007 回应"有计划但排期忙不过来"。feat 分支的 nftables 驱动正是回应这一点。

### P5. 用户被锁在服务器外面（#5852、#3274、#12476 仍 OPEN）
- 误删全部端口、误设面板端口仅本地访问、初始化时链顺序错乱（AFTER 的 DROP 排在 BEFORE 的 ACCEPT 之前）导致 SSH 实时断连。
- #12476 中用户提供了 iptables-save 实证链顺序确实会乱，官方"设计上不会"的回应不成立，issue 仍 OPEN。
- feat 分支的核心价值正在于此（staging 校验、启动保底注入+回读、caller IP 紧急放行、心跳回滚）。

### 次级诟病
- 重启后规则丢失/22 端口"复活"（#11553、#11121，部分已修）
- ufw+firewalld 共存时面板瘫痪（#6734，已加检测）
- 禁 Ping 重启失效（#7454、#11472，已修）
- UFW 重启导致 Docker 容器网络断（#10247，已加提示）
- 防火墙页面 CPU 飙升（#8388，已修）
- `cleanUnUsedData` 静默删用户规则描述（dev-v2 仍存在，feat 分支已删，见第三节）

---

## 二、现有草案盘点

### plan2/plan.md：双模式架构设计
- **模式 A Panel Managed**（无 ufw/firewalld）：1Panel 全权代理 iptables/nftables，DB 快照为真源，开机按快照恢复。
- **模式 B Panel Visualized**（有 ufw/firewalld）：系统状态为真源，1Panel 只做可视化+快照备份，还原必须显式确认。
- 统一领域模型：FirewallMode / FirewallProvider / FirewallSnapshot / FirewallRule（带 fingerprint、managed_by、family）/ FirewallProfile。
- 三张新表：firewall_runtime、firewall_snapshot、firewall_rule_meta。
- 安全原则：错误快照不得覆盖系统；恢复必须有保底白名单+回读验证；"宁可不恢复，也不能误开放端口"；迁移容忍部分丢失但不允许大规模失效。
- 四阶段实施：①双模式+快照模型+修 repo 缺陷 → ②统一 driver/registry、私有链收回 driver → ③新表迁移+前端工作台 → ④清理旧补丁+nftables 接入点。

### feat/firewall-safety-stage1：已实现内容（3 commits，~3500 行）

| Commit | 内容 |
|---|---|
| b4751999b | 锁外防护+快照恢复：staging-chain 预校验规则文件（坏规则不再让 DROP 链半挂载）；启动时注入并回读校验 SSH/面板紧急 ACCEPT（v4+v6），失败拒绝 bind INPUT；变更 API 中间件给调用方 IP 插 10 分钟 ACCEPT；iptables-save 快照（留 10 份）+ 60s 心跳回滚 API；删除 cleanUnUsedData；core 的 UpdatePort 改为只增不删旧端口 |
| 91d37b4a3 | 完整 nftables 驱动（inet 1panel filter 表 + ip 1panel_nat 表，nft -f 原子事务，持久化/紧急放行对齐 iptables）；FirewallProvider 设置（空=auto，默认顺序 firewalld>ufw>iptables>nftables，存量机器绝不静默切换）；启动 nft 分支 |
| 0679a4e50 | provider 列表/切换 API（ufw/firewalld 在管时拒绝、目标二进制缺失拒绝、当前后端有活动规则需 force；切换前先拍快照并给 nft 侧预置紧急放行）；快照列表/恢复 API + 前端抽屉/对话框 UI |

### 与 plan 的差距（未实现部分）
- 双模式（panel_managed/panel_visualized）未显式建模，仍是隐式的 if-else。
- 统一快照表/规则元数据表未建——快照在文件系统（`<FirewallDir>/backup/*.v4|.v6`），DB 只加了一个 FirewallProvider setting。
- 统一规则模型/指纹、一致性校验（ValidateConsistency）、新服务层 API（GetRuntimeState 等）未做。
- 前端统一工作台未做（8 个 vue 文件中仍有 43 处 `fireName` 写死判断）。
- 旧数据迁移器未做。
- 心跳回滚的前端 60s 确认 UI 未接（后端 API 已就绪）。

---

## 三、合并风险评估（feat 分支 vs dev-v2）

- 分支基点 2026-04-21，**落后 dev-v2 共 229 个 commit（约 2 个月）**。
- `git merge-tree` 实测 **8 个文件实质冲突**：agent/app/service/firewall.go、iptables.go、init/firewall/firewall.go、migrate.go、migrations/init.go、server.go、client/iptables/persistence.go、core/utils/firewall/firewall.go、frontend status/index.vue。
- **最大冲突源：上游期间合入了端口白名单功能**（#12912/#12949/#12950/#12957/#12961）：
  - `firewall_setting.go` 新增 `FirewallPortWhiteList` 设置 + `loadRequiredFirewallPortWhiteList()`（强制含面板+SSH 端口），并在 iptables 链上同步（含重启后重放，#12957）。
  - 这与 feat 分支的 `EmergencyAccepts` 在功能上**重叠**：两套"保底放行"机制如果同时存在会互相打架（重复规则、删了一边另一边复活、清理逻辑互删）。rebase 时必须融合为一套。
- dev-v2 的 `cleanUnUsedData`（firewall.go:560）仍在每次搜索后异步静默删除规则描述记录（feat 分支已删除）；该函数还有遍历中删元素的索引 bug。rebase 时保留 feat 分支的删除即可，但要确认白名单功能没有新依赖它。

---

## 四、痛点 × 方案覆盖矩阵

| 痛点 | plan2 设计 | feat 分支现状 | 缺口 |
|---|---|---|---|
| P1 Docker 绕过 | ❌ 未提及 | ❌ 无 | **需补充 DOCKER-USER 链管理设计**（最大诟病却无方案）|
| P2 黑名单被白名单绕过 | ⚠️ baseline profile 概念有但未定优先级 | ⚠️ EmergencyAccepts 含 80/443，恶化问题 | 需重新设计规则优先级：黑名单 DROP 应先于端口 ACCEPT；失联保护改由 caller-IP 紧急放行+心跳回滚承担 |
| P3 IPv6 | ⚠️ 规则模型有 family 字段 | ⚠️ 仅紧急规则 v6；nft inet 双栈 | iptables 模式普通规则需 ip6tables 同步写入，或引导用户迁 nftables |
| P4 nftables | ✅ 预留同级驱动 | ✅ 完整驱动+切换（opt-in）| 需实机验证矩阵 + 切换回退路径 |
| P5 锁外 | ✅ 保底集+恢复预检 | ✅ 核心已实现 | 心跳回滚前端未接；#12476 链顺序错乱根因需在 bind 逻辑中显式保证顺序 |
| 重启丢规则 | ✅ 快照恢复流程 | ⚠️ 文件快照+staging 校验 | 统一 DB 快照表未做（可后置）|
| 前端写死 | ✅ capabilities 驱动 | ❌ 未动 | 后置阶段 |

---

## 五、代码审查发现的隐患（上线前必须处理）

1. **80/443 不应进入无条件保底集**。`agent/init/firewall/firewall.go` 调 `EmergencyAccepts(sshPort, panelPort, []string{"80","443"})`——这正是 #12897 用户痛骂的设计。保底集应只含 SSH+面板端口；80/443 交给用户白名单（dev-v2 的 FirewallPortWhiteList 默认值）管理，且黑名单必须能压过它们。
2. **快照恢复是全表 `iptables-restore`，会清掉快照之后 Docker/fail2ban 动态新增的规则**。snapshot.go 注释声称"第三方规则也在快照里所以不会丢"——只对快照之前的规则成立，窗口期内 Docker 新建容器的 NAT 规则会被回滚掉，可能造成容器端口失联。建议：恢复限定 filter 表的 `1PANEL_*` 链 + INPUT 中的 jump 位置，而非全表；或至少恢复前 diff 并警示。
3. **ArmRollback 是全局单例 pending**——多管理员/快速连续操作时后一次会取消前一次的自动回滚，前一次操作失去保护。可接受为 v1 限制，但要在 UI 提示。
4. **caller IP 紧急放行插在原生 INPUT 顶部**，ufw/firewalld reload 会清掉（代码已注明为已知限制）；面板挂反代时 RemoteAddr 是代理 IP，保护的是代理而非用户（已刻意不信任 X-Forwarded-For，方向正确，需文档说明）。
5. **#12476 的链顺序错乱根因未直接修**：feat 分支靠"校验失败就不 bind"兜底，但 bind 时 `1PANEL_BASIC_BEFORE/BASIC/AFTER` 在 INPUT 中的相对顺序仍需显式断言（按固定序号插入并回读验证顺序，而不只验证存在性）。
6. 迁移文件 `init.go` 末尾缺换行符（gofmt 问题，rebase 时顺手修）。

---

## 六、重构上线路线建议

原则：**默认行为零变化**——每个阶段对未主动操作的存量用户必须是 no-op；高危能力一律 opt-in；每阶段独立可回滚。

### Stage 0（rebase + 融合，1 个 PR）
- rebase 到 dev-v2，解决 8 个冲突。
- **把 EmergencyAccepts 与上游 FirewallPortWhiteList 融合成一套"保底访问集"**：required 集 = SSH+面板端口（复用上游 `loadRequiredFirewallPortWhiteList`），feat 分支的注入+回读校验作为它的执行与验证层。删去 80/443 的硬编码。
- 保留 cleanUnUsedData 的删除。

### Stage 1（安全加固先行上线，风险最低、收益最高 → 直接回应 P5）
- staging 校验、启动保底注入+回读、caller-IP 中间件、快照+恢复 API/UI、UpdatePort 只增不删。
- 补：bind 顺序显式断言（修 #12476）；快照恢复限定 1PANEL 链（隐患 2）。
- 灰度：先 beta 渠道，观察一个版本周期再进稳定版。

### Stage 2（nftables opt-in → 回应 P4，并顺带给 P3 真解法）
- nftables 驱动 + provider 切换上线，文档明确"新装 Debian 12+/Ubuntu 24+ 推荐"，存量绝不自动切换。
- 切换流程补一条回退路径：切换失败/不满意时一键切回 iptables 并恢复切换前快照。
- 心跳回滚前端 60s 确认 UI 在此阶段接上（后端已就绪）。

### Stage 3（规则语义修正 → 回应 P2 + P3）
- 重排规则优先级：用户黑名单（drop/reject 的 IP 规则）移到保底端口 ACCEPT 之前；失联风险由 caller-IP 紧急放行 + 心跳回滚兜底，而不是靠无条件端口白名单。
- iptables 模式按规则 family 同步写 ip6tables（规则模型加 family 字段，plan2 已有此设计）。
- 这一阶段改变默认行为，需要醒目的升级说明 + 一个版本的 beta 验证。

### Stage 4（Docker 边界 → 回应 P1，建议补进 plan）
- 面板提供 DOCKER-USER 链的 IP/端口访问控制管理（plan2 未覆盖，但这是诟病最大头）。
- 最小可行版：在防火墙端口/IP 规则上提供"对 Docker 映射端口同样生效"选项，底层写 DOCKER-USER；并在端口规则列表标注哪些端口实际由 Docker 暴露（现有 port occupancy 展示 #12961 可复用）。

### Stage 5（结构统一，纯内部重构）
- 双模式显式建模、统一快照表（firewall_runtime/firewall_snapshot/firewall_rule_meta）、旧数据保守迁移、前端 capabilities 驱动的统一工作台。
- 放最后：对用户不可见，风险却最高（迁移），等前面阶段稳定后做。

### 百万用户风险控制
- 升级测试矩阵：{ufw, firewalld, iptables, nftables-only} × {Debian 11/12, Ubuntu 22/24, CentOS/RHEL 系} × {有/无 Docker} × {从 v2.x 旧版本升级}。
- 每个 Stage 单独 PR、单独版本发布，不要一个大 PR 全量合入。
- 迁移只做"加"（新 setting/新表），不在前四个阶段动旧表。
- 关键路径（boot init、provider switch、snapshot restore）打足日志（分支已做 `[firewall-boot]` 前缀，保持）。

---

## 七、待你拍板的问题

1. **黑名单 vs 80/443 保底的取舍**（P2 根因）：是否同意把 80/443 移出无条件保底集、让黑名单可以压过端口放行？这会改变 #12897 类用户的体验（变好），但理论上增加误操作封 Web 的可能（有 caller-IP 兜底）。
2. **DOCKER-USER 链管理是否纳入本次重构范围**（P1）？plan2 没写，但它是诟病最大来源；不做的话重构上线后"防火墙形同虚设"的声音不会减少。
3. **上线节奏**：按上面 Stage 1-5 拆 PR 逐版本发布，还是希望 Stage 1+2 合成一个版本先上？
4. **心跳回滚（60s keep/revert）前端**：本期实现，还是先只上快照手动恢复？
5. rebase 时与上游白名单功能的融合动到 ssongliu 刚写的代码，**是否需要先和上游维护者对齐**再动手？

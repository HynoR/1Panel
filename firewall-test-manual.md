# 1Panel 防火墙重构 — 测试手册（归档版）

> 版本：v1.0，2026-06-29
> 基线：`feat/dev2`（相对 `dev-v2` 的三点 diff：48 文件，+4447/-314）
> 性质：本手册是 `firewall-refactor-design.md` §5 测试矩阵 + §7 测试作战手册的**可执行落地版**。所有用例基于 `feat/dev2` 实际代码事实编写；凡设计稿承诺与代码实现不一致处，用 ⚠️ 标注并给出"预期结果偏离设计"的判定，作为发布门禁的红线证据。
> 配套文档：`firewall-refactor-design.md`（设计依据）、`firewall-refactor-report.md`（issue 背景）。

---

## 0. 阅读约定

| 标记 | 含义 |
|---|---|
| 🎯 | 必过项（发布门禁，任一不过即 no-go） |
| ⚠️ | 代码与设计稿不一致，**当前代码下预期会失败**或行为偏离——是缺陷上报点，不是测试者操作失误 |
| 🟢 | 已实现且与设计一致，回归确认即可 |
| 探针视角 | 判定以**外部探针机**的 nc/nmap/ssh/curl 结果为准，目标机自查 `iptables -S` 仅作辅助 |
| `T` / `P` | T=目标机（被测 1Panel 主机），P=探针机（同网段另一台，纯客户端） |

**关键术语对照（代码事实）：**

```
链布局(managed/iptables, filter/INPUT 固定 5 段 + 可选高级链):
  1. 1PANEL_GUARD     lo + RELATED,ESTABLISHED (+v6: ipv6-icmp/NDP)
  2. 1PANEL_DENY      黑名单 drop/reject —— 排在保底之前(根治 #12897)
  3. 1PANEL_BASELINE  SSH + 面板端口 不可删保底
  4. 1PANEL_ALLOW     80/443 默认白名单(可删) + 用户放行
  5. 1PANEL_AFTER     严格模式 DROP tcp/udp
  (可选) 1PANEL_INPUT 高级过滤，插在 ALLOW 与 AFTER 之间
Docker(正交): DOCKER-USER 第1条 -j 1PANEL_DOCKER (仅 IPv4)
证据: agent/utils/firewall/client/iptables/common.go:34-38; app/service/iptables.go baseChainOrder
```

---

## 1. 测试目标与发布门禁

### 1.1 唯一硬性验收：零失联

设计稿目标5 与 §8.1 go/no-go 标准：**任何路径下用户不能把自己锁在外面**。本手册所有锁外/红线用例（§6）服务于此。门禁判据：

| 门禁项 | 判定方式 | 对应用例 |
|---|---|---|
| 🎯 G1 零失联 | S1-S5/S9/S10 锁外演练全部能自救恢复 SSH/面板 | §6 |
| 🎯 G2 升级语义等价 | S6 升级前后 `iptables-save` 规范化集合 diff 为空（链名映射后）；SSH/面板可达；无新增开放端口 | §5.1 |
| 🎯 G3 external 不介入 | S8 ufw/firewalld 模式 `ufw reload` / `firewall-cmd --reload` 后规则不漂移 | §7 |
| 🎯 G4 Docker 端口受管 | S7 黑名单 IP 访问容器发布端口不通 | §4.7 |
| 🎯 G5 commit-confirm 兜底 | 降可达性变更 60s 不确认自动还原 | §4.9 |

### 1.2 当前代码下已知达不到门禁的项（发布前必须修，否则降级发布范围）

下列为事实库裁决（`yes-with-fixes`）中 critical/high 缺口，对应用例**当前代码预期失败**，必须作为强制前置：

| 缺陷 | 影响门禁 | 证据 | 用例 |
|---|---|---|---|
| ⚠️ 迁移非原子 + 失败无回滚 + 崩溃后被 boot_mark 阻止重试 | G2 | `migrate.go:54-66`；`firewall.go:30,38-157,178` | M-4、L1-9 |
| ⚠️ 开机失败态不强制只读，用户可在脏布局叠加规则 | G2 | `firewall.go:160-175`；`firewall.go` 写入口无 gate | L1-9 |
| ⚠️ 跨多笔会话累积阻断 / 快照恢复不过 I1/I2 | G1 | `firewall.go:822-827,957-990` | X-10②、X-10⑥ |
| ⚠️ external 模式无 commit-confirm / 无逆操作日志 | G1/G3 | `firewall.go:318,541` isManagedMode 门控 | S8b、X-10⑤ |
| ⚠️ 升级把旧 80/443 错归不可删 BASELINE | G2 | `migrate.go:95-101` | M-2 |
| ⚠️ 整个 firewall 子系统 0 个 `*_test.go` | L0 全层 | `agent/utils/firewall/*`、`agent/init/firewall/*` | §3 L0 |

### 1.3 changelog 前置阻断（最高优先，非测试项但影响一切）

⚠️ **`feat/dev2` 落后 `dev-v2` 14 个 commit**。两点 diff（`dev-v2..feat/dev2`）会把上游 mcp_server/website_ssl/runtime/i18n/package.json 误显示为删除。**合并前必须先 rebase 或 merge dev-v2**，否则回退 14 个 PR。验证命令：

```bash
git merge-base --is-ancestor dev-v2 feat/dev2 && echo "已同步" || echo "⚠️ 落后基线，禁止合并"
git diff --stat dev-v2...feat/dev2   # 三点：真实改动 48 文件
```

---

## 2. 环境矩阵与准备

### 2.1 矩阵维度（设计稿 §5）

```
发行版    × provider          × Docker × 安装方式
─────────────────────────────────────────────────
Debian 11   ufw 活动            有        全新安装
Debian 12   firewalld 活动      无        从 v2.x 升级
Ubuntu 22   iptables managed
Ubuntu 24   全裸(无防火墙)
Rocky 9
```

完整笛卡尔积 5×4×2×2 = 80 组合，全跑不现实。**分层取样策略**见 §3。最小必跑子集（覆盖所有判定分支）：

| 编号 | 发行版 | provider | Docker | 安装 | 主测目标 |
|---|---|---|---|---|---|
| E1 | Ubuntu 22 | iptables managed | 无 | 全新 | 链布局/红线/commit-confirm 主战场 |
| E2 | Ubuntu 24 | iptables managed | 有 | 全新 | Docker 防护 + IPv6（默认 nft 后端） |
| E3 | Debian 12 | firewalld 活动 | 无 | 全新 | external firewalld 不介入 |
| E4 | Debian 11 | ufw 活动 | 有 | 全新 | external ufw + 转发回落 NAT |
| E5 | Rocky 9 | iptables managed | 有 | **升级** | S6 迁移终极考场 |
| E6 | Ubuntu 22 | ufw+firewalld 都装 | 无 | 全新 | 共存冲突降级（C11） |

### 2.2 每种环境如何准备

**managed (E1/E2/E5)：** 确保系统无 ufw/firewalld，仅有 iptables：
```bash
systemctl disable --now ufw firewalld 2>/dev/null; apt-get remove -y ufw firewalld 2>/dev/null
which iptables ip6tables conntrack    # conntrack 用于"封禁立即生效"，缺则降级
iptables -P INPUT ACCEPT              # 起测前确认默认放行（fail-open 基线）
```

**external ufw (E4)：**
```bash
apt-get install -y ufw && ufw --force enable && ufw status verbose
```

**external firewalld (E3)：**
```bash
dnf install -y firewalld && systemctl enable --now firewalld && firewall-cmd --state
```

**共存冲突 (E6)：** 同时安装并 `systemctl start ufw firewalld`，两者都 running 才触发 `ConflictState`（`driver.go:116-136`）。

**Docker (E2/E4/E5)：** `docker run -d -p 18080:80 nginx` 制造 DNAT 发布端口；确认 `iptables -t filter -nL DOCKER-USER` 存在（`DockerProtectionAvailable()` 判据）。

**升级 (E5)：** 先装稳定版 v2.x → 用 §8 `seed-legacy-rules.sh` 布题 → 再升级到 `feat/dev2` 构建。

### 2.3 探针机 P 准备
```bash
apt-get install -y nmap netcat-openbsd curl iputils-ping   # nc/nmap/ssh/curl/ping6
# P 与 T 必须同网段直连；P 上保存 T 的 SSH 私钥用于可达性探测
```

---

## 3. 分层测试策略（L0-L4）

```
L0 单测      CI 跑，无环境       指纹规范化 / iptables-save 解析 / 迁移分类器 / 白名单解析
L1 单机集成  VM 批量刷矩阵       multipass/libvirt 起 E1-E6，每场景跑完回滚快照
L2 双机真机  T + P 探针          所有"规则生效与否"以 P 视角为准
L3 锁外演练  带 VNC/串口的云机    S1-S5/S9/S10 故意锁外，验证自救链路
L4 浸泡      1-2 台长期机         cron 每小时随机增删 + 每天重启，跑一周比对无漂移
```

### L0 单测现状（⚠️ 发布门禁未满足）

设计稿 §5/§7.1 要求表驱动单测，**实测 `agent/utils/firewall/`、`agent/init/firewall/` 下 0 个 `*_test.go`**。补测清单（作为 nftables/降级回归门禁）：

| 待补测文件 | 覆盖对象 | 关键边界 |
|---|---|---|
| `agent/init/firewall/migrate_test.go` | `classifyLegacyRule` | BASIC_BEFORE 的 80/443、lo/ESTABLISHED、BasicAfter |
| `agent/utils/firewall/fingerprint_test.go` | `Fingerprint`/`RuleKey` | CIDR/端口区间/空值/IPv6 family；DB 写入与系统回读指纹恒定 |
| `agent/utils/firewall/snapshot_test.go` | `parseSave` | 1PANEL_* 链与纯 jump 提取、跳过 1PANEL_DOCKER |

L0 验证命令（补测后）：
```bash
cd agent && go test ./utils/firewall/... ./init/firewall/...
```

### L1/L2/L3/L4 入口

- L1：每个 E* 起 VM，跑 §4 功能用例 + §5 迁移用例，断言用 `iptables -S` + DB 查询。
- L2：T 上每改一条规则，P 立即跑 §8 `firewall-probe.sh`，diff 必须为空。
- L3：见 §6，**必须有带外通道**（VNC/串口/IPMI），否则真锁外救不回来。
- L4：见 §8 浸泡脚本。

---

## 4. 功能测试用例（逐功能）

> 每条格式：【前置】【步骤】【预期】【判定(探针视角)】。编号 F<功能><序号>。
> 所有 API 路径前缀 `/api/v2/hosts/firewall`（`agent/router/ro_host.go:30-52`）。

### 4.1 端口规则（port）

#### 🟢 FP-1 添加放行端口（纯放行不进事务）
- 前置：E1，managed，已 init+bind base 链。
- 步骤：UI 端口页新建 `tcp/8080 accept anyWhere`。
- 预期：规则落入 `1PANEL_ALLOW`；**不弹 commit-confirm 卡片**（`lowersReachability` 对 add+accept 返回 false，`firewall.go:940-955`）。
- 判定：P 执行 `nc -z -w3 <T> 8080` → 通；`iptables -S 1PANEL_ALLOW | grep 8080` 存在。

#### 🟢 FP-2 添加端口黑名单可压过保底（根治 #12897）
- 前置：E1，SSH=22 在 BASELINE。
- 步骤：新建 `tcp/22 drop anyWhere`（force 通过 L1，见 §6）。
- 预期：规则落入 `1PANEL_DENY`（序2，**先于** BASELINE 序3），`client/iptables.go:149-155`。
- 判定：⚠️ 这是危险操作，**必须在 L3 带外通道下做**；P 视角 `ssh <T>` 应被拒（DENY 生效）；60s 不确认后自动还原，SSH 恢复（见 §6 S1 同理）。

#### FP-3 端口黑名单不清已建连接（已知补偿缺口）
- 前置：E1，P 已有一条到 T:9090 的长连接（`nc <T> 9090` 保持）。
- 步骤：T 新建 `tcp/9090 drop`（纯端口黑名单，无源地址）。
- 预期：⚠️ 现存连接**不立即中断**——`client.Port(drop)` 不调 `ClearConntrack`，仅 `RichRules` 带 address 时清（`client/iptables.go:300-302`）。GUARD 的 ESTABLISHED 放行在 DENY 之前。
- 判定：P 旧连接仍通，新建 `nc -z <T> 9090` 不通。**上报点**：UI 无"需重连"提示。

#### FP-4 端口规则带 family（IPv4/IPv6/both）
- 前置：E2（有 ip6tables），managed。
- 步骤：新建 `tcp/8443 accept`，family=both。
- 预期：v4 写 `1PANEL_ALLOW`，v6 镜像写 ip6tables 同名链（`app/service/iptables.go:479-548`）。
- 判定：P `nc -z <T4> 8443` 与 `nc -6 -z <T6> 8443` 均通。
- 注意：family 选择器仅 `mode===managed && capabilities.ipv6Rules` 显示（`port/operate/index.vue:42`）。

#### FP-5 端口规则描述按指纹保留（修 C3）
- 步骤：加 `tcp/7070 accept 描述="测试中文"` → 删除 → 重新添加同元组。
- 预期：描述按指纹关联存 `firewall_rule_meta`（`firewall.go:215-244`），删除时按指纹删 meta。
- 判定：查 DB `SELECT * FROM firewall_rule_meta WHERE description='测试中文'`。
- ⚠️ 已知缺陷：记录层 `addPortRecord` 指纹 family 硬编码 `ipv4`（`firewall.go:887`），而列表回填按 `info.Family`（`firewall.go:237-244`）。**IPv6 规则描述回读会失配丢失**——用 FP-4 的 v6 规则加中文描述，删后重建验证描述是否丢。

### 4.2 IP 规则（ip）

#### 🟢 FIP-1 IP 黑名单 + conntrack 清连接
- 前置：E1，conntrack 已装；P IP = 10.0.0.50，与 T 有活动连接。
- 步骤：T 新建 `deny 10.0.0.50`（带源地址）。
- 预期：`RichRules` add+DROP+address 调 `ClearConntrack`（`client/iptables.go:299-302`），现存连接被清。
- 判定：P 旧连接**立即中断**，新连接全不通。⚠️ 必须 L3 带外（封的就是探针/自己）。

#### ⚠️ FIP-2 IP 规则缺 family 选择器（与 port 不一致）
- 步骤：打开 IP 规则对话框。
- 预期：⚠️ 对话框**无 family 字段**（`ip/operate/index.vue` 无 family；`RuleIP` 接口有 `family?` 但 UI 不暴露）。双栈机封一个 IP 可能只封 v4。
- 判定：封一个同时有 v4/v6 的主机 IP，P `nc -6` 验证 v6 是否仍通。**上报点**。

### 4.3 转发规则（forward）

#### 🟢 FF-1 managed 端口转发（panel-nat）
- 前置：E1，forward tab init+bind（`1PANEL_FORWARD`）。
- 步骤：新建 `tcp 源6000 → 127.0.0.1:80`，入站网卡=all。
- 预期：`capabilities.forwardImpl==='panel-nat'`，显示 interface 列（`forward/index.vue:62`）；走 NAT 链。
- 判定：P `curl http://<T>:6000` 返回 80 端口服务内容。仅 IPv4（对话框有 ipv4Limit 警告）。

#### 🟢 FF-2 external ufw 转发回落 iptables NAT（C1 例外）
- 前置：E4，ufw 活动。
- 步骤：新建转发 `tcp 6001 → 127.0.0.1:80`。
- 预期：ufw 无原生转发，1Panel 用 iptables NAT 实现（`client/ufw.go PortForward`），UI 标注"由 1Panel 通过 iptables NAT 实现"。
- 判定：P `curl http://<T>:6001` 通；`ufw status` 中**无**该转发（NAT 不在 ufw 管理范围）。

#### 🟢 FF-3 firewalld 原生转发
- 前置：E3。
- 步骤：新建转发。
- 预期：用 `firewall-cmd --add-forward-port`（`client/firewalld.go`）。
- 判定：`firewall-cmd --list-forward-ports` 可见；`forwardImpl==='native'` → 对话框**不显示**入站网卡字段（`forward/operate/index.vue:32`）。

### 4.4 高级过滤（advance / iptables filter）

#### 🟢 FA-1 高级规则仅 capabilities.filter 可用
- 前置：E1 显示表格；E3/E4（external）显示 `advancedControlNotAvailable` 占位（`advance/index.vue:16,31`）。
- 步骤：E1 入站方向（1PANEL_INPUT）新建 `tcp/5000 drop 源=1.2.3.4`。
- 判定：P 从 1.2.3.4 访问 5000 不通。
- ⚠️ 已知：advance tab 按钮在 `index.vue` 常驻（仅内容降级），设计要求"仅 capabilities.filter 时显示该 tab"未严格落地。

#### ⚠️ FA-2 高级规则 Search 仍裸匹配 DB（C3 半迁移）
- 预期：⚠️ 高级链路径 `Search()` 用六字段相等匹配 DB（`app/service/iptables.go:50-65`），未用指纹。数据层半迁移。**上报点**：高级规则改元组后描述会丢。

### 4.5 端口白名单（white-list）

#### ⚠️ FW-1 白名单未分区（required 只读缺失）
- 步骤：打开白名单抽屉。
- 预期：⚠️ 完全扁平可增删列表，默认值 `80/tcp,443/tcp,443/udp`（`constant/common.go:11`）。**无 required(SSH/面板)只读区、无删 80/443 风险确认**（设计 §3.10 要求分区，未实现）。
- 判定：尝试删 80/443 → 无任何拦截直接删。**上报点**。

#### 🟢 FW-2 保底集 SSH/面板不可删
- 验证：SSH+面板端口由 `loadRequiredFirewallPortWhiteList` 渲染进 `1PANEL_BASELINE`（`firewall_setting.go:55`），白名单抽屉里**不出现**这两个端口（它们不在可编辑白名单中）。
- 判定：`iptables -S 1PANEL_BASELINE | grep <面板端口>` 恒存在。

### 4.6 快照（snapshot）

#### 🟢 FS-1 限定 1PANEL 链恢复（非全表）
- 前置：E1，已有快照。
- 步骤：手工在 INPUT 加一条非 1PANEL 规则（如 fail2ban 模拟 `iptables -I INPUT -s 9.9.9.9 -j DROP`）→ UI 恢复快照。
- 预期：恢复只重建 1PANEL_* 链与纯 jump，**跳过 1PANEL_DOCKER**，**不动** 9.9.9.9 这条第三方规则（`snapshot.go:181-320` applyScoped）。
- 判定：恢复后 `iptables -S INPUT | grep 9.9.9.9` 仍在。

#### ⚠️ FS-2 快照恢复不过 I1/I2 红线
- 步骤：构造一份会锁外的历史快照（含无源封 SSH）→ 恢复。
- 预期：⚠️ `RestoreSnapshot` 只 `BeginSession`+恢复，**不做 I1/I2 静态求值**（`firewall.go:822-827`）。设计 §3.5.2/S10⑥"被 I2 拦截"**不成立**，只靠 60s commit-confirm 兜底。
- 判定：L3 带外做。恢复后 SSH 断 → 60s 自动还原。**上报点**：缺事前拦截 + 无 diff 预览（`snapshot/index.vue` 无 diff，设计 §9.3 要求）。

### 4.7 Docker 防护（仅 IPv4）— 🎯 G4

#### 🎯🟢 FD-1 黑名单 IP 拦截容器发布端口（S7 核心）
- 前置：E2/E5，`docker run -d -p 18080:80 nginx`，DOCKER-USER 存在。
- 步骤：UI IP 规则新建 `deny <P的IP>`，勾选"同时拦截 Docker 端口流量"（检测到 Docker 默认勾选）。
- 预期：`1PANEL_DOCKER` 从 DOCKER-USER 第1条跳入，`-s <P> -j DROP` + `ClearConntrack`（`docker.go:41-145`）。
- 判定：P `curl http://<T>:18080` **不通**；删除黑名单后恢复通。

#### 🎯 FD-2 Docker 端口防护（还原 DNAT 前端口）
- 步骤：新建 `tcp/18080 drop` 勾选 Docker。
- 预期：用 `-m conntrack --ctorigdstport 18080 --ctdir ORIGINAL -j DROP`（`docker.go:103-145`，还原 DNAT 前端口）。
- 判定：P `curl http://<T>:18080` 不通，但 `curl http://<T>:9999`（面板）仍通。

#### 🎯 FD-3 Docker 重启后 jump 自动重断言
- 步骤：FD-1 生效后 `systemctl restart docker`（重建 DOCKER-USER）→ 等≤60s 巡检。
- 预期：`EnsureDockerChain` 在每分钟巡检（`StartEmergencyJanitor`）重断言 jump 为 DOCKER-USER 第1条（`docker.go` + `emergency.go:89-101`）。
- 判定：P 重启后再 `curl http://<T>:18080` 仍不通；`iptables -S DOCKER-USER` 第1条仍是 `-j 1PANEL_DOCKER`。

#### FD-4 Docker 规则不进 commit-confirm/快照
- 预期：⚠️（合理偏离）Docker 封禁由 `dockerMu` 独立维护，**不纳入会话快照**（`snapshot.go` 跳过 1PANEL_DOCKER）。设计 §3.5 字面"恢复限定 1PANEL_* 链"含 DOCKER 暗示，开发主动解耦（避免开机空文件覆盖 P1）。判定：恢复快照后 Docker 封禁规则仍在。**changelog 注明点**。

### 4.8 IPv6（ip6tables 镜像）

#### 🟢 FV-1 双栈端口规则删除后 v4/v6 均不可达（修 #12997）
- 前置：E2，ip6tables 存在。
- 步骤：加 `tcp/8090 accept both` → P 验证 v4/v6 均通 → 删除。
- 预期：删除同步清 v4+v6 镜像（`syncFirewallPortWhiteListRules`）。
- 判定：P `nc -z <T4> 8090` 与 `nc -6 -z <T6> 8090` **均不通**。

#### ⚠️ FV-2 v6 链顺序无回读断言
- 预期：⚠️ `bindBaseChainsInOrder6` 只 Unbind+Insert，**无 v6 版 assertBaseOrder**（`app/service/iptables.go:514-527`）。v6 链顺序错乱（AFTER DROP 跑到前面）不被捕获。
- 判定：双栈机上人工打乱 v6 jump 顺序后重 bind，观察是否报错（当前不报）。**上报点**。

#### ⚠️ FV-3 v6 面板端口开机保底为 IPv4-only
- 预期：⚠️ 开机 `runBootReplay` 面板端口"再注入"与回读校验仅 v4（`firewall.go:106-131`），v6 BASELINE 完全依赖 `.v6` 文件重放，无强制再注入/无 degraded 告警。
- 判定：删除 T 的 `*.rules.v6` baseline 文件 → 重启 → P `nc -6 <T6> <面板端口>` 是否仍通（当前可能无保底且无告警）。**上报点**。

#### 🟢 FV-4 ip6tables 缺失优雅降级
- 前置：移除 ip6tables 二进制的机器。
- 预期：`HasIP6tables()` 缓存探测返回 false → `capabilities.ipv6Rules=false`，family 选择器不显示。
- 判定：UI 端口对话框无 family 选项，功能不报错。

### 4.9 commit-confirm 提交-确认事务 — 🎯 G5

#### 🎯🟢 FC-1 降可达性变更进事务，60s 自动还原
- 前置：E1，L3 带外通道。
- 步骤：加 `deny <自己IP>`（force）→ **不点确认** → 等 60s。
- 预期：`BeginSession`→`armTimerLocked`(time.AfterFunc 60s)→超时 `RevertSession` 还原（`session.go:63-102`）。
- 判定：60s 后 P 重新可达 T；UI 确认卡片消失。

#### 🎯 FC-2 窗口期连续多笔变更整体生效/回退
- 步骤：窗口内连续做 3 笔降可达性变更 → 观察卡片计数刷新 → 点"立即撤销"。
- 预期：3 笔整体回滚到会话前快照（deadline 每次刷新，Stop+重建 timer）。
- 判定：3 笔规则全部消失。

#### 🎯 FC-3 agent 崩溃后未确认会话回收
- 步骤：做 1 笔降可达性变更 → 立即 `kill -9 <agent pid>` → 重启 agent。
- 预期：`ReclaimSession` 启动读 `session.lock` 视同超时还原（`session.go:190-209`）。
- 判定：agent 重启后规则已还原，P 恢复可达。

#### ⚠️ FC-4 "确认前不落盘"被破坏（设计 §3.5.1 第1点）
- 步骤：做 1 笔 deny 变更（进会话）→ 立即检查 T 上 DENY 链持久化文件。
- 预期：⚠️ `client.Port/RichRules` **每次操作立即 SaveRulesToFile**（`client/iptables.go:184,283`）。会话窗口内危险规则**已写盘**，`session.go:135` 注释宣称的"断电重启重放会话前规则"**不成立**——安全完全依赖 ReclaimSession 还原成功。
- 判定（对应 S9③）：做 deny → **不等还原直接断电** → 模拟 ReclaimSession 失败（损坏 session.lock 或 snapshot）→ `needInit=true` 真机重启 → `runBootReplay` 是否从脏文件**复活危险规则**。**上报点（high）**。

#### ⚠️ FC-5 external 模式无 commit-confirm（S8 后半）
- 前置：E4 ufw。
- 步骤：ufw 模式下做降可达性变更。
- 预期：⚠️ `BeginSession` 被 `isManagedMode()` 门控（`firewall.go:318,541`），**external 变更不进任何会话**；§3.5.1 第5点逆操作日志**零实现**。误封后无 L3 自动回退，仅靠 L2 临时 ACCEPT（且 ufw reload 会清掉它）。
- 判定：ufw 模式封自己 → 无确认卡片 → 60s 后**不会**自动还原。**上报点（high）**：external 锁外保护弱于 managed，须 changelog 明示。

#### ⚠️ FC-6 确认卡片缺 2s "应用中"过渡态
- 预期：⚠️ 保存成功后无过渡态，卡片靠下次轮询（最长 3s）才出现（`session-confirm.vue`），设计 §9.3 要求 spinner 过渡态缺失。**上报点（low）**。

---

## 5. 迁移测试用例（S6 升级 / 卸载切换 / 降级）

### 5.1 🎯 S6 升级语义等价（G2 终极考场，E5）

**考前布题（§8 `seed-legacy-rules.sh`）：** 在 v2.x 上制造：黑名单 50 条、白名单含 80/443、严格模式开、转发 10 条、高级规则若干、带中文描述的记录。

#### 🎯 M-1 升级前后语义等价
- 步骤：
  1. v2.x 上 `iptables-save > /tmp/before.v4`；导出 DB 描述清单。
  2. 升级到 `feat/dev2` 构建，首启自动迁移。
  3. `iptables-save > /tmp/after.v4`。
  4. 跑 §8 语义等价比对器（规范化 + 链名旧→新映射后集合 diff）。
- 预期：放行/封禁集合等价；SSH/面板可达；**无新增开放端口**；描述保留率（可指纹化行）≈100%。
- 判定：P 全程探针；比对器 diff 仅为链名差异。

#### ⚠️ M-2 升级后 80/443 错归不可删 BASELINE
- 预期：⚠️ `classifyLegacyRule` 对 BASIC_BEFORE 只把 lo/ESTABLISHED 归 GUARD，其余（含 80/443 ACCEPT）一律归 BASELINE（`migrate.go:95-101`）。升级用户 **80/443 变不可删**，且与默认白名单在 ALLOW 重复放行。
- 判定：升级后白名单抽屉中**删不掉** 80/443；`iptables -S` 中 80/443 同时出现在 BASELINE 与 ALLOW。**上报点（medium）**。

#### ⚠️ M-3 升级后黑名单求值顺序反转
- 预期：升级后 DENY(序2) 恒先于 BASELINE/ALLOW，黑名单可压过 SSH/面板/80-443（有意修复 #12897）。但迁移**即生效、无 dry-run 报告、无 diff**。
- 判定：若布题含"封网段但放行其中某 IP 访问 80"的旧顺序依赖组合，升级后语义可能反转。检查迁移日志是否输出分类 diff（当前无）。**上报点**：建议输出审计 diff。

#### ⚠️ M-4 迁移部分失败被密封为"已完成"（critical）
- 步骤：模拟磁盘满/权限错使某新链 `writeChainRules` 失败：
  ```bash
  # 制造 BASELINE 文件不可写，触发 writeChainRules 失败
  chattr +i <FirewallDir>/1panel_baseline.rules 2>/dev/null
  # 升级首启
  ```
- 预期：⚠️ writeChainRules 失败仅 `Errorf` 续跑（`migrate.go:54-58`），随后**无条件**把旧文件 rename 为 `.bak`（`migrate.go:61-66`）。Go map 随机序若 guard 先写成功 → "新布局不完整 + 旧文件已移走 + guard 存在=永久视为已迁移"。`runBootReplay` 失败只 `return failed:`，**从不 RestoreSnapshot**（`firewall.go:38-157`）。
- 判定：升级后链布局不完整且无法自愈，只能人工 rescue。**上报点（critical）**，对应设计 §3.4 step5 未实现。

#### ⚠️ M-5 崩溃后 boot_mark 阻止重试（critical 反例链）
- 步骤：升级首启 `runBootReplay` 进入活体绑定阶段（guard 文件已写出）时 `kill -9` agent → **仅重启 agent 进程**（不重启主机，`/run/1panel_boot_mark` 仍在）。
- 预期：⚠️ `needInit()`=false（mark 在，`firewall.go:178`）+ `legacyMigrationPending()`=false（guard 已写出，`migrate.go:134`）→ `firewall.go:30` 早退 → **runBootReplay 整段被跳过**，内核停半绑定态直到**整机重启**。
- 判定：agent 重启后 `iptables -S INPUT` 缺部分 1PANEL jump；P 验证规则失效。**上报点（critical）**。

#### ⚠️ M-6 失败态不强制只读
- 步骤：制造 M-4/M-5 的 degraded/failed 态 → UI 继续加端口规则。
- 预期：⚠️ `recordBootStatus` 仅写 `firewall_state` 供横幅（`firewall.go:160-175`），写入口**无 bootStatus gate**。用户在脏布局上叠加规则加剧不一致。
- 判定：failed 态下 OperatePortRule 仍成功。**上报点（high）**。

### 5.2 卸载切换（external → managed，对抗式）

#### ⚠️ M-7 外部卸载 ufw 无失效钩子
- 步骤：E4 上 SSH 里 `apt-get remove -y ufw`（绕过 OperateFirewall）。
- 预期：⚠️ `InvalidateProbe` 仅 start/stop/restart 调用（`firewall.go:258/268/274`），外部卸载无钩子。模式改判靠 60s TTL 被动过期（`driver.go:79,91`）。
- 判定：卸载后立即刷新 `/firewall/base` → ≤60s 内仍显示 external（错误模式窗口）。**上报点（medium）**。

#### ⚠️ M-8 切回 managed 不重建保护（保护真空）
- 步骤：M-7 后等 60s TTL 过期 → detect 改判 managed → 不重启主机，做端口操作。
- 预期：⚠️ GUARD/DENY/BASELINE/ALLOW/AFTER 新链与保底注入**只在开机 runBootReplay** 发生；ex-external 主机 `legacyMigrationPending` 恒 false、进程重启 `needInit` 也 false → **运行期不自举**，保护真空持续到整机重启。
- 判定：卸载 ufw 后（ufw 规则已被系统清空）→ `iptables -S` 无 1PANEL base 链 → P 扫描发现端口大面积敞开（INPUT 默认 ACCEPT 时不锁外但保护真空）。**上报点（high）**。

#### ⚠️ M-9 纯 nftables 主机 ErrNoFirewall
- 步骤：纯 nftables（无 iptables 二进制）机器卸载 ufw。
- 预期：⚠️ `detect()` 仅 `cmd.Which("iptables")`（`driver.go:145`），纯 nft 无 iptables → `ErrNoFirewall`；`ProviderNftables` 是死常量。iptables-nft 兼容层机器表面可用但 1Panel 不感知后端为 nft。
- 判定：`/firewall/base` 报无防火墙。设计标 Stage 3 可接受，但缺显式探测/文档。**上报点（low）**。

### 5.3 降级回退（Stage 3 验证 §8.3）

#### ⚠️ M-10 .bak 不自动重放（high）
- 步骤：升级到 `feat/dev2` → 降级回 v2.x 二进制 → 重启。
- 预期：⚠️ `.bak` 经 `os.Rename` 生成（`migrate.go:64`），但**全仓无任何代码读 .bak**；旧版本只认原名 `1panel_basic.rules`（已被改名移走）。设计 §8.3"旧代码开机重放 .bak 即恢复"**不成立**。新建的 1PANEL_GUARD 等是旧版本不识别的孤儿链。
- 判定：降级后旧布局不恢复，需人工：
  ```bash
  cd <FirewallDir> && for f in *.rules.bak; do mv "$f" "${f%.bak}"; done
  1pctl firewall rescue --clean-new-chains   # 清孤儿链
  ```
  **上报点（high）**：缺 `rescue --downgrade-restore`。

---

## 6. 锁外/红线专项演练（S1-S5/S9/S10）

> 🚨 **全部必须用带 VNC/串口/IPMI 的机器**。每次演练后用带外通道救回，不重装。

### 6.1 恢复总流程（演练前熟记）

锁外后通过 VNC/串口登录，按严重度选：
```bash
# 1) 最轻：解绑全部 1PANEL jump（保留链定义）
1pctl firewall rescue
# 2) 中：解绑 + 删除 1PANEL_* 链（含 DOCKER-USER 上的 1PANEL_DOCKER）
1pctl firewall rescue --clean-new-chains
# 3) 末路：全表 iptables-restore 最近快照（⚠️ 会覆盖 Docker/fail2ban 等第三方规则）
1pctl firewall rescue --restore-latest
# 证据: core/cmd/server/cmd/firewall.go:19-20,35-48,57,81
```
⚠️ **`doctor` 命令不存在**（设计 §7.2 建议项，实测 grep 无匹配）。诊断只能手工 `iptables -S` + 查 `firewall_state` 表。

### 6.2 用例

#### 🎯 S1 封禁自己当前 IP（force → 60s 自动还原）
- 步骤：UI IP 规则 `deny <自己IP>` → L1 返回 risk → force 确认 → **不点确认卡片**。
- 预期：60s 后 `RevertSession` 自动还原（`session.go`）。
- 判定：P 在第 ~61s 恢复可达。若没救回，用 6.1 流程 1。

#### 🎯 S2 严格模式 + 空白名单
- 步骤：开严格模式（AFTER DROP）且白名单空。
- 预期：⚠️ 严格模式/链解绑等操作**未接入 precheck+BeginSession**（`BeginSession` 全仓仅 3 处：port/addr/snapshot restore）。设计 §3.5.1 要求"开严格模式"强制走事务，**未实现**。
- 判定：严格模式可能直接锁外且无自动回退。**上报点**；用 6.1 流程 1 救回。

#### 🎯 S3 损坏持久化链文件 + 重启
- 步骤：`echo "garbage" >> <FirewallDir>/1panel_baseline.rules` → 重启主机。
- 预期：开机重放单条失败仅 `Errorf` 继续（`persistence.go:106-134`），`EnsureInputPolicySafe` 在 INPUT policy=DROP 时注入 SSH/面板直连 ACCEPT（`emergency.go:67-86`）；回读校验面板端口缺失记 degraded。
- 判定：主机仍可达；UI 显示 bootDegraded 横幅；rescue 可恢复。⚠️ 回读只校验"面板端口 ACCEPT 存在性"，**不校验内容/顺序/6-jump**（`firewall.go:127`）。

#### 🎯 S4 开机重放中途 kill agent
- 步骤：重启主机，开机重放过程中 `kill -9` agent。
- 预期：再次启动应幂等收敛。
- 判定：⚠️ 见 M-5——若 mark 仍在则**不收敛**直到整机重启。**这是 S4 当前会失败的点**。

#### 🎯 S5 改面板端口新端口放行失败 → 旧端口仍可用
- 步骤：external 模式（E4）模拟新端口被占用/放行失败：改面板端口 → agent `client.Port add` 失败。
- 预期：core `UpdatePort` 先委托 agent `panel-port`，agent 失败则整体失败、**未** `Update(ServerPort)`，旧端口规则未动（`setting.go:336-344`；`firewall.go:782-785`）。只增不删。
- 判定：P 用**旧端口** `curl https://<T>:<旧面板端口>` 仍通。🟢 设计符合（修 C2）。

#### 🎯 S9 提交-确认事务专项
- S9①：加 deny 不确认 → 60s 自动还原 → 见 FC-1。🟢
- S9②：窗口期连续 3 笔 → 确认/回退整体生效 → 见 FC-2。🟢
- S9③：变更后立即断电重启 → ⚠️ 见 FC-4，"确认前不落盘"被破坏，需验证脏文件是否复活危险规则。**上报点**。
- S9④：纯放行不进事务立即落定 → 见 FP-1。🟢

#### 🎯 S10 红线专项（§3.5.2）
| 子用例 | 步骤 | 设计预期 | 当前代码实际 | 判定 |
|---|---|---|---|---|
| ⚠️ X-10① | 提交无条件 DROP（INPUT 无源 ip drop） | 硬拒绝 `ErrFirewallUnconditionalDrop` | 🟢 INPUT 方向成立（`firewall.go:957-990`）；**OUTPUT 方向无拦截** | INPUT 被拒；OUTPUT 无源 drop 不被拦（上报） |
| ⚠️ X-10② | 跨多笔会话累积阻断 SSH+面板 | 硬拒绝 | ⚠️ precheck 是**单请求浅检查**，跨会话累积**抓不到**（`firewall.go:957-990`） | 累积锁外不被拦，靠 60s 兜底。**上报(high)** |
| ⚠️ X-10③ | 全局封 SSH 但面板放行 | force+L3 事务 | ⚠️ I2 分级表**未实现且偏严**，无源封面板/SSH 一律硬拒（`firewall.go:985-988`），合法场景被挡 | 被硬拒（偏离设计） |
| 🎯 X-10④ | `iptables -P INPUT DROP` + 损坏链文件 + 重启 | 注入直连紧急 ACCEPT，主机可达 | 🟢 `EnsureInputPolicySafe`（`emergency.go:67-86`） | P 仍可达 SSH/面板 |
| ⚠️ X-10⑤ | external ufw default deny 删 SSH 放行 | 硬拒绝 | ⚠️ precheck **不按模式分流**，remove+accept **不触发**红线（`firewall.go:958-990`） | 删除成功 → 锁外。**上报(high)** |
| ⚠️ X-10⑥ | 恢复会锁外的历史快照 | 被 I2 拦截 | ⚠️ 见 FS-2，**不过 I1/I2** | 不被拦，靠 60s 兜底。**上报** |

---

## 7. 回归测试（external 不介入，S8）— 🎯 G3

#### 🎯 S8a ufw 模式不漂移（E4）
- 步骤：1Panel 加/删端口规则 → `ufw reload` → 再 `ufw status verbose`。
- 预期：1Panel 操作全部通过 ufw 原生命令落地（`client/ufw.go Port/RichRules`），reload 后规则不漂移。
- 判定：`ufw status` 中能看到 1Panel 加的规则；reload 前后规则集一致。NAT 转发（FF-2）除外。

#### 🎯 S8b firewalld 模式不漂移（E3）
- 步骤：1Panel 操作 → `firewall-cmd --reload` → `firewall-cmd --list-all`。
- 预期：用富规则/`--add-port` 落地，reload 后保持。
- 判定：firewalld 富规则可见且持久。

#### ⚠️ S8c external 提交-确认回退（设计要求逆操作日志）
- 预期：⚠️ 见 FC-5，external **无** commit-confirm/逆操作日志。设计 §3.5.1 第5点要求的"逆操作倒序重放"**零实现**。**S8 后半当前不可覆盖，门禁项缺失**。

#### 🎯 S8d 共存冲突降级（E6，修 C11）
- 步骤：ufw+firewalld 都 running → 打开防火墙页。
- 预期：`Detect()` 永不因冲突 error，`/firewall/base` 正常返回带 `conflictState`（`driver.go:116-136`）；仅 `NewFirewallClient()`（写操作）拒绝。
- 判定：基础信息页**仍可看**（显示冲突横幅）；任何写操作被拒。停掉其一后操作恢复。验证 `InvalidateProbe` 后立即重新探测。🟢

---

## 8. 工具清单

### 8.1 探针断言脚本 `firewall-probe.sh`（L2/L3 核心，需自建）

```bash
#!/usr/bin/env bash
# firewall-probe.sh <target> <expect-file>
# expect-file 每行: <proto> <family> <port> <expect:open|closed>
# 例:  tcp ipv4 22 open / tcp ipv6 8090 closed
TARGET=$1; EXPECT=$2; FAIL=0
while read proto fam port want; do
  [[ -z "$proto" || "$proto" == \#* ]] && continue
  if [[ "$fam" == ipv6 ]]; then nc -6 -z -w3 "$TARGET" "$port" 2>/dev/null
  else nc -z -w3 "$TARGET" "$port" 2>/dev/null; fi
  [[ $? -eq 0 ]] && got=open || got=closed
  if [[ "$got" != "$want" ]]; then echo "DIFF $proto/$fam:$port want=$want got=$got"; FAIL=1; fi
done < "$EXPECT"
# SSH 可达性单独验
ssh -o BatchMode=yes -o ConnectTimeout=5 root@"$TARGET" true 2>/dev/null \
  && echo "SSH reachable" || echo "SSH UNREACHABLE"
exit $FAIL
```

### 8.2 存量机模拟器 `seed-legacy-rules.sh`（S6 考前布题，需自建）

在 v2.x 上通过 1Panel API 或直接 iptables 批量制造：黑名单 50 条 + 白名单含 80/443 + 严格模式 + 转发 10 条 + 高级规则 + 中文描述记录。用于 M-1 语义等价的基线。

### 8.3 语义等价比对器（S6 判分器，需自建）

```bash
# 规范化 iptables-save: 去 counter、排序、链名旧→新映射后集合 diff
normalize() { sed -E 's/\[[0-9]+:[0-9]+\]//g' "$1" \
  | sed -E 's/1PANEL_BASIC_BEFORE/1PANEL_GUARD/; s/1PANEL_BASIC_AFTER/1PANEL_AFTER/; s/1PANEL_BASIC/1PANEL_ALLOW/' \
  | grep -E '^-A' | sort -u; }
diff <(normalize /tmp/before.v4) <(normalize /tmp/after.v4)
# DB 描述保留率: 比对升级前后 firewall 描述数 vs firewall_rule_meta 行数
```

### 8.4 `1pctl firewall rescue`（已实现，纯 shell，agent 崩溃可用）

```bash
1pctl firewall rescue                    # 解绑全部 1PANEL_* jump（INPUT/OUTPUT/FORWARD/DOCKER-USER/nat）
1pctl firewall rescue --clean-new-chains # 再 -F/-X 删 1PANEL_* 链
1pctl firewall rescue --restore-latest   # 全表 iptables-restore 最近快照(⚠️覆盖第三方规则)
# 证据: core/cmd/server/cmd/firewall.go:35-48
```

### 8.5 `1pctl firewall doctor` — ⚠️ 未实现

设计 §7.2 建议项。当前需手工替代：
```bash
iptables -S INPUT | grep 1PANEL          # 看 6-jump 顺序
iptables -S 1PANEL_BASELINE              # 看 SSH/面板保底
sqlite3 <agent.db> "SELECT * FROM firewall_state;"   # 开机自检状态
which conntrack                          # conntrack 可用性
ls -lt <FirewallDir>/snapshots/          # 最近快照
```

### 8.6 L4 浸泡脚本（cron）

```bash
# /etc/cron.hourly/fw-soak : 随机增删一条端口规则
# /etc/cron.daily/fw-reboot : reboot
# 跑一周后比对: 规则集无漂移、firewall_rule_meta 描述无丢失、无重复规则累积
iptables-save | grep -c 1PANEL_ALLOW     # 监控规则数不应单调增长
sqlite3 <agent.db> "SELECT count(*) FROM firewall_rule_meta;"  # 描述数稳定
```

---

## 9. 缺陷上报模板

> 🚨 因 `doctor` 未实现，上报时贴 §8.5 手工诊断输出代替。

```
标题: [firewall][<E编号>] <一句话现象>

环境:
  - 发行版/版本:           (e.g. Ubuntu 24.04)
  - provider/mode:         (managed-iptables / external-ufw / external-firewalld / conflict)
  - Docker:                有/无, DOCKER-USER 是否存在
  - 安装方式:              全新 / 从 v2.x 升级
  - 后端: iptables-legacy / iptables-nft / 纯nft
  - conntrack: 已装/未装

用例编号: (e.g. FC-4 / M-5 / X-10②)
前置/步骤: (逐条可复现)
预期: (设计稿章节号 + 设计预期)
实际: (探针视角结果)

诊断输出(§8.5 手工 doctor 替代):
  $ iptables -S INPUT | grep 1PANEL
  <粘贴 6-jump 顺序>
  $ iptables -S 1PANEL_BASELINE
  <粘贴保底链>
  $ sqlite3 agent.db "SELECT provider,mode,last_boot_status,consistent FROM firewall_state;"
  <粘贴>
  $ iptables-save > /tmp/snap.v4    (附件)
  $ ip6tables-save > /tmp/snap.v6   (双栈机附件)

探针机视角:
  $ firewall-probe.sh <T> expect.txt
  <粘贴 DIFF / SSH 可达性>

自救结果: (用 6.1 哪一档救回 / 是否需带外通道)
代码定位(若已知): (file:line)
严重度: critical/high/medium/low (失联类一律 critical)
```

---

## 10. 用例索引与门禁汇总

| 类别 | 用例 | 门禁 | 当前预期 |
|---|---|---|---|
| 端口 | FP-1~5 | — | FP-3/FP-5(v6) ⚠️ |
| IP | FIP-1~2 | — | FIP-2 ⚠️ |
| 转发 | FF-1~3 | — | 🟢 |
| 高级 | FA-1~2 | — | FA-2 ⚠️ |
| 白名单 | FW-1~2 | — | FW-1 ⚠️ |
| 快照 | FS-1~2 | — | FS-2 ⚠️ |
| Docker | FD-1~4 | 🎯 G4 | FD-1~3 🟢 / FD-4 注明 |
| IPv6 | FV-1~4 | — | FV-2/3 ⚠️ |
| 事务 | FC-1~6 | 🎯 G5 | FC-1~3 🟢 / FC-4~6 ⚠️ |
| 升级 | M-1~6 | 🎯 G2 | M-1 待验 / M-2,4,5,6 ⚠️ |
| 切换 | M-7~9 | — | 全 ⚠️ |
| 降级 | M-10 | — | ⚠️ |
| 锁外 | S1~S5,S9,S10 | 🎯 G1 | S1,S5,X-10④,S8d 🟢 / 余 ⚠️ |
| external | S8a~d | 🎯 G3 | S8a,b,d 🟢 / S8c ⚠️ |

**发布建议（基于事实库裁决 yes-with-fixes）：** 在 §1.2 的 critical/high 缺口（M-4/M-5/M-6/X-10②/X-10⑤/FC-4/FC-5/M-8/M-10、L0 补测）落地前，**仅限 beta 定向内测**，不进稳定通道。managed 模式正常路径（无崩溃、磁盘有空间）可发；external 模式锁外保护弱于 managed，须在 changelog 与 UI 明示并依赖云控制台/rescue 自救。

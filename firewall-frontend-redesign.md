# 1Panel 防火墙前端重构设计

> 版本：v1.0 草案，2026-06-29
> 性质：前端交互层（设计稿 §9 + §3.10）的施工设计稿。后端「安全栈接入 + 字段管线打通」已在 `feat/dev2` 落地（详见 `firewall-refactor-design.md` §3），本文聚焦尚未动工的前端体验改造（PR-7 收尾）。
> 基线：`feat/dev2` 分支，`frontend/src/views/host/firewall/` 全量复核。
> 关联：设计稿 `firewall-refactor-design.md` §9「前端交互设计」、§3.10「单写者 / 白名单分区」。

---

## 0. 一句话结论

`feat/dev2` 的前端只落地了**「安全栈接入 + 字段管线打通」**这一层（capabilities/mode/conflict/bootStatus 字段接入、Docker `applyToDocker` 勾选、port 对话框 IPv6 family、snapshot 抽屉、全局 SessionConfirm 确认卡片），而设计稿 §9 真正改善**「理解成本 / 恐惧成本」**的交互层——状态页三卡片、规则生效顺序可视化、风险预检对话框、初始化向导、确认卡片 2s 过渡态、快照 diff 预览——**几乎全部未动工**。同时残留一处逻辑 Bug（`onInit()` switch fall-through）与一批术语外泄、双接口并存问题。本设计稿给出可独立合并的分阶段落地方案。

---

## 1. 背景与目标

### 1.1 设计稿 §9 的两个核心痛点

设计稿 §9 开宗明义，前端要消灭两种用户痛苦：

| 痛苦 | 本质 | 上游对应 |
|---|---|---|
| 「我加的规则为什么没生效」 | 理解成本——链求值顺序不可见 | #12897、#12372 |
| 「我不敢点，怕把自己锁外面」 | 恐惧成本——危险操作事前零预警 | #11553、#11121、#6734 |

设计稿明确：**保留五 tab 骨架不动**（KISS + 老用户肌肉记忆），在其内做四件事——状态页说人话（§9.1）、规则生效顺序可视化（§9.2）、危险操作从恐惧到有保险（§9.3）、其他落点（§9.4）。

### 1.2 后端已为前端铺好的「线」

| 后端能力 | 前端可消费的字段 / 接口 | 当前消费情况 |
|---|---|---|
| 双模式探测 | `base.mode`（managed/external） | 已用（徽章 + 少量 gating） |
| 能力集 | `base.capabilities`（rules/forward/forwardImpl/filter/baseline/snapshot/ipv6Rules/defaultDrop） | 仅 filter/forwardImpl/ipv6Rules 真正驱动渲染 |
| 共存冲突 | `base.conflict` | 已用（冲突横幅） |
| 开机自检 | `base.bootStatus` | 已用（降级横幅） |
| 提交-确认会话 | `/session/status|confirm|revert` | 已用（SessionConfirm 卡片） |
| 快照 | `/snapshot/list|restore` | 已用（抽屉，但无 diff 预览） |
| Docker 防护 | `/docker/status`、`applyToDocker` | 已用（对话框勾选） |
| 风险预检（L1） | **接口 dto 无 `risk` 字段** | 未接线（设计 §9.3 缺口的根因之一） |
| 保底通道开关态 | **base 无 80/443 开关态字段** | 未接线（设计 §9.1 三卡片缺口的根因之一） |

> 关键前置依赖：§9.1 保底通道卡片需后端 `base` 补 baseline 的 80/443 当前开关态；§9.3 风险预检需 operate 接口/dto 增 `risk` 字段。这两项是前端落地的**硬阻塞**，需与后端 agent 协同（见 §7 落地计划）。

### 1.3 重构原则（KISS + Element Plus + tailwindcss）

1. **保留 4 个老 tab 的肌肉记忆**，但补一个独立「概览/状态」作为默认着陆页（把内嵌的 `status/index.vue` 状态头升级成三卡片页），让用户第一眼看到「我的保底通道安全吗」而非一张规则表。
2. **把不可见的链求值顺序变成可见的心智模型**：列表页顶部加静态「数据包流向条」（纯 div+icon，不引画布库），规则行加「生效层级」彩色 tag 并按真实求值顺序排序。
3. **危险操作走「恐惧→有保险」三段式**：事前风险预检（说后果+保险，而非「确定吗」）、红线拒绝（错误态 alert、无继续按钮）、事后确认卡片补 2s「应用中…」过渡态——三者视觉必须可区分。
4. **术语说人话、隐藏实现细节**：`1PANEL_INPUT/OUTPUT`→「入站/出站方向」；「绑定链/初始化」→「启用 1Panel 管理」+向导；「可视化管理」→「管理 ufw（不介入启停）」。链名只许进 tooltip，不进选择器 label。
5. **capabilities 真正驱动渲染、收敛 fireName 哨兵判断**：把 `fireName !== '-'` 的事实判断收敛到一处 `isReady` 计算属性，让 nftables / 未来后端零前端改动。
6. **双端一致 + 移动端可用**：IP 对话框补 family 选择器对齐 port；确认卡片与风险对话框在窄屏（失联抢救常用手机）保持可操作，沿用现有 `md:flex` 响应式写法。
7. **少自定 style**：三卡片用 `el-card`+`el-row`/`el-col`+flex gap-*；流向条用 flex+`el-tag`+`el-icon`；彩色层级 tag 复用 `el-tag` type（danger/info/success），避免新增 scss。

---

## 2. 现状盘点（逐 tab 真实布局，file:line 证据）

### 2.1 信息架构总览（实测）

```
frontend/src/views/host/firewall/
├── index.vue            ← 全局壳：RouterButton(4 按钮) + <SessionConfirm/> + router-view
├── session-confirm.vue  ← 全局确认卡片（commit-confirm 前端面）
├── status/index.vue     ← 「共享状态头」被每个子页 <FireStatus> 内嵌渲染一遍（无独立状态页！）
│   ├── snapshot/index.vue   ← 快照抽屉
│   └── white-list/index.vue ← 端口白名单抽屉（扁平可删）
├── port/{index,operate,import}/  ← 端口规则
├── ip/{index,operate,import}/    ← IP 黑白名单
├── forward/{index,operate,import}/ ← 端口转发
└── advance/{index,operate}/      ← iptables 高级 filter
```

实测 `index.vue:15-32` 仅 4 个 RouterButton（端口/转发/IP/`iptables ` 高级），**根本没有独立状态页 tab**——状态信息靠 `status/index.vue` 以 `<FireStatus current-tab=...>` 形式内嵌在每个子页顶端，等于每个子页各画一遍状态头。

### 2.2 逐组件现状与问题

| 组件 | 路径 | 真实布局 | 关键问题（file:line） |
|---|---|---|---|
| 全局壳 | `firewall/index.vue` | RouterButton 4 按钮 + 全局 SessionConfirm + router-view | 无「概览/状态」tab；高级 tab 常驻而非 `capabilities.filter` 条件显示（`index.vue:28-31`） |
| 共享状态头 | `status/index.vue:3-128` | 单 `el-card` 一行：name 标签 / mode 徽章 / 启停灯 / version；右侧按钮随 currentTab/mode 变；下方条件渲染 conflict + bootDegraded 横幅 | **无三卡片、无保底通道可见性**；`onInit()` switch 缺 break 形成 fall-through（`status/index.vue:284-294`）；快照按钮恒显示不看 `capabilities.snapshot`（`status/index.vue:90`） |
| 快照抽屉 | `status/snapshot/index.vue` | DrawerPro + info；表列 name/tag/IPv6/操作；恢复弹通用 ElMessageBox | **无 diff 预览**（§9.3 缺失） |
| 白名单抽屉 | `status/white-list/index.vue:9-33` | 扁平 ComplexTable 内联增删改；默认值 `80/tcp,443/tcp,443/udp` | **无 required(SSH/面板) 只读区、无删 80/443 风险拦截**（§3.10 缺失） |
| 端口规则 | `port/index.vue:80-201` | FireStatus(base) + 表格（协议/端口/状态/策略/地址/描述/操作） | `fireName!=='-'` 才渲染（`port:18,690`）；**无流向条、无生效层级 tag、无 Docker 容器徽章** |
| 端口对话框 | `port/operate/index.vue:171-224` | 协议/端口/来源/地址/策略/family/applyToDocker/描述 | family 仅 `mode==='managed' && capabilities.ipv6Rules` 显示（`operate:41-51`）；**onSubmit 直接提交、无 L1 风险预检** |
| IP 规则 | `ip/index.vue:66-130` | 同 port 结构，current-tab 仍传 `'base'`；策略筛选文案 allow/deny 但 value 仍 accept/drop | **无生效顺序可视化** |
| IP 对话框 | `ip/operate/index.vue:133-166` | 地址/策略/applyToDocker/描述 | **缺 family 选择器**（RuleIP 接口有 `family?` 但 UI 不暴露，与 port 不一致）；**无风险预检** |
| 转发规则 | `forward/index.vue` | FireStatus(forward)；interface 列仅 `forwardImpl==='panel-nat'` 显示（`forward:62`） | forwardImpl 驱动 native/panel-nat 差异（已实现） |
| 转发对话框 | `forward/operate/index.vue` | ipv4Limit 警告；入站网卡仅 `forwardImpl!=='native'` 显示 | 明示仅 IPv4 |
| 高级 | `advance/index.vue` | `capabilities.filter` gating（`advance:16,31`）；链下拉直接暴露 `1PANEL_INPUT/OUTPUT`（`advance:63-64`） | **链名外泄**；tab 按钮常驻仅内容降级 |
| 确认卡片 | `session-confirm.vue` | el-alert + 倒计时 + 明细 + 确认/撤销 + 3s 轮询 + 1s tick | **缺 2s「应用中…」过渡态**（`session-confirm.vue:72-80`）；倒计时归 0 后 remain 停 0 不主动提示 |

### 2.3 `onInit()` fall-through Bug（实测确认）

`status/index.vue:284-294` 的 switch 三个 case 均**无 break**：

```js
switch (props.currentTab) {
    case 'base':
        chainName = '1PANEL_BASIC';
        msg = ...baseIptables;        // ← 缺 break
    case 'forward':
        chainName = '1PANEL_FORWARD';
        msg = ...forwardIptables;     // ← 缺 break
    case 'advance':
        chainName = '1PANEL_INPUT';
        msg = ...advanceIptables;
}
```

后果：无论 currentTab 是 `base`/`forward`/`advance`，`chainName` 最终恒落为 `'1PANEL_INPUT'`、`msg` 恒为 advance 文案。虽然后端 `operateFilterChain` 按 `'init-' + currentTab` 的 action 串处理掩盖了 chainName 传错的影响，但这是确凿的逻辑 Bug + 提示文案错误，初始化向导落地时必须一并修复。

### 2.4 fireName 硬判断残留（实测 30 处，目标 0-2）

`grep -rn fireName frontend/src/views/host/firewall/` 统计 **30 处**，分布：

| 文件 | 处数 | 文件 | 处数 |
|---|---|---|---|
| `port/index.vue` | 7 | `forward/index.vue` | 6 |
| `port/operate/index.vue` | 2 | `forward/operate/index.vue` | 1 |
| `ip/index.vue` | 6 | `forward/import/index.vue` | 1 |
| `ip/operate/index.vue` | 2 | `advance/index.vue` | 5 |

其中 `fireName !== '-'` 仍是各页「防火墙是否就绪/已初始化」的事实判断主力（`port:18,690`、`ip:19,356`、`forward:16,284`、`advance:16,359`）。`'-'` 哨兵值来自 `FireStatus` 在 `!isInit`/catch 时 `emit('update:name','-')`。多个对话框 fireName prop 透传后基本未实际使用。设计稿 PR-7「删 fireName 硬判断」（目标 0-2）**未达成**。

### 2.5 数据流（实测）

```
进入子页(port/ip/forward/advance)
  └─ onMounted: fireName!=='-' → fireStatusRef.acceptParams()
        └─ FireStatus.loadBaseInfo() POST /hosts/firewall/base{name:tab} (40s 超时)
              └─ emit 回 name/isActive/isInit/isBind/capabilities/mode (未 init 时 name='-')
              └─ emit('search') → 父页 search(): !isActive 清空，否则 POST /hosts/firewall/search
  端口页 search 后再调 process 模块 getListeningProcess 合并监听进程
  高级页 search 额外 POST /hosts/firewall/filter/chain/status 拿 isBind/defaultStrategy

对话框打开 → POST /hosts/firewall/docker/status (loadFireDockerStatus) 决定 applyToDocker

全局 SessionConfirm（独立）→ onMounted 每 3s POST /session/status；确认/撤销走 /session/confirm|revert
快照抽屉 → /snapshot/list、/snapshot/restore
白名单抽屉 → setting 模块 getAgentSettingInfo/updateAgentSetting(key=FirewallPortWhiteList)  ← 非 firewall 专用接口
状态头 Docker 重启判断 → container 模块 loadDockerStatus  ← 与对话框的 firewall docker/status 是两条不同链路
```

**轮询只有 session/status 一处（3s）**；base/列表无自动轮询，靠手动刷新或操作后 search。**两套 Docker 探测接口并存**：状态头用 `container.loadDockerStatus`、对话框用 `firewall.loadFireDockerStatus`。

---

## 3. 重构后信息架构

### 3.1 是否保留五 tab？——保留肌肉记忆，补一个默认着陆页

设计稿 §9 原文是「保留五 tab 骨架」，但**当前代码实际只有 4 个 RouterButton，根本没有独立状态页**。这是设计稿措辞与代码现状的第一处偏差。重构方向：**在保留 4 个老 tab 原位的前提下，新增「概览」作为第 5 个 tab 且设为默认路由**——既兑现「五 tab 骨架」，又把 §9.1 三卡片落到一个有归属的页面，而非继续散在每个子页顶端重复渲染。

### 3.2 总览图（重构后）

```
/hosts/firewall
   │ 默认重定向
   ▼
[ 概览 ]  [ 端口 ]  [ 转发 ]  [ IP 黑白名单 ]  [ iptables 高级 ]
   ↑默认着陆       ←——— 老用户肌肉记忆 4 tab 原位保留 ———→        ↑仅 capabilities.filter 显示
   │
   ├─ 三卡片：防火墙状态 / 保底通道 / 快照
   ├─ conflict 横幅 + bootDegraded 横幅（从 status/index.vue 迁来）
   └─ 入口：管理白名单 / 管理快照 / 启停 / 禁 Ping / 初始化向导

各功能页顶部不再各画一遍 <FireStatus> 状态头
   → 改为轻量 useFireBaseInfo composable，只取 capabilities/mode/isReady
   → 列表页顶部改放「数据包流向条」（端口/IP 页）
```

### 3.3 状态头组件的拆分策略

当前 `status/index.vue` 同时承担「状态展示 + 启停/初始化/绑定/白名单/快照入口 + emit capabilities 给父页」三重职责，被每个子页内嵌。重构拆为：

- **概览页**（`overview/index.vue`，新建）：承载三卡片 + 横幅 + 所有操作入口（复用 status 现有逻辑）。
- **`useFireBaseInfo` composable**（新建）：子页只调它拿 `capabilities/mode/isReady/isActive`，不再 import 整个 el-card 状态头，消除重复渲染。
- **`status/index.vue`**：瘦身为仅概览页使用，修复 fall-through，文案改人话。

---

## 4. 逐页重构方案 + ASCII Mockup

### 4.1 概览页 三卡片（设计 §9.1，当前完全缺失）

```
┌─ 防火墙状态 ──────────────┐ ┌─ 保底通道（不会被锁外） ─────┐ ┌─ 快照 ──────────────┐
│ ● 运行中   iptables v1.8  │ │ SSH    :22    ✓ 已放行       │ │ 最近备份: 2 分钟前    │
│ 模式: 1Panel 全权管理  ⓘ  │ │ 面板   :9999  ✓ 已放行       │ │ 共 8 份             │
│ 开机自检: 通过 ✓          │ │ HTTP   :80    ✓ （可关闭）   │ │ [管理快照] [立即备份]│
│ [停止] [重启] [禁 Ping]   │ │ HTTPS  :443   ✓ （可关闭）   │ │                     │
└───────────────────────────┘ │ [管理白名单]                 │ └─────────────────────┘
   ⓘ tooltip:                  └──────────────────────────────┘
   "1Panel 全权管理 iptables 规则"   external 模式 tooltip:
                                "ufw 由系统管理，1Panel 代为操作、不改其启停"
[!] 冲突横幅（firewalld+ufw 同时运行） / 开机自检降级横幅 —— 保留现有 el-alert
```

要点：
- 卡片①复用 status 现有 name/mode 徽章 + tooltip + 启停/禁 Ping，**文案改人话**。
- 卡片②**全新**：列 SSH:22 / 面板:9999 / 80 / 443 的放行态。SSH/面板为不可关闭保底（只读），80/443 提供可关闭开关 + 风险确认。**数据依赖后端 base 补 baseline 的 80/443 开关态字段**（硬阻塞，见 §7）。
- 卡片③复用 snapshot 抽屉入口，显示最近备份时间/数量；按 `capabilities.snapshot` 区分 panel / native-export 语义。
- 布局：`el-row` + `el-col :span="8"` + `el-card`，内部 flex gap-*，禁止新增 scss。

### 4.2 规则列表页 顶部流向条 + 层级 tag（设计 §9.2，当前完全缺失）

设计稿自称这是「性价比最高的一个改动」，直接回答 #12897。

```
┌ 数据包流向（点击各段过滤列表） ────────────────────────────────────────────┐
│ 入站 → [自救通道] → [黑名单 ✕] → [保底 SSH/面板🔒] → [放行 ✓] → [默认:宽松] │
└──────────────────────────────────────────────────────────────────────────┘
  新建  删除  导入 导出           策略[全部▼]  🔍搜索  ⟳  ⚙
┌──────┬──────┬──────────┬────────┬──────────┬──────────┬──────────┐
│ 层级 │ 协议 │ 端口     │ 状态   │ 策略     │ 地址     │ 描述     │
├──────┼──────┼──────────┼────────┼──────────┼──────────┼──────────┤
│🔴黑名单│ tcp │ 3306     │ mysqld │ 拒绝     │ 1.2.3.4  │ ...      │ ←按真实求值顺序排序
│🔒保底 │ tcp │ 22       │ sshd   │ 放行     │ 全部     │ SSH(只读)│
│🟢放行 │ tcp │ 80 🐳    │ nginx  │ 放行     │ 全部     │ ...      │ 🐳=Docker 发布端口徽章
│⚪失效 │ tcp │ 8080     │ 无监听 │ 放行     │ 全部     │ [清理]   │
└──────┴──────┴──────────┴────────┴──────────┴──────────┴──────────┘
  层级 tag: el-tag type=danger(黑名单)/info+lock(保底)/success(放行)/info(失效)
```

要点：
- 流向条为纯 `flex + el-icon(ArrowRight) + el-tag`，每段 `@click emit('filter', level)` 让父列表过滤；默认策略段读 `capabilities.defaultDrop` 显示宽松/严格。
- 表格首列「生效层级」彩色 tag，数据**按真实求值顺序排序**。求值顺序对应后端链布局 DENY→BASELINE→ALLOW（见 `firewall-refactor-design.md` §3.4），需 search 接口/dto 补 `level` 字段，或前端依据 `strategy` + 保底集推断（KISS 优先用后者，避免后端改动）。
- **澄清 `unUsed` tag 语义**：当前 `port/index.vue:143` 的 unUsed tag 表示「端口未被进程监听」，不是「规则失效」。重构改为「无监听」灰 tag，另加「规则失效」灰 tag + 工具栏「清理失效描述」按钮（调 `CleanOrphanFirewallRecords`，替代被删的 `cleanUnUsedData`）。

### 4.3 确认卡片（commit-confirm）两态（设计 §9.3，缺 2s 过渡态）

```
应用中态（保存后约 2s，按钮禁用）:
┌─ ⟳ 正在应用防火墙变更… ──────────────────────────────────┐
│ 若应用后失联，将在倒计时结束后自动撤销   [确认保留(禁用)] │
└──────────────────────────────────────────────────────────┘
倒计时态（轮询/应用完成后）:
┌─ ⚠ 3 处变更已生效，0:58 后自动撤销 ──────────────────────┐
│ • 14:02 拒绝 1.2.3.4 访问 3306                            │
│ • 14:02 放行 tcp/8443                                     │
│                       [明细▾] [✓ 确认保留] [✕ 立即撤销]   │
└──────────────────────────────────────────────────────────┘
```

要点（对照 §9.3 三处不符）：
- **补 2s「应用中…」过渡态**：暴露 `enterApplying()` 方法供规则保存成功后立即调用，显示 spinner 态（确认/撤销禁用）约 2s 或直到下次轮询拿到 `active`——解决「保存后靠最长 3s 轮询才出现卡片、期间无任何反馈」。
- **倒计时归 0 主动刷新**：归 0 时 refresh 并提示「已自动撤销」，而非 remain 停在 0。
- **文案后果化**：保持「OS 改分辨率保留设置？」心智模型，沿用现有 `md:flex-row` 窄屏适配。

### 4.4 危险操作 风险预检 vs 红线拒绝（设计 §9.3，当前完全缺失）

```
风险预检（L1 返回 risk，可继续）:          红线拒绝（L1 红线，不可继续）:
┌─ ⚠ 这条规则可能让你失联 ───────────┐   ┌─ ⛔ 操作已拒绝 ──────────────────┐
│ 此规则将拦截你当前的 IP 1.2.3.4。  │   │ 该规则会同时阻断 SSH 与 1Panel   │
│ 应用后若失联，60 秒内未确认将自动  │   │ 面板，已拒绝。                    │
│ 撤销。                             │   │ 如需默认拒绝入站，请使用          │
│ ☑ 我已了解风险                     │   │「严格模式」开关。                 │
│            [取消]  [仍要应用]      │   │                    [我知道了]    │
└────────────────────────────────────┘   └──────────────────────────────────┘
  el-alert type=warning + 勾选才启用按钮     el-alert type=error，无继续按钮
```

要点：
- **后端依赖**：operate 接口/dto 需增 `risk` 字段返回 L1 预检结果（后端 `precheckPortRule`/`precheckAddressRule` 已有 L1 逻辑，只需把 risk 信息回传）。这是硬阻塞。
- 风险态：`el-alert type=warning` + `el-checkbox`「我已了解风险」勾选才启用「仍要应用」，文案带当前 IP。
- 红线态：`el-alert type=error`，**无继续按钮**，只有「我知道了」——不给用户「再点一次就能过」的错觉。
- `port/operate/index.vue:171-224`、`ip/operate/index.vue:133-166` 的 onSubmit 改为：先预检（或捕获后端 L1 返回的 risk/红线错误码），弹对话框，确认后再 operate。

### 4.5 快照恢复 diff 预览（设计 §9.3，缺失）

```
┌─ 恢复快照 firewall-20260629-1402 ──────────────────────┐
│ 将恢复 12 条规则：                                      │
│   + 新增放行  2   tcp/8443、tcp/9000                    │
│   - 移除放行  1   tcp/3000                              │
│   + 新增封禁  3   1.2.3.4、5.6.7.8、9.0.0.0/8           │
│                                  [取消]  [确认恢复]     │
└────────────────────────────────────────────────────────┘
```

恢复前调 `snapshot/preview` 接口（**需后端补**）展示 diff，用 `el-descriptions` 或 `el-table` 呈现，确认后才 `restoreFireSnapshot`。

### 4.6 初始化向导（设计 §9.4，替换裸 init 按钮 + 修 fall-through）

```
步骤 1/3 确认保底端口    步骤 2/3 选默认策略         步骤 3/3 应用并自检
SSH  :22   ☑           ○ 宽松(未列出端口默认放行)   ⟳ 写入规则…      ✓
面板 :9999 ☑           ○ 严格(未列出端口默认拒绝)   ⟳ 探针自查…      ✓
80/443     ☑可选        ⓘ 严格模式更安全但需先        ✓ SSH/面板可达
[下一步]               放行所有业务端口 [上一步][下一步]  [完成]
```

要点：
- `el-steps` 三步替换 `status/index.vue:281-304` 的裸 ElMessageBox `onInit`。
- 步骤 3 调 `operateFilterChain` + 自查 `base`，绿勾呈现探针式自查。
- **同时修复 §2.3 的 switch fall-through**（每个 case 末尾补 break）。

### 4.7 Docker / IPv6 可见性（设计 §9.4，部分缺失）

- **Docker 端口徽章**：端口列表给 Docker 发布端口加 🐳 图标徽章（复用 `dockerStatus`），状态页显示容器端口防护状态。当前 `applyToDocker` 勾选已实现，但徽章/状态可见性缺失。
- **统一 Docker 探测**：废弃概览页对 `container.loadDockerStatus` 的依赖，统一走 `firewall.loadFireDockerStatus`，消除双接口歧义。
- **IPv6 一致性**：`ip/operate` 补 family 选择器对齐 port，条件 `mode==='managed' && capabilities.ipv6Rules`。当前双栈机上封 IP 黑名单可能只封了 v4 且无提示。

### 4.8 白名单分区（设计 §3.10，缺失）

```
┌─ 端口白名单 ───────────────────────────────────┐
│ 保底端口（不可删除）                            │
│   SSH    :22     [只读]                          │
│   面板   :9999   [只读]                          │
│ ─────────────────────────────────────────────  │
│ 可编辑端口                                       │
│   80/tcp                              [编辑][删] │
│   443/tcp                             [编辑][删] │  ← 删 80/443 走风险二次确认
│   443/udp                             [编辑][删] │
│                              [+ 新增]  [确认]    │
└─────────────────────────────────────────────────┘
```

把 `white-list/index.vue:9-33` 的扁平表分区：required(SSH/面板) 只读区（禁删/禁编） + 可编辑区（含默认 80/443）；删 80/443 走 `ElMessageBox` 风险二次确认。

---

## 5. 组件级改动清单

> 约定：Element Plus + tailwindcss，少自定 style；新文案进 i18n（zh/en 先行）。「依赖后端」列标注需后端 agent 协同的项。

| # | 文件 | 改动 | 依赖后端 |
|---|---|---|---|
| 1 | `firewall/index.vue` | buttons 首位新增「概览」tab（path `/hosts/firewall/overview`）设为默认重定向；高级 tab 改 `v-if` 依据 `capabilities.filter`（经路由 meta 或顶层 store）而非常驻 | — |
| 2 | `firewall/overview/index.vue`（新建） | 概览页三卡片（§4.1）：`el-row/el-col :span=8` + `el-card`；卡片②保底通道全新；冲突/bootDegraded 横幅从 status 迁入 | 需 base 补 80/443 开关态 |
| 3 | `firewall/composables/useFireBaseInfo.ts`（新建） | 抽出 base 拉取逻辑，子页只取 `capabilities/mode/isReady`，不再内嵌 el-card 状态头 | — |
| 4 | `status/index.vue` | 修 `onInit()` switch fall-through（补 break，284-294）；状态头瘦身为仅概览页用；`modeExternal` 文案「可视化管理」→「管理 ufw（不介入启停）」；快照按钮加 `v-if capabilities.snapshot` | — |
| 5 | `components/firewall/flow-bar.vue`（新建） | 数据包流向条（§4.2）：纯 flex + el-icon(ArrowRight) + el-tag，每段 `@click emit('filter', level)`；默认策略段读 `capabilities.defaultDrop` | — |
| 6 | `port/index.vue` | 顶部引入 flow-bar；表首列「生效层级」el-tag 并按求值顺序排序；Docker 发布端口加 🐳 徽章；`unUsed` tag 语义改「无监听」+ 加「规则失效」灰 tag + 工具栏「清理失效描述」(调 CleanOrphanFirewallRecords)；去 `fireName!=='-'` 改 `isReady` 计算属性 | level 字段可前端推断 |
| 7 | `ip/index.vue` | 同 port：引入 flow-bar、生效层级 tag、按求值顺序排序；策略筛选 value 与文案对齐（当前 allow/deny 文案但 value 仍 accept/drop） | — |
| 8 | `ip/operate/index.vue` | 补 family 选择器对齐 `port/operate:41-51`，条件 `mode==='managed' && capabilities.ipv6Rules`；需父页 `ip/index` 把 capabilities/mode 经 v-model 透传给对话框 | — |
| 9 | `components/firewall/risk-precheck-dialog.vue`（新建） | 风险预检/红线拒绝两态（§4.4）：risk 态 `el-alert warning` + checkbox 勾选才启用；红线态 `el-alert error` 无继续按钮 | 需 operate 接口/dto 增 risk 字段 |
| 10 | `port/operate/index.vue` | onSubmit 前调预检（或捕获后端 L1 risk/红线错误码）弹 risk-precheck-dialog，确认后再 operatePortRule | 同上 |
| 11 | `session-confirm.vue` | 补 2s「应用中…」过渡态：暴露 `enterApplying()`；倒计时归 0 主动 refresh + 提示「已自动撤销」 | — |
| 12 | `status/snapshot/index.vue` | 恢复前加 diff 预览（§4.5），调 snapshot/preview，用 el-descriptions/el-table，确认后才 restore | 需后端补 snapshot/preview |
| 13 | `status/white-list/index.vue` | 分区：required(SSH/面板) 只读区 + 可编辑区；删 80/443 走风险二次确认 | base 提供 required 集 |
| 14 | `advance/index.vue` | 链下拉 value 保留 1PANEL_*、label 已是入站/出站方向（现状可接受）；「绑定/解绑」→「启用/停用 1Panel 管理」；prompt defaultStrategy 文案去裸链名；初始化入口接向导 | — |
| 15 | `firewall/init-wizard/index.vue`（新建） | 三步初始化向导（§4.6）：el-steps + 确认端口/选策略/应用自检，替换裸 ElMessageBox onInit | — |
| 16 | `lang/modules/{zh,en}.ts` | 新增/改写文案（见 §6） | — |
| 17 | `api/modules/host.ts` + `api/interface/host.ts` | 统一 Docker 探测走 `loadFireDockerStatus`；RuleIP 补 family 透传；补 snapshot preview、risk、base 的 baseline 80/443 开关态类型定义 | 依赖后端对应改动 |

---

## 6. i18n 文案要点（中英）

> 新文案 9 语言至少补 zh/en，其余 zh-Hant/ja 等可机翻后人工校。

| key（建议） | zh | en |
|---|---|---|
| `firewall.modeExternal` | 管理 ufw（不介入启停） | Manage ufw (no control over start/stop) |
| `firewall.modeExternalTip` | ufw 由系统管理，1Panel 代为操作、不修改其启动行为 | ufw is managed by the system; 1Panel operates on your behalf without changing its boot behavior |
| `firewall.modeManagedTip` | 1Panel 全权管理 iptables 规则 | 1Panel fully manages iptables rules |
| `firewall.rescueChannel` | 保底通道（不会被锁外） | Rescue channels (won't lock you out) |
| `firewall.rescueAllowed` | 已放行 | Allowed |
| `firewall.rescueClosable` | 可关闭 | Closable |
| `firewall.flowInbound` | 入站 | Inbound |
| `firewall.flowRescue` | 自救通道 | Rescue |
| `firewall.flowDeny` | 黑名单 | Denylist |
| `firewall.flowBaseline` | 保底 | Baseline |
| `firewall.flowAllow` | 放行 | Allow |
| `firewall.flowDefaultLoose` / `flowDefaultStrict` | 默认：宽松 / 默认：严格 | Default: loose / Default: strict |
| `firewall.levelDeny`/`levelBaseline`/`levelAllow`/`levelOrphan` | 黑名单 / 保底 / 放行 / 失效 | Denylist / Baseline / Allow / Orphan |
| `firewall.riskTitle` | 这条规则可能让你失联 | This rule may lock you out |
| `firewall.riskCurrentIP` | 此规则将拦截你当前的 IP {0}，应用后若失联，60 秒内未确认将自动撤销。 | This rule will block your current IP {0}; if you lose connection, it auto-reverts in 60s unless confirmed. |
| `firewall.riskAck` | 我已了解风险 | I understand the risk |
| `firewall.riskProceed` | 仍要应用 | Apply anyway |
| `firewall.redlineTitle` | 操作已拒绝 | Operation rejected |
| `firewall.redlineBlockBoth` | 该规则会同时阻断 SSH 与 1Panel 面板，已拒绝。如需默认拒绝入站，请使用「严格模式」开关。 | This rule would block both SSH and the 1Panel console; rejected. To deny inbound by default, use the Strict Mode switch. |
| `firewall.applying` | 正在应用防火墙变更… | Applying firewall changes… |
| `firewall.autoReverted` | 变更未确认，已自动撤销 | Changes unconfirmed and auto-reverted |
| `firewall.snapshotDiffTitle` | 将恢复 {0} 条规则 | Will restore {0} rules |
| `firewall.snapshotDiffAdd`/`Remove`/`Block` | 新增放行 {0} / 移除放行 {0} / 新增封禁 {0} | Add allow {0} / Remove allow {0} / Add block {0} |
| `firewall.wizardStep1`/`Step2`/`Step3` | 确认保底端口 / 选默认策略 / 应用并自检 | Confirm rescue ports / Choose default policy / Apply & self-check |
| `firewall.enableManaged` / `disableManaged` | 启用 1Panel 管理 / 停用 1Panel 管理 | Enable 1Panel management / Disable |
| `firewall.cleanOrphan` | 清理失效描述 | Clean orphan records |
| `firewall.noListen` | 无监听 | No listener |

---

## 7. 分阶段落地计划（KISS、可独立合并）

> 原则：每个 PR 可独立合并、独立回归；纯前端项优先（无后端阻塞），后端依赖项后置。

| 阶段 | PR | 内容 | 后端依赖 | 风险 |
|---|---|---|---|---|
| **P0 修 Bug + 术语** | FE-1 | 修 `onInit()` switch fall-through（补 break）；`modeExternal` 文案改人话；advance「绑定/解绑」文案改「启用/停用 1Panel 管理」、去裸链名 | 无 | 极低 |
| **P1 信息架构** | FE-2 | 新增「概览」tab + 默认重定向；抽 `useFireBaseInfo` composable；状态头瘦身（子页不再各画一遍）；高级 tab 改 `capabilities.filter` 条件显示 | 无 | 中（路由/默认页变更，需回归各 tab 进入路径） |
| **P2 性价比最高** | FE-3 | 流向条 `flow-bar.vue` + 端口/IP 列表生效层级 tag + 按求值顺序排序（level 前端推断）；澄清 unUsed 语义 + 失效描述清理按钮 | 无（level 推断）/ 可选后端 level 字段 | 低 |
| **P3 概览三卡片** | FE-4 | 概览页三卡片完整版（保底通道卡片）；白名单分区（required 只读 + 删 80/443 风险确认） | **base 补 80/443 开关态 + required 集** | 中（卡 后端） |
| **P4 恐惧→保险** | FE-5 | 确认卡片 2s 过渡态 + 倒计时归 0 提示；快照 diff 预览 | snapshot/preview（diff 部分） | 低（过渡态无依赖，diff 卡后端） |
| **P5 风险预检** | FE-6 | risk-precheck-dialog + port/ip operate 接入；初始化向导 | **operate dto 增 risk 字段** | 中（卡后端） |
| **P6 一致性收尾** | FE-7 | ip/operate 补 family；统一 Docker 探测接口；Docker 端口徽章；收敛 fireName 到 isReady（目标 0-2） | 无 | 低 |

**关键路径与解耦建议**：P0/P1/P2/P6 为纯前端，可立即开工并独立合并；P3/P5 强依赖后端字段（80/443 开关态、risk 字段），应优先推动后端补齐；P4 的过渡态部分无依赖可先做、diff 部分后置。fireName 收敛（P6）建议放最后，因其触及 30 处、需在前序 PR 把 capabilities 驱动渲染铺好后再统一替换，降低回归面。

---

## 8. 与设计稿 §9 的对照（已实现 / 未实现）

### 8.1 已实现（feat/dev2）

| 设计条目 | 落地证据 | 备注 |
|---|---|---|
| §3.5.1/§9.3 全局 commit-confirm 确认卡片 | `session-confirm.vue`（倒计时+明细+确认/撤销+3s 轮询） | 缺 2s 过渡态 |
| §9.1 mode 徽章 + tooltip | `status/index.vue:8-23` | 文案「可视化管理」≠ 设计「管理 ufw（不介入）」 |
| §9.1 ufw+firewalld 冲突横幅 + 开机自检降级横幅 | `status/index.vue:112-127` | — |
| 快照抽屉（复用旧分支，有 IPv6 标签） | `snapshot/index.vue` | 无 diff 预览 |
| §9.4 Docker `applyToDocker` 勾选 | port/ip 对话框（检测到 Docker 默认勾选） | — |
| §9.4 IPv6 family 选择器 | 仅 port 对话框（`operate:41-51`） | IP 对话框缺 |
| capabilities 部分驱动渲染 | advance.filter / forward.forwardImpl | baseline/snapshot/defaultDrop/rules 几乎未用 |

### 8.2 未实现

| 设计条目 | 缺口 | 根因 |
|---|---|---|
| §9.1 状态页三卡片 + 保底通道可见性 | 根本没有独立状态页；SSH/面板/80-443 保底态从不展示 | 无概览页 + base 缺 80/443 开关态字段 |
| §9.2 规则生效顺序可视化（设计称性价比最高） | 流向条 + 层级彩色 tag + 求值顺序排序全缺 | 未动工 |
| §9.3 风险预检对话框（L1 risk） | operate onSubmit 直接提交、不读 risk | dto 无 risk 字段 |
| §9.3 红线拒绝视觉区分 | 无 | 同上 |
| §9.3 确认卡片 2s「应用中…」过渡态 | 保存后靠最长 3s 轮询才出现卡片 | `session-confirm.vue:72-80` 未实现 |
| §9.3 快照恢复 diff 预览 | 仅通用 ElMessageBox | 无 preview 接口 |
| §9.4 初始化向导（三步） | 仍裸 ElMessageBox，且有 fall-through Bug | `status/index.vue:281-304` |
| §9.4 端口列表 Docker 容器图标徽章 | 无 | 未动工（勾选已有） |
| §9.4 失效描述灰 tag + 清理按钮 | 无（unUsed tag 语义是「未监听」非「规则失效」） | `port/index.vue:143` |
| §3.10 白名单 required 只读 / 可编辑分区 + 删 80/443 风险确认 | 扁平可删 | `white-list/index.vue:9-33` |
| §3.10/PR-7 删 fireName 硬判断 | 残留 30 处（目标 0-2） | 未做 |
| IP 对话框 family 选择器 | 缺（与 port 不一致） | 未对齐 |

### 8.3 偏差 / Bug（代码与设计不一致处）

| 类别 | 描述 | 证据 |
|---|---|---|
| 设计措辞偏差 | 设计称「保留五 tab 骨架」，代码实际只有 4 个 RouterButton、无独立状态页 | `index.vue:15-32` |
| 逻辑 Bug | `onInit()` switch 缺 break，chainName 恒 `1PANEL_INPUT`、msg 恒 advance 文案 | `status/index.vue:284-294`（实测确认无 break） |
| 实现偏差 | advance tab 按钮常驻，非「仅 capabilities.filter 时显示」（仅内容降级） | `index.vue:28-31`、`advance/index.vue:16` |
| 维护歧义 | 两套 Docker 探测接口并存：`container.loadDockerStatus`（状态头）vs `firewall.loadFireDockerStatus`（对话框） | `status/index.vue:257` vs `port/operate:122` |
| 术语外泄 | `1PANEL_INPUT/OUTPUT` 链名进选择器、「绑定链/初始化」当用户心智模型 | `advance/index.vue:63-64`、`status/index.vue:60-93` |
| 字段冗余 | capabilities 8 字段中 baseline/snapshot/defaultDrop/rules 声明了但前端几乎未消费 | `status/index.vue:185-195` |

### 8.4 总体判断

`feat/dev2` 前端落地的是「**安全栈接入 + 字段管线打通**」（PR-1/PR-2 的前端面），设计稿 §9 真正改善「理解成本 / 恐惧成本」的交互层（PR-7 收尾）**尚未动工**。本设计稿的 7 个阶段 PR 即为补齐 §9 的施工路径，其中 P3/P5 强依赖后端补齐 base 的 80/443 开关态与 operate 的 risk 字段——这两项是前端体验落地的硬阻塞，需优先与后端 agent 协同。

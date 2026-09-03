# 实机验收:终端会话保持 v2(feat/session-v2)

> 给云 Linux 验收 agent 的操作手册。逐项记录**实际命令输出 / 截图描述**作为证据,最后按第 7 节模板出结论。
> 本文件不跟踪,不要提交。只验收,不修改代码;发现问题记录并继续。

## 0. 设计要点(判断"符合预期"的依据)

- ssh 会话绑定**浏览器标签页**,不绑定路由。终端组件由 `components/terminal/host.vue` 常驻在 Layout 里,进入终端页时 Teleport 到页面,离开时挪回后台。
- 终端 tab 上有图钉(pin)。**未 pin**:离开终端页 → 前端发 ws close 1000 → agent 立即关 shell(和原行为一致)。**已 pin**:离开终端页 ws 不断,shell 一直在。
- agent 只区分两种断开:收到 close 1000 立即回收;其他任何断开(断网、刷新、关标签页、半开)留 **2 分钟宽限期**,期间带 `?session=<id>` 重连可接回。
- 回放是有损的:agent 每会话一个 128KB ring buffer,重连只回放尾部;客户端落后超过 128KB 会看到一行黄色 `[输出已截断,仅显示最近输出]`。
- pinned 会话的 id 记在 **sessionStorage**(按浏览器标签页隔离):刷新后自动重连;另开一个浏览器标签页看不到。
- 半开检测靠 ws 协议层 ping/pong(30s 一次,75s 没 pong 判死),不依赖浏览器 JS 定时器。
- 没有新增 REST 接口、设置项、DB 迁移。

## 1. 构建与部署

```bash
cd <repo> && git checkout feat/session-v2 && git log --oneline -1
cd agent && go build ./... && go vet ./utils/terminal/ ./app/api/v2/ && go test -race -count=1 ./utils/terminal/ ; cd ..
cd core && go build ./... ; cd ..
make build_all            # 产物:build/1panel-core build/1panel-agent(前端已打进 core)
# 备份并替换(路径以实际安装为准,通常在 /usr/local/bin)
systemctl stop 1panel-agent 1panel-core
cp /usr/local/bin/1panel-core /usr/local/bin/1panel-core.bak && cp /usr/local/bin/1panel-agent /usr/local/bin/1panel-agent.bak
cp build/1panel-core build/1panel-agent /usr/local/bin/
systemctl start 1panel-core 1panel-agent && sleep 3 && systemctl is-active 1panel-core 1panel-agent
```
记录:go test 输出(应 `ok`,无 FAIL)、两个服务 active。

## 2. 基本功能(浏览器,建议 Chrome,开着 DevTools → Network → WS)

| # | 操作 | 预期 |
|---|---|---|
| 2.1 | 打开 主机 → 终端,新建本地终端 | ws 首条服务端消息为 `{"type":"session","id":"<uuid>"}`;终端可用 |
| 2.2 | 观察 tab 标题右侧 | 有一个半透明图钉按钮,hover 提示"固定会话…";点击后变高亮(橙色),再点取消 |
| 2.3 | **未 pin**:在终端跑 `sleep 600 &`,记 pid;切到"概览"菜单,再切回终端 | 切走瞬间 ws 关闭码 **1000**;回来是**新**会话(新 session id);服务器上 `ps -p <pid>` 已不存在(shell 被关,子进程随之收到 SIGHUP) |
| 2.4 | **已 pin**:pin 后跑 `sleep 600 &` 并 `echo marker-$RANDOM`;切走 30 秒再回来 | 切走时 ws **不关闭**(Network 面板里连接仍是 101 打开状态);回来同一个 tab、同一个 session id,marker 和之前的滚动内容原样在,不闪屏不重连;`ps -p <pid>` 仍在 |
| 2.5 | pinned 会话切走期间,在服务器上往该 tty 打输出(例:在终端里先跑 `for i in $(seq 1 30); do echo tick-$i; sleep 1; done`,然后马上切走 10 秒再回来) | 回来后能看到切走期间打印的 tick 行(xterm 在后台持续收数据,不需要回放) |
| 2.6 | 关闭一个 pinned 的 tab(点 x) | 弹确认框"该会话已固定,关闭标签页将结束服务器上的 shell";确认后 ws 关闭码 1000,shell 结束 |
| 2.7 | 关闭未 pin 的 tab | 无确认,直接关 |
| 2.8 | 开 3 个终端,pin 其中 1 个,切走再回来 | 只剩 pinned 那一个 tab,其他两个消失 |

## 3. 断网重连(核心)

| # | 操作 | 预期 |
|---|---|---|
| 3.1 | pin 一个会话,跑 `sleep 600 &` 记 pid;DevTools → Network → 勾选 **Offline**;等 20 秒;取消 Offline | 断网时终端出现黄字"连接已断开,正在重连...";恢复后几秒内自动重连(新的 ws 101,URL 带 `&session=<同一个id>`),屏幕先清空再回放最近输出,`ps -p <pid>` 仍在,shell 里 `echo $$` 与断网前一致(同一个 shell) |
| 3.2 | 断网期间产生大量输出:pin 后运行 `yes | head -c 3000000`(约 3MB)的同时勾 Offline 30 秒后恢复 | 重连后先出现黄字 `[输出已截断,仅显示最近输出]`,随后只看到尾部,不会卡死、不会把 3MB 全部推过来;agent 进程内存无明显增长(`ps -o rss= -p $(pidof 1panel-agent)` 前后对比) |
| 3.3 | 宽限过期:Offline 保持 **2 分 30 秒** 再恢复 | 恢复后重连被 agent 以关闭码 **4404** 拒绝,终端红字"会话已失效…";tab 状态变为断开(出现刷新按钮);点刷新按钮 → 新开一个会话正常可用 |
| 3.4 | 未 pin 的会话断网 20 秒再恢复 | 同样会自动重连(宽限期与 pin 无关,pin 只管切页面);证据同 3.1 |
| 3.5 | 半开检测:pinned 会话,在服务器上用 iptables 丢弃该客户端到面板端口的包(或直接拔网线级别的中断)约 100 秒,然后恢复 | agent 日志或 `ss -tnp` 显示旧连接在 ~75–105 秒内被 agent 主动关掉;客户端恢复后仍能带 session id 重连成功(仍在 2 分钟宽限内) |

## 4. 刷新 / 标签页 / 多窗口

| # | 操作 | 预期 |
|---|---|---|
| 4.1 | pin 一个会话,跑 `sleep 600 &`,按 F5 刷新 | 刷新后**不用进终端页**,DevTools 里已经能看到 ws 带 `&session=<id>` 重连成功(host 在 Layout 挂载时就重连);进入终端页看到同一会话,`ps -p <pid>` 仍在;`sessionStorage.getItem('terminal.pinnedSessions')` 里有该 id |
| 4.2 | 未 pin 的会话按 F5 | 刷新后没有恢复(sessionStorage 无记录);agent 侧该会话 2 分钟后自动回收(可用 `ss -tnp` 或等待后观察 `ps`) |
| 4.3 | 另开一个**新浏览器标签页**登录同一面板 | 新标签页看不到旧标签页的 pinned 会话(sessionStorage 隔离) |
| 4.4 | 在新标签页手动构造重连:复制旧标签页 ws URL(含 session id)在控制台 `new WebSocket(url)` | 旧标签页终端出现红字"该会话已在其他窗口打开",ws 关闭码 **4409**;旧标签页点刷新按钮又能抢回来 |
| 4.5 | 关闭整个浏览器标签页,等 2 分半,再新开标签页登录 | 不会恢复;服务器上 shell 已回收 |
| 4.6 | 登出再登录(同一标签页) | 登出时所有会话以 1000 关闭;重新登录后如果 sessionStorage 还有记录,重连会收到 4404,tab 显示为断开态且记录被清掉,不报错不卡 |

## 5. 回归(不能坏的东西)

| # | 操作 | 预期 |
|---|---|---|
| 5.1 | 容器 → 某容器 → 终端 | 正常;没有 session hello 也无所谓,断开后不会尝试重连(行为与改动前一致) |
| 5.2 | 文件管理 → 终端、数据库 Redis 终端、运行环境终端、AI 模型终端 | 各打开一次,正常收发 |
| 5.3 | 终端页快捷命令、批量输入(勾选"批量输入")、全屏按钮、AI 设置 | 正常;批量输入发到所有 tab |
| 5.4 | 终端设置里改字体大小/主题 | pinned 会话也实时生效 |
| 5.5 | vim/htop 全屏程序在 pinned 会话里,断网重连后 | 屏幕可能只回放了尾部而显示不完整,**按 Ctrl-L 可重绘**;记录现象即可,这是已知取舍 |
| 5.6 | 菜单标签页模式(设置 → 面板设置 → 开启菜单标签页)下重复 2.3、2.4 | 结论一致;高度计算正常(无多余滚动条) |
| 5.7 | 手机宽度视口 | 图钉按钮不破坏 tab 布局 |

## 6. 静态门槛

```bash
cd agent && gofmt -l ./utils/terminal ./app/api/v2 && go vet ./utils/terminal/ ./app/api/v2/      # 无输出/exit 0
cd frontend && npx prettier --check src/components/terminal/index.vue src/components/terminal/host.vue src/store/modules/terminal-session.ts src/store/index.ts src/layout/index.vue src/views/terminal/terminal/index.vue
git diff --stat dev-v2...HEAD | tail -3
```
确认:没有新增 REST 路由(`grep -n "sessions" agent/router/ro_host.go` 无输出)、没有新迁移、没有设置项。

## 7. 结论模板

```
# 验收报告 — feat/session-v2(<日期>)
环境:发行版/内核、浏览器版本、1Panel 安装方式
第 1 节:构建/测试/部署 → 通过/失败(附输出)
第 2 节:8 项 → X 通过 / Y 失败(失败项附证据)
第 3 节:5 项 → …
第 4 节:6 项 → …
第 5 节:7 项 → …
第 6 节:通过/失败
阻塞级问题(必须修):
非阻塞问题 / 观察:
结论:可合 / 需修后再验
```

## 7. 第一轮反馈后的修复与重测(2026-09-03)

**已修**:未 pin 会话离开终端页不关闭(2.3 / 2.8 / 2.6 同源)。原因是 `views/terminal/index.vue` 在父组件 `onUnmounted` 里调子组件 ref,此时 ref 已是 null,`closeUnpinned()` 从未执行。现在改由 `views/terminal/terminal/index.vue` 自己的 `onBeforeUnmount` 触发。

**重测前**:重新 `pnpm build` 前端、重启 agent(agent 侧新增一条 debug 日志)。把 agent 日志级别调到 debug,每次 ws 断开都会打:

```
terminal session <id> detached, clean=true    # 收到 1000,立即关 shell
terminal session <id> detached, clean=false   # 非 1000,进入 2 分钟宽限
```

**重测项**:2.3、2.6、2.8,判定以这条日志为准:
- 2.3 / 2.8:切走后未 pin 的每个 session 都应出现 `clean=true`,并且 `ps -p <pid>` 在 5 秒内消失。
- 2.6:确认关闭后应出现 `clean=true`。若日志是 `clean=false`,说明 1000 关闭码没有穿过 core → agent 的 ws 代理,请附上 core 与 agent 各自的日志片段;若日志是 `clean=true` 但 `sleep` 仍活着,请记录 `ps -o pid,ppid,stat,cmd -p <pid>` 和存活秒数(区分"没关"和"关得慢")。

之后继续第 3–5 节。

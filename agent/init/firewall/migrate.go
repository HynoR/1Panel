package firewall

import (
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// denyQuarantineFileName 存放迁移时被判定为"广源且覆盖保底端口"的旧 DENY 规则原文。
// 这些规则在老 3 链布局里位于保底 ACCEPT 之后从未生效（休眠）；迁移若把它们放进新 DENY(第②位)
// 会先于 BASELINE(第③位)的 SSH/面板 ACCEPT 命中，升级瞬间静默锁外，故隔离不加载（评审 R1）。
const denyQuarantineFileName = "deny.quarantine"

// migrateLegacyChains 把旧的 BASIC_BEFORE/BASIC/BASIC_AFTER 持久化文件一次性转换为
// 新的 GUARD/DENY/BASELINE/ALLOW/AFTER 布局文件（设计稿 §3.4 存量链迁移）。
//
// 设计取舍：迁移只做"文件转换 + 拍快照 + 旧文件留 .bak"这类低风险操作；真正的活体加载与
// 固定顺序绑定 + 回读断言交给随后的开机重放（runBootReplay）完成——它本就带 readback 与
// degraded/failed 状态记录。迁移失败时旧 .bak 文件保留，可用 `1pctl firewall rescue
// --restore-latest` 或降级旧版本（重放 .bak）恢复。
//
// ⚠️ 这是设计标注的"全计划之最"高风险点（数百万异构存量机活体迁移），按要求需人工逐行评审
// + S6 升级演练，禁止仅凭编译通过就上线。
func migrateLegacyChains() error {
	dir := global.Dir.FirewallDir
	// 已迁移（新文件已存在）→ 跳过，幂等。
	if fileExists(path.Join(dir, iptables.GuardFileName)) {
		return nil
	}
	// 无任何旧文件 → 全新安装，无需迁移。
	if !fileExists(path.Join(dir, iptables.BasicFileName)) &&
		!fileExists(path.Join(dir, iptables.BasicBeforeFileName)) &&
		!fileExists(path.Join(dir, iptables.BasicAfterFileName)) {
		return nil
	}

	global.LOG.Info("[firewall-migrate] migrating legacy BASIC chains to GUARD/DENY/BASELINE/ALLOW/AFTER layout")
	// 快照是迁移唯一的回滚锚点：拍不成就中止，迁移幂等，下次启动 legacyMigrationPending 仍为 true 会重试。
	// 无锚点仍继续迁移，一旦新布局出错就无处回退，违背 fail-open。
	if _, err := firewall.TakeSnapshot("pre-migration"); err != nil {
		global.LOG.Errorf("[firewall-migrate] pre-migration snapshot failed, abort migration: %v", err)
		return err
	}

	// 按新链聚合转换后的规则行。
	newRules := map[string][]string{
		iptables.Chain1PanelGuard:    {},
		iptables.Chain1PanelDeny:     {},
		iptables.Chain1PanelBaseline: {},
		iptables.Chain1PanelAllow:    {},
		iptables.Chain1PanelAfter:    {},
	}

	// 隔离判定所需的保底端口（SSH+面板）；取不到则视为空，isDenyRuleLockoutRisk 只会因"无 --dport 全端口 DROP"隔离。
	baselinePorts := service.LoadBaselinePorts()
	var quarantined []string

	classifyLegacyFile(dir, iptables.BasicBeforeFileName, iptables.Chain1PanelBasicBefore, newRules, baselinePorts, &quarantined)
	classifyLegacyFile(dir, iptables.BasicFileName, iptables.Chain1PanelBasic, newRules, baselinePorts, &quarantined)
	classifyLegacyFile(dir, iptables.BasicAfterFileName, iptables.Chain1PanelBasicAfter, newRules, baselinePorts, &quarantined)

	// 隔离文件先于链文件落盘（尤其先于最后写的 GuardFileName）：写失败即 return err，GuardFileName 未写，
	// 下次启动仍会重试；否则半迁移下丢失隔离记录会缺失 degraded 横幅（但规则本就未进 DENY，不锁外）。
	if len(quarantined) > 0 {
		if err := writeChainRules(path.Join(dir, denyQuarantineFileName), quarantined); err != nil {
			global.LOG.Errorf("[firewall-migrate] write deny quarantine failed: %v", err)
			return err
		}
		global.LOG.Warnf("[firewall-migrate] quarantined %d broad-source legacy deny rules to %s (not loaded into DENY)", len(quarantined), denyQuarantineFileName)
	}

	// 先全部写成功，再统一改名旧文件。GUARD 刻意最后写：GuardFileName 既是 GUARD 链规则文件、
	// 又是 legacyMigrationPending 判定"迁移完成"的标记，故只有全部链写成功才落盘它——任一链写失败时
	// 直接返回 err（不改名旧文件、不写后续标记），旧文件原状保留，下次启动 legacyMigrationPending 仍为
	// true 可重试；否则一旦 GuardFileName 已写而某链缺失，下次启动不再重试，该链规则永久丢失。
	order := []string{
		iptables.Chain1PanelDeny,
		iptables.Chain1PanelBaseline,
		iptables.Chain1PanelAllow,
		iptables.Chain1PanelAfter,
		iptables.Chain1PanelGuard,
	}
	for _, chain := range order {
		if err := writeChainRules(path.Join(dir, iptables.ChainFileName(chain)), newRules[chain]); err != nil {
			global.LOG.Errorf("[firewall-migrate] write %s failed: %v", chain, err)
			return err
		}
	}

	// 旧文件留为 .bak（供降级重放，设计稿 §8.3）。
	for _, f := range []string{iptables.BasicBeforeFileName, iptables.BasicFileName, iptables.BasicAfterFileName} {
		old := path.Join(dir, f)
		if fileExists(old) {
			_ = os.Rename(old, old+".bak")
		}
	}
	global.LOG.Info("[firewall-migrate] legacy chain files converted; boot replay will apply and verify the new layout")
	return nil
}

// classifyLegacyFile 读取旧链文件的每条 `-A <oldChain> ...` 规则，按设计 §3.4 step 2 归类到新链。
// 归入 DENY 的规则若被判定为锁外风险（广源+覆盖保底端口），改写入 quarantine 收集器而非 DENY（评审 R1）。
func classifyLegacyFile(dir, fileName, oldChain string, out map[string][]string, baselinePorts []string, quarantine *[]string) {
	data, err := os.ReadFile(path.Join(dir, fileName))
	if err != nil {
		return
	}
	prefix := "-A " + oldChain
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		target := classifyLegacyRule(oldChain, rest)
		if target == "" {
			continue
		}
		newLine := "-A " + target + " " + rest
		if target == iptables.Chain1PanelDeny && isDenyRuleLockoutRisk(rest, baselinePorts) {
			*quarantine = append(*quarantine, newLine)
			global.LOG.Warnf("[firewall-migrate] quarantine broad-source deny rule (covers baseline port): %s", rest)
			continue
		}
		out[target] = append(out[target], newLine)
	}
}

// classifyLegacyRule 把一条旧规则（去掉 "-A oldChain" 前缀的部分）映射到新链。
func classifyLegacyRule(oldChain, rest string) string {
	lower := strings.ToLower(rest)
	switch oldChain {
	case iptables.Chain1PanelBasicBefore:
		// lo / ESTABLISHED → GUARD；其余（SSH/面板保底 ACCEPT）→ BASELINE。
		if strings.Contains(lower, "-i lo") || strings.Contains(lower, "loopback") ||
			strings.Contains(lower, "ctstate related,established") || strings.Contains(lower, "established") {
			return iptables.Chain1PanelGuard
		}
		// R3：老 BASIC_BEFORE 的 80/443 ACCEPT 是可删的 HTTP(S) 放行，应归 ALLOW 而非不可删的 BASELINE。
		// 仅精确单端口匹配（KISS）：端口段/multiport 里夹带保底端口的情形留在 BASELINE，避免误降级。
		if strings.Contains(lower, "-j accept") && (hasExactDport(rest, "80") || hasExactDport(rest, "443")) {
			return iptables.Chain1PanelAllow
		}
		return iptables.Chain1PanelBaseline
	case iptables.Chain1PanelBasic:
		// 用户规则：ACCEPT（含 80/443 白名单）→ ALLOW；DROP/REJECT（黑名单）→ DENY。
		if strings.Contains(lower, "-j drop") || strings.Contains(lower, "-j reject") {
			return iptables.Chain1PanelDeny
		}
		return iptables.Chain1PanelAllow
	case iptables.Chain1PanelBasicAfter:
		return iptables.Chain1PanelAfter
	default:
		return ""
	}
}

// isDenyRuleLockoutRisk 纯函数：判断一条即将进入 DENY 的旧规则（去掉 "-A oldChain" 前缀部分）
// 是否可能在升级瞬间静默锁外——即"广源"且"目的端口覆盖任一保底端口"。
// 广源：无 -s，或 -s 为 0.0.0.0/0 / ::/0 / anywhere，或取反源 `! -s <ip>`。
// 端口覆盖：无 --dport/--dports 的全端口 DROP 视为覆盖全部；否则解析 --dport(单端口或 x:y 段)、
//
//	--dports(multiport 逗号列表，每项可为段) 是否命中任一保底端口。
//
// 刻意忽略 -p 协议：保底端口皆 tcp，宁可对 udp-only DROP 也多隔离一条（fail-open 更安全）。
func isDenyRuleLockoutRisk(rule string, baselinePorts []string) bool {
	if !isBroadSource(rule) {
		return false
	}
	spec, ok := extractDportSpec(rule)
	if !ok {
		// 无 --dport/--dports：全端口 DROP，覆盖所有保底端口。
		return true
	}
	for _, p := range baselinePorts {
		if portInSpec(p, spec) {
			return true
		}
	}
	return false
}

// isBroadSource 报告规则源地址是否为"广源"（无 -s 或全网段）。
func isBroadSource(rule string) bool {
	fields := strings.Fields(rule)
	for i, f := range fields {
		if f == "-s" && i+1 < len(fields) {
			if i > 0 && fields[i-1] == "!" {
				return true
			}
			v := strings.ToLower(fields[i+1])
			return v == "0.0.0.0/0" || v == "::/0" || v == "anywhere"
		}
	}
	return true
}

// extractDportSpec 返回 --dport / --dports 后的端口规格串（原样，可含逗号与段），无则 ok=false。
func extractDportSpec(rule string) (string, bool) {
	fields := strings.Fields(rule)
	for i, f := range fields {
		if (f == "--dport" || f == "--dports") && i+1 < len(fields) {
			return fields[i+1], true
		}
	}
	return "", false
}

// hasExactDport 报告规则是否含 `--dport <port>` 的精确单端口匹配（非段、非 multiport）。
func hasExactDport(rule, port string) bool {
	fields := strings.Fields(rule)
	for i, f := range fields {
		if f == "--dport" && i+1 < len(fields) {
			return fields[i+1] == port
		}
	}
	return false
}

// portInSpec 判断端口 port 是否落在端口规格 spec 内（逗号分隔，每项为单端口或 lo:hi 段，段端可省略）。
func portInSpec(port, spec string) bool {
	target, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if loStr, hiStr, isRange := strings.Cut(part, ":"); isRange {
			lo, hi := 0, 65535
			if s := strings.TrimSpace(loStr); s != "" {
				if n, e := strconv.Atoi(s); e == nil {
					lo = n
				} else {
					continue
				}
			}
			if s := strings.TrimSpace(hiStr); s != "" {
				if n, e := strconv.Atoi(s); e == nil {
					hi = n
				} else {
					continue
				}
			}
			if target >= lo && target <= hi {
				return true
			}
			continue
		}
		if n, e := strconv.Atoi(part); e == nil && n == target {
			return true
		}
	}
	return false
}

// quarantinedDenyCount 返回 deny.quarantine 中的规则条数（非空行数），供开机重放判定是否提示 degraded。
// 每次开机都读文件（不依赖迁移是否本次执行）：迁移可能是上次启动完成的，隔离文件此时仍在。
func quarantinedDenyCount() int {
	data, err := os.ReadFile(path.Join(global.Dir.FirewallDir, denyQuarantineFileName))
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func writeChainRules(filePath string, rules []string) error {
	content := ""
	for _, r := range rules {
		content += r + "\n"
	}
	return os.WriteFile(filePath, []byte(content), 0600)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// legacyMigrationPending 报告是否存在"尚未迁移的旧 BASIC 布局"。判据与 migrateLegacyChains 顶部一致：
// 新布局文件已存在 → 已迁移；无任何旧文件 → 全新安装。两者皆否才算待迁移。
// 用于开机流程：升级首启通常是进程重启（/run 引导标记仍在，needInit 为 false），
// 据此强制触发一次重放，避免内核停留旧布局而新代码按新链读写（评审 P1）。
func legacyMigrationPending() bool {
	dir := global.Dir.FirewallDir
	if fileExists(path.Join(dir, iptables.GuardFileName)) {
		return false
	}
	return fileExists(path.Join(dir, iptables.BasicFileName)) ||
		fileExists(path.Join(dir, iptables.BasicBeforeFileName)) ||
		fileExists(path.Join(dir, iptables.BasicAfterFileName))
}

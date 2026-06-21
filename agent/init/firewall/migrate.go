package firewall

import (
	"os"
	"path"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

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
func migrateLegacyChains() {
	dir := global.Dir.FirewallDir
	// 已迁移（新文件已存在）→ 跳过，幂等。
	if fileExists(path.Join(dir, iptables.GuardFileName)) {
		return
	}
	// 无任何旧文件 → 全新安装，无需迁移。
	if !fileExists(path.Join(dir, iptables.BasicFileName)) &&
		!fileExists(path.Join(dir, iptables.BasicBeforeFileName)) &&
		!fileExists(path.Join(dir, iptables.BasicAfterFileName)) {
		return
	}

	global.LOG.Info("[firewall-migrate] migrating legacy BASIC chains to GUARD/DENY/BASELINE/ALLOW/AFTER layout")
	if _, err := firewall.TakeSnapshot("pre-migration"); err != nil {
		global.LOG.Warnf("[firewall-migrate] pre-migration snapshot failed (continuing): %v", err)
	}

	// 按新链聚合转换后的规则行。
	newRules := map[string][]string{
		iptables.Chain1PanelGuard:    {},
		iptables.Chain1PanelDeny:     {},
		iptables.Chain1PanelBaseline: {},
		iptables.Chain1PanelAllow:    {},
		iptables.Chain1PanelAfter:    {},
	}

	classifyLegacyFile(dir, iptables.BasicBeforeFileName, iptables.Chain1PanelBasicBefore, newRules)
	classifyLegacyFile(dir, iptables.BasicFileName, iptables.Chain1PanelBasic, newRules)
	classifyLegacyFile(dir, iptables.BasicAfterFileName, iptables.Chain1PanelBasicAfter, newRules)

	for chain, rules := range newRules {
		if err := writeChainRules(path.Join(dir, iptables.ChainFileName(chain)), rules); err != nil {
			global.LOG.Errorf("[firewall-migrate] write %s failed: %v", chain, err)
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
}

// classifyLegacyFile 读取旧链文件的每条 `-A <oldChain> ...` 规则，按设计 §3.4 step 2 归类到新链。
func classifyLegacyFile(dir, fileName, oldChain string, out map[string][]string) {
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
		out[target] = append(out[target], "-A "+target+" "+rest)
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

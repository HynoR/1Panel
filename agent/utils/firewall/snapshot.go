package firewall

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// 安全栈 L3 的快照与"限定恢复"（设计稿 §3.5）。
//
// 关键约束：快照用 iptables-save 全量留底，但**恢复时只重建 1PANEL_* 链及其 jump**，
// 绝不做全表 iptables-restore——否则会回滚掉窗口期内 Docker/fail2ban 动态新增的规则
// （旧分支注释声称"第三方规则也在快照里不会丢"只对快照之前的规则成立，是错的）。
//
// ⚠️ 本文件是全新代码、边界 case 多（链不存在、jump 重复、位置漂移），按设计要求需人工逐行评审 + 重点单测。

const snapshotKeep = 10

const panelChainPrefix = "1PANEL_"

var baseChainsByTable = map[string][]string{
	// 刻意不含 DOCKER-USER：Docker 防护（1PANEL_DOCKER 链 + DOCKER-USER 跳转 + 持久化文件）与
	// 提交-确认会话/快照完全解耦，统一由 docker.go（persistDocker / LoadDockerRules / EnsureDockerChain，
	// dockerMu 串行）维护。快照恢复既不增删 1PANEL_DOCKER 链内容（applyScoped step2/3 跳过），也不动
	// DOCKER-USER 上的跳转——否则会与巡检/用户操作跨 goroutine 竞争，并可能误删独立维护的容器封禁规则（P1）。
	// 代价：commit-confirm 回滚 / 手动恢复快照不会回滚 Docker 封禁规则，但其本属"只增加拦截"的兜底动作、
	// 不会造成把自己锁在外面，且内核与文件始终一致（不会陈旧复活），可由 Docker 防护页独立管理。
	// 链/基础链不存在时各操作自动 no-op。
	"filter": {"INPUT", "OUTPUT", "FORWARD"},
	"nat":    {"PREROUTING", "POSTROUTING", "OUTPUT"},
}

type SnapshotInfo struct {
	Name      string `json:"name"`
	Tag       string `json:"tag"`
	CreatedAt string `json:"createdAt"`
	HasV6     bool   `json:"hasV6"`
	Size      int64  `json:"size"`
}

func snapshotDir() string {
	return path.Join(global.Dir.FirewallDir, "backup")
}

// TakeSnapshot 全量 iptables-save 留底（v4 + best-effort v6），保留最近 snapshotKeep 份。
func TakeSnapshot(tag string) (string, error) {
	dir := snapshotDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create snapshot dir failed: %w", err)
	}
	ts := time.Now().UTC().Format("20060102150405")
	name := fmt.Sprintf("%s_%s", ts, sanitizeTag(tag))

	v4, err := saveOutput("iptables-save")
	if err != nil {
		return "", fmt.Errorf("iptables-save failed: %w", err)
	}
	if err := os.WriteFile(path.Join(dir, name+".v4"), []byte(v4), 0600); err != nil {
		return "", err
	}
	if cmd.Which("ip6tables-save") {
		if v6, err := saveOutput("ip6tables-save"); err == nil {
			_ = os.WriteFile(path.Join(dir, name+".v6"), []byte(v6), 0600)
		}
	}
	pruneSnapshots()
	global.LOG.Infof("[firewall-snapshot] captured %s", name)
	return name, nil
}

func saveOutput(bin string) (string, error) {
	return cmd.NewCommandMgr(cmd.WithTimeout(60 * time.Second)).RunWithOptionalSudoAndStdout(bin)
}

func sanitizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		tag = "manual"
	}
	tag = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, tag)
	if len(tag) > 32 {
		tag = tag[:32]
	}
	return tag
}

// ListSnapshots 返回快照列表（按时间倒序）。
func ListSnapshots() ([]SnapshotInfo, error) {
	dir := snapshotDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []SnapshotInfo{}, nil
		}
		return nil, err
	}
	seen := make(map[string]*SnapshotInfo)
	for _, e := range entries {
		fileName := e.Name()
		if !strings.HasSuffix(fileName, ".v4") && !strings.HasSuffix(fileName, ".v6") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(fileName, ".v4"), ".v6")
		info := seen[base]
		if info == nil {
			ts, tag := splitSnapshotName(base)
			info = &SnapshotInfo{Name: base, Tag: tag, CreatedAt: ts}
			seen[base] = info
		}
		if strings.HasSuffix(fileName, ".v6") {
			info.HasV6 = true
		}
		if fi, err := e.Info(); err == nil {
			info.Size += fi.Size()
		}
	}
	result := make([]SnapshotInfo, 0, len(seen))
	for _, v := range seen {
		result = append(result, *v)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name > result[j].Name })
	return result, nil
}

func splitSnapshotName(base string) (string, string) {
	if idx := strings.Index(base, "_"); idx > 0 {
		return base[:idx], base[idx+1:]
	}
	return base, ""
}

func pruneSnapshots() {
	list, err := ListSnapshots()
	if err != nil || len(list) <= snapshotKeep {
		return
	}
	for _, item := range list[snapshotKeep:] {
		_ = os.Remove(path.Join(snapshotDir(), item.Name+".v4"))
		_ = os.Remove(path.Join(snapshotDir(), item.Name+".v6"))
	}
}

// RestoreSnapshot 限定恢复 1PANEL_* 链与 jump（v4 + 存在则 v6）。
func RestoreSnapshot(name string) error {
	dir := snapshotDir()
	v4Path := path.Join(dir, name+".v4")
	if _, err := os.Stat(v4Path); err != nil {
		return fmt.Errorf("snapshot %s not found", name)
	}
	if err := restoreScoped(v4Path, "iptables"); err != nil {
		return err
	}
	v6Path := path.Join(dir, name+".v6")
	if _, err := os.Stat(v6Path); err == nil && cmd.Which("ip6tables") {
		if err := restoreScoped(v6Path, "ip6tables"); err != nil {
			global.LOG.Warnf("[firewall-snapshot] restore v6 failed: %v", err)
		}
	}
	global.LOG.Infof("[firewall-snapshot] restored 1PANEL chains from %s", name)
	return nil
}

type savedTable struct {
	chains map[string][][]string // 1PANEL_* chain -> ordered rule arg lists (after "-A chain")
	jumps  map[string][]string   // base chain -> ordered list of 1PANEL_* chains it jumps to
}

// parseSave 解析 iptables-save 输出，按表收集 1PANEL_* 链规则与基础链上的 1PANEL jump。
func parseSave(content string) map[string]*savedTable {
	tables := make(map[string]*savedTable)
	current := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "*") {
			current = strings.TrimPrefix(line, "*")
			if tables[current] == nil {
				tables[current] = &savedTable{chains: map[string][][]string{}, jumps: map[string][]string{}}
			}
			continue
		}
		if current == "" || tables[current] == nil {
			continue
		}
		tbl := tables[current]
		if strings.HasPrefix(line, ":") {
			// 链声明，例如 ":1PANEL_BASIC - [0:0]"
			fields := strings.Fields(line)
			chain := strings.TrimPrefix(fields[0], ":")
			if strings.HasPrefix(chain, panelChainPrefix) {
				if _, ok := tbl.chains[chain]; !ok {
					tbl.chains[chain] = [][]string{}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "-A ") {
			args := tokenize(strings.TrimPrefix(line, "-A "))
			if len(args) < 1 {
				continue
			}
			chain := args[0]
			rest := args[1:]
			if strings.HasPrefix(chain, panelChainPrefix) {
				tbl.chains[chain] = append(tbl.chains[chain], rest)
				continue
			}
			// 基础链上的 1PANEL jump：-A INPUT -j 1PANEL_xxx
			if target := jumpTarget(rest); target != "" {
				tbl.jumps[chain] = append(tbl.jumps[chain], target)
			}
		}
	}
	return tables
}

// jumpTarget 仅认"纯 jump"（恰好 `-j 1PANEL_*`，无其它匹配条件），与 BindChain 写出的形式一致。
// 带额外匹配条件的跳转不认（返回 ""），避免恢复时把它当纯 jump 重插而丢失其匹配条件。
func jumpTarget(rest []string) string {
	if len(rest) == 2 && rest[0] == "-j" && strings.HasPrefix(rest[1], panelChainPrefix) {
		return rest[1]
	}
	return ""
}

func restoreScoped(file, bin string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return applyScoped(parseSave(string(data)), bin)
}

// runScoped 容忍 exit code 1（链/规则已存在或不存在），用于"建链"与尽力而为的解绑/清理。
func runScoped(bin, tab string, args ...string) error {
	full := append([]string{"-t", tab, "-w"}, args...)
	_, err := cmd.NewCommandMgr(cmd.WithTimeout(60*time.Second), cmd.WithIgnoreExist1()).RunWithOptionalSudoAndStdout(bin, full...)
	return err
}

// runScopedStrict 不容忍任何错误，用于恢复的关键步骤（清空链、重放规则、重绑 jump）：
// 这些操作在前序步骤保证链已存在的前提下不应出现"已存在/不存在"的良性 exit 1，
// 因此失败必须上报，避免快照恢复/会话回滚在只完成部分重放后仍返回成功（评审 P1）。
func runScopedStrict(bin, tab string, args ...string) error {
	full := append([]string{"-t", tab, "-w"}, args...)
	_, err := cmd.NewCommandMgr(cmd.WithTimeout(60 * time.Second)).RunWithOptionalSudoAndStdout(bin, full...)
	return err
}

// applyScoped 把解析出的 1PANEL_* 链状态重建到系统（bin = iptables | ip6tables，链表与列举都用同一 bin）：
//  1. 解绑基础链上所有现存 1PANEL jump；
//  2. 重建快照里的每个 1PANEL 链（建链→清空→按序重放规则）；
//  3. 删除当前存在但快照里没有的 1PANEL 链；
//  4. 按快照顺序重新绑定 jump（从位置 1 起递增）。
func applyScoped(tables map[string]*savedTable, bin string) error {
	for tab, bases := range baseChainsByTable {
		tbl := tables[tab]
		// 1. 先解绑所有现存 1PANEL jump（无论快照里有没有），保证顺序可控。
		for _, base := range bases {
			unbindAllPanelJumps(bin, tab, base)
		}
		if tbl == nil {
			continue
		}
		// 2. 重建快照中的 1PANEL 链。
		//    跳过 1PANEL_DOCKER：Docker 防护与会话/快照解耦，其链内容只由 docker.go 维护，
		//    在此重建会与巡检/用户操作跨 goroutine 竞争（dockerMu 覆盖不到本路径），P1/P2。
		for chain, rules := range tbl.chains {
			if chain == iptables.Chain1PanelDocker {
				continue
			}
			_ = runScoped(bin, tab, "-N", chain) // 已存在则忽略（WithIgnoreExist1）
			if err := runScopedStrict(bin, tab, "-F", chain); err != nil {
				return fmt.Errorf("flush chain %s (%s/%s) failed: %w", chain, bin, tab, err)
			}
			for _, rule := range rules {
				if err := runScopedStrict(bin, tab, append([]string{"-A", chain}, rule...)...); err != nil {
					return fmt.Errorf("replay rule in chain %s (%s/%s) failed: %w", chain, bin, tab, err)
				}
			}
		}
		// 3. 删除当前存在但快照里没有的 1PANEL 链。
		//    同样跳过 1PANEL_DOCKER：它由 persistDocker/LoadDockerRules 独立维护，删它会永久丢规则（P1）。
		for _, chain := range listPanelChains(bin, tab) {
			if chain == iptables.Chain1PanelDocker {
				continue
			}
			if _, ok := tbl.chains[chain]; !ok {
				_ = runScoped(bin, tab, "-F", chain)
				_ = runScoped(bin, tab, "-X", chain)
			}
		}
		// 4. 重新绑定 jump（按快照顺序，递增插入）。绑定失败须上报：链已重建但未挂回基础链，
		//    等于恢复未生效（可能仍是危险规则集），不能让上层误判回滚成功（评审 P1）。
		for _, base := range bases {
			pos := 1
			for _, target := range tbl.jumps[base] {
				if err := runScopedStrict(bin, tab, "-I", base, fmt.Sprintf("%d", pos), "-j", target); err != nil {
					return fmt.Errorf("rebind jump %s -> %s (%s/%s) failed: %w", base, target, bin, tab, err)
				}
				pos++
			}
		}
	}
	return nil
}

func unbindAllPanelJumps(bin, tab, base string) {
	for {
		num := findFirstPanelJump(bin, tab, base)
		if num == 0 {
			return
		}
		if err := runScoped(bin, tab, "-D", base, fmt.Sprintf("%d", num)); err != nil {
			return
		}
	}
}

// findFirstPanelJump 返回基础链上第一条"目标列为 1PANEL_* 链"的规则行号（step1 解绑用）。
// 注意与 jumpTarget（step4 重绑用）的非对称：step1 会解绑任意以 1PANEL_* 为目标的跳转
// （含带匹配条件的），而 step4 只重绑"纯 jump"。这是有意的——1Panel 自己只产生纯 jump，
// 故纳管规则可无损往返；step1 顺带清掉手工/第三方加的带条件跳转（不重建）属于清理而非回滚丢失。
func findFirstPanelJump(bin, tab, base string) int {
	out, err := cmd.NewCommandMgr(cmd.WithTimeout(30*time.Second), cmd.WithIgnoreExist1()).
		RunWithOptionalSudoAndStdout(bin, "-t", tab, "-w", "-L", base, "--line-numbers", "-n")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, panelChainPrefix) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// target 列（fields[1]）须是 1PANEL_* 链名（纯 jump）。
		if strings.HasPrefix(fields[1], panelChainPrefix) {
			var num int
			if _, err := fmt.Sscanf(fields[0], "%d", &num); err == nil {
				return num
			}
		}
	}
	return 0
}

func listPanelChains(bin, tab string) []string {
	out, err := cmd.NewCommandMgr(cmd.WithTimeout(30*time.Second), cmd.WithIgnoreExist1()).
		RunWithOptionalSudoAndStdout(bin, "-t", tab, "-w", "-S")
	if err != nil {
		return nil
	}
	var chains []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-N "+panelChainPrefix) {
			chains = append(chains, strings.TrimPrefix(line, "-N "))
		}
	}
	return chains
}

// tokenize 把一行 iptables 规则按空白切分，支持双引号包裹的 comment（含空格）。
func tokenize(s string) []string {
	var tokens []string
	var buf strings.Builder
	inQuote := false
	flush := func() {
		if buf.Len() > 0 {
			tokens = append(tokens, buf.String())
			buf.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			buf.WriteRune(r)
		}
	}
	flush()
	return tokens
}

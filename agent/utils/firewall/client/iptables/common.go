package iptables

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

const (
	Chain1PanelPreRouting  = "1PANEL_PREROUTING"
	Chain1PanelPostRouting = "1PANEL_POSTROUTING"
	Chain1PanelForward     = "1PANEL_FORWARD"
	ChainInput             = "INPUT"
	ChainOutput            = "OUTPUT"
	Chain1PanelInput       = "1PANEL_INPUT"
	Chain1PanelOutput      = "1PANEL_OUTPUT"

	// 旧布局（保留供升级迁移读取，迁移完成后两个版本清理，修 C6/C9）。
	Chain1PanelBasicBefore = "1PANEL_BASIC_BEFORE"
	Chain1PanelBasic       = "1PANEL_BASIC"
	Chain1PanelBasicAfter  = "1PANEL_BASIC_AFTER"

	// 新布局（设计稿 §3.4）：INPUT 固定 6 个 jump，序号即真理。
	//   1 GUARD    lo / ESTABLISHED / caller-IP 紧急放行
	//   2 DENY     用户全部 drop/reject 规则（黑名单先于端口放行 → 根治 #12897）
	//   3 BASELINE SSH + 面板端口 ACCEPT（不可移除）
	//   4 ALLOW    用户 accept 规则 + 端口白名单（80/443 默认在此，可删）
	//   5 1PANEL_INPUT  高级过滤（可选 bind）
	//   6 AFTER    严格模式 DROP all
	Chain1PanelGuard    = "1PANEL_GUARD"
	Chain1PanelDeny     = "1PANEL_DENY"
	Chain1PanelBaseline = "1PANEL_BASELINE"
	Chain1PanelAllow    = "1PANEL_ALLOW"
	Chain1PanelAfter    = "1PANEL_AFTER"

	// Docker 防护（PR-6）：与防火墙模式正交，挂在 Docker 的 DOCKER-USER 链下。
	Chain1PanelDocker = "1PANEL_DOCKER"
	ChainDockerUser   = "DOCKER-USER"
)

const (
	EstablishedRule = "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment \"ESTABLISHED Whitelist\""
	IoRuleIn        = "-i lo -j ACCEPT -m comment --comment \"Loopback Whitelist\""
	DropAllTcp      = "-p tcp -j DROP"
	DropAllUdp      = "-p udp -j DROP"
	AllowSSH        = "-p tcp --dport ssh -j ACCEPT"
)

const (
	ACCEPT   = "ACCEPT"
	DROP     = "DROP"
	REJECT   = "REJECT"
	ANYWHERE = "anywhere"
)

const (
	FilterTab = "filter"
	NatTab    = "nat"
)

const (
	binIptables  = "iptables"
	binIP6tables = "ip6tables"
)

// runBin 执行 <bin> -t <tab> [-w] <args...>（bin = iptables | ip6tables），v4/v6 共用的底层实现。
func runBin(bin, tab string, ignoreExist1, withWait bool, ruleArgs ...string) (string, error) {
	options := []cmd.Option{cmd.WithTimeout(60 * time.Second)}
	if ignoreExist1 {
		options = append(options, cmd.WithIgnoreExist1())
	}
	cmdMgr := cmd.NewCommandMgr(options...)
	args := []string{"-t", tab}
	if withWait {
		args = append(args, "-w")
	}
	args = append(args, ruleArgs...)
	return cmdMgr.RunWithOptionalSudoAndStdout(bin, args...)
}

// runFor 返回对应地址族的带日志执行函数（iptables → Run，ip6tables → Run6）。
func runFor(bin string) func(tab string, args ...string) error {
	if bin == binIP6tables {
		return Run6
	}
	return Run
}

// ClearConntrack 在系统存在 conntrack 工具时清掉某源的现存连接，使新加的黑名单/封禁立即生效（conntrack 处理双栈，设计稿 §3.4）。
func ClearConntrack(ip string) {
	if !cmd.Which("conntrack") {
		return
	}
	if err := cmd.NewCommandMgr(cmd.WithTimeout(20*time.Second)).RunWithOptionalSudo("conntrack", "-D", "-s", ip); err != nil {
		global.LOG.Debugf("conntrack -D -s %s returned: %v", ip, err)
	}
}

func RunWithStd(tab string, args ...string) (string, error) {
	stdout, err := runBin(binIptables, tab, true, true, args...)
	if err != nil {
		global.LOG.Errorf("iptables command failed [table=%s, args=%s]: %v", tab, strings.Join(args, " "), err)
		return stdout, err
	}
	return stdout, nil
}
func RunWithoutIgnore(tab string, args ...string) (string, error) {
	return runBin(binIptables, tab, false, false, args...)
}
func Run(tab string, args ...string) error {
	if _, err := RunWithStd(tab, args...); err != nil {
		return err
	}
	return nil
}

func NewChain(tab, chain string) error {
	return Run(tab, "-N", chain)
}

func ClearChain(tab, chain string) error {
	return Run(tab, "-F", chain)
}

func AddRule(tab, chain string, ruleArgs ...string) error {
	if CheckRuleExist(tab, chain, ruleArgs...) {
		return nil
	}
	args := append([]string{"-A", chain}, ruleArgs...)
	return Run(tab, args...)
}
func DeleteRule(tab, chain string, ruleArgs ...string) error {
	args := append([]string{"-D", chain}, ruleArgs...)
	return Run(tab, args...)
}

func CheckChainExist(tab, chain string) (bool, error) {
	stdout, err := RunWithStd(tab, "-S")
	if err != nil {
		global.LOG.Errorf("check chain %s from tab %s exist failed, err: %v", chain, tab, err)
		return false, fmt.Errorf("check chain %s from tab %s exist failed, err: %v", chain, tab, err)
	}
	return chainExistsIn(stdout, chain), nil
}

// chainExistsIn 判断 `-S` 输出中是否含有链声明 "-N <chain>"（v4/v6 共用解析）。
func chainExistsIn(stdout, chain string) bool {
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) == "-N "+chain {
			return true
		}
	}
	return false
}
func CheckChainBind(tab, parentChain, chain string) (bool, error) {
	stdout, err := RunWithStd(tab, "-S", parentChain)
	if err != nil {
		global.LOG.Errorf("check chain %s from tab %s is bind to %s failed, err: %v", chain, tab, parentChain, err)
		return false, fmt.Errorf("check chain %s from tab %s is bind to %s failed, err: %v", chain, tab, parentChain, err)
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "-j "+chain) {
			return true, nil
		}
	}
	return false, nil
}
func CheckRuleExist(tab, chain string, ruleArgs ...string) bool {
	args := append([]string{"-C", chain}, ruleArgs...)
	_, err := RunWithoutIgnore(tab, args...)
	return err == nil
}

func AddChain(tab, chain string) error {
	exists, err := CheckChainExist(tab, chain)
	if err != nil {
		return fmt.Errorf("check chain %s exist from tab %s failed, err: %w", chain, tab, err)
	}
	if !exists {
		if err := NewChain(tab, chain); err != nil {
			return fmt.Errorf("add chain %s for tab %s failed, err: %w", tab, chain, err)
		}
	}
	return nil
}
func BindChain(tab, targetChain, chain string, position int) error {
	line, err := FindChainNum(tab, targetChain, chain)
	if err != nil {
		return fmt.Errorf("find chain %s number from %s failed, err: %w", chain, targetChain, err)
	}
	if line == 0 {
		if err := Run(tab, "-I", targetChain, strconv.Itoa(position), "-j", chain); err != nil {
			return fmt.Errorf("bind chain %s to %s failed, err: %w", chain, targetChain, err)
		}
	}
	return nil
}
func UnbindChain(tab, targetChain, chain string) error {
	line, err := FindChainNum(tab, targetChain, chain)
	if err != nil {
		return fmt.Errorf("find chain %s number from %s failed, err: %w", chain, targetChain, err)
	}
	if line != 0 {
		return Run(tab, "-D", targetChain, strconv.Itoa(line))
	}
	return nil
}

func FindChainNum(tab, targetChain, chain string) (int, error) {
	cmdMgr := cmd.NewCommandMgr(cmd.WithIgnoreExist1(), cmd.WithTimeout(60*time.Second))
	commandName, commandArgs := cmd.WrapWithOptionalSudo("iptables", "-w", "-t", tab, "-L", targetChain, "--line-numbers", "-n")
	stdout, err := cmdMgr.RunPipe(
		cmd.PipeCommand{Name: commandName, Args: commandArgs},
		cmd.PipeCommand{Name: "grep", Args: []string{"-w", chain}},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to list rules in chain %s: %w", targetChain, err)
	}

	lineItem := strings.TrimSpace(stdout)
	lines := strings.Split(lineItem, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == chain {
			itemNum, err := strconv.Atoi(fields[0])
			return itemNum, err
		}
	}
	return 0, nil
}

// findJumpLine 返回 targetChain 中第一条"目标列匹配 match"的规则行号（-L --line-numbers 解析，0 表示没有）。
func findJumpLine(bin, tab, targetChain string, match func(target string) bool) int {
	out, err := runBin(bin, tab, true, true, "-L", targetChain, "--line-numbers", "-n")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if match(fields[1]) {
			num, _ := strconv.Atoi(fields[0])
			return num
		}
	}
	return 0
}

// unbindChainAll 循环解绑 targetChain 上全部跳向 chain 的 jump（处理重复绑定，最多 16 次）。
func unbindChainAll(bin, tab, targetChain, chain string) {
	run := runFor(bin)
	for i := 0; i < 16; i++ {
		num := findJumpLine(bin, tab, targetChain, func(target string) bool { return target == chain })
		if num == 0 {
			return
		}
		if err := run(tab, "-D", targetChain, strconv.Itoa(num)); err != nil {
			return
		}
	}
}

// UnbindChainAll 解绑 targetChain 上全部跳向 chain 的 jump（v4，语义与 UnbindChain6 对齐）。
func UnbindChainAll(tab, targetChain, chain string) {
	unbindChainAll(binIptables, tab, targetChain, chain)
}

// InsertChain 在 targetChain 的 position 处插入跳转到 chain（不去重，调用方负责先解绑）。
func InsertChain(tab, targetChain, chain string, position int) error {
	return Run(tab, "-I", targetChain, strconv.Itoa(position), "-j", chain)
}

// UnbindMatchingJumps 循环解绑 targetChain 上所有"目标列以 prefix 开头"的 jump
// （-L --line-numbers 解析 → -D <num>，bin = iptables | ip6tables，失败即停止）。
func UnbindMatchingJumps(bin, tab, targetChain, prefix string) {
	for {
		num := findJumpLine(bin, tab, targetChain, func(target string) bool { return strings.HasPrefix(target, prefix) })
		if num == 0 {
			return
		}
		if _, err := runBin(bin, tab, true, true, "-D", targetChain, strconv.Itoa(num)); err != nil {
			return
		}
	}
}

// ListChainsByPrefix 列出某表中链名以 prefix 开头的全部自定义链（bin = iptables | ip6tables）。
func ListChainsByPrefix(bin, tab, prefix string) []string {
	out, err := runBin(bin, tab, true, true, "-S")
	if err != nil {
		return nil
	}
	var chains []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-N "+prefix) {
			chains = append(chains, strings.TrimPrefix(line, "-N "))
		}
	}
	return chains
}

func AddChainWithAppend(tab, parentChain, chain string) error {
	exists, err := CheckChainExist(tab, chain)
	if err != nil {
		return fmt.Errorf("failed to check chain %s: %w", chain, err)
	}
	if !exists {
		if err := NewChain(tab, chain); err != nil {
			return fmt.Errorf("failed to create chain %s: %w", chain, err)
		}
	}
	isBind, err := CheckChainBind(tab, parentChain, chain)
	if err != nil {
		return fmt.Errorf("check chain %s bind to %s failed, err: %w", parentChain, chain, err)
	}
	if !isBind {
		if err := AppendChain(tab, parentChain, chain); err != nil {
			return fmt.Errorf("failed to append %s to %s: %w", chain, parentChain, err)
		}
	}
	return nil
}
func AppendChain(tab string, parentChain, chain string) error {
	return Run(tab, "-A", parentChain, "-j", chain)
}

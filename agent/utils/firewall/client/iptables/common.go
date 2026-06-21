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

// BaseChainOrder 是新布局在 INPUT 中的固定顺序（不含可选的 1PANEL_INPUT 高级链）。
// bind 后须按此顺序回读断言（修 C9 的链顺序错乱）。
var BaseChainOrder = []string{
	Chain1PanelGuard,
	Chain1PanelDeny,
	Chain1PanelBaseline,
	Chain1PanelAllow,
}

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

func runIptables(tab string, ignoreExist1, withWait bool, ruleArgs ...string) (string, error) {
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
	return cmdMgr.RunWithOptionalSudoAndStdout("iptables", args...)
}

func RunWithStd(tab string, args ...string) (string, error) {
	stdout, err := runIptables(tab, true, true, args...)
	if err != nil {
		global.LOG.Errorf("iptables command failed [table=%s, args=%s]: %v", tab, strings.Join(args, " "), err)
		return stdout, err
	}
	return stdout, nil
}
func RunWithoutIgnore(tab string, args ...string) (string, error) {
	stdout, err := runIptables(tab, false, false, args...)
	if err != nil {
		return stdout, err
	}
	return stdout, nil
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
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) == "-N "+chain {
			return true, nil
		}
	}
	return false, nil
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

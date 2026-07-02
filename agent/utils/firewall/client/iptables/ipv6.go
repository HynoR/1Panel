package iptables

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// ip6tables 镜像层（设计稿 §3.7）：managed 模式下对 both/ipv6 规则镜像写 ip6tables 同名链。
// inet 族天然双栈是 nftables 的事；iptables 模式只能 v4/v6 双写。
// v6 持久化文件 = 对应 v4 文件名 + ".v6" 后缀，开机分别重放。

var (
	has6Once   sync.Once
	has6Cached bool
)

// HasIP6tables 报告系统是否可用 ip6tables（进程内缓存：ip6tables 是否存在在进程生命周期内不变，
// 避免每条端口/IP 规则都 LookPath 一次——该函数在热路径上被调用 20 余处）。
func HasIP6tables() bool {
	has6Once.Do(func() {
		has6Cached = cmd.Which("ip6tables")
		global.LOG.Infof("[firewall] ip6tables available: %v", has6Cached)
	})
	return has6Cached
}

func run6(tab string, args ...string) (string, error) {
	full := append([]string{"-t", tab, "-w"}, args...)
	return cmd.NewCommandMgr(cmd.WithTimeout(60*time.Second), cmd.WithIgnoreExist1()).RunWithOptionalSudoAndStdout("ip6tables", full...)
}

func Run6(tab string, args ...string) error {
	if _, err := run6(tab, args...); err != nil {
		global.LOG.Errorf("ip6tables command failed [table=%s, args=%s]: %v", tab, strings.Join(args, " "), err)
		return err
	}
	return nil
}

func CheckChainExist6(tab, chain string) bool {
	out, err := run6(tab, "-S")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "-N "+chain {
			return true
		}
	}
	return false
}

func AddChain6(tab, chain string) error {
	if CheckChainExist6(tab, chain) {
		return nil
	}
	return Run6(tab, "-N", chain)
}

func ClearChain6(tab, chain string) error {
	return Run6(tab, "-F", chain)
}

func CheckRuleExist6(tab, chain string, ruleArgs ...string) bool {
	args := append([]string{"-C", chain}, ruleArgs...)
	full := append([]string{"-t", tab, "-w"}, args...)
	_, err := cmd.NewCommandMgr(cmd.WithTimeout(60*time.Second)).RunWithOptionalSudoAndStdout("ip6tables", full...)
	return err == nil
}

func AddRule6(tab, chain string, ruleArgs ...string) error {
	if CheckRuleExist6(tab, chain, ruleArgs...) {
		return nil
	}
	return Run6(tab, append([]string{"-A", chain}, ruleArgs...)...)
}

func DeleteRule6(tab, chain string, ruleArgs ...string) error {
	return Run6(tab, append([]string{"-D", chain}, ruleArgs...)...)
}

func FindChainNum6(tab, targetChain, chain string) int {
	out, err := run6(tab, "-L", targetChain, "--line-numbers", "-n")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[1] == chain {
			num, _ := strconv.Atoi(fields[0])
			return num
		}
	}
	return 0
}

func UnbindChain6(tab, targetChain, chain string) {
	for i := 0; i < 16; i++ {
		num := FindChainNum6(tab, targetChain, chain)
		if num == 0 {
			return
		}
		if err := Run6(tab, "-D", targetChain, strconv.Itoa(num)); err != nil {
			return
		}
	}
}

// InsertChain6 在 targetChain 的 position 处插入跳转到 chain（不去重，调用方负责先解绑）。
func InsertChain6(tab, targetChain, chain string, position int) error {
	return Run6(tab, "-I", targetChain, strconv.Itoa(position), "-j", chain)
}

func SaveRulesToFile6(tab, chain, fileName string) error {
	rulesFile := path.Join(global.Dir.FirewallDir, fileName+".v6")
	out, err := run6(tab, "-S", chain)
	if err != nil {
		return fmt.Errorf("failed to list ip6tables %s rules: %w", chain, err)
	}
	var rules []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, fmt.Sprintf("-A %s", chain)) {
			rules = append(rules, line)
		}
	}
	content := strings.Join(rules, "\n")
	if len(rules) > 0 {
		content += "\n"
	}
	return os.WriteFile(rulesFile, []byte(content), 0644)
}

func LoadRulesFromFile6(tab, chain, fileName string) error {
	if err := AddChain6(tab, chain); err != nil {
		return err
	}
	rulesFile := path.Join(global.Dir.FirewallDir, fileName+".v6")
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return nil
	}
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return err
	}
	_ = ClearChain6(tab, chain)
	for _, rule := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(rule, fmt.Sprintf("-A %s", chain)) {
			continue
		}
		restoreInput := fmt.Sprintf("*%s\n%s\nCOMMIT\n", tab, rule)
		commandName, commandArgs := cmd.WrapWithOptionalSudo("ip6tables-restore", "-n")
		if _, err := cmd.NewCommandMgr().RunPipe(cmd.PipeCommand{
			Name:  commandName,
			Args:  commandArgs,
			Stdin: bytes.NewReader([]byte(restoreInput)),
		}); err != nil {
			global.LOG.Errorf("apply ip6tables rule '%s' failed, err: %v", rule, err)
		}
	}
	return nil
}

// ReadFilterRulesByChain6 读取某 v6 链的规则（复用 v4 的解析助手，family=ipv6）。
func ReadFilterRulesByChain6(chain string) ([]FilterRules, error) {
	var rules []FilterRules
	if cmd.CheckIllegal(chain) {
		return rules, nil
	}
	out, err := run6(FilterTab, "-nL", chain)
	if err != nil {
		return rules, err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		strategy := strings.ToLower(fields[0])
		if strategy != "accept" && strategy != "drop" && strategy != "reject" {
			continue
		}
		rules = append(rules, FilterRules{
			Chain:    chain,
			Protocol: loadProtocol(fields[1]),
			SrcPort:  loadPort("src", fields),
			DstPort:  loadPort("dst", fields),
			SrcIP:    loadIP(fields[3]),
			DstIP:    loadIP(fields[4]),
			Strategy: strategy,
		})
	}
	return rules, nil
}

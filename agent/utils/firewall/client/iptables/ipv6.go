package iptables

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// ip6tables 镜像层（设计稿 §3.7）：managed 模式下对 both/ipv6 规则镜像写 ip6tables 同名链。
// 本文件只保留 v6 薄封装，底层实现按 bin 参数化在 common.go / persistence.go / filter.go 中复用。
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

// run6 与 v4 的差异（有意保留）：始终带 -w 且容忍 exit 1（WithIgnoreExist1），
// 而 v4 侧 CheckRuleExist 走 RunWithoutIgnore（不带 -w、不容忍 exit 1）。
func run6(tab string, args ...string) (string, error) {
	return runBin(binIP6tables, tab, true, true, args...)
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
	return chainExistsIn(out, chain)
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
	_, err := runBin(binIP6tables, tab, false, true, append([]string{"-C", chain}, ruleArgs...)...)
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

// FindChainNum6 与 v4 FindChainNum 的差异（有意保留）：返回裸 int 并吞掉错误。
func FindChainNum6(tab, targetChain, chain string) int {
	return findJumpLine(binIP6tables, tab, targetChain, func(target string) bool { return target == chain })
}

func UnbindChain6(tab, targetChain, chain string) {
	unbindChainAll(binIP6tables, tab, targetChain, chain)
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
	return writeChainRules(out, chain, rulesFile)
}

func LoadRulesFromFile6(tab, chain, fileName string) error {
	if err := AddChain6(tab, chain); err != nil {
		return err
	}
	return replayRulesFromFile(binIP6tables, tab, chain, path.Join(global.Dir.FirewallDir, fileName+".v6"))
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
	return parseFilterRules(chain, out), nil
}

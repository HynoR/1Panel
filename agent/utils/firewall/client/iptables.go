package client

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/buserr"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

type Iptables struct{}

func NewIptables() (*Iptables, error) {
	return &Iptables{}, nil
}

func (i *Iptables) Name() string {
	return "iptables"
}

func (i *Iptables) Status() (bool, error) {
	stdout, err := cmd.NewCommandMgr(cmd.WithTimeout(20*time.Second)).RunWithStdout("iptables", "-L", "-n")
	if err != nil {
		return false, err
	}
	firstLine := strings.Split(strings.TrimSpace(stdout), "\n")[0]
	return strings.Contains(firstLine, "Chain"), nil
}

func (i *Iptables) Start() error {
	return nil
}

func (i *Iptables) Stop() error {
	return nil
}

func (i *Iptables) Restart() error {
	return nil
}

func (i *Iptables) Reload() error {
	return nil
}

func (i *Iptables) Version() (string, error) {
	stdout, err := cmd.NewCommandMgr(cmd.WithTimeout(20*time.Second)).RunWithStdout("iptables", "--version")
	if err != nil {
		return "", fmt.Errorf("failed to get iptables version: %w", err)
	}
	parts := strings.Fields(stdout)
	if len(parts) >= 2 {
		return strings.TrimPrefix(parts[1], "v"), nil
	}
	return strings.TrimSpace(stdout), nil
}

func (i *Iptables) ListPort() ([]FireInfo, error) {
	// 新布局：端口规则散落在 DENY(黑名单)、BASELINE(保底)、ALLOW(放行/白名单) 三条链。
	if _, err := iptables.ReadFilterRulesByChain(iptables.Chain1PanelDeny); err != nil {
		return nil, err
	}
	chains := []string{iptables.Chain1PanelDeny, iptables.Chain1PanelBaseline, iptables.Chain1PanelAllow}
	var datas []FireInfo
	idx := map[string]int{}
	appendPortRules(&datas, idx, iptables.ReadFilterRulesByChain, chains, "ipv4")
	if iptables.HasIP6tables() {
		appendPortRules(&datas, idx, iptables.ReadFilterRulesByChain6, chains, "ipv6")
	}
	return datas, nil
}

func (i *Iptables) ListAddress() ([]FireInfo, error) {
	// 新布局：IP 规则在 DENY(黑名单) 与 ALLOW(白名单) 两条链。
	if _, err := iptables.ReadFilterRulesByChain(iptables.Chain1PanelDeny); err != nil {
		return nil, err
	}
	chains := []string{iptables.Chain1PanelDeny, iptables.Chain1PanelAllow}
	var datas []FireInfo
	idx := map[string]int{}
	appendAddressRules(&datas, idx, iptables.ReadFilterRulesByChain, chains, "ipv4")
	if iptables.HasIP6tables() {
		appendAddressRules(&datas, idx, iptables.ReadFilterRulesByChain6, chains, "ipv6")
	}
	return datas, nil
}

// appendPortRules 合并多条链的端口规则；v4/v6 同一条语义规则合并为 family=both（保持 v4 出现顺序）。
func appendPortRules(out *[]FireInfo, idx map[string]int, reader func(string) ([]iptables.FilterRules, error), chains []string, family string) {
	for _, chain := range chains {
		rules, _ := reader(chain)
		for _, item := range rules {
			if len(item.DstPort) == 0 {
				continue
			}
			strategy := item.Strategy
			if strategy == "drop" || strategy == "reject" {
				strategy = "drop"
			}
			key := item.DstPort + "|" + item.Protocol + "|" + strategy + "|" + item.SrcIP
			if i, ok := idx[key]; ok {
				(*out)[i].Family = combineFamily((*out)[i].Family, family)
				continue
			}
			idx[key] = len(*out)
			*out = append(*out, FireInfo{Chain: item.Chain, Address: item.SrcIP, Protocol: item.Protocol, Port: item.DstPort, Strategy: strategy, Family: family})
		}
	}
}

func appendAddressRules(out *[]FireInfo, idx map[string]int, reader func(string) ([]iptables.FilterRules, error), chains []string, family string) {
	for _, chain := range chains {
		rules, _ := reader(chain)
		for _, item := range rules {
			if len(item.DstPort) != 0 || len(item.SrcPort) != 0 {
				continue
			}
			strategy := item.Strategy
			if strategy == "drop" || strategy == "reject" {
				strategy = "drop"
			}
			key := strategy + "|" + item.SrcIP
			if i, ok := idx[key]; ok {
				(*out)[i].Family = combineFamily((*out)[i].Family, family)
				continue
			}
			idx[key] = len(*out)
			*out = append(*out, FireInfo{Address: item.SrcIP, Strategy: strategy, Family: family})
		}
	}
}

func combineFamily(a, b string) string {
	if a == b {
		return a
	}
	return "both"
}

func (i *Iptables) Port(port FireInfo, operation string) error {
	if operation != "add" && operation != "remove" {
		return buserr.New("ErrCmdIllegal")
	}
	if len(port.Chain) == 0 {
		// accept → ALLOW；drop/reject → DENY（黑名单先于放行，修 C6）。
		port.Chain = iptables.Chain1PanelAllow
		if port.Strategy == "drop" || port.Strategy == "reject" {
			port.Chain = iptables.Chain1PanelDeny
		}
	}

	portSpec, err := normalizePortSpec(port.Port)
	if err != nil {
		return err
	}

	protocol := port.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	action := "ACCEPT"
	if port.Strategy == "drop" {
		action = "DROP"
	}

	ruleArgs := []string{"-p", protocol, "--dport", portSpec, "-j", action}
	name := iptables.ChainFileName(port.Chain)
	// 端口规则默认双栈（family 空=both）；镜像写 ip6tables 同名链（修 C7）。
	doV4, doV6 := familyTargets(port.Family)
	if doV4 {
		if operation == "add" {
			if err := iptables.AddRule(iptables.FilterTab, port.Chain, ruleArgs...); err != nil {
				return err
			}
		} else if err := iptables.DeleteRule(iptables.FilterTab, port.Chain, ruleArgs...); err != nil {
			return err
		}
		if err := iptables.SaveRulesToFile(iptables.FilterTab, port.Chain, name); err != nil {
			global.LOG.Errorf("persistence for %s failed, err: %v", port.Chain, err)
		}
	}
	if doV6 && iptables.HasIP6tables() {
		if operation == "add" {
			if err := iptables.AddRule6(iptables.FilterTab, port.Chain, ruleArgs...); err != nil {
				return err
			}
		} else if err := iptables.DeleteRule6(iptables.FilterTab, port.Chain, ruleArgs...); err != nil {
			return err
		}
		if err := iptables.SaveRulesToFile6(iptables.FilterTab, port.Chain, name); err != nil {
			global.LOG.Errorf("v6 persistence for %s failed, err: %v", port.Chain, err)
		}
	}
	return nil
}

// familyTargets 把 family 字段映射为 (写 v4, 写 v6)。空 → both。
func familyTargets(family string) (bool, bool) {
	switch family {
	case "ipv4":
		return true, false
	case "ipv6":
		return false, true
	default:
		return true, true
	}
}

func (i *Iptables) RichRules(rule FireInfo, operation string) error {
	if operation != "add" && operation != "remove" {
		return buserr.New("ErrCmdIllegal")
	}
	if len(rule.Chain) == 0 {
		// accept → ALLOW；drop/reject → DENY（黑名单先于放行，修 C6）。
		rule.Chain = iptables.Chain1PanelAllow
		if rule.Strategy == "drop" || rule.Strategy == "reject" {
			rule.Chain = iptables.Chain1PanelDeny
		}
	}

	address := strings.TrimSpace(rule.Address)
	if strings.EqualFold(address, "Anywhere") {
		address = ""
	}

	action := "ACCEPT"
	if rule.Strategy == "drop" {
		action = "DROP"
	}

	var ruleArgs []string
	if address != "" {
		ruleArgs = append(ruleArgs, "-s", address)
	}

	protocol := strings.TrimSpace(rule.Protocol)
	if rule.Port != "" && protocol == "" {
		protocol = "tcp"
	}

	if protocol != "" {
		ruleArgs = append(ruleArgs, "-p", protocol)
	}

	if rule.Port != "" {
		portSegment, err := normalizePortSpec(rule.Port)
		if err != nil {
			return err
		}
		if protocol == "" {
			return fmt.Errorf("protocol is required when specifying a port")
		}
		ruleArgs = append(ruleArgs, "--dport", portSegment)
	}

	ruleArgs = append(ruleArgs, "-j", action)
	name := iptables.ChainFileName(rule.Chain)

	// 按地址族判定：有地址按地址族；无地址（纯端口富规则）按 family（默认 both）。
	doV4, doV6 := familyTargets(rule.Family)
	if address != "" {
		if strings.Contains(address, ":") {
			doV4, doV6 = false, true
		} else {
			doV4, doV6 = true, false
		}
	}

	if doV4 {
		if operation == "add" {
			if err := iptables.AddRule(iptables.FilterTab, rule.Chain, ruleArgs...); err != nil {
				return err
			}
		} else if err := iptables.DeleteRule(iptables.FilterTab, rule.Chain, ruleArgs...); err != nil {
			return err
		}
		if err := iptables.SaveRulesToFile(iptables.FilterTab, rule.Chain, name); err != nil {
			global.LOG.Errorf("persistence for %s failed, err: %v", rule.Chain, err)
		}
	}
	if doV6 && iptables.HasIP6tables() {
		if operation == "add" {
			if err := iptables.AddRule6(iptables.FilterTab, rule.Chain, ruleArgs...); err != nil {
				return err
			}
		} else if err := iptables.DeleteRule6(iptables.FilterTab, rule.Chain, ruleArgs...); err != nil {
			return err
		}
		if err := iptables.SaveRulesToFile6(iptables.FilterTab, rule.Chain, name); err != nil {
			global.LOG.Errorf("v6 persistence for %s failed, err: %v", rule.Chain, err)
		}
	}
	// 黑名单立即生效：清掉该源已建立的连接（conntrack 处理双栈）。
	if operation == "add" && action == "DROP" && address != "" {
		clearConntrack(address)
	}
	return nil
}

// clearConntrack 在系统存在 conntrack 工具时清掉某源的现存连接，使新加的黑名单立即生效（设计稿 §3.4）。
func clearConntrack(ip string) {
	if !cmd.Which("conntrack") {
		return
	}
	if err := cmd.NewCommandMgr(cmd.WithTimeout(20*time.Second)).RunWithOptionalSudo("conntrack", "-D", "-s", ip); err != nil {
		global.LOG.Debugf("conntrack -D -s %s returned: %v", ip, err)
	}
}

func (i *Iptables) PortForward(info Forward, operation string) error {
	return iptablesPortForward(info, operation)
}

func (i *Iptables) EnableForward() error {
	return EnableIptablesForward()
}

func (i *Iptables) ListForward() ([]FireInfo, error) {
	return iptablesListForward()
}

func EnableIptablesForward() error {
	if err := cmd.WriteFileWithOptionalSudo("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}
	if data, err := os.ReadFile("/etc/sysctl.conf"); err == nil {
		if !strings.Contains(string(data), "net.ipv4.ip_forward") {
			content := strings.TrimRight(string(data), "\n") + "\nnet.ipv4.ip_forward = 1\n"
			_ = cmd.WriteFileWithOptionalSudo("/etc/sysctl.conf", []byte(content), 0644)
		}
	}
	_ = cmd.NewCommandMgr().RunWithOptionalSudo("sysctl", "-p")

	if err := iptables.AddChainWithAppend(iptables.NatTab, "PREROUTING", iptables.Chain1PanelPreRouting); err != nil {
		return err
	}
	if err := iptables.AddChainWithAppend(iptables.NatTab, "POSTROUTING", iptables.Chain1PanelPostRouting); err != nil {
		return err
	}
	if err := iptables.AddChainWithAppend(iptables.FilterTab, "FORWARD", iptables.Chain1PanelForward); err != nil {
		return err
	}

	return nil
}

func iptablesPortForward(info Forward, operation string) error {
	if operation != "add" && operation != "remove" {
		return buserr.New("ErrCmdIllegal")
	}
	if info.Protocol == "" || info.Port == "" || info.TargetPort == "" {
		return fmt.Errorf("protocol, port, and target port are required")
	}
	if operation == "add" {
		if err := iptables.AddForward(info.Protocol, info.Port, info.TargetIP, info.TargetPort, info.Interface, true); err != nil {
			return err
		}
	} else {
		if err := iptables.DeleteForward(info.Num, info.Protocol, info.Port, info.TargetIP, info.TargetPort, info.Interface); err != nil {
			return err
		}
	}
	forwardPersistence()
	return nil
}

func forwardPersistence() {
	if err := iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelForward, iptables.ForwardFileName); err != nil {
		global.LOG.Errorf("persistence for %s failed, err: %v", iptables.Chain1PanelForward, err)
	}
	if err := iptables.SaveRulesToFile(iptables.NatTab, iptables.Chain1PanelPreRouting, iptables.ForwardFileName1); err != nil {
		global.LOG.Errorf("persistence for %s failed, err: %v", iptables.Chain1PanelPreRouting, err)
	}
	if err := iptables.SaveRulesToFile(iptables.NatTab, iptables.Chain1PanelPostRouting, iptables.ForwardFileName2); err != nil {
		global.LOG.Errorf("persistence for %s failed, err: %v", iptables.Chain1PanelPostRouting, err)
	}
}

func iptablesListForward() ([]FireInfo, error) {
	natList, err := iptables.ListForward(iptables.Chain1PanelPreRouting)
	if err != nil {
		return nil, fmt.Errorf("failed to list NAT rules: %w", err)
	}

	var datas []FireInfo
	for _, nat := range natList {
		datas = append(datas, FireInfo{
			Num:        nat.Num,
			Protocol:   nat.Protocol,
			Port:       strings.TrimPrefix(nat.SrcPort, ":"),
			TargetIP:   nat.Destination,
			TargetPort: strings.TrimPrefix(nat.DestPort, ":"),
			Interface:  nat.InIface,
		})
	}

	return datas, nil
}

func parsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", portStr)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}

func normalizePortSpec(port string) (string, error) {
	value := strings.TrimSpace(port)
	if value == "" {
		return "", fmt.Errorf("port is required")
	}

	separator := ""
	if strings.Contains(value, "-") {
		separator = "-"
	} else if strings.Contains(value, ":") {
		separator = ":"
	}

	if separator != "" {
		parts := strings.Split(value, separator)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid port range: %s", port)
		}
		start, err := parsePort(strings.TrimSpace(parts[0]))
		if err != nil {
			return "", err
		}
		end, err := parsePort(strings.TrimSpace(parts[1]))
		if err != nil {
			return "", err
		}
		if start > end {
			return "", fmt.Errorf("invalid port range: %d-%d", start, end)
		}
		return fmt.Sprintf("%d:%d", start, end), nil
	}

	single, err := parsePort(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", single), nil
}

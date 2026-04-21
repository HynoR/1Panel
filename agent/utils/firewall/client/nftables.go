package client

import (
	"fmt"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/buserr"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/nftables"
)

// Nftables is an opt-in FirewallClient that manages rules via the modern
// nftables backend. The driver mirrors the iptables semantic layer:
// three chains in `inet 1panel` (panel_before / panel_basic / panel_after)
// feed the input hook; a separate `ip 1panel_nat` table carries port
// forwards. IPv4 and IPv6 traffic share the filter chains via the `inet`
// family, so every user rule applies to both unless scoped by address.
//
// The driver never silently wipes the ruleset: the topology is created
// idempotently on Start/Reload, and destructive operations happen through
// nft's native transactional semantics.
type Nftables struct{}

func NewNftables() (*Nftables, error) {
	return &Nftables{}, nil
}

func (n *Nftables) Name() string {
	return "nftables"
}

func (n *Nftables) Version() (string, error) {
	stdout, err := nftables.Run("--version")
	if err != nil {
		return "", fmt.Errorf("load nftables version failed: %w", err)
	}
	parts := strings.Fields(strings.TrimSpace(stdout))
	if len(parts) >= 2 {
		return strings.TrimPrefix(parts[1], "v"), nil
	}
	return strings.TrimSpace(stdout), nil
}

// Status reports whether 1Panel's filter topology exists. Unlike
// firewalld/ufw, nftables has no notion of "service running"; we treat
// "the filter table + input hook are installed" as active.
func (n *Nftables) Status() (bool, error) {
	tableOk, err := nftables.TableExists(nftables.InetFamily, nftables.FilterTable)
	if err != nil {
		return false, err
	}
	if !tableOk {
		return false, nil
	}
	hookOk, err := nftables.ChainExists(nftables.InetFamily, nftables.FilterTable, nftables.ChainInput)
	if err != nil {
		return false, err
	}
	return hookOk, nil
}

// Start provisions the filter topology (table, panel_* chains, input
// hook, chain-jumps) idempotently. Called from OperateFirewall("start")
// as well as lazily before any mutating op, so a fresh host reaches a
// consistent state without a separate init step.
func (n *Nftables) Start() error {
	return n.ensureFilterTopology()
}

func (n *Nftables) Stop() error {
	return nil
}

func (n *Nftables) Restart() error {
	return n.ensureFilterTopology()
}

func (n *Nftables) Reload() error {
	return n.ensureFilterTopology()
}

func (n *Nftables) ensureFilterTopology() error {
	if err := nftables.EnsureTable(nftables.InetFamily, nftables.FilterTable); err != nil {
		return err
	}
	chains := []string{nftables.ChainPanelBefore, nftables.ChainPanelBasic, nftables.ChainPanelAfter}
	for _, ch := range chains {
		if err := nftables.EnsureRegularChain(nftables.InetFamily, nftables.FilterTable, ch); err != nil {
			return err
		}
	}
	if err := nftables.EnsureHookChain(nftables.InetFamily, nftables.FilterTable, nftables.ChainInput, nftables.InetHookInput); err != nil {
		return err
	}
	for _, ch := range chains {
		if err := nftables.AddJump(nftables.InetFamily, nftables.FilterTable, nftables.ChainInput, ch); err != nil {
			return err
		}
	}
	return nil
}

func (n *Nftables) ensureNatTopology() error {
	if err := nftables.EnsureTable(nftables.IPFamily, nftables.NatTable); err != nil {
		return err
	}
	for _, ch := range []string{nftables.ChainPanelPre, nftables.ChainPanelPost} {
		if err := nftables.EnsureRegularChain(nftables.IPFamily, nftables.NatTable, ch); err != nil {
			return err
		}
	}
	if err := nftables.EnsureHookChain(nftables.IPFamily, nftables.NatTable, nftables.ChainPreRouting, nftables.NatHookPre); err != nil {
		return err
	}
	if err := nftables.EnsureHookChain(nftables.IPFamily, nftables.NatTable, nftables.ChainPostRouting, nftables.NatHookPost); err != nil {
		return err
	}
	if err := nftables.AddJump(nftables.IPFamily, nftables.NatTable, nftables.ChainPreRouting, nftables.ChainPanelPre); err != nil {
		return err
	}
	if err := nftables.AddJump(nftables.IPFamily, nftables.NatTable, nftables.ChainPostRouting, nftables.ChainPanelPost); err != nil {
		return err
	}
	return nil
}

// ListPort aggregates port-match rules from panel_before and panel_basic.
// Emergency rules in panel_before (loopback, ESTABLISHED) are filtered out
// by MatchPortRule which only returns tcp/udp dport forms.
func (n *Nftables) ListPort() ([]FireInfo, error) {
	if err := n.ensureFilterTopology(); err != nil {
		return nil, err
	}
	var datas []FireInfo
	for _, chain := range []string{nftables.ChainPanelBasic, nftables.ChainPanelBefore} {
		rules, err := nftables.ListChainRulesWithHandle(nftables.InetFamily, nftables.FilterTable, chain)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			port, ok := nftables.MatchPortRule(r.Body)
			if !ok {
				continue
			}
			strategy := port.Strategy
			if strategy == "reject" {
				strategy = "drop"
			}
			datas = append(datas, FireInfo{
				Address:  port.Address,
				Protocol: port.Protocol,
				Port:     port.Port,
				Strategy: strategy,
				Family:   portFamilyHint(port.Family),
			})
		}
	}
	return datas, nil
}

func (n *Nftables) ListAddress() ([]FireInfo, error) {
	if err := n.ensureFilterTopology(); err != nil {
		return nil, err
	}
	var datas []FireInfo
	rules, err := nftables.ListChainRulesWithHandle(nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBasic)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		addr, ok := nftables.MatchAddressRule(r.Body)
		if !ok {
			continue
		}
		strategy := addr.Strategy
		if strategy == "reject" {
			strategy = "drop"
		}
		datas = append(datas, FireInfo{
			Address:  addr.Address,
			Strategy: strategy,
			Family:   portFamilyHint(addr.Family),
		})
	}
	return datas, nil
}

func (n *Nftables) ListForward() ([]FireInfo, error) {
	if err := n.ensureNatTopology(); err != nil {
		return nil, err
	}
	rules, err := nftables.ListChainRulesWithHandle(nftables.IPFamily, nftables.NatTable, nftables.ChainPanelPre)
	if err != nil {
		return nil, err
	}
	var datas []FireInfo
	for _, r := range rules {
		fwd, ok := nftables.MatchForwardRule(r.Body)
		if !ok {
			continue
		}
		targetIP, targetPort := splitDnatTarget(fwd.Target)
		datas = append(datas, FireInfo{
			Protocol:   fwd.Protocol,
			Port:       fwd.Port,
			TargetIP:   targetIP,
			TargetPort: targetPort,
			Num:        fmt.Sprintf("%d", r.Handle),
		})
	}
	return datas, nil
}

// Port adds or removes a dport match. The chain is always panel_basic
// (user rules); emergency rules go into panel_before via a dedicated
// helper in the init path. Removal locates the existing rule by exact
// body match and deletes it by handle — this sidesteps the need to
// flush-and-rebuild the chain for every edit.
func (n *Nftables) Port(port FireInfo, operation string) error {
	if operation != "add" && operation != "remove" {
		return buserr.New("ErrCmdIllegal")
	}
	if err := n.ensureFilterTopology(); err != nil {
		return err
	}
	protocol := port.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	body, err := nftables.FormatPortRule(protocol, port.Address, port.Port, normStrategy(port.Strategy))
	if err != nil {
		return err
	}
	if operation == "add" {
		if err := nftables.AddRule(nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBasic, body); err != nil {
			return err
		}
		return n.persistFilter()
	}
	if err := n.deleteRuleByBody(nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBasic, body); err != nil {
		return err
	}
	return n.persistFilter()
}

// RichRules handles address-scoped rules. When Port is also provided, the
// rule is delegated through FormatPortRule to keep the "address + port"
// combined form as a single atomic rule — matching what firewalld's rich
// rules express natively.
func (n *Nftables) RichRules(rule FireInfo, operation string) error {
	if operation != "add" && operation != "remove" {
		return buserr.New("ErrCmdIllegal")
	}
	if err := n.ensureFilterTopology(); err != nil {
		return err
	}
	address := strings.TrimSpace(rule.Address)
	if strings.EqualFold(address, "Anywhere") {
		address = ""
	}
	strategy := normStrategy(rule.Strategy)

	var body string
	var err error
	if strings.TrimSpace(rule.Port) != "" {
		protocol := rule.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		body, err = nftables.FormatPortRule(protocol, address, rule.Port, strategy)
	} else {
		if address == "" {
			return fmt.Errorf("address required for rich rule without port")
		}
		body, err = nftables.FormatAddressRule(address, strategy)
	}
	if err != nil {
		return err
	}

	if operation == "add" {
		if err := nftables.AddRule(nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBasic, body); err != nil {
			return err
		}
		return n.persistFilter()
	}
	if err := n.deleteRuleByBody(nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBasic, body); err != nil {
		return err
	}
	return n.persistFilter()
}

func (n *Nftables) PortForward(info Forward, operation string) error {
	if operation != "add" && operation != "remove" {
		return buserr.New("ErrCmdIllegal")
	}
	if err := n.ensureNatTopology(); err != nil {
		return err
	}
	body, err := nftables.FormatForwardRule(info.Protocol, info.Port, info.TargetIP, info.TargetPort)
	if err != nil {
		return err
	}
	if operation == "add" {
		if err := nftables.AddRule(nftables.IPFamily, nftables.NatTable, nftables.ChainPanelPre, body); err != nil {
			return err
		}
		return n.persistNat()
	}
	if err := n.deleteRuleByBody(nftables.IPFamily, nftables.NatTable, nftables.ChainPanelPre, body); err != nil {
		return err
	}
	return n.persistNat()
}

// EnableForward turns on kernel IP forwarding, builds the NAT topology,
// and ensures a single masquerade rule in panel_post. Mirrors the
// iptables driver's EnableIptablesForward behaviour.
func (n *Nftables) EnableForward() error {
	if err := cmd.RunDefaultBashC("echo 1 > /proc/sys/net/ipv4/ip_forward"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}
	_ = cmd.RunDefaultBashC("grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf || echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf")
	_ = cmd.RunDefaultBashC("sysctl -p")

	if err := n.ensureNatTopology(); err != nil {
		return err
	}

	rules, err := nftables.ListChainRulesWithHandle(nftables.IPFamily, nftables.NatTable, nftables.ChainPanelPost)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if strings.Contains(r.Body, "masquerade") {
			return n.persistNat()
		}
	}
	if err := nftables.AddRule(nftables.IPFamily, nftables.NatTable, nftables.ChainPanelPost, "masquerade"); err != nil {
		return err
	}
	return n.persistNat()
}

func (n *Nftables) persistFilter() error {
	if err := nftables.SaveTable(nftables.InetFamily, nftables.FilterTable, nftables.FilterFileName); err != nil {
		global.LOG.Errorf("persist nft filter table failed: %v", err)
		return nil
	}
	return nil
}

func (n *Nftables) persistNat() error {
	if err := nftables.SaveTable(nftables.IPFamily, nftables.NatTable, nftables.NatFileName); err != nil {
		global.LOG.Errorf("persist nft nat table failed: %v", err)
		return nil
	}
	return nil
}

// deleteRuleByBody locates the first rule whose body exactly matches the
// expected spec (or is a superstring — nft sometimes prints extra
// annotations like `counter packets 0 bytes 0` when counters are
// enabled) and deletes it by handle. Returns nil if no match — matching
// iptables driver behaviour which treats "remove missing rule" as a
// no-op so retries are safe.
func (n *Nftables) deleteRuleByBody(family, table, chain, body string) error {
	rules, err := nftables.ListChainRulesWithHandle(family, table, chain)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if nftables.RuleBodyMatches(r.Body, body) {
			return nftables.DeleteRuleByHandle(family, table, chain, r.Handle)
		}
	}
	return nil
}

func normStrategy(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "accept", "allow":
		return "accept"
	case "drop", "deny":
		return "drop"
	case "reject":
		return "reject"
	}
	return "accept"
}

func portFamilyHint(family string) string {
	switch family {
	case "ip":
		return "ipv4"
	case "ip6":
		return "ipv6"
	}
	return "ipv4"
}

func splitDnatTarget(target string) (string, string) {
	if target == "" {
		return "", ""
	}
	if strings.HasPrefix(target, ":") {
		return "127.0.0.1", strings.TrimPrefix(target, ":")
	}
	idx := strings.LastIndex(target, ":")
	if idx < 0 {
		return target, ""
	}
	return target[:idx], target[idx+1:]
}

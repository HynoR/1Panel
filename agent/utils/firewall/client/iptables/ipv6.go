package iptables

import (
	"fmt"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// IPv6 helpers.
//
// 1Panel's firewall module is IPv4-centric: the 1PANEL_* chain machinery
// lives in iptables only. IPv6 emergency accept rules are therefore injected
// directly at the top of the native ip6tables INPUT chain instead of routing
// them through a 1Panel-managed chain. This keeps the IPv6 footprint tiny
// while still protecting SSH and the panel port in dual-stack deployments.

// HasIPv6Tables reports whether ip6tables is available on the host.
func HasIPv6Tables() bool {
	return cmd.Which("ip6tables")
}

// EnsureIPv6EmergencyAccepts idempotently inserts loopback, ESTABLISHED and
// per-port ACCEPT rules at position 1 of ip6tables INPUT. Rules are inserted
// in reverse order so the final order on INPUT matches the slice order
// (loopback first, then ESTABLISHED, then TCP ports).
//
// No-op when ip6tables is absent from the host.
func EnsureIPv6EmergencyAccepts(sshPort, panelPort string, extraTcpPorts []string) error {
	if !HasIPv6Tables() {
		return nil
	}
	specs := []string{
		"-i lo -j ACCEPT",
		"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	}
	tcpPorts := make([]string, 0, 2+len(extraTcpPorts))
	if sshPort != "" {
		tcpPorts = append(tcpPorts, sshPort)
	}
	if panelPort != "" && panelPort != sshPort {
		tcpPorts = append(tcpPorts, panelPort)
	}
	for _, p := range extraTcpPorts {
		if p == "" {
			continue
		}
		tcpPorts = append(tcpPorts, p)
	}
	for _, p := range tcpPorts {
		specs = append(specs, fmt.Sprintf("-p tcp -m tcp --dport %s -j ACCEPT", p))
	}

	for i := len(specs) - 1; i >= 0; i-- {
		spec := specs[i]
		if check6RuleExist("filter", "INPUT", spec) {
			continue
		}
		if err := run6("filter", fmt.Sprintf("-I INPUT 1 %s", spec)); err != nil {
			return fmt.Errorf("inject ipv6 emergency %q failed: %w", spec, err)
		}
	}
	return nil
}

// VerifyIPv6EmergencyAccepts returns an error if any of the emergency rules
// generated for (sshPort, panelPort, extraTcpPorts) are missing from ip6tables
// INPUT. Returns nil when ip6tables is absent — the host is effectively IPv4
// only and there is nothing to protect.
func VerifyIPv6EmergencyAccepts(sshPort, panelPort string, extraTcpPorts []string) error {
	if !HasIPv6Tables() {
		return nil
	}
	specs := []string{
		"-i lo -j ACCEPT",
		"-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	}
	tcpPorts := make([]string, 0, 2+len(extraTcpPorts))
	if sshPort != "" {
		tcpPorts = append(tcpPorts, sshPort)
	}
	if panelPort != "" && panelPort != sshPort {
		tcpPorts = append(tcpPorts, panelPort)
	}
	for _, p := range extraTcpPorts {
		if p == "" {
			continue
		}
		tcpPorts = append(tcpPorts, p)
	}
	for _, p := range tcpPorts {
		specs = append(specs, fmt.Sprintf("-p tcp -m tcp --dport %s -j ACCEPT", p))
	}
	for _, spec := range specs {
		if !check6RuleExist("filter", "INPUT", spec) {
			return fmt.Errorf("ipv6 emergency rule %q missing from INPUT", spec)
		}
	}
	return nil
}

func run6(tab, rule string) error {
	_, err := runWithStd6(tab, rule)
	return err
}

func runWithStd6(tab, rule string) (string, error) {
	cmdMgr := cmd.NewCommandMgr(cmd.WithIgnoreExist1(), cmd.WithTimeout(60*time.Second))
	stdout, err := cmdMgr.RunWithStdoutBashCf("%s ip6tables -w -t %s %s", cmd.SudoHandleCmd(), tab, rule)
	if err != nil {
		global.LOG.Errorf("ip6tables command failed [table=%s, rule=%s]: %v", tab, rule, err)
		return stdout, err
	}
	return stdout, nil
}

func runWithoutIgnore6(tab, rule string) (string, error) {
	cmdMgr := cmd.NewCommandMgr(cmd.WithTimeout(60 * time.Second))
	stdout, err := cmdMgr.RunWithStdoutBashCf("%s ip6tables -t %s %s", cmd.SudoHandleCmd(), tab, rule)
	if err != nil {
		return stdout, err
	}
	return stdout, nil
}

func check6RuleExist(tab, chain, rule string) bool {
	_, err := runWithoutIgnore6(tab, fmt.Sprintf("-C %s %s", chain, rule))
	return err == nil
}

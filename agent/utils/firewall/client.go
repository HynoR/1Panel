package firewall

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
)

// ProviderIptables / ProviderNftables are the valid FirewallProvider
// setting values aside from the empty "auto" string. They are exported
// so API handlers can reference the same names the persistence layer
// writes.
const (
	ProviderIptables = "iptables"
	ProviderNftables = "nftables"
	ProviderUfw      = "ufw"
	ProviderFirewalld = "firewalld"
)

type FirewallClient interface {
	Name() string // ufw firewalld
	Start() error
	Stop() error
	Restart() error
	Reload() error
	Status() (bool, error)
	Version() (string, error)

	ListPort() ([]client.FireInfo, error)
	ListForward() ([]client.FireInfo, error)
	ListAddress() ([]client.FireInfo, error)

	Port(port client.FireInfo, operation string) error
	RichRules(rule client.FireInfo, operation string) error
	PortForward(info client.Forward, operation string) error

	EnableForward() error
}

// NewFirewallClient returns the active firewall driver. Selection logic:
//
//  1. System firewalls take precedence: firewalld wins over ufw, and the
//     two refuse to coexist (per the upstream conflict rule).
//  2. When neither is installed, 1Panel manages the rules itself. The
//     backend is chosen from the persisted `FirewallProvider` setting:
//     iptables or nftables. Unset / unknown values fall through to the
//     default order.
//  3. Default order is iptables-first: existing installations must not
//     flip to nftables silently, and operators who want the newer
//     backend can opt in explicitly once iptables is not yet initialised.
//
// The function never panics; unreachable branches return an explicit
// error that the UI surfaces as "firewall unavailable".
func NewFirewallClient() (FirewallClient, error) {
	firewalld := cmd.Which("firewalld")
	ufw := cmd.Which("ufw")

	if firewalld && ufw {
		return nil, errors.New("It is detected that the system has both firewalld and ufw services. To avoid conflicts, please uninstall and try again!")
	}
	if firewalld {
		return client.NewFirewalld()
	}
	if ufw {
		return client.NewUfw()
	}

	iptablesAvailable := cmd.Which("iptables")
	nftablesAvailable := cmd.Which("nft")

	pref := LoadPreferredProvider()
	switch pref {
	case ProviderNftables:
		if nftablesAvailable {
			return client.NewNftables()
		}
		if iptablesAvailable {
			return client.NewIptables()
		}
		return nil, errors.New("FirewallProvider=nftables but nft binary is missing and no fallback is available")
	case ProviderIptables:
		if iptablesAvailable {
			return client.NewIptables()
		}
		if nftablesAvailable {
			return client.NewNftables()
		}
		return nil, errors.New("FirewallProvider=iptables but the iptables binary is missing and no fallback is available")
	}

	if iptablesAvailable {
		return client.NewIptables()
	}
	if nftablesAvailable {
		return client.NewNftables()
	}
	return nil, errors.New("No system firewall service detected (firewalld/ufw/iptables/nftables), please check and try again!")
}

// LoadPreferredProvider reads the persisted `FirewallProvider` setting.
// Returns "" when the setting is absent, invalid, or points at a value
// that only makes sense as an auto-detected native firewall
// (firewalld / ufw are not accepted as preferences because they are
// mutually exclusive with 1Panel's managed backends).
func LoadPreferredProvider() string {
	if global.DB == nil {
		return ""
	}
	var row struct {
		Value string
	}
	if err := global.DB.Table("settings").Select("value").Where("key = ?", "FirewallProvider").Limit(1).Scan(&row).Error; err != nil {
		return ""
	}
	v := strings.ToLower(strings.TrimSpace(row.Value))
	switch v {
	case ProviderIptables, ProviderNftables:
		return v
	}
	return ""
}

// AvailableProviders probes the host for installed backends. The
// returned slice always reflects the order the UI should present:
// already-authoritative native firewalls first, then 1Panel-managed
// backends. Callers use this to render the provider switcher.
type ProviderInfo struct {
	Name          string `json:"name"`
	Available     bool   `json:"available"`
	IsCurrent     bool   `json:"isCurrent"`
	IsInitialized bool   `json:"isInitialized"`
	Version       string `json:"version"`
}

// AvailableProviders returns one ProviderInfo per candidate backend on
// the host. `isCurrent` marks the backend that NewFirewallClient would
// pick right now. `isInitialized` is only populated for the managed
// backends (iptables / nftables) and indicates whether 1Panel has
// already taken over rule management — a switcher should refuse to
// change away from an initialised backend without an explicit confirm.
func AvailableProviders() []ProviderInfo {
	currentName := ""
	if c, err := NewFirewallClient(); err == nil {
		currentName = c.Name()
	}
	iptablesInit := iptablesInitialized()
	nftablesInit := nftablesInitialized()

	out := []ProviderInfo{
		{Name: ProviderFirewalld, Available: cmd.Which("firewalld"), IsCurrent: currentName == ProviderFirewalld},
		{Name: ProviderUfw, Available: cmd.Which("ufw"), IsCurrent: currentName == ProviderUfw},
		{Name: ProviderIptables, Available: cmd.Which("iptables"), IsCurrent: currentName == ProviderIptables, IsInitialized: iptablesInit},
		{Name: ProviderNftables, Available: cmd.Which("nft"), IsCurrent: currentName == ProviderNftables, IsInitialized: nftablesInit},
	}
	return out
}

// iptablesInitialized returns true when 1Panel's filter chains are live
// (either the DB flag says so, or the chain is actually bound to INPUT).
// The DB flag is authoritative but we cross-check the kernel in case a
// stale setting was left behind by an uninstall.
func iptablesInitialized() bool {
	if global.DB == nil {
		return false
	}
	var row struct {
		Value string
	}
	_ = global.DB.Table("settings").Select("value").Where("key = ?", "IptablesStatus").Limit(1).Scan(&row).Error
	if row.Value == constant.StatusEnable {
		return true
	}
	return iptablesChainBound("1PANEL_BASIC")
}

// nftablesInitialized returns true when the inet 1panel table and its
// input hook chain exist.
func nftablesInitialized() bool {
	if !cmd.Which("nft") {
		return false
	}
	if _, err := cmd.RunDefaultWithStdoutBashCf("%s nft list table inet 1panel", cmd.SudoHandleCmd()); err != nil {
		return false
	}
	if _, err := cmd.RunDefaultWithStdoutBashCf("%s nft list chain inet 1panel input", cmd.SudoHandleCmd()); err != nil {
		return false
	}
	return true
}

// iptablesChainBound returns true when `chain` appears as a jump target
// under the native INPUT chain. Used only to double-check the settings
// row against observed kernel state — do not rely on it for authoritative
// "initialised" decisions.
func iptablesChainBound(chain string) bool {
	stdout, err := cmd.RunDefaultWithStdoutBashCf("%s iptables -w -t filter -S INPUT", cmd.SudoHandleCmd())
	if err != nil {
		return false
	}
	needle := fmt.Sprintf("-j %s", chain)
	return strings.Contains(stdout, needle)
}

// SetPreferredProvider writes the preference to the settings table.
// The caller is responsible for any migration side-effects (topology
// teardown, snapshot capture) before flipping the flag; this helper
// is write-only.
func SetPreferredProvider(pref string) error {
	switch pref {
	case "", ProviderIptables, ProviderNftables:
	default:
		return fmt.Errorf("invalid firewall provider %q", pref)
	}
	if global.DB == nil {
		return errors.New("database is not initialised")
	}
	return global.DB.Exec(
		"INSERT INTO settings(key, value) VALUES('FirewallProvider', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		pref,
	).Error
}

func LoadPingStatus() string {
	data, err := os.ReadFile("/proc/sys/net/ipv4/icmp_echo_ignore_all")
	if err != nil {
		return constant.StatusNone
	}
	v6Data, v6err := os.ReadFile("/proc/sys/net/ipv6/icmp/echo_ignore_all")
	if v6err != nil {
		if strings.TrimSpace(string(data)) == "1" {
			return constant.StatusEnable
		}
		return constant.StatusDisable
	} else {
		if strings.TrimSpace(string(data)) == "1" && strings.TrimSpace(string(v6Data)) == "1" {
			return constant.StatusEnable
		}
		return constant.StatusDisable
	}
}

func UpdatePingStatus(enable string) error {
	const confPath = "/etc/sysctl.conf"
	const panelSysctlPath = "/etc/sysctl.d/98-onepanel.conf"

	var targetPath string
	var applyCmd string

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		targetPath = panelSysctlPath
		applyCmd = fmt.Sprintf("%s sysctl --system", cmd.SudoHandleCmd())
		if err := cmd.RunDefaultBashCf("%s mkdir -p /etc/sysctl.d", cmd.SudoHandleCmd()); err != nil {
			return fmt.Errorf("failed to create directory /etc/sysctl.d: %v", err)
		}
	} else {
		targetPath = confPath
		applyCmd = fmt.Sprintf("%s sysctl -p", cmd.SudoHandleCmd())
	}

	lineBytes, err := os.ReadFile(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %v", targetPath, err)
	}

	if err := cmd.RunDefaultBashCf("echo %s | %s tee /proc/sys/net/ipv4/icmp_echo_ignore_all > /dev/null", enable, cmd.SudoHandleCmd()); err != nil {
		return fmt.Errorf("failed to apply ipv4 ping status temporarily: %v", err)
	}

	var hasIpv6 bool
	if _, err := os.Stat("/proc/sys/net/ipv6/icmp/echo_ignore_all"); err == nil {
		hasIpv6 = true
		if err := cmd.RunDefaultBashCf("echo %s | %s tee /proc/sys/net/ipv6/icmp/echo_ignore_all > /dev/null", enable, cmd.SudoHandleCmd()); err != nil {
			global.LOG.Warnf("failed to apply ipv6 ping status temporarily: %v", err)
		}
	}

	var files []string
	if err == nil {
		files = strings.Split(string(lineBytes), "\n")
	}

	var newFiles []string
	hasIPv4Line, hasIPv6Line := false, false

	for _, line := range files {
		if strings.HasPrefix(strings.TrimSpace(line), "net.ipv4.icmp_echo_ignore_all") {
			newFiles = append(newFiles, "net.ipv4.icmp_echo_ignore_all="+enable)
			hasIPv4Line = true
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "net.ipv6.icmp.echo_ignore_all") {
			newFiles = append(newFiles, "net.ipv6.icmp.echo_ignore_all="+enable)
			hasIPv6Line = true
			continue
		}
		newFiles = append(newFiles, line)
	}

	if !hasIPv4Line {
		newFiles = append(newFiles, "net.ipv4.icmp_echo_ignore_all="+enable)
	}
	if hasIpv6 && !hasIPv6Line {
		newFiles = append(newFiles, "net.ipv6.icmp.echo_ignore_all="+enable)
	}

	file, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, constant.FilePerm)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", targetPath, err)
	}
	defer file.Close()

	if _, err = file.WriteString(strings.Join(newFiles, "\n")); err != nil {
		return fmt.Errorf("failed to write to %s: %v", targetPath, err)
	}

	if err := cmd.RunDefaultBashC(applyCmd); err != nil {
		global.LOG.Warnf("failed to apply persistent config with '%s': %v", applyCmd, err)
	}

	return nil
}

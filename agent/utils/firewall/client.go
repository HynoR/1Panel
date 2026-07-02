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

// NewFirewallClient 是所有"操作型"调用的入口：返回当前选定 driver。
// 它复用 Detect() 的缓存探测（修 C12），并在 ufw+firewalld 同时运行时拒绝执行（修 C11）。
// 只读型/展示型调用（如 LoadBaseInfo）应直接用 Detect()，以便在冲突时仍能返回基础信息。
func NewFirewallClient() (FirewallClient, error) {
	provider, err := Detect()
	if err != nil {
		return nil, err
	}
	if provider.Conflict().HasConflict {
		return nil, errors.New(provider.Conflict().Message)
	}
	return provider.Client(), nil
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
	applyArgs := []string{"-p"}

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		targetPath = panelSysctlPath
		applyArgs = []string{"--system"}
		if err := cmd.NewCommandMgr().RunWithOptionalSudo("mkdir", "-p", "/etc/sysctl.d"); err != nil {
			return fmt.Errorf("failed to create directory /etc/sysctl.d: %v", err)
		}
	} else {
		targetPath = confPath
	}

	lineBytes, err := os.ReadFile(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %v", targetPath, err)
	}

	if err := cmd.WriteFileWithOptionalSudo("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte(enable), constant.FilePerm); err != nil {
		return fmt.Errorf("failed to apply ipv4 ping status temporarily: %v", err)
	}

	var hasIpv6 bool
	if _, err := os.Stat("/proc/sys/net/ipv6/icmp/echo_ignore_all"); err == nil {
		hasIpv6 = true
		if err := cmd.WriteFileWithOptionalSudo("/proc/sys/net/ipv6/icmp/echo_ignore_all", []byte(enable), constant.FilePerm); err != nil {
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

	if err = cmd.WriteFileWithOptionalSudo(targetPath, []byte(strings.Join(newFiles, "\n")), constant.FilePerm); err != nil {
		return fmt.Errorf("failed to write to %s: %v", targetPath, err)
	}

	if err := cmd.NewCommandMgr().RunWithOptionalSudo("sysctl", applyArgs...); err != nil {
		global.LOG.Warnf("failed to apply persistent config: %v", err)
	}

	return nil
}

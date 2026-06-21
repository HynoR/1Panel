package firewall

import (
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// Docker 边界防护（设计稿 §3.6，修 C8 —— "防火墙形同虚设"最大来源 #726/#12471）。
//
// Docker 通过 FORWARD/DOCKER 链直接放行映射端口，面板的 INPUT 规则拦不住。解法：在 Docker 的
// DOCKER-USER 链最前面挂一条跳到 1PANEL_DOCKER 的规则，把封禁写进 1PANEL_DOCKER。
// DOCKER-USER 中的流量已经过 DNAT，端口防护必须用 conntrack 还原原始目的端口。
//
// 与防火墙模式正交：只要检测到 DOCKER-USER 链存在（Docker 的 iptables 集成开启）即可用。

// DockerProtectionAvailable 报告 Docker iptables 集成是否开启（DOCKER-USER 链存在）。
func DockerProtectionAvailable() bool {
	exist, _ := iptables.CheckChainExist(iptables.FilterTab, iptables.ChainDockerUser)
	return exist
}

// EnsureDockerChain 确保 1PANEL_DOCKER 链存在，且 DOCKER-USER 第一条规则跳向它。
// Docker 重启会重建 DOCKER-USER，故开机、每分钟巡检、每次操作都重新断言这个 jump。
func EnsureDockerChain() {
	if !DockerProtectionAvailable() {
		return
	}
	if err := iptables.AddChain(iptables.FilterTab, iptables.Chain1PanelDocker); err != nil {
		global.LOG.Warnf("[firewall-docker] create 1PANEL_DOCKER failed: %v", err)
		return
	}
	num, _ := iptables.FindChainNum(iptables.FilterTab, iptables.ChainDockerUser, iptables.Chain1PanelDocker)
	if num == 1 {
		return
	}
	if num > 1 {
		_ = iptables.Run(iptables.FilterTab, "-D", iptables.ChainDockerUser, strconv.Itoa(num))
	}
	if err := iptables.Run(iptables.FilterTab, "-I", iptables.ChainDockerUser, "1", "-j", iptables.Chain1PanelDocker); err != nil {
		global.LOG.Warnf("[firewall-docker] bind 1PANEL_DOCKER to DOCKER-USER failed: %v", err)
	}
}

// ApplyDockerIPRule 在 1PANEL_DOCKER 中按源 IP 封禁/解封（对应"同时拦截 Docker 端口流量"勾选）。
func ApplyDockerIPRule(ip, operation string) error {
	if !DockerProtectionAvailable() {
		return nil
	}
	EnsureDockerChain()
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	args := []string{"-s", ip, "-j", "DROP"}
	if operation == "add" {
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelDocker, args...); err != nil {
			return err
		}
		clearConntrack(ip)
	} else {
		if err := iptables.DeleteRule(iptables.FilterTab, iptables.Chain1PanelDocker, args...); err != nil {
			return err
		}
	}
	return persistDocker()
}

// ApplyDockerPortRule 在 1PANEL_DOCKER 中按"原始目的端口"封禁容器发布端口（用 conntrack 还原 DNAT 前的端口）。
// srcException 非空时附带源限定（只对该源生效）。
func ApplyDockerPortRule(port, protocol, srcException, operation string) error {
	if !DockerProtectionAvailable() {
		return nil
	}
	EnsureDockerChain()
	port = strings.TrimSpace(port)
	if port == "" {
		return nil
	}
	if protocol == "" {
		protocol = "tcp"
	}
	args := []string{}
	if srcException != "" {
		args = append(args, "-s", srcException)
	}
	args = append(args, "-p", protocol, "-m", "conntrack", "--ctorigdstport", port, "--ctdir", "ORIGINAL", "-j", "DROP")
	if operation == "add" {
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelDocker, args...); err != nil {
			return err
		}
	} else {
		if err := iptables.DeleteRule(iptables.FilterTab, iptables.Chain1PanelDocker, args...); err != nil {
			return err
		}
	}
	return persistDocker()
}

// DockerRule 是 1PANEL_DOCKER 中一条已纳管规则的展示形态。
type DockerRule struct {
	Address  string `json:"address"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Strategy string `json:"strategy"`
}

// DockerStatus 返回 Docker 防护可用性与已纳管规则（供 /firewall/docker/status）。
func DockerStatus() (bool, []DockerRule) {
	if !DockerProtectionAvailable() {
		return false, nil
	}
	rules, err := iptables.ReadFilterRulesByChain(iptables.Chain1PanelDocker)
	if err != nil {
		return true, nil
	}
	var out []DockerRule
	for _, item := range rules {
		strategy := item.Strategy
		if strategy == "reject" {
			strategy = "drop"
		}
		out = append(out, DockerRule{
			Address:  item.SrcIP,
			Port:     item.DstPort,
			Protocol: item.Protocol,
			Strategy: strategy,
		})
	}
	return true, out
}

// LoadDockerRules 开机重放 1PANEL_DOCKER 规则并重新断言 DOCKER-USER jump。
func LoadDockerRules() {
	if !DockerProtectionAvailable() {
		return
	}
	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelDocker, iptables.DockerFileName); err != nil {
		global.LOG.Warnf("[firewall-docker] load docker rules failed: %v", err)
	}
	EnsureDockerChain()
}

func persistDocker() error {
	return iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelDocker, iptables.DockerFileName)
}

// clearConntrack 清掉某源的现存连接，使 Docker 封禁立即生效（conntrack 处理双栈）。
func clearConntrack(ip string) {
	if !cmd.Which("conntrack") {
		return
	}
	if err := cmd.NewCommandMgr(cmd.WithTimeout(20*time.Second)).RunWithOptionalSudo("conntrack", "-D", "-s", ip); err != nil {
		global.LOG.Debugf("conntrack -D -s %s returned: %v", ip, err)
	}
}

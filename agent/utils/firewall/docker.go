package firewall

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// dockerReplayPending 标记开机时因 Docker 尚未就绪而未能重放 1panel_docker.rules。
// 巡检 goroutine 在 Docker 就绪后据此补做一次重放，避免"Docker 比 agent 晚启动 → 容器封禁规则丢失"（P1）。
var dockerReplayPending atomic.Bool

// dockerMu 串行化对 1PANEL_DOCKER 的所有变更（用户增删+持久化、开机/巡检重放的清空+重放），
// 避免巡检的 LoadDockerRules（-F 清空后重放旧文件）与并发的用户 AddRule+persist 交错，
// 导致刚加的规则既不在内核也不在文件中而静默丢失（P3）。EnsureDockerChain 为内部 helper，
// 仅在已持锁路径中调用，自身不再加锁（非可重入）。
var dockerMu sync.Mutex

// Docker 防护当前仅支持 IPv4（DOCKER-USER 走 iptables）。v6 地址不喂给 v4 iptables（否则报错且 UI 误报已拦截）。

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
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	// Docker 防护仅 v4：v6 地址不喂给 v4 iptables（INPUT 侧的 v6 封禁仍由 RichRules→ip6tables 生效）。
	if isIPv6(ip) {
		global.LOG.Debugf("[firewall-docker] skip ipv6 address %s (docker protection is ipv4-only)", ip)
		return nil
	}
	dockerMu.Lock()
	defer dockerMu.Unlock()
	args := []string{"-s", ip, "-j", "DROP"}
	if operation == "add" {
		EnsureDockerChain()
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelDocker, args...); err != nil {
			return err
		}
		iptables.ClearConntrack(ip)
		return persistDocker()
	}
	// 幂等删除：链不存在或规则不存在则视为无事可做（不报错、不建空链）。
	if exist, _ := iptables.CheckChainExist(iptables.FilterTab, iptables.Chain1PanelDocker); !exist {
		return nil
	}
	if iptables.CheckRuleExist(iptables.FilterTab, iptables.Chain1PanelDocker, args...) {
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
	port = strings.TrimSpace(port)
	if port == "" {
		return nil
	}
	// Docker 防护仅 v4：带 v6 源限定的端口规则不喂给 v4 iptables。
	if srcException != "" && isIPv6(srcException) {
		global.LOG.Debugf("[firewall-docker] skip ipv6 source %s (docker protection is ipv4-only)", srcException)
		return nil
	}
	dockerMu.Lock()
	defer dockerMu.Unlock()
	if protocol == "" {
		protocol = "tcp"
	}
	args := []string{}
	if srcException != "" {
		args = append(args, "-s", srcException)
	}
	args = append(args, "-p", protocol, "-m", "conntrack", "--ctorigdstport", port, "--ctdir", "ORIGINAL", "-j", "DROP")
	if operation == "add" {
		EnsureDockerChain()
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelDocker, args...); err != nil {
			return err
		}
		return persistDocker()
	}
	// 幂等删除：链不存在或规则不存在则视为无事可做。
	if exist, _ := iptables.CheckChainExist(iptables.FilterTab, iptables.Chain1PanelDocker); !exist {
		return nil
	}
	if iptables.CheckRuleExist(iptables.FilterTab, iptables.Chain1PanelDocker, args...) {
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
// 若 Docker 尚未就绪（DOCKER-USER 不存在），标记 pending，待巡检在 Docker 起来后补做重放，
// 避免"Docker 比 agent 晚启动 → 已持久化的容器封禁规则在重启后静默丢失"（P1）。
func LoadDockerRules() {
	if !DockerProtectionAvailable() {
		dockerReplayPending.Store(true)
		return
	}
	dockerMu.Lock()
	defer dockerMu.Unlock()
	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelDocker, iptables.DockerFileName); err != nil {
		global.LOG.Warnf("[firewall-docker] load docker rules failed: %v", err)
	}
	EnsureDockerChain()
	dockerReplayPending.Store(false)
}

// ReconcileDockerChain 供每分钟巡检调用：若开机重放仍未完成（Docker 后启动），就在 Docker 就绪后补做一次完整重放；
// 否则只重新断言 DOCKER-USER 上的 jump（Docker 重启会清掉它，但 1PANEL_DOCKER 链内容仍在内核中）。
func ReconcileDockerChain() {
	if dockerReplayPending.Load() {
		LoadDockerRules() // 自带加锁
		return
	}
	dockerMu.Lock()
	EnsureDockerChain()
	dockerMu.Unlock()
}

func persistDocker() error {
	return iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelDocker, iptables.DockerFileName)
}

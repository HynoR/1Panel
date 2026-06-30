package firewall

import (
	"net"
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
	// add 需要 Docker 集成就绪（DOCKER-USER 存在）才能落地；remove 即使 Docker 暂时停机也要继续——
	// 1PANEL_DOCKER 链内容在 Docker 停机期间仍驻留内核，须删规则并重写持久化文件，否则 Docker 恢复后
	// LoadDockerRules 会重放陈旧 DROP（评审 P2）。链不存在时下方删除分支幂等 no-op。
	if operation == "add" && !DockerProtectionAvailable() {
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
	// add 需要 Docker 集成就绪才能落地；remove 即使 Docker 暂时停机也要继续清理内核链与持久化文件，
	// 避免 Docker 恢复后重放陈旧 DROP（评审 P2）。链不存在时下方删除分支幂等 no-op。
	if operation == "add" && !DockerProtectionAvailable() {
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

// DockerStatus 返回 Docker 防护可用性与已纳管规则（供 /firewall/docker/status 与列表 applyToDocker 回显）。
// 用 `iptables -S 1PANEL_DOCKER` 解析规则规格：端口规则走 conntrack `--ctorigdstport`，`iptables -nL` 的 dpt:
// 解析拿不到该字段（loadPort 只认 dpt:/spt:），会导致端口规则的 Port 恒为空、前端永远匹配不上（item1）。
func DockerStatus() (bool, []DockerRule) {
	if !DockerProtectionAvailable() {
		return false, nil
	}
	out, err := iptables.RunWithStd(iptables.FilterTab, "-S", iptables.Chain1PanelDocker)
	if err != nil {
		return true, nil
	}
	prefix := "-A " + iptables.Chain1PanelDocker + " "
	var rules []DockerRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		r := parseDockerRuleSpec(strings.TrimPrefix(line, prefix))
		if r.Strategy == "" {
			continue
		}
		rules = append(rules, r)
	}
	return true, rules
}

// parseDockerRuleSpec 从 `iptables -S` 的规则规格中提取 -s/-p/--ctorigdstport/-j。
func parseDockerRuleSpec(spec string) DockerRule {
	var r DockerRule
	tokens := strings.Fields(spec)
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "-s":
			if i+1 < len(tokens) {
				r.Address = tokens[i+1]
				i++
			}
		case "-p":
			if i+1 < len(tokens) {
				r.Protocol = strings.ToLower(tokens[i+1])
				i++
			}
		case "--ctorigdstport":
			if i+1 < len(tokens) {
				r.Port = strings.ReplaceAll(tokens[i+1], ":", "-")
				i++
			}
		case "-j":
			if i+1 < len(tokens) {
				strategy := strings.ToLower(tokens[i+1])
				if strategy == "reject" {
					strategy = "drop"
				}
				r.Strategy = strategy
				i++
			}
		}
	}
	return r
}

// IsDockerProtected 判断一条 port/address 规则是否已落地到 1PANEL_DOCKER（供列表回显 applyToDocker）。
// port 规则按 port+protocol+strategy+归一化地址 匹配；address 规则按 address+strategy 匹配（仅匹配端口为空的纯地址 docker 规则）。
// 归一化 Anywhere/空源/0.0.0.0/0 为同一 v4 任意源；v6 任意源/地址不匹配（Docker 防护仅 v4）。
func IsDockerProtected(ruleType, port, protocol, strategy, address string, dockerRules []DockerRule) bool {
	if len(dockerRules) == 0 {
		return false
	}
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy != "drop" && strategy != "reject" {
		return false
	}
	strategy = "drop"
	normAddr := normDockerAddr(address)
	if ruleType == "address" {
		for _, r := range dockerRules {
			if r.Port != "" || r.Protocol != "" {
				continue
			}
			if strings.EqualFold(r.Strategy, strategy) && normDockerAddr(r.Address) == normAddr {
				return true
			}
		}
		return false
	}
	protos := dockerPortProtocols(protocol)
	portNorm := normDockerPort(port)
	if len(protos) == 0 || portNorm == "" {
		return false
	}
	for _, proto := range protos {
		found := false
		for _, r := range dockerRules {
			if !strings.EqualFold(r.Strategy, strategy) {
				continue
			}
			if normDockerPort(r.Port) != portNorm {
				continue
			}
			if !strings.EqualFold(r.Protocol, proto) {
				continue
			}
			if normDockerAddr(r.Address) != normAddr {
				continue
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

// dockerPortProtocols 把端口规则的 protocol 字段展开为需要逐一命中 docker 链的协议集合（tcp/udp → [tcp,udp]）。
func dockerPortProtocols(protocol string) []string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return nil
	}
	var protos []string
	for _, p := range strings.Split(protocol, "/") {
		p = strings.TrimSpace(p)
		if p == "tcp" || p == "udp" {
			protos = append(protos, p)
		}
	}
	return protos
}

func normDockerPort(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return strings.ReplaceAll(v, ":", "-")
}

// normDockerAddr 归一化源地址用于 docker 匹配：v4 任意源(空/Anywhere/0.0.0.0/0)→""；v6 任意源→独立标记不匹配 v4；CIDR/IP 标准化。
func normDockerAddr(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "0.0.0.0/0" {
		return ""
	}
	if v == "::/0" || strings.HasPrefix(v, "anywhere (v6)") {
		return "v6-anywhere"
	}
	if strings.HasPrefix(v, "anywhere") {
		return ""
	}
	if strings.Contains(v, "/") {
		if _, ipNet, err := net.ParseCIDR(v); err == nil {
			return ipNet.String()
		}
		return v
	}
	if ip := net.ParseIP(v); ip != nil {
		return ip.String()
	}
	return v
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

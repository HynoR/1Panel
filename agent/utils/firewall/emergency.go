package firewall

import (
	"net"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// EnsureInputPolicySafe 实现 L4 ① 的"敌对 policy 双杀"防护（设计稿 §3.5）：
// "不 bind 保命"依赖 INPUT 默认策略为 ACCEPT；若检测到 policy 已被外部置为 DROP，
// 则在中止/继续前先向 INPUT 直接注入 SSH/面板紧急 ACCEPT，杜绝"坏文件 + 敌对 policy"双杀。
func EnsureInputPolicySafe(ports []string) {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !cmd.Which(bin) {
			continue
		}
		out, err := runFirewallBin(bin, "-S", "INPUT")
		if err != nil || !strings.Contains(out, "-P INPUT DROP") {
			continue
		}
		global.LOG.Warnf("[firewall-boot] %s INPUT policy is DROP, injecting direct baseline ACCEPT", bin)
		for _, p := range ports {
			if strings.TrimSpace(p) == "" {
				continue
			}
			if _, err := runFirewallBin(bin, "-I", "INPUT", "1", "-p", "tcp", "--dport", p, "-j", "ACCEPT"); err != nil {
				global.LOG.Warnf("[firewall-boot] inject baseline accept %s failed: %v", p, err)
			}
		}
	}
}

// StartEmergencyJanitor 启动后台巡检 goroutine（开机调用一次）。
func StartEmergencyJanitor() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		// 开机立即巡检一次：首轮从持久化文件重放 1PANEL_DOCKER 并断言 jump（替代原独立的开机重放调用）。
		ReconcileDockerChain()
		for range ticker.C {
			// PR-6：Docker 重启会重建 DOCKER-USER 清掉我们的 jump，每分钟巡检重新断言；
			// 若开机时 Docker 未就绪导致规则未重放，这里在 Docker 起来后补做重放。
			ReconcileDockerChain()
		}
	}()
}

func isIPv6(ip string) bool {
	host := ip
	if strings.Contains(ip, "/") {
		host = strings.SplitN(ip, "/", 2)[0]
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.To4() == nil
}

func runFirewallBin(bin string, args ...string) (string, error) {
	allArgs := append([]string{"-w"}, args...)
	return cmd.NewCommandMgr(cmd.WithTimeout(30*time.Second)).RunWithOptionalSudoAndStdout(bin, allArgs...)
}

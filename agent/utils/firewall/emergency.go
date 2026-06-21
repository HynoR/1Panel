package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// 安全栈 L2（设计稿 §3.5）：变更型 API 给调用方 IP 在 INPUT 顶部插一条 10 分钟临时 ACCEPT，
// 让"误封自己"的人大概率仍能打开面板、看到确认卡片。过期时间编码进规则 comment，
// 因此无需 DB，agent 重启后后台清理仍能识别并回收过期规则。
//
// 注意（设计稿已知限制）：external 模式下 ufw/firewalld reload 会清掉它——这只是兜底而非功能。
// 反代场景下 RemoteAddr 是代理 IP，刻意不信任 X-Forwarded-For（方向正确）。

const (
	emergencyComment = "1PANEL_EMERGENCY"
	emergencyTTL     = 10 * time.Minute
)

// EnsureCallerAccept 为调用方 IP 刷新一条临时 ACCEPT（先删同 IP 旧规则再插新的，等于刷新 TTL）。
// best-effort：任何失败只记日志，不影响业务流程。
func EnsureCallerAccept(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	bin := firewallBin(ip)
	if !cmd.Which(bin) {
		return
	}
	removeEmergencyForIP(bin, ip)
	expiry := time.Now().Add(emergencyTTL).Unix()
	comment := fmt.Sprintf("%s %d", emergencyComment, expiry)
	if _, err := runFirewallBin(bin, "-I", "INPUT", "1", "-s", ip, "-j", "ACCEPT", "-m", "comment", "--comment", comment); err != nil {
		global.LOG.Warnf("[firewall-emergency] ensure caller accept for %s failed: %v", ip, err)
	}
}

// CleanExpiredEmergency 删除所有已过期的临时 ACCEPT（后台每分钟调用一次）。
func CleanExpiredEmergency() {
	now := time.Now().Unix()
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !cmd.Which(bin) {
			continue
		}
		rules := scanEmergency(bin)
		// 倒序删除，避免行号位移。
		for i := len(rules) - 1; i >= 0; i-- {
			if rules[i].expiry <= now {
				if _, err := runFirewallBin(bin, "-D", "INPUT", strconv.Itoa(rules[i].line)); err != nil {
					global.LOG.Warnf("[firewall-emergency] delete expired rule (%s line %d) failed: %v", bin, rules[i].line, err)
				}
			}
		}
	}
}

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

// StartEmergencyJanitor 启动后台清理 goroutine（开机调用一次）。
func StartEmergencyJanitor() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		CleanExpiredEmergency()
		ReconcileDockerChain()
		for range ticker.C {
			CleanExpiredEmergency()
			// PR-6：Docker 重启会重建 DOCKER-USER 清掉我们的 jump，每分钟巡检重新断言；
			// 若开机时 Docker 未就绪导致规则未重放，这里在 Docker 起来后补做重放。
			ReconcileDockerChain()
		}
	}()
}

type emergencyRule struct {
	line   int
	src    string
	expiry int64
}

func scanEmergency(bin string) []emergencyRule {
	out, err := runFirewallBin(bin, "-L", "INPUT", "--line-numbers", "-n")
	if err != nil {
		return nil
	}
	var rules []emergencyRule
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, emergencyComment)
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		num, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		// comment 形如: /* 1PANEL_EMERGENCY 1700000000 */
		expiry := parseEmergencyExpiry(line[idx:])
		src := ""
		// -L -n 的列: num target prot opt source destination ...
		if len(fields) >= 5 {
			src = fields[4]
		}
		rules = append(rules, emergencyRule{line: num, src: src, expiry: expiry})
	}
	return rules
}

func parseEmergencyExpiry(s string) int64 {
	fields := strings.Fields(s)
	// fields[0] == "1PANEL_EMERGENCY", fields[1] == "<unix>"
	if len(fields) >= 2 {
		if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			return v
		}
	}
	return 0
}

func removeEmergencyForIP(bin, ip string) {
	rules := scanEmergency(bin)
	for i := len(rules) - 1; i >= 0; i-- {
		if sameIP(rules[i].src, ip) {
			if _, err := runFirewallBin(bin, "-D", "INPUT", strconv.Itoa(rules[i].line)); err != nil {
				global.LOG.Warnf("[firewall-emergency] remove rule (%s line %d) failed: %v", bin, rules[i].line, err)
			}
		}
	}
}

func sameIP(a, b string) bool {
	a = strings.TrimSuffix(strings.TrimSpace(a), "/32")
	a = strings.TrimSuffix(a, "/128")
	b = strings.TrimSuffix(strings.TrimSpace(b), "/32")
	b = strings.TrimSuffix(b, "/128")
	return a == b
}

func firewallBin(ip string) string {
	if isIPv6(ip) {
		return "ip6tables"
	}
	return "iptables"
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

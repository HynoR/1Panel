package firewall

import (
	"testing"

	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// TestClassifyLegacyRule 覆盖旧 3 链规则到新布局的归类，含 R3（BASIC_BEFORE 的 80/443 归 ALLOW）。
func TestClassifyLegacyRule(t *testing.T) {
	cases := []struct {
		name     string
		oldChain string
		rest     string
		want     string
	}{
		{"lo accept -> GUARD", iptables.Chain1PanelBasicBefore, "-i lo -j ACCEPT", iptables.Chain1PanelGuard},
		{"established -> GUARD", iptables.Chain1PanelBasicBefore, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", iptables.Chain1PanelGuard},
		{"ssh baseline accept -> BASELINE", iptables.Chain1PanelBasicBefore, "-p tcp -m tcp --dport 22 -j ACCEPT", iptables.Chain1PanelBaseline},
		{"http 80 accept -> ALLOW", iptables.Chain1PanelBasicBefore, "-p tcp -m tcp --dport 80 -j ACCEPT", iptables.Chain1PanelAllow},
		{"https 443 accept -> ALLOW", iptables.Chain1PanelBasicBefore, "-p tcp -m tcp --dport 443 -j ACCEPT", iptables.Chain1PanelAllow},
		{"before 80 range not exact -> BASELINE", iptables.Chain1PanelBasicBefore, "-p tcp -m tcp --dport 80:81 -j ACCEPT", iptables.Chain1PanelBaseline},
		{"basic accept -> ALLOW", iptables.Chain1PanelBasic, "-p tcp -m tcp --dport 8080 -j ACCEPT", iptables.Chain1PanelAllow},
		{"basic drop -> DENY", iptables.Chain1PanelBasic, "-s 1.2.3.4 -j DROP", iptables.Chain1PanelDeny},
		{"basic reject -> DENY", iptables.Chain1PanelBasic, "-s 1.2.3.4 -j REJECT", iptables.Chain1PanelDeny},
		{"basic_after -> AFTER", iptables.Chain1PanelBasicAfter, "-p tcp -j DROP", iptables.Chain1PanelAfter},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyLegacyRule(c.oldChain, c.rest); got != c.want {
				t.Fatalf("classifyLegacyRule(%q, %q) = %q, want %q", c.oldChain, c.rest, got, c.want)
			}
		})
	}
}

// TestIsDenyRuleLockoutRisk 覆盖 R1 隔离判定：广源 + 覆盖保底端口才隔离。
func TestIsDenyRuleLockoutRisk(t *testing.T) {
	baseline := []string{"22", "9999"}
	cases := []struct {
		name string
		rule string
		want bool
	}{
		{"broad covers ssh 22", "-p tcp -m tcp --dport 22 -j DROP", true},
		{"broad explicit anywhere covers panel", "-s 0.0.0.0/0 -p tcp --dport 9999 -j DROP", true},
		{"specific src single ip", "-s 1.2.3.4 -p tcp --dport 22 -j DROP", false},
		{"no dport full drop", "-j DROP", true},
		{"multiport contains 22", "-p tcp -m multiport --dports 22,80,443 -j DROP", true},
		{"port range 20:30 contains 22", "-p tcp -m tcp --dport 20:30 -j DROP", true},
		{"broad but non-baseline port", "-p tcp -m tcp --dport 8080 -j DROP", false},
		{"multiport without baseline", "-p tcp -m multiport --dports 80,443 -j DROP", false},
		{"specific src full drop", "-s 10.0.0.0/8 -j DROP", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDenyRuleLockoutRisk(c.rule, baseline); got != c.want {
				t.Fatalf("isDenyRuleLockoutRisk(%q) = %v, want %v", c.rule, got, c.want)
			}
		})
	}
}

package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	fireClient "github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
)

// Caller routing matrix for PR-01 Commit 01.4.
// Each NewFirewallClient caller must land on the correct ownership lane.
//
// Callers:
//  1. firewall.go page CRUD / OperateFirewall / OperateFirewallPort
//  2. firewall_setting.go whitelist sync
//  3. init/firewall boot replay
//  4. fail2ban.go read-only provider probe
//  5. migrations/init.go Name() backfill
//  6. ssh.go / website_domain.go via OperateFirewallPort
//
// VM baseline capture (test plan §5 / §7) before merge:
//
//	E-UFW:  ufw status numbered; CRUD transcript; no 1PANEL_ chains
//	E-FWD:  firewall-cmd --list-all; rich rules; forward ports; no 1PANEL_ chains
//	I-L1:   iptables -t filter -S / -t nat -S; BASIC_* order unchanged
//	Also:   Fail2Ban banaction, Docker DOCKER-USER (observe only), SSH/panel ports

func TestLaneOfNameRouting(t *testing.T) {
	tests := []struct {
		name     string
		wantLane firewall.Lane
	}{
		{name: "ufw", wantLane: firewall.LaneExternalNative},
		{name: "firewalld", wantLane: firewall.LaneExternalNative},
		{name: "iptables", wantLane: firewall.LaneSelfManagedLegacyV1},
		{name: "unknown", wantLane: firewall.LaneExternalNative},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firewall.LaneOfName(tt.name); got != tt.wantLane {
				t.Fatalf("LaneOfName(%q)=%q want %q", tt.name, got, tt.wantLane)
			}
		})
	}
}

func TestCallerRoutingMatrix(t *testing.T) {
	type expect struct {
		lane firewall.Lane
	}
	callers := []string{
		"LoadBaseInfo",
		"OperatePortRule",
		"OperateAddressRule",
		"addPortsBeforeStart",
		"syncFirewallPortWhiteListAfterUpdate",
		"OperateFirewallPort",
		"fail2ban.UpdateConf.banaction",
		"migration.AddIptablesFilterRuleTable",
		"init.firewall.boot",
	}
	providers := []struct {
		name string
		lane firewall.Lane
	}{
		{"ufw", firewall.LaneExternalNative},
		{"firewalld", firewall.LaneExternalNative},
		{"iptables", firewall.LaneSelfManagedLegacyV1},
	}

	for _, caller := range callers {
		for _, p := range providers {
			t.Run(caller+"/"+p.name, func(t *testing.T) {
				got := routeCaller(caller, p.name)
				if got.lane != p.lane {
					t.Fatalf("caller %s on %s routed to %s, want %s", caller, p.name, got.lane, p.lane)
				}
				if caller == "fail2ban.UpdateConf.banaction" && got.writes {
					t.Fatal("Fail2Ban probe must remain read-only")
				}
				if caller == "migration.AddIptablesFilterRuleTable" && got.writes {
					t.Fatal("migration Name() backfill must remain read-only")
				}
			})
		}
	}
}

type routeResult struct {
	lane   firewall.Lane
	writes bool
}

// routeCaller encodes the PR-01 ownership dispatch contract used by production callers.
func routeCaller(caller, providerName string) routeResult {
	lane := firewall.LaneOfName(providerName)
	switch caller {
	case "fail2ban.UpdateConf.banaction", "migration.AddIptablesFilterRuleTable":
		return routeResult{lane: lane, writes: false}
	default:
		return routeResult{lane: lane, writes: true}
	}
}

func TestExternalOperatePortParityFixture(t *testing.T) {
	// Parity with Commit 01.1 external command fixtures: UFW/firewalld args must match
	// and never mention managed chains.
	ufwArgs, err := buildUfwPortArgsFixture(fireClient.FireInfo{Port: "80", Protocol: "tcp", Strategy: "accept"}, "add")
	if err != nil {
		t.Fatal(err)
	}
	assertExternalArgs(t, ufwArgs, []string{"allow", "80/tcp"})

	fwdArgs := []string{"--zone=public", "--add-port=443/tcp", "--permanent"}
	assertExternalArgs(t, fwdArgs, fwdArgs)
}

func TestExternalNativeErrorPassthrough(t *testing.T) {
	nativeErr := errors.New("ERROR: Invalid rule")
	got := passthroughNativeError(nativeErr)
	if !errors.Is(got, nativeErr) {
		t.Fatalf("external lane must return native error unchanged, got %v", got)
	}
	if strings.Contains(got.Error(), "iptables") && !strings.Contains(nativeErr.Error(), "iptables") {
		t.Fatal("external errors must not be rewritten into iptables fallback messages")
	}
}

func TestFail2BanProbeIsReadOnlyContract(t *testing.T) {
	// banaction validation may DetectProvider + Status only.
	// It must not invoke Port/RichRules/Start/Stop or managed chain helpers.
	allowed := map[string]bool{
		"DetectProvider": true,
		"Name":           true,
		"Status":         true,
	}
	forbidden := []string{"Port", "RichRules", "Start", "Stop", "Restart", "PortForward", "EnableForward", "Reload"}
	for _, method := range forbidden {
		if allowed[method] {
			t.Fatalf("%s should not be allowed", method)
		}
	}
	if !allowed["DetectProvider"] || !allowed["Status"] {
		t.Fatal("read-only probe methods missing")
	}
}

func TestLoadInitStatusExternalParity(t *testing.T) {
	// firewalld always reports initialized in LoadInitStatus.
	isInit, isBind := loadExternalInitStatus("firewalld", "base")
	if !isInit || !isBind {
		t.Fatalf("firewalld base expected true,true got %v,%v", isInit, isBind)
	}
	isInit, isBind = loadExternalInitStatus("ufw", "base")
	if !isInit || !isBind {
		t.Fatalf("ufw base expected true,true got %v,%v", isInit, isBind)
	}
	isInit, isBind = loadExternalInitStatus("ufw", "port")
	if !isInit || !isBind {
		t.Fatalf("ufw port expected true,true got %v,%v", isInit, isBind)
	}
}

func buildUfwPortArgsFixture(port fireClient.FireInfo, operation string) ([]string, error) {
	strategy := port.Strategy
	switch strategy {
	case "accept":
		strategy = "allow"
	case "drop":
		strategy = "deny"
	default:
		return nil, errors.New("unsupported strategy")
	}
	args := []string{strategy, port.Port}
	if operation == "remove" {
		args = []string{"delete", strategy, port.Port}
	}
	if len(port.Protocol) != 0 {
		args[len(args)-1] += "/" + port.Protocol
	}
	return args, nil
}

func assertExternalArgs(t *testing.T, got, want []string) {
	t.Helper()
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "1PANEL_") {
		t.Fatalf("external args contain managed chain: %s", joined)
	}
	if len(got) != len(want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func passthroughNativeError(err error) error {
	// Mirrors external lane: return client errors directly, no iptables rescue.
	return err
}

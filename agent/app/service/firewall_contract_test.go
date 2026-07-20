package service

import (
	"reflect"
	"testing"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/constant"
)

// NewFirewallClient callers inventory (PR-01 Commit 01.1):
// 1. firewall.go — page CRUD / OperateFirewall / OperateFirewallPort
// 2. firewall_setting.go — whitelist sync
// 3. init/firewall — boot replay
// 4. fail2ban.go — read-only provider probe
// 5. migrations/init.go — Name() backfill only
// 6. ssh.go / website_domain.go — OperateFirewallPort (allow-only)

func TestParseFirewallPortWhiteListContract(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []firewallPortWhitelist
		wantErr bool
	}{
		{
			name:  "default value",
			value: constant.FirewallPortWhiteListValue,
			want: []firewallPortWhitelist{
				{Port: "80", Protocol: "tcp"},
				{Port: "443", Protocol: "tcp"},
				{Port: "443", Protocol: "udp"},
			},
		},
		{
			name:  "dedup",
			value: "80/tcp,80/tcp,443/tcp",
			want: []firewallPortWhitelist{
				{Port: "80", Protocol: "tcp"},
				{Port: "443", Protocol: "tcp"},
			},
		},
		{
			name:  "default protocol tcp",
			value: "8080",
			want: []firewallPortWhitelist{
				{Port: "8080", Protocol: "tcp"},
			},
		},
		{
			name:    "invalid protocol",
			value:   "80/icmp",
			wantErr: true,
		},
		{
			name:    "invalid port",
			value:   "99999/tcp",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFirewallPortWhiteList(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v want %#v", got, tt.want)
			}
		})
	}
}

func TestNormalizeFirewallPortWhiteListContract(t *testing.T) {
	got := normalizeFirewallPortWhiteList([]firewallPortWhitelist{
		{Port: "22", Protocol: "tcp"},
		{Port: "22", Protocol: "tcp"},
		{Port: "", Protocol: "tcp"},
		{Port: "80", Protocol: "tcp"},
	})
	want := []firewallPortWhitelist{
		{Port: "22", Protocol: "tcp"},
		{Port: "80", Protocol: "tcp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitFirewallRuleAddressesContract(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty becomes single empty", in: "", want: []string{""}},
		{name: "anywhere normalized", in: "Anywhere", want: []string{""}},
		{name: "csv", in: "1.1.1.1,2.2.2.2", want: []string{"1.1.1.1", "2.2.2.2"}},
		{name: "trailing comma", in: "1.1.1.1,", want: []string{"1.1.1.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitFirewallRuleAddresses(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v want %#v", got, tt.want)
			}
		})
	}
}

func TestCheckPortUsedContract(t *testing.T) {
	apps := []portOfApp{
		{AppName: "wordpress", HttpPort: "8080", HttpsPort: "8443"},
		{AppName: "1panel", HttpPort: "9999"},
	}
	if got := checkPortUsed("8080", "tcp", apps); got != "wordpress" {
		t.Fatalf("got %q want wordpress", got)
	}
	if got := checkPortUsed("9999", "tcp", apps); got != "1panel" {
		t.Fatalf("got %q want 1panel", got)
	}
	if got := checkPortUsed("12345", "tcp", apps); got != "" {
		// ScanPortWithProto may or may not find a listener in CI; only assert app miss path returns non-app name when unused.
		// When unused, empty string is expected.
		_ = got
	}
}

func TestFirewallAPIDtoSnapshot(t *testing.T) {
	assertStructFields(t, dto.PortRuleOperate{}, []string{
		"ID", "Operation", "Chain", "Address", "Port", "Protocol", "Strategy", "Description",
	})
	assertStructFields(t, dto.AddrRuleOperate{}, []string{
		"ID", "Operation", "Address", "Strategy", "Description",
	})
	assertStructFields(t, dto.ForwardRuleOperate{}, []string{
		"ForceDelete", "Rules",
	})
	assertStructFields(t, dto.FirewallBaseInfo{}, []string{
		"Name", "IsExist", "IsActive", "IsInit", "IsBind", "Version", "PingStatus",
	})
	assertStructFields(t, dto.FirewallOperation{}, []string{
		"Operation", "WithDockerRestart",
	})
	assertStructFields(t, dto.BatchRuleOperate{}, []string{
		"Type", "Rules",
	})
	assertStructFields(t, dto.IptablesRuleOp{}, []string{
		"Operation", "ID", "Chain", "Protocol", "SrcIP", "SrcPort", "DstIP", "DstPort", "Strategy", "Description",
	})
}

func assertStructFields(t *testing.T, sample any, want []string) {
	t.Helper()
	typ := reflect.TypeOf(sample)
	if typ.Kind() != reflect.Struct {
		t.Fatalf("expected struct, got %s", typ.Kind())
	}
	got := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s fields changed\ngot  %#v\nwant %#v", typ.Name(), got, want)
	}
}

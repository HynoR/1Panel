package service

import (
	"errors"
	"reflect"
	"testing"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	fireClient "github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

type filterCall struct {
	method    string
	operation string
	info      fireClient.FireInfo
}

type fakeFilterClient struct {
	name      string
	active    bool
	version   string
	err       error
	portRules []fireClient.FireInfo
	addrRules []fireClient.FireInfo
	calls     []filterCall
}

func (f *fakeFilterClient) Name() string {
	return f.name
}

func (f *fakeFilterClient) Start() error {
	f.calls = append(f.calls, filterCall{method: "start"})
	return f.err
}

func (f *fakeFilterClient) Stop() error {
	f.calls = append(f.calls, filterCall{method: "stop"})
	return f.err
}

func (f *fakeFilterClient) Restart() error {
	f.calls = append(f.calls, filterCall{method: "restart"})
	return f.err
}

func (f *fakeFilterClient) Reload() error {
	f.calls = append(f.calls, filterCall{method: "reload"})
	return f.err
}

func (f *fakeFilterClient) Status() (bool, error) {
	f.calls = append(f.calls, filterCall{method: "status"})
	return f.active, f.err
}

func (f *fakeFilterClient) Version() (string, error) {
	f.calls = append(f.calls, filterCall{method: "version"})
	return f.version, f.err
}

func (f *fakeFilterClient) ListPort() ([]fireClient.FireInfo, error) {
	f.calls = append(f.calls, filterCall{method: "list-port"})
	return f.portRules, f.err
}

func (f *fakeFilterClient) ListAddress() ([]fireClient.FireInfo, error) {
	f.calls = append(f.calls, filterCall{method: "list-address"})
	return f.addrRules, f.err
}

func (f *fakeFilterClient) Port(info fireClient.FireInfo, operation string) error {
	f.calls = append(f.calls, filterCall{method: "port", operation: operation, info: info})
	return f.err
}

func (f *fakeFilterClient) RichRules(info fireClient.FireInfo, operation string) error {
	f.calls = append(f.calls, filterCall{method: "rich", operation: operation, info: info})
	return f.err
}

func TestOperatePortRuleUsesProductionLaneDispatch(t *testing.T) {
	service := &FirewallService{}
	req := dto.PortRuleOperate{
		Operation: "add",
		Port:      "8000-8010",
		Protocol:  "tcp",
		Strategy:  "accept",
	}

	ufw := &fakeFilterClient{name: "ufw"}
	if err := service.operatePortRuleWithClient(ufw, req, false); err != nil {
		t.Fatal(err)
	}
	assertSingleFilterCall(t, ufw.calls, "port", "add")
	if ufw.calls[0].info.Port != "8000:8010" {
		t.Fatalf("UFW lane must preserve dev-v2 range syntax, got %q", ufw.calls[0].info.Port)
	}

	legacy := &fakeFilterClient{name: "iptables"}
	if err := service.operatePortRuleWithClient(legacy, req, false); err != nil {
		t.Fatal(err)
	}
	assertSingleFilterCall(t, legacy.calls, "port", "add")
	if legacy.calls[0].info.Port != "8000-8010" {
		t.Fatalf("legacy lane must preserve dev-v2 range syntax, got %q", legacy.calls[0].info.Port)
	}
	if legacy.calls[0].info.Chain != iptables.Chain1PanelBasic {
		t.Fatalf("legacy lane must use %s, got %s", iptables.Chain1PanelBasic, legacy.calls[0].info.Chain)
	}

	unknown := &fakeFilterClient{name: "unknown"}
	if err := service.operatePortRuleWithClient(unknown, req, false); err == nil {
		t.Fatal("unknown provider must be rejected before a filter write")
	}
	if len(unknown.calls) != 0 {
		t.Fatalf("unknown provider unexpectedly wrote filter state: %#v", unknown.calls)
	}
}

func TestOperateAddressRuleUsesProductionLaneDispatch(t *testing.T) {
	service := &FirewallService{}
	req := dto.AddrRuleOperate{
		Operation: "remove",
		Address:   "10.0.0.1",
		Strategy:  "drop",
	}
	for _, name := range []string{"ufw", "firewalld", "iptables"} {
		t.Run(name, func(t *testing.T) {
			client := &fakeFilterClient{name: name}
			if err := service.operateAddressRuleWithClient(client, req, false); err != nil {
				t.Fatal(err)
			}
			assertSingleFilterCall(t, client.calls, "rich", "remove")
			if client.calls[0].info.Address != req.Address {
				t.Fatalf("got address %q want %q", client.calls[0].info.Address, req.Address)
			}
		})
	}
}

func TestOperateFirewallPortUsesProductionLaneDispatch(t *testing.T) {
	wantMethods := []string{"port:add", "port:remove", "reload:"}
	for _, name := range []string{"ufw", "firewalld", "iptables"} {
		t.Run(name, func(t *testing.T) {
			client := &fakeFilterClient{name: name}
			if err := operateFirewallPortWithClient(client, []int{22}, []int{2222}); err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(client.calls))
			for _, call := range client.calls {
				got = append(got, call.method+":"+call.operation)
			}
			if !reflect.DeepEqual(got, wantMethods) {
				t.Fatalf("got calls %#v want %#v", got, wantMethods)
			}
			if client.calls[0].info.Port != "2222" || client.calls[1].info.Port != "22" {
				t.Fatalf("new port must be added before old port is removed: %#v", client.calls)
			}
		})
	}
}

func TestFilterLifecycleAndListUseProductionLaneDispatch(t *testing.T) {
	for _, tt := range []struct {
		name string
		lane firewall.Lane
	}{
		{name: "ufw", lane: firewall.LaneExternalNative},
		{name: "firewalld", lane: firewall.LaneExternalNative},
		{name: "iptables", lane: firewall.LaneSelfManagedLegacyV1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeFilterClient{
				name:      tt.name,
				portRules: []fireClient.FireInfo{{Port: "80"}},
				addrRules: []fireClient.FireInfo{{Address: "10.0.0.1"}},
			}
			if err := operateFilterLifecycleByLane(client, tt.lane, "restart"); err != nil {
				t.Fatal(err)
			}
			if _, err := listFilterRulesByLane(client, tt.lane, "port"); err != nil {
				t.Fatal(err)
			}
			if _, err := listFilterRulesByLane(client, tt.lane, "address"); err != nil {
				t.Fatal(err)
			}
			if err := reloadFilterByLane(client); err != nil {
				t.Fatal(err)
			}
			got := []string{client.calls[0].method, client.calls[1].method, client.calls[2].method, client.calls[3].method}
			want := []string{"restart", "list-port", "list-address", "reload"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got calls %#v want %#v", got, want)
			}
		})
	}
}

func TestWhitelistSyncUsesProductionLaneResolution(t *testing.T) {
	client := &fakeFilterClient{name: "unknown"}
	if err := syncFirewallPortWhiteListAfterUpdateWithClient(client, "80/tcp"); err == nil {
		t.Fatal("unknown provider must be rejected before whitelist state is loaded")
	}
	if len(client.calls) != 0 {
		t.Fatalf("unknown provider unexpectedly touched filter state: %#v", client.calls)
	}
}

func TestExternalLaneReturnsClientErrorWithoutFallback(t *testing.T) {
	nativeErr := errors.New("native firewall failure")
	client := &fakeFilterClient{name: "ufw", err: nativeErr}
	err := (&FirewallService{}).operatePortRuleWithClient(client, dto.PortRuleOperate{
		Operation: "add",
		Port:      "80",
		Protocol:  "tcp",
		Strategy:  "accept",
	}, false)
	if !errors.Is(err, nativeErr) {
		t.Fatalf("external lane must return the client error, got %v", err)
	}
	assertSingleFilterCall(t, client.calls, "port", "add")
}

func TestFail2BanProviderStatusUsesReadOnlyInterface(t *testing.T) {
	active := &statusOnlyFirewall{active: true}
	if err := ensureFirewallProviderActive(active, "ufw"); err != nil {
		t.Fatal(err)
	}
	if active.calls != 1 {
		t.Fatalf("status called %d times, want 1", active.calls)
	}

	inactive := &statusOnlyFirewall{}
	if err := ensureFirewallProviderActive(inactive, "ufw"); err == nil {
		t.Fatal("inactive provider must be rejected")
	}
}

func TestLoadInitStatusExternalParity(t *testing.T) {
	for _, tt := range []struct {
		name string
		tab  string
	}{
		{name: "ufw", tab: "base"},
		{name: "ufw", tab: "port"},
		{name: "firewalld", tab: "base"},
		{name: "firewalld", tab: "advance"},
	} {
		t.Run(tt.name+"/"+tt.tab, func(t *testing.T) {
			isInit, isBind := loadExternalInitStatus(tt.name, tt.tab)
			if !isInit || !isBind {
				t.Fatalf("expected dev-v2 true,true, got %v,%v", isInit, isBind)
			}
		})
	}
}

type statusOnlyFirewall struct {
	active bool
	calls  int
}

func (s *statusOnlyFirewall) Status() (bool, error) {
	s.calls++
	return s.active, nil
}

func assertSingleFilterCall(t *testing.T, calls []filterCall, method, operation string) {
	t.Helper()
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1: %#v", len(calls), calls)
	}
	if calls[0].method != method || calls[0].operation != operation {
		t.Fatalf("got call %#v want %s:%s", calls[0], method, operation)
	}
}

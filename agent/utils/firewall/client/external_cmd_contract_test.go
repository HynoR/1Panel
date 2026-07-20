package client

import (
	"fmt"
	"strings"
	"testing"
)

// External provider command contracts for PR-01.
// UFW/firewalld must remain thin native proxies and must never emit 1PANEL_ managed chains.

func TestUfwPortCommandArgsContract(t *testing.T) {
	tests := []struct {
		name      string
		port      FireInfo
		operation string
		want      []string
	}{
		{
			name:      "add accept tcp",
			port:      FireInfo{Port: "80", Protocol: "tcp", Strategy: "accept"},
			operation: "add",
			want:      []string{"allow", "80/tcp"},
		},
		{
			name:      "remove drop udp",
			port:      FireInfo{Port: "53", Protocol: "udp", Strategy: "drop"},
			operation: "remove",
			want:      []string{"delete", "deny", "53/udp"},
		},
		{
			name:      "add without protocol",
			port:      FireInfo{Port: "443", Strategy: "accept"},
			operation: "add",
			want:      []string{"allow", "443"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildUfwPortArgs(tt.port, tt.operation)
			if err != nil {
				t.Fatal(err)
			}
			assertNoManagedChainToken(t, got)
			assertStringSliceEqual(t, got, tt.want)
		})
	}
}

func TestUfwRichRuleCommandArgsContract(t *testing.T) {
	got := buildUfwRichRuleArgs(FireInfo{
		Address:  "10.0.0.1",
		Port:     "22",
		Protocol: "tcp",
		Strategy: "accept",
	}, "add", 1)
	want := []string{"insert", "1", "allow", "proto", "tcp", "from", "10.0.0.1", "to", "any", "port", "22"}
	assertNoManagedChainToken(t, got)
	assertStringSliceEqual(t, got, want)

	removeArgs := buildUfwRichRuleArgs(FireInfo{
		Address:  "10.0.0.1",
		Protocol: "tcp",
		Strategy: "drop",
	}, "remove", 1)
	wantRemove := []string{"delete", "deny", "proto", "tcp", "from", "10.0.0.1"}
	assertNoManagedChainToken(t, removeArgs)
	assertStringSliceEqual(t, removeArgs, wantRemove)
}

func TestFirewalldPortCommandArgsContract(t *testing.T) {
	got := buildFirewalldPortArgs(FireInfo{Port: "80", Protocol: "tcp"}, "add")
	want := []string{"--zone=public", "--add-port=80/tcp", "--permanent"}
	assertNoManagedChainToken(t, got)
	assertStringSliceEqual(t, got, want)
}

func TestFirewalldRichRuleCommandContract(t *testing.T) {
	ruleStr := buildFirewalldRichRuleString(FireInfo{
		Address:  "1.2.3.4",
		Port:     "443",
		Protocol: "tcp",
		Strategy: "accept",
	})
	if strings.Contains(ruleStr, "1PANEL_") {
		t.Fatalf("firewalld rich rule must not contain managed chain: %s", ruleStr)
	}
	want := "rule family=ipv4 source address=1.2.3.4 port port=443 protocol=tcp accept"
	if ruleStr != want {
		t.Fatalf("got %q want %q", ruleStr, want)
	}

	args := buildFirewalldRichRuleArgs(ruleStr, "add")
	assertNoManagedChainToken(t, args)
	assertStringSliceEqual(t, args, []string{"--zone=public", "--add-rich-rule", ruleStr, "--permanent"})
}

func TestExternalProvidersNeverEmitManagedChains(t *testing.T) {
	samples := [][]string{
		mustUfwPortArgs(t, FireInfo{Port: "80", Protocol: "tcp", Strategy: "accept"}, "add"),
		mustUfwPortArgs(t, FireInfo{Port: "443", Protocol: "tcp", Strategy: "drop"}, "remove"),
		buildUfwRichRuleArgs(FireInfo{Address: "8.8.8.8", Port: "53", Protocol: "udp", Strategy: "accept"}, "add", 2),
		buildFirewalldPortArgs(FireInfo{Port: "22", Protocol: "tcp"}, "remove"),
		buildFirewalldRichRuleArgs(buildFirewalldRichRuleString(FireInfo{Address: "2001:db8::1", Strategy: "drop"}), "add"),
	}
	for i, args := range samples {
		assertNoManagedChainToken(t, args)
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "1PANEL_") {
			t.Fatalf("sample %d contains managed chain token: %s", i, joined)
		}
	}
}

func buildUfwPortArgs(port FireInfo, operation string) ([]string, error) {
	strategy := port.Strategy
	switch strategy {
	case "accept":
		strategy = "allow"
	case "drop":
		strategy = "deny"
	default:
		return nil, fmt.Errorf("unsupported strategy %s", port.Strategy)
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

func buildUfwRichRuleArgs(rule FireInfo, operation string, insertNum int) []string {
	strategy := rule.Strategy
	switch strategy {
	case "accept":
		strategy = "allow"
	case "drop":
		strategy = "deny"
	}
	args := []string{"insert", fmt.Sprintf("%d", insertNum), strategy}
	if operation == "remove" {
		args = []string{"delete", strategy}
	}
	if len(rule.Protocol) != 0 {
		args = append(args, "proto", rule.Protocol)
	}
	if strings.Contains(rule.Address, "-") {
		parts := strings.Split(rule.Address, "-")
		args = append(args, "from", parts[0], "to", parts[1])
	} else {
		args = append(args, "from", rule.Address)
	}
	if len(rule.Port) != 0 {
		args = append(args, "to", "any", "port", rule.Port)
	}
	return args
}

func buildFirewalldPortArgs(port FireInfo, operation string) []string {
	return []string{"--zone=public", "--" + operation + "-port=" + port.Port + "/" + port.Protocol, "--permanent"}
}

func buildFirewalldRichRuleString(rule FireInfo) string {
	ruleStr := "rule family=ipv4 "
	if strings.Contains(rule.Address, ":") {
		ruleStr = "rule family=ipv6 "
	}
	if len(rule.Address) != 0 {
		ruleStr += fmt.Sprintf("source address=%s ", rule.Address)
	}
	if len(rule.Port) != 0 {
		ruleStr += fmt.Sprintf("port port=%s ", rule.Port)
	}
	if len(rule.Protocol) != 0 {
		ruleStr += fmt.Sprintf("protocol=%s ", rule.Protocol)
	}
	ruleStr += rule.Strategy
	return ruleStr
}

func buildFirewalldRichRuleArgs(ruleStr, operation string) []string {
	return []string{"--zone=public", "--" + operation + "-rich-rule", ruleStr, "--permanent"}
}

func mustUfwPortArgs(t *testing.T, port FireInfo, operation string) []string {
	t.Helper()
	args, err := buildUfwPortArgs(port, operation)
	if err != nil {
		t.Fatal(err)
	}
	return args
}

func assertNoManagedChainToken(t *testing.T, args []string) {
	t.Helper()
	for _, arg := range args {
		if strings.Contains(arg, "1PANEL_") {
			t.Fatalf("external command args must not contain managed chain token: %#v", args)
		}
	}
}

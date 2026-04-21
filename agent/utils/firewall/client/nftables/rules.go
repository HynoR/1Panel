package nftables

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// NftRule is a single rule parsed from `nft -a list chain` output, carrying
// both the raw rule body (without leading/trailing whitespace or the
// trailing ` # handle N` comment) and its handle for later deletion.
type NftRule struct {
	Handle int
	Body   string
}

// ListChainRulesWithHandle returns the rules currently installed in
// (family, table, chain) alongside their nft handles. Chains that do
// not exist return (nil, nil) — callers that need to distinguish
// "missing chain" from "empty chain" should probe with ChainExists.
func ListChainRulesWithHandle(family, table, chain string) ([]NftRule, error) {
	exists, err := ChainExists(family, table, chain)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	stdout, err := Run(fmt.Sprintf("-a list chain %s %s %s", family, table, chain))
	if err != nil {
		return nil, err
	}
	return parseChainRules(stdout), nil
}

var handleRe = regexp.MustCompile(`^(.*?)\s*#\s*handle\s+(\d+)\s*$`)

// parseChainRules takes the output of `nft -a list chain ...` and returns
// just the inner rule lines, excluding the chain declaration and braces.
// Empty bodies (e.g. the `type filter hook ... ;` line on hook chains)
// are filtered out.
//
// `nft -a` emits handle markers on every container line ("table X {
// # handle N", "chain Y { # handle M"), so a simple HasSuffix("{") would
// miss the opening braces. We track nesting depth via any line that
// contains "{" or "}".
func parseChainRules(stdout string) []NftRule {
	var rules []NftRule
	depth := 0
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		opensBrace := strings.Contains(line, "{")
		closesBrace := strings.Contains(line, "}")
		if depth == 0 {
			if opensBrace {
				depth++
			}
			continue
		}
		if depth == 1 && opensBrace && !closesBrace {
			// Entering the chain body itself.
			depth++
			continue
		}
		if closesBrace && !opensBrace {
			depth--
			if depth <= 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(line, "chain ") || strings.HasPrefix(line, "table ") {
			continue
		}
		if strings.HasPrefix(line, "type ") {
			continue
		}
		body := line
		handle := 0
		if m := handleRe.FindStringSubmatch(line); m != nil {
			body = strings.TrimSpace(m[1])
			if h, err := strconv.Atoi(m[2]); err == nil {
				handle = h
			}
		}
		if body == "" {
			continue
		}
		rules = append(rules, NftRule{Handle: handle, Body: body})
	}
	return rules
}

// MatchPortRule extracts port / protocol / strategy from a rule body of
// the form `[ip saddr <cidr> ] (tcp|udp) dport <port|range> (accept|drop|reject)`.
// Returns ok=false for bodies that don't match this shape.
type ParsedPortRule struct {
	Protocol string // tcp | udp
	Address  string // source CIDR or empty
	Port     string // "80" or "8000-8080"
	Strategy string // accept | drop | reject
	Family   string // ip | ip6 | "" (unspecified)
}

var portBodyRe = regexp.MustCompile(`^(?:(ip|ip6)\s+saddr\s+(\S+)\s+)?(tcp|udp)\s+dport\s+(\{\s*[^}]+\s*\}|[0-9-]+)\s+(accept|drop|reject)\s*$`)

func MatchPortRule(body string) (ParsedPortRule, bool) {
	m := portBodyRe.FindStringSubmatch(strings.TrimSpace(body))
	if m == nil {
		return ParsedPortRule{}, false
	}
	port := strings.TrimSpace(m[4])
	port = strings.Trim(port, "{}")
	port = strings.TrimSpace(port)
	return ParsedPortRule{
		Family:   m[1],
		Address:  m[2],
		Protocol: m[3],
		Port:     port,
		Strategy: m[5],
	}, true
}

// MatchAddressRule extracts source-only rules: `(ip|ip6) saddr <cidr> (accept|drop|reject)`.
type ParsedAddressRule struct {
	Family   string // ip | ip6
	Address  string
	Strategy string
}

var addrBodyRe = regexp.MustCompile(`^(ip|ip6)\s+saddr\s+(\S+)\s+(accept|drop|reject)\s*$`)

func MatchAddressRule(body string) (ParsedAddressRule, bool) {
	m := addrBodyRe.FindStringSubmatch(strings.TrimSpace(body))
	if m == nil {
		return ParsedAddressRule{}, false
	}
	return ParsedAddressRule{
		Family:   m[1],
		Address:  m[2],
		Strategy: m[3],
	}, true
}

// MatchForwardRule extracts DNAT forwards of the form
// `(tcp|udp) dport <port> dnat to <target>`.
type ParsedForwardRule struct {
	Protocol string
	Port     string
	Target   string // raw dnat target: "1.2.3.4:22" or ":22" for same-host
}

var forwardBodyRe = regexp.MustCompile(`^(tcp|udp)\s+dport\s+(\S+)\s+dnat\s+to\s+(\S+)\s*$`)

func MatchForwardRule(body string) (ParsedForwardRule, bool) {
	m := forwardBodyRe.FindStringSubmatch(strings.TrimSpace(body))
	if m == nil {
		return ParsedForwardRule{}, false
	}
	return ParsedForwardRule{
		Protocol: m[1],
		Port:     m[2],
		Target:   m[3],
	}, true
}

// FormatPortRule emits the nft syntax for a port/address ACCEPT|DROP rule.
// `protocol` must be tcp or udp. `port` may be a single number or a nft range
// like "8000-8080". `srcAddr` is optional; when provided it is prefixed as
// `ip saddr <cidr>` (or `ip6` for IPv6 addresses).
func FormatPortRule(protocol, srcAddr, port, strategy string) (string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if protocol != "tcp" && protocol != "udp" {
		return "", fmt.Errorf("unsupported protocol %q", protocol)
	}
	if port == "" {
		return "", fmt.Errorf("port required")
	}
	if strategy == "" {
		strategy = "accept"
	}
	if strategy != "accept" && strategy != "drop" && strategy != "reject" {
		return "", fmt.Errorf("unsupported strategy %q", strategy)
	}

	var b strings.Builder
	if addr := strings.TrimSpace(srcAddr); addr != "" && !strings.EqualFold(addr, "Anywhere") {
		family := "ip"
		if strings.Contains(addr, ":") {
			family = "ip6"
		}
		fmt.Fprintf(&b, "%s saddr %s ", family, addr)
	}
	portSpec := strings.ReplaceAll(port, ":", "-")
	fmt.Fprintf(&b, "%s dport %s %s", protocol, portSpec, strategy)
	return b.String(), nil
}

// FormatAddressRule emits a source-address-only rule.
func FormatAddressRule(addr, strategy string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("address required")
	}
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy != "accept" && strategy != "drop" && strategy != "reject" {
		return "", fmt.Errorf("unsupported strategy %q", strategy)
	}
	family := "ip"
	if strings.Contains(addr, ":") {
		family = "ip6"
	}
	return fmt.Sprintf("%s saddr %s %s", family, addr, strategy), nil
}

// FormatForwardRule emits a nat-table dnat rule.
func FormatForwardRule(protocol, port, targetIP, targetPort string) (string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "tcp" && protocol != "udp" {
		return "", fmt.Errorf("unsupported protocol %q", protocol)
	}
	if port == "" || targetPort == "" {
		return "", fmt.Errorf("port and targetPort required")
	}
	target := targetIP + ":" + targetPort
	if targetIP == "" || targetIP == "127.0.0.1" || targetIP == "localhost" {
		target = ":" + targetPort
	}
	return fmt.Sprintf("%s dport %s dnat to %s", protocol, port, target), nil
}

// EmergencyAcceptSpecs builds the list of rule-body strings that constitute
// the baseline ACCEPT set for nftables' panel_before chain. The returned
// slice is ordered: loopback, conntrack established, then per-port TCP
// accepts. Duplicate ports are deduped in-place.
func EmergencyAcceptSpecs(sshPort, panelPort string, extraTcpPorts []string) []string {
	specs := []string{
		`iif "lo" accept`,
		`ct state related,established accept`,
	}
	seen := map[string]bool{}
	ports := make([]string, 0, 2+len(extraTcpPorts))
	if sshPort != "" && !seen[sshPort] {
		ports = append(ports, sshPort)
		seen[sshPort] = true
	}
	if panelPort != "" && !seen[panelPort] {
		ports = append(ports, panelPort)
		seen[panelPort] = true
	}
	for _, p := range extraTcpPorts {
		if p == "" || seen[p] {
			continue
		}
		ports = append(ports, p)
		seen[p] = true
	}
	for _, p := range ports {
		specs = append(specs, fmt.Sprintf("tcp dport %s accept", p))
	}
	return specs
}

// RuleBodyMatches treats two rule bodies as equivalent when `actual`
// contains every significant token of `expected` in the same order.
// nftables normalises its output (quoting, whitespace, implicit
// counters) so a naive string compare would misfire on round-tripped
// rules. The matcher is intentionally forgiving: extra tokens in actual
// are allowed because nftables may insert counters or `handle` markers.
func RuleBodyMatches(actual, expected string) bool {
	actualTokens := strings.Fields(actual)
	expectedTokens := strings.Fields(expected)
	if len(expectedTokens) == 0 {
		return false
	}
	j := 0
	for i := 0; i < len(actualTokens) && j < len(expectedTokens); i++ {
		if tokenEquivalent(actualTokens[i], expectedTokens[j]) {
			j++
		}
	}
	return j == len(expectedTokens)
}

func tokenEquivalent(a, b string) bool {
	ac := strings.Trim(a, `"`)
	bc := strings.Trim(b, `"`)
	return ac == bc
}

// EnsureEmergencyAccepts idempotently installs the emergency ACCEPT set
// into (family, table, chain). Rules already present (per
// RuleBodyMatches) are skipped. The chain itself must exist before the
// call; use the driver's ensure-topology helper first.
func EnsureEmergencyAccepts(family, table, chain string, specs []string) error {
	rules, err := ListChainRulesWithHandle(family, table, chain)
	if err != nil {
		return fmt.Errorf("list %s %s %s: %w", family, table, chain, err)
	}
	present := make(map[int]bool, len(specs))
	for idx, spec := range specs {
		for _, r := range rules {
			if RuleBodyMatches(r.Body, spec) {
				present[idx] = true
				break
			}
		}
	}
	for idx, spec := range specs {
		if present[idx] {
			continue
		}
		if err := AddRule(family, table, chain, spec); err != nil {
			return err
		}
	}
	return nil
}

// VerifyEmergencyAccepts re-reads the chain and returns an error naming
// the first spec that is still missing. Used as a post-condition on
// init paths where failure must abort the bind of any DROP-all sibling
// chain.
func VerifyEmergencyAccepts(family, table, chain string, specs []string) error {
	rules, err := ListChainRulesWithHandle(family, table, chain)
	if err != nil {
		return err
	}
	for _, spec := range specs {
		found := false
		for _, r := range rules {
			if RuleBodyMatches(r.Body, spec) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("emergency rule %q missing from %s %s %s", spec, family, table, chain)
		}
	}
	return nil
}

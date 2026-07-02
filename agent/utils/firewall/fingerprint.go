package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
)

// RuleKey 是计算指纹的规范化输入。同一条语义规则无论来自 DB、文件还是系统回读，
// 只要填入相同字段即得到相同指纹（设计稿 §3.3）。
type RuleKey struct {
	Family     string // ipv4 | ipv6 | both
	Scope      string // input | output | forward | docker
	Kind       string // port | address | forward | filter | docker
	Action     string // accept | drop | reject
	Protocol   string
	SrcIP      string
	SrcPort    string
	DstIP      string
	DstPort    string
	TargetIP   string
	TargetPort string
	Interface  string
}

// Fingerprint = sha256(规范化字段 join "|") 取前 16 字节 hex。
func Fingerprint(k RuleKey) string {
	parts := []string{
		normFamily(k.Family),
		normLower(k.Scope),
		normLower(k.Kind),
		normLower(k.Action),
		normProtocol(k.Protocol),
		normIP(k.SrcIP),
		normPort(k.SrcPort),
		normIP(k.DstIP),
		normPort(k.DstPort),
		normIP(k.TargetIP),
		normPort(k.TargetPort),
		normEmpty(strings.TrimSpace(k.Interface)),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:16])
}

func normEmpty(v string) string {
	if v == "" {
		return "*"
	}
	return v
}

func normLower(v string) string {
	return normEmpty(strings.ToLower(strings.TrimSpace(v)))
}

func normFamily(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "ipv6", "both":
		return v
	default:
		return "ipv4"
	}
}

func normProtocol(v string) string {
	return normLower(v)
}

// normPort 统一端口区间为 a-b（接受 ":" 或 "-" 分隔），单端口原样。
func normPort(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "*"
	}
	v = strings.ReplaceAll(v, ":", "-")
	return v
}

// normIP 规范化地址：空/0.0.0.0/0/anywhere → "*"；CIDR/IP 标准化为 net 包形式。
func normIP(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || v == "0.0.0.0/0" || v == "::/0" || v == "anywhere" {
		return "*"
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

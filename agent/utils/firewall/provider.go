package firewall

import (
	"errors"

	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// Lane identifies ownership of a filter backend.
// External native providers (UFW/firewalld) stay thin proxies.
// Self-managed legacy-v1 is the current iptables implementation on dev-v2.
type Lane string

const (
	LaneExternalNative      Lane = "external-native"
	LaneSelfManagedLegacyV1 Lane = "self-managed-legacy-v1"
)

// ProviderInfo is a read-only detection result used for routing.
// DetectProvider never constructs a writable client or mutates kernel state.
type ProviderInfo struct {
	Name string
	Lane Lane
}

// DetectProvider reuses NewFirewallClient selection order without building a client:
// firewalld+ufw conflict -> firewalld -> ufw -> iptables.
func DetectProvider() (ProviderInfo, error) {
	return resolveProviderFromPresence(cmd.Which("firewalld"), cmd.Which("ufw"), cmd.Which("iptables"))
}

// resolveProviderFromPresence encodes the sticky-free detection algorithm.
// It is read-only and never mutates kernel or service state.
func resolveProviderFromPresence(firewalld, ufw, iptables bool) (ProviderInfo, error) {
	if firewalld && ufw {
		return ProviderInfo{}, errors.New("It is detected that the system has both firewalld and ufw services. To avoid conflicts, please uninstall and try again!")
	}
	if firewalld {
		return ProviderInfo{Name: "firewalld", Lane: LaneExternalNative}, nil
	}
	if ufw {
		return ProviderInfo{Name: "ufw", Lane: LaneExternalNative}, nil
	}
	if iptables {
		return ProviderInfo{Name: "iptables", Lane: LaneSelfManagedLegacyV1}, nil
	}
	return ProviderInfo{}, errors.New("No system firewall service detected (firewalld/ufw/iptables), please check and try again!")
}

// IsExternal reports whether the provider is a native UFW/firewalld proxy.
func (p ProviderInfo) IsExternal() bool {
	return p.Lane == LaneExternalNative
}

// IsLegacyV1 reports whether the provider is iptables legacy-v1.
func (p ProviderInfo) IsLegacyV1() bool {
	return p.Lane == LaneSelfManagedLegacyV1
}

// LaneOfName maps a provider name to its ownership lane.
// Unknown names are treated as external to avoid accidental managed writes.
func LaneOfName(name string) Lane {
	if name == "iptables" {
		return LaneSelfManagedLegacyV1
	}
	return LaneExternalNative
}

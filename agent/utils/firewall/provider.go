package firewall

import (
	"errors"

	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
)

// Lane identifies ownership of a filter backend.
// External native providers (UFW/firewalld) stay thin proxies.
// Self-managed legacy-v1 is the current iptables implementation on dev-v2.
type Lane string

const (
	LaneUnknown             Lane = "unknown"
	LaneExternalNative      Lane = "external-native"
	LaneSelfManagedLegacyV1 Lane = "self-managed-legacy-v1"
)

// ProviderInfo is a read-only detection result used for routing.
// DetectProvider never constructs a writable client or mutates kernel state.
type ProviderInfo struct {
	Name string
	Lane Lane
}

// ProviderStatusReader exposes only the capability required by read-only callers.
type ProviderStatusReader interface {
	Status() (bool, error)
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

// LaneOfName maps a known provider name to its ownership lane.
func LaneOfName(name string) Lane {
	switch name {
	case "ufw", "firewalld":
		return LaneExternalNative
	case "iptables":
		return LaneSelfManagedLegacyV1
	default:
		return LaneUnknown
	}
}

// ResolveLane rejects unknown providers instead of guessing an ownership lane.
func ResolveLane(name string) (Lane, error) {
	lane := LaneOfName(name)
	if lane == LaneUnknown {
		return LaneUnknown, errors.New("unsupported firewall provider: " + name)
	}
	return lane, nil
}

// NewProviderStatusReader constructs a provider through a read-only interface.
func NewProviderStatusReader(provider ProviderInfo) (ProviderStatusReader, error) {
	lane, err := ResolveLane(provider.Name)
	if err != nil {
		return nil, err
	}
	if provider.Lane != lane {
		return nil, errors.New("firewall provider lane does not match provider name")
	}
	switch provider.Name {
	case "firewalld":
		return client.NewFirewalld()
	case "ufw":
		return client.NewUfw()
	case "iptables":
		return client.NewIptables()
	default:
		return nil, errors.New("unsupported firewall provider: " + provider.Name)
	}
}

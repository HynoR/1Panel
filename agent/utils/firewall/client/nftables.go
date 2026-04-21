package client

import (
	"errors"
	"fmt"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// Nftables is a placeholder driver for nftables.
//
// This file exists to reserve the integration surface for a future
// panel_managed nftables backend (designed as the successor to iptables on
// modern distributions). All operation-level methods return ErrNftablesNotImpl
// today; only Name/Version/Status are wired so the presence check in
// NewFirewallClient can surface a clear "unsupported" message to the UI when
// iptables is absent but nftables is the only option on the host.
//
// When nftables is implemented, delete ErrNftablesNotImpl-returning stubs
// and plug the driver into NewFirewallClient after the ufw/firewalld branches
// but BEFORE the iptables fallback. The rest of the architecture — emergency
// chains, snapshots, caller-IP guard, staging-chain atomic apply — is
// designed to translate cleanly to nftables native transactions.
type Nftables struct {
	cmdStr string
}

// ErrNftablesNotImpl marks any nftables-driver operation that has not been
// wired yet. Callers should treat it as "capability missing on this host"
// and fall back to a supported driver instead of failing hard.
var ErrNftablesNotImpl = errors.New("nftables driver is not yet implemented; iptables/ufw/firewalld remain the supported paths")

// NewNftables constructs the placeholder driver. Not referenced by
// NewFirewallClient yet — intentional until the real implementation lands.
func NewNftables() (*Nftables, error) {
	return &Nftables{cmdStr: fmt.Sprintf("%s nft", cmd.SudoHandleCmd())}, nil
}

func (n *Nftables) Name() string { return "nftables" }

func (n *Nftables) Version() (string, error) {
	stdout, err := cmd.RunDefaultWithStdoutBashCf("%s --version", n.cmdStr)
	if err != nil {
		return "", fmt.Errorf("load nftables version failed: %w", err)
	}
	parts := strings.Fields(strings.TrimSpace(stdout))
	if len(parts) >= 2 {
		return strings.TrimPrefix(parts[1], "v"), nil
	}
	return strings.TrimSpace(stdout), nil
}

func (n *Nftables) Status() (bool, error) {
	_, err := cmd.RunDefaultWithStdoutBashCf("%s list ruleset", n.cmdStr)
	return err == nil, nil
}

func (n *Nftables) Start() error   { return ErrNftablesNotImpl }
func (n *Nftables) Stop() error    { return ErrNftablesNotImpl }
func (n *Nftables) Restart() error { return ErrNftablesNotImpl }
func (n *Nftables) Reload() error  { return ErrNftablesNotImpl }

func (n *Nftables) ListPort() ([]FireInfo, error) {
	return nil, ErrNftablesNotImpl
}
func (n *Nftables) ListForward() ([]FireInfo, error) {
	return nil, ErrNftablesNotImpl
}
func (n *Nftables) ListAddress() ([]FireInfo, error) {
	return nil, ErrNftablesNotImpl
}

func (n *Nftables) Port(_ FireInfo, _ string) error {
	return ErrNftablesNotImpl
}
func (n *Nftables) RichRules(_ FireInfo, _ string) error {
	return ErrNftablesNotImpl
}
func (n *Nftables) PortForward(_ Forward, _ string) error {
	return ErrNftablesNotImpl
}
func (n *Nftables) EnableForward() error {
	return ErrNftablesNotImpl
}

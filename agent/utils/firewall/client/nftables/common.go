package nftables

import (
	"fmt"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// nftables table/chain naming for 1Panel-managed rules.
//
// One inet table (`1panel`) covers both IPv4 and IPv6 filter rules. A
// separate `ip` table (`1panel_nat`) carries IPv4 port forwards; IPv6
// NAT is deliberately out of scope today and can be added in a sibling
// table when needed.
//
// Chain names intentionally avoid the `1PANEL_*` iptables prefix so the
// two backends can coexist on hosts that have both binaries installed
// without confusing operators reading `nft list ruleset` or
// `iptables-save`.

const (
	InetFamily = "inet"
	IPFamily   = "ip"

	FilterTable = "1panel"
	NatTable    = "1panel_nat"

	ChainPanelBefore = "panel_before"
	ChainPanelBasic  = "panel_basic"
	ChainPanelAfter  = "panel_after"

	ChainInput       = "input"
	ChainForward     = "forward"
	ChainPreRouting  = "prerouting"
	ChainPostRouting = "postrouting"

	ChainPanelForward = "panel_forward"
	ChainPanelPre     = "panel_pre"
	ChainPanelPost    = "panel_post"
)

// InetHookInput / NatHookPre / NatHookPost are the nft chain-declaration
// specs for the three kernel hooks 1Panel attaches to. `policy accept` is
// chosen deliberately: a broken or empty 1panel deployment must never
// leave the host with INPUT default DROP. Operators who want a final
// drop get it by adding rules to panel_after, not by flipping the chain
// default.
const (
	InetHookInput = "type filter hook input priority filter; policy accept;"
	NatHookPre    = "type nat hook prerouting priority dstnat; policy accept;"
	NatHookPost   = "type nat hook postrouting priority srcnat; policy accept;"
)

// HasNft reports whether the nft binary is installed on the host.
func HasNft() bool {
	return cmd.Which("nft")
}

// Run executes `nft <args>` with sudo, 60 s timeout, returning stdout
// and any non-zero exit error. Errors carry the command and captured
// output for diagnosis.
func Run(args string) (string, error) {
	mgr := cmd.NewCommandMgr(cmd.WithTimeout(60 * time.Second))
	stdout, err := mgr.RunWithStdoutBashCf("%s nft %s", cmd.SudoHandleCmd(), args)
	if err != nil {
		global.LOG.Errorf("nft command failed [args=%s]: %v", args, err)
		return stdout, err
	}
	return stdout, nil
}

// RunNoError is Run that swallows the error — useful for commands whose
// non-zero exit is semantically "not found" rather than failure (e.g.
// `list table`).
func RunNoError(args string) (string, error) {
	mgr := cmd.NewCommandMgr(cmd.WithIgnoreExist1(), cmd.WithTimeout(60*time.Second))
	return mgr.RunWithStdoutBashCf("%s nft %s", cmd.SudoHandleCmd(), args)
}

// RunSpec streams a multi-line nft spec into `nft -f -`. Used for atomic
// ruleset restores where an in-kernel transaction is required.
func RunSpec(spec string) error {
	escaped := strings.ReplaceAll(spec, "'", "'\\''")
	mgr := cmd.NewCommandMgr(cmd.WithTimeout(60 * time.Second))
	stdout, err := mgr.RunWithStdoutBashCf("printf '%%s' '%s' | %s nft -f -", escaped, cmd.SudoHandleCmd())
	if err != nil {
		return fmt.Errorf("nft -f failed: %v; stdout=%s; spec=%s", err, stdout, spec)
	}
	return nil
}

// TableExists reports whether (family, table) is defined in the current
// nft ruleset.
func TableExists(family, table string) (bool, error) {
	_, err := RunNoError(fmt.Sprintf("list table %s %s", family, table))
	if err == nil {
		return true, nil
	}
	// nft returns exit 1 for missing tables; the helper swallows exit 1
	// already, so a real error here means something is actually wrong.
	return false, err
}

// EnsureTable creates (family, table) if missing. Idempotent.
func EnsureTable(family, table string) error {
	exists, err := TableExists(family, table)
	if err != nil {
		return fmt.Errorf("check table %s %s: %w", family, table, err)
	}
	if exists {
		return nil
	}
	if _, err := Run(fmt.Sprintf("add table %s %s", family, table)); err != nil {
		return fmt.Errorf("add table %s %s: %w", family, table, err)
	}
	return nil
}

// ChainExists reports whether (family, table, chain) is present.
func ChainExists(family, table, chain string) (bool, error) {
	_, err := RunNoError(fmt.Sprintf("list chain %s %s %s", family, table, chain))
	if err == nil {
		return true, nil
	}
	return false, err
}

// EnsureRegularChain creates a user-defined chain (no hook declaration) if
// missing.
func EnsureRegularChain(family, table, chain string) error {
	exists, err := ChainExists(family, table, chain)
	if err != nil {
		return fmt.Errorf("check chain %s %s %s: %w", family, table, chain, err)
	}
	if exists {
		return nil
	}
	if _, err := Run(fmt.Sprintf("add chain %s %s %s", family, table, chain)); err != nil {
		return fmt.Errorf("add chain %s %s %s: %w", family, table, chain, err)
	}
	return nil
}

// EnsureHookChain creates a chain with a kernel-hook declaration
// (`{ type ... hook ... priority ... ; policy ... ; }`). Call only for
// input / prerouting / postrouting chains. If the chain already exists
// the declaration is NOT changed — hook and policy edits on a live chain
// are best done by tearing down and rebuilding the table.
func EnsureHookChain(family, table, chain, hookSpec string) error {
	exists, err := ChainExists(family, table, chain)
	if err != nil {
		return fmt.Errorf("check chain %s %s %s: %w", family, table, chain, err)
	}
	if exists {
		return nil
	}
	if _, err := Run(fmt.Sprintf("add chain %s %s %s { %s }", family, table, chain, hookSpec)); err != nil {
		return fmt.Errorf("add hook chain %s %s %s: %w", family, table, chain, err)
	}
	return nil
}

// FlushChain removes every rule from a chain but keeps the chain itself.
func FlushChain(family, table, chain string) error {
	if _, err := Run(fmt.Sprintf("flush chain %s %s %s", family, table, chain)); err != nil {
		return fmt.Errorf("flush chain %s %s %s: %w", family, table, chain, err)
	}
	return nil
}

// DeleteChain flushes and removes a chain. Chains that are jump targets
// of other chains must have their references removed first; nft will
// refuse otherwise.
func DeleteChain(family, table, chain string) error {
	_ = FlushChain(family, table, chain)
	if _, err := Run(fmt.Sprintf("delete chain %s %s %s", family, table, chain)); err != nil {
		return fmt.Errorf("delete chain %s %s %s: %w", family, table, chain, err)
	}
	return nil
}

// AddRule appends a rule to chain. Returns the full rule spec that was
// issued so callers can correlate it with the handle-annotated output
// of ListChainRulesWithHandle if they need to delete later.
func AddRule(family, table, chain, rule string) error {
	if _, err := Run(fmt.Sprintf("add rule %s %s %s %s", family, table, chain, rule)); err != nil {
		return fmt.Errorf("add rule %q to %s %s %s: %w", rule, family, table, chain, err)
	}
	return nil
}

// InsertRule prepends a rule at position 1 of chain. Used for emergency
// accepts that must fire before any persisted user rule.
func InsertRule(family, table, chain, rule string) error {
	if _, err := Run(fmt.Sprintf("insert rule %s %s %s %s", family, table, chain, rule)); err != nil {
		return fmt.Errorf("insert rule %q to %s %s %s: %w", rule, family, table, chain, err)
	}
	return nil
}

// DeleteRuleByHandle removes the rule whose handle equals h. Handles are
// stable within a chain's lifetime and monotonically increasing.
func DeleteRuleByHandle(family, table, chain string, handle int) error {
	if _, err := Run(fmt.Sprintf("delete rule %s %s %s handle %d", family, table, chain, handle)); err != nil {
		return fmt.Errorf("delete handle %d in %s %s %s: %w", handle, family, table, chain, err)
	}
	return nil
}

// AddJump appends `jump target` to parent; idempotent.
func AddJump(family, table, parent, target string) error {
	existing, err := ListChainRulesWithHandle(family, table, parent)
	if err != nil {
		return err
	}
	needle := fmt.Sprintf("jump %s", target)
	for _, e := range existing {
		if strings.Contains(e.Body, needle) {
			return nil
		}
	}
	return AddRule(family, table, parent, needle)
}

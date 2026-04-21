package nftables

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/global"
)

// Persisted ruleset files. One per nft table, matching the way the
// iptables backend stores per-chain files under the same directory.
//
// Files are plain nft scripts produced by `nft list table ...` so they
// can be inspected or replayed with `nft -f <file>` outside 1Panel.
const (
	FilterFileName = "nftables_filter.nft"
	NatFileName    = "nftables_nat.nft"
)

// SaveTable dumps `family table` into fileName under FirewallDir. Missing
// tables are treated as "no rules" and the file is emptied — this lets
// the load path know not to replay stale state if the table was deleted
// deliberately from the console.
func SaveTable(family, table, fileName string) error {
	dest := path.Join(global.Dir.FirewallDir, fileName)

	exists, err := TableExists(family, table)
	if err != nil {
		return err
	}
	if !exists {
		return os.WriteFile(dest, []byte(""), 0o600)
	}

	stdout, err := Run(fmt.Sprintf("list table %s %s", family, table))
	if err != nil {
		return fmt.Errorf("list table %s %s: %w", family, table, err)
	}
	return os.WriteFile(dest, []byte(stdout), 0o600)
}

// LoadTable applies a previously saved ruleset atomically. The replay
// uses a single nft transaction of the form:
//
//	flush table <family> <table>
//	table <family> <table> { ... chains ... }
//
// so the table is rebuilt from scratch without a window of partial
// state. Absent or empty persistence files are a no-op; callers are
// expected to EnsureTable() + rebuild hook chains afterward when the
// file is empty.
func LoadTable(family, table, fileName string) error {
	src := path.Join(global.Dir.FirewallDir, fileName)
	data, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil
	}

	if err := EnsureTable(family, table); err != nil {
		return err
	}
	script := fmt.Sprintf("flush table %s %s\n%s", family, table, string(data))
	if err := RunSpec(script); err != nil {
		return fmt.Errorf("atomic restore of %s %s failed: %w", family, table, err)
	}
	return nil
}

// SavePath returns the absolute path of fileName inside FirewallDir. Used
// by the driver for logging and by tooling that needs to tail the file.
func SavePath(fileName string) string {
	return path.Join(global.Dir.FirewallDir, fileName)
}

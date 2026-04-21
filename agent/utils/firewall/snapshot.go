package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// Iptables snapshot & heartbeat-rollback.
//
// Destructive iptables operations (chain binds/unbinds, default-policy changes,
// bulk rule rewrites) are preceded by a full iptables-save snapshot. The
// snapshot is written under <FirewallDir>/backup/ with a timestamped name and
// a tag describing the operation. The last snapshotRetention entries are kept;
// older ones are pruned.
//
// Snapshots give us two capabilities:
//   1. Manual recovery: an admin can restore any snapshot via the RestoreSnapshot
//      API when a bad rule leaves the box reachable but misconfigured.
//   2. Heartbeat auto-rollback (opt-in via ArmRollback): after a destructive
//      op the caller arms a timer. If ConfirmRollback is not called within
//      the TTL, the goroutine automatically restores the snapshot. Frontend
//      can render a "keep / revert" confirmation prompt backed by this API.
//
// Rollback is a safety net, not a transaction primitive: it only guarantees
// that the tables go back to the byte-identical state captured by
// iptables-save. Rules inserted by third parties (Docker, fail2ban, …) in the
// same window are captured in the snapshot too, so a rollback will not drop
// their state either.

const (
	snapshotDirName   = "backup"
	snapshotRetention = 10
	rollbackDefaultTTL = 60 * time.Second
)

type SnapshotInfo struct {
	Name      string    `json:"name"`
	Tag       string    `json:"tag"`
	CreatedAt time.Time `json:"createdAt"`
	SizeV4    int64     `json:"sizeV4"`
	SizeV6    int64     `json:"sizeV6"`
}

type pendingRollback struct {
	snapshotName string
	deadline     time.Time
	cancel       context.CancelFunc
}

var (
	rollbackMu      sync.Mutex
	rollbackPending *pendingRollback
)

// CaptureSnapshot runs iptables-save (and ip6tables-save when available),
// storing the output in <FirewallDir>/backup/<ts>_<tag>.v[46]. Returns the
// stem name (without suffix). Callers must propagate any non-nil error and
// skip the destructive operation that motivated the capture — no snapshot
// means no safe recovery path.
func CaptureSnapshot(tag string) (string, error) {
	cleanTag := sanitizeTag(tag)
	dir := path.Join(global.Dir.FirewallDir, snapshotDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create snapshot dir failed: %w", err)
	}
	name := fmt.Sprintf("%s_%s", time.Now().UTC().Format("20060102T150405Z"), cleanTag)

	v4Path := path.Join(dir, name+".v4")
	if err := saveIptables("iptables-save", v4Path); err != nil {
		return "", fmt.Errorf("iptables-save failed: %w", err)
	}
	if cmd.Which("ip6tables-save") {
		v6Path := path.Join(dir, name+".v6")
		if err := saveIptables("ip6tables-save", v6Path); err != nil {
			_ = os.Remove(v4Path)
			return "", fmt.Errorf("ip6tables-save failed: %w", err)
		}
	}
	pruneSnapshots(dir, snapshotRetention)
	global.LOG.Infof("[firewall-snapshot] captured %s", name)
	return name, nil
}

// RestoreSnapshot applies a previously captured snapshot. Restoration uses
// iptables-restore (and ip6tables-restore) which atomically replaces the
// table contents. An ongoing auto-rollback timer for a different snapshot
// is left untouched; use ConfirmRollback first if that is not desired.
func RestoreSnapshot(name string) error {
	if !isSafeSnapshotName(name) {
		return errors.New("invalid snapshot name")
	}
	dir := path.Join(global.Dir.FirewallDir, snapshotDirName)
	v4Path := path.Join(dir, name+".v4")
	if _, err := os.Stat(v4Path); err != nil {
		return fmt.Errorf("snapshot %s missing: %w", name, err)
	}
	if err := restoreIptables("iptables-restore", v4Path); err != nil {
		return fmt.Errorf("iptables-restore failed: %w", err)
	}
	v6Path := path.Join(dir, name+".v6")
	if _, err := os.Stat(v6Path); err == nil && cmd.Which("ip6tables-restore") {
		if err := restoreIptables("ip6tables-restore", v6Path); err != nil {
			global.LOG.Warnf("[firewall-snapshot] ip6tables-restore for %s failed: %v", name, err)
		}
	}
	global.LOG.Infof("[firewall-snapshot] restored %s", name)
	return nil
}

// ListSnapshots returns the stored snapshots newest-first, capped at
// snapshotRetention entries. Missing v6 counterparts are reported as size 0.
func ListSnapshots() ([]SnapshotInfo, error) {
	dir := path.Join(global.Dir.FirewallDir, snapshotDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	infoByName := map[string]*SnapshotInfo{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		stem, suffix, ok := splitSnapshotFile(e.Name())
		if !ok {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		info, exists := infoByName[stem]
		if !exists {
			info = &SnapshotInfo{
				Name:      stem,
				Tag:       extractTag(stem),
				CreatedAt: fi.ModTime(),
			}
			infoByName[stem] = info
		}
		switch suffix {
		case ".v4":
			info.SizeV4 = fi.Size()
		case ".v6":
			info.SizeV6 = fi.Size()
		}
	}
	out := make([]SnapshotInfo, 0, len(infoByName))
	for _, v := range infoByName {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// ArmRollback starts (or replaces) an auto-rollback timer for snapshotName.
// If ConfirmRollback is not called before ttl elapses, the snapshot is
// restored. ttl <= 0 uses rollbackDefaultTTL (60 s). Any previously armed
// rollback is cancelled (not fired) before the new one is set up, so back-
// to-back destructive operations share a single pending rollback.
func ArmRollback(snapshotName string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = rollbackDefaultTTL
	}
	rollbackMu.Lock()
	if rollbackPending != nil {
		rollbackPending.cancel()
		rollbackPending = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	pending := &pendingRollback{
		snapshotName: snapshotName,
		deadline:     time.Now().Add(ttl),
		cancel:       cancel,
	}
	rollbackPending = pending
	rollbackMu.Unlock()

	go func() {
		timer := time.NewTimer(ttl)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			rollbackMu.Lock()
			if rollbackPending != pending {
				rollbackMu.Unlock()
				return
			}
			rollbackPending = nil
			rollbackMu.Unlock()
			global.LOG.Warnf("[firewall-rollback] auto-restoring snapshot %s after %s with no confirm", snapshotName, ttl)
			if err := RestoreSnapshot(snapshotName); err != nil {
				global.LOG.Errorf("[firewall-rollback] auto-restore failed: %v", err)
			}
		}
	}()
}

// ConfirmRollback cancels any pending auto-rollback and returns the snapshot
// name that was pending (empty if none). Call this from the frontend after
// the admin verifies the rule change did not lock them out.
func ConfirmRollback() string {
	rollbackMu.Lock()
	defer rollbackMu.Unlock()
	if rollbackPending == nil {
		return ""
	}
	name := rollbackPending.snapshotName
	rollbackPending.cancel()
	rollbackPending = nil
	return name
}

// PendingRollback returns snapshot name and remaining TTL for the currently
// armed rollback, or "" and 0 when none is armed. Used by the UI to render
// the confirm countdown.
func PendingRollback() (string, time.Duration) {
	rollbackMu.Lock()
	defer rollbackMu.Unlock()
	if rollbackPending == nil {
		return "", 0
	}
	remaining := time.Until(rollbackPending.deadline)
	if remaining < 0 {
		remaining = 0
	}
	return rollbackPending.snapshotName, remaining
}

func saveIptables(bin, dest string) error {
	out, err := cmd.RunDefaultWithStdoutBashCf("%s %s", cmd.SudoHandleCmd(), bin)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, []byte(out), 0o600)
}

func restoreIptables(bin, src string) error {
	return cmd.RunDefaultBashCf("%s %s < %s", cmd.SudoHandleCmd(), bin, src)
}

func pruneSnapshots(dir string, keep int) {
	infos, err := ListSnapshots()
	if err != nil || len(infos) <= keep {
		return
	}
	for _, stale := range infos[keep:] {
		_ = os.Remove(path.Join(dir, stale.Name+".v4"))
		_ = os.Remove(path.Join(dir, stale.Name+".v6"))
	}
}

func splitSnapshotFile(name string) (stem, suffix string, ok bool) {
	for _, s := range []string{".v4", ".v6"} {
		if strings.HasSuffix(name, s) {
			return strings.TrimSuffix(name, s), s, true
		}
	}
	return "", "", false
}

var tagSanitizerDrops = ".,/\\ \t\n\r"

func sanitizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "op"
	}
	var b strings.Builder
	for _, r := range tag {
		if strings.ContainsRune(tagSanitizerDrops, r) {
			continue
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "op"
	}
	if b.Len() > 40 {
		return b.String()[:40]
	}
	return b.String()
}

func isSafeSnapshotName(name string) bool {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func extractTag(stem string) string {
	idx := strings.Index(stem, "_")
	if idx < 0 || idx == len(stem)-1 {
		return stem
	}
	return stem[idx+1:]
}

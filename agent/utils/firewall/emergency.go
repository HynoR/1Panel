package firewall

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// Emergency caller-IP temporary ACCEPT.
//
// When a client invokes a firewall-changing API, the middleware calls
// RegisterCallerIP with the client's RemoteAddr. This inserts a top-priority
// ACCEPT rule for that IP into iptables (and ip6tables if the caller is v6)
// INPUT chain for 10 minutes. If the user's change accidentally strands their
// SSH session, they still have a 10-minute window to reach the panel from the
// same IP and roll back.
//
// Rules are tagged with a comment `1PANEL_CALLER_<unix_ts>` and a background
// loop evicts expired entries once per minute.
//
// Limitations:
//   - Rules sit at the top of the native INPUT chain, so an ufw or firewalld
//     reload may wipe them. Accepted risk for a best-effort safety net.
//   - Private/loopback/multicast/zero addresses are skipped (no value).

const (
	emergencyCallerTTL       = 10 * time.Minute
	emergencyCallerMinRespin = 30 * time.Second
	emergencyCallerPrefix    = "1PANEL_CALLER_"
)

var (
	callerMu    sync.Mutex
	callerTrack = map[string]time.Time{} // keyed by ip string
)

// RegisterCallerIP injects a 10-minute INPUT ACCEPT rule for the given IP.
// The function is best-effort: any iptables failure is returned but callers
// should NOT fail the user request because this is a safety net, not a
// requirement. Re-entry within 30 s for the same IP is a no-op to avoid
// flooding INPUT with duplicate rules on busy UIs.
func RegisterCallerIP(ip string) error {
	if !shouldProtect(ip) {
		return nil
	}

	callerMu.Lock()
	if last, ok := callerTrack[ip]; ok && time.Since(last) < emergencyCallerMinRespin {
		callerMu.Unlock()
		return nil
	}
	callerTrack[ip] = time.Now()
	callerMu.Unlock()

	ts := time.Now().Unix()
	comment := fmt.Sprintf("%s%d", emergencyCallerPrefix, ts)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid ip %q", ip)
	}
	if parsed.To4() != nil {
		spec := fmt.Sprintf("-s %s/32 -j ACCEPT -m comment --comment \"%s\"", ip, comment)
		return runEmergency("iptables", "-I INPUT 1 "+spec)
	}
	spec := fmt.Sprintf("-s %s/128 -j ACCEPT -m comment --comment \"%s\"", ip, comment)
	return runEmergency("ip6tables", "-I INPUT 1 "+spec)
}

// StartEmergencyCleanup starts a goroutine that evicts expired 1PANEL_CALLER_*
// rules from INPUT every minute. Call once at agent start; the goroutine exits
// when ctx is cancelled.
func StartEmergencyCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupExpiredCallerRules()
			}
		}
	}()
}

func cleanupExpiredCallerRules() {
	deadline := time.Now().Add(-emergencyCallerTTL).Unix()
	for _, bin := range []string{"iptables", "ip6tables"} {
		if bin == "ip6tables" && !cmd.Which("ip6tables") {
			continue
		}
		stdout, err := cmd.RunDefaultWithStdoutBashCf("%s %s -w -t filter -S INPUT", cmd.SudoHandleCmd(), bin)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(stdout, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-A INPUT ") {
				continue
			}
			ts, ok := parseCallerTimestamp(line)
			if !ok || ts >= deadline {
				continue
			}
			delSpec := strings.Replace(line, "-A INPUT ", "-D INPUT ", 1)
			if err := runEmergency(bin, delSpec); err != nil {
				global.LOG.Warnf("evict expired emergency rule failed, line=%q err=%v", line, err)
			}
		}
	}
}

func parseCallerTimestamp(line string) (int64, bool) {
	idx := strings.Index(line, emergencyCallerPrefix)
	if idx < 0 {
		return 0, false
	}
	rest := line[idx+len(emergencyCallerPrefix):]
	end := 0
	for end < len(rest) {
		ch := rest[end]
		if ch < '0' || ch > '9' {
			break
		}
		end++
	}
	if end == 0 {
		return 0, false
	}
	ts, err := strconv.ParseInt(rest[:end], 10, 64)
	if err != nil {
		return 0, false
	}
	return ts, true
}

// shouldProtect returns false for IPs where inserting an emergency rule is
// pointless or dangerous (loopback, link-local, unspecified, multicast,
// broadcast). Private/VPN IPs ARE protected because an admin reaching the
// panel over a private network still benefits from the safety net.
func shouldProtect(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return true
}

func runEmergency(bin, rule string) error {
	_, err := cmd.RunDefaultWithStdoutBashCf("%s %s -w -t filter %s", cmd.SudoHandleCmd(), bin, rule)
	if err != nil {
		return fmt.Errorf("%s %s failed: %w", bin, rule, err)
	}
	return nil
}

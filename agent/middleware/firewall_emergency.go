package middleware

import (
	"net"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	"github.com/gin-gonic/gin"
)

// FirewallEmergencyCallerGuard protects the admin from accidental self-lockout
// when invoking firewall-CHANGE endpoints. Before the handler runs, the
// caller's TCP peer IP is registered for a 10-minute top-priority ACCEPT in
// iptables/ip6tables INPUT. If the handler then installs a rule that would
// strand the admin's SSH session, they still have a 10-minute window to
// reach the panel and roll back.
//
// The guard uses Request.RemoteAddr (not c.ClientIP) to avoid trusting
// forwarded headers that a client could spoof. Failures to inject the rule
// are logged but never block the request — the feature is a best-effort
// safety net, not a prerequisite.
func FirewallEmergencyCallerGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			host = c.Request.RemoteAddr
		}
		host = strings.TrimSpace(host)
		if host != "" && net.ParseIP(host) != nil {
			if err := firewall.RegisterCallerIP(host); err != nil {
				global.LOG.Warnf("[firewall-emergency] register caller IP %s failed: %v", host, err)
			}
		}
		c.Next()
	}
}

package middleware

import (
	"net"

	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	"github.com/gin-gonic/gin"
)

// FirewallEmergency 安全栈 L2（设计稿 §3.5）：变更型防火墙 API 在执行前，
// 给调用方 IP 插一条 10 分钟临时 ACCEPT，确保"误封自己"后仍能打开面板撤销/确认。
//
// 刻意只用 RemoteAddr，不信任 X-Forwarded-For：反代场景下保护的是代理出口而非用户，
// 这是有意选择（见设计稿 §3.5 第 4 点），需在文档中说明。
func FirewallEmergency() gin.HandlerFunc {
	return func(c *gin.Context) {
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			host = c.Request.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			firewall.EnsureCallerAccept(host)
		}
		c.Next()
	}
}

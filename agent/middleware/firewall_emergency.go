package middleware

import (
	"net"

	"github.com/1Panel-dev/1Panel/agent/utils/callerip"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	"github.com/gin-gonic/gin"
)

// FirewallEmergency 安全栈 L2（设计稿 §3.5）：变更型防火墙 API 在执行前，
// 给调用方 IP 插一条 10 分钟临时 ACCEPT，确保"误封自己"后仍能打开面板撤销/确认。
//
// 调用方 IP 由 callerip.Resolve 解析：master 单机部署下 core 经受信 unix socket
// 反代，agent 侧 RemoteAddr 取不到浏览器 IP，改采信 core 注入的 X-1Panel-Caller-Ip；
// node 多节点(TCP)部署下 RemoteAddr 就是真实对端 IP，忽略任何(可伪造的)头。
// 刻意不信任 X-Forwarded-For(反代下指向代理出口而非用户，见设计稿 §3.5 第 4 点)。
// loopback 调用是本机访问，无需紧急放行，跳过。
func FirewallEmergency() gin.HandlerFunc {
	return func(c *gin.Context) {
		if host := callerip.Resolve(c.Request); host != "" {
			if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
				firewall.EnsureCallerAccept(host)
			}
		}
		c.Next()
	}
}

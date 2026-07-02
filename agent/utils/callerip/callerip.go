package callerip

import (
	"net"
	"net/http"
)

// CallerIPHeader 是 core 反代经受信 unix socket 注入的内部头，携带 core 侧看到的
// 真实客户端(管理员浏览器)IP。只在 unix socket 连接上采信，见 Resolve 的信任模型。
const CallerIPHeader = "X-1Panel-Caller-Ip"

// ContextKey 是 FirewallEmergency 中间件把 Resolve 结果写入 gin.Context 的键：
// 同一请求内 handler 直接读取，避免中间件与 handler 各自独立解析。
const ContextKey = "firewallCallerIP"

// Resolve 返回本次请求调用方的真实客户端 IP（无法确定时返回空串）。
//
// 信任模型（务必先读 agent/server/server.go 的监听设置）：
//   - master 单机部署：agent 只监听 root-only 的 unix socket(/etc/1panel/agent.sock)，
//     core 经该 socket 反代 /api/v2。unix socket 连接没有对端 IP，RemoteAddr 解析
//     不出合法 IP(为 "@" 或空)。此时连接必然来自本机 core 反代进程——这是受信的
//     内部通道，故采信 core 注入的 X-1Panel-Caller-Ip。
//   - node 多节点部署：agent 监听 TCP(0.0.0.0:port, mTLS)，RemoteAddr 是真实对端 IP。
//     TCP 上任何 X-1Panel-Caller-Ip 头都可能被网络侧伪造，一律忽略，直接用 RemoteAddr。
//
// 判据即“RemoteAddr 能否解析出合法 IP”：能(TCP)→ 用 RemoteAddr 并忽略所有头；
// 不能(unix socket)→ 采信受信头。刻意不信任 X-Forwarded-For：反代下它指向代理出口
// 而非真实用户，只有 core 经受信 unix socket 注入的 X-1Panel-Caller-Ip 才可信。
func Resolve(r *http.Request) string {
	// TCP 连接：RemoteAddr 是真实对端 IP，直接采用并忽略任何(可伪造的)头。
	if ip := remoteIP(r.RemoteAddr); ip != "" {
		return ip
	}
	// unix socket 连接(受信内部通道)：采信 core 注入的真实客户端 IP。
	if v := r.Header.Get(CallerIPHeader); v != "" {
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// remoteIP 从 RemoteAddr 解析合法 IP；unix socket 下 RemoteAddr 为 "@"/空，返回空串。
func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

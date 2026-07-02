package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

const SockPath = "/etc/1panel/agent.sock"

var (
	LocalAgentProxy *httputil.ReverseProxy
)

func Init() {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	dialUnix := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", SockPath)
	}
	transport := &http.Transport{
		DialContext:         dialUnix,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
	}
	LocalAgentProxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if req.Header.Get("X-Forwarded-Proto") == "" {
				if req.TLS != nil {
					req.Header.Set("X-Forwarded-Proto", "https")
				} else {
					req.Header.Set("X-Forwarded-Proto", "http")
				}
			}
			if req.Header.Get("X-Forwarded-Host") == "" && req.Host != "" {
				req.Header.Set("X-Forwarded-Host", req.Host)
			}
			// 经受信的 root-only unix socket 把 core 看到的真实客户端 IP 传给 agent，
			// 供防火墙紧急放行 / 单 IP 自锁检测使用（unix socket 下 agent 侧 RemoteAddr
			// 取不到浏览器 IP）。刻意只用入站 RemoteAddr，不信任外部 X-Forwarded-For；
			// 先 Del 再 Set，防止外部请求伪造同名头穿透到 agent。
			req.Header.Del("X-1Panel-Caller-Ip")
			if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				if ip := net.ParseIP(host); ip != nil {
					req.Header.Set("X-1Panel-Caller-Ip", ip.String())
				}
			}
			req.URL.Scheme = "http"
			req.URL.Host = "unix"
		},
		Transport: transport,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			rw.WriteHeader(http.StatusBadGateway)
			_, _ = rw.Write([]byte("Bad Gateway: " + err.Error()))
		},
	}
}

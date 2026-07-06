package firewall

import (
	"errors"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// ErrNoFirewall 表示系统未检测到任何受支持的防火墙后端。
var ErrNoFirewall = errors.New("No system firewall service detected (firewalld/ufw/iptables), please check and try again!")

// Mode 显式化防火墙模式（设计稿 §3.1）。
//
//	managed  — 系统无 ufw/firewalld，1Panel 是规则真源，全权管理 iptables（未来 nft）。
//	external — 系统有 ufw/firewalld，1Panel 只通过原生命令读写，不注入自有链到 filter 主路径。
type Mode string

const (
	ModeManaged  Mode = "managed"
	ModeExternal Mode = "external"
)

const (
	ProviderIptables  = "iptables"
	ProviderUfw       = "ufw"
	ProviderFirewalld = "firewalld"
)

// Capabilities 只保留两个真正的运行期变量。其余能力（高级过滤、保底集、
// 严格模式、快照方式等）与 Mode 一一对应，消费方直接按 Mode 分支，不再重复声明为独立能力位。
type Capabilities struct {
	ForwardImpl string `json:"forwardImpl"` // native | panel-nat：端口转发实现方式
	IPv6Rules   bool   `json:"ipv6Rules"`   // 普通规则是否镜像写 ip6tables
}

// ConflictState 用于 ufw+firewalld 同时运行的降级处置（修 C11）。
// 操作接口会因冲突拒绝执行，但 /firewall/base 仍正常返回并携带本字段供前端展示处置指引。
type ConflictState struct {
	HasConflict bool     `json:"hasConflict"`
	Providers   []string `json:"providers"`
	Message     string   `json:"message"`
}

// Provider 是探测结果的进程内表示：选定的 driver + 模式 + 能力 + 冲突态。
type Provider struct {
	name     string
	mode     Mode
	caps     Capabilities
	conflict ConflictState
	client   FirewallClient
}

func (p *Provider) Name() string { return p.name }

func (p *Provider) Mode() Mode { return p.mode }

func (p *Provider) Capabilities() Capabilities { return p.caps }

func (p *Provider) Conflict() ConflictState { return p.conflict }

func (p *Provider) Client() FirewallClient { return p.client }

var (
	probeMu     sync.Mutex
	probeCache  *Provider
	probeExpire time.Time
)

const probeTTL = 60 * time.Second

// Detect 返回当前 provider（带缓存，TTL 60s）。探测结果进程内缓存，
// 不再每请求 cmd.Which 三连探测（修 C12 页面 CPU 飙升）。
// 防火墙启停后须调用 InvalidateProbe 主动失效缓存。
//
// 与 NewFirewallClient 的区别：Detect 永不因 ufw+firewalld 冲突报错，
// 而是把冲突写进 Provider.Conflict()，供 /firewall/base 展示；
// 真正的操作入口 NewFirewallClient 仍会在冲突时拒绝。
func Detect() (*Provider, error) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if probeCache != nil && time.Now().Before(probeExpire) {
		return probeCache, nil
	}
	p, err := detect()
	if err != nil {
		return nil, err
	}
	probeCache = p
	probeExpire = time.Now().Add(probeTTL)
	return p, nil
}

// InvalidateProbe 使探测缓存立即失效（防火墙启停/切换后调用）。
func InvalidateProbe() {
	probeMu.Lock()
	probeCache = nil
	probeExpire = time.Time{}
	probeMu.Unlock()
}

func detect() (*Provider, error) {
	hasFirewalld := cmd.Which("firewalld")
	hasUfw := cmd.Which("ufw")

	switch {
	case hasFirewalld && hasUfw:
		fw, _ := client.NewFirewalld()
		uw, _ := client.NewUfw()
		fwRunning, _ := fw.Status()
		ufwRunning, _ := uw.Status()
		switch {
		case fwRunning && ufwRunning:
			// 都在运行才报冲突；选 firewalld 作为展示 provider，操作侧拒绝。
			p := newExternalProvider(ProviderFirewalld, fw)
			p.conflict = ConflictState{
				HasConflict: true,
				Providers:   []string{ProviderFirewalld, ProviderUfw},
				Message:     "It is detected that the system has both firewalld and ufw running. To avoid conflicts, please disable one of them and try again!",
			}
			return p, nil
		case ufwRunning && !fwRunning:
			return newExternalProvider(ProviderUfw, uw), nil
		default:
			// 都没运行 → 保持现有 firewalld 优先级。
			return newExternalProvider(ProviderFirewalld, fw), nil
		}
	case hasFirewalld:
		fw, _ := client.NewFirewalld()
		return newExternalProvider(ProviderFirewalld, fw), nil
	case hasUfw:
		uw, _ := client.NewUfw()
		return newExternalProvider(ProviderUfw, uw), nil
	}

	if cmd.Which("iptables") {
		ipt, _ := client.NewIptables()
		return newManagedProvider(ProviderIptables, ipt), nil
	}
	return nil, ErrNoFirewall
}

func newManagedProvider(name string, c FirewallClient) *Provider {
	caps := Capabilities{
		ForwardImpl: "panel-nat",
		IPv6Rules:   iptables.HasIP6tables(),
	}
	return &Provider{name: name, mode: ModeManaged, caps: caps, client: c}
}

func newExternalProvider(name string, c FirewallClient) *Provider {
	caps := Capabilities{
		IPv6Rules: true, // ufw/firewalld 原生双栈
	}
	if name == ProviderFirewalld {
		caps.ForwardImpl = "native"
	} else {
		// ufw 无原生转发能力，1Panel 用 iptables NAT 链实现（现状 C1，UI 需标注）。
		caps.ForwardImpl = "panel-nat"
	}
	return &Provider{name: name, mode: ModeExternal, caps: caps, client: c}
}

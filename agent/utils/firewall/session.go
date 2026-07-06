package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/buserr"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// 安全栈 L3：提交-确认事务（commit-confirm，设计稿 §3.5.1）。
//
// 时序：降低可达性的变更 → 立即应用 + 武装确认窗口（默认 60s）
//      → 用户在面板点"确认保留"（HTTP 请求本身即可达性证明）→ 落定
//      → 窗口超时无人确认（被锁外的人点不到）→ 自动整体还原到会话前。
//
// 还原锚点是武装会话时对全部纳管链拍下的 pre-session 逐链文件（snapshotPreSession），
// 还原即用与开机重放同一套代码把这些文件重载回内核（restorePreSession）。
// 不能拿现役持久化文件当锚点：普通端口/IP 操作"每次操作立即落盘"（applyFilterRule），
// 待确认的危险规则在会话期间就已写进现役文件，直接重载等于没有回滚。
//
// 计时器在 agent 服务端，与前端存活无关；agent 启动时若发现未确认会话标记 → 视同超时立即还原，
// 堵死"变更后 agent 崩溃/重启"的逃逸路径。

const sessionMarkerFile = "session.lock"

const defaultConfirmWindow = 60

// 自动回滚失败 → 会话置 poisoned：内核处于半还原危险态，冻结确认与新变更（防把危险状态
// 落盘/叠加），保留 marker。出路：用户手动点"立即撤销"重试（restorePreSession 幂等）、
// 重启 agent 由 ReclaimSession 兜底、或 1pctl firewall rescue。

// StrictModeSessionSummary 是开启白名单（严格）模式时登记的会话摘要，作为该会话的可辨识标记。
// 关闭白名单（disableStrictMode）据此判定"当前活动会话是否只是这一笔严格变更"，
// 只有这种会话才允许被关闭动作整体 Revert，避免连带回滚窗口内另一笔无关的待确认变更（D3）。
const StrictModeSessionSummary = "enable strict (whitelist) mode"

type SessionChange struct {
	Summary string `json:"summary"`
	At      string `json:"at"`
}

type SessionInfo struct {
	Active        bool            `json:"active"`
	Changes       []SessionChange `json:"changes"`
	RemainSeconds int             `json:"remainSeconds"`
	Since         string          `json:"since"`
	Poisoned      bool            `json:"poisoned"`
}

// sessionMarker 的内容只为排障留痕：回收时只看 marker 文件是否存在（还原锚点是固定的
// pre-session 目录），不再从中读取任何字段。
type sessionMarker struct {
	Changes  []SessionChange `json:"changes"`
	Deadline int64           `json:"deadline"`
	Since    int64           `json:"since"`
}

type sessionState struct {
	mu        sync.Mutex
	active    bool
	changes   []SessionChange
	since     time.Time
	deadline  time.Time
	windowSec int
	timer     *time.Timer
	poisoned  bool
}

var session = &sessionState{windowSec: defaultConfirmWindow}

// BeginSession 登记一笔"降低可达性"的变更并武装/刷新确认窗口。
// 若当前无会话则先拍两份留底作为还原点：latest 全量快照（仅供 rescue CLI 失联自救）与
// pre-session 逐链文件（本会话的回滚锚点）；任一 v4 侧失败即拒绝武装（无锚点不做危险变更）。
// 窗口内的后续变更并入同一会话并刷新计时器。
// 调用方应先登记会话再应用规则；若应用失败且尚未改动规则，由调用方 CancelSession 清理本次会话。
func BeginSession(summary string) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	// poisoned：上次自动回滚失败，内核处于半还原危险态。冻结新变更（并入会话会把新风险
	// 叠在无法回滚的状态上），指引用户先手动撤销/重启 agent/rescue。
	if session.active && session.poisoned {
		return buserr.New("ErrFirewallRevertExhausted")
	}
	if !session.active {
		if err := WriteRescueSnapshot(); err != nil {
			return err
		}
		if err := snapshotPreSession(); err != nil {
			return err
		}
		session.active = true
		session.changes = nil
		session.since = time.Now()
	}
	session.changes = append(session.changes, SessionChange{
		Summary: summary,
		At:      time.Now().Format("2006-01-02 15:04:05"),
	})
	session.deadline = time.Now().Add(time.Duration(session.windowSec) * time.Second)
	session.persistMarkerLocked()
	session.armTimerLocked()
	global.LOG.Infof("[firewall-session] armed confirm window %ds, change: %s", session.windowSec, summary)
	return nil
}

// SessionGuard 封装"武装提交-确认会话 + 失败时撤销幽灵会话"的样板（服务层三处复用）。
// BeginSessionGuard 成功后，若整个操作失败（Finish 收到非 nil 错误）、本会话是新武装的、
// 且期间没有任何内核写入（未 MarkApplied），则 CancelSession 清理，避免"武装会话→写规则前
// 就失败"残留一张 60s 幽灵确认卡片；已有待确认会话或已部分写入时不取消——前者不属于本次，
// 后者需保留会话在超时/崩溃时 RevertSession 兜底。
type SessionGuard struct {
	wasActive bool
	applied   bool
}

// BeginSessionGuard 登记一笔变更并武装/刷新确认窗口（见 BeginSession），返回守卫对象。
func BeginSessionGuard(summary string) (*SessionGuard, error) {
	wasActive := SessionStatus().Active
	if err := BeginSession(summary); err != nil {
		return nil, err
	}
	return &SessionGuard{wasActive: wasActive}, nil
}

// MarkApplied 标记本次操作已向内核写入过规则（此后失败不再撤销会话，交由超时 Revert 兜底）。
// nil 安全：未武装会话（guard 为 nil）时为 no-op。
func (g *SessionGuard) MarkApplied() {
	if g != nil {
		g.applied = true
	}
}

// Finish 在操作结束时调用（defer）：失败且本会话为新武装、失败前零写入时撤销会话。
// reason 为取消日志的操作描述前缀。nil 安全。
func (g *SessionGuard) Finish(reason string, retErr error) {
	if g == nil || retErr == nil || g.wasActive || g.applied {
		return
	}
	CancelSession(fmt.Sprintf("%s failed before any rule was applied: %v", reason, retErr))
}

func (s *sessionState) armTimerLocked() {
	if s.timer != nil {
		s.timer.Stop()
	}
	d := time.Until(s.deadline)
	if d < 0 {
		d = 0
	}
	s.timer = time.AfterFunc(d, func() {
		global.LOG.Warn("[firewall-session] confirm window expired, auto-reverting")
		if err := RevertSession(); err != nil {
			global.LOG.Errorf("[firewall-session] auto-revert failed: %v", err)
		}
	})
}

// ConfirmSession 确认保留：写持久化、清空会话（请求本身即可达性证明）。
func ConfirmSession() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.active {
		return nil
	}
	// poisoned：自动回滚失败过，内核处于半还原危险态。此时绝不能确认——persistManagedChains
	// 会把这份半还原状态落盘并覆盖上次确认的良好持久化文件，令危险规则集在重启/重放后复活（D1）。
	// 拒绝确认，指引用户手动撤销重试、重启 agent 或用 1pctl firewall rescue 恢复。
	if session.poisoned {
		return buserr.New("ErrFirewallRevertExhausted")
	}
	persistManagedChains()
	global.LOG.Infof("[firewall-session] confirmed %d change(s)", len(session.changes))
	session.clearLocked()
	return nil
}

// CancelSession 丢弃尚未发生实际规则写入的新会话，用于写规则前置检查或首次写入失败后的清理。
// 只应在调用方确认本次会话没有任何内核规则变更时使用；已有待确认会话不应被失败的后续请求取消。
func CancelSession(reason string) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.active {
		return
	}
	global.LOG.Warnf("[firewall-session] cancel pending session: %s", reason)
	session.clearLocked()
}

// RevertSession 立即撤销：从 pre-session 逐链文件把全部纳管链重载回会话前状态，并重写持久化文件。
// 全程持锁（与 ConfirmSession 一致）：还原窗口内并发 BeginSession 只会追加到当前会话而非重拍锚点，
// 否则可能出现"SSH accept 已删但新会话被 clearLocked 一并清掉、再无自动回滚"的永久锁外竞态。
// restorePreSession/persistManagedChains 的调用链均不获取 session.mu，持锁执行不会自死锁。
func RevertSession() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.active {
		return nil
	}
	if err := restorePreSession(); err != nil {
		// 还原未完整完成（restorePreSession fail-fast 上报）：绝不能把半还原的内核状态写盘，
		// 否则会覆盖上次确认的良好持久化文件并在重启/重放后复活危险规则集。置 poisoned、保留
		// marker：确认与新变更被冻结（见 ConfirmSession/BeginSession），用户仍可手动"立即撤销"
		// 重试本函数（restorePreSession 幂等，成功即解毒），或重启 agent 走 ReclaimSession 兜底。
		global.LOG.Errorf("[firewall-session] revert failed, session poisoned; keeping marker, not persisting partial state: %v", err)
		session.poisoned = true
		return err
	}
	// 还原成功后重写持久化文件，把会话期间已落盘的未确认变更从现役文件里冲掉。
	persistManagedChains()
	global.LOG.Infof("[firewall-session] reverted %d change(s)", len(session.changes))
	session.clearLocked()
	return nil
}

// SessionStatus 返回未确认会话状态供前端确认卡片轮询。
func SessionStatus() SessionInfo {
	session.mu.Lock()
	defer session.mu.Unlock()
	info := SessionInfo{Active: session.active, Changes: session.changes, Poisoned: session.poisoned}
	if session.active {
		info.Since = session.since.Format("2006-01-02 15:04:05")
		remain := int(time.Until(session.deadline).Seconds())
		if remain < 0 {
			remain = 0
		}
		info.RemainSeconds = remain
	}
	return info
}

// ActiveSessionIsStrictOnly 判定当前活动会话是否"仅由开启白名单（严格）模式"这一/这些变更组成。
// 仅取 mu 读快照、不嵌套其他会话函数，故与 Begin/Confirm/Revert/Status 顺序取锁不会死锁。
// 关闭白名单时据此决定能否整体 Revert：窗口内若混入了别的待确认变更（如某条待确认的 DROP 规则），
// Revert 会把它一并撤销（D3/A4 误伤），此时返回 false 让上层要求用户先确认或撤销。
func ActiveSessionIsStrictOnly() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.active || len(session.changes) == 0 {
		return false
	}
	for _, c := range session.changes {
		if c.Summary != StrictModeSessionSummary {
			return false
		}
	}
	return true
}

func (s *sessionState) clearLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.active = false
	s.changes = nil
	s.deadline = time.Time{}
	s.since = time.Time{}
	s.poisoned = false
	_ = os.Remove(markerPath())
}

func (s *sessionState) persistMarkerLocked() {
	marker := sessionMarker{
		Changes:  s.changes,
		Deadline: s.deadline.Unix(),
		Since:    s.since.Unix(),
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return
	}
	if err := os.WriteFile(markerPath(), data, 0600); err != nil {
		global.LOG.Warnf("[firewall-session] persist marker failed: %v", err)
	}
}

// ReclaimSession 在 agent 启动时调用：若存在未确认会话标记，视同超时立即还原（堵死崩溃逃逸路径）。
// 标记文件存在本身即"有未确认会话"的判据（内容仅为排障留痕），还原锚点是固定的 pre-session 目录。
func ReclaimSession() {
	if _, err := os.Stat(markerPath()); err != nil {
		return
	}
	global.LOG.Warn("[firewall-session] found unconfirmed session on startup, reverting to pre-session state")
	if err := restorePreSession(); err != nil {
		// 启动还原失败：保留标记、不落盘，下次启动再试（评审 P2）。进程重启时 runBootReplay 会跳过，
		// ReclaimSession 是唯一兜底；若此处落盘半还原状态并删标记，则危险规则集既被持久化又永失重试。
		global.LOG.Errorf("[firewall-session] startup revert failed, keeping marker for retry, not persisting partial state: %v", err)
		return
	}
	persistManagedChains()
	_ = os.Remove(markerPath())
}

func markerPath() string {
	return path.Join(global.Dir.FirewallDir, sessionMarkerFile)
}

const preSessionSubDir = "pre-session"

func preSessionRelName(chain string) string {
	return path.Join(preSessionSubDir, iptables.ChainFileName(chain))
}

type chainRef struct {
	tab   string
	chain string
}

// managedChains 是会话机制纳管的全部 1PANEL 链（persistManagedChains 落盘与
// snapshotPreSession/restorePreSession 回滚共用同一清单，保证锚点覆盖面与落盘面一致）。
// 注意：1PANEL_DOCKER 刻意不在此列表内。Docker 规则由 persistDocker（写）+ LoadDockerRules（开机重放）
// 独立维护，与提交-确认会话解耦。若让会话机制读内核 docker 链回写文件，会在开机"链已建空但
// 尚未 LoadDockerRules"的窗口里用空内容覆盖文件而永久丢规则（P1），且与巡检/用户操作存在跨 goroutine
// 竞争。解耦后内核与文件始终由 docker.go（dockerMu 串行）保持一致，不会出现陈旧文件复活。
var managedChains = []chainRef{
	{iptables.FilterTab, iptables.Chain1PanelGuard},
	{iptables.FilterTab, iptables.Chain1PanelDeny},
	{iptables.FilterTab, iptables.Chain1PanelBaseline},
	{iptables.FilterTab, iptables.Chain1PanelAllow},
	{iptables.FilterTab, iptables.Chain1PanelAfter},
	{iptables.FilterTab, iptables.Chain1PanelInput},
	{iptables.FilterTab, iptables.Chain1PanelOutput},
	{iptables.FilterTab, iptables.Chain1PanelForward},
	{iptables.NatTab, iptables.Chain1PanelPreRouting},
	{iptables.NatTab, iptables.Chain1PanelPostRouting},
}

// snapshotPreSession 把全部纳管链的当前内核状态存为 pre-session 逐链文件（本会话唯一回滚锚点）。
// v4 侧失败即上抛（拿不到锚点就拒绝武装会话）；v6 侧与旧快照语义一致 best-effort——
// 捕获失败或链不存在时删除残留副本，revert 侧按"无 v6 副本 → 不动 v6"处理。
// 链不存在时删除 v4 残留副本，revert 侧据此清空该链（capture 对存在的链必写文件，缺文件即权威）。
func snapshotPreSession() error {
	if err := os.MkdirAll(path.Join(global.Dir.FirewallDir, preSessionSubDir), 0700); err != nil {
		return fmt.Errorf("create pre-session dir failed: %w", err)
	}
	for _, item := range managedChains {
		rel := preSessionRelName(item.chain)
		full := path.Join(global.Dir.FirewallDir, rel)
		if exist, _ := iptables.CheckChainExist(item.tab, item.chain); !exist {
			_ = os.Remove(full)
		} else if err := iptables.SaveRulesToFile(item.tab, item.chain, rel); err != nil {
			return fmt.Errorf("capture pre-session state of %s failed: %w", item.chain, err)
		}
		if item.tab != iptables.FilterTab || !iptables.HasIP6tables() {
			continue
		}
		if !iptables.CheckChainExist6(item.tab, item.chain) {
			_ = os.Remove(full + ".v6")
		} else if err := iptables.SaveRulesToFile6(item.tab, item.chain, rel); err != nil {
			global.LOG.Warnf("[firewall-session] capture v6 pre-session state of %s failed: %v", item.chain, err)
			_ = os.Remove(full + ".v6")
		}
	}
	return nil
}

// restorePreSession 把全部纳管链重载回 pre-session 文件记录的状态（与开机重放共用
// Load*RulesFromFile 代码，但用严格版：回滚只完成一部分却报成功会让上层把半还原状态落盘）。
// jump 绑定全程不动——会话武装的操作（端口/IP 规则、开启严格模式）都不改绑定；
// 窗口内其他管理员的 advance 绑定开关不属于本会话，不应被连带回滚（D3/A4 同理）。
func restorePreSession() error {
	for _, item := range managedChains {
		rel := preSessionRelName(item.chain)
		full := path.Join(global.Dir.FirewallDir, rel)
		if _, err := os.Stat(full); os.IsNotExist(err) {
			// 会话开始时该链不存在：清空内核同名链即等效还原（会话期不会新建纳管链，此为兜底）。
			if exist, _ := iptables.CheckChainExist(item.tab, item.chain); exist {
				if err := iptables.ClearChain(item.tab, item.chain); err != nil {
					return fmt.Errorf("clear chain %s failed: %w", item.chain, err)
				}
			}
		} else if err := iptables.LoadRulesFromFileStrict(item.tab, item.chain, rel); err != nil {
			return fmt.Errorf("reload chain %s from pre-session file failed: %w", item.chain, err)
		}
		if item.tab != iptables.FilterTab || !iptables.HasIP6tables() {
			continue
		}
		if _, err := os.Stat(full + ".v6"); err == nil {
			if err := iptables.LoadRulesFromFile6Strict(item.tab, item.chain, rel); err != nil {
				return fmt.Errorf("reload v6 chain %s from pre-session file failed: %w", item.chain, err)
			}
		}
	}
	return nil
}

// persistManagedChains 把当前 managed 模式下的全部 1PANEL 链回写到持久化文件
// （文件名统一由 iptables.ChainFileName 派生，单一真源）。
func persistManagedChains() {
	for _, item := range managedChains {
		file := iptables.ChainFileName(item.chain)
		if exist, _ := iptables.CheckChainExist(item.tab, item.chain); !exist {
			// 链已不存在（如 revert 删掉了本会话新建的转发链）→ 删掉其残留持久化文件，
			// 否则下次开机重放会把已撤销的规则复活，破坏"确认前不落盘"承诺。
			_ = os.Remove(path.Join(global.Dir.FirewallDir, file))
			if item.tab == iptables.FilterTab {
				_ = os.Remove(path.Join(global.Dir.FirewallDir, file+".v6"))
			}
			continue
		}
		if err := iptables.SaveRulesToFile(item.tab, item.chain, file); err != nil {
			global.LOG.Warnf("[firewall-session] persist chain %s failed: %v", item.chain, err)
		}
		// 镜像写 v6（filter 表的链才有 v6 镜像）。
		if item.tab == iptables.FilterTab && iptables.HasIP6tables() && iptables.CheckChainExist6(item.tab, item.chain) {
			_ = iptables.SaveRulesToFile6(item.tab, item.chain, file)
		}
	}
}

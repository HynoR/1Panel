package firewall

import (
	"encoding/json"
	"os"
	"path"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

// 安全栈 L3：提交-确认事务（commit-confirm，设计稿 §3.5.1）。
//
// 时序：降低可达性的变更 → 立即应用 + 自动拍快照 + 武装确认窗口（默认 60s）
//      → 用户在面板点"确认保留"（HTTP 请求本身即可达性证明）→ 落定
//      → 窗口超时无人确认（被锁外的人点不到）→ 自动整体还原到会话前。
//
// 计时器在 agent 服务端，与前端存活无关；agent 启动时若发现未确认会话标记 → 视同超时立即还原，
// 堵死"变更后 agent 崩溃/重启"的逃逸路径。

const sessionMarkerFile = "session.lock"

const defaultConfirmWindow = 60

type SessionChange struct {
	Summary string `json:"summary"`
	At      string `json:"at"`
}

type SessionInfo struct {
	Active        bool            `json:"active"`
	Changes       []SessionChange `json:"changes"`
	RemainSeconds int             `json:"remainSeconds"`
	Since         string          `json:"since"`
	Snapshot      string          `json:"snapshot"`
}

type sessionMarker struct {
	Snapshot string          `json:"snapshot"`
	Changes  []SessionChange `json:"changes"`
	Deadline int64           `json:"deadline"`
	Since    int64           `json:"since"`
}

type sessionState struct {
	mu        sync.Mutex
	active    bool
	snapshot  string
	changes   []SessionChange
	since     time.Time
	deadline  time.Time
	windowSec int
	timer     *time.Timer
}

var session = &sessionState{windowSec: defaultConfirmWindow}

// BeginSession 登记一笔"降低可达性"的变更并武装/刷新确认窗口。
// 若当前无会话则先拍快照作为还原点；窗口内的后续变更并入同一会话并刷新计时器。
// 变更应在调用本函数之前已实际应用（设计稿：立即应用，用户才能在当前连接上验证没锁外）。
func BeginSession(summary string) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	if !session.active {
		snap, err := TakeSnapshot("commit-confirm")
		if err != nil {
			return err
		}
		session.active = true
		session.snapshot = snap
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
	persistManagedChains()
	global.LOG.Infof("[firewall-session] confirmed %d change(s)", len(session.changes))
	session.clearLocked()
	return nil
}

// RevertSession 立即撤销：限定恢复会话前的 1PANEL 链快照，并重写持久化文件。
func RevertSession() error {
	session.mu.Lock()
	snap := session.snapshot
	active := session.active
	session.mu.Unlock()
	if !active {
		return nil
	}
	var err error
	if snap != "" {
		err = RestoreSnapshot(snap)
	}
	// 还原后重写持久化文件，使确认前不落盘的承诺即便经历崩溃也成立。
	persistManagedChains()

	session.mu.Lock()
	session.clearLocked()
	session.mu.Unlock()
	return err
}

// SessionStatus 返回未确认会话状态供前端确认卡片轮询。
func SessionStatus() SessionInfo {
	session.mu.Lock()
	defer session.mu.Unlock()
	info := SessionInfo{Active: session.active, Changes: session.changes, Snapshot: session.snapshot}
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

func (s *sessionState) clearLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.active = false
	s.snapshot = ""
	s.changes = nil
	s.deadline = time.Time{}
	s.since = time.Time{}
	_ = os.Remove(markerPath())
}

func (s *sessionState) persistMarkerLocked() {
	marker := sessionMarker{
		Snapshot: s.snapshot,
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
func ReclaimSession() {
	data, err := os.ReadFile(markerPath())
	if err != nil {
		return
	}
	var marker sessionMarker
	if err := json.Unmarshal(data, &marker); err != nil || marker.Snapshot == "" {
		_ = os.Remove(markerPath())
		return
	}
	global.LOG.Warnf("[firewall-session] found unconfirmed session on startup, reverting snapshot %s", marker.Snapshot)
	if err := RestoreSnapshot(marker.Snapshot); err != nil {
		global.LOG.Errorf("[firewall-session] startup revert failed: %v", err)
	}
	persistManagedChains()
	_ = os.Remove(markerPath())
}

func markerPath() string {
	return path.Join(global.Dir.FirewallDir, sessionMarkerFile)
}

// persistManagedChains 把当前 managed 模式下的全部 1PANEL 链回写到持久化文件。
// 注意：链布局在 PR-3 会变化，届时需同步更新本列表。
func persistManagedChains() {
	type chainFile struct {
		tab   string
		chain string
		file  string
	}
	items := []chainFile{
		{iptables.FilterTab, iptables.Chain1PanelGuard, iptables.GuardFileName},
		{iptables.FilterTab, iptables.Chain1PanelDeny, iptables.DenyFileName},
		{iptables.FilterTab, iptables.Chain1PanelBaseline, iptables.BaselineFileName},
		{iptables.FilterTab, iptables.Chain1PanelAllow, iptables.AllowFileName},
		{iptables.FilterTab, iptables.Chain1PanelAfter, iptables.AfterFileName},
		{iptables.FilterTab, iptables.Chain1PanelInput, iptables.InputFileName},
		{iptables.FilterTab, iptables.Chain1PanelOutput, iptables.OutputFileName},
		{iptables.FilterTab, iptables.Chain1PanelForward, iptables.ForwardFileName},
		{iptables.NatTab, iptables.Chain1PanelPreRouting, iptables.ForwardFileName1},
		{iptables.NatTab, iptables.Chain1PanelPostRouting, iptables.ForwardFileName2},
	}
	// 注意：1PANEL_DOCKER 刻意不在此列表内。Docker 规则由 persistDocker（写）+ LoadDockerRules（开机重放）
	// 独立维护，与提交-确认会话/快照解耦。若让会话机制读内核 docker 链回写文件，会在开机"链已建空但
	// 尚未 LoadDockerRules"的窗口里用空内容覆盖文件而永久丢规则（P1），且与巡检/用户操作存在跨 goroutine
	// 竞争。解耦后内核与文件始终由 docker.go（dockerMu 串行）保持一致，不会出现陈旧文件复活。
	for _, item := range items {
		if exist, _ := iptables.CheckChainExist(item.tab, item.chain); !exist {
			// 链已不存在（如 revert 删掉了本会话新建的转发链）→ 删掉其残留持久化文件，
			// 否则下次开机重放会把已撤销的规则复活，破坏"确认前不落盘"承诺。
			_ = os.Remove(path.Join(global.Dir.FirewallDir, item.file))
			if item.tab == iptables.FilterTab {
				_ = os.Remove(path.Join(global.Dir.FirewallDir, item.file+".v6"))
			}
			continue
		}
		if err := iptables.SaveRulesToFile(item.tab, item.chain, item.file); err != nil {
			global.LOG.Warnf("[firewall-session] persist chain %s failed: %v", item.chain, err)
		}
		// 镜像写 v6（filter 表的链才有 v6 镜像）。
		if item.tab == iptables.FilterTab && iptables.HasIP6tables() && iptables.CheckChainExist6(item.tab, item.chain) {
			_ = iptables.SaveRulesToFile6(item.tab, item.chain, item.file)
		}
	}
}

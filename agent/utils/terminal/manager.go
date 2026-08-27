package terminal

import (
	"errors"
	"slices"
	"sync"
	"time"
)

// Errors returned by the Manager. Callers map them onto business errors.
var (
	// ErrSessionNotFound is returned for an unknown id and for a session that
	// belongs to somebody else. The two cases are deliberately indistinct.
	ErrSessionNotFound = errors.New("terminal session not found")
	// ErrPinDisabled is returned when the keep alive duration is zero.
	ErrPinDisabled = errors.New("terminal session pinning is disabled")
	// ErrPinLimit is returned when the pinned session quota is exhausted.
	ErrPinLimit = errors.New("pinned terminal session limit reached")
)

// Default configuration used until a config provider is installed and whenever
// the provider hands back unusable values.
const (
	DefaultKeepAlive = 30 * time.Minute
	DefaultMaxPinned = 10
)

const (
	// managerInterval is how often detached sessions are reaped and live ones
	// are probed with an ssh keepalive.
	managerInterval = 30 * time.Second
	// keepaliveTimeout bounds one keepalive probe.
	keepaliveTimeout = 10 * time.Second
	// unpinnedGrace is a safety net for detached sessions that are not pinned.
	// Those close themselves as soon as their websocket goes away, so this only
	// catches sessions that were registered but never successfully attached.
	unpinnedGrace = time.Minute
)

// Config drives the session lifetime. It is provided by the service layer so
// that this package never has to reach into the settings repository.
type Config struct {
	// KeepAlive is how long a pinned session survives without a websocket.
	// Zero disables pinning entirely.
	KeepAlive time.Duration
	// MaxPinned is the number of sessions that may be pinned at once.
	MaxPinned int
	// RingSize is the replay buffer capacity in bytes.
	RingSize int
}

// Manager owns every live terminal session of this agent.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	config   func() Config
	now      func() time.Time

	startOnce sync.Once
}

// DefaultManager is the process wide session registry.
var DefaultManager = NewManager()

// NewManager returns an empty registry. The background loop only starts once
// the first session is registered.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		now:      time.Now,
	}
}

// SetConfigProvider installs the function the manager asks for its settings.
// The provider is called lazily, so it may depend on the database being up.
func (m *Manager) SetConfigProvider(fn func() Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = fn
}

// Config returns the current settings, with unusable values replaced by their
// defaults.
func (m *Manager) Config() Config {
	m.mu.Lock()
	fn := m.config
	m.mu.Unlock()

	cfg := Config{KeepAlive: DefaultKeepAlive, MaxPinned: DefaultMaxPinned, RingSize: defaultRingSize}
	if fn != nil {
		cfg = fn()
	}
	cfg.KeepAlive = max(cfg.KeepAlive, 0)
	cfg.MaxPinned = max(cfg.MaxPinned, 0)
	if cfg.RingSize <= 0 {
		cfg.RingSize = defaultRingSize
	}
	return cfg
}

// Register adds s to the registry and makes it remove itself once it closes.
func (m *Manager) Register(s *Session) {
	if s == nil {
		return
	}
	s.SetOnClosed(m.remove)

	m.mu.Lock()
	m.sessions[s.ID] = s
	m.mu.Unlock()

	m.start()

	// The session may have died between its creation and this registration, in
	// which case the hook installed above never fires.
	select {
	case <-s.Done():
		m.remove(s)
	default:
	}
}

// Get returns the session with that id, if it is still alive.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	return sess, ok
}

// List returns a snapshot of the sessions visible to owner, oldest first. An
// empty owner sees everything, and sessions without an owner are visible to
// everybody (the proxy in front of the agent does not always identify callers).
func (m *Manager) List(owner string) []SessionInfo {
	sessions := m.snapshot()
	infos := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		info := sess.Info()
		if !OwnerMatches(info.Owner, owner) {
			continue
		}
		infos = append(infos, info)
	}
	slices.SortFunc(infos, func(a, b SessionInfo) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return infos
}

// Pin pins or unpins a session. Unpinning a detached session closes it, see
// Session.SetPinned.
func (m *Manager) Pin(id, owner string, pinned bool) error {
	sess, err := m.lookup(id, owner)
	if err != nil {
		return err
	}
	if !pinned {
		sess.SetPinned(false)
		return nil
	}

	cfg := m.Config()
	if cfg.KeepAlive <= 0 {
		return ErrPinDisabled
	}
	if m.pinnedCount(sess) >= cfg.MaxPinned {
		return ErrPinLimit
	}
	sess.SetPinned(true)
	return nil
}

// Close terminates a session owned by owner.
func (m *Manager) Close(id, owner string) error {
	sess, err := m.lookup(id, owner)
	if err != nil {
		return err
	}
	sess.Close()
	return nil
}

// OwnerMatches reports whether a caller may act on a session. Either side being
// empty means "unknown", which is treated as a match.
func OwnerMatches(sessionOwner, caller string) bool {
	return sessionOwner == "" || caller == "" || sessionOwner == caller
}

// lookup resolves an id for one caller, hiding foreign sessions.
func (m *Manager) lookup(id, owner string) (*Session, error) {
	sess, ok := m.Get(id)
	if !ok || !OwnerMatches(sess.Owner, owner) {
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

// remove drops s from the registry. It is the session close hook, so it must
// never take a session lock nor block.
func (m *Manager) remove(s *Session) {
	if s == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.sessions[s.ID]; ok && current == s {
		delete(m.sessions, s.ID)
	}
}

// snapshot copies the registered sessions. Everything that may end up calling
// Session.Close works off such a copy, because closing a session calls back
// into remove and would otherwise deadlock on m.mu.
func (m *Manager) snapshot() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, sess := range m.sessions {
		sessions = append(sessions, sess)
	}
	return sessions
}

// pinnedCount counts the pinned sessions, ignoring exclude.
func (m *Manager) pinnedCount(exclude *Session) int {
	count := 0
	for _, sess := range m.snapshot() {
		if sess == exclude {
			continue
		}
		if sess.Pinned() {
			count++
		}
	}
	return count
}

// setNow overrides the clock the reaper reads, for tests.
func (m *Manager) setNow(fn func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = fn
}

func (m *Manager) timeNow() time.Time {
	m.mu.Lock()
	fn := m.now
	m.mu.Unlock()
	if fn == nil {
		return time.Now()
	}
	return fn()
}

// start launches the background loop exactly once.
func (m *Manager) start() {
	m.startOnce.Do(func() { go m.loop() })
}

// loop reaps expired sessions and probes the live ones forever.
func (m *Manager) loop() {
	for range time.Tick(managerInterval) {
		m.reap()
		m.keepaliveAll()
	}
}

// reap closes every detached session whose grace period elapsed.
func (m *Manager) reap() {
	cfg := m.Config()
	now := m.timeNow()
	for _, sess := range m.snapshot() {
		info := sess.Info()
		if info.Attached {
			continue
		}
		// A session that was never attached has no detach timestamp, so its
		// creation time is what the grace period is measured from.
		since := info.DetachedAt
		if since.IsZero() {
			since = info.CreatedAt
		}
		grace := unpinnedGrace
		if info.Pinned {
			grace = cfg.KeepAlive
		}
		if now.Sub(since) >= grace {
			sess.Close()
		}
	}
}

// keepaliveAll probes every session. A probe can block for as long as the
// network takes, so each one runs on its own goroutine under a timeout and a
// failure takes that single session down.
func (m *Manager) keepaliveAll() {
	for _, sess := range m.snapshot() {
		go func() {
			result := make(chan error, 1)
			go func() { result <- sess.keepalive() }()
			select {
			case err := <-result:
				if err != nil {
					sess.Close()
				}
			case <-time.After(keepaliveTimeout):
				sess.Close()
			case <-sess.Done():
			}
		}()
	}
}

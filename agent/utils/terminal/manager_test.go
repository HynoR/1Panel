package terminal

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// newManagedSession returns a session backed by a fake shell, registered in m.
func newManagedSession(t *testing.T, m *Manager, owner string) (*Session, *fakeBackend) {
	t.Helper()
	backend := newFakeBackend()
	sess := newSessionWithBackend(backend, new(safeBuffer), SessionOptions{
		Kind:     SessionKindLocal,
		Owner:    owner,
		Cols:     80,
		Rows:     24,
		RingSize: 4096,
	})
	t.Cleanup(sess.Close)
	m.Register(sess)
	return sess, backend
}

// staticConfig installs a fixed configuration on m.
func staticConfig(m *Manager, cfg Config) {
	m.SetConfigProvider(func() Config { return cfg })
}

func TestManagerRegisterAndGet(t *testing.T) {
	m := NewManager()
	sess, _ := newManagedSession(t, m, "alice")

	got, ok := m.Get(sess.ID)
	if !ok || got != sess {
		t.Fatalf("Get(%q) = %v, %v, want the registered session", sess.ID, got, ok)
	}
	if _, ok := m.Get("nope"); ok {
		t.Error("Get() on an unknown id returned a session")
	}
}

func TestManagerRemovesClosedSession(t *testing.T) {
	m := NewManager()
	sess, _ := newManagedSession(t, m, "alice")

	sess.Close()
	waitFor(t, "session removal", func() bool {
		_, ok := m.Get(sess.ID)
		return !ok
	})
}

func TestManagerRegisterOfAlreadyClosedSession(t *testing.T) {
	m := NewManager()
	backend := newFakeBackend()
	sess := newSessionWithBackend(backend, new(safeBuffer), SessionOptions{Kind: SessionKindLocal, RingSize: 1024})
	sess.Close()

	m.Register(sess)
	if _, ok := m.Get(sess.ID); ok {
		t.Fatal("a session that was closed before Register stayed in the registry")
	}
}

func TestManagerListFiltersByOwner(t *testing.T) {
	m := NewManager()
	alice, _ := newManagedSession(t, m, "alice")
	bob, _ := newManagedSession(t, m, "bob")
	shared, _ := newManagedSession(t, m, "")

	ids := func(infos []SessionInfo) map[string]bool {
		out := make(map[string]bool, len(infos))
		for _, info := range infos {
			out[info.ID] = true
		}
		return out
	}

	all := ids(m.List(""))
	if len(all) != 3 {
		t.Fatalf("List(\"\") returned %d sessions, want 3", len(all))
	}

	mine := ids(m.List("alice"))
	if !mine[alice.ID] || !mine[shared.ID] {
		t.Errorf("List(\"alice\") = %v, want the alice and the ownerless session", mine)
	}
	if mine[bob.ID] {
		t.Errorf("List(\"alice\") leaked bob's session")
	}
}

func TestManagerListIsSortedByCreatedAt(t *testing.T) {
	m := NewManager()
	first, _ := newManagedSession(t, m, "alice")
	time.Sleep(2 * time.Millisecond)
	second, _ := newManagedSession(t, m, "alice")
	time.Sleep(2 * time.Millisecond)
	third, _ := newManagedSession(t, m, "alice")

	infos := m.List("alice")
	want := []string{first.ID, second.ID, third.ID}
	if len(infos) != len(want) {
		t.Fatalf("List() returned %d sessions, want %d", len(infos), len(want))
	}
	for i, info := range infos {
		if info.ID != want[i] {
			t.Fatalf("List()[%d].ID = %q, want %q", i, info.ID, want[i])
		}
	}
}

func TestManagerPinRejectsForeignSession(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: time.Minute, MaxPinned: 5, RingSize: 4096})
	sess, _ := newManagedSession(t, m, "alice")

	if err := m.Pin(sess.ID, "bob", true); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Pin() by a foreign owner = %v, want ErrSessionNotFound", err)
	}
	if err := m.Close(sess.ID, "bob"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Close() by a foreign owner = %v, want ErrSessionNotFound", err)
	}
	if sess.Pinned() {
		t.Error("session got pinned by a foreign owner")
	}
}

func TestManagerPinRejectedWhenDisabled(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: 0, MaxPinned: 5, RingSize: 4096})
	sess, _ := newManagedSession(t, m, "alice")

	if err := m.Pin(sess.ID, "alice", true); !errors.Is(err, ErrPinDisabled) {
		t.Fatalf("Pin() with keep alive 0 = %v, want ErrPinDisabled", err)
	}
	if sess.Pinned() {
		t.Error("session got pinned while pinning is disabled")
	}
}

func TestManagerPinEnforcesLimit(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: time.Minute, MaxPinned: 2, RingSize: 4096})

	var pinned []*Session
	for range 2 {
		sess, _ := newManagedSession(t, m, "alice")
		if err := m.Pin(sess.ID, "alice", true); err != nil {
			t.Fatalf("Pin() = %v, want nil", err)
		}
		pinned = append(pinned, sess)
	}

	extra, _ := newManagedSession(t, m, "alice")
	if err := m.Pin(extra.ID, "alice", true); !errors.Is(err, ErrPinLimit) {
		t.Fatalf("Pin() over the limit = %v, want ErrPinLimit", err)
	}

	// Freeing one slot lets the next pin through.
	if err := m.Pin(pinned[0].ID, "alice", false); err != nil {
		t.Fatalf("unpin = %v, want nil", err)
	}
	if err := m.Pin(extra.ID, "alice", true); err != nil {
		t.Fatalf("Pin() after freeing a slot = %v, want nil", err)
	}
}

func TestManagerUnpinClosesDetachedSession(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: time.Minute, MaxPinned: 5, RingSize: 4096})
	sess, backend := newManagedSession(t, m, "alice")

	if err := m.Pin(sess.ID, "alice", true); err != nil {
		t.Fatalf("Pin() = %v, want nil", err)
	}
	if err := m.Pin(sess.ID, "alice", false); err != nil {
		t.Fatalf("unpin = %v, want nil", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("unpinning a detached session did not close it")
	}
	waitFor(t, "backend close", backend.isClosed)
	waitFor(t, "session removal", func() bool {
		_, ok := m.Get(sess.ID)
		return !ok
	})
}

func TestManagerUnpinKeepsAttachedSession(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: time.Minute, MaxPinned: 5, RingSize: 4096})

	backend := newFakeBackend()
	sess := newSessionWithBackend(backend, new(safeBuffer), SessionOptions{
		Kind: SessionKindLocal, Owner: "alice", Cols: 80, Rows: 24, RingSize: 4096,
	})
	t.Cleanup(sess.Close)
	m.Register(sess)

	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	if err := m.Pin(sess.ID, "alice", true); err != nil {
		t.Fatalf("Pin() = %v, want nil", err)
	}
	if err := m.Pin(sess.ID, "alice", false); err != nil {
		t.Fatalf("unpin = %v, want nil", err)
	}
	select {
	case <-sess.Done():
		t.Fatal("unpinning an attached session closed it")
	case <-time.After(200 * time.Millisecond):
	}

	// Once the websocket leaves, the now unpinned session dies as usual.
	_ = conn.Close()
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("unpinned session survived the loss of its websocket")
	}
}

func TestManagerCloseTerminatesSession(t *testing.T) {
	m := NewManager()
	sess, backend := newManagedSession(t, m, "alice")

	if err := m.Close(sess.ID, "alice"); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	waitFor(t, "backend close", backend.isClosed)
	if err := m.Close(sess.ID, "alice"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Close() twice = %v, want ErrSessionNotFound", err)
	}
}

func TestManagerReapClosesExpiredPinnedSessions(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: 10 * time.Minute, MaxPinned: 5, RingSize: 4096})

	now := time.Now()
	m.setNow(func() time.Time { return now })

	expired, expiredBackend := newManagedSession(t, m, "alice")
	fresh, freshBackend := newManagedSession(t, m, "alice")
	for _, sess := range []*Session{expired, fresh} {
		if err := m.Pin(sess.ID, "alice", true); err != nil {
			t.Fatalf("Pin() = %v, want nil", err)
		}
	}
	// Both sessions are detached; only one of them long enough to expire.
	expired.mu.Lock()
	expired.detachedAt = now.Add(-11 * time.Minute)
	expired.mu.Unlock()
	fresh.mu.Lock()
	fresh.detachedAt = now.Add(-1 * time.Minute)
	fresh.mu.Unlock()

	m.reap()

	select {
	case <-expired.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("reap() did not close the expired session")
	}
	waitFor(t, "expired backend close", expiredBackend.isClosed)

	select {
	case <-fresh.Done():
		t.Fatal("reap() closed a session that is still within its keep alive")
	default:
	}
	if freshBackend.isClosed() {
		t.Fatal("reap() closed the backend of a live session")
	}
	if _, ok := m.Get(expired.ID); ok {
		t.Error("the reaped session is still registered")
	}
	if _, ok := m.Get(fresh.ID); !ok {
		t.Error("the live session was dropped from the registry")
	}
}

func TestManagerReapClosesStrandedUnpinnedSessions(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: 10 * time.Minute, MaxPinned: 5, RingSize: 4096})

	now := time.Now()
	m.setNow(func() time.Time { return now })

	stranded, _ := newManagedSession(t, m, "alice")
	stranded.mu.Lock()
	stranded.createdAt = now.Add(-2 * time.Minute)
	stranded.mu.Unlock()

	recent, _ := newManagedSession(t, m, "alice")

	m.reap()

	select {
	case <-stranded.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("reap() did not close a session that was never attached")
	}
	select {
	case <-recent.Done():
		t.Fatal("reap() closed a freshly created session")
	default:
	}
}

func TestManagerKeepaliveProbesSessions(t *testing.T) {
	m := NewManager()
	sess, backend := newManagedSession(t, m, "alice")

	m.keepaliveAll()
	waitFor(t, "keepalive probe", func() bool { return backend.keepaliveCount() > 0 })
	select {
	case <-sess.Done():
		t.Fatal("a successful keepalive closed the session")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestManagerKeepaliveFailureClosesSession(t *testing.T) {
	m := NewManager()
	sess, backend := newManagedSession(t, m, "alice")
	backend.setKeepaliveErr(errors.New("connection lost"))

	m.keepaliveAll()

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a failing keepalive did not close the session")
	}
	waitFor(t, "session removal", func() bool {
		_, ok := m.Get(sess.ID)
		return !ok
	})
}

func TestManagerConfigFallsBackToDefaults(t *testing.T) {
	m := NewManager()
	cfg := m.Config()
	if cfg.KeepAlive != DefaultKeepAlive || cfg.MaxPinned != DefaultMaxPinned || cfg.RingSize != defaultRingSize {
		t.Fatalf("Config() without a provider = %+v, want the package defaults", cfg)
	}

	staticConfig(m, Config{KeepAlive: -time.Minute, MaxPinned: -1, RingSize: 0})
	cfg = m.Config()
	if cfg.KeepAlive != 0 || cfg.MaxPinned != 0 || cfg.RingSize != defaultRingSize {
		t.Fatalf("Config() with unusable values = %+v, want them clamped", cfg)
	}
}

func TestManagerConcurrentRegisterAndClose(t *testing.T) {
	m := NewManager()
	staticConfig(m, Config{KeepAlive: time.Minute, MaxPinned: 100, RingSize: 4096})

	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			backend := newFakeBackend()
			sess := newSessionWithBackend(backend, new(safeBuffer), SessionOptions{
				Kind: SessionKindLocal, Owner: "alice", Cols: 80, Rows: 24, RingSize: 1024,
			})
			m.Register(sess)
			_ = m.Pin(sess.ID, "alice", true)
			m.List("alice")
			m.reap()
			_ = m.Close(sess.ID, "alice")
			sess.Close()
		})
	}
	wg.Wait()

	waitFor(t, "empty registry", func() bool { return len(m.List("")) == 0 })
}

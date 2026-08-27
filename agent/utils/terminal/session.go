package terminal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/i18n"
	terminalai "github.com/1Panel-dev/1Panel/agent/utils/terminal/ai"
	"github.com/gorilla/websocket"
	gossh "golang.org/x/crypto/ssh"
)

// Session kinds handled by this package.
const (
	SessionKindLocal = "local"
	SessionKindSSH   = "ssh"
)

// closeCodeAttachedElsewhere is sent to a websocket that gets kicked because
// another websocket attached to the same session.
const closeCodeAttachedElsewhere = 4409

// comboFlushInterval is the output coalescing interval.
const comboFlushInterval = 60 * time.Millisecond

// logoutOutput is the shell output that marks a finished login shell.
var logoutOutput = []byte{13, 10, 108, 111, 103, 111, 117, 116, 13, 10}

var errSessionClosed = errors.New("terminal session is closed")

// shellBackend is the interactive shell a Session drives. It is an interface so
// that the session logic can be exercised without a real ssh server.
type shellBackend interface {
	Write(p []byte) (int, error)
	Resize(cols, rows int) error
	Wait() error
	Close() error
}

// SessionOptions describes a session that is about to be created.
type SessionOptions struct {
	Kind     string
	HostID   uint
	Title    string
	Owner    string
	Cols     int
	Rows     int
	InitCmd  string
	RingSize int
}

// SessionInfo is an immutable view of a session state.
type SessionInfo struct {
	ID           string
	Kind         string
	HostID       uint
	Title        string
	Owner        string
	Pinned       bool
	Attached     bool
	CreatedAt    time.Time
	LastActiveAt time.Time
	DetachedAt   time.Time
}

// Session owns one shell and its output buffer. A websocket connection is only
// an attachment on top of it and can come and go without killing the shell.
type Session struct {
	ID     string
	Kind   string
	HostID uint
	Title  string
	Owner  string

	mu           sync.Mutex
	pinned       bool
	createdAt    time.Time
	lastActiveAt time.Time
	detachedAt   time.Time
	cols         int
	rows         int
	attached     *attachment

	backend shellBackend
	combo   *safeBuffer
	ring    *ringBuffer

	lang          string
	aiInterceptor *aiInputInterceptor
	aiVersion     uint64

	done      chan struct{}
	closeOnce sync.Once
	onClosed  func(*Session)
}

// NewSession opens a shell on client and starts buffering its output.
func NewSession(client *gossh.Client, opts SessionOptions) (*Session, error) {
	combo := new(safeBuffer)
	backend, err := newSSHBackend(client, opts.Cols, opts.Rows, opts.InitCmd, combo)
	if err != nil {
		return nil, err
	}
	return newSessionWithBackend(backend, combo, opts), nil
}

// newSessionWithBackend wires an already started backend into a session and
// launches its output pump and shell watcher.
func newSessionWithBackend(backend shellBackend, out *safeBuffer, opts SessionOptions) *Session {
	now := time.Now()
	lang := i18n.GetLanguageFromDB()
	sess := &Session{
		ID:     newSessionID(),
		Kind:   opts.Kind,
		HostID: opts.HostID,
		Title:  opts.Title,
		Owner:  opts.Owner,

		createdAt:    now,
		lastActiveAt: now,
		cols:         opts.Cols,
		rows:         opts.Rows,

		backend: backend,
		combo:   out,
		ring:    newRingBuffer(opts.RingSize),

		lang:          lang,
		aiInterceptor: newAIInputInterceptor("", lang),
		aiVersion:     terminalai.CurrentTerminalRuntimeVersion(),

		done: make(chan struct{}),
	}
	go sess.pump()
	go sess.waitBackend()
	return sess
}

func newSessionID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// Done is closed once the session is terminated.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// SetOnClosed registers a hook invoked once when the session terminates.
func (s *Session) SetOnClosed(fn func(*Session)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onClosed = fn
}

// SetPinned marks the session as surviving the loss of its attachment.
func (s *Session) SetPinned(pinned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned = pinned
}

// Pinned reports whether the session survives the loss of its attachment.
func (s *Session) Pinned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pinned
}

// IsAttached reports whether a websocket is currently bound to the session.
func (s *Session) IsAttached() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attached != nil
}

// Info returns a snapshot of the session state.
func (s *Session) Info() SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionInfo{
		ID:           s.ID,
		Kind:         s.Kind,
		HostID:       s.HostID,
		Title:        s.Title,
		Owner:        s.Owner,
		Pinned:       s.pinned,
		Attached:     s.attached != nil,
		CreatedAt:    s.createdAt,
		LastActiveAt: s.lastActiveAt,
		DetachedAt:   s.detachedAt,
	}
}

// Attach binds ws to the session, kicking any previous attachment. The caller
// owns the returned attachment and must run it.
func (s *Session) Attach(ws *websocket.Conn, cols, rows int) (*attachment, error) {
	if ws == nil {
		return nil, errors.New("nil websocket connection")
	}
	att := &attachment{sess: s, ws: ws, done: make(chan struct{})}

	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, errSessionClosed
	default:
	}
	previous := s.attached
	s.attached = att
	if cols > 0 {
		s.cols = cols
	}
	if rows > 0 {
		s.rows = rows
	}
	s.detachedAt = time.Time{}
	s.lastActiveAt = time.Now()
	pinned := s.pinned
	newCols, newRows := s.cols, s.rows
	// Hold the write lock before releasing the session lock so that the hello
	// message and the replay always reach the client before any live output.
	att.writeMu.Lock()
	s.mu.Unlock()

	if previous != nil {
		previous.close(closeCodeAttachedElsewhere, "attached elsewhere")
	}

	err := func() error {
		defer att.writeMu.Unlock()
		hello, err := json.Marshal(WsMsg{Type: WsMsgSession, ID: s.ID, Pinned: &pinned})
		if err != nil {
			return err
		}
		if err := att.writeLocked(websocket.TextMessage, hello); err != nil {
			return err
		}
		replay := s.ring.Snapshot()
		if len(replay) == 0 {
			return nil
		}
		wsData, err := json.Marshal(WsMsg{Type: WsMsgCmd, Data: base64.StdEncoding.EncodeToString(replay)})
		if err != nil {
			return err
		}
		return att.writeLocked(websocket.TextMessage, wsData)
	}()
	if err != nil {
		att.close(websocket.CloseInternalServerErr, "attach failed")
		s.mu.Lock()
		if s.attached == att {
			s.attached = nil
		}
		s.mu.Unlock()
		return nil, err
	}

	if err := s.backend.Resize(newCols, newRows); err != nil {
		global.LOG.Errorf("ssh pty change windows size failed, err: %v", err)
	}
	return att, nil
}

// onAttachmentClosed is called once the attachment loop returned.
func (s *Session) onAttachmentClosed(a *attachment) {
	s.mu.Lock()
	if s.attached != a {
		s.mu.Unlock()
		return
	}
	s.attached = nil
	pinned := s.pinned
	if pinned {
		s.detachedAt = time.Now()
	}
	s.mu.Unlock()

	if !pinned {
		s.Close()
	}
}

// Close terminates the shell and any current attachment. It is idempotent and
// safe to call from any goroutine.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.backend != nil {
			_ = s.backend.Close()
		}
		s.mu.Lock()
		att := s.attached
		s.attached = nil
		onClosed := s.onClosed
		s.mu.Unlock()

		if att != nil {
			att.close(websocket.CloseNormalClosure, "")
		}
		if onClosed != nil {
			onClosed(s)
		}
	})
}

// resize forwards a window size change to the shell.
func (s *Session) resize(cols, rows int) {
	s.mu.Lock()
	s.cols = cols
	s.rows = rows
	s.lastActiveAt = time.Now()
	s.mu.Unlock()
	if err := s.backend.Resize(cols, rows); err != nil {
		global.LOG.Errorf("ssh pty change windows size failed, err: %v", err)
	}
}

// writeInput forwards client input to the shell stdin.
func (s *Session) writeInput(data []byte) {
	s.mu.Lock()
	s.lastActiveAt = time.Now()
	s.mu.Unlock()
	if _, err := s.backend.Write(data); err != nil {
		global.LOG.Errorf("ws cmd bytes write to ssh.stdin pipe failed, err: %v", err)
	}
}

// ensureAIInterceptor rebuilds the interceptor when the terminal ai runtime
// settings changed since the session was created.
func (s *Session) ensureAIInterceptor() *aiInputInterceptor {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aiInterceptor != nil {
		return s.aiInterceptor
	}
	currentVersion := terminalai.CurrentTerminalRuntimeVersion()
	if s.aiVersion == currentVersion {
		return s.aiInterceptor
	}
	s.aiVersion = currentVersion
	s.aiInterceptor = newAIInputInterceptor("", s.lang)
	return s.aiInterceptor
}

// pump coalesces shell output every comboFlushInterval, stores it in the replay
// ring and forwards it to the current attachment.
func (s *Session) pump() {
	defer func() {
		if r := recover(); r != nil {
			global.LOG.Errorf("a panic occurred during send combo output, error message: %v", r)
		}
	}()
	tick := time.NewTicker(comboFlushInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			bs := s.combo.Take()
			if len(bs) == 0 {
				continue
			}
			if _, err := s.ring.Write(bs); err != nil {
				global.LOG.Errorf("combo output to ring buffer failed, err: %v", err)
			}
			s.deliver(bs)
			if bytes.Equal(bs, logoutOutput) {
				s.Close()
				return
			}
		}
	}
}

// deliver sends one output chunk to the current attachment. A failing write
// only drops that attachment, the session keeps running.
func (s *Session) deliver(data []byte) {
	s.mu.Lock()
	att := s.attached
	s.lastActiveAt = time.Now()
	s.mu.Unlock()
	if att == nil {
		return
	}
	wsData, err := json.Marshal(WsMsg{Type: WsMsgCmd, Data: base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		global.LOG.Errorf("encoding combo output to json failed, err: %v", err)
		return
	}
	if err := att.write(websocket.TextMessage, wsData); err != nil {
		global.LOG.Errorf("ssh sending combo output to webSocket failed, err: %v", err)
		att.close(websocket.CloseInternalServerErr, "write failed")
	}
}

// waitBackend closes the session once the remote shell exited.
func (s *Session) waitBackend() {
	_ = s.backend.Wait()
	s.Close()
}

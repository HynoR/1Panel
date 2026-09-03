package terminal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/i18n"
	terminalai "github.com/1Panel-dev/1Panel/agent/utils/terminal/ai"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	gossh "golang.org/x/crypto/ssh"
)

// Lifetime rules. A session is bound to the browser tab that opened it:
//   - the client closes its websocket with 1000  -> the shell is closed at once
//   - the websocket drops any other way          -> the shell waits graceTimeout for a reattach
//
// ponytail: all fixed; promote to settings only if someone asks.
var (
	graceTimeout      = 2 * time.Minute
	keepaliveInterval = 30 * time.Second
	keepaliveTimeout  = 10 * time.Second
	pumpInterval      = 60 * time.Millisecond
)

// closeCodeAttachedElsewhere is sent to the old websocket when a new one attaches.
const closeCodeAttachedElsewhere = 4409

var errSessionClosed = errors.New("terminal session is closed")

// shellBackend is the interactive shell a Session drives.
type shellBackend interface {
	Write(p []byte) (int, error)
	Resize(cols, rows int) error
	Keepalive() error
	Wait() error
	Close() error
}

// SessionOptions describes a session that is about to be created.
type SessionOptions struct {
	Owner   string
	Cols    int
	Rows    int
	InitCmd string
}

// Session owns one shell; a websocket is only a detachable attachment.
type Session struct {
	ID    string
	Owner string

	mu       sync.Mutex
	attached *attachment
	grace    *time.Timer
	cols     int
	rows     int

	backend shellBackend
	ring    *ringBuffer

	lang          string
	aiInterceptor *aiInputInterceptor
	aiVersion     uint64

	done      chan struct{}
	closeOnce sync.Once
	onClosed  func()
}

// Open starts a shell on client and registers the session.
func Open(client *gossh.Client, opts SessionOptions) (*Session, error) {
	ring := newRingBuffer(ringSize)
	backend, err := newSSHBackend(client, opts.Cols, opts.Rows, opts.InitCmd, ring)
	if err != nil {
		return nil, err
	}
	return newSession(backend, ring, opts), nil
}

// newSession registers the session and starts its goroutines.
func newSession(backend shellBackend, ring *ringBuffer, opts SessionOptions) *Session {
	lang := i18n.GetLanguageFromDB()
	s := &Session{
		ID:            uuid.NewString(),
		Owner:         opts.Owner,
		cols:          opts.Cols,
		rows:          opts.Rows,
		backend:       backend,
		ring:          ring,
		lang:          lang,
		aiInterceptor: newAIInputInterceptor("", lang),
		aiVersion:     terminalai.CurrentTerminalRuntimeVersion(),
		done:          make(chan struct{}),
	}
	register(s)
	go s.pump()
	go s.keepaliveLoop()
	go s.waitBackend()
	return s
}

// Done is closed once the session is terminated.
func (s *Session) Done() <-chan struct{} { return s.done }

// Attached reports whether a websocket is currently bound to the session.
func (s *Session) Attached() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attached != nil
}

// Attach binds ws to the session, kicking any previous attachment, and replays
// the retained output tail before any live output.
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
	if s.grace != nil {
		s.grace.Stop()
		s.grace = nil
	}
	if cols > 0 {
		s.cols = cols
	}
	if rows > 0 {
		s.rows = rows
	}
	cols, rows = s.cols, s.rows
	att.cursor = s.ring.Oldest()
	// Hold writeMu across unlock so hello+replay go out before the pump can write.
	att.writeMu.Lock()
	s.mu.Unlock()

	if previous != nil {
		previous.close(closeCodeAttachedElsewhere, "attached elsewhere")
	}

	err := func() error {
		defer att.writeMu.Unlock()
		hello, err := json.Marshal(WsMsg{Type: WsMsgSession, ID: s.ID})
		if err != nil {
			return err
		}
		if err := att.writeLocked(hello); err != nil {
			return err
		}
		data, next, _ := s.ring.ReadFrom(att.cursor)
		att.cursor = next
		if len(data) == 0 {
			return nil
		}
		return att.writeLocked(cmdMessage(data))
	}()
	if err != nil {
		att.close(websocket.CloseInternalServerErr, "attach failed")
		s.detach(att, false)
		return nil, err
	}

	if err := s.backend.Resize(cols, rows); err != nil {
		global.LOG.Errorf("ssh pty change windows size failed, err: %v", err)
	}
	return att, nil
}

// detach unbinds a. A clean detach closes the shell; a dirty one arms the grace timer.
func (s *Session) detach(a *attachment, clean bool) {
	s.mu.Lock()
	if s.attached != a {
		s.mu.Unlock()
		return
	}
	s.attached = nil
	if !clean {
		s.grace = time.AfterFunc(graceTimeout, s.Close)
	}
	s.mu.Unlock()
	global.LOG.Debugf("terminal session %s detached, clean=%v", s.ID, clean)
	if clean {
		s.Close()
	}
}

// Close terminates the shell and any attachment. Idempotent.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		att := s.attached
		s.attached = nil
		if s.grace != nil {
			s.grace.Stop()
		}
		s.mu.Unlock()
		if att != nil {
			att.close(websocket.CloseNormalClosure, "")
		}
		if err := s.backend.Close(); err != nil {
			global.LOG.Debugf("close terminal backend: %v", err)
		}
		if s.onClosed != nil {
			s.onClosed()
		}
	})
}

// resize forwards a window size change to the shell.
func (s *Session) resize(cols, rows int) {
	s.mu.Lock()
	s.cols, s.rows = cols, rows
	s.mu.Unlock()
	if err := s.backend.Resize(cols, rows); err != nil {
		global.LOG.Errorf("ssh pty change windows size failed, err: %v", err)
	}
}

// writeInput forwards client input to the shell stdin.
func (s *Session) writeInput(data []byte) {
	if _, err := s.backend.Write(data); err != nil {
		global.LOG.Errorf("ws cmd bytes write to ssh.stdin pipe failed, err: %v", err)
	}
}

// ensureAIInterceptor rebuilds the interceptor when AI runtime settings change.
func (s *Session) ensureAIInterceptor() *aiInputInterceptor {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v := terminalai.CurrentTerminalRuntimeVersion(); s.aiInterceptor == nil || s.aiVersion != v {
		s.aiVersion = v
		s.aiInterceptor = newAIInputInterceptor("", s.lang)
	}
	return s.aiInterceptor
}

// pump forwards new ring output to the current attachment.
func (s *Session) pump() {
	defer func() {
		if r := recover(); r != nil {
			global.LOG.Errorf("a panic occurred during send combo output, error message: %v", r)
		}
	}()
	tick := time.NewTicker(pumpInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.flush()
		}
	}
}

// flush sends everything the attachment has not seen yet. A client that fell
// behind the ring skips ahead and is told so; output is never queued unbounded.
func (s *Session) flush() {
	s.mu.Lock()
	att := s.attached
	s.mu.Unlock()
	if att == nil {
		return
	}
	att.writeMu.Lock()
	defer att.writeMu.Unlock()
	data, next, lost := s.ring.ReadFrom(att.cursor)
	if lost {
		notice := "\r\n\x1b[33m" + i18n.GetMsgByKeyAndLang(s.lang, "TerminalOutputTruncated") + "\x1b[m\r\n"
		if err := att.writeLocked(cmdMessage([]byte(notice))); err != nil {
			att.close(websocket.CloseInternalServerErr, "write failed")
			return
		}
	}
	if len(data) == 0 {
		return
	}
	if err := att.writeLocked(cmdMessage(data)); err != nil {
		global.LOG.Errorf("ssh sending combo output to webSocket failed, err: %v", err)
		att.close(websocket.CloseInternalServerErr, "write failed")
		return
	}
	att.cursor = next
}

// keepaliveLoop probes the shell connection; a failed or stuck probe closes the session.
func (s *Session) keepaliveLoop() {
	tick := time.NewTicker(keepaliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			result := make(chan error, 1)
			go func() { result <- s.backend.Keepalive() }()
			select {
			case err := <-result:
				if err != nil {
					global.LOG.Infof("terminal session %s keepalive failed: %v", s.ID, err)
					s.Close()
					return
				}
			case <-time.After(keepaliveTimeout):
				global.LOG.Infof("terminal session %s keepalive timed out", s.ID)
				s.Close()
				return
			case <-s.done:
				return
			}
		}
	}
}

// waitBackend closes the session once the shell exits, after a last flush.
func (s *Session) waitBackend() {
	_ = s.backend.Wait()
	s.flush()
	s.Close()
}

func cmdMessage(data []byte) []byte {
	msg, _ := json.Marshal(WsMsg{Type: WsMsgCmd, Data: base64.StdEncoding.EncodeToString(data)})
	return msg
}

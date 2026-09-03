package terminal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/i18n"
	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestMain(m *testing.M) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	global.LOG = logger
	i18n.Init()
	// the ai interceptor and i18n both read settings from the database
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		panic(err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		panic(err)
	}
	global.DB = db

	// shortened once, before any session exists, so no goroutine races the write
	graceTimeout = 2 * time.Second
	keepaliveInterval = 20 * time.Millisecond
	os.Exit(m.Run())
}

// fakeBackend is an in memory shellBackend used instead of a real ssh session.
type fakeBackend struct {
	mu           sync.Mutex
	input        bytes.Buffer
	cols, rows   int
	keepalives   int
	keepaliveErr error
	closed       bool
	exitedOnce   sync.Once
	exited       chan struct{}
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{exited: make(chan struct{})}
}

func (f *fakeBackend) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.input.Write(p)
}

func (f *fakeBackend) Resize(cols, rows int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cols, f.rows = cols, rows
	return nil
}

func (f *fakeBackend) Keepalive() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keepalives++
	return f.keepaliveErr
}

func (f *fakeBackend) Wait() error {
	<-f.exited
	return nil
}

func (f *fakeBackend) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.exit()
	return nil
}

// exit makes Wait return, the way a remote shell exiting would.
func (f *fakeBackend) exit() { f.exitedOnce.Do(func() { close(f.exited) }) }

func (f *fakeBackend) setKeepaliveErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keepaliveErr = err
}

func (f *fakeBackend) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// newTestSession returns a session backed by fakeBackend and its ring.
func newTestSession(t *testing.T, ringCapacity int) (*Session, *fakeBackend, *ringBuffer) {
	t.Helper()
	backend := newFakeBackend()
	ring := newRingBuffer(ringCapacity)
	sess := newSession(backend, ring, SessionOptions{Owner: "alice", Cols: 80, Rows: 24})
	t.Cleanup(sess.Close)
	return sess, backend, ring
}

var testUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// newTestServer serves websocket attachments for sess.
func newTestServer(t *testing.T, sess *Session) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		att, err := sess.Attach(ws, 80, 24)
		if err != nil {
			_ = ws.Close()
			return
		}
		att.Run()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialTest(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readMsg(t *testing.T, conn *websocket.Conn) WsMsg {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read message failed: %v", err)
	}
	msg := WsMsg{}
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal message %q failed: %v", data, err)
	}
	return msg
}

func readHello(t *testing.T, conn *websocket.Conn, sess *Session) {
	t.Helper()
	msg := readMsg(t, conn)
	if msg.Type != WsMsgSession {
		t.Fatalf("first message type = %q, want %q", msg.Type, WsMsgSession)
	}
	if msg.ID != sess.ID {
		t.Fatalf("hello id = %q, want %q", msg.ID, sess.ID)
	}
}

// readCmd reads the next cmd payload, skipping anything else.
func readCmd(t *testing.T, conn *websocket.Conn) string {
	t.Helper()
	for {
		msg := readMsg(t, conn)
		if msg.Type != WsMsgCmd {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			t.Fatalf("decode output failed: %v", err)
		}
		return string(decoded)
	}
}

func sendMsg(t *testing.T, conn *websocket.Conn, msg WsMsg) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal message failed: %v", err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		t.Fatalf("write message failed: %v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitClosed asserts the session terminates within d.
func waitClosed(t *testing.T, sess *Session, d time.Duration, what string) {
	t.Helper()
	select {
	case <-sess.Done():
	case <-time.After(d):
		t.Fatalf("session still open: %s", what)
	}
}

func TestSessionSurvivesDirtyDisconnectUntilGrace(t *testing.T) {
	sess, _, _ := newTestSession(t, 4096)
	srv := newTestServer(t, sess)

	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	// dirty disconnect: drop the tcp connection without a close frame
	_ = conn.UnderlyingConn().Close()
	waitFor(t, "detach", func() bool { return !sess.Attached() })

	if _, ok := Lookup(sess.ID, "alice"); !ok {
		t.Fatal("Lookup() after a dirty disconnect = not found, want the session")
	}
	select {
	case <-sess.Done():
		t.Fatal("session closed immediately after a dirty disconnect")
	case <-time.After(50 * time.Millisecond):
	}

	waitClosed(t, sess, 3*time.Second, "grace timer did not close it")
	waitFor(t, "registry removal", func() bool {
		_, ok := Lookup(sess.ID, "alice")
		return !ok
	})
}

func TestSessionCleanCloseClosesImmediately(t *testing.T) {
	sess, backend, _ := newTestSession(t, 4096)
	srv := newTestServer(t, sess)

	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	if err := conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("write close failed: %v", err)
	}

	waitClosed(t, sess, 3*time.Second, "close code 1000 did not close it")
	waitFor(t, "backend close", backend.isClosed)
}

func TestSessionReattachReplaysAndKicksFirst(t *testing.T) {
	sess, _, ring := newTestSession(t, 4096)
	srv := newTestServer(t, sess)

	first := dialTest(t, srv)
	readHello(t, first, sess)
	ring.Write([]byte("before\r\n"))
	if got := readCmd(t, first); !strings.Contains(got, "before") {
		t.Fatalf("live output = %q, want it to contain %q", got, "before")
	}

	// a second attachment while the first is still open kicks the first
	second := dialTest(t, srv)
	readHello(t, second, sess)
	if _, _, err := first.ReadMessage(); !websocket.IsCloseError(err, closeCodeAttachedElsewhere) {
		t.Fatalf("first ws error = %v, want close code %d", err, closeCodeAttachedElsewhere)
	}

	// dirty disconnect, output while detached, then reattach
	_ = second.UnderlyingConn().Close()
	waitFor(t, "detach", func() bool { return !sess.Attached() })
	ring.Write([]byte("while-detached\r\n"))

	third := dialTest(t, srv)
	readHello(t, third, sess)
	if got := readCmd(t, third); !strings.Contains(got, "while-detached") {
		t.Fatalf("replay = %q, want it to contain %q", got, "while-detached")
	}
}

func TestSessionSlowReaderGetsTruncatedNotice(t *testing.T) {
	sess, _, ring := newTestSession(t, 256)
	srv := newTestServer(t, sess)

	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	// hold the attachment write lock so the pump cannot drain while the ring wraps
	sess.mu.Lock()
	att := sess.attached
	sess.mu.Unlock()
	att.writeMu.Lock()
	ring.Write([]byte("old stuff that will be dropped\r\n"))
	ring.Write([]byte(strings.Repeat("x", 512) + "\r\ntail-marker\r\n"))
	att.writeMu.Unlock()

	notice := readCmd(t, conn)
	if !strings.Contains(notice, i18n.GetMsgByKeyAndLang("en", "TerminalOutputTruncated")) {
		t.Fatalf("notice = %q, want the truncated message", notice)
	}
	got := readCmd(t, conn)
	if !strings.Contains(got, "tail-marker") {
		t.Fatalf("output = %q, want it to contain %q", got, "tail-marker")
	}
	if strings.Contains(got, "old stuff") {
		t.Fatalf("output = %q, want the dropped head gone", got)
	}
}

func TestSessionClosesOnKeepaliveFailureAndBackendExit(t *testing.T) {
	t.Run("keepalive failure", func(t *testing.T) {
		sess, backend, _ := newTestSession(t, 4096)
		backend.setKeepaliveErr(errors.New("connection lost"))
		waitClosed(t, sess, 3*time.Second, "a failing keepalive did not close it")
	})

	t.Run("backend exit", func(t *testing.T) {
		sess, backend, _ := newTestSession(t, 4096)
		srv := newTestServer(t, sess)
		conn := dialTest(t, srv)
		readHello(t, conn, sess)

		backend.exit()
		waitClosed(t, sess, 3*time.Second, "the shell exiting did not close it")
		_, _, err := conn.ReadMessage()
		if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			t.Fatalf("ws error = %v, want close code %d", err, websocket.CloseNormalClosure)
		}
	})
}

func TestLookupOwner(t *testing.T) {
	owned, _, _ := newTestSession(t, 1024)
	anon := newSession(newFakeBackend(), newRingBuffer(1024), SessionOptions{Cols: 80, Rows: 24})
	t.Cleanup(anon.Close)

	tests := []struct {
		name  string
		sess  *Session
		owner string
		want  bool
	}{
		{"same owner", owned, "alice", true},
		{"other owner", owned, "bob", false},
		{"empty caller", owned, "", true},
		{"empty session owner", anon, "bob", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := Lookup(tc.sess.ID, tc.owner); ok != tc.want {
				t.Errorf("Lookup(%q) ok = %v, want %v", tc.owner, ok, tc.want)
			}
		})
	}
	if _, ok := Lookup("no-such-id", "alice"); ok {
		t.Error("Lookup() of an unknown id = found, want not found")
	}
}

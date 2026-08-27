package terminal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	global.LOG = logger
	os.Exit(m.Run())
}

// fakeBackend is an in memory shellBackend used instead of a real ssh session.
type fakeBackend struct {
	mu             sync.Mutex
	input          bytes.Buffer
	cols           int
	rows           int
	resizes        int
	keepalives     int
	keepaliveErr   error
	keepaliveBlock chan struct{}
	closed         bool
	exited         chan struct{}
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
	f.resizes++
	return nil
}

func (f *fakeBackend) Keepalive() error {
	f.mu.Lock()
	f.keepalives++
	err := f.keepaliveErr
	block := f.keepaliveBlock
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	return err
}

func (f *fakeBackend) keepaliveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keepalives
}

func (f *fakeBackend) setKeepaliveErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keepaliveErr = err
}

func (f *fakeBackend) Wait() error {
	<-f.exited
	return nil
}

func (f *fakeBackend) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.exited)
	}
	return nil
}

func (f *fakeBackend) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeBackend) inputString() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.input.String()
}

func (f *fakeBackend) size() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cols, f.rows
}

// newTestSession returns a session backed by fakeBackend plus the writer the
// backend output is supposed to be written to.
func newTestSession(t *testing.T) (*Session, *fakeBackend, *safeBuffer) {
	t.Helper()
	backend := newFakeBackend()
	out := new(safeBuffer)
	sess := newSessionWithBackend(backend, out, SessionOptions{
		Kind:     SessionKindLocal,
		Title:    "tab-1",
		Owner:    "tester",
		Cols:     80,
		Rows:     24,
		RingSize: 4096,
	})
	t.Cleanup(sess.Close)
	return sess, backend, out
}

var testUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

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

func readHello(t *testing.T, conn *websocket.Conn, sess *Session) WsMsg {
	t.Helper()
	msg := readMsg(t, conn)
	if msg.Type != WsMsgSession {
		t.Fatalf("first message type = %q, want %q", msg.Type, WsMsgSession)
	}
	if msg.ID != sess.ID {
		t.Fatalf("hello id = %q, want %q", msg.ID, sess.ID)
	}
	return msg
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

func TestSessionAttachSendsHelloFirst(t *testing.T) {
	sess, _, _ := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)

	msg := readHello(t, conn, sess)
	if msg.Pinned == nil || *msg.Pinned {
		t.Errorf("hello pinned = %v, want explicit false", msg.Pinned)
	}
	if len(sess.ID) != 32 {
		t.Errorf("session id = %q, want 32 hex chars", sess.ID)
	}
	if !sess.IsAttached() {
		t.Error("IsAttached() = false, want true")
	}
}

func TestSessionForwardsBackendOutput(t *testing.T) {
	sess, _, out := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	if _, err := out.Write([]byte("hello world\r\n")); err != nil {
		t.Fatalf("write to backend output failed: %v", err)
	}

	msg := readMsg(t, conn)
	if msg.Type != WsMsgCmd {
		t.Fatalf("message type = %q, want %q", msg.Type, WsMsgCmd)
	}
	decoded, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		t.Fatalf("decode data failed: %v", err)
	}
	if string(decoded) != "hello world\r\n" {
		t.Fatalf("decoded output = %q, want %q", decoded, "hello world\r\n")
	}
	waitFor(t, "ring buffer content", func() bool {
		return string(sess.ring.Snapshot()) == "hello world\r\n"
	})
}

func TestSessionClientCommandReachesBackend(t *testing.T) {
	sess, backend, _ := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	sendMsg(t, conn, WsMsg{Type: WsMsgCmd, Data: base64.StdEncoding.EncodeToString([]byte("ls -al"))})
	waitFor(t, "backend input", func() bool { return backend.inputString() == "ls -al" })
}

func TestSessionResizeReachesBackend(t *testing.T) {
	sess, backend, _ := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	sendMsg(t, conn, WsMsg{Type: WsMsgResize, Cols: 120, Rows: 40})
	waitFor(t, "backend resize", func() bool {
		cols, rows := backend.size()
		return cols == 120 && rows == 40
	})
}

func TestSessionHeartbeatIsEchoed(t *testing.T) {
	sess, _, _ := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	sendMsg(t, conn, WsMsg{Type: WsMsgHeartbeat, Timestamp: 1234})
	msg := readMsg(t, conn)
	if msg.Type != WsMsgHeartbeat || msg.Timestamp != 1234 {
		t.Fatalf("echo = %+v, want heartbeat with timestamp 1234", msg)
	}
}

func TestSessionSecondAttachKicksFirstAndReplays(t *testing.T) {
	sess, _, out := newTestSession(t)
	srv := newTestServer(t, sess)

	first := dialTest(t, srv)
	readHello(t, first, sess)
	if _, err := out.Write([]byte("line one\r\n")); err != nil {
		t.Fatalf("write to backend output failed: %v", err)
	}
	msg := readMsg(t, first)
	if msg.Type != WsMsgCmd {
		t.Fatalf("message type = %q, want %q", msg.Type, WsMsgCmd)
	}

	second := dialTest(t, srv)
	hello := readHello(t, second, sess)
	if hello.Pinned == nil || *hello.Pinned {
		t.Errorf("hello pinned = %v, want explicit false", hello.Pinned)
	}
	replay := readMsg(t, second)
	if replay.Type != WsMsgCmd {
		t.Fatalf("replay type = %q, want %q", replay.Type, WsMsgCmd)
	}
	decoded, err := base64.StdEncoding.DecodeString(replay.Data)
	if err != nil {
		t.Fatalf("decode replay failed: %v", err)
	}
	if string(decoded) != "line one\r\n" {
		t.Fatalf("replay = %q, want %q", decoded, "line one\r\n")
	}

	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err := first.ReadMessage()
		if err == nil {
			continue
		}
		closeErr, ok := err.(*websocket.CloseError)
		if !ok {
			t.Fatalf("first connection error = %v, want websocket close error", err)
		}
		if closeErr.Code != closeCodeAttachedElsewhere {
			t.Fatalf("close code = %d, want %d", closeErr.Code, closeCodeAttachedElsewhere)
		}
		break
	}

	select {
	case <-sess.Done():
		t.Fatal("session closed after the first attachment was kicked")
	case <-time.After(200 * time.Millisecond):
	}
	if !sess.IsAttached() {
		t.Fatal("IsAttached() = false, want true")
	}
}

func TestSessionClosesWhenUnpinnedClientLeaves(t *testing.T) {
	sess, backend, _ := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	_ = conn.Close()

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close after the client left")
	}
	waitFor(t, "backend close", backend.isClosed)
}

func TestSessionSurvivesClientLeaveWhenPinned(t *testing.T) {
	sess, backend, out := newTestSession(t)
	srv := newTestServer(t, sess)
	sess.SetPinned(true)

	first := dialTest(t, srv)
	readHello(t, first, sess)
	if _, err := out.Write([]byte("pinned output\r\n")); err != nil {
		t.Fatalf("write to backend output failed: %v", err)
	}
	if msg := readMsg(t, first); msg.Type != WsMsgCmd {
		t.Fatalf("message type = %q, want %q", msg.Type, WsMsgCmd)
	}
	_ = first.Close()

	waitFor(t, "detach", func() bool { return !sess.IsAttached() })
	select {
	case <-sess.Done():
		t.Fatal("pinned session closed after the client left")
	case <-time.After(200 * time.Millisecond):
	}
	if backend.isClosed() {
		t.Fatal("backend closed for a pinned session")
	}
	info := sess.Info()
	if !info.Pinned {
		t.Error("Info().Pinned = false, want true")
	}
	if info.Attached {
		t.Error("Info().Attached = true, want false")
	}
	if info.DetachedAt.IsZero() {
		t.Error("Info().DetachedAt is zero, want a timestamp")
	}

	second := dialTest(t, srv)
	hello := readHello(t, second, sess)
	if hello.Pinned == nil || !*hello.Pinned {
		t.Errorf("hello pinned = %v, want explicit true", hello.Pinned)
	}
	replay := readMsg(t, second)
	decoded, err := base64.StdEncoding.DecodeString(replay.Data)
	if err != nil {
		t.Fatalf("decode replay failed: %v", err)
	}
	if string(decoded) != "pinned output\r\n" {
		t.Fatalf("replay = %q, want %q", decoded, "pinned output\r\n")
	}
	if sess.Info().DetachedAt != (time.Time{}) {
		t.Error("Info().DetachedAt not cleared after re-attach")
	}
}

func TestSessionCloseIsIdempotentUnderConcurrency(t *testing.T) {
	sess, backend, _ := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	var closed int
	sess.SetOnClosed(func(*Session) { closed++ })

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(sess.Close)
	}
	wg.Wait()

	select {
	case <-sess.Done():
	default:
		t.Fatal("Done() not closed after Close()")
	}
	if !backend.isClosed() {
		t.Fatal("backend not closed after Close()")
	}
	if closed != 1 {
		t.Fatalf("onClosed called %d times, want 1", closed)
	}
	if _, err := sess.Attach(conn, 80, 24); err == nil {
		t.Fatal("Attach() on a closed session returned no error")
	}
}

func TestSessionClosesOnLogoutOutput(t *testing.T) {
	sess, backend, out := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	if _, err := out.Write(logoutOutput); err != nil {
		t.Fatalf("write to backend output failed: %v", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close on logout output")
	}
	waitFor(t, "backend close", backend.isClosed)
}

func TestSessionClosesWhenBackendExits(t *testing.T) {
	sess, backend, _ := newTestSession(t)
	srv := newTestServer(t, sess)
	conn := dialTest(t, srv)
	readHello(t, conn, sess)

	_ = backend.Close()
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close after the backend exited")
	}
}

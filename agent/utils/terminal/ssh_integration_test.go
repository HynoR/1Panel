package terminal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	gossh "golang.org/x/crypto/ssh"
)

// The tests in this file drive the real sshBackend against an in process ssh
// server, so that the ssh specific wiring (pty request, shell, window change,
// global keepalive, client ownership) is covered end to end and not only
// through the fake backend of session_test.go.

// bgTickDelay is how long the fake shell waits before emitting its unsolicited
// line, which is used to produce output while no websocket is attached.
const bgTickDelay = 100 * time.Millisecond

// ptyRequestMsg is the payload of an ssh "pty-req" channel request.
type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

// windowChangeMsg is the payload of an ssh "window-change" channel request.
type windowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

// exitStatusMsg is the payload of an ssh "exit-status" channel request.
type exitStatusMsg struct {
	Status uint32
}

// sshTestServer is a minimal ssh server serving a fake shell. It records the
// last window size it was told about and counts the keepalive global requests
// it answered.
type sshTestServer struct {
	addr       string
	keepalives atomic.Int64

	mu    sync.Mutex
	cols  int
	rows  int
	conns []net.Conn
}

// startSSHServer listens on a loopback port and serves ssh until the test ends.
func startSSHServer(t *testing.T) *sshTestServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key failed: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("build host key signer failed: %v", err)
	}
	config := &gossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	srv := &sshTestServer{addr: listener.Addr().String()}
	go srv.accept(listener, config)
	t.Cleanup(srv.closeConns)
	return srv
}

// accept serves every incoming connection until the listener is closed. It runs
// off the test goroutine, so failures are reported through timing out
// assertions rather than through t.
func (s *sshTestServer) accept(listener net.Listener, config *gossh.ServerConfig) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		go s.serve(conn, config)
	}
}

// serve completes the ssh handshake and dispatches channels and global requests.
func (s *sshTestServer) serve(conn net.Conn, config *gossh.ServerConfig) {
	serverConn, chans, reqs, err := gossh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = serverConn.Close() }()

	go s.handleGlobalRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, channelReqs, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(channel, channelReqs)
	}
}

// handleGlobalRequests answers every global request and counts the keepalives.
func (s *sshTestServer) handleGlobalRequests(reqs <-chan *gossh.Request) {
	for req := range reqs {
		if req.Type == "keepalive@openssh.com" {
			s.keepalives.Add(1)
		}
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	}
}

// handleSession answers the channel requests of one shell session.
func (s *sshTestServer) handleSession(channel gossh.Channel, reqs <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	shellStarted := false
	for req := range reqs {
		ok := false
		switch req.Type {
		case "pty-req":
			var msg ptyRequestMsg
			if err := gossh.Unmarshal(req.Payload, &msg); err == nil {
				s.setWindowSize(int(msg.Columns), int(msg.Rows))
				ok = true
			}
		case "window-change":
			var msg windowChangeMsg
			if err := gossh.Unmarshal(req.Payload, &msg); err == nil {
				s.setWindowSize(int(msg.Columns), int(msg.Rows))
				ok = true
			}
		case "env":
			ok = true
		case "shell":
			ok = true
			if !shellStarted {
				shellStarted = true
				go fakeShell(channel)
			}
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
}

func (s *sshTestServer) setWindowSize(cols, rows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cols, s.rows = cols, rows
}

func (s *sshTestServer) windowSize() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cols, s.rows
}

func (s *sshTestServer) keepaliveCount() int {
	return int(s.keepalives.Load())
}

// closeConns drops every accepted connection, which simulates a dead network.
func (s *sshTestServer) closeConns() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// fakeShell is a line echoing shell. There is no tty line discipline behind an
// ssh channel, so the raw bytes are split on the line terminators themselves.
func fakeShell(channel gossh.Channel) {
	var writeMu sync.Mutex
	write := func(text string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_, _ = io.WriteString(channel, text)
	}

	write("$ ")
	var line strings.Builder
	buf := make([]byte, 256)
	for {
		n, err := channel.Read(buf)
		for _, b := range buf[:n] {
			if b != '\n' && b != '\r' {
				line.WriteByte(b)
				continue
			}
			command := line.String()
			line.Reset()
			switch command {
			case "":
				// A bare terminator, most likely the second half of a CRLF.
			case "exit":
				write("logout\r\n")
				_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(exitStatusMsg{Status: 0}))
				_ = channel.Close()
				return
			case "bg":
				write("echo:bg\r\n$ ")
				go func() {
					time.Sleep(bgTickDelay)
					write("bg:tick\r\n")
				}()
			default:
				write("echo:" + command + "\r\n$ ")
			}
		}
		if err != nil {
			return
		}
	}
}

// dialSSHTest connects to the test server and closes the client when the test
// ends. Closing an already closed client is a no-op, so this stays safe even
// though the session backend owns the client too.
func dialSSHTest(t *testing.T, srv *sshTestServer) *gossh.Client {
	t.Helper()
	client, err := gossh.Dial("tcp", srv.addr, &gossh.ClientConfig{
		User:            "tester",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial failed: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// newSSHTestSession opens a real ssh backed session against a fresh server.
func newSSHTestSession(t *testing.T) (*Session, *sshTestServer, *gossh.Client) {
	t.Helper()
	srv := startSSHServer(t)
	client := dialSSHTest(t, srv)
	sess, err := NewSession(client, SessionOptions{
		Kind:     SessionKindSSH,
		Title:    "ssh-tab",
		Owner:    "alice",
		Cols:     80,
		Rows:     24,
		RingSize: 4096,
	})
	if err != nil {
		t.Fatalf("NewSession() = %v, want nil", err)
	}
	t.Cleanup(sess.Close)
	return sess, srv, client
}

// readOutputUntil accumulates the decoded payload of cmd messages until it
// contains want, and returns everything read so far.
func readOutputUntil(t *testing.T, conn *websocket.Conn, want string) string {
	t.Helper()
	var seen strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		_, data, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read output failed after %q: %v", seen.String(), err)
		}
		msg := WsMsg{}
		if err := json.Unmarshal(data, &msg); err != nil {
			t.Fatalf("unmarshal message %q failed: %v", data, err)
		}
		if msg.Type != WsMsgCmd {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			t.Fatalf("decode output failed: %v", err)
		}
		seen.Write(decoded)
		if strings.Contains(seen.String(), want) {
			return seen.String()
		}
	}
	t.Fatalf("timed out waiting for %q, got %q", want, seen.String())
	return ""
}

// sendCommand writes one shell input line to the session websocket.
func sendCommand(t *testing.T, conn *websocket.Conn, command string) {
	t.Helper()
	sendMsg(t, conn, WsMsg{Type: WsMsgCmd, Data: base64.StdEncoding.EncodeToString([]byte(command))})
}

func TestSSHSessionRoundTrip(t *testing.T) {
	sess, srv, _ := newSSHTestSession(t)
	wsSrv := newTestServer(t, sess)
	conn := dialTest(t, wsSrv)

	readHello(t, conn, sess)
	readOutputUntil(t, conn, "$ ")

	sendCommand(t, conn, "hello\n")
	readOutputUntil(t, conn, "echo:hello")

	sendMsg(t, conn, WsMsg{Type: WsMsgResize, Cols: 100, Rows: 30})
	waitFor(t, "server window size", func() bool {
		cols, rows := srv.windowSize()
		return cols == 100 && rows == 30
	})
}

func TestSSHSessionDetachReplayReattach(t *testing.T) {
	sess, _, _ := newSSHTestSession(t)
	wsSrv := newTestServer(t, sess)
	sess.SetPinned(true)

	first := dialTest(t, wsSrv)
	readHello(t, first, sess)
	sendCommand(t, first, "one\n")
	readOutputUntil(t, first, "echo:one")

	// The unsolicited line lands roughly bgTickDelay after this command, so it
	// is produced while no websocket is attached at all.
	sendCommand(t, first, "bg\n")
	readOutputUntil(t, first, "echo:bg")
	_ = first.Close()

	waitFor(t, "detach", func() bool {
		return !sess.IsAttached() && !sess.Info().DetachedAt.IsZero()
	})
	waitFor(t, "background output while detached", func() bool {
		return strings.Contains(string(sess.ring.Snapshot()), "bg:tick")
	})

	second := dialTest(t, wsSrv)
	hello := readHello(t, second, sess)
	if hello.Pinned == nil || !*hello.Pinned {
		t.Errorf("hello pinned = %v, want explicit true", hello.Pinned)
	}
	replay := readMsg(t, second)
	if replay.Type != WsMsgCmd {
		t.Fatalf("replay type = %q, want %q", replay.Type, WsMsgCmd)
	}
	decoded, err := base64.StdEncoding.DecodeString(replay.Data)
	if err != nil {
		t.Fatalf("decode replay failed: %v", err)
	}
	for _, want := range []string{"echo:one", "bg:tick"} {
		if !strings.Contains(string(decoded), want) {
			t.Fatalf("replay = %q, want it to contain %q", decoded, want)
		}
	}

	sendCommand(t, second, "three\n")
	readOutputUntil(t, second, "echo:three")
}

func TestSSHSessionExitClosesSession(t *testing.T) {
	sess, _, client := newSSHTestSession(t)
	wsSrv := newTestServer(t, sess)
	conn := dialTest(t, wsSrv)

	readHello(t, conn, sess)
	readOutputUntil(t, conn, "$ ")
	sendCommand(t, conn, "exit\n")

	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("session did not close after the remote shell exited")
	}
	// The backend owns the client, so the whole connection must be gone.
	waitFor(t, "ssh client close", func() bool {
		sshSession, err := client.NewSession()
		if err != nil {
			return true
		}
		_ = sshSession.Close()
		return false
	})
}

func TestSSHManagerKeepaliveReachesServer(t *testing.T) {
	sess, srv, _ := newSSHTestSession(t)
	m := NewManager()
	m.Register(sess)

	m.keepaliveAll()
	waitFor(t, "keepalive on the ssh server", func() bool { return srv.keepaliveCount() == 1 })
	select {
	case <-sess.Done():
		t.Fatal("a successful keepalive closed the session")
	case <-time.After(100 * time.Millisecond):
	}

	// A dead connection must take the session down rather than leak it.
	srv.closeConns()
	m.keepaliveAll()
	select {
	case <-sess.Done():
	case <-time.After(keepaliveTimeout + 2*time.Second):
		t.Fatal("a keepalive over a dead connection did not close the session")
	}
	waitFor(t, "session removal", func() bool {
		_, ok := m.Get(sess.ID)
		return !ok
	})
}

func TestSSHManagerUnpinWhileDetachedClosesClient(t *testing.T) {
	sess, _, client := newSSHTestSession(t)
	m := NewManager()
	staticConfig(m, Config{KeepAlive: time.Minute, MaxPinned: 5, RingSize: 4096})
	m.Register(sess)
	wsSrv := newTestServer(t, sess)

	if err := m.Pin(sess.ID, "alice", true); err != nil {
		t.Fatalf("Pin() = %v, want nil", err)
	}
	conn := dialTest(t, wsSrv)
	readHello(t, conn, sess)
	readOutputUntil(t, conn, "$ ")

	_ = conn.Close()
	waitFor(t, "detach", func() bool { return !sess.IsAttached() })

	if err := m.Pin(sess.ID, "", false); err != nil {
		t.Fatalf("unpin = %v, want nil", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("unpinning a detached ssh session did not close it")
	}
	waitFor(t, "session removal", func() bool {
		_, ok := m.Get(sess.ID)
		return !ok
	})
	waitFor(t, "ssh client close", func() bool {
		sshSession, err := client.NewSession()
		if err != nil {
			return true
		}
		_ = sshSession.Close()
		return false
	})
}

package terminal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

// Real sshBackend against an in-process ssh server (pty, shell, window-change, keepalive).

// delay before the fake shell emits an unsolicited line (unattached output)
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

// sshTestServer is a minimal ssh server with a fake shell.
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

// accept serves connections until the listener is closed.
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

// fakeShell echoes lines; input is split on CR/LF because there is no tty.
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
				// second half of a CRLF
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

// dialSSHTest connects to srv and closes the client when the test ends.
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
func newSSHTestSession(t *testing.T) (*Session, *sshTestServer) {
	t.Helper()
	srv := startSSHServer(t)
	client := dialSSHTest(t, srv)
	sess, err := Open(client, SessionOptions{Owner: "alice", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("Open() = %v, want nil", err)
	}
	t.Cleanup(sess.Close)
	return sess, srv
}

// readOutputUntil reads cmd payloads until they contain want.
func readOutputUntil(t *testing.T, conn *websocket.Conn, want string) string {
	t.Helper()
	var seen strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		seen.WriteString(readCmd(t, conn))
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

func TestSSHSessionDetachReplayReattach(t *testing.T) {
	sess, srv := newSSHTestSession(t)
	wsSrv := newTestServer(t, sess)

	first := dialTest(t, wsSrv)
	readHello(t, first, sess)
	sendCommand(t, first, "one\n")
	readOutputUntil(t, first, "echo:one")

	// bg produces output after bgTickDelay, by which time nothing is attached
	sendCommand(t, first, "bg\n")
	readOutputUntil(t, first, "echo:bg")
	_ = first.UnderlyingConn().Close()
	waitFor(t, "detach", func() bool { return !sess.Attached() })
	waitFor(t, "background output while detached", func() bool {
		data, _, _ := sess.ring.ReadFrom(0)
		return strings.Contains(string(data), "bg:tick")
	})

	second := dialTest(t, wsSrv)
	readHello(t, second, sess)
	replay := readCmd(t, second)
	for _, want := range []string{"echo:one", "bg:tick"} {
		if !strings.Contains(replay, want) {
			t.Fatalf("replay = %q, want it to contain %q", replay, want)
		}
	}

	sendCommand(t, second, "three\n")
	readOutputUntil(t, second, "echo:three")

	// the keepalive loop probes the real ssh connection
	waitFor(t, "keepalive on the ssh server", func() bool { return srv.keepaliveCount() > 0 })
}

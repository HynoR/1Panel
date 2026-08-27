package terminal

import (
	"io"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// sshBackend drives one interactive shell on top of an ssh client session.
// The backend owns the ssh client: closing it tears the whole connection down,
// so that a session outliving its websocket keeps exactly one client alive.
type sshBackend struct {
	client  *gossh.Client
	session *gossh.Session
	stdin   io.WriteCloser
}

// newSSHBackend opens a shell with a pty on client and streams its output to out.
func newSSHBackend(client *gossh.Client, cols, rows int, initCmd string, out io.Writer) (*sshBackend, error) {
	sshSession, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	stdinPipe, err := sshSession.StdinPipe()
	if err != nil {
		_ = sshSession.Close()
		return nil, err
	}
	sshSession.Stdout = out
	sshSession.Stderr = out

	modes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}
	if err := sshSession.RequestPty("xterm", rows, cols, modes); err != nil {
		_ = sshSession.Close()
		return nil, err
	}
	if err := sshSession.Shell(); err != nil {
		_ = sshSession.Close()
		return nil, err
	}
	if len(initCmd) != 0 {
		time.Sleep(100 * time.Millisecond)
		_, _ = stdinPipe.Write([]byte(initCmd + "\n"))
	}
	return &sshBackend{client: client, session: sshSession, stdin: stdinPipe}, nil
}

// Write forwards p to the shell stdin.
func (b *sshBackend) Write(p []byte) (int, error) {
	return b.stdin.Write(p)
}

// Resize changes the pty window size.
func (b *sshBackend) Resize(cols, rows int) error {
	return b.session.WindowChange(rows, cols)
}

// Wait blocks until the remote shell exits.
func (b *sshBackend) Wait() error {
	return b.session.Wait()
}

// Keepalive probes the ssh connection with a global request. It may block for
// as long as the network takes to answer, so callers should bound it.
func (b *sshBackend) Keepalive() error {
	if b.client == nil {
		return nil
	}
	// An unsupported request is answered with a failure reply and no error,
	// which is enough to prove the connection is still alive.
	_, _, err := b.client.SendRequest("keepalive@openssh.com", true, nil)
	return err
}

// Close terminates the ssh session and the ssh client owned by this backend.
func (b *sshBackend) Close() error {
	err := b.session.Close()
	if b.client != nil {
		if clientErr := b.client.Close(); err == nil {
			err = clientErr
		}
	}
	return err
}

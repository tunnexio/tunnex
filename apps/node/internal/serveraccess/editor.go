package serveraccess

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"golang.org/x/crypto/ssh"
)

// Native editor SSH terminates at the gateway. Certificates stay on the gateway;
// the local SSH identity is valid only for this browser-authorized connection.
func serveEditor(ctx context.Context, transport net.Conn, target *ssh.Client, m terminalwire.Material) error {
	if len(m.EditorHostKey) != ed25519.PrivateKeySize {
		return errors.New("invalid editor host key")
	}
	signer, e := ssh.NewSignerFromKey(ed25519.PrivateKey(m.EditorHostKey))
	if e != nil {
		return e
	}
	key, _, options, rest, e := ssh.ParseAuthorizedKey([]byte(m.EditorClientKey))
	if e != nil || len(options) != 0 || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
		return errors.New("invalid editor client key")
	}
	config := &ssh.ServerConfig{MaxAuthTries: 2, PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if c.User() != m.Account || subtle.ConstantTimeCompare(k.Marshal(), key.Marshal()) != 1 {
			return nil, errors.New("editor authentication refused")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(signer)
	_ = transport.SetDeadline(time.Now().Add(10 * time.Second))
	conn, channels, requests, e := ssh.NewServerConn(transport, config)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = transport.SetDeadline(time.Time{})
	go func() {
		for req := range requests {
			if req.WantReply {
				_ = req.Reply(req.Type == "keepalive@openssh.com", nil)
			}
		}
	}()
	slots := make(chan struct{}, 32)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		case incoming, ok := <-channels:
			if !ok {
				return nil
			}
			select {
			case slots <- struct{}{}:
			default:
				_ = incoming.Reject(ssh.ResourceShortage, "editor channel limit")
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				switch incoming.ChannelType() {
				case "session":
					proxyEditorSession(incoming, target)
				case "direct-tcpip":
					proxyEditorLoopback(incoming, target)
				default:
					_ = incoming.Reject(ssh.UnknownChannelType, "unsupported editor channel")
				}
			}()
		}
	}
}

func proxyEditorSession(incoming ssh.NewChannel, target *ssh.Client) {
	session, e := target.NewSession()
	if e != nil {
		_ = incoming.Reject(ssh.ConnectionFailed, "target session unavailable")
		return
	}
	defer session.Close()
	channel, requests, e := incoming.Accept()
	if e != nil {
		return
	}
	defer channel.Close()
	stdin, e := session.StdinPipe()
	if e != nil {
		return
	}
	session.Stdout = channel
	session.Stderr = channel.Stderr()
	go func() { _, _ = io.Copy(stdin, channel); _ = stdin.Close() }()
	started := false
	finish := func() {
		e := session.Wait()
		status := uint32(0)
		var exit *ssh.ExitError
		if errors.As(e, &exit) {
			status = uint32(exit.ExitStatus())
		} else if e != nil {
			status = 255
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		_ = channel.Close()
	}
	for req := range requests {
		accepted := false
		switch req.Type {
		case "env":
			var env struct{ Name, Value string }
			if !started && ssh.Unmarshal(req.Payload, &env) == nil && allowedEditorEnv(env.Name, env.Value) {
				accepted = session.Setenv(env.Name, env.Value) == nil
			}
		case "pty-req":
			var pty struct {
				Term                      string
				Cols, Rows, Width, Height uint32
				Modes                     string
			}
			if !started && ssh.Unmarshal(req.Payload, &pty) == nil && pty.Cols > 0 && pty.Cols <= 1000 && pty.Rows > 0 && pty.Rows <= 1000 && len(pty.Term) <= 64 {
				accepted = session.RequestPty(pty.Term, int(pty.Rows), int(pty.Cols), ssh.TerminalModes{}) == nil
			}
		case "window-change":
			var window struct{ Cols, Rows, Width, Height uint32 }
			if ssh.Unmarshal(req.Payload, &window) == nil && window.Cols > 0 && window.Cols <= 1000 && window.Rows > 0 && window.Rows <= 1000 {
				accepted = session.WindowChange(int(window.Rows), int(window.Cols)) == nil
			}
		case "exec":
			var command struct{ Command string }
			if !started && ssh.Unmarshal(req.Payload, &command) == nil && len(command.Command) <= 65536 && !strings.ContainsRune(command.Command, 0) {
				accepted = session.Start(command.Command) == nil
			}
		case "shell":
			if !started && len(req.Payload) == 0 {
				accepted = session.Shell() == nil
			}
		case "subsystem":
			var subsystem struct{ Name string }
			if !started && ssh.Unmarshal(req.Payload, &subsystem) == nil && subsystem.Name == "sftp" {
				accepted = session.Start(editorSFTPCommand) == nil
			}
		case "signal":
			var signal struct{ Name string }
			if started && ssh.Unmarshal(req.Payload, &signal) == nil && (signal.Name == "INT" || signal.Name == "TERM" || signal.Name == "KILL") {
				accepted = session.Signal(ssh.Signal(signal.Name)) == nil
			}
		}
		if req.WantReply {
			_ = req.Reply(accepted, nil)
		}
		if accepted && (req.Type == "exec" || req.Type == "shell" || req.Type == "subsystem") {
			started = true
			go finish()
		}
	}
}

const editorSFTPCommand = `for server in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; do if [ -x "$server" ]; then exec "$server"; fi; done; echo "SFTP server unavailable" >&2; exit 127`

func allowedEditorEnv(name, value string) bool {
	return len(value) <= 1024 && !strings.ContainsRune(value, 0) && (name == "LANG" || name == "TERM" || strings.HasPrefix(name, "LC_"))
}

type editorForward struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}

func editorLoopback(payload []byte) (editorForward, error) {
	var f editorForward
	if ssh.Unmarshal(payload, &f) != nil || f.Port == 0 || f.Port > 65535 || (f.Host != "localhost" && f.Host != "127.0.0.1" && f.Host != "::1") {
		return f, errors.New("only target loopback forwarding is allowed")
	}
	return f, nil
}

// VS Code uses dynamic local ports on the target. Open only target loopback
// services through an authenticated exec channel; the target's existing blanket
// SSH forwarding prohibition stays intact for every certificate and listener.
// Python 3 is already required by the Linux enrollment flow.
const editorSocketProgram = `import socket,sys,threading
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),10)
s.settimeout(None)
def send():
 try:
  while True:
   b=sys.stdin.buffer.read1(32768)
   if not b: break
   s.sendall(b)
  s.shutdown(socket.SHUT_WR)
 except OSError: pass
threading.Thread(target=send,daemon=True).start()
try:
 while True:
  b=s.recv(32768)
  if not b: break
  sys.stdout.buffer.write(b)
  sys.stdout.buffer.flush()
finally: s.close()
`

func proxyEditorLoopback(incoming ssh.NewChannel, target *ssh.Client) {
	forward, e := editorLoopback(incoming.ExtraData())
	if e != nil {
		_ = incoming.Reject(ssh.Prohibited, "only target loopback forwarding is allowed")
		return
	}
	session, e := target.NewSession()
	if e != nil {
		_ = incoming.Reject(ssh.ConnectionFailed, "target session unavailable")
		return
	}
	defer session.Close()
	stdin, e := session.StdinPipe()
	if e != nil {
		_ = incoming.Reject(ssh.ConnectionFailed, "target session unavailable")
		return
	}
	// All interpolated values are fixed literals or validated numeric ports.
	host := "127.0.0.1"
	if forward.Host == "::1" {
		host = "::1"
	}
	channel, requests, e := incoming.Accept()
	if e != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	session.Stdout = channel
	session.Stderr = io.Discard
	command := fmt.Sprintf("python3 -c '%s' %s %s", editorSocketProgram, host, strconv.FormatUint(uint64(forward.Port), 10))
	if e = session.Start(command); e != nil {
		return
	}
	go func() { _, _ = io.Copy(stdin, channel); _ = stdin.Close() }()
	_ = session.Wait()
}

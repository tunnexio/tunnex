package serveraccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/terminalwire"
	"golang.org/x/crypto/ssh"
)

// The downstream is a synthetic SSH server executing only test-owned commands.
// This exercises the real SSH protocol and Python loopback relay without touching
// an enrolled server, customer files, certificates or management SSH config.
func TestEditorNativeSSHExecutionAndLoopback(t *testing.T) {
	if _, e := exec.LookPath("python3"); e != nil {
		t.Skip("Python 3 needed for enrollment/editor fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPrivate)
	_, clientPrivate, _ := ed25519.GenerateKey(rand.Reader)
	clientSigner, _ := ssh.NewSignerFromKey(clientPrivate)
	targetListener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer targetListener.Close()
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(hostSigner)
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		raw, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		server, channels, requests, err := ssh.NewServerConn(raw, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.Prohibited, "fixture")
				continue
			}
			go runEditorTargetFixture(incoming)
		}
	}()
	target, e := ssh.Dial("tcp", targetListener.Addr().String(), &ssh.ClientConfig{User: "synthetic", Timeout: time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if subtle.ConstantTimeCompare(key.Marshal(), hostSigner.PublicKey().Marshal()) != 1 {
			return fmt.Errorf("fixture host mismatch")
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer raw.Close()
		go func() { <-ctx.Done(); _ = raw.Close(); _ = target.Close() }()
		finished <- serveEditor(ctx, raw, target, terminalwire.Material{Account: "ubuntu", EditorHostKey: hostPrivate, EditorClientKey: string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey()))})
	}()
	client, e := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "ubuntu", Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)}, Timeout: 2 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if subtle.ConstantTimeCompare(key.Marshal(), hostSigner.PublicKey().Marshal()) != 1 {
			return fmt.Errorf("editor host mismatch")
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	output, e := session.Output("printf editor-smoke")
	session.Close()
	if e != nil || string(output) != "editor-smoke" {
		t.Fatalf("exec output %q: %v", output, e)
	}
	// VS Code install phase exits, then a second session reuses the SSH connection.
	session, e = client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	output, e = session.Output("printf second-channel")
	session.Close()
	if e != nil || string(output) != "second-channel" {
		t.Fatalf("reused session %q: %v", output, e)
	}
	// Exercise SFTP file creation and readback when the standard server binary exists.
	if _, err := os.Stat("/usr/libexec/sftp-server"); err == nil {
		channel, requests, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatal(err)
		}
		go ssh.DiscardRequests(requests)
		ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
		if err != nil || !ok {
			t.Fatal("SFTP request failed", err)
		}
		packet := func(payload []byte) []byte {
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, uint32(len(payload)))
			return append(header, payload...)
		}
		receive := func() []byte {
			t.Helper()
			header := make([]byte, 4)
			if _, err := io.ReadFull(channel, header); err != nil {
				t.Fatal(err)
			}
			length := binary.BigEndian.Uint32(header)
			if length > 65536 {
				t.Fatal("oversized SFTP fixture")
			}
			data := make([]byte, length)
			if _, err := io.ReadFull(channel, data); err != nil {
				t.Fatal(err)
			}
			return data
		}
		send := func(kind byte, body any) []byte {
			t.Helper()
			if _, err := channel.Write(packet(append([]byte{kind}, ssh.Marshal(body)...))); err != nil {
				t.Fatal(err)
			}
			return receive()
		}
		if reply := send(1, struct{ Version uint32 }{3}); reply[0] != 2 {
			t.Fatal("SFTP version missing")
		}
		fixturePath := filepath.Join(t.TempDir(), "developer.txt")
		opened := send(3, struct {
			ID           uint32
			Path         string
			Flags, Attrs uint32
		}{1, fixturePath, 26, 0})
		if opened[0] != 102 {
			t.Fatal("SFTP open failed")
		}
		var handle struct {
			ID     uint32
			Handle string
		}
		if ssh.Unmarshal(opened[1:], &handle) != nil {
			t.Fatal("bad SFTP handle")
		}
		result := send(6, struct {
			ID     uint32
			Handle string
			Offset uint64
			Data   string
		}{2, handle.Handle, 0, "developer file edit"})
		if result[0] != 101 || binary.BigEndian.Uint32(result[5:9]) != 0 {
			t.Fatal("SFTP write failed")
		}
		result = send(4, struct {
			ID     uint32
			Handle string
		}{3, handle.Handle})
		if result[0] != 101 || binary.BigEndian.Uint32(result[5:9]) != 0 {
			t.Fatal("SFTP close failed")
		}
		contents, err := os.ReadFile(fixturePath)
		if err != nil || string(contents) != "developer file edit" {
			t.Fatal("SFTP file edit not persisted", err)
		}
		_ = channel.Close()
	}
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	forwarded, e := client.Dial("tcp", echo.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer forwarded.Close()
	// ssh.Channel connections have no deadline support; the fixture context bounds it.
	if _, e = forwarded.Write([]byte("editor-loopback")); e != nil {
		t.Fatal(e)
	}
	readback := make([]byte, len("editor-loopback"))
	if _, e = io.ReadFull(forwarded, readback); e != nil || string(readback) != "editor-loopback" {
		t.Fatalf("loopback relay %q: %v", readback, e)
	}
	if c, e := client.Dial("tcp", "10.1.2.3:22"); e == nil {
		c.Close()
		t.Fatal("editor escaped target loopback")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("editor did not stop with its lease context")
	}
}
func runEditorTargetFixture(incoming ssh.NewChannel) {
	channel, requests, e := incoming.Accept()
	if e != nil {
		return
	}
	defer channel.Close()
	for req := range requests {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		var command struct{ Command string }
		if ssh.Unmarshal(req.Payload, &command) != nil {
			_ = req.Reply(false, nil)
			return
		}
		if !strings.HasPrefix(command.Command, "printf ") && !strings.HasPrefix(command.Command, "python3 -c ") && command.Command != editorSFTPCommand {
			_ = req.Reply(false, nil)
			return
		}
		cmd := exec.Command("/bin/sh", "-c", command.Command)
		cmd.Stdin = channel
		cmd.Stdout = channel
		cmd.Stderr = channel.Stderr()
		if cmd.Start() != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		// Consume the request channel so EOF and close messages are delivered.
		go ssh.DiscardRequests(requests)
		status := uint32(0)
		if cmd.Wait() != nil {
			status = 1
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

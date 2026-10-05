package sandboxruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fixtureDialer struct{ endpoint string }

func (d fixtureDialer) DialContext(ctx context.Context, network, endpoint string) (net.Conn, error) {
	if network != "tcp" || endpoint != "10.99.0.4:22" {
		return nil, errors.New("unexpected probe target")
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.endpoint)
}
func probeSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
func probeFixture(t *testing.T, host, user ssh.Signer, output string, status uint32) privateDialer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != "sandbox" || !bytes.Equal(key.Marshal(), user.PublicKey().Marshal()) {
				return nil, errors.New("wrong identity")
			}
			return nil, nil
		}}
		config.AddHostKey(host)
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.UnknownChannelType, "session required")
				continue
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			for request := range requests {
				var command struct{ Command string }
				if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || command.Command != "/usr/bin/id -u" {
					_ = request.Reply(false, nil)
					continue
				}
				_ = request.Reply(true, nil)
				_, _ = channel.Write([]byte(output))
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				_ = channel.Close()
				break
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("probe fixture did not close")
		}
	})
	return fixtureDialer{listener.Addr().String()}
}
func TestPrivateSSHProbePinsHostAndRequiresUnprivilegedSuccess(t *testing.T) {
	host, user := probeSigner(t), probeSigner(t)
	for _, test := range []struct {
		name, output                      string
		status                            uint32
		wrongHost, wrongUser, wantSuccess bool
	}{
		{name: "ready", output: "1001\n", wantSuccess: true},
		{name: "root refused", output: "0\n"},
		{name: "nonzero exit", output: "1001\n", status: 7},
		{name: "oversized output", output: string(bytes.Repeat([]byte{'1'}, 64))},
		{name: "changed host key", output: "1001\n", wrongHost: true},
		{name: "wrong probe identity", output: "1001\n", wrongUser: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dialer := probeFixture(t, host, user, test.output, test.status)
			pin, identity := host.PublicKey(), user
			if test.wrongHost {
				pin = probeSigner(t).PublicKey()
			}
			if test.wrongUser {
				identity = probeSigner(t)
			}
			result, err := probePrivateSSH(context.Background(), dialer, netip.MustParseAddr("10.99.0.4"), pin, identity)
			if test.wantSuccess {
				if err != nil || result.UID != 1001 || result.HostKeyFingerprint != ssh.FingerprintSHA256(pin) || result.ObservedAt.IsZero() {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, ErrUnavailable) {
				t.Fatal("invalid readiness accepted", err)
			}
		})
	}
}
func TestPrivateSSHProbeRejectsNonPrivateTargetsBeforeDial(t *testing.T) {
	host, user := probeSigner(t), probeSigner(t)
	for _, address := range []string{"127.0.0.1", "169.254.169.254", "8.8.8.8", "::1"} {
		if _, err := probePrivateSSH(context.Background(), fixtureDialer{}, netip.MustParseAddr(address), host.PublicKey(), user); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid target reached dial", address, err)
		}
	}
}

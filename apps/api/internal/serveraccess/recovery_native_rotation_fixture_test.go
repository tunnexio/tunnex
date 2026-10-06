package serveraccess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A NEW isolated OpenSSH target trusts only these public fixture CA files. CA
// private keys and the client private key remain in this test process's RAM.
func TestRecoveryNativeCARotation(t *testing.T) {
	if os.Getenv("TUNNEX_SA_NATIVE_ROTATION") != "1" {
		t.Skip("requires new owned synthetic SSH target")
	}
	root := os.Getenv("TUNNEX_SA_NATIVE_DIR")
	if !regexp.MustCompile(`^/owned-recordings/recovery-native-[a-f0-9]{12}$`).MatchString(root) {
		t.Fatal("foreign native fixture refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ca := func() ssh.Signer {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { clear(key) })
		signer, e := ssh.NewSignerFromKey(key)
		if e != nil {
			t.Fatal(e)
		}
		return signer
	}
	oldCA, newCA, foreignCA := ca(), ca(), ca()
	client := ca()
	cert := func(signer ssh.Signer, start, end int64) ssh.Signer {
		c := &ssh.Certificate{Key: client.PublicKey(), Serial: 1, CertType: ssh.UserCert, KeyId: "synthetic-native-rotation", ValidPrincipals: []string{"sa-native-rotation"}, ValidAfter: uint64(start), ValidBefore: uint64(end), Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}}}
		if e := c.SignCert(rand.Reader, signer); e != nil {
			t.Fatal(e)
		}
		out, e := ssh.NewCertSigner(c, client)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	now := time.Now().Unix()
	oldCert, newCert := cert(oldCA, now-10, now+300), cert(newCA, now-10, now+300)
	expired, foreign := cert(oldCA, now-100, now-20), cert(foreignCA, now-10, now+300)
	for name, public := range map[string]ssh.PublicKey{"old.pub": oldCA.PublicKey(), "new.pub": newCA.PublicKey()} {
		if e := os.WriteFile(filepath.Join(root, name), ssh.MarshalAuthorizedKey(public), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.MkdirAll(filepath.Join(root, "principals"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "principals", "fixture"), []byte("sa-native-rotation\n"), 0644); e != nil {
		t.Fatal(e)
	}
	wait := func(name string) {
		for {
			if _, e := os.Stat(filepath.Join(root, name)); e == nil {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("native fixture phase timed out")
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	wait("ready.json")
	var target struct {
		Address     string `json:"address"`
		Fingerprint string `json:"fingerprint"`
	}
	raw, e := os.ReadFile(filepath.Join(root, "ready.json"))
	if e != nil || json.Unmarshal(raw, &target) != nil {
		t.Fatal("invalid native fixture descriptor")
	}
	dial := func(signer ssh.Signer, fp string) (*ssh.Client, error) {
		config := &ssh.ClientConfig{User: "fixture", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, Timeout: 2 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != fp {
				return deny("host_key_mismatch")
			}
			return nil
		}}
		conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", target.Address)
		if e != nil {
			return nil, e
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		c, ch, r, e := ssh.NewClientConn(conn, target.Address, config)
		if e != nil {
			conn.Close()
			return nil, e
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		return ssh.NewClient(c, ch, r), nil
	}
	shell := func(signer ssh.Signer, marker string) {
		c, e := dial(signer, target.Fingerprint)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		s, e := c.NewSession()
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		var output bytes.Buffer
		s.Stdout = &output
		s.Stderr = io.Discard
		in, e := s.StdinPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); e != nil {
			t.Fatal(e)
		}
		if e = s.Shell(); e != nil {
			t.Fatal(e)
		}
		if e = s.WindowChange(40, 120); e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(in, "printf '"+marker+"\\n'; id -u; stty size; exit\n"); e != nil {
			t.Fatal(e)
		}
		if e = s.Wait(); e != nil {
			t.Fatal(e)
		}
		out := output.String()
		if !strings.Contains(out, marker) || !strings.Contains(out, "1000") || !strings.Contains(out, "40 120") {
			t.Fatalf("native PTY/account/resize proof absent: %q", out)
		}
	}
	shell(oldCert, "OLD_CA_NATIVE_OK")
	for _, bad := range []ssh.Signer{newCert, expired, foreign, client} {
		if c, e := dial(bad, target.Fingerprint); e == nil {
			c.Close()
			t.Fatal("untrusted/expired/raw key authenticated")
		} else if !strings.Contains(e.Error(), "unable to authenticate") {
			t.Fatalf("negative auth masked by transport failure: %v", e)
		}
	}
	if e = os.WriteFile(filepath.Join(root, "old-phase.done"), []byte("ok\n"), 0600); e != nil {
		t.Fatal(e)
	}
	wait("trust-switched.done")
	if time.Now().Unix() >= now+300 {
		t.Fatal("old cert expired before trust-cutover assertion")
	}
	if c, e := dial(oldCert, target.Fingerprint); e == nil {
		c.Close()
		t.Fatal("old unexpired CA certificate survived trust removal")
	} else if !strings.Contains(e.Error(), "unable to authenticate") {
		t.Fatalf("old CA trust denial masked by transport failure: %v", e)
	}
	shell(newCert, "NEW_CA_NATIVE_OK")
	if c, e := dial(newCert, "SHA256:wrongfixturehost"); e == nil {
		c.Close()
		t.Fatal("wrong pinned host accepted")
	}
	t.Log("native OpenSSH old unexpired CA denied after publictrust cutover; new CA PTY/account/resize accepted; foreign/expired/raw key/wronghost denied")
}

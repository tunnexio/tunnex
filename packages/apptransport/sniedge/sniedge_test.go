package sniedge

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport/proxyproto"
)

var token = bytes.Repeat([]byte{3}, 32)

func certificate(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type upstream struct {
	addr string
	got  chan string
}

// upstream records the PROXY source and the first TLS record type it receives.
func newUpstream(t *testing.T) upstream {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	u := upstream{addr: l.Addr().String(), got: make(chan string, 4)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				src, err := proxyproto.Read(r, token)
				if err != nil {
					u.got <- "bad header"
					return
				}
				first, _ := r.ReadByte()
				host, _, _ := net.SplitHostPort(src.String())
				u.got <- host + "|" + string(rune('0'+first%10))
			}()
		}
	}()
	return u
}

func edge(t *testing.T, cfg Config) string {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(inner, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	server := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{certificate(t, "*.share.test")}})
	go func() {
		for {
			c, err := server.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.WriteString(c, "owned\n") }()
		}
	}()
	return inner.Addr().String()
}

func TestEdgeTerminatesOwnAndSplicesOthersWithClientAddress(t *testing.T) {
	console, apps := newUpstream(t), newUpstream(t)
	address := edge(t, Config{Own: Subdomain("share.test"), Routes: []Route{{Match: Under("apps.test"), Target: apps.addr}}, Default: console.addr, Token: token})
	c, err := tls.Dial("tcp", address, &tls.Config{ServerName: "p-1.share.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal("owned SNI not terminated by the owner", err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if line != "owned\n" {
		t.Fatal("owner did not serve", line)
	}
	for _, tc := range []struct {
		sni  string
		want upstream
	}{{"cp.example.test", console}, {"demo.apps.test", apps}, {"", console}, {"a.b.share.test", console}} {
		raw, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = tls.Client(raw, &tls.Config{ServerName: tc.sni, InsecureSkipVerify: true}).Handshake() }()
		select {
		case got := <-tc.want.got:
			// 22 = TLS handshake record: the ClientHello reached the target unchanged.
			if !strings.HasPrefix(got, "127.0.0.1|") || got != "127.0.0.1|"+string(rune('0'+22%10)) {
				t.Fatal(tc.sni, "spliced stream wrong", got)
			}
		case <-time.After(3 * time.Second):
			t.Fatal(tc.sni, "not spliced to the expected target")
		}
		raw.Close()
	}
}

func TestEdgeClosesNonTLSAndSlowClients(t *testing.T) {
	console := newUpstream(t)
	address := edge(t, Config{Own: Subdomain("share.test"), Default: console.addr, Token: token, Timeout: 300 * time.Millisecond})
	for _, payload := range []string{"GET / HTTP/1.1\r\nHost: x\r\n\r\n", ""} {
		c, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, payload)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err = c.Read(make([]byte, 1)); err == nil {
			t.Fatal("non-TLS or silent client was not closed")
		}
		c.Close()
	}
	select {
	case got := <-console.got:
		t.Fatal("garbage reached an upstream", got)
	default:
	}
}

func TestSubdomainAndUnder(t *testing.T) {
	own := Subdomain("Share.Test")
	for sni, want := range map[string]bool{"a.share.test": true, "A.SHARE.TEST": true, "share.test": false, "a.b.share.test": false, "ashare.test": false} {
		if own(sni) != want {
			t.Fatal(sni)
		}
	}
	under := Under("apps.test")
	if !under("apps.test") || !under("x.y.apps.test") || under("xapps.test") {
		t.Fatal("under")
	}
}

func TestNewRequiresTokenAndDefault(t *testing.T) {
	inner, _ := net.Listen("tcp", "127.0.0.1:0")
	defer inner.Close()
	if _, err := New(inner, Config{Own: Subdomain("x.test"), Default: "127.0.0.1:1"}); err == nil {
		t.Fatal("edge without token")
	}
}

// Local-only HTTP/HTTPS origin for actual gateway connection checks. This is
// built as a test binary and never added to a shipping image.
//go:debug httpmuxgo121=0

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("fixture key unavailable")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Owned App Access origin fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		log.Fatal("fixture CA unavailable")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("fixture leaf key unavailable")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "origin-app-fixture"}, DNSNames: []string{"origin-app-fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		log.Fatal("fixture certificate unavailable")
	}
	if err = os.WriteFile("/fixture/origin-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		log.Fatal("fixture public CA output unavailable")
	}
	handler := originHandler()
	server := &http.Server{Addr: ":8444", Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	go func() { log.Fatal(server.ListenAndServeTLS("", "")) }()
	plain := &http.Server{Addr: ":8081", Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	log.Fatal(plain.ListenAndServe())
}

// Compatibility fixtures exercise actual origin behavior over the connector.
// They carry no control-plane credentials and persist no application data.
func originHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Owned origin fixture</title><link rel="stylesheet" href="/assets/app.css"><main><h1>Gateway reached the owned origin</h1><p>This local test application exercises browser delivery. Form submissions are echoed and are not stored.</p><form method="post" action="/form"><label>Message <input name="message" required maxlength="200"></label><button>Submit message</button></form><p><a href="/redirect">Follow an origin redirect</a> · <a href="/cookie">Set an application cookie</a></p><p id="asset-state">Loading application asset…</p><script src="/assets/app.js" defer></script></main></html>`)
	})
	mux.HandleFunc("GET /assets/app.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		io.WriteString(w, "body{font:16px system-ui;max-width:48rem;margin:3rem auto;padding:1rem;background:#f6f7fb;color:#18212f}main{background:white;padding:2rem;border-radius:1rem}input,button{font:inherit;padding:.6rem}label{display:block;margin-bottom:1rem}")
	})
	mux.HandleFunc("GET /assets/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		io.WriteString(w, "document.getElementById('asset-state').textContent='Application asset loaded.';")
	})
	mux.HandleFunc("POST /form", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil || len(r.PostForm.Get("message")) > 200 {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "<!doctype html><title>Form submitted</title><h1>Form submitted</h1><p>%s</p><a href=\"/\">Back</a>", html.EscapeString(r.PostForm.Get("message")))
	})
	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("GET /cookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "fixture_preference", Value: "enabled", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
		fixtureUpload.Add(1)
		defer fixtureUpload.Add(-1)
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
		hash := sha256.New()
		count, err := io.Copy(hash, r.Body)
		if err != nil {
			http.Error(w, "Upload refused", http.StatusRequestEntityTooLarge)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%d %x\n", count, hash.Sum(nil))
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		fixtureSSE.Add(1)
		defer fixtureSSE.Add(-1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for index := 0; ; index++ {
			if _, err := fmt.Fprintf(w, "data: %d\n\n", index); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})

	addStreamFixtures(mux)
	return mux
}

// These endpoints are local compatibility fixtures, never shipping API routes.
var fixtureSSE, fixtureWS, fixtureDownload, fixtureUpload, fixtureLong atomic.Int64

func addStreamFixtures(mux *http.ServeMux) {
	mux.HandleFunc("GET /download", func(w http.ResponseWriter, r *http.Request) {
		fixtureDownload.Add(1)
		defer fixtureDownload.Add(-1)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(64<<20))
		w.Header().Set("Cache-Control", "no-store")
		block := make([]byte, 4096)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for sent := 0; sent < 64<<20; sent += len(block) {
			if _, err := w.Write(block); err != nil {
				return
			}
			if http.NewResponseController(w).Flush() != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})
	mux.HandleFunc("GET /long-response", func(w http.ResponseWriter, r *http.Request) {
		fixtureLong.Add(1)
		defer fixtureLong.Add(-1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := io.WriteString(w, "owned long HTTP fixture\n"); err != nil {
				return
			}
			if http.NewResponseController(w).Flush() != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	})
	mux.HandleFunc("GET /ws", fixtureWebSocket)
	mux.HandleFunc("GET /__fixture/stream-state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]int64{"sse": fixtureSSE.Load(), "websocket": fixtureWS.Load(), "download": fixtureDownload.Load(), "upload": fixtureUpload.Load(), "long_http": fixtureLong.Load()})
	})
}
func fixtureWebSocket(w http.ResponseWriter, r *http.Request) {
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(key) != 16 || r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "Unsupported fixture handshake", 400)
		return
	}
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	fixtureWS.Add(1)
	defer fixtureWS.Add(-1)
	hash := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(hash[:]))
	if rw.Flush() != nil {
		return
	}
	for {
		opcode, payload, err := readFixtureFrame(rw.Reader)
		if err != nil {
			return
		}
		if opcode == 8 {
			_, _ = conn.Write([]byte{0x88, 0})
			return
		}
		if opcode == 9 {
			opcode = 10
		}
		if opcode != 1 && opcode != 2 && opcode != 10 {
			return
		}
		frame := append([]byte{0x80 | opcode, byte(len(payload))}, payload...)
		if _, err = conn.Write(frame); err != nil {
			return
		}
	}
}
func readFixtureFrame(r *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	if header[0]&0x80 == 0 || header[0]&0x70 != 0 || header[1]&0x80 == 0 || header[1]&0x7f > 125 {
		return 0, nil, fmt.Errorf("unsupported fixture frame")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(r, mask); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return header[0] & 0x0f, payload, nil
}

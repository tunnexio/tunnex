// Nonshipping owned native session-capacity qualification. No authority mutations.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const owned = "/Users/pawangupta/tunnex/tests/app-access-local"
const host = "payroll.apps.127.0.0.1.nip.io"

type evidence struct {
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	PositiveStreams int       `json:"positive_streams"`
	OverflowStatus  int       `json:"overflow_status"`
	ReplacementMS   int64     `json:"replacement_ms"`
	RootStatus      int       `json:"root_status"`
	Passed          bool      `json:"passed"`
	Failure         string    `json:"failure,omitempty"`
	Scope           string    `json:"scope"`
}

func privatePath(path string, existing bool) bool {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(path) || !strings.HasPrefix(clean, owned+"/.runtime/") {
		return false
	}
	target := clean
	if !existing {
		target = filepath.Dir(clean)
	}
	resolved, err := filepath.EvalSymlinks(target)
	return err == nil && resolved == target
}

func configuration(path string) (string, *tls.Config, error) {
	if os.Getenv("APP_ACCESS_OWNED_PROJECT") != "tunnex-app-access-aa0-1003" || os.Getenv("APP_ACCESS_OWNED_CHECKOUT") != owned || !privatePath(path, true) {
		return "", nil, errors.New("owned boundary refused")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return "", nil, errors.New("private session refused")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, errors.New("session unreadable")
	}
	var input struct {
		Token string `json:"app_session_token"`
	}
	if json.Unmarshal(data, &input) != nil || len(input.Token) < 32 || len(input.Token) > 256 || strings.ContainsAny(input.Token, ";\r\n \t\"\\") {
		return "", nil, errors.New("session invalid")
	}
	ca, err := os.ReadFile(owned + "/.runtime/aa6-proxy/ca-cert.pem")
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		return "", nil, errors.New("owned CA invalid")
	}
	return input.Token, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: host, NextProtos: []string{"http/1.1"}}, nil
}

func open(ctx context.Context, token string, config *tls.Config, path string) (net.Conn, *http.Response, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", "127.0.0.1:443")
	if err != nil {
		return nil, nil, err
	}
	conn := tls.Client(raw, config.Clone())
	context.AfterFunc(ctx, func() { conn.Close() })
	if err = conn.HandshakeContext(dialCtx); err != nil {
		conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	request, _ := http.NewRequest("GET", "https://"+host+path, nil)
	request.Host = host
	request.Header.Set("Cookie", "__Host-tunnex_app_session="+token)
	request.Header.Set("Connection", "close")
	if err = request.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, response, nil
}

func positiveSSE(response *http.Response) bool {
	if response.StatusCode != 200 || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		return false
	}
	line, err := bufio.NewReader(io.LimitReader(response.Body, 256)).ReadString('\n')
	return err == nil && strings.HasPrefix(line, "data: ")
}

func qualify(ctx context.Context, token string, config *tls.Config) (out evidence) {
	out.StartedAt = time.Now()
	out.Scope = "Actual session16 admission and release only; not app/gateway/global/callback limits, memory, throughput, fairness or HA."
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
		out.FinishedAt = time.Now()
	}()
	for i := 0; i < 16; i++ {
		conn, response, err := open(ctx, token, config, "/events")
		if err != nil {
			out.Failure = "positive stream setup failed"
			return
		}
		conns = append(conns, conn)
		if !positiveSSE(response) {
			out.Failure = "initial origin content absent"
			return
		}
		out.PositiveStreams++
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		go func() { _, _ = io.Copy(io.Discard, response.Body) }()
	}
	conn, response, err := open(ctx, token, config, "/events")
	if err != nil {
		out.Failure = "overflow response absent"
		return
	}
	out.OverflowStatus = response.StatusCode
	conn.Close()
	if out.OverflowStatus != 403 {
		out.Failure = "overflow was not generic denial"
		return
	}
	conns[0].Close()
	start := time.Now()
	retryDeadline := start.Add(10 * time.Second)
	for time.Now().Before(retryDeadline) && ctx.Err() == nil {
		conn, response, err = open(ctx, token, config, "/events")
		if err == nil && positiveSSE(response) {
			conns = append(conns, conn)
			out.ReplacementMS = time.Since(start).Milliseconds()
			break
		}
		if conn != nil {
			conn.Close()
		}
		select {
		case <-ctx.Done():
			out.Failure = "replacement timed out"
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if len(conns) != 17 {
		out.Failure = "released capacity was not reusable"
		return
	}
	for _, c := range conns {
		c.Close()
	}
	// Admission release is asynchronous; bounded retries distinguish cleanup from denial.
	for i := 0; i < 20 && ctx.Err() == nil; i++ {
		conn, response, err = open(ctx, token, config, "/")
		if err == nil {
			out.RootStatus = response.StatusCode
			conn.Close()
			if out.RootStatus == 200 {
				out.Passed = true
				return
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	out.Failure = "root unavailable after cleanup"
	return
}

func main() {
	session := flag.String("session-file", "", "private owned native session JSON")
	output := flag.String("evidence-file", "", "exclusive private evidence JSON")
	flag.Parse()
	token, config, err := configuration(*session)
	if err != nil || !privatePath(*output, false) {
		println("Owned capacity setup refused")
		os.Exit(2)
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		println("Exclusive evidence file refused")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := qualify(ctx, token, config)
	err = json.NewEncoder(file).Encode(result)
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		println("Evidence write failed")
		os.Exit(2)
	}
	if !result.Passed {
		println("Capacity qualification failed; inspect redacted evidence")
		os.Exit(1)
	}
	println("Session16 admission and release qualified")
}

// Read-only owned browser-desired diagnosis; channel request obtains no content.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Owned browser diagnostic refused")
		os.Exit(1)
	}
}
func run() error {
	if os.Getenv("APP_ACCESS_OWNED_DIAGNOSTIC") != "1" {
		return fmt.Errorf("guard")
	}
	cert, e := tls.LoadX509KeyPair("/owned-gateway/cert.pem", "/owned-gateway/key.pem")
	if e != nil {
		return e
	}
	ca, e := os.ReadFile("/owned-gateway/ca.pem")
	if e != nil {
		return e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("ca")
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return e
	}
	client := func(name string, mutual bool) *http.Client {
		cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: name, NextProtos: []string{"http/1.1"}}
		if mutual {
			cfg.Certificates = []tls.Certificate{cert}
		}
		return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: cfg}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, e := client("app-access-fixture", true).Get("https://app-access-fixture:18447/agent/app-access/browser-desired-state")
	if e != nil {
		return e
	}
	defer response.Body.Close()
	var desired struct {
		Withdrawn   bool   `json:"withdrawn"`
		Reason      string `json:"reason"`
		Assignments []struct {
			Binding     map[string]any `json:"binding"`
			Stage       string         `json:"stage"`
			OperationID string         `json:"operation_id"`
			Deadline    time.Time      `json:"deadline"`
		} `json:"assignments"`
	}
	if e = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&desired); e != nil {
		return e
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"desired_status": response.StatusCode, "withdrawn": desired.Withdrawn, "reason": desired.Reason, "assignment_count": len(desired.Assignments), "current_certificate_not_after": leaf.NotAfter})
	if response.StatusCode != 200 {
		return fmt.Errorf("desired")
	}
	token, e := os.ReadFile("/owned-proxy/proxy-credential")
	if e != nil {
		return e
	}
	for _, a := range desired.Assignments {
		payload, e := json.Marshal(map[string]any{"binding": a.Binding, "certificate_serial": leaf.SerialNumber.Text(16)})
		if e != nil {
			return e
		}
		req, _ := http.NewRequest("POST", "https://tunnex-app-authority:18448/internal/app-access/channel-authorize", bytes.NewReader(payload))
		req.Header.Set("Authorization", "AppProxy "+strings.TrimSpace(string(token)))
		req.Header.Set("Content-Type", "application/json")
		r, e := client("tunnex-app-authority", false).Do(req)
		if e != nil {
			return e
		}
		io.Copy(io.Discard, io.LimitReader(r.Body, 8192))
		r.Body.Close()
		json.NewEncoder(os.Stdout).Encode(map[string]any{"operation_id": a.OperationID, "stage": a.Stage, "app_id": a.Binding["app_id"], "deadline_future": a.Deadline.After(time.Now()), "channel_authorize_status": r.StatusCode})
	}
	return nil
}

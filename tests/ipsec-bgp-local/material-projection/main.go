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
	"time"
)

func main() {
	cert, e := tls.LoadX509KeyPair("/state/cert.pem", "/state/key.pem")
	if e != nil {
		panic("owned certificate unavailable")
	}
	ca, e := os.ReadFile("/state/ca.pem")
	if e != nil {
		panic("owned CA unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		panic("CA refused")
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "tunnex-control", MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("POST", "https://api:8443/agent/ipsec/connections/4ae1e806-d6ed-4791-8137-cff6871dbd4e/material", bytes.NewBufferString(`{"desired_revision":2}`))
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		panic("mTLS projection unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		fmt.Printf("{\"http_status\":%d}\n", res.StatusCode)
		return
	}
	var out struct {
		ID     string          `json:"delivery_id"`
		Policy json.RawMessage `json:"policy"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out) != nil {
		panic("projection decode refused")
	}
	json.NewEncoder(os.Stdout).Encode(struct {
		ID              string          `json:"delivery_id"`
		Policy          json.RawMessage `json:"policy"`
		SecretsRecorded bool            `json:"secrets_recorded"`
	}{out.ID, out.Policy, false})
}

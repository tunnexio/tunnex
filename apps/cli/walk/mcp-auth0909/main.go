//go:build ignore

// This manual wire harness uses production collection and proxy code. It does
// not simulate control-plane credential leasing or managed-runtime enrollment.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/cli/internal/cli"
	"github.com/tunnexio/tunnex/packages/mcp"
)

func main() {
	endpoint := flag.String("endpoint", "https://127.0.0.1:54931/mcp", "local fixture endpoint")
	ca := flag.String("ca", "", "fixture CA certificate")
	tokenFile := flag.String("token-file", "", "synthetic credential file")
	policyFile := flag.String("policy-file", "", "JSON array of allowed fixture tools")
	output := flag.String("output", "", "sanitized discovery results")
	listen := flag.String("listen", "127.0.0.1:54932", "loopback proxy")
	flag.Parse()
	if !strings.HasPrefix(*endpoint, "https://127.0.0.1:") || !strings.HasPrefix(*listen, "127.0.0.1:") {
		panic("wire fixture requires loopback listeners")
	}
	token, err := os.ReadFile(*tokenFile)
	check(err)
	pem, err := os.ReadFile(*ca)
	check(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid fixture CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	// The production proxy clones this transport; trust only this fixture CA.
	http.DefaultTransport = transport
	headers := http.Header{"Authorization": {"Bearer " + strings.TrimSpace(string(token))}}
	collector := mcp.Client{HTTP: &http.Client{Transport: transport, Timeout: 3 * time.Second}, Headers: headers}
	base := strings.TrimSuffix(*endpoint, "/mcp")
	results := map[string]any{
		"authenticated": collector.Observe(context.Background(), *endpoint),
		"anonymous":     (mcp.Client{HTTP: collector.HTTP}).Observe(context.Background(), *endpoint),
		"forbidden":     collector.Observe(context.Background(), base+"/denied"),
		"incomplete":    collector.Observe(context.Background(), base+"/second-page-fails"),
	}
	raw, err := json.MarshalIndent(results, "", "  ")
	check(err)
	check(os.WriteFile(*output, raw, 0600))
	proxy, err := cli.MCPToolProxyWithHeaders(
		func(context.Context) (string, error) { return *endpoint, nil },
		func(context.Context) (cli.MCPProxyPolicy, error) {
			raw, err := os.ReadFile(*policyFile)
			if err != nil {
				return cli.MCPProxyPolicy{}, err
			}
			var allowed []string
			if err := json.Unmarshal(raw, &allowed); err != nil {
				return cli.MCPProxyPolicy{}, err
			}
			policy := cli.MCPProxyPolicy{Version: 1}
			for _, name := range allowed {
				policy.Rules = append(policy.Rules, cli.MCPProxyRule{Endpoint: *endpoint, ToolName: name})
			}
			return policy, nil
		},
		func(_ context.Context, target string) (http.Header, error) {
			if target != *endpoint {
				return nil, errors.New("fixture endpoint mismatch")
			}
			return headers.Clone(), nil
		},
	)
	check(err)
	fmt.Printf("Fixture discovery recorded; production MCP proxy listening at http://%s\n", *listen)
	server := &http.Server{Addr: *listen, Handler: proxy, ReadHeaderTimeout: 5 * time.Second}
	check(server.ListenAndServe())
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

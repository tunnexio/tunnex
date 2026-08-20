package safedial

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if addrs, ok := r[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("not found")
}

func TestResolverBlocksMetadataAndPrivateTargets(t *testing.T) {
	t.Parallel()
	client := NewClient(Options{Resolver: resolver{"metadata.invalid": {netip.MustParseAddr("169.254.169.254")}}})
	request, err := http.NewRequest(http.MethodPost, "https://metadata.invalid/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(request)
	if !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("metadata request error=%v, want unsafe destination", err)
	}
}

func TestResolverDialsCheckedLiteralInsteadOfHostname(t *testing.T) {
	t.Parallel()
	var got string
	client := NewClient(Options{
		Resolver: resolver{"hook.example": {netip.MustParseAddr("203.0.113.10")}},
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			got = address
			return nil, errors.New("stop after dial capture")
		},
	})
	req, _ := http.NewRequest(http.MethodPost, "https://hook.example/alert", nil)
	_, _ = client.Do(req)
	if got != "203.0.113.10:443" {
		t.Fatalf("dial=%q, want resolved IP literal", got)
	}
}

func TestRedirectIsNeverFollowedEvenForAllowedPrivateDestination(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer server.Close()
	client := NewClient(Options{AllowPrivate: true})
	_, err := client.Get(server.URL)
	if !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("redirect error=%v, want unsafe destination", err)
	}
}

func TestResponseReadIsBounded(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 16)))
	}))
	defer server.Close()
	client := NewClient(Options{AllowPrivate: true, Timeout: time.Second})
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ReadBody(response, 8)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("body error=%v, want response too large", err)
	}
	if len(body) != 8 {
		t.Fatalf("read %d bytes, want capped 8", len(body))
	}
}

func TestClientRejectsUnvalidatedPlainHTTP(t *testing.T) {
	t.Parallel()
	client := NewClient(Options{})
	_, err := client.Get("http://hooks.example/alert")
	if !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("plain HTTP request error=%v, want unsafe destination", err)
	}
}

func TestResponseReadHonorsClientDeadline(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		time.Sleep(250 * time.Millisecond)
	}))
	defer server.Close()
	client := NewClient(Options{AllowPrivate: true, Timeout: 50 * time.Millisecond})
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	_, err = ReadBody(response, 8)
	if err == nil {
		t.Fatal("slow response read unexpectedly succeeded")
	}
}

func TestValidateURLRequiresHTTPSUnlessPrivateOptIn(t *testing.T) {
	t.Parallel()
	if _, err := ValidateURL("http://hooks.example/alert", false); !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("plain HTTP error=%v, want unsafe destination", err)
	}
	if _, err := ValidateURL("http://10.0.0.10/hook", true); err != nil {
		t.Fatalf("private opt-in URL: %v", err)
	}
}

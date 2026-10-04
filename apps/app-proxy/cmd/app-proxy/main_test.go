package main

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShutdownForcesBlockedHTTPWithinSharedBudget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	finished := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(finished) })}
	go server.Serve(listener)
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: fixture\r\n\r\n"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler not entered")
	}
	worker := make(chan struct{}) // Deliberately stalled: cannot extend HTTP grace.
	begin := time.Now()
	shutdownServers([]*http.Server{server}, worker, 100*time.Millisecond)
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("shutdown exceeded budget: %v", elapsed)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("active request not cancelled")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(conn).ReadByte(); err == nil {
		t.Fatal("active socket remained open")
	}
}

func TestLimitedListenerCloseReleasesAcceptedSlot(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &limitListener{Listener: inner, slots: make(chan struct{}, 1), done: make(chan struct{})}
	defer l.Close()
	peer, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if len(l.slots) != 1 {
		t.Fatal("accepted slot absent")
	}
	_ = conn.Close()
	_ = conn.Close()
	if len(l.slots) != 0 {
		t.Fatal("slot leaked")
	}
}

func TestRestoreMarkerConfigurationRequiredForProxy(t *testing.T) {
	for _, path := range []string{"", "relative/marker", "/private/secret\x00marker"} {
		err := validateRestoreMarker(path)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid marker configuration accepted/leaked")
		}
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "marker.json")
	if err := validateRestoreMarker(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if validateRestoreMarker(path) == nil {
		t.Fatal("present marker accepted")
	}
}

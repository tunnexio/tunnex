package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("read deadline reached") }
func TestPositiveRequiresOriginSSEContent(t *testing.T) {
	for _, test := range []struct {
		status int
		mime   string
		body   io.Reader
		want   bool
	}{
		{200, "text/event-stream", strings.NewReader("data: 0\n\n"), true},
		{403, "text/html", strings.NewReader("Application unavailable"), false},
		{200, "text/html", strings.NewReader("data: 0\n"), false},
		{200, "text/event-stream", strings.NewReader(""), false},
		{200, "text/event-stream", failedReader{}, false},
	} {
		r := &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": []string{test.mime}}, Body: io.NopCloser(test.body)}
		if positiveSSE(r) != test.want {
			t.Fatal("refusal/timeout/content qualification incorrect")
		}
	}
}
func TestStalledPositiveContentDeadline(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	_ = reader.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(reader)}
	if positiveSSE(response) {
		t.Fatal("stalled body counted as positive origin traffic")
	}
}
func TestEvidenceBoundaryRejectsForeignPaths(t *testing.T) {
	for _, path := range []string{"evidence.json", "/private/tmp/evidence.json", owned + "/.runtime/../outside.json"} {
		if privatePath(path, false) {
			t.Fatal("foreign evidence permitted")
		}
	}
}

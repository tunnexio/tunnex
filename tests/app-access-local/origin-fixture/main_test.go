package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestFixtureStreamsCancelAndCounters(t *testing.T) {
	server := httptest.NewServer(originHandler())
	defer server.Close()
	for _, path := range []string{"/events", "/download", "/long-response"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Fatal(path, response.StatusCode)
		}
		if _, err = io.ReadFull(response.Body, make([]byte, 1)); err != nil {
			t.Fatal(path, err)
		}
		response.Body.Close()
	}
	until := time.Now().Add(time.Second)
	for (fixtureSSE.Load() != 0 || fixtureDownload.Load() != 0 || fixtureLong.Load() != 0) && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if fixtureSSE.Load() != 0 || fixtureDownload.Load() != 0 || fixtureLong.Load() != 0 {
		t.Fatal("fixture origin streams survived cancellation")
	}
}
func TestFixtureRFC6455HandshakeMaskedEchoAndClose(t *testing.T) {
	server := httptest.NewServer(originHandler())
	defer server.Close()
	target, _ := url.Parse(server.URL)
	conn, err := net.Dial("tcp", target.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	request, _ := http.NewRequest("GET", server.URL+"/ws", nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if request.Write(conn) != nil {
		t.Fatal("write")
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") == "" {
		t.Fatal("handshake", err)
	}
	_, err = conn.Write([]byte{0x81, 0x83, 1, 2, 3, 4, 'a' ^ 1, 'a' ^ 2, '7' ^ 3})
	if err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, 5)
	if _, err = io.ReadFull(reader, echoed); err != nil || string(echoed) != string([]byte{0x81, 3, 'a', 'a', '7'}) {
		t.Fatal("echo", err)
	}
	conn.Close()
	until := time.Now().Add(time.Second)
	for fixtureWS.Load() != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if fixtureWS.Load() != 0 {
		t.Fatal("fixture websocket remained open")
	}
}

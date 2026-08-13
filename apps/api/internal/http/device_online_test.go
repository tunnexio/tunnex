package http

import (
	"testing"
	"time"
)

func TestDeviceOnlineThreshold(t *testing.T) {
	if deviceOnline(nil) {
		t.Fatal("no handshake -> not online")
	}
	recent := time.Now().Add(-30 * time.Second)
	if !deviceOnline(&recent) {
		t.Fatal("recent handshake -> online")
	}
	// Just inside / just outside the boundary.
	inside := time.Now().Add(-(onlineThreshold - 5*time.Second))
	if !deviceOnline(&inside) {
		t.Fatal("handshake within threshold -> online")
	}
	stale := time.Now().Add(-(onlineThreshold + 5*time.Second))
	if deviceOnline(&stale) {
		t.Fatal("handshake older than threshold -> offline (WG has no connection state)")
	}
}
